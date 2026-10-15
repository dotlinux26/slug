# 03. Ứng dụng AI và Stateful AI Audit

> **Nguyên tắc:** AI hỗ trợ phát hiện theo ngữ nghĩa; các quyết định truy cập và chặn truyền tệp vẫn phải được thực thi bởi rule engine xác định, có thể kiểm thử và có audit.

## 1. Vai trò của AI trong Slug

Slug không dùng AI để thay thế parser hoặc pattern matching thông thường. Các quy tắc dễ xác định như `.gitignore`, phần mở rộng, đường dẫn, kích thước tệp và chữ ký secret phổ biến được xử lý trước bằng scanner tĩnh. AI Extension được dùng cho các trường hợp cần hiểu ngữ cảnh, ví dụ phân biệt chuỗi dữ liệu giả trong test với credential có thể đang được dùng, hoặc nhận diện một secret bị viết theo cách không khớp regex.

AI là lớp hỗ trợ phát hiện, không phải một cơ chế chứng minh rằng tệp sạch. Một kết quả `CLEAN` có nghĩa là tệp đã vượt qua bộ kiểm tra theo phiên bản/chính sách cụ thể, không phải bảo đảm file không chứa mọi loại bí mật.

## 2. Các chế độ vận hành

### 2.1. Mặc định: không gọi AI

```bash
slug add ./project
```

- Dùng quy tắc tĩnh và ACL.
- Không gửi nội dung tệp tới AI provider.
- Khởi động nhanh là mục tiêu đo đạc; thời gian thực tế phụ thuộc kích thước workspace, filesystem, I/O, cấu hình và việc tạo manifest.

### 2.2. AI Fast-Scan

```bash
slug add ./project -ai --ai-provider local
```

- Loại trừ các thư mục thường có nhiều tệp sinh tự động theo cấu hình mặc định, ví dụ `.git/`, `node_modules/`, `build/`.
- Chỉ gửi các đoạn cần thiết đã được chọn lọc để đánh giá.
- Cần có giới hạn kích thước, timeout, concurrency và ngân sách token.
- Không mặc định gửi toàn bộ mã nguồn lên cloud.

### 2.3. AI Deep-Scan

```bash
slug audit scan ./project --deep --ai-provider local
```

- Kết hợp phát hiện tĩnh, entropy heuristic, quy tắc nội dung và AI để đánh giá các vùng nghi vấn.
- Kết quả phải kèm file, phạm vi dòng khi khả thi, loại phát hiện, mức tin cậy, provider/model và thời gian.
- Việc tự tạo rule mới chỉ nên ở chế độ đề xuất hoặc yêu cầu phê duyệt; không âm thầm thay đổi chính sách bảo mật đang áp dụng.

Không công bố các mốc như “dưới 10 giây” hay “30–60 giây” trước khi có benchmark tái lập cho nhiều kích thước workspace và loại máy.

## 3. Stateful Audit: chỉ mục theo nội dung

Slug duy trì một chỉ mục nội dung, ví dụ `.slug/index.db`, để không phải gọi AI lặp lại cho nội dung không đổi. Cơ chế này tương tự tư tưởng lưu trạng thái của công cụ quản lý source code, nhưng không đồng nhất với định dạng nội bộ của Git.

### 3.1. Trường dữ liệu đề xuất

| Trường | Ý nghĩa |
|---|---|
| `workspace_id` | ID workspace chứa tệp |
| `relative_path` | Đường dẫn tương đối sau khi chuẩn hóa |
| `content_hash` | Hash BLAKE3 của đúng nội dung đã quét |
| `size`, `mtime_ns` | Metadata hỗ trợ phát hiện thay đổi; không thay thế hash trong chế độ bảo mật nghiêm ngặt |
| `status` | `UNKNOWN`, `CLEAN`, `AI_FLAGGED`, `STALE`, `USER_ALLOWED`, `RULE_BLOCKED` |
| `reason_code` | Mã lý do xác định được của scanner/policy |
| `explanation` | Mô tả ngắn cho người dùng |
| `scanner_version` | Phiên bản scanner/ruleset |
| `provider`, `model` | Provider/model nếu có dùng AI |
| `scanned_at` | Thời điểm kiểm tra |
| `decision_actor` | Hệ thống hoặc người đã đưa ra override |
| `decision_reason` | Lý do cho ngoại lệ thủ công, nếu có |

Không nên lưu nguyên secret bị phát hiện trong audit log. Hãy lưu loại phát hiện, đường dẫn, dòng và một đoạn che thông tin nhạy cảm khi thực sự cần.

### 3.2. Luồng kiểm tra

1. Liệt kê tệp trong workspace sau khi áp dụng giới hạn đường dẫn.
2. Đánh giá bộ lọc tĩnh và chính sách bắt buộc.
3. Tạo hash nội dung; metadata như mtime/size chỉ là tín hiệu tối ưu hóa, không phải bằng chứng nội dung không đổi.
4. Nếu hash và phiên bản scanner/chính sách khớp với kết quả trước, có thể tái sử dụng kết quả đó mà không gọi AI lần nữa.
5. Nếu nội dung thay đổi, trạng thái kết quả cũ trở thành `STALE`; cần recheck trước khi cho phép chia sẻ nội dung mới.
6. Ghi lại kết quả và phiên bản của pipeline đã thực hiện kiểm tra.

**Quan trọng:** hash phải tương ứng với nội dung thực tế sắp gửi. Nếu file thay đổi sau khi quét nhưng trước khi đọc để truyền (TOCTOU), Slug phải phát hiện hash khác và chặn/đánh giá lại. Chỉ dựa vào `mtime` có thể bỏ sót một số thay đổi.

### 3.3. Quy tắc chuyển trạng thái

| Trạng thái hiện tại | Sự kiện | Trạng thái tiếp theo | Hành vi chia sẻ |
|---|---|---|---|
| `UNKNOWN` | Chưa quét | `UNKNOWN` | Chặn hoặc áp dụng chính sách fail-closed |
| `UNKNOWN` | Quét đạt | `CLEAN` | Có thể chia sẻ nếu các rule khác cho phép |
| `UNKNOWN` | Phát hiện rủi ro | `AI_FLAGGED` | Bỏ qua tệp và ghi lý do |
| `CLEAN` | Hash/phiên bản scanner đổi | `STALE` | Tạm chặn đến khi recheck |
| `AI_FLAGGED` | Hash không đổi | `AI_FLAGGED` | Tiếp tục bỏ qua |
| `AI_FLAGGED` | Nội dung thay đổi | `STALE` | Không tự động mở khóa |
| `STALE` | Recheck đạt | `CLEAN` | Có thể chia sẻ nếu policy cho phép |
| `STALE` | Recheck phát hiện vấn đề | `AI_FLAGGED` | Bỏ qua |
| Bất kỳ trạng thái phù hợp | Người dùng tạo ngoại lệ | `USER_ALLOWED` | Chỉ áp dụng theo phạm vi đã xác định, có audit |

Ngoại lệ nên được gắn với hash hiện tại hoặc phạm vi/rule rõ ràng. Nếu file thay đổi sau khi được `USER_ALLOWED`, ngoại lệ theo hash phải hết hiệu lực và tệp trở về `STALE`.

## 4. Các lệnh kiểm soát cảnh báo

```bash
slug audit list
slug audit show src/db/conn.py
slug audit recheck src/db/conn.py
slug audit recheck --all
slug audit allow tests/mock-token.json --reason "Fixture không chứa credential thật"
slug audit deny src/config/local.json --reason "Không chia sẻ cấu hình cục bộ"
```

- `list`: hiển thị tệp đang bị chặn, stale hoặc đã được cho phép ngoại lệ.
- `show`: hiển thị lý do, hash và lịch sử quyết định có liên quan.
- `recheck`: quét lại nội dung hiện tại; không xóa lịch sử cũ.
- `allow`: tạo ngoại lệ có phạm vi rõ ràng, gắn với hash hoặc rule và yêu cầu lý do.
- `deny`: giữ chặn đối với tệp hoặc chuyển thành rule quản trị nếu người dùng xác nhận.

Tên lệnh là đặc tả đề xuất; phải được thống nhất với CLI thật trước khi phát hành tài liệu sử dụng.

## 5. Tách phát hiện và quyết định chính sách

Quyết định có được truyền tệp hay không nên theo thứ tự:

1. Xác minh workspace root, quyền người dùng và trạng thái TTL.
2. Áp dụng cấm truy cập ngoài root, tệp metadata nội bộ và luật bảo mật bắt buộc.
3. Áp dụng `.gitignore` và `rules.conf` với thứ tự ưu tiên được công bố.
4. Kiểm tra trạng thái AI audit tương ứng với đúng hash nội dung.
5. Nếu nội dung mới chưa có đánh giá hợp lệ, áp dụng chính sách đã chọn: chặn cho tới khi quét, hoặc cho phép với cảnh báo theo cấu hình có chủ ý.
6. Ghi sự kiện bỏ qua/chia sẻ/override mà không làm lộ nguyên secret.

Không nên coi một câu trả lời từ mô hình kiểu “tệp này an toàn” là thứ có quyền vượt qua một rule `block` do quản trị viên đặt ra.

## 6. Provider local và cloud

### Local provider

Có thể kết nối tới runtime cục bộ như Ollama hoặc llama.cpp. Đây là lựa chọn ưu tiên khi mã nguồn không được phép rời máy. “Local” giảm nguy cơ gửi dữ liệu ra ngoài qua API nhưng vẫn cần xem xét log, telemetry, model cache, quyền đọc tệp và bảo vệ tiến trình local.

### Cloud provider

Cloud API là tùy chọn có thể gửi nội dung được trích chọn tới nhà cung cấp. Trước khi gửi cần:

- Hiển thị rõ provider/model và loại dữ liệu có thể được truyền.
- Cho phép opt-in rõ ràng; không âm thầm chuyển sang cloud khi local provider lỗi.
- Hạn chế payload, che secret đã phát hiện bằng scanner tĩnh khi khả thi.
- Không gửi tệp nhị phân hoặc toàn bộ workspace nếu không cần thiết.
- Đặt timeout, giới hạn chi phí và xử lý lỗi/giới hạn rate.
- Ghi audit metadata, không ghi secret plaintext vào log.

### Rủi ro prompt injection

Nội dung trong mã nguồn hoặc tài liệu có thể chứa chỉ dẫn nhằm thao túng mô hình. Provider phải xem nội dung tệp là dữ liệu không đáng tin, không phải lệnh điều khiển. AI không được quyền tự chạy command, thay đổi ACL, gửi dữ liệu đi nơi khác hoặc sửa chính sách mà không qua lớp xác nhận xác định.

## 7. False positive và trách nhiệm người dùng

AI Guard là công cụ hỗ trợ, không nên chặn vĩnh viễn một file chỉ vì mô hình từng đưa ra cảnh báo. Người dùng cần hiểu:

- File nào bị skip;
- Rule hoặc phân tích nào tạo ra cảnh báo;
- Cảnh báo dựa trên hash nào;
- Cách sửa và quét lại;
- Cách chấp nhận ngoại lệ có audit;
- Hậu quả khi override cảnh báo.

Để dễ dùng, lệnh `slug pull --dry-run` và báo cáo phía server nên phân biệt rõ `ignored by pattern`, `blocked by mandatory rule`, `AI flagged`, `pending recheck` và `manually allowed`.

## 8. Kiểm thử AI Guard

Bộ kiểm thử tối thiểu:

- Secret chuẩn trong tệp cấu hình; token giả và fixture trong thư mục test.
- Cùng nội dung nhưng đổi mtime; nội dung đổi nhưng kích thước giữ nguyên.
- File thay đổi giữa scan và transfer.
- Model timeout, provider không khả dụng, response không hợp lệ.
- Prompt injection nằm trong source/comment/README.
- Cache từ model/scanner version cũ.
- Override ngoại lệ rồi file thay đổi hash.
- Nhiều client đồng thời yêu cầu cùng tệp đang ở trạng thái `STALE`.
- Kiểm tra cloud provider không được gọi khi cấu hình chỉ cho phép local.

## 9. Định hướng

Mục tiêu của Stateful AI Audit không phải “AI nhớ mãi file sạch”, mà là **gắn mỗi quyết định kiểm tra với đúng nội dung, phiên bản scanner và chính sách**. BLAKE3 giúp nhận diện nội dung trùng khớp; trạng thái có audit làm cho cảnh báo có thể giải thích, quét lại và quản lý được.
