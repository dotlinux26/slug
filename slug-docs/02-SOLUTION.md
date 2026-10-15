# 02. Giải pháp và kiến trúc sản phẩm

> **Trạng thái tài liệu:** Đặc tả sản phẩm đề xuất. Tính năng nào chưa có bản triển khai và kết quả kiểm thử tương ứng không nên được trình bày như tính năng đã hoàn tất.

## 1. Tổng quan

**Slug** (`slug`) là công cụ CLI đa nền tảng hướng đến chia sẻ và đồng bộ thư mục giữa một host và các client. Mỗi workspace chia sẻ có cấu hình, ACL, quy tắc lọc và trạng thái audit riêng. Các client chỉ được truy cập đúng workspace và các thao tác được cấp phép.

Mô hình cốt lõi là **một workspace, một phạm vi bảo vệ**. Việc dùng các cổng riêng là một phương án vận hành; cổng riêng không thay thế kiểm tra quyền ở tầng ứng dụng.

## 2. Workspace cô lập

Lệnh dự kiến:

```bash
slug add ./du-an -p 9443 -s 3 --ttl 24h
slug status
slug stop -p 9443
```

Một workspace có thể lưu metadata trong `.slug/`:

```text
.slug/
  config.toml
  acl.db
  rules.conf
  index.db
  audit.log
  manifest-state.db
```

- `config.toml`: cấu hình share, suite, giới hạn và tùy chọn giao thức.
- `acl.db`: tài khoản, role, hạn sử dụng và trạng thái thu hồi.
- `rules.conf`: quy tắc bổ sung ngoài `.gitignore`.
- `index.db`: cache kiểm tra nội dung, trạng thái AI Guard và dấu vân tay tệp.
- `audit.log`: sự kiện cấp/thu hồi quyền, override cảnh báo và thao tác quản trị.
- `manifest-state.db`: epoch, root hash và metadata cần để phát hiện trạng thái manifest bất thường.

Các tệp metadata nội bộ phải luôn bị loại khỏi danh sách chia sẻ, kể cả khi quy tắc ignore bị cấu hình sai. Server phải chuẩn hóa đường dẫn theo workspace root, kiểm tra quyền truy cập sau khi resolve đường dẫn và xử lý symlink an toàn. `weakly_canonical()` hỗ trợ chuẩn hóa nhưng **không tự nó loại bỏ mọi TOCTOU hoặc symlink race**; thao tác mở tệp cần dùng cơ chế an toàn phù hợp từng hệ điều hành.

## 3. Ba Crypto Suites

Slug đề xuất ba cấu hình giao thức; suite được chốt trong handshake, sau đó áp dụng thống nhất cho phiên. Không được để client tự hạ cấp suite âm thầm. Nếu chính sách yêu cầu suite tối thiểu mà hai bên không đáp ứng được, kết nối phải thất bại rõ ràng.

| ID | Tên | Băm nội dung / transcript | Chữ ký định danh | Thiết lập khóa | AEAD dữ liệu |
|---|---|---|---|---|---|
| `0x01` | `classical` | SHA-256 | Ed25519 | X25519 | XChaCha20-Poly1305 |
| `0x02` | `modern` | BLAKE3 | Ed25519 | X25519 | XChaCha20-Poly1305 |
| `0x03` | `pure-pqc` | BLAKE3 | ML-DSA-65 (FIPS 204) | ML-KEM-768 (FIPS 203) | XChaCha20-Poly1305 |

**Diễn giải:**

- Suite 1 là cấu hình cổ điển. X25519 và Ed25519 không được thiết kế để chống lại đối thủ có máy tính lượng tử đủ mạnh.
- Suite 2 dùng BLAKE3 cho hash nội dung/transcript nhằm hướng tới thông lượng băm cao; việc dùng BLAKE3 không tự làm cho suite chống lượng tử.
- Suite 3 dùng ML-KEM-768 và ML-DSA-65, hai thuật toán hậu lượng tử được chuẩn hóa trong FIPS 203 và FIPS 204. Đây là cấu hình được thiết kế theo NIST Security Category 3; không nên mô tả thành bảo đảm an toàn tuyệt đối.
- XChaCha20-Poly1305 là AEAD dùng nonce 192-bit. Nonce dài không bù được việc tái sử dụng key/nonce sai cách; giao thức vẫn phải bảo đảm tính duy nhất theo từng key và phân tách key theo hướng truyền.

BLAKE3 là hàm băm; không nên gọi nó là chữ ký, KEM hay thuật toán mã hóa. KEM thiết lập bí mật chung; AEAD mã hóa và xác thực dữ liệu; chữ ký xác thực khóa/danh tính và metadata đã ký. Các vai trò này không thay thế lẫn nhau.

## 4. Xác thực và quyền truy cập có thời hạn

### 4.1. Mã kết nối nhanh 8 chữ số

Server hiển thị mã ngắn hạn để một client kết nối nhanh. Mã được tiêu thụ nguyên tử sau lần xác thực thành công đầu tiên; các yêu cầu song song chỉ được phép có tối đa một yêu cầu thắng. Server cần giới hạn tốc độ thử mã, ghi nhận thất bại và buộc bằng chứng xác thực gắn với challenge/session hiện tại.

Đây là mã bootstrap có entropy thấp hơn khóa mật mã. Không dùng chính mã 8 chữ số làm khóa mã hóa hoặc làm bí mật có thể kiểm tra ngoại tuyến từ transcript công khai. Sau khi có kênh bảo mật, mã được gửi/kiểm tra trong kênh đó và không bao giờ được chấp nhận lại trong cùng time-step/token ID.

Nếu sử dụng TOTP theo RFC 6238, thời gian thay đổi mã phải được triển khai đúng tham số đã công bố. Tính “chỉ dùng một lần” là **lớp tiêu thụ trạng thái phía server** bổ sung, không tự có chỉ vì mã TOTP đổi theo thời gian.

### 4.2. Tài khoản workspace

Role dự kiến:

- `r`: liệt kê và tải xuống tệp được phép đọc.
- `w`: tải tệp lên các vị trí được phép ghi.
- `rw`: đọc và ghi trong phạm vi đã cấp.

Role cần được kiểm tra phía server tại mỗi API/operation, không chỉ ẩn nút trên GUI. Với tài khoản tạm thời, `--ttl` xác định `expires_at`; mọi thao tác sau khi hết hạn phải bị từ chối. Thu hồi tài khoản cần vô hiệu hóa các session token/credential liên quan hoặc khiến chúng bị từ chối ở lần kiểm tra kế tiếp.

Lệnh dự kiến:

```bash
slug user add -u dev_a --role rw --ttl 24h
slug user add -u nop_bai --role w --ttl 2h
slug user list -p 9443
slug user rm -u dev_a -p 9443
```

## 5. Bộ lọc theo tầng

### 5.1. `.gitignore`

Slug hướng đến hỗ trợ ngữ nghĩa `.gitignore` quen thuộc: pattern theo thư mục, quy tắc ở các cấp cha/con, thứ tự ưu tiên và phủ định `!`. Nếu chưa hiện thực toàn bộ ngữ nghĩa Git, tài liệu triển khai phải công bố rõ phần được hỗ trợ; không nên tuyên bố tương thích hoàn toàn khi còn thiếu các trường hợp biên.

Các quy tắc được áp dụng theo đường dẫn tương đối với workspace. Tệp `.slug/` và metadata nội bộ luôn bị loại trừ khỏi truyền tải theo quy tắc bảo vệ cố định.

### 5.2. `.slug/rules.conf`

`rules.conf` bổ sung các luật chặn theo đường dẫn, phần mở rộng, mẫu regex hoặc nội dung file. Ví dụ cú pháp đề xuất:

```text
# Mẫu này là cú pháp riêng của Slug, không phải cú pháp Git.
# <rule id="private-key" action="block" type="content">BEGIN PRIVATE KEY</rule>
# <rule id="cloud-token" action="block" type="regex">akia[0-9a-z]{16}</rule>
# <rule id="example-env" action="allow" type="path">./.env.example</rule>
```

Các thẻ được parser Slug đọc từ `rules.conf`; vì là dòng comment bắt đầu bằng `#`, chúng vẫn được Git xem là comment nếu tệp được đặt ở nơi Git đọc. Luật `allow` không được phép âm thầm ghi đè chính sách bắt buộc như cấm gửi `.slug/` hoặc cấm truy cập ngoài root.

### 5.3. Bỏ qua file có giải thích

Khi tệp bị chặn, Slug ghi lại đường dẫn, hash nội dung, nguồn quy tắc và lý do. Trong một lần tải thư mục, tệp bị chặn được đưa vào danh sách `skipped` cùng lý do; các tệp còn lại tiếp tục truyền. Client phải phân biệt “đã đồng bộ đầy đủ” với “đã đồng bộ có tệp bị bỏ qua”.

## 6. Stateful AI Guard

AI là extension tùy chọn, dùng để phân tích ngữ nghĩa các đoạn mã nghi vấn sau khi bộ lọc tĩnh thực hiện bước sàng lọc ban đầu.

```bash
slug add ./du-an -ai --ai-provider local
slug audit list
slug audit recheck --all
slug audit allow ./tests/mock_token.json --reason "Dữ liệu giả đã được xác minh"
```

`index.db` lưu hash của nội dung đã được đánh giá, trạng thái (`CLEAN`, `AI_FLAGGED`, `STALE`, `USER_ALLOWED`), thời gian, phiên bản scanner/provider và lý do. Nếu hash thay đổi, kết quả đánh giá trước đó không còn áp dụng cho nội dung mới: chuyển sang `STALE` và yêu cầu recheck. **Không tự mở khóa chỉ vì file đã thay đổi.** Chỉ đưa file về `CLEAN` khi kiểm tra lại đạt yêu cầu, hoặc cho phép ngoại lệ thủ công có ghi audit và gắn với hash cụ thể.

AI có thể sai hoặc bị đánh lừa bởi nội dung được thiết kế để thao túng mô hình. Quyết định chính sách cuối cùng phải nằm ở rule engine và chính sách người quản trị, không phải ở câu trả lời tự do của mô hình.

## 7. Delta Sync và lựa chọn tệp

Lệnh `slug pull` trao đổi manifest đã áp dụng bộ lọc và ACL trước khi tải nội dung. Client so sánh hash với bản sao cục bộ:

- Hash tệp giống nhau: không cần tải lại tệp.
- Tệp mới hoặc thay đổi: chỉ tải nội dung cần thiết.
- Tệp bị loại trừ hoặc bị chặn: không tải nội dung; hiển thị trong báo cáo.
- `--dry-run`: chỉ trình bày diff dự kiến.
- `--only`, `--ext`, `--max-size`: giới hạn tập tệp cần đồng bộ.
- `--prune`: xóa bản cục bộ của tệp mà manifest hiện tại không còn công bố; chỉ thực hiện khi người dùng yêu cầu rõ và có bản xem trước.

Lệnh dự kiến:

```bash
slug pull --dry-run
slug pull --only "src/core/**"
slug pull --ext ".cpp,.hpp,.md"
slug pull --max-size 50MB
slug pull --prune
```

Với tệp lớn, manifest có thể chứa hash theo khối. Chỉ khối có hash khác mới cần truyền. Nếu dùng khối kích thước cố định, việc chèn dữ liệu đầu tệp có thể làm lệch ranh giới các khối sau; content-defined chunking là một lựa chọn cải tiến nhưng cần thêm thuật toán, giới hạn tài nguyên và kiểm thử.

## 8. `slug env`: mã hóa secret khi lưu trữ

Đề xuất `slug env` mã hóa `.env` thành tệp mã hóa và cấp biến môi trường cho tiến trình đích khi chạy. Thiết kế nên dùng envelope encryption: sinh một khóa dữ liệu ngẫu nhiên (DEK), mã hóa nội dung bằng AEAD, bọc DEK bằng cơ chế thiết lập/bảo vệ khóa được định danh rõ ràng, và ký metadata nếu cần xác thực nguồn phát hành.

ML-KEM là cơ chế đóng gói khóa, không phải thuật toán mã hóa trực tiếp toàn bộ tệp. Quy trình cần xác định rõ ai sở hữu private key dùng để mở DEK, cách backup/rotation/revocation và cách khôi phục khi mất khóa.

Lệnh minh họa:

```bash
slug env init --recipient local-dev-key
slug env run -- npm run dev
```

Tệp plaintext không nên được ghi ra ổ đĩa bởi Slug, nhưng bí mật sẽ hiện diện trong bộ nhớ và trong môi trường của tiến trình đích. Quyền quản trị hệ điều hành, dump bộ nhớ, crash dump, log hoặc tiến trình con có thể làm lộ secret; tính năng này giảm rủi ro lưu trữ dạng văn bản rõ chứ không loại bỏ mọi rủi ro runtime.

## 9. CLI, GUI và giao thức truyền

CLI là bề mặt quản trị chính; GUI nhúng có thể dùng cho directory listing, upload/download, quản lý ACL và xem cảnh báo. Trình duyệt tiêu chuẩn không thể trực tiếp mở socket UDP tùy ý. Do đó, nếu giao thức truyền dữ liệu tùy chỉnh dùng UDP, cần một client native/helper hoặc chọn một giao thức được trình duyệt hỗ trợ như HTTPS/WebSocket/WebTransport (nếu môi trường hỗ trợ). Không nên mô tả web GUI như thể nó có quyền phát UDP raw trực tiếp.

## 10. Lộ trình triển khai đề xuất

1. **MVP an toàn:** workspace, ACL, TLS/kênh bảo mật đã lựa chọn, TCP/HTTPS truyền file, path confinement, `.gitignore` subset được công bố, audit log và test.
2. **Crypto agility:** suite negotiation có xác thực và chống downgrade; tích hợp thư viện mật mã đã kiểm tra; vector test và benchmark.
3. **AI Guard:** scanner tĩnh, cache hash, local provider, recheck, override có audit.
4. **Delta sync:** manifest có chữ ký, file hash, dry-run, selective pull, phục hồi truyền tải.
5. **UDP transport (nếu cần):** chunking, ACK chọn lọc, chống replay, congestion control, MTU handling và fuzzing.
6. **EnvShield:** mô hình khóa, envelope format, rotation/recovery, threat model cho hệ điều hành.

Không nên triển khai đồng loạt tất cả thành phần trước khi có mô hình giao thức và kiểm thử cho từng lớp.
