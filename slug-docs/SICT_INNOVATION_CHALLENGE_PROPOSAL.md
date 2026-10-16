# BÁO CÁO GIẢI PHÁP DỰ THI
# SICT INNOVATION CHALLENGE 2026 — TRACK: TECH YOUR SOLUTIONS

---

### TÊN ĐỀ TÀI:
## SLUG — GIẢI PHÁP BẢO VỆ DỮ LIỆU MÃ NGUỒN VÀ CHIA SẺ WORKSPACE AN TOÀN TRONG QUY TRÌNH PHÁT TRIỂN PHẦN MỀM CÓ AI HỖ TRỢ

- **Lĩnh vực giải pháp:** Phần mềm (Quy trình phát triển & Quản lý dữ liệu mã nguồn) & Mạng (Chia sẻ cục bộ P2P & Bảo vệ biên dữ liệu)
- **Hình thức sản phẩm:** Ứng dụng dòng lệnh (CLI Tool) đa nền tảng C++20, tích hợp Engine Viewing Web Explorer cục bộ (Zero-Dependency Portable Binary ~8MB)
- **Mã nguồn mở chính thức:** [https://github.com/dotlinux26/slug](https://github.com/dotlinux26/slug) (Apache License 2.0)

---

## TÓM TẮT DỰ ÁN (EXECUTIVE SUMMARY)

Trong kỷ nguyên phát triển phần mềm hiện đại, sinh viên và kỹ sư phần mềm thường xuyên sử dụng các trợ lý lập trình trí tuệ nhân tạo (AI Coding Assistants như GitHub Copilot, Cursor, Claude Code) và làm việc nhóm trong mạng nội bộ (phòng lab trường học, văn phòng công ty, ký túc xá). Quy trình này làm phát sinh các khoảng trống bảo mật và bất tiện thực tế:
1. **Lộ lọt khóa bí mật (Secret Leakage) khi lưu trữ và công khai:** Các tệp `.env`, khóa API đám mây (OpenAI, Gemini, AWS), token thanh toán và chuỗi kết nối cơ sở dữ liệu được lưu dưới dạng văn bản rõ (plaintext) trong thư mục dự án. Chúng dễ dàng bị các công cụ lập chỉ mục của AI đọc lén, hoặc bị vô tình đẩy lên các nền tảng công khai (như GitHub public repository — điều kiện bắt buộc của cuộc thi) dẫn đến việc bị bot tự động quét và đánh cắp trong vài chục giây.
2. **Ô nhiễm dữ liệu và thiếu kiểm soát khi chia sẻ qua mạng:** Việc chia sẻ nhanh mã nguồn dở dang (chưa commit) cho bạn bè thường được thực hiện qua các công cụ truyền thống như `python -m http.server` hoặc nén file `.zip`. Cách làm này truyền tải cả hàng trăm megabyte dữ liệu rác (`node_modules/`, `build/`), không có mã hóa an toàn trên mạng Wi-Fi công cộng, và không hề có cơ chế ngăn chặn việc gửi nhầm các file cấu hình nhạy cảm.
3. **Lãng phí băng thông WAN và thiếu công cụ thu bài học sinh gọn nhẹ:** Khi chuyển file trong cùng mạng LAN văn phòng/trường học, người dùng vẫn phải tải qua Google Drive/Zalo (tốn băng thông Internet, phụ thuộc bên thứ 3). Trong khi đó, giảng viên cần thu bài 40–50 sinh viên trong phòng lab thiếu một giải pháp một chiều (Write-Only) vừa nhẹ, vừa chống sinh viên xem trộm bài của nhau.

**Giải pháp Slug:** Slug là một công cụ độc lập, tinh gọn (~8MB), cung cấp **Lớp kiểm soát biên thống nhất (Unified Workspace Boundary Controller)** cho môi trường học tập và phát triển:
- **Kiểm soát bí mật với AI Guard:** Phân tích ngữ nghĩa mã nguồn, phân biệt dữ liệu giả lập (mock test) với khóa bí mật thật, giải thích nguy cơ bằng tiếng Việt dễ hiểu.
- **Bảo vệ văn bản rõ với EnvShield:** Cất file `.env` vào Kho trung tâm của người dùng (`~/.slug/env_vault/`), mã hóa repo thành `.env.pqc`, nạp biến môi trường trực tiếp từ bộ nhớ RAM cho tiến trình con khi chạy test (`slug env run`), loại bỏ văn bản rõ trên ổ đĩa.
- **Chia sẻ P2P có kiểm soát & Thu bài một chạm:** Tự động lọc bỏ rác build theo `.gitignore`, khóa cứng các file nhạy cảm ngay tại tầng đọc của hệ thống tệp ảo (VFS Jail), xác thực một chạm bằng mã OTP 8 chữ số tự hủy, phân quyền Write-Only (`[w]`) thu bài phòng máy chống nhìn trộm bài, và mã hóa kênh truyền bằng chuẩn mật mã hậu lượng tử mới nhất (NIST FIPS 203 ML-KEM-768).

---

## MỤC I. ĐẶT VẤN ĐỀ THỰC TẾ VÀ TÍNH CẤP THIẾT

### 1.1. Các kịch bản đời thường trong học tập, phòng lab và văn phòng
Mỗi ngày, hàng triệu sinh viên công nghệ thông tin và lập trình viên đối mặt với các tình huống rất đỗi quen thuộc:
- **Chuyển tệp lớn qua mạng LAN:** Hai máy tính trong cùng phòng lab trường học hoặc văn phòng công ty cần chuyển file đồ án, tài liệu thiết kế dung lượng vài GB. Thay vì tận dụng mạng LAN gigabit (~125 MB/s), mọi người phải upload lên Google Drive hoặc gửi qua Zalo, tốn băng thông WAN của đơn vị và bị giới hạn dung lượng.
- **Bài toán thu bài tập sinh viên phòng máy:** Giảng viên cần thu bài thi/bài tập của 40–50 sinh viên nhanh gọn. Dùng Google Form/Drive thì nghẽn mạng WAN; dùng `python -m http.server` thì sinh viên nhìn thấy bài của nhau và tải về chép; dùng FTP/SMB thì cấu hình tài khoản cồng kềnh, cần quyền admin hệ thống.
- **Lập trình với trợ lý AI và làm việc nhóm:** Sinh viên dùng Copilot, Cursor để viết code thử nghiệm gọi API (OpenAI, Gemini), đặt API key vào `.env`. Khi làm việc nhóm, việc nén nhanh cả thư mục đang code dở để gửi cho bạn bè gỡ lỗi rất dễ kéo theo cả API key thật hoặc hàng trăm MB thư mục rác `node_modules/`.
- **Yêu cầu public repository khi nộp bài:** Sinh viên nộp đồ án môn học hoặc tham gia hackathon/cuộc thi công nghệ bắt buộc phải công khai repo trên GitHub (như quy chế SICT Innovation Challenge). Chỉ một sơ suất nhỏ là khóa bí mật bị bot quét vét sạch.

### 1.2. Phân tích lỗ hổng của các giải pháp truyền thống

| Phương thức | Lỗ hổng & Bất tiện thực tế |
| :--- | :--- |
| **`python -m http.server`** | • **Plaintext HTTP:** Ai cùng mạng Wi-Fi cũng bắt được gói tin mã nguồn.<br>• **Không phân quyền:** Bất kỳ ai biết IP đều tải được mọi file.<br>• **Không hỗ trợ nộp bài an toàn:** Chỉ cho download. Nếu dùng script upload thì ai cũng xem và tải được bài người khác vừa nộp.<br>• **Không kiểm duyệt:** Phơi bày toàn bộ `.env` và file nhạy cảm nếu mở từ thư mục cha. |
| **SFTP / FTP / SMB** | • **Cấu hình cồng kềnh:** Đòi hỏi quyền quản trị viên (root/admin), tạo tài khoản user, mở port firewall phức tạp.<br>• **Không cơ động (Ephemeral):** Không phù hợp để chia sẻ nhanh vài phút giữa hai máy cá nhân.<br>• **Thiếu kiểm soát nội dung:** Không hiểu `.gitignore`, không có cơ chế rà soát secret chủ động. |
| **Google Drive / Zalo** | • **Lãng phí băng thông WAN:** Dữ liệu nội bộ phải đi vòng qua Internet.<br>• **Rủi ro lộ bí mật:** Khóa bí mật công ty bị đẩy lên máy chủ bên thứ ba.<br>• **Bị bóp băng thông & giới hạn dung lượng.** |

---

## MỤC II. TÍNH KHẢ THI VÀ HIỆN THỰC HÓA SẢN PHẨM

Slug không dừng lại ở mức ý tưởng trên giấy, mà đã được **hiện thực hóa 100% bằng mã nguồn C++20**, có sẵn bản phát hành độc lập chạy trên cả Windows và Linux.

### 2.1. Kiến trúc tối giản, sẵn sàng sử dụng ngay
- **Zero-Dependency:** Đóng gói thành đúng **1 file thực thi duy nhất (`slug`) với dung lượng chỉ ~8MB**.
- **Không cần cài đặt môi trường:** Không đòi hỏi cài Node.js runtime, Python, Java, hay cơ sở dữ liệu cồng kềnh. Tải về là chạy ngay.
- **Tích hợp Web Explorer:** Ngoài giao diện dòng lệnh (CLI), Slug tích hợp sẵn một Engine Viewing nội bộ hiển thị trên trình duyệt (`127.0.0.1:8080/drop`) với phong cách Techno B2B trực quan, hỗ trợ xem cây thư mục và tải file một chạm.

### 2.2. Quy trình sử dụng 3 bước tinh gọn (The 3-Step Workflow)
Sản phẩm được thiết kế sao cho một sinh viên năm nhất cũng có thể làm chủ trong 1 phút:

```bash
# Bước 1: Quét kiểm tra mã nguồn trước khi chia sẻ/commit
slug audit scan .

# Bước 2: Đóng băng secret vào Vault, chạy code và test hoàn toàn từ RAM
slug env init
slug env run -- npm test      # (hoặc pytest, python app.py, cargo test)

# Bước 3: Chia sẻ thư mục sạch qua mạng nội bộ cho bạn bè
slug add .                    # Xuất link kèm mã OTP 8 số
# Phía bạn bè chỉ cần gõ:
slug get <link_nhận_được>
```

---

## MỤC III. TÍNH SÁNG TẠO VÀ KHÁC BIỆT VỀ CƠ CHẾ

Khác biệt cốt lõi của Slug không phải là việc "phát minh ra nguyên lý mã hóa mới", mà nằm ở **Cơ chế kiểm soát biên đóng khép kín (Closed-Loop Boundary Enforcement)** giữa các tác nhân phát triển:

```text
CÁC CÔNG CỤ RỜI RẠC TRÊN THỊ TRƯỜNG             CƠ CHẾ HỢP NHẤT TRÊN SLUG
====================================             =========================
[Gitleaks]    --> Chỉ quét lúc commit            [Stateful AI Guard]
                   (quên quét là lộ)                     |
                                                         v
[dotenvx]     --> Chỉ bọc file .env              [Central Vault & RAM Injection]
                   (không bảo vệ lúc share)              |
                                                         v
[http.server] --> Truyền file vô tri             [SlugVFS Jail & P2P Transport]
                   (truyền cả rác & secret)       Kiểm duyệt trực tiếp tại hàm đọc chunk!
```

### 3.1. Kho lưu trữ trung tâm ngoài Workspace (Centralized Env Vault)
Khi chạy `slug env init`:
- Slug tính toán mã băm định danh duy nhất của workspace (BLAKE3).
- Tự động di chuyển bản sao `.env` ra ngoài workspace vào thư mục an toàn của người dùng: `~/.slug/env_vault/<workspace_hash>/`.
- Thư mục dự án chỉ còn lại file `.env.pqc` (được mã hóa bằng ML-KEM-768 và AES-256-GCM). File bản rõ trên đĩa bị xóa.
- Khi cần sửa đổi hoặc tương tác với các công cụ bắt buộc đọc file đĩa, sinh viên chỉ cần gõ `slug env restore` để khôi phục trong 1 giây.

### 3.2. Cấp biến môi trường trực tiếp từ RAM (Process RAM Injection)
Lệnh `slug env run -- <lệnh>` đọc và giải mã `.env.pqc` trong bộ nhớ RAM của Slug, sau đó nạp trực tiếp vào khối môi trường của tiến trình con thông qua API hệ điều hành (`CreateProcessW` trên Windows, `execve` trên Linux).
- Tiến trình con (ví dụ `pytest`) nhận đầy đủ 100% biến môi trường để chạy test bình thường.
- Không sinh ra bất kỳ file bản rõ tạm thời nào trên ổ đĩa.

### 3.3. Cổng kiểm soát đọc VFS Jail (Closed-Loop Read Path Gating)
Trong các công cụ truyền file thông thường, nếu người dùng quên quét secret, công cụ vẫn vui vẻ gửi file đi. Ở Slug, hệ thống tệp ảo (`SlugVFS`) khóa chặt hàm đọc dữ liệu `vfs_.read_file()`:
- Một file bị AI Guard hoặc quy tắc bảo mật đánh dấu cách ly (`QUARANTINED` / `RULE_BLOCKED`) sẽ bị từ chối ngay tại ranh giới filesystem.
- Kể cả khi client cố tình gửi request tải trực tiếp một chunk của file đó mà bỏ qua manifest, máy chủ Slug vẫn chặn đứng tại chỗ.

### 3.4. Thu bài tập một chiều với OTP Write-Only (`[w]` Blind Drop)
- Giáo viên chỉ cần chạy `slug add ./bai_nop -p 9443` và cấp mã OTP `[w]` cho sinh viên.
- Sinh viên chỉ có quyền tải bài lên qua Web Dropbox hoặc lệnh `slug push`.
- Tầng `SlugVFS Jail` cưỡng chế chặn tuyệt đối quyền đọc (`read_file`) và liệt kê (`list_dir`) đối với role này. Sinh viên hoàn toàn không thể xem hoặc tải bài của nhau về chép.

### 3.5. Ba chế độ chia sẻ linh hoạt (Configurable Filter Modes)
- `protected` (Mặc định): Bật toàn bộ lá chắn lọc `.gitignore`, chặn secret và cách ly dữ liệu nhạy cảm.
- `include-ignored` (`--include-ignored`): Chia sẻ cả file build/artifact bị gitignore, nhưng **vẫn giữ nguyên rào chắn chặn secret**.
- `none` (`--no-filter`): Chia sẻ thô cho máy tin cậy, nhưng **bất biến an toàn (Security Invariant)** luôn được bảo toàn: không bao giờ cho phép path traversal vượt ngục ra khỏi thư mục gốc (`resolve_safe_path`), không bao giờ để lộ thư mục cấu hình nội bộ `.slug/`.

---

## MỤC IV. ỨNG DỤNG TRÍ TUỆ NHÂN TẠO (AI) THỰC CHẤT

Slug không coi AI là "tính năng trang trí", mà ứng dụng AI giải quyết đúng 2 bài toán nhức nhối:

### 4.1. AI Guard: Phân tích ngữ cảnh & Phân biệt dữ liệu thử nghiệm
- **Vấn đề của Regex truyền thống:** Khi quét mã nguồn, regex thường báo lỗi hàng loạt chuỗi giả lập trong các file test unit (ví dụ `api_key = "sk-fake-test-key-123"`), làm sinh viên bối rối và có thói quen bỏ qua mọi cảnh báo.
- **Giải pháp của Slug:** Khi bật chế độ `-a / --ai`, Slug trích xuất đoạn ngữ cảnh và đưa qua mô hình AI để phân tích:
  - Phân biệt giữa dữ liệu giả lập vô hại trong thư mục `tests/` và khóa kết nối thật trong thư mục `src/`.
  - Giải thích bằng tiếng Việt thân thiện: chỉ rõ dòng code có nguy cơ, giải thích vì sao nguy hiểm và gợi ý cách đưa vào `.env`.
- **Nguyên tắc an toàn (Advisory Only):** AI chỉ đóng vai trò cố vấn. Các quy tắc cấm của chủ máy (trong `.slug/rules.conf`) luôn có hiệu lực tối thượng, AI không thể tự ý mở khóa các file vi phạm chính sách cứng.

### 4.2. Bộ nhớ đệm kiểm toán băm BLAKE3 (Stateful Audit Index)
- Việc gọi AI liên tục mỗi lần gõ lệnh sẽ làm chậm hệ thống và tốn chi phí token.
- Slug duy trì cơ sở dữ liệu trạng thái (`.slug/index.db`) gắn chặt với mã băm nội dung BLAKE3 của từng file.
- **Tối ưu thời gian:** File chưa bị sửa đổi sẽ lấy kết quả kiểm toán từ cache trong chưa đầy 1 mili-giây.
- **Chống sửa lén (Anti-TOCTOU):** Nếu người dùng sửa nội dung file, mã băm BLAKE3 thay đổi $\rightarrow$ trạng thái lập tức chuyển sang `STALE`, buộc phải kiểm tra lại trước khi cho phép chia sẻ qua mạng.

### 4.3. Dạy AI Agent dùng công cụ an toàn (Agent Directive)
- Khi chạy `slug env init`, Slug tự động tạo ra file chỉ thị `.slug/ai-rule.md` (và lệnh `slug env prompt`).
- Chỉ thị này hướng dẫn các AI Coding Agent (Cursor, Copilot): *"Trong repo này, secret đã được mã hóa an toàn trong `.env.pqc`. Đừng cố tìm hay tạo file `.env` trên đĩa. Hãy luôn chạy lệnh qua `slug env run -- <lệnh>`"*.
- Nhờ đó, AI tự giác tuân thủ quy trình bảo mật, không cố đọc trộm file cấu hình và không làm gãy quy trình test tự động.

---

## MỤC V. PHẢN BIỆN KỸ THUẬT VÀ TÍNH TRUNG THỰC KHOA HỌC

Để khẳng định tính nghiêm túc và trung thực khoa học trước Ban giám khảo, nhóm dự thi xin thẳng thắn làm rõ 4 điểm phản biện kỹ thuật:

### 1. "Chạy ứng dụng qua `slug env run` có bảo đảm 100% ứng dụng đều hoạt động không?"
- **Trả lời trung thực:** Đa số các ứng dụng và framework hiện đại (Node.js, Python, Go, Rust, C++) đều đọc từ biến môi trường trên RAM (`process.env`, `os.environ`) trước khi tìm file đĩa, nên sẽ chạy mượt mà qua `slug env run`.
- **Ranh giới:** Đối với các công cụ hoặc thư viện cá biệt bị lập trình cứng (hardcoded) bắt buộc phải `fopen("./.env")`, ứng dụng sẽ báo thiếu file. Trong tình huống này, Slug cung cấp giải pháp chuyển tiếp tiện lợi: sinh viên chỉ cần gõ `slug env restore` để lấy lại file `.env` từ Central Vault để làm việc, xong việc lại gõ `slug env init` để niêm phong lại.

### 2. "Gitleaks cũng quét được secret trong thư mục, vậy điểm khác của Slug là gì?"
- **Trả lời trung thực:** Gitleaks là công cụ quét tĩnh xuất sắc. Nhưng Gitleaks là công cụ kiểm tra độc lập, kết quả quét không hề liên kết với công cụ truyền file. Nếu lập trình viên quên chạy Gitleaks mà trực tiếp mở `http.server` hoặc gửi zip, secret vẫn lọt ra ngoài.
- **Điểm khác biệt:** Slug liên kết trực tiếp kết quả kiểm duyệt với hệ thống tệp ảo (`SlugVFS`). Việc kiểm tra và việc truyền tải nằm trong cùng một vòng khép kín: file chưa đạt kiểm duyệt sẽ bị VFS từ chối phục vụ ngay ở tầng đọc gói tin.

### 3. "Hàm băm BLAKE3 có bảo đảm file an toàn tuyệt đối không?"
- **Trả lời trung thực:** Không! BLAKE3 chỉ là hàm băm toàn vẹn nội dung, bản thân nó không nói lên file có chứa secret hay không.
- **Giá trị thực tế:** BLAKE3 trong Slug đóng vai trò làm **vô hiệu hóa bộ nhớ đệm (Cache Invalidation)**. Nó đảm bảo rằng trạng thái an toàn chỉ có hiệu lực với đúng phiên bản nội dung đã được quét; nếu một ký tự bị sửa đổi, trạng thái lập tức thành `STALE` và bắt buộc phải qua trạm kiểm soát lại.

### 4. "Mật mã hậu lượng tử ML-KEM-768 và mã OTP 8 số liên kết với nhau như thế nào?"
- **Trả lời trung thực:** ML-KEM-768 (NIST FIPS 203) là cơ chế đóng gói khóa để thiết lập kênh truyền mã hóa an toàn trước máy tính lượng tử. Nhưng KEM thuần túy không chứng minh được máy khách là bạn cùng nhóm của mình.
- **Cơ chế phối hợp:** Slug sử dụng mã OTP 8 số ngẫu nhiên (dựa trên RFC 6238 TOTP) trao đổi ngoài kênh (out-of-band) để xác thực người nhận. Khi client kết nối, mã OTP được gửi bên trong kênh PQC đã mã hóa và được máy chủ tiêu thụ theo cơ chế nguyên tử (Atomic Single-Use): dùng xong lập tức tự hủy, chống hoàn toàn tấn công phát lại (Replay Attack) và nghe lén (Man-in-the-Middle).

---

## MỤC VI. KỊCH BẢN THỰC NGHIỆM VÀ HƯỚNG DẪN DEMO 3 PHÚT

Nhóm dự thi đã chuẩn bị sẵn kịch bản trình diễn 3 phút cực kỳ thuyết phục và trực quan dành cho Ban giám khảo:

```text
+-----------------------------------------------------------------------------------+
| KỊCH BẢN TRÌNH DIỄN THỰC NGHIỆM TRONG 3 PHÚT (DEMO WALKTHROUGH)                   |
+-----------------------------------------------------------------------------------+

[PHÚT 1: BẢO VỆ BIẾN MÔI TRƯỜNG VỚI ENVSHIELD]
1. Mở thư mục dự án mẫu có chứa file `.env` với khóa OpenAI và Stripe thật.
2. Gõ lệnh: slug env init
   -> File `.env` biến mất khỏi thư mục dự án! Thay bằng `.env.pqc`.
   -> File gốc được cất an toàn tại ~/.slug/env_vault/.
3. Chạy test ứng dụng: slug env run -- pytest
   -> Bộ test pass! Chứng minh secret được nạp thẳng vào RAM mà không cần file đĩa.

[PHÚT 2: PHÁT HIỆN SECRET & AI GUARD PHÂN TÍCH]
1. Tạo một file mã nguồn mới `src/leak.py` dán một Google Gemini API key và một token giả.
2. Gõ lệnh: slug audit scan .
   -> Slug lập tức phát hiện độ hỗn loạn cao (Shannon Entropy = 4.2).
   -> AI Guard phân tích ngữ cảnh, giải thích bằng tiếng Việt file này có nguy cơ lộ lọt.
   -> Trạng thái file chuyển sang QUARANTINED.

[PHÚT 3: CHIA SẺ P2P KHÔNG LO RÁC VÀ KHÔNG LO LỘ BÍ MẬT]
1. Trên máy gửi, gõ: slug add .
   -> Terminal hiện banner màu sắc sinh động, thông báo tự động bỏ qua node_modules/.
   -> File `src/leak.py` bị cách ly, không có mặt trong danh sách chia sẻ.
   -> Xuất hiện link kèm mã OTP 8 chữ số.
2. Trên máy nhận, gõ: slug get <link> (hoặc mở trình duyệt Web Explorer).
   -> Nhận toàn bộ mã nguồn sạch chỉ trong 2 giây!
   -> Kiểm tra trên máy nhận: Hoàn toàn không có file rác node_modules/, không có .env
      và không có file `src/leak.py` bị cách ly.
3. Thử kết nối lại bằng mã OTP cũ:
   -> Máy chủ báo lỗi: "OTP already burned / expired" (Chống tấn công phát lại thành công!).
```

---

## MỤC VII. KẾT LUẬN VÀ CAM KẾT MÃ NGUỒN MỞ

Slug là một lời giải thực tế, trực diện và tinh gọn cho vấn đề bảo vệ mã nguồn của sinh viên và cộng đồng phát triển phần mềm trong thời đại AI:
1. **Đúng chủ đề SICT Innovation Challenge:** Giải quyết các vấn đề thực tế trong cả hai lĩnh vực **Phần mềm** (thao tác, dữ liệu, biến môi trường) và **Mạng** (kết nối P2P, băng thông, bảo mật đường truyền).
2. **Khả thi và hoàn thiện cao:** Sản phẩm là một ứng dụng C++20 hoàn chỉnh, chạy thực tế với hiệu năng cao, đóng gói 1 file duy nhất ~8MB.
3. **Ứng dụng AI có trách nhiệm:** Đưa AI vào đúng vị trí cần thiết (phân tích ngữ nghĩa, giải thích bằng ngôn ngữ tự nhiên, tiết kiệm token bằng cache), giữ vững các rào cản bảo mật xác định.

Toàn bộ mã nguồn, tài liệu kỹ thuật, hướng dẫn xây dựng và bản phát hành nhị phân được công khai minh bạch tại:
- **Repository chính thức:** [https://github.com/dotlinux26/slug](https://github.com/dotlinux26/slug)
- **Giấy phép bản quyền:** Apache License 2.0 (Mã nguồn mở phi lợi nhuận).
