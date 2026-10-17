# 02. Giải pháp và Các Kịch Bản Ứng Dụng Thực Tế của Slug

> **Định vị sản phẩm:** Công cụ chia sẻ tệp tin và kiểm soát mã nguồn an toàn cục bộ, bảo vệ bí mật trước các trợ lý AI.  
> **Hình thức sản phẩm:** Ứng dụng dòng lệnh (CLI Tool) đa nền tảng viết bằng C++20, đóng gói 1 file thực thi duy nhất (~8MB, zero-dependency) tích hợp Web Portal cục bộ.

---

## 1. Triết lý thiết kế: Tối giản bên ngoài, Chắc chắn bên trong

Một sản phẩm công nghệ thực tiễn dành cho sinh viên, giảng viên và kỹ sư phần mềm phải dễ sử dụng như các công cụ quen thuộc hằng ngày (`git`, `npm`, `python`), không bắt người dùng phải cấu hình máy chủ phức tạp hay nhớ hàng chục tham số rườm rà.

Slug chuẩn hóa toàn bộ quy trình kiểm soát và chia sẻ tệp tin thành **Quy trình 3 bước trực quan**:

```text
+-----------------------------------------------------------------------------------+
| QUY TRÌNH 3 BƯỚC BẢO VỆ VÀ CHIA SẺ VỚI SLUG                                       |
+-----------------------------------------------------------------------------------+

  [BƯỚC 1: KIỂM TOÁN NỘI DUNG (SLUG AUDIT)]
       slug audit scan .
       ├── Quét heuristic và Shannon Entropy tìm API keys, tokens, credentials
       └── AI Semantic Guard đọc ngữ cảnh, cảnh báo mức độ rủi ro của từng file
                                     |
                                     v
  [BƯỚC 2: NIÊM PHONG BÍ MẬT & CHẠY AN TOÀN (ENVSHIELD)]
       slug env init  --->  slug env run -- <lệnh test / start>
       ├── Cất file .env vào Central Vault (~/.slug/env_vault/)
       ├── Khóa lại thành file mã hóa .env.pqc trong repo
       └── Nạp biến môi trường thẳng vào RAM tiến trình khi chạy, không để plaintext trên đĩa
                                     |
                                     v
  [BƯỚC 3: CHIA SẺ NỘI BỘ LAN / P2P THEO VAI TRÒ & 4 CẤP ĐỘ LỌC]
       slug add .  --->  slug pull -i <host> -p <port> -o <otp>
       ├── Tự động lọc bỏ rác build (node_modules/, target/, build/) theo .gitignore
       ├── Hệ thống 4 cấp độ lọc: Level 1 (Rules), Level 2 (Regex), Level 3 (Entropy), Level 4 (AI)
       ├── Hỗ trợ luật cấu hình của Host qua .slug/rules.conf và ngoại lệ Whitelist (!.env.example)
       ├── Tự động bảo toàn cấu trúc cây thư mục (Directory Visibility Invariant: AVAILABLE / BLOCKED)
       └── Kênh truyền P2P mã hóa Hậu Lượng Tử (PQC), xác thực bằng OTP xoay vòng linh hoạt hoặc RBAC
```

---

## 2. Các Kịch Bản Đời Thường Thực Tế (Real-World Use Cases)

### Kịch Bản 1: Chuyển Tệp Lớn Trong Mạng LAN Văn Phòng / Trường Học
- **Tình huống:** Hai đồng nghiệp trong văn phòng công ty hoặc hai sinh viên trong phòng lab cần chuyển cho nhau tệp đồ án, tài liệu thiết kế hoặc video dung lượng vài GB.
- **Cách làm cũ:** Tải lên Google Drive hoặc gửi qua Zalo. Mất hàng chục phút để upload lên server bên thứ ba rồi lại tải xuống, ngốn băng thông đường truyền WAN của trường/công ty.
- **Giải pháp với Slug:**
  1. Người gửi mở chia sẻ thư mục:
     ```bash
     slug add ./tailieu -p 9443
     ```
  2. Người nhận kéo trực tiếp qua mạng LAN chỉ trong vài giây (tốc độ đạt trần băng thông LAN/Wi-Fi):
     ```bash
     # Đồng bộ toàn bộ thư mục bằng CLI:
     slug pull -i 192.168.1.105 -p 9443 -o 12822565 --to ./tailieu

     # Hoặc tải 1 file đơn lẻ cụ thể:
     slug get 192.168.1.105:9443?otp=12822565 bao_cao.pdf ./bao_cao.pdf

     # Hoặc mở giao diện Web Viewing Engine cục bộ trên máy mình (gõ 'slug' -> http://127.0.0.1:8080/):
     # Kết nối tới 192.168.1.105:9443 bằng OTP và nhấn "Tải ZIP Toàn Bộ Thư Mục"
     ```
  - **Lợi ích:** 0 byte băng thông Internet (WAN), không phụ thuộc bên thứ ba, bảo mật hai đầu bằng mật mã Hậu Lượng Tử NIST FIPS 203 (ML-KEM-768). Tuyệt đối Zero Remote HTTP trên mạng!

---

### Kịch Bản 2: Thu Bài Tập Phòng Máy Sinh Viên Gọn Nhẹ (Write-Only / Blind Drop)
- **Tình huống:** Giảng viên cần thu bài thi / bài tập thực hành của 40 sinh viên trong phòng máy. Giảng viên muốn sinh viên có thể nộp bài nhanh nhưng **không thể xem hay tải bài của nhau về chép**.
- **Cách làm cũ:**
  - Dùng Google Form/Drive: Máy trường học nghẽn mạng WAN; sinh viên phải đăng nhập tài khoản cá nhân trên máy công cộng.
  - Dùng `python -m http.server`: Không hỗ trợ upload. Nếu dùng script upload thì ai cũng nhìn thấy và tải được bài của bạn khác về.
  - Dùng FTP/SMB: Cấu hình phức tạp, cần tạo tài khoản user hệ thống, phân quyền thư mục cồng kềnh.
- **Giải pháp với Slug:**
  1. Giảng viên chỉ cần gõ 1 lệnh khởi tạo trạm thu bài:
     ```bash
     slug add ./nop_bai -p 9443
     ```
  2. Giảng viên cấp tài khoản chung quyền Ghi (`[w]` Write-Only / Nộp bài) cho sinh viên:
     - Giảng viên tạo nhanh tài khoản chung (hoặc tài khoản lớp) trên Web Trạm Điều Khiển hoặc qua lệnh CLI (ví dụ: username `sinhvien` với vai trò `[w] Write-Only`) để cả lớp cùng đăng nhập nộp bài đồng thời mà không bị giới hạn 1 máy.
     - *(Lưu ý: Mã OTP 8 chữ số là vé định danh bảo mật dùng một lần cho từng phiên/1 máy riêng lẻ; đối với lớp học đông người, cơ chế tài khoản RBAC chung với quyền `[w]` giúp toàn bộ 40–50 sinh viên cùng nộp bài thuận tiện).*
  3. Sinh viên mở trình duyệt Web hoặc dùng lệnh nộp bài:
     - Sinh viên đăng nhập tài khoản chung rồi kéo thả bài làm vào Web Dropbox hoặc gõ `slug push`.
     - **Cơ chế VFS Jail & RBAC:** Tầng hệ thống tập tin ảo của Slug cưỡng chế quyền `WRITE_ONLY`. Sinh viên chỉ được phép ghi file lên server, **hoàn toàn bị cấm liệt kê thư mục (`list_dir`) hoặc đọc tệp (`read_file`)**.
  - **Lợi ích:** Thu bài cực kỳ gọn nhẹ, zero-setup, chống nhìn trộm bài thi triệt để, hoạt động mượt mà ngay cả khi phòng máy mất kết nối Internet quốc tế.

---

### Kịch Bản 3: Chia Sẻ Thư Mục Mã Nguồn Dự Án Không Lo Lộ Secret Hay Thừa Rác
- **Tình huống:** Lập trình viên cần gửi nhanh thư mục mã nguồn đang viết dở cho bạn cùng nhóm để hỗ trợ gỡ lỗi (debug).
- **Rủi ro thường gặp:** Thư mục chứa file cấu hình `.env` có API key thật, hoặc chứa thư mục `node_modules/` nặng cả GB. Nếu nén ZIP gửi đi, người nhận tải rất lâu và người gửi có nguy cơ lộ token thanh toán / API key cloud.
- **Giải pháp với Slug:**
  - Khi chạy `slug add .`, hệ thống **Slug Guard** tự động kích hoạt:
    1. **Tự động lọc rác build:** Đọc file `.gitignore` để loại bỏ các thư mục `node_modules/`, `target/`, `build/`.
    2. **Rà soát secret đa cơ chế:** Quét qua bộ lọc Heuristic & Shannon Entropy. Nếu phát hiện chuỗi token có độ ngẫu nhiên cao hoặc file nghi vấn, hệ thống tự động gắn cờ cách ly (`QUARANTINED`), ngăn không cho đối tác tải về.
    3. **AI Semantic Guard:** Hỗ trợ phân tích ngữ cảnh để phân biệt giữa mock key trong file test và API key thật sự.
  - **Lợi ích:** Đồng đội nhận được mã nguồn sạch sẽ, không bị nghẽn mạng vì rác build, và người gửi an tâm rằng các khóa bí mật đã được kiểm duyệt và cách ly an toàn.

---

### Kịch Bản 4: Làm Việc Với Trợ Lý AI Lập Trình Mà Không Bị Đọc Trộm Bí Mật (EnvShield)
- **Tình huống:** Lập trình viên dùng Cursor, Copilot hoặc Claude Code để phát triển ứng dụng gọi LLM API hoặc kết nối cơ sở dữ liệu.
- **Rủi ro:** Trợ lý AI liên tục quét và đọc các tệp plaintext trên đĩa để nạp context window gửi về server cloud của bên thứ ba, làm lộ API key.
- **Giải pháp với Slug EnvShield:**
  ```bash
  slug env init                 # Cất .env vào ~/.slug/env_vault/, mã hóa thành .env.pqc, xóa plaintext trên đĩa
  slug env prompt               # Sinh chỉ thị chuẩn cho AI agent (lưu vào .slug/ai-rule.md)
  slug env run -- npm test      # Giải mã trực tiếp trong RAM và nạp biến môi trường lúc chạy
  slug env restore              # Khôi phục lại .env bản rõ khi cần cấu hình lại
  ```
  - **Lợi ích:** Tạo ra rào cản ma sát chủ động (friction barrier) ngăn chặn AI đọc trộm secret từ ổ đĩa, trong khi tiến trình test và run vẫn chạy bình thường với 100% biến môi trường được cấp từ RAM.

---

## 3. Bảng So Sánh Toàn Diện Giữa Slug và Các Công Cụ Khác

| Tiêu chí | `python -m http.server` | FTP / SFTP | Google Drive / Zalo | **Slug** |
| :--- | :---: | :---: | :---: | :---: |
| **Bảo mật kênh truyền (Wire Security)** | ❌ Plaintext (HTTP) | ⚠️ SFTP có TLS/SSH, FTP là bản rõ | ⚠️ TLS tới Cloud bên thứ ba | ✅ **100% PQC AEAD** (ML-KEM-768 + XChaCha20) |
| **Băng thông & Tốc độ** | ✅ Tối đa LAN | ✅ Tối đa LAN | ❌ Phụ thuộc tốc độ WAN Internet | ✅ **Tối đa LAN gigabit (0 byte WAN)** |
| **Cài đặt & Thiết lập** | ✅ Cực nhanh (cần Python) | ❌ Rất phức tạp (cần root/admin) | ⚠️ Cần tài khoản, login mạng | ✅ **1 file nhị phân (~8MB, zero-setup)** |
| **Phân quyền nộp bài (Write-Only)** | ❌ Không có | ⚠️ Cấu hình quyền thư mục phức tạp | ❌ Khó kiểm soát bài nộp chép nhau | ✅ **Hỗ trợ sẵn OTP quyền Ghi `[w]` (Blind Drop)** |
| **Nhận thức cấu trúc dự án** | ❌ Không (gửi cả rác build) | ❌ Không (gửi nguyên thư mục) | ❌ Không (phải tự nén thủ công) | ✅ **Tự động đọc `.gitignore` lọc rác build** |
| **Kiểm duyệt bí mật (Secret Scanner)** | ❌ Không (lộ sạch `.env`) | ❌ Không có | ❌ Không có | ✅ **Slug Guard (Entropy + AI Semantic Guard)** |
| **Bảo vệ RAM cho tiến trình chạy AI** | ❌ Không có | ❌ Không có | ❌ Không có | ✅ **PQC EnvShield (RAM-Only Injection)** |

---

## 4. Tôn Chỉ "Nói Đúng - Nói Đủ - Không Overclaim"

Slug cam kết tính trung thực và minh bạch trong mọi tài liệu kỹ thuật:
1. **Không thần thánh hóa AI:** AI trong Slug không thể "đoán mò" hay "ngăn chặn 100% mọi lỗi lập trình". AI chỉ đóng vai trò là một người cố vấn ngữ cảnh (Advisor) hỗ trợ phân loại mức độ rủi ro của các chuỗi bí mật nghi vấn.
2. **Quyền quyết định tối thượng thuộc về người dùng:** Mọi quyết định gắn cờ của AI đều có thể được người dùng phê duyệt hoặc bỏ qua thông qua lệnh `slug audit allow`.
3. **Thẳng thắn về giới hạn bộ nhớ:** Slug EnvShield bảo vệ secret khỏi sự quét ngầm của AI từ đĩa cứng. Khi ứng dụng chạy, biến môi trường hiển nhiên tồn tại trong RAM; nếu người dùng cố tình viết code `printenv` để trích xuất thì dữ liệu vẫn sẽ hiển thị.
4. **Không phóng đại hiệu năng mạng:** Lệnh `slug bench` chỉ đo hiệu năng CPU mật mã (ML-KEM, BLAKE3, ChaCha20), tốc độ phân mảnh vi sai In-Memory và tốc độ đọc ghi đĩa vật lý của máy; tốc độ truyền mạng thực tế phụ thuộc vào hạ tầng đường truyền giữa hai máy.
