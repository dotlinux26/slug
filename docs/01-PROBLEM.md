# THỰC TRẠNG VÀ CÁC ĐIỂM YẾU TRONG CHIA SẺ WORKSPACE HIỆN NAY

## 1. Đặt Vấn Đề

Trong quy trình phát triển phần mềm, thử nghiệm bảo mật (Red Team/Pentest), và vận hành hệ thống đám mây, nhu cầu chia sẻ nhanh một không gian làm việc (workspace) đang diễn ra liên tục:
- Chuyển giao mã nguồn đang sửa dở (uncommitted hotfix) giữa máy cá nhân và máy trạm (lab/staging VM).
- Gửi tài liệu nghiên cứu, file binary sau khi biên dịch, log phân tích sự cố cho đồng nghiệp trong mạng nội bộ hoặc qua Internet.
- Thiết lập môi trường chạy thử nghiệm tạm thời cho các công cụ lập trình tự động (AI Coding Agents).

Tuy nhiên, các phương thức truyền thống mà kỹ sư đang dùng hàng ngày đều bộc lộ những lỗ hổng bảo mật nghiêm trọng hoặc rào cản vận hành nặng nề.

---

## 2. Phân Tích Các Rủi Ro Điển Hình

### 2.1. Lỗ Hổng Từ `python3 -m http.server` Và Các Web Server Tạm Thời
Thói quen phổ biến nhất của lập trình viên khi cần gửi file nhanh là bật một HTTP server một dòng lệnh:
```bash
python3 -m http.server 8000
```
Phương thức này tiềm ẩn 5 nguy cơ chí mạng:
1. **Truyền dẫn bản rõ (Plaintext HTTP):** Toàn bộ dữ liệu, mã nguồn và token trong thư mục được truyền qua mạng không mã hóa. Bất kỳ ai trong cùng mạng Wi-Fi/LAN (sử dụng ARP Spoofing hoặc Wireshark) đều có thể thu thập toàn bộ nội dung.
2. **Không có cơ chế xác thực (Zero Authentication):** Bất kỳ thiết bị nào dò quét dải IP nội bộ đều có thể truy cập, duyệt và tải toàn bộ thư mục.
3. **Nguy cơ duyệt thư mục trái phép (Directory Traversal):** Nếu server chạy từ thư mục gốc hoặc có symbolic link trỏ ra ngoài, kẻ tấn công có thể đọc trộm các file nhạy cảm của hệ thống như `/etc/passwd` hoặc `~/.ssh/id_rsa`.
4. **Quên tắt tiến trình (Zombie Servers):** Server thường bị bỏ quên chạy ngầm trong nhiều ngày, biến thành một cửa hậu vĩnh viễn trong mạng nội bộ.
5. **Thiếu khả năng tải lên có kiểm soát:** Máy chủ HTTP cơ bản chỉ cho phép tải về một chiều, không hỗ trợ nhận file ngược lại một cách an toàn.

### 2.2. Sự Nặng Nề Và Dấu Vết Lịch Sử Của Git Cho Nhu Cầu Tạm Thời
Git là hệ thống quản lý phiên bản phân tán tuyệt vời, nhưng không được thiết kế cho nhu cầu chia sẻ không gian làm việc ngắn hạn:
1. **Ô nhiễm lịch sử Commit (History Pollution):** Để chuyển vài file thử nghiệm, kỹ sư phải tạo commit tạm (`git commit -m "wip"`), đẩy lên nhánh riêng trên remote repository, rồi sau đó phải rebase hoặc xóa nhánh.
2. **Nguy cơ rò rỉ khóa bí mật vào Git Tree:** Các file cấu hình như `.env`, khóa API, chứng chỉ SSL thường vô tình bị `git add .` gom vào commit. Ngay cả khi đã sửa bằng commit sau, các secret này vẫn nằm vĩnh viễn trong lịch sử git object trừ khi dùng các công cụ rewrite lịch sử phức tạp.
3. **Phụ thuộc vào máy chủ trung gian (Centralized Remote):** Cả hai máy đều phải có quyền truy cập chung vào GitHub/GitLab, đòi hỏi cấu hình SSH Key hoặc Personal Access Token phức tạp.
4. **Không tối ưu cho file nhị phân lớn:** Git xử lý kém đối với các file build artifact, dataset hoặc mô hình máy học (yêu cầu cài đặt Git LFS phức tạp).

### 2.3. Rào Cản Phân Quyền Của SSH / SCP / rsync
Khi sử dụng `scp` hoặc `rsync -avz` qua giao thức SSH:
1. **Đòi hỏi quyền truy cập tài khoản hệ điều hành:** Để nhận file, máy đích phải có tài khoản người dùng Linux và cấu hình SSH public key.
2. **Nguy cơ cấp thừa quyền (Over-privileged Access):** Việc cấp quyền SSH thường đồng nghĩa với việc mở toàn bộ quyền truy cập shell và đọc được các file khác ngoài phạm vi chia sẻ.
3. **Tài khoản mồ côi (Orphaned Accounts):** Sau các buổi chuyển giao dữ liệu ngắn hạn (1-2 giờ), quản trị viên thường quên thu hồi khóa SSH hoặc tài khoản tạm, để lại bề mặt tấn công lâu dài.

### 2.4. Đám Mây Bên Thứ Ba (Google Drive, Dropbox, WeTransfer)
1. **Mất chủ quyền dữ liệu (Data Sovereignty):** Mã nguồn độc quyền và tài liệu mật của doanh nghiệp bị tải lên hạ tầng bên thứ ba, vi phạm các tiêu chuẩn tuân thủ (SOC2, ISO 27001, GDPR).
2. **Tồn lưu bộ nhớ đệm (Cloud Cache):** Các bản sao không được mã hóa ở mức ứng dụng vẫn lưu lại trên máy chủ đám mây sau khi phiên làm việc kết thúc.

### 2.5. Rủi Ro Mới Từ Kỷ Nguyên Trợ Lý Lập Trình AI (AI Coding Assistants)
Sự bùng nổ của các IDE tích hợp AI (Cursor, GitHub Copilot Workspace, Claude Dev, Antigravity) tạo ra bề mặt rò rỉ thông tin mới:
1. **Tự động đọc toàn bộ Workspace:** Các agent AI liên tục quét lập chỉ mục toàn bộ thư mục dự án để làm context cho mô hình ngôn ngữ lớn (LLM).
2. **Vô tình gửi Secret về máy chủ AI:** File `.env` chứa token production (OpenAI API key, Stripe secret, AWS credentials, Database passwords) có thể bị gửi về máy chủ đám mây của nhà cung cấp AI qua telemetry hoặc context prompt.
3. **Thiếu cơ chế che chắn ở mức bộ nhớ RAM:** Lập trình viên thiếu công cụ cách ly biến môi trường nhạy cảm trong lúc chạy ứng dụng thử nghiệm.

---

## 3. Tổng Hợp Ma Trận Điểm Yếu

| Tiêu chí | `python -m http.server` | Git Remote | SSH / rsync | Cloud Drive | Nhu Cầu Lý Tưởng |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Mã hóa đường truyền** | Không | TLS | SSHv2 | TLS | Hậu lượng tử (PQC) |
| **Bảo vệ chống nghe lén LAN** | 0% | Phụ thuộc TLS | 100% | 100% | 100% (AEAD Full-Duplex) |
| **Xác thực tự hủy (One-Time Burn)** | Không | Không | Không | Không | TOTP tự hủy sau 1 lần |
| **Phân quyền vai trò (RBAC)** | Không | Phân theo Repo | Quyền OS | Quyền Folder | Granular (`r`, `w`, `rw`) |
| **Thời hạn sống (TTL)** | Vĩnh viễn đến khi kill | Vĩnh viễn | Vĩnh viễn | Thủ công | Tự động hủy (`1h`, `1d`, ...) |
| **Chống rò rỉ AI Secret** | Không | Bị lộ | Không | Không | Quét heuristic & Shannon entropy |
| **Cách ly biến môi trường RAM** | Không | Không | Không | Không | PQC EnvShield RAM-Only |
| **Trải nghiệm sử dụng** | 1 lệnh đơn | Phức tạp (nhiều bước) | Cần setup SSH | Cần trình duyệt | One-shot (`slug get`) |

---

## 4. Mục Tiêu Thiết Kế Của Slug

Từ các phân tích trên, dự án **Slug** được xây dựng với mục tiêu định nghĩa lại chuẩn mực chia sẻ workspace:
1. **Bảo mật tuyệt đối mặc định:** Sử dụng chuẩn mã hóa hậu lượng tử (NIST FIPS 203 / 204) kết hợp AEAD XChaCha20-Poly1305.
2. **Cơ chế xác thực ngắn hạn:** 3 mã TOTP phân quyền (`rw`, `r`, `w`) tự động làm mới và tự hủy sau khi sử dụng; các tài khoản khách tự hết hạn theo TTL.
3. **Kiểm duyệt bí mật chủ động:** Ngăn chặn tuyệt đối việc chia sẻ nhầm các secret hoặc để AI agent đọc trộm file `.env`.
4. **Trải nghiệm tức thì ("Mì ăn liền như AirDrop"):** Tinh gọn luồng làm việc thành lệnh một chạm `slug get` hoặc kéo thả trực quan trên Web UI.
