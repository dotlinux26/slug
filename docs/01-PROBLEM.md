# 01. Đặt vấn đề và Nhu cầu thực tế

> **Đơn vị dự thi:** Đội thi SICT Innovation Challenge 2026 — Track: Tech Your Solutions (Trường CNTT&TT — Đại học Công nghiệp Hà Nội)  
> **Lĩnh vực giải pháp:** Phần mềm (Quy trình làm việc & Quản lý dữ liệu) & Mạng (Chia sẻ cục bộ P2P & Bảo vệ biên dữ liệu)

---

## 1. Bối cảnh: Các kịch bản đời thường trong học tập, văn phòng và phát triển phần mềm

Trong sinh hoạt công nghệ hàng ngày tại trường học, phòng thực hành máy tính (lab) và môi trường văn phòng công ty, nhu cầu trao đổi tệp tin và mã nguồn diễn ra liên tục với các kịch bản rất đỗi quen thuộc:

1. **Chuyển tệp tin và dữ liệu lớn qua mạng LAN nội bộ:**
   - Trong cùng một phòng lab, giảng đường hoặc văn phòng công ty, hạ tầng mạng nội bộ (LAN/Wi-Fi) thường đạt tốc độ rất cao (1 Gbps = ~125 MB/s). Tuy nhiên, khi cần chuyển một tệp dữ liệu lớn, một video tài liệu hay một thư mục dự án, người dùng thường có thói quen tải lên Google Drive, gửi qua Zalo, Telegram hoặc WeTransfer.
   - **Hậu quả:** Lãng phí băng thông đường truyền quốc tế (WAN) của đơn vị; tắc nghẽn mạng chung; bị giới hạn dung lượng tải tệp; và đặc biệt là dữ liệu nội bộ bị lưu chuyển qua máy chủ trung gian của bên thứ ba.
2. **Bài toán thu bài thi và bài tập sinh viên trong phòng máy thực hành:**
   - Trong một buổi thi thực hành hoặc kết thúc giờ làm bài tập lớn, giảng viên cần thu bài của 40–50 sinh viên cùng lúc một cách nhanh gọn, công bằng.
   - Nếu bắt sinh viên nộp qua Google Form/Email: Mạng phòng máy dễ bị nghẽn đường truyền WAN khi hàng chục máy cùng tải lên tệp nén hàng chục MB; sinh viên tốn thời gian đăng nhập tài khoản cá nhân trên máy tính công cộng của trường.
   - Nếu giáo viên chia sẻ thư mục qua mạng LAN: Rất khó để kiểm soát việc sinh viên nhìn thấy bài của nhau hoặc sao chép bài của bạn trước khi nộp.
3. **Lập trình viên làm việc cùng các trợ lý AI và làm việc nhóm:**
   - Sinh viên và kỹ sư phần mềm thường xuyên dùng các trợ lý AI (GitHub Copilot, Cursor, Claude Code) để code. Quá trình này đòi hỏi phải tạo các API key, token (`OPENAI_API_KEY`, `GEMINI_API_KEY`, Stripe, DB Connection String) lưu trong file `.env` hoặc file cấu hình cục bộ.
   - Khi làm việc nhóm, việc nén nhanh cả thư mục đang code dở để gửi cho bạn bè gỡ lỗi (debug) rất dễ kéo theo cả các file bí mật hoặc hàng trăm MB thư mục rác build (`node_modules/`, `target/`, `build/`).
4. **Yêu cầu công khai mã nguồn (Public Repository):**
   - Khi nộp đồ án môn học hoặc tham gia các cuộc thi công nghệ (như chính quy chế SICT Innovation Challenge yêu cầu mọi đội thi phải mở repository công khai trên GitHub của Ban tổ chức), việc sơ suất commit nhầm một file cấu hình nhạy cảm sẽ khiến toàn bộ khóa API bị lộ ra toàn thế giới.

---

## 2. Điểm nghẽn của các giải pháp truyền thống

| Phương thức truyền thống | Điểm nghẽn thực tế & Rủi ro |
| :--- | :--- |
| **`python -m http.server 8000`** | - **Không mã hóa (Plaintext):** Bất kỳ ai trong cùng mạng Wi-Fi trường học/văn phòng đều có thể bắt gói tin (sniffing) và lấy toàn bộ nội dung.<br>- **Không phân quyền:** Ai có địa chỉ IP và cổng đều tải được mọi thứ.<br>- **Không hỗ trợ nộp bài (Blind Drop):** Chỉ hỗ trợ tải xuống (download). Nếu viết thêm script upload thì ai cũng xem và tải được file người khác vừa nộp.<br>- **Không kiểm duyệt:** Mở từ thư mục nào là phơi bày toàn bộ file ẩn, `.env` hoặc file nhạy cảm trong thư mục đó. |
| **SFTP / FTP / SMB (Windows Share)** | - **Cấu hình cồng kềnh:** Đòi hỏi quyền quản trị viên (Admin/Root), tạo tài khoản người dùng hệ thống (User Accounts), mở port tường lửa phức tạp.<br>- **Thiếu cơ động (Ephemeral):** Thích hợp cho hạ tầng cố định, không phù hợp cho nhu cầu chia sẻ nhanh vài phút giữa hai máy tính cá nhân.<br>- **Không có khả năng kiểm soát nội dung chủ động:** Chỉ đóng vai trò "đường ống truyền dẫn thô", không hiểu cấu trúc dự án (`.gitignore`) và không có cơ chế cảnh báo file bí mật. |
| **Cloud trung gian (Google Drive, Zalo, OneDrive)** | - **Lãng phí băng thông WAN:** Hai máy tính ngồi cạnh nhau trong cùng 1 phòng nhưng tệp tin phải đi vòng ra ngoài Internet tới máy chủ bên thứ ba rồi mới tải về lại.<br>- **Rủi ro lộ bí mật và chính sách riêng tư:** Dữ liệu nội bộ, khóa bí mật công ty bị đẩy lên server của bên thứ ba.<br>- **Giới hạn tốc độ & dung lượng:** Bị bóp băng thông, giới hạn file nén lớn. |

---

## 3. Các vấn đề cốt lõi mà Slug tập trung giải quyết

### 3.1. Rủi ro lộ lọt khóa bí mật và credential (Secret Leakage)
- **Thực trạng:** Tệp `.env`, file private key, token xác thực thử nghiệm rất dễ bị bỏ quên trong thư mục dự án. Sinh viên hoặc lập trình viên chỉ cần một lần gõ `git add .` rồi `git push`, hoặc nén nhầm cả thư mục thành file ZIP gửi cho người khác, là toàn bộ khóa API đã bị lộ ra ngoài.
- **Hậu quả:** Khóa API bị bot quét tự động vét sạch trong vòng vài chục giây sau khi lên GitHub public; tài khoản đám mây bị trừ tiền ngoài ý muốn (hóa đơn hàng triệu đến hàng chục triệu đồng), tài khoản bị khóa, hoặc dữ liệu thử nghiệm bị rò rỉ.

### 3.2. Trợ lý AI tự động đọc trộm file cấu hình nhạy cảm trên đĩa cứng
- Khi lập trình viên mở workspace trong các IDE tích hợp AI, AI agent tự động quét và lập chỉ mục (index) toàn bộ các file văn bản trong thư mục để nạp ngữ cảnh vào Context Window gửi lên cloud.
- Nếu file `.env` nằm dạng văn bản rõ (plaintext) trên đĩa cứng, AI sẽ vô tình đọc trọn vẹn các secret này và gửi kèm trong các request gửi về máy chủ AI cloud, tạo ra nguy cơ rò rỉ thông tin cấu hình nội bộ.

### 3.3. Rác build và ô nhiễm đường truyền khi chia sẻ thư mục
- Một dự án web hoặc phần mềm hiện đại thường đi kèm các thư mục build cực kỳ nặng nề: `node_modules/` (hàng trăm MB đến vài GB), `build/`, `dist/`, `target/`, `.venv/`.
- Khi người dùng nén cả thư mục hoặc bật HTTP server để gửi cho người khác, họ lãng phí băng thông và thời gian để truyền đi hàng chục nghìn file rác mà máy người nhận hoàn toàn có thể tự tạo lại (`npm install`).

### 3.4. Thiếu một cơ chế thu nộp dữ liệu gọn nhẹ, an toàn trong mạng nội bộ
- Giảng viên trong phòng lab hoặc trưởng nhóm trong văn phòng cần một công cụ **thu bài / nhận tệp một chiều (Write-Only / Blind Drop)**: Người nộp chỉ có quyền đẩy tệp lên, không có quyền duyệt cây thư mục hoặc tải bài của người khác về.

---

## 4. Định vị của Slug trong SICT Innovation Challenge

Slug không cố gắng phát minh lại các nguyên lý mã hóa hay công cụ quét mã độc quy mô lớn. **Slug là một giải pháp kỹ thuật thực tế, tinh gọn (~10MB, 1 file nhị phân tĩnh duy nhất, zero-dependency), hỗ trợ sinh viên, giảng viên và kỹ sư phần mềm giải quyết trọn vẹn các nhu cầu thường nhật:**

```text
+-----------------------------------------------------------------------------------+
| SLUG — CÔNG CỤ CHIA SẺ VÀ BẢO VỆ DỮ LIỆU CỤC BỘ TRONG KỶ NGUYÊN AI                |
+-----------------------------------------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        v                                 v                                 v
[1. CHIA SẺ P2P LAN AN TOÀN]     [2. KIỂM SOÁT NỘI DUNG CHỦ ĐỘNG] [3. LÁ CHẮN AI ENVSHIELD]
Truyền file nội bộ gigabit,      Tự lọc bỏ rác build (.gitignore), Niêm phong .env vào Vault,
mã hóa Hậu Lượng Tử (PQC),       rà soát secret entropy cao, luật  nạp biến vào RAM lúc chạy,
OTP 1 lần, tài khoản chung lớp   Whitelist (!.env.example) và      không để plaintext trên đĩa
Write-Only để thu bài gọn nhẹ.   Slug AI cố vấn cảnh báo.          cho AI đọc trộm.
```

---

## 5. Bảng Tổng Hợp Thông Tin Hỗ Trợ Hội Đồng Giám Khảo Rà Soát

Nhằm hỗ trợ Hội đồng Ban giám khảo cuộc thi **SICT Innovation Challenge (“Tech Your Solutions” — Trường CNTT&TT, Đại học Công nghiệp Hà Nội)** thuận tiện trong quá trình thẩm định và đối chiếu giải pháp, nhóm dự thi tổng hợp các luận điểm kỹ thuật tương ứng với 4 khía cạnh đánh giá của vòng sơ khảo:

| Khía cạnh đánh giá | Thực trạng & Cách tiếp cận của Slug | Minh chứng kỹ thuật & File tài liệu liên quan |
| :--- | :--- | :--- |
| **1. Mức độ cần thiết & Thực tế của vấn đề** | Giải quyết trực tiếp các nhu cầu phát sinh hàng ngày trong môi trường trường học và văn phòng:<br>• Chuyển tệp nội bộ gigabit, không tiêu hao băng thông Internet đối với dữ liệu nội bộ, không qua máy chủ bên thứ ba.<br>• Thu bài tập sinh viên phòng máy một chạm, chống nhìn trộm bài chép.<br>• Ngăn chặn nguy cơ lộ API key/token khi làm việc với AI hoặc đưa repo lên GitHub. | • [01-PROBLEM.md](01-PROBLEM.md)<br>• Bảng phân tích lỗ hổng của `python -m http.server`, FTP/SFTP và Cloud Drive ở Mục 2. |
| **2. Tính khả thi của ý tưởng & mức độ hoàn thiện** | • Đóng gói thành **1 file thực thi nhị phân duy nhất (~10MB)**, zero-dependency, không cần cài đặt Python, Node.js hay database.<br>• Chạy thực tế mượt mà trên cả Linux và Windows.<br>• Hỗ trợ cả giao diện dòng lệnh POSIX (`slug pull/get/push`) lẫn Web Viewing Engine nội bộ (`127.0.0.1:8081/`). | • [02-SOLUTION.md](02-SOLUTION.md)<br>• [BUILD.md](../BUILD.md)<br>• Bản phát hành nhị phân có sẵn trong Releases. |
| **3. Tính sáng tạo & Điểm khác biệt** | • **Khắc phục nhược điểm của `python http.server`:** Thay thế đường truyền plain HTTP bằng kênh PQC AEAD nhị phân; bổ sung phân quyền OTP 3 vai trò (`[rw]`, `[r]`, `[w]`).<br>• **Khác biệt so với FTP/SFTP:** Có khả năng kiểm soát nội dung chủ động (Selective Staging) tự động lọc rác build theo `.gitignore` và quy tắc Whitelist ngoại lệ (`!.env.example`).<br>• **Sáng tạo với PQC EnvShield:** Nạp biến môi trường vào RAM lúc chạy test/start, không để plaintext trên đĩa cho AI đọc trộm. | • [04-ARCHITECTURE.md](04-ARCHITECTURE.md)<br>• [MODULE-MAP.md](MODULE-MAP.md)<br>• Kiến trúc đóng khung Directional AEAD và VFS Jail. |
| **4. Ứng dụng AI & Giá trị thực tế mang lại** | • Định vị kỹ thuật: **Slug Guard** là chốt chặn xác định chạy offline (Regex + Shannon Entropy $H(X) \ge 4.0$).<br>• **Slug AI** là lớp cố vấn tùy chọn (`--ai`), trả về schema JSON (`has_secret`, `reason`, `line`) để tham vấn ngữ cảnh, không thay thế cơ chế xác định của Slug Guard.<br>• Tối ưu hiệu năng bằng bộ nhớ đệm trạng thái BLAKE3 (`index.db`), không quét lại file cũ.<br>• Dạy AI coding agent cách thực thi lệnh qua công cụ (`slug env run`). | • [03-AI-USAGE.md](03-AI-USAGE.md)<br>• Module `src/ai/stateful_audit.hpp` và `src/ai/scanner.cpp`. |


