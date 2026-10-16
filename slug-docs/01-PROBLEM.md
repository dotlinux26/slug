# 01. Đặt vấn đề thực tế: Bài toán chia sẻ dữ liệu trong phòng máy trường học

> **Đơn vị dự thi:** Đội thi SICT Innovation Challenge 2026 — Track: Tech Your Solutions (Đại học Công nghiệp Hà Nội)  
> **Lĩnh vực giải pháp:** Mạng (Kết nối LAN trực tiếp, Băng thông, Bảo mật kênh truyền) & Phần mềm (Thao tác người dùng, Lọc dữ liệu, Bảo vệ bí mật mã nguồn)

---

## 1. Một tình huống rất "đời" trong môi trường học tập

Hãy hình dung một tình huống diễn ra hàng ngày tại các phòng máy thực hành CNTT, phòng lab nghiên cứu hoặc khu ký túc xá:

> **Sinh viên ngồi tại Máy A muốn gửi nhanh một thư mục bài tập lớn, đồ án môn học hoặc dữ liệu thử nghiệm cho bạn ngồi tại Máy B (hoặc gửi cho thầy cô/mentor để nhờ kiểm tra lỗi).**

Các máy tính trong phòng máy được nối với nhau qua switch theo **mô hình mạng hình sao (Star Topology)**. Về mặt vật lý, hai máy chỉ cách nhau vài mét cáp mạng LAN hoặc cùng một sóng Wi-Fi phòng lab. Tuy nhiên, để chuyển được thư mục mã nguồn sang máy bên cạnh, sinh viên gặp phải hàng loạt rào cản:

```text
               [MÔ HÌNH THỰC TẾ TRONG PHÒNG MÁY TRƯỜNG HỌC]

                      +-----------------------+
                      |   INTERNET / CLOUD    |
                      | (Zalo / Drive / Zipp) |
                      +-----------------------+
                             ^         |
              Vòng qua đám mây:        | Tải xuống lại:
              Tốn băng thông Internet  | Nghẽn mạng phòng máy!
              và lộ dữ liệu riêng tư!  |
                             |         v
  [MÁY A - SINH VIÊN 1] <==================> [MÁY B - SINH VIÊN 2]
                     KẾT NỐI LAN TRỰC TIẾP QUA SWITCH
                     - Tốc độ Gigabit nội bộ cực nhanh!
                     - Nhưng thiếu công cụ:
                       + Không thạo FTP / SSH / Cấu hình server.
                       + Gửi qua HTTP thuần thì không mã hóa.
                       + Vô tình gửi cả thư mục rác node_modules/.
                       + Vô tình để lộ API key, token cá nhân!
```

---

## 2. Năm rào cản lớn khi chia sẻ dữ liệu giữa các máy tính

### 2.1. Rào cản công cụ: Sinh viên không phải ai cũng biết dựng FTP/SSH
- Các công cụ truyền thống như FTP, SFTP, SCP đòi hỏi kiến thức quản trị mạng: phải cài đặt daemon máy chủ (`sshd`, `vsftpd`), cấu hình cổng, cấp tài khoản hệ điều hành (user/password của Windows/Linux) và cấu hình tường lửa.
- Việc này quá phức tạp cho nhu cầu gửi nhanh một thư mục trong tiết học 45 phút, dễ dẫn đến việc cấp thừa quyền hoặc để lại tài khoản mồ côi (orphaned accounts) trên máy thực hành.

### 2.2. Lãng phí băng thông: Vòng qua Internet đám mây không cần thiết
- Khi không có công cụ nội bộ, sinh viên thường nén file ZIP rồi gửi qua Zalo, Messenger, Discord hoặc tải lên Google Drive.
- Hai máy tính ngồi cạnh nhau trong cùng mạng LAN nhưng dữ liệu phải tải ngược lên máy chủ đám mây rồi tải ngược trở về. Tại các phòng máy trường học có hàng trăm sinh viên cùng thực hành, đường truyền Internet ra ngoài thường xuyên bị quá tải, nghẽn mạng, khiến việc gửi một file đồ án mất hàng chục phút.

### 2.3. Gửi thừa dữ liệu: Thư mục dự án chứa đầy file rác
- Một dự án lập trình hiện đại (Node.js, React, Python, Rust, Java) chứa các thư mục phụ thuộc và file tạm cực kỳ nặng nề: `node_modules/` (hàng trăm MB đến hàng GB), `build/`, `dist/`, `.venv/`, `target/`.
- Khi nén cả thư mục để gửi, sinh viên làm lãng phí dung lượng ổ đĩa của bạn bè và lãng phí thời gian truyền tải những file mà máy người nhận hoàn toàn có thể tự tái tạo lại (`npm install`).

### 2.4. Rủi ro riêng tư: Vô tình gửi nhầm API key và cấu hình bí mật
- Trong quá trình làm đồ án có sử dụng AI (OpenAI, Gemini) hoặc kết nối cơ sở dữ liệu, sinh viên lưu khóa bí mật trong file `.env` hoặc file cấu hình cá nhân.
- Khi gửi nhanh cả thư mục cho bạn hoặc đẩy lên GitHub công khai (theo yêu cầu nộp bài của trường hoặc thể lệ cuộc thi), sinh viên rất dễ quên xóa `.env`. Hậu quả: tài khoản đám mây bị bot quét tự động vét sạch, gây mất tiền oan hoặc rò rỉ dữ liệu thử nghiệm.

### 2.5. Lo ngại an toàn đường truyền: Mạng Wi-Fi công cộng thiếu mã hóa
- Nếu sinh viên dùng lệnh chia sẻ nhanh quen thuộc `python -m http.server 8000`:
  - Dữ liệu truyền hoàn toàn bằng văn bản rõ (Plaintext HTTP). Bất kỳ ai trong cùng mạng Wi-Fi trường học đều có thể bắt gói tin (sniffing qua Wireshark) và lấy cắp toàn bộ mã nguồn bài thi/đồ án.
  - Không có bất kỳ cơ chế xác thực danh tính: ai biết IP và cổng đều tải được mọi file trong máy.

---

## 3. Khoảng trống cần giải quyết

Sinh viên và lập trình viên không cần một hệ thống quản trị mạng phức tạp của doanh nghiệp. Họ cần:
> **Một công cụ chuyển file và thư mục dự án trực tiếp giữa các máy tính trong mạng nội bộ: Cực kỳ đơn giản (chỉ cần nhập IP, Port và mã OTP), tốc độ LAN tối đa, tự động lọc sạch file rác và chặn hoàn toàn việc gửi nhầm dữ liệu nhạy cảm trước khi rời máy.**

Đó chính là sứ mệnh thực tế của **Slug**.
