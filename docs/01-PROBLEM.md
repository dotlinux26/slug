# 01. Đặt vấn đề và Nhu cầu thực tế

> **Đơn vị dự thi:** Đội thi SICT Innovation Challenge 2026 — Track: Tech Your Solutions (Đại học Công nghiệp Hà Nội)  
> **Lĩnh vực giải pháp:** Phần mềm (Quy trình phát triển & Quản lý dữ liệu mã nguồn) & Mạng (Chia sẻ cục bộ P2P & Bảo vệ biên dữ liệu)

---

## 1. Bối cảnh: Khi sinh viên và lập trình viên làm việc cùng AI

Trong quá trình học tập, làm đồ án môn học, nghiên cứu và phát triển phần mềm, sinh viên ngành Công nghệ Thông tin và các kỹ sư phần mềm thường xuyên đối mặt với một kịch bản quen thuộc:

1. **Sử dụng trợ lý AI để hỗ trợ lập trình:** Các công cụ AI (như GitHub Copilot, Cursor, Claude Code, ChatGPT) trở thành bạn đồng hành hàng ngày. Để chạy thử nghiệm các tính năng gọi LLM API, cổng thanh toán hoặc dịch vụ đám mây, sinh viên phải tạo các khóa bí mật (`OPENAI_API_KEY`, `GEMINI_API_KEY`, `STRIPE_KEY`, Database URL) và lưu vào file `.env` hoặc file cấu hình cục bộ.
2. **Chia sẻ nhanh mã nguồn cho bạn cùng nhóm:** Khi làm việc nhóm trong phòng lab, ký túc xá hoặc qua mạng LAN, việc gửi nhanh thư mục mã nguồn đang viết dở (chưa kịp commit lên Git) cho bạn bè để cùng gỡ lỗi (debug) diễn ra liên tục. Sinh viên thường dùng lệnh nhanh như `python -m http.server`, nén file `.zip` gửi qua Zalo/Discord/Google Drive, hoặc dùng USB.
3. **Yêu cầu công khai mã nguồn (Public Repository):** Khi nộp bài tập lớn hoặc tham gia các cuộc thi công nghệ (như chính quy chế của SICT Innovation Challenge yêu cầu repository dự thi phải mở công khai — public repo), toàn bộ mã nguồn phải được đưa lên GitHub/GitLab.

---

## 2. Các vấn đề thực tế nhức nhối (The Core Problems)

### 2.1. "Quên" và vô tình công khai khóa bí mật (Secret Leakage)
- **Thực trạng:** Tệp `.env`, file private key, token xác thực thử nghiệm rất dễ bị bỏ quên trong thư mục dự án. Sinh viên hoặc lập trình viên mới chỉ cần một lần gõ `git add .` rồi `git push`, hoặc nén nhầm cả thư mục thành file ZIP gửi cho người khác, là toàn bộ khóa API đã bị lộ ra ngoài.
- **Hậu quả:** Khóa API bị bot quét tự động vét sạch trong vòng vài chục giây sau khi lên GitHub public; tài khoản đám mây bị trừ tiền ngoài ý muốn (hóa đơn hàng triệu đến hàng chục triệu đồng), tài khoản bị khóa, hoặc dữ liệu thử nghiệm bị rò rỉ.

### 2.2. Trợ lý AI tự động đọc trộm file cấu hình nhạy cảm
- Khi lập trình viên mở workspace trong các IDE tích hợp AI, AI agent tự động quét và lập chỉ mục (index) toàn bộ các file văn bản trong thư mục để nạp ngữ cảnh vào Context Window.
- Nếu file `.env` nằm dạng văn bản rõ (plaintext) trên đĩa cứng, AI sẽ đọc trọn vẹn các secret này và gửi kèm trong các request gửi về máy chủ AI cloud, tạo ra nguy cơ rò rỉ thông tin cấu hình nội bộ.

### 2.3. Rác build và ô nhiễm đường truyền khi chia sẻ workspace
- Một dự án web hoặc ứng dụng hiện đại thường đi kèm các thư mục build cực kỳ nặng nề: `node_modules/` (hàng trăm MB đến vài GB), `build/`, `dist/`, `target/`, `.venv/`.
- Khi sinh viên nén cả thư mục hoặc bật HTTP server để gửi cho bạn bè, họ lãng phí băng thông và thời gian để truyền đi hàng chục nghìn file rác mà máy người nhận hoàn toàn có thể tự tạo lại (`npm install`).

### 2.4. Chia sẻ nhanh qua mạng nội bộ thiếu bảo vệ
- Lệnh chia sẻ phổ biến nhất mà sinh viên hay gõ là `python -m http.server 8000`. Lệnh này:
  - Truyền dữ liệu hoàn toàn bằng bản rõ (Plaintext HTTP), bất kỳ ai trong cùng mạng Wi-Fi trường học/phòng lab cũng có thể bắt gói tin (sniffing) và lấy cắp mã nguồn.
  - Không có bất kỳ cơ chế xác thực nào (ai biết IP và cổng đều tải được mọi file trong máy).
  - Không có bộ lọc: sẵn sàng gửi cả `.env`, file private key hoặc file hệ thống nếu người dùng mở từ thư mục cha.

---

## 3. Vì sao các công cụ hiện tại chưa tạo thành một quy trình thuận tiện?

Hiện nay trên thị trường đã có những công cụ giải quyết từng phần rời rạc:
- **`gitleaks` / `trufflehog`:** Quét secret rất tốt, nhưng chỉ là công cụ kiểm tra tĩnh (linter); không ngăn được người dùng mở lệnh truyền file và không có cơ chế cấp secret lúc chạy ứng dụng.
- **`dotenvx`:** Mã hóa `.env` tốt, nhưng không giải quyết bài toán chia sẻ thư mục hay lọc file nhạy cảm khi gửi workspace qua mạng.
- **`python -m http.server` / `wormhole` / `croc`:** Truyền file nhanh nhưng không hiểu cấu trúc dự án lập trình (`.gitignore`), không kiểm duyệt nội dung bên trong thư mục và không ngăn việc gửi nhầm secret.

**Khoảng trống thực tế:** Một sinh viên phải tự cài đặt, cấu hình và kết hợp 3–4 công cụ khác nhau với các cú pháp phức tạp chỉ để làm một công việc thường nhật: *"Làm sao để vừa chạy được code với AI an toàn, vừa kiểm tra chắc chắn dự án không lộ secret, vừa gửi nhanh thư mục sạch cho bạn cùng nhóm qua mạng mà không sợ rò rỉ?"*

---

## 4. Định vị của Slug trong SICT Innovation Challenge

Slug không cố gắng phát minh lại các nguyên lý mã hóa hay công cụ quét mã độc. **Slug là một công cụ thực tế, tinh gọn (~8MB, 1 file nhị phân duy nhất, zero-dependency), hỗ trợ sinh viên và kỹ sư phần mềm giải quyết trọn vẹn 3 nhu cầu cấp thiết trong một quy trình thống nhất:**

```text
+-----------------------------------------------------------------------------------+
| SLUG — CÔNG CỤ BẢO VỆ SOURCE CODE TRƯỚC KHI CÔNG KHAI HOẶC CHIA SẺ               |
+-----------------------------------------------------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        v                                 v                                 v
[1. KIỂM SOÁT SECRET (AI)]       [2. BẢO VỆ VĂN BẢN RÕ]           [3. CHIA SẺ P2P AN TOÀN]
Phát hiện API key, token,        Cất .env vào kho trung tâm       Gửi nhanh mã nguồn qua mạng
credential bằng Heuristic,       (~/.slug/env_vault/), nạp vào    LAN với bộ lọc .gitignore,
Entropy và AI Guard giải thích   RAM cho tiến trình chạy test,    xác thực OTP 8 số, chặn truyền
nguy cơ trước khi push/share.    không để plaintext trên đĩa.     tuyệt đối các file nhạy cảm.
```

---

## 5. Tiêu chí đánh giá tính thực tiễn và hiệu quả

Để bài thi đạt tính thuyết phục cao nhất theo barem điểm SICT Innovation Challenge (25đ Vấn đề thực tế, 25đ Tính khả thi, 25đ Sáng tạo, 25đ Ứng dụng AI):

1. **Tính gần gũi và cấp thiết:** Đánh trúng nỗi sợ lớn nhất của sinh viên CNTT khi làm đồ án và thi hackathon: **sợ lộ API key tốn tiền và sợ nén nhầm file rác nặng máy**.
2. **Khả thi và gọn nhẹ:** Chỉ cần tải 1 file thực thi `slug`, chạy được ngay trên Windows/Linux, không cần cài Node.js, Python runtime hay máy chủ cơ sở dữ liệu.
3. **Giá trị thực của AI:** AI đóng vai trò như một người bạn đồng hành (Advisor): đọc đoạn code nghi vấn, giải thích bằng tiếng Việt vì sao file đó có nguy cơ lộ lọt, phân biệt giữa key giả dùng để test và key thật của dịch vụ đám mây.
4. **Trực quan và dễ demo:** Ban giám khảo có thể nhìn thấy kết quả ngay trong 3 phút qua giao diện CLI màu sinh động và Web UI trực quan trên trình duyệt.
