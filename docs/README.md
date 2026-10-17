# Slug — Hệ Thống Tài Liệu Kỹ Thuật & Hồ Sơ Giải Pháp Dự Thi

> **Cuộc thi:** SICT Innovation Challenge 2026 — Track: Tech Your Solutions  
> **Đơn vị tổ chức:** Trường Công nghệ Thông tin và Truyền thông — Đại học Công nghiệp Hà Nội  
> **Lĩnh vực đề tài:** Phần mềm (Quy trình làm việc & Quản lý dữ liệu) & Mạng (Chia sẻ cục bộ P2P & Bảo vệ biên dữ liệu)  
> **Mã nguồn mở chính thức:** [https://github.com/dotlinux26/slug](https://github.com/dotlinux26/slug) (Apache License 2.0)

---

## 1. Lời Mở Đầu & Mục Đích Tài Liệu

Tài liệu này được biên soạn như một **lớp tổng hợp toàn diện** nhằm hỗ trợ **Hội đồng Ban giám khảo, các chuyên gia phản biện và cộng đồng lập trình viên** nhanh chóng nắm bắt bản chất vấn đề, kiến trúc kỹ thuật, tính khả thi và giá trị thực tiễn của giải pháp **Slug**.

Slug không chạy theo các khẩu hiệu quảng bá hoa mỹ hay thần thánh hóa công nghệ. Dự án kiên định với phương châm **"Nói đúng - Nói đủ - Trung thực về kỹ thuật (No-Overclaim)"**, tập trung giải quyết triệt để các bài toán thường nhật phát sinh trong môi trường trường học, phòng thực hành (lab), văn phòng công ty và quy trình phát triển phần mềm hiện đại.

---

## 2. Bản Đồ Hệ Thống Tài Liệu (Documentation Map)

Hệ thống tài liệu trong thư mục `docs/` được phân tách khoa học theo từng khía cạnh kỹ thuật, giúp người đọc dễ dàng tra cứu chi tiết:

```text
docs/
├── README.md              <-- (Tài liệu hiện tại) Tổng quan kiến trúc & Cẩm nang thẩm định giải pháp
├── 01-PROBLEM.md          <-- Đặt vấn đề thực tế: Bối cảnh LAN văn phòng, thu bài phòng lab & lỗ hổng của công cụ cũ
├── 02-SOLUTION.md         <-- Giải pháp kỹ thuật, Quy trình 3 bước & 4 kịch bản đời thường, so sánh đa chiều
├── 03-AI-USAGE.md         <-- 4 Cấp độ lọc, Cố vấn ngữ cảnh (Advisory), Entropy Scanner & SQLite Auto-Healing
├── 04-ARCHITECTURE.md     <-- Đặc tả 5 tầng, Directional AEAD, SQLite WAL, TTL đa tầng & Wireshark Packet Inspection
├── MODULE-MAP.md          <-- Bản đồ phân rã mã nguồn C++20 và hệ thống các chốt chặn kiểm duyệt (Gatekeepers)
└── TUTORIAL_VI.md         <-- Cẩm nang hướng dẫn sử dụng và triển khai thực chiến chi tiết bằng tiếng Việt
```

| Tài liệu | Nội dung trọng tâm | Nhóm người đọc khuyến nghị |
| :--- | :--- | :--- |
| **[01-PROBLEM.md](01-PROBLEM.md)** | Phân tích thực trạng chuyển tệp LAN bị lãng phí băng thông WAN; bài toán thu bài tập phòng máy; lỗ hổng Plaintext của `python -m http.server`; sự cồng kềnh của FTP/SFTP; và rủi ro lộ API key khi dùng trợ lý AI. | Giám khảo, Trưởng nhóm kỹ thuật, Quản trị mạng |
| **[02-SOLUTION.md](02-SOLUTION.md)** | Quy trình 3 bước tinh gọn; chi tiết 4 kịch bản đời thường (chuyển tệp nội bộ, thu bài sinh viên một chiều Write-Only, chia sẻ workspace sạch, bảo vệ bí mật với EnvShield); bảng so sánh toàn diện với các công cụ hiện hữu. | Giám khảo, Lập trình viên, Giảng viên |
| **[03-AI-USAGE.md](03-AI-USAGE.md)** | Định vị chính xác vai trò của AI là Cố vấn phân tích ngữ cảnh (Contextual Advisor); 4 cấp độ lọc tích lũy; bộ phân tích Shannon Entropy trên file scannable; SQLite auto-healing (`index.db`); kỹ thuật nạp biến môi trường vào RAM. | Chuyên gia AI, Chuyên gia An toàn thông tin |
| **[04-ARCHITECTURE.md](04-ARCHITECTURE.md)** | Đặc tả kiến trúc 5 tầng nghiêm ngặt; Mô hình Web UI Localhost Proxy (Kiến trúc A); cơ chế dẫn xuất muối độc lập phân hướng (Directional Salts) chống Nonce-Reuse; SQLite WAL; Bất biến cây thư mục; Hướng dẫn bắt gói Wireshark. | Kỹ sư Hệ thống, Kiến trúc sư Phần mềm |
| **[MODULE-MAP.md](MODULE-MAP.md)** | Bản đồ liên kết mã nguồn C++20 (`src/`), phân tích các chốt chặn kiểm duyệt dữ liệu tại tầng giao vận, tầng hệ thống tệp ảo (`SlugVFS Jail`) và tầng chính sách RBAC. | Lập trình viên thẩm định mã nguồn (Code Review) |
| **[TUTORIAL_VI.md](TUTORIAL_VI.md)** | Cẩm nang hướng dẫn sử dụng thực chiến tiếng Việt: lệnh `slug host`, 4 cấp độ lọc, quản trị Admin Dashboard, bắt gói tin Wireshark và cheatsheet CLI. | Người dùng cuối, Lập trình viên, Giảng viên |

---

## 3. Các Bài Toán Đời Thường & Lời Giải Của Slug

### 3.1. Chuyển tệp lớn qua mạng LAN (Văn phòng / Trường học)
- **Thực trạng:** Khi hai máy tính trong cùng phòng làm việc muốn gửi cho nhau một file lớn vài GB, thói quen thông thường là tải lên Google Drive, gửi qua Zalo, Telegram... Điều này gây lãng phí băng thông Internet quốc tế (WAN), phụ thuộc vào máy chủ trung gian của bên thứ ba và bị bóp tốc độ.
- **Lời giải Slug:** Thiết lập kết nối P2P trực tiếp qua LAN, đạt trần tốc độ đường truyền phần cứng (Gigabit LAN = ~125 MB/s), 0 byte băng thông WAN, bảo mật hai đầu bằng mật mã Hậu Lượng Tử (PQC ML-KEM-768).

### 3.2. Thu bài thi / bài tập sinh viên phòng máy một chạm (Blind Drop)
- **Thực trạng:** Giảng viên cần thu bài 40–50 sinh viên nhanh chóng, không bị nghẽn mạng WAN như Google Drive, không phức tạp như tạo tài khoản FTP/Domain, và **đặc biệt phải chống nhìn trộm / chép bài của bạn khác**. `python -m http.server` không hỗ trợ tính năng này (ai cũng xem và tải được file người khác vừa nộp).
- **Lời giải Slug:** Giảng viên khởi tạo workspace với quyền Ghi **Write-Only (`[w]`)** và tạo tài khoản lớp chung (`[w] Write-Only`) để toàn bộ 40–50 sinh viên cùng nộp bài đồng thời (mã OTP 8 số là vé bảo mật dùng 1 lần cho từng máy riêng). Sinh viên đăng nhập tài khoản chung rồi kéo thả bài vào trình duyệt Web Dropbox hoặc gõ `slug push`. Tầng `SlugVFS Jail` cưỡng chế chặn lệnh đọc (`read_file`) và liệt kê (`list_dir`) đối với máy khách, đảm bảo sinh viên chỉ nộp được bài mà không thể xem bài của bạn khác. Zero-setup, chạy offline hoàn toàn.

### 3.3. Chia sẻ mã nguồn nhóm có kiểm soát (Selective Staging)
- **Thực trạng:** Lập trình viên muốn gửi nhanh thư mục code cho bạn cùng nhóm để gỡ lỗi. Các công cụ FTP hay HTTP Server chỉ là "đường ống thụ động" — gặp gì gửi nấy, dẫn đến việc gửi thừa hàng trăm MB rác build (`node_modules/`, `build/`) và lỡ tay chia sẻ nhầm file `.env` chứa token/khóa bí mật.
- **Lời giải Slug:** Hệ thống **Slug Guard** đa cơ chế tự động đọc `.gitignore` để loại bỏ rác build; đồng thời bộ quét Heuristic & Shannon Entropy ($H(X) \ge 4.0$) rà soát các chuỗi khóa bí mật nghi vấn, kết hợp bộ lọc Whitelist (`!.env.example`) và AI Semantic Advisor hỗ trợ cảnh báo trước khi truyền dữ liệu.

### 3.4. Phòng vệ bí mật trước các trợ lý AI lập trình (EnvShield)
- **Thực trạng:** Khi lập trình với Cursor, Copilot hay Claude Code, các trợ lý AI tự động đọc các file văn bản rõ (plaintext `.env`) trên ổ đĩa để nạp vào Context Window gửi lên cloud, làm rò rỉ API key.
- **Lời giải Slug:** Lệnh `slug env init` cất file `.env` vào Kho trung tâm ngoài workspace (`~/.slug/env_vault/`), mã hóa thành `.env.pqc` trong repo và xóa sạch plaintext trên đĩa. Khi chạy ứng dụng, `slug env run -- <lệnh>` giải mã trực tiếp trong RAM và nạp biến môi trường cho tiến trình, không để plaintext trên ổ đĩa cho AI đọc lén.

---

## 4. Bảng Tổng Hợp Đối Chiếu Hỗ Trợ Hội Đồng Ban Giám Khảo

Nhằm hỗ trợ Hội đồng Giám khảo nhanh chóng đối chiếu thông tin sản phẩm theo các định hướng đánh giá của cuộc thi **SICT Innovation Challenge**:

| Khía cạnh đánh giá | Thực trạng & Cách tiếp cận của Slug | Minh chứng kỹ thuật & Vị trí tra cứu |
| :--- | :--- | :--- |
| **1. Mức độ cần thiết & Tính thực tế** | Giải quyết trực diện các nỗi đau thường nhật:<br>• Chuyển tệp nội bộ gigabit, tiết kiệm 100% băng thông WAN.<br>• Thu bài phòng máy một chiều chống chép bài.<br>• Ngăn chặn nguy cơ mất tiền do lộ API key khi làm việc với AI hoặc push repo công khai. | • [01-PROBLEM.md](01-PROBLEM.md)<br>• Bảng phân tích lỗ hổng của `python -m http.server`, FTP/SFTP và Cloud Drive ở Mục 2. |
| **2. Tính khả thi & Mức độ hoàn thiện** | • Đóng gói thành **1 file thực thi nhị phân duy nhất (~8MB)**, zero-dependency, không cần cài đặt Python, Node.js hay DB.<br>• Đã hiện thực hóa 100% bằng C++20, chạy mượt mà trên cả Linux và Windows.<br>• Cung cấp cả CLI POSIX chuẩn mực lẫn Web Viewing Engine nội bộ (`127.0.0.1:8080/`). | • [02-SOLUTION.md](02-SOLUTION.md)<br>• [BUILD.md](../BUILD.md)<br>• CI/CD tự động build binary đa nền tảng trong `.github/workflows/`. |
| **3. Tính sáng tạo & Điểm khác biệt** | • **Khắc phục nhược điểm của `python http.server`:** Thay đường truyền plain HTTP bằng kênh PQC AEAD; bổ sung phân quyền OTP 3 vai trò (`[rw]`, `[r]`, `[w]`).<br>• **Khác biệt so với FTP/SFTP:** Khả năng kiểm soát nội dung chủ động (Selective Staging) tự động lọc rác build theo `.gitignore` và quy tắc Whitelist (`!.env.example`).<br>• **Sáng tạo với EnvShield:** Nạp biến môi trường vào RAM lúc chạy, ngăn chặn AI đọc trộm secret trên đĩa. | • [04-ARCHITECTURE.md](04-ARCHITECTURE.md)<br>• [MODULE-MAP.md](MODULE-MAP.md)<br>• Kiến trúc đóng khung Directional AEAD và VFS Jail. |
| **4. Ứng dụng AI & Giá trị thực tế** | • Định vị trung thực: **Slug Guard** chịu trách nhiệm chặn cứng (Heuristic Regex + Shannon Entropy $H(X) \ge 4.0$ hoàn toàn offline).<br>• **Slug AI** là lớp cố vấn tùy chọn (`--ai`), trả về schema JSON (`has_secret`, `reason`, `line`) để tham vấn ngữ cảnh, tuyệt đối không lạm dụng thay thế cơ chế an toàn deterministic.<br>• Tối ưu hiệu năng bằng bộ nhớ đệm trạng thái BLAKE3 (`index.db`), không quét lại file cũ.<br>• Chỉ dẫn AI agent cách dùng công cụ an toàn (`.slug/ai-rule.md`). | • [03-AI-USAGE.md](03-AI-USAGE.md)<br>• Mã nguồn module `src/ai/stateful_audit.hpp` và `src/ai/scanner.cpp`. |

---

## 5. Hướng Dẫn Trải Nghiệm Nhanh (3-Minute Demo Walkthrough)

Ban giám khảo hoặc người dùng có thể kiểm chứng toàn bộ quy trình của Slug trong vòng 3 phút qua 3 bước cốt lõi:

```bash
# Bước 1: Quét kiểm tra mã nguồn (Slug Guard Heuristic + Shannon Entropy + AI Advisor)
slug audit scan .

# Bước 2: Niêm phong file .env vào Vault và chạy ứng dụng từ RAM
slug env init
slug env run -- npm test      # (hoặc pytest, python main.py)
# -> Kiểm tra thư mục: File .env bản rõ đã biến mất, tiến trình vẫn chạy pass 100%!

# Bước 3: Mở trạm chia sẻ P2P mã hóa với bộ lọc rác tự động
slug add . -p 9443
# -> Terminal hiển thị thông số và các mã OTP phân quyền ([rw], [r], [w]).
# Máy đồng nghiệp hoặc sinh viên có thể kéo dữ liệu bằng lệnh:
slug pull -i <IP_SERVER> -p 9443 -o <OTP> --to ./tai_ve
# Hoặc tải 1 file cụ thể:
slug get <IP_SERVER>:9443?otp=<OTP> src/main.cpp ./main.cpp
# Hoặc mở trực tiếp Web Viewing Engine trên loopback: gõ 'slug' (http://127.0.0.1:8080/)
```

---

## 6. Cam Kết Trung Thực Kỹ Thuật (No-Overclaim Commitment)

Nhóm phát triển Slug cam kết tuân thủ các chuẩn mực đạo đức khoa học và kỹ thuật:
1. **Về ranh giới bộ nhớ RAM:** Slug EnvShield bảo vệ secret khỏi sự đọc trộm thụ động của các trợ lý AI từ đĩa cứng. Khi ứng dụng thực thi, biến môi trường tồn tại trong RAM; nếu người dùng cố tình viết code `printenv` để trích xuất thì dữ liệu vẫn sẽ hiển thị.
2. **Về đo lường hiệu năng:** Lệnh `slug bench` chỉ đo lường năng lực tính toán CPU mật mã (ML-KEM, BLAKE3, ChaCha20), tốc độ phân mảnh vi sai In-Memory và tốc độ I/O đĩa cứng vật lý cục bộ. Tốc độ truyền tải mạng thực tế phụ thuộc hoàn toàn vào hạ tầng kết nối vật lý giữa hai máy.
3. **Về vai trò của AI:** AI trong Slug không tự ý quyết định thay con người và không thay thế các quy tắc toán học xác định. AI là một công cụ hỗ trợ phân tích ngữ cảnh, quyền quyết định kiểm soát dữ liệu tối thượng luôn thuộc về chủ máy (Host Admin).
