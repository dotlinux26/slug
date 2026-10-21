# Slug — Hệ Thống Tài Liệu Kỹ Thuật & Hồ Sơ Giải Pháp Dự Thi

> **Cuộc thi:** SICT Innovation Challenge 2026 — Track: Tech Your Solutions  
> **Đơn vị tổ chức:** Trường Công nghệ Thông tin và Truyền thông — Đại học Công nghiệp Hà Nội  
> **Lĩnh vực đề tài:** Phần mềm (Quy trình làm việc & Quản lý dữ liệu) & Mạng (Chia sẻ cục bộ P2P & Bảo vệ biên dữ liệu)  
> **Mã nguồn mở chính thức:** [https://github.com/dotlinux26/slug](https://github.com/dotlinux26/slug) (Apache License 2.0)

---

## 1. Mục Đích Tài Liệu

Tài liệu này được biên soạn nhằm hỗ trợ người đọc nắm bắt các bài toán kỹ thuật, giải pháp kiến trúc, tính khả thi và cách thức triển khai của dự án **Slug**.

Nội dung tập trung mô tả chi tiết các tính năng, giải pháp kiến trúc và cách áp dụng trong môi trường trường học, phòng thực hành (lab), văn phòng và quy trình phát triển phần mềm.

---

## 2. Bản Đồ Hệ Thống Tài Liệu (Documentation Map)

Hệ thống tài liệu trong thư mục `docs/` được phân tách theo từng khía cạnh kỹ thuật:

```text
docs/
├── README.md              <-- (Tài liệu hiện tại) Tổng quan kiến trúc & Cẩm nang thẩm định giải pháp
├── 01-PROBLEM.md          <-- Đặt vấn đề thực tế: Bối cảnh LAN văn phòng, thu bài phòng lab & rủi ro công cụ cũ
├── 02-SOLUTION.md         <-- Giải pháp kỹ thuật, Quy trình 3 bước & 4 kịch bản đời thường, so sánh đa chiều
├── 03-AI-USAGE.md         <-- 4 Cấp độ lọc, Cố vấn ngữ cảnh (Advisory), Entropy Scanner & SQLite Cache
├── 04-ARCHITECTURE.md     <-- Đặc tả 5 tầng, Directional AEAD, SQLite WAL, TTL đa tầng & Bắt gói Wireshark
├── MODULE-MAP.md          <-- Bản đồ phân rã mã nguồn C++20 và hệ thống các chốt chặn kiểm duyệt (Gatekeepers)
└── TUTORIAL_VI.md         <-- Cẩm nang hướng dẫn sử dụng và triển khai thực tế bằng tiếng Việt
```

| Tài liệu | Nội dung trọng tâm | Nhóm người đọc khuyến nghị |
| :--- | :--- | :--- |
| **[01-PROBLEM.md](01-PROBLEM.md)** | Phân tích thực trạng chuyển tệp LAN qua Internet WAN; bài toán thu bài tập phòng máy; lỗ hổng Plaintext của `python -m http.server`; sự cồng kềnh của FTP/SFTP; và rủi ro lộ API key khi dùng trợ lý AI. | Giám khảo, Trưởng nhóm kỹ thuật, Quản trị mạng |
| **[02-SOLUTION.md](02-SOLUTION.md)** | Quy trình 3 bước tinh gọn; chi tiết 4 kịch bản đời thường (chuyển tệp nội bộ, thu bài sinh viên một chiều Write-Only, chia sẻ workspace có lọc, bảo vệ bí mật với EnvShield); bảng so sánh toàn diện với các công cụ hiện hữu. | Giám khảo, Lập trình viên, Giảng viên |
| **[03-AI-USAGE.md](03-AI-USAGE.md)** | Định vị vai trò của AI là Cố vấn phân tích ngữ cảnh (Contextual Advisor); 4 cấp độ lọc; bộ phân tích Shannon Entropy trên file scannable; SQLite cache (`index.db`); kỹ thuật nạp biến môi trường vào RAM. | Chuyên gia AI, Chuyên gia An toàn thông tin |
| **[04-ARCHITECTURE.md](04-ARCHITECTURE.md)** | Đặc tả kiến trúc 5 tầng; Mô hình Web UI Localhost Proxy (Kiến trúc A); cơ chế dẫn xuất muối độc lập phân hướng (Directional Salts) chống Nonce-Reuse; SQLite WAL; Bất biến cây thư mục; Hướng dẫn bắt gói Wireshark. | Kỹ sư Hệ thống, Kiến trúc sư Phần mềm |
| **[MODULE-MAP.md](MODULE-MAP.md)** | Bản đồ liên kết mã nguồn C++20 (`src/`), phân tích các chốt chặn kiểm duyệt dữ liệu tại tầng giao vận, tầng hệ thống tệp ảo (`SlugVFS Jail`) và tầng chính sách RBAC. | Lập trình viên thẩm định mã nguồn (Code Review) |
| **[TUTORIAL_VI.md](TUTORIAL_VI.md)** | Cẩm nang hướng dẫn sử dụng thực tế tiếng Việt: lệnh `slug host`, 4 cấp độ lọc, quản trị Admin Dashboard, bắt gói tin Wireshark và cheatsheet CLI. | Người dùng cuối, Lập trình viên, Giảng viên |

---

## 3. Các Bài Toán Thực Tế & Giải Pháp Của Slug

### 3.1. Chuyển tệp lớn qua mạng LAN (Văn phòng / Trường học)
- **Thực trạng:** Khi hai máy tính trong cùng phòng làm việc muốn gửi cho nhau một file lớn vài GB, việc tải lên dịch vụ đám mây (Google Drive, Zalo, Telegram...) gây phụ thuộc vào máy chủ bên thứ ba và tốc độ kết nối Internet bên ngoài.
- **Giải pháp Slug:** Thiết lập kết nối P2P trực tiếp qua LAN, tận dụng tốc độ phần cứng mạng cục bộ, không gửi dữ liệu qua Internet, bảo vệ hai đầu bằng mật mã Hậu Lượng Tử (PQC ML-KEM-768 / XChaCha20-Poly1305).

### 3.2. Thu bài thi / bài tập sinh viên phòng máy một chạm (Blind Drop)
- **Thực trạng:** Giảng viên cần thu bài 40–50 sinh viên nhanh chóng, không bị nghẽn mạng Internet như dịch vụ đám mây, không yêu cầu thiết lập tài khoản phức tạp như FTP/Domain, và cần ngăn việc xem hoặc sao chép bài của sinh viên khác.
- **Giải pháp Slug:** Giảng viên khởi tạo workspace với quyền Ghi **Write-Only (`[w]`)** và tạo tài khoản lớp chung (`[w] Write-Only`) để sinh viên cùng nộp bài. Sinh viên đăng nhập rồi kéo thả bài vào giao diện Web hoặc dùng lệnh `slug push`. Tầng `SlugVFS Jail` chặn lệnh đọc (`read_file`) và liệt kê (`list_dir`) đối với máy khách, đảm bảo sinh viên chỉ nộp bài mà không xem được danh sách bài của người khác.

### 3.3. Chia sẻ mã nguồn nhóm có kiểm soát (Selective Staging)
- **Thực trạng:** Khi chia sẻ thư mục mã nguồn cho thành viên trong nhóm, các công cụ máy chủ tệp truyền thống thường gửi toàn bộ thư mục, dẫn đến gửi thừa thư mục build (`node_modules/`, `build/`) hoặc vô tình gửi tệp cấu hình chứa khóa bí mật.
- **Giải pháp Slug:** Hệ thống **Slug Guard** tự động đọc cấu hình `.gitignore` để loại bỏ các thư mục rác; đồng thời bộ quét Heuristic & Shannon Entropy ($H(X) \ge 4.0$) rà soát các chuỗi khóa bí mật nghi vấn, kết hợp bộ lọc Whitelist (`!.env.example`) và AI Semantic Advisor hỗ trợ cảnh báo trước khi truyền dữ liệu.

### 3.4. Quản lý bí mật trong môi trường trợ lý AI (EnvShield)
- **Thực trạng:** Trong môi trường phát triển sử dụng các công cụ lập chỉ mục hoặc trợ lý AI, tệp văn bản rõ (`.env`) trên ổ đĩa có thể bị đọc tự động và đưa vào ngữ cảnh gửi lên cloud.
- **Giải pháp Slug:** Lệnh `slug env init` cất file `.env` vào Kho trung tâm ngoài workspace (`~/.slug/env_vault/`), mã hóa thành `.env.pqc` trong thư mục làm việc và xóa tệp bản rõ trên đĩa. Khi chạy ứng dụng, `slug env run -- <lệnh>` giải mã trực tiếp trong RAM và nạp biến môi trường cho tiến trình con.

---

## 4. Bảng Tổng Hợp Đối Chiếu Kỹ Thuật

| Khía cạnh | Thực trạng & Giải pháp của Slug | Minh chứng kỹ thuật & Tra cứu |
| :--- | :--- | :--- |
| **1. Mức độ cần thiết & Tính thực tế** | Giải quyết trực diện nhu cầu làm việc hàng ngày:<br>• Chuyển tệp nội bộ tốc độ cao qua LAN, không gửi dữ liệu ra ngoài Internet.<br>• Thu bài phòng máy một chiều chống xem bài chép bài.<br>• Giảm thiểu rủi ro lộ tệp cấu hình chứa secret vào công cụ AI hoặc commit lên kho mã nguồn. | • [01-PROBLEM.md](01-PROBLEM.md)<br>• Bảng so sánh tính năng ở Mục 2. |
| **2. Tính khả thi & Mức độ hoàn thiện** | • Đóng gói thành **1 file thực thi nhị phân duy nhất (~10MB)**, zero-dependency, không đòi hỏi cài thêm runtime.<br>• Được triển khai bằng C++20, hỗ trợ cả Linux và Windows.<br>• Cung cấp giao diện CLI POSIX lẫn Web Viewing Engine nội bộ (`127.0.0.1:8081/`). | • [02-SOLUTION.md](02-SOLUTION.md)<br>• [BUILD.md](../BUILD.md)<br>• CI/CD tự động build binary đa nền tảng trong `.github/workflows/`. |
| **3. Điểm mới & Khác biệt kỹ thuật** | • **Kênh truyền nhị phân bảo mật:** Thay đường truyền plain HTTP bằng kênh PQC AEAD; cơ chế xác thực OTP 3 vai trò (`[rw]`, `[r]`, `[w]`).<br>• **Kiểm soát nội dung chia sẻ:** Tự động loại bỏ thư mục theo `.gitignore` và hỗ trợ Whitelist (`!.env.example`).<br>• **EnvShield:** Nạp biến môi trường vào RAM tiến trình con khi thực thi lệnh, giảm thiểu lưu tệp cấu hình bản rõ trên đĩa. | • [04-ARCHITECTURE.md](04-ARCHITECTURE.md)<br>• [MODULE-MAP.md](MODULE-MAP.md)<br>• Kiến trúc Directional AEAD và VFS Jail. |
| **4. Ứng dụng AI & Giá trị thực tế** | • **Slug Guard:** Tầng chặn xác định offline (Heuristic Regex + Shannon Entropy $H(X) \ge 4.0$).<br>• **Slug AI:** Tùy chọn cố vấn ngữ cảnh (`--ai`), trả về schema JSON (`has_secret`, `reason`, `line`) hỗ trợ người dùng phân tích thêm ngữ cảnh.<br>• Bộ nhớ đệm trạng thái BLAKE3 (`index.db`), tránh quét lặp lại tệp không đổi.<br>• Hướng dẫn công cụ (`.slug/ai-rule.md`). | • [03-AI-USAGE.md](03-AI-USAGE.md)<br>• Mã nguồn module `src/ai/stateful_audit.hpp` và `src/ai/scanner.cpp`. |

---

## 5. Hướng Dẫn Trải Nghiệm Nhanh (3-Minute Demo Walkthrough)

Quy trình sử dụng cơ bản của Slug qua 3 bước cốt lõi:

```bash
# Bước 1: Quét kiểm tra mã nguồn (Slug Guard Heuristic + Shannon Entropy + AI Advisor)
slug audit scan .

# Bước 2: Niêm phong file .env vào Vault và chạy ứng dụng từ RAM
slug env init
slug env run -- npm test      # (hoặc pytest, python main.py)
# -> Kiểm tra thư mục: File .env bản rõ không còn trên đĩa, tiến trình nhận biến môi trường từ RAM và thực thi bình thường.

# Bước 3: Mở trạm chia sẻ P2P mã hóa với bộ lọc rác tự động
slug add . -p 9443
# -> Terminal hiển thị thông số và các mã OTP phân quyền ([rw], [r], [w]).
# Máy đồng nghiệp hoặc sinh viên có thể kéo dữ liệu bằng lệnh:
slug pull -i <IP_SERVER> -p 9443 -o <OTP> --to ./tai_ve
# Hoặc tải 1 file cụ thể:
slug get <IP_SERVER>:9443?otp=<OTP> src/main.cpp ./main.cpp
# Hoặc mở trực tiếp Web Viewing Engine trên loopback: gõ 'slug' (http://127.0.0.1:8081/)
```

---

## 6. Phạm Vi Hoạt Động & Giới Hạn Kỹ Thuật (Scope & Boundaries)

1. **Bộ nhớ RAM của tiến trình:** EnvShield quản lý tệp cấu hình trên đĩa và nạp trực tiếp vào bộ nhớ RAM của tiến trình con. Khi tiến trình thực thi, biến môi trường nằm trong không gian tiến trình; các lệnh đọc môi trường trực tiếp từ tiến trình (như `printenv`) vẫn có thể truy cập giá trị này.
2. **Đo lường hiệu năng:** Lệnh `slug bench` đo lường năng lực tính toán CPU với các nguyên mẫu mật mã (ML-KEM, BLAKE3, XChaCha20), tốc độ xử lý phân mảnh vi sai In-Memory và tốc độ I/O đĩa cục bộ. Băng thông mạng thực tế phụ thuộc vào hạ tầng mạng vật lý giữa các máy.
3. **Phạm vi của AI:** Module AI hoạt động như một lớp tham vấn ngữ cảnh bổ trợ (advisory), việc chặn/cho phép dữ liệu cơ sở do các quy tắc lọc xác định và chính sách của người quản trị máy chủ (Host Admin) quyết định.
