# PHIẾU ĐĂNG KÝ CUỘC THI SICT INNOVATION CHALLENGE

---

## II. THÔNG TIN DỰ ÁN

### 4. Lĩnh vực của dự án*
- [x] **SICT Tech Your Solutions**
- [ ] SICT MediaTech Solutions Challenge
- [ ] SICT AI For Game
- [ ] SICT DIGITAL SOLUTIONS FOR STUDENT LIFE
- [ ] SICT AI-Art Challenge
- [ ] SICT AI for Education
- [ ] SICT Tech Connect Challenge

*(Phân loại: Giải pháp Công nghệ phần mềm, Công cụ bảo mật hệ thống và Hạ tầng mạng nội bộ)*

---

### 5. Điểm mới và tính sáng tạo của dự án*

Dự án **Slug** giới thiệu các điểm mới và sáng tạo sau trong lĩnh vực bảo mật và chia sẻ dữ liệu làm việc (workspace):

1. **Quản lý cấu hình nhạy cảm trong bộ nhớ (In-Memory EnvShield):**
   - Thay vì lưu trữ tệp `.env` dạng văn bản rõ (plaintext) trên ổ đĩa – nơi các công cụ quét tự động và trợ lý AI (AI Coding Assistants) dễ dàng đọc vào context window và đồng bộ lên đám mây – Slug mã hóa tệp cấu hình bằng thuật toán hậu lượng tử (`.env.pqc`) và đưa bản sao lưu vào kho trung tâm ngoài workspace (`~/.slug/env_vault/`).
   - Khi chạy ứng dụng (`slug env run -- <command>`), Slug giải mã dữ liệu duy nhất trong RAM và nạp trực tiếp vào bảng tiến trình của hệ điều hành, không tạo bất kỳ tệp tạm hay byte bản rõ nào trên đĩa cứng.

2. **Kênh truyền nhị phân an toàn hậu lượng tử (PQC AEAD Wire Protocol):**
   - Không sử dụng máy chủ HTTP từ xa hay phơi bày API ra mạng LAN (mô hình Zero Remote HTTP).
   - Thiết lập giao thức nhị phân hướng luồng qua TCP với cơ chế bắt tay mật mã hậu lượng tử theo chuẩn NIST FIPS: **ML-KEM-768** (Kyber) cho trao đổi khóa, **ML-DSA-65** (Dilithium) cho chữ ký số, và **XChaCha20-Poly1305** kèm Directional Salt cho mã hóa từng khối dữ liệu (Chunk-Level AEAD 64 KiB), bảo vệ dữ liệu trước nguy cơ "Thu thập dữ liệu hiện tại, giải mã bằng máy tính lượng tử trong tương lai" (Harvest Now, Decrypt Later).

3. **Cơ chế nộp bài một chiều chống sao chép (`[w]` Blind Drop / Write-Only):**
   - Phục vụ trực tiếp môi trường phòng thực hành máy tính và làm việc nhóm: bên nhận cấp mã PIN quyền ghi (`[w]`), cho phép người gửi tải bài lên nhưng hoàn toàn không thể xem, đọc hay tải xuống các tệp đã có trong thư mục, giải quyết bài toán quay cóp hoặc chép mã nguồn của nhau trên cùng mạng nội bộ.

4. **Kiểm soát bí mật đa tầng tại biên (Multi-Layer Secret Detection):**
   - Tự động bỏ qua các thư mục build rác (`node_modules/`, `.git/`, `target/`, `.venv/`) dựa trên `.gitignore` để tối ưu băng thông.
   - Tích hợp bộ quét phát hiện khóa truy cập, token nhạy cảm bằng biểu thức chính quy (Regex) kết hợp tính toán độ hỗn loạn Shannon Entropy ($H(X) \ge 4.0$), tự động cô lập tệp nghi vấn trước khi dữ liệu rời khỏi máy tính.

5. **Kiến trúc nhị phân độc lập (Zero-Dependency & Portable):**
   - Toàn bộ giải pháp được viết bằng C++ hiện đại, biên dịch thành một tệp thực thi duy nhất (`slug` / `slug.exe`), tích hợp sẵn giao diện Web Viewing Engine cục bộ phong cách Techno B2B, không phụ thuộc trình biên dịch, runtime ngoài hay dịch vụ đám mây trung gian.

---

### 6. Tên ý tưởng dự án (Nếu có)*
**Slug — Nền tảng chia sẻ Workspace an toàn và quản lý cấu hình nhạy cảm trong bộ nhớ (PQC-Encrypted Ephemeral Workspace Sharing & In-Memory Secret Shield)**

---

### 7. Giá trị và lợi ích của dự án*

1. **Đối với sinh viên và nhà trường (Môi trường học đường & Phòng máy Lab):**
   - **Tiết kiệm tài nguyên mạng:** Dữ liệu được chia sẻ và đồng bộ trực tiếp ngang hàng trong mạng nội bộ (LAN/WiFi), tiêu thụ 0 byte băng thông Internet (WAN), giúp các buổi thực hành diễn ra ổn định ngay cả khi đường truyền ra ngoài bị nghẽn hoặc mất kết nối Internet.
   - **Hỗ trợ chấm bài và thu bài phòng lab:** Giảng viên khởi chạy chế độ Hộp thư nộp bài (`slug share --write-only`) chỉ với một lệnh; sinh viên nộp bài trực tiếp không cần đăng nhập tài khoản đám mây hay cắm USB (giảm thiểu lây lan mã độc qua USB).

2. **Đối với lập trình viên và nhóm phát triển phần mềm:**
   - **Bảo vệ khóa bí mật trước trợ lý AI:** Loại bỏ tình trạng rò rỉ API key (OpenAI, Stripe, AWS) khi sử dụng các công cụ AI coding như GitHub Copilot, Cursor, Claude Code, vốn có xu hướng quét toàn bộ cây thư mục workspace.
   - **Chia sẻ tức thì, vòng đời có hạn (Ephemeral):** Phiên chia sẻ tự hủy theo thời gian thực (TTL), không lưu trữ vĩnh viễn trên kho chứa công khai (public repo), phù hợp cho các buổi thảo luận, review mã nguồn nhanh (code review) hoặc pair programming nội bộ.

3. **Về mặt kỹ thuật và an toàn thông tin:**
   - **Bảo mật dữ liệu đường truyền:** Toàn bộ lưu lượng truyền tải trên mạng vật lý được mã hóa bằng chuẩn mật mã hậu lượng tử, chống lại các hành vi nghe lén mạng nội bộ (LAN sniffing), tấn công trung gian (MITM) và tấn công phát lại (Replay Attacks).
   - **Dễ triển khai:** File chạy độc lập, kích thước nhỏ gọn (~2MB), hỗ trợ đa nền tảng (Windows, Linux, macOS), sẵn sàng sử dụng ngay sau khi tải về mà không yêu cầu cài đặt môi trường phức tạp.

---

### 8. Mục tiêu khi đến với cuộc thi SICT INNOVATION CHALLENGE*

1. **Thử nghiệm và đánh giá thực tế:** Đưa giải pháp thử nghiệm trực tiếp tại các phòng máy thực hành và các câu lạc bộ học thuật của nhà trường, thu thập dữ liệu về hiệu năng truyền tải và trải nghiệm người dùng thực tế.
2. **Tiếp nhận phản hồi chuyên môn:** Lắng nghe đánh giá, phản biện từ Hội đồng Giám khảo và các chuyên gia trong ngành phần mềm/an toàn thông tin để tiếp tục hoàn thiện kiến trúc hệ thống và chuẩn hóa giao thức.
3. **Lan tỏa công cụ mã nguồn mở:** Phát triển Slug thành một công cụ mã nguồn mở hữu ích, phục vụ cộng đồng sinh viên công nghệ thông tin trong học tập, nghiên cứu và làm việc nhóm.
4. **Kết nối và mở rộng tiềm năng ứng dụng:** Tìm kiếm cơ hội hợp tác đưa giải pháp vào ứng dụng thực tế trong quản lý hạ tầng phòng máy lab hoặc tích hợp vào quy trình phát triển phần mềm an toàn (DevSecOps) tại doanh nghiệp.

---

## TÀI LIỆU HỒ SƠ DỰ THI ĐÍNH KÈM (THAM KHẢO CHO TỆP TẢI LÊN)

### 1. Tóm tắt nội dung bản mô tả ý tưởng (Idea Proposal)
- **Thông tin nhóm tác giả:** Nhóm phát triển dự án Slug.
- **Vấn đề giải quyết:** 
  1. Rò rỉ biến môi trường `.env` và API keys do AI Agent tự động đọc context từ đĩa.
  2. Lãng phí băng thông WAN khi chia sẻ dữ liệu lớn trong mạng LAN qua cloud storage.
  3. Rủi ro gian lận, chép bài trong phòng lab khi dùng chung thư mục chia sẻ không phân quyền nộp bài một chiều.
  4. Nguy cơ dữ liệu bị thu thập và giải mã trong tương lai bởi máy tính lượng tử.
- **Giải pháp kiến trúc:**
  - Mô-đun **Slug EnvShield**: Niêm phong `.env` thành `.env.pqc`, lưu khóa ở Central Vault ngoài workspace, bơm trực tiếp vào RAM tiến trình khi chạy.
  - Mô-đun **Slug Core Engine & PQC Wire Protocol**: Truyền dữ liệu vi sai (Rolling Hash Chunking), mã hóa ML-KEM-768 + XChaCha20-Poly1305, phân quyền RBAC 3 mã PIN (`[rw]`, `[r]`, `[w]`).
  - Mô-đun **Slug Guard**: Quét 5 cấp độ (Rules, .gitignore, Regex, Shannon Entropy, AI Semantic).
  - Mô-đun **Web Viewing Engine**: Giao diện điều khiển Web GUI cục bộ (Techno B2B, loopback 127.0.0.1, 0 byte external CDN).

### 2. Kịch bản Video Clip thuyết trình (Thời lượng dự kiến: 05 phút)
- **Phút 00:00 - 00:45:** Giới thiệu vấn đề thực tế tại các phòng lab và môi trường lập trình có trợ lý AI (tình trạng rò rỉ credential và quá tải đường truyền).
- **Phút 00:45 - 02:00:** Trình bày giải pháp Slug: Nguyên lý nạp cấu hình trên RAM (EnvShield) và giao thức nhị phân an toàn lượng tử.
- **Phút 02:00 - 03:45:** Trình diễn demo thực tế:
  - Thao tác 1: `slug env init` và `slug env run` (chứng minh không lưu plaintext trên ổ đĩa).
  - Thao tác 2: Mở phiên chia sẻ `slug share` với quyền Write-Only `[w]` nộp bài phòng lab.
  - Thao tác 3: Bắt gói tin bằng Wireshark chứng minh luồng dữ liệu nhị phân mã hóa, không có HTTP bản rõ.
- **Phút 03:45 - 04:30:** Nêu bật giá trị mang lại cho sinh viên, trường đại học và cộng đồng công nghệ.
- **Phút 04:30 - 05:00:** Kết luận, mục tiêu phát triển và thông điệp dự thi.

### 3. Thông tin mã nguồn và liên kết thử nghiệm (Demo Links)
- **Kho mã nguồn dự án:** `https://github.com/dotlinux26/slug`
- **Tài liệu hướng dẫn kỹ thuật:** Thư mục `docs/` trong mã nguồn dự án.
- **Kịch bản tự động chạy thử (Showcase Playground):**
  - PowerShell (Windows): `.\docs\demo\setup_demo.ps1`
  - Bash (Linux/macOS): `./docs/demo/setup_demo.sh`
