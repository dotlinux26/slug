# 04. Kiến trúc Hệ thống, Cơ chế Thực thi và Ranh giới Bảo mật

> **Trọng tâm kỹ thuật:** Cách Slug hiện thực hóa các cam kết bảo mật ở tầng lõi hệ điều hành, hệ thống tệp ảo (VFS) và giao thức mạng P2P, đảm bảo tính khả thi và ổn định cao trên 1 file nhị phân C++20 độc lập.

---

## 1. Mô hình kiến trúc phân lớp (System Architecture)

Slug được thiết kế theo cấu trúc mô-đun hóa đơn hướng nghiêm ngặt bằng C++20, biên dịch tĩnh 100% không phụ thuộc thư viện ngoài (zero-runtime dependency):

```text
+-----------------------------------------------------------------------------------+
| TẦNG 1: GIAO DIỆN & ĐIỀU PHỐI (CLI DISPATCHER & LOCAL WEB EXPLORER)               |
|  - Phân tích tham số POSIX/GNU (src/main.cpp), bảng màu ANSI Terminal            |
|  - Localhost Web Explorer (Engine viewing nội bộ trên 127.0.0.1:8080)             |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 2: QUẢN LÝ BIẾN MÔI TRƯỜNG & KHO TRUNG TÂM (ENVSHIELD CORE)                  |
|  - Centralized Vault: ~/.slug/env_vault/<workspace_hash>/                         |
|  - Nạp RAM tiến trình con: Windows (CreateProcessW), Linux (execve)               |
|  - Mã hóa Envelope: ML-KEM-768 + AES-256-GCM (.env.pqc)                           |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 3: HỆ THỐNG TỆP ẢO & TRẠM KIỂM SOÁT BIÊN (SLUG VFS & JAIL GATEWAY)          |
|  - Virtual File System Jail: Chống vượt ngục ../ và bẫy Symlink (resolve_safe_path)|
|  - Cổng kiểm soát đọc (Closed-Loop Gating): vfs_.read_file() ép qua Audit Index   |
|  - Chế độ lọc 3 mức: protected (mặc định), include-ignored, none                  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 4: CHÍNH SÁCH BẢO MẬT & KIỂM DUYỆT (POLICY & AUDIT ENGINE)                   |
|  - Bộ phân tích phân tầng .gitignore và chính sách máy chủ .slug/rules.conf       |
|  - Stateful Audit Index (.slug/index.db) băm BLAKE3, phát hiện sửa đổi STALE      |
|  - Heuristic Scanner + Shannon Entropy Analyzer + Trợ lý AI ngữ nghĩa             |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 5: MẬT MÃ & GIAO VẬN MẠNG P2P (CRYPTO PRIMITIVES & WIRE TRANSPORT)           |
|  - Bắt tay hậu lượng tử: NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65)    |
|  - Xác thực nhanh: Mã OTP 8 chữ số (RFC 6238 TOTP), tiêu thụ 1 lần chống replay    |
|  - Mã hóa kênh truyền: AES-256-GCM / XChaCha20-Poly1305 với phân tách khóa 2 chiều|
+-----------------------------------------------------------------------------------+
```

---

## 2. Cơ chế EnvShield: Cấp biến môi trường từ RAM cho tiến trình con

### 2.1. Bản chất cách hệ điều hành kế thừa môi trường
Khi sinh viên hoặc AI Agent chạy một lệnh kiểm thử hoặc khởi động ứng dụng (ví dụ `pytest`, `npm test`, `python app.py`):
- Mọi ngôn ngữ lập trình và framework (Node.js `process.env`, Python `os.environ`, Go/Rust/C++ `getenv()`) đều ưu tiên đọc giá trị từ **Khối môi trường (Environment Block) trên bộ nhớ RAM** của chính tiến trình đó trước khi nghĩ đến việc tìm file `.env` trên đĩa.
- `slug env run -- <lệnh>` tận dụng nguyên lý này:
  1. Đọc và giải mã `.env.pqc` trực tiếp vào một cấu trúc dữ liệu tạm thời trong RAM của Slug.
  2. Nạp khối môi trường này vào tiến trình con thông qua syscall cấp thấp của hệ điều hành:
     - Trên Windows: Sử dụng `CreateProcessW` với khối Unicode Environment Block (`lpEnvironment`).
     - Trên Linux: Sử dụng `fork` và `execve` với mảng `envp`.
  3. Xóa sạch vùng nhớ chứa secret trong tiến trình cha ngay sau khi tiến trình con khởi tạo thành công (`memset_s` / secure memory wipe).

### 2.2. Điểm ma sát thực tế và cách Slug giải quyết
- **Trường hợp ứng dụng tương thích môi trường chuẩn (Đa số):** Ứng dụng nhận đủ biến môi trường ngay từ RAM, chạy hoàn hảo mà không cần có bất kỳ file `.env` nào trên đĩa cứng.
- **Trường hợp công cụ bị hardcode bắt buộc đọc file đĩa:** Một số công cụ hoặc thư viện đặc thù có thể được lập trình cứng bắt buộc phải `fopen("./.env")`, nếu không thấy file sẽ báo lỗi `FileNotFound`.
  - **Cách xử lý của Slug:** Người dùng chỉ cần gõ `slug env restore` để lấy lại file `.env` từ Central Vault (`~/.slug/env_vault/<hash>/`) trong 1 giây. Khi làm việc xong, chỉ cần gõ `slug env init` để xóa lại file đĩa.

---

## 3. Hệ thống tệp ảo (SlugVFS) & Cổng kiểm soát đọc (Closed-Loop Gating)

### 3.1. Điểm khác biệt giữa công cụ quét rời rạc và Slug VFS
- Với công cụ rời rạc (`gitleaks` + `http.server`): Công cụ quét chỉ in ra màn hình. Nếu người dùng quên quét hoặc cố tình mở cổng truyền file, toàn bộ dữ liệu nhạy cảm vẫn bị gửi đi bình thường.
- Với **Slug**: Việc kiểm duyệt được gắn trực tiếp vào **đường đọc dữ liệu của hệ thống tệp ảo** (`vfs_.read_file()`):
  ```cpp
  // Mã thực tế trong src/core/vfs.cpp
  if (filter_mode != FilterMode::NONE) {
      if (!is_file_allowed(rel_path)) {
          return VFSResult::err(VFSError::PERMISSION_DENIED);
      }
  }
  ```
  Ngay cả khi một client gửi yêu cầu tải trực tiếp một chunk dữ liệu nhằm né tránh danh sách manifest, hàm đọc của máy chủ sẽ từ chối ngay lập tức tại ranh giới filesystem.

### 3.2. Ba chế độ chia sẻ (Configurable Filter Modes)
Người dùng có toàn quyền điều khiển mức độ lọc khi chia sẻ workspace thông qua lệnh `slug add`:
1. **`protected` (Mặc định):** Kích hoạt toàn bộ bộ lọc `.gitignore`, luật cấm `.slug/rules.conf`, quét secret và cách ly tự động.
2. **`include-ignored` (`--include-ignored`):** Cho phép chia sẻ cả các file build/artifact thường bị ignore, nhưng **vẫn giữ nguyên rào chắn chặn secret và file nhạy cảm**.
3. **`none` (`--no-filter`):** Chia sẻ thô toàn bộ thư mục cho các đồng đội tin cậy trong mạng nội bộ.
   - **Bảo chứng an toàn bất biến (Security Invariant):** Kể cả khi chạy ở chế độ `none`, Slug **tuyệt đối không bao giờ cho phép** đọc vượt ngục ra khỏi thư mục gốc (`resolve_safe_path`), không bao giờ chia sẻ thư mục khóa nội bộ `.slug/`, và luôn yêu cầu mã xác thực OTP 8 số trước khi bắt tay.

---

## 4. Giao thức P2P: Bắt tay hậu lượng tử và Xác thực OTP 8 số

### 4.1. Mã OTP 8 chữ số tự hủy (One-Time Ephemeral TOTP)
- Để kết nối nhanh giữa 2 máy sinh viên trong mạng LAN mà không cần tạo tài khoản hay trao đổi mật khẩu dài dòng:
  - Máy Host tạo ra một mã 8 chữ số ngẫu nhiên có thời gian sống ngắn (dựa trên RFC 6238 TOTP).
  - Phía máy Host áp dụng **cơ chế tiêu thụ trạng thái nguyên tử (Atomic Single-Use)**: Ngay khi máy khách xác thực thành công, mã OTP lập tức bị đốt cháy (burned). Mọi nỗ lực kết nối lại bằng mã cũ đều bị từ chối, triệt tiêu nguy cơ tấn công phát lại (Replay Attack).

### 4.2. Mật mã hậu lượng tử (Post-Quantum Cryptography)
- Slug ứng dụng các tiêu chuẩn mật mã học mới nhất do Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ (NIST) ban hành (tháng 8/2024):
  - **NIST FIPS 203 (ML-KEM-768):** Cơ chế đóng gói khóa mạng tinh thể (Module-Lattice KEM) để thiết lập khóa phiên bí mật dùng chung an toàn trước cả máy tính lượng tử tương lai.
  - **NIST FIPS 204 (ML-DSA-65):** Chữ ký số mạng tinh thể xác thực danh tính máy chủ.
  - **Mã hóa dữ liệu AEAD (AES-256-GCM / XChaCha20-Poly1305):** Đảm bảo tính bảo mật và toàn vẹn dữ liệu cho từng khối (chunk) truyền qua mạng.

---

## 5. Bảng ma trận ranh giới an toàn (Threat Model & Boundaries)

Để đảm bảo tính trung thực và minh bạch khoa học, Slug công bố rõ ràng ranh giới bảo vệ:

| Tình huống nguy cơ | Mức độ Slug bảo vệ | Cơ chế thực hiện |
| :--- | :---: | :--- |
| **Vô tình push `.env` lên GitHub public** | **Ngăn chặn triệt để** | `slug env init` đã xóa file `.env` khỏi đĩa, chỉ còn file mã hóa `.env.pqc`. |
| **AI Agent đọc lén secret từ ổ cứng** | **Ngăn chặn triệt để** | Ổ cứng không có plaintext; AI được hướng dẫn qua `.slug/ai-rule.md`. |
| **Chạy lén lệnh in bộ nhớ / printenv trong code** | *Ngoài phạm vi* | Tiến trình con có quyền đọc biến trên RAM của chính nó để thực thi code. |
| **Sniffing bắt gói tin trong mạng Wi-Fi công cộng** | **Bảo vệ tuyệt đối** | Kênh P2P mã hóa bằng AEAD 256-bit, không có byte HTTP lộ thiên trên mạng. |
| **Gửi nhầm file chứa API key cho bạn qua mạng** | **Tự động cách ly** | AI Guard và Heuristic phát hiện và VFS Jail chặn tại hàm đọc chunk. |
| **Tấn công đường dẫn thư mục `../../etc/passwd`** | **Ngăn chặn triệt để** | `PathUtils::resolve_safe_path` ép mọi đường dẫn nằm gọn trong root workspace. |
