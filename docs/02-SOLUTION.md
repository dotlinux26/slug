# GIẢI PHÁP TOÀN DIỆN CỦA SLUG (THE SLUG SOLUTION)

## 1. Triết Lý Thiết Kế: "Bảo Mật Hậu Lượng Tử - Trải Nghiệm Một Chạm"

Slug giải quyết triệt để sự xung đột kinh điển giữa **tính bảo mật chặt chẽ** và **sự tiện dụng tức thì**. Dự án biến quy trình chia sẻ thư mục làm việc phức tạp (vốn đòi hỏi nhiều bước cấu hình SSH, Git remote hoặc mở port nguy hiểm) thành một trải nghiệm liền mạch:
- **Tốc độ:** Khởi tạo workspace trong 1 giây, kéo toàn bộ dự án về máy khách chỉ bằng 1 câu lệnh duy nhất.
- **Không rác hệ thống (Zero Footprint):** Các tài khoản, phiên làm việc và mã xác thực đều có thời hạn sống (TTL) và tự động tiêu hủy.
- **An toàn tuyệt đối:** Mã hóa đầu-cuối chuẩn hậu lượng tử (Post-Quantum Cryptography) kết hợp cơ chế giam giữ đường dẫn (Path Jailing) và kiểm duyệt rò rỉ bí mật.

---

## 2. Quy Hoạch 9 Lệnh Cốt Lõi ("The Essential 9" POSIX/GNU CLI)

Hệ thống dòng lệnh của Slug được chuẩn hóa theo tiêu chuẩn POSIX/GNU, phân định rõ ràng giữa danh từ (tài nguyên) và động từ (hành động).

```text
SLUG ESSENTIAL 9 ARCHITECTURE

HOST WORKSPACE               ACCESS & SECURITY            CLIENT WORKSPACE SYNC
  slug add                     slug user                    slug get (One-Shot)
  slug status                  slug audit                   slug pull
  slug totp                                                 slug push
  slug stop
```

### Bảng Chi Tiết 9 Lệnh Cốt Lõi

| Lệnh | Chức năng | Ví dụ sử dụng tiêu biểu |
| :--- | :--- | :--- |
| **`slug add [path]`** | Khởi tạo và host một workspace an toàn | `slug add . -p 9443 -s pqc -t 1d --ai` |
| **`slug status`** | Kiểm tra danh sách hoặc chi tiết server đang chạy | `slug status` hoặc `slug status -p 9443 -s` |
| **`slug totp`** | Xuất bảng 3 mã OTP phân quyền hoặc lấy mã nhanh | `slug totp -p 9443` hoặc `slug totp -p 9443 -r r --code-only` |
| **`slug stop`** | Dừng một server cụ thể hoặc dừng tất cả | `slug stop -p 9443` hoặc `slug stop --all` |
| **`slug user`** | Quản lý tài khoản truy cập phân quyền | `slug user add dev -p 9443 -r rw -t 7d` |
| **`slug audit`** | Quản lý danh sách file bị AI Guard chặn | `slug audit list -p 9443` hoặc `slug audit allow <file>` |
| **`slug get`** | Kéo dự án về máy khách trong đúng 1 lệnh (One-Shot) | `slug get "192.168.1.107:9443?otp=12822565" ./my-project` |
| **`slug pull`** | Đồng bộ vi sai các thay đổi mới nhất từ Host | `slug pull --prune` |
| **`slug push`** | Đẩy các file đã sửa hoặc file mới lên Host | `slug push --dry-run` |

### Các Lệnh Tiện Ích Hỗ Trợ (System Utilities)
- **`slug serve -p <port> [-w]`**: Xem chi tiết thông số bảo mật của server hoặc mở giao diện Web Dashboard quản trị.
- **`slug conn`**: Quản lý danh sách kết nối lưu trên máy client (`slug conn list`, `slug conn use`, `slug conn prune`).
- **`slug env`**: Bảo vệ biến môi trường nhạy cảm trong bộ nhớ RAM (`slug env init`, `slug env run -- <cmd>`).
- **`slug completion <bash|zsh>`**: Sinh script gợi ý lệnh (Tab completion) tự động nhận diện các cổng đang mở.
- **`slug bench`**: Đo kiểm tốc độ vi sai và hiệu năng thuật toán mật mã.
- **`slug version`**: Hiển thị thông tin phiên bản, commit hash và giấy phép Apache-2.0.

---

## 3. Đột Phá UX: Lệnh Một Chạm `slug get` (One-Shot Magic Transfer)

Thay vì buộc người dùng phía máy khách phải thực hiện tuần tự 3 bước:
1. `slug connect -i 192.168.1.107 -p 9443 -o 12822565`
2. Lưu và kích hoạt ngữ cảnh kết nối.
3. `slug pull` để kéo file về máy.

Lệnh **`slug get`** gộp toàn bộ chuỗi thao tác trên vào một câu lệnh duy nhất:

```bash
slug get "192.168.1.107:9443?otp=12822565" ./lab-workspace
```

### Cơ Chế Xử Lý Thông Minh Của `slug get`:
1. **Bộ phân tích URL linh hoạt (Smart URL Parser):**
   - Hỗ trợ định dạng ngắn: `192.168.1.107:9443?otp=12822565`
   - Hỗ trợ scheme tiêu chuẩn: `slug://192.168.1.107:9443?otp=12822565`
   - Hỗ trợ Web link: `http://192.168.1.107:9443/drop?ticket=24b3eca0...`
   - Nhận diện đa dạng query parameter: `?otp=`, `?token=`, `?ticket=`, `?user=`, `?pass=`.
2. **Tự động bắt tay mật mã (PQC Handshake):** Trao đổi khóa ML-KEM-768 và chữ ký số ML-DSA-65 qua kênh socket nhị phân an toàn.
3. **Kích hoạt cơ chế Single-Use Burn:** Mã OTP được máy chủ xác thực và tiêu hủy tức thì, sau đó máy chủ cấp vé phiên (Session Certificate Ticket) độc quyền.
4. **Kéo dữ liệu vi sai (Differential Sync Engine):** Tự động khởi tạo thư mục đích, tải manifest từ máy chủ, so khớp hash khối 64 KiB và tải về chính xác các khối dữ liệu còn thiếu.

---

## 4. Ba Bộ Suite Mật Mã Tiêu Chuẩn Quốc Tế

Slug cho phép lựa chọn bộ thuật toán mật mã phù hợp với yêu cầu bảo mật của hạ tầng qua cờ `-s`:

```bash
slug add . -p 9443 -s pqc
```

| Suite | Tên định danh | KEM / Key Exchange | Chữ Ký Số (Signature) | Băm Nội Dung | Mã Hóa Khối (AEAD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Suite 1** | `classical` | X25519 (ECDH) | Ed25519 | SHA-256 | XChaCha20-Poly1305 |
| **Suite 2** | `modern` | X25519 (ECDH) | Ed25519 | BLAKE3 (High-speed) | XChaCha20-Poly1305 |
| **Suite 3** | `pqc` *(Mặc định)* | **ML-KEM-768** (NIST FIPS 203) | **ML-DSA-65** (NIST FIPS 204) | **BLAKE3** | **XChaCha20-Poly1305** |

- **Suite 3 (PurePQC):** Đạt khả năng kháng tấn công thu thập trước giải mã sau (Harvest Now, Decrypt Later) của máy tính lượng tử tương lai, sử dụng bài toán toán học trên lưới đại số (Lattice-based cryptography).

---

## 5. Tầng Hệ Thống Tập Tin Ảo An Toàn (`SlugVFS`)

Để ngăn chặn hoàn toàn nguy cơ vượt ngục thư mục (Directory Traversal) và bảo vệ cây thư mục máy chủ, toàn bộ các thao tác đọc/ghi đều bị cô lập qua lớp trừu tượng `SlugVFS` (`src/core/vfs.hpp`):

1. **Định Danh Đường Dẫn Ảo (Virtual Path):**
   - Phía Client không bao giờ biết đường dẫn vật lý thực tế trên máy chủ (ví dụ: `/home/user/secret_proj`).
   - Mọi tệp tin đều được biểu diễn dưới dạng đường dẫn ảo bắt đầu từ gốc `/` (ví dụ: `/src/main.cpp`).
2. **Giam Giữ Thư Mục Tuyệt Đối (Path Jailing):**
   - Mọi yêu cầu được phân giải qua `vfs.resolve_and_jail(virtual_path, role)`.
   - Các nỗ lực chứa ký tự điều hướng (`../`, `..\\`) hoặc symbolic link trỏ ra ngoài thư mục máy chủ đều bị từ chối ngay lập tức với mã lỗi `AccessDenied`.
3. **Thực Thi RBAC Ngay Tại Tầng VFS:**
   - **`Role::WRITE_ONLY` (`w`):** Không được phép gọi `list_dir()` hoặc `read_file()`. Khách chỉ có thể đẩy file vào hòm thư mù (Blind Drop).
   - **`Role::READ_ONLY` (`r`):** Bị cấm gọi `write_file()` hoặc `delete_file()`. Khách chỉ có thể đọc và đồng bộ về máy.
   - **`Role::READ_WRITE` (`rw`):** Cho phép đồng bộ song hướng hoàn chỉnh.
4. **Bộ Lọc Tập Trung Đa Tầng:**
   - Kết hợp đồng nhất `.gitignore` phân tầng, quy tắc cấu hình nội bộ `.slug/rules.conf`, và danh sách tệp bị AI Guard chặn (`AI_FLAGGED`).

---

## 6. Cơ Chế Phân Quyền Hạt Nhân (Granular RBAC & Ephemeral TTL)

### Bộ Ba Mã OTP Tự Động Làm Mới (Role OTPs)
Mỗi workspace khi khởi chạy luôn duy trì 3 mã OTP 8 chữ số độc lập:
- `[rw] Read-Write OTP`: Dành cho lập trình viên cần kéo và đẩy code đầy đủ.
- `[r]  Read-Only OTP`: Dành cho người xem xét mã (Code Reviewer), máy chủ build CI/CD chỉ cần tải code.
- `[w]  Write-Only OTP`: Dành cho khách nộp bài, gửi log kiểm toán mà không được xem mã nguồn của máy chủ.

Mã OTP được làm mới sau mỗi 60 giây và tự động bị tiêu hủy (Single-Use Burn) ngay khi kết nối thành công.

### Tài Khoản Định Danh Và Thời Hạn Sống (TTL)
Chủ máy có thể cấp tài khoản định danh riêng cho đồng nghiệp:
```bash
# Cấp tài khoản tạm thời hết hạn sau 24 giờ
slug user add alice -p 9443 -r rw -t 24h

# Cấp tài khoản vĩnh viễn (cho server CI nội bộ)
slug user add ci-bot -p 9443 -r r -t inf
```
Sau khi hết thời hạn TTL, máy chủ sẽ tự động vô hiệu hóa tài khoản và dọn dẹp phiên làm việc mà không cần sự can thiệp thủ công của quản trị viên.

---

## 7. Giao Diện Web Techno B2B SaaS (Web Dropbox & Admin Dashboard)

Đối với các tình huống người nhận không có cài đặt sẵn Slug CLI (ví dụ: mở trên điện thoại, máy tính bảng hoặc máy khách không có quyền cài binary):
- Chủ máy mở giao diện quản trị: `slug serve -p 9443 -w`.
- Người nhận mở link chia sẻ kèm vé phiên: `http://<IP>:9443/drop?ticket=<24-byte-hex>`.

### Đặc Điểm Giao Diện Web Của Slug:
- **Phong cách Techno Minimalist B2B:** Sử dụng bảng màu tối doanh nghiệp (`#0d1117`, `#161b22`, `#21262d`, `#30363d`, `#58a6ff`), bo góc sắc nét (`2px`), font chữ kỹ thuật (`JetBrains Mono`).
- **Kéo Thả Trực Quan (No-CLI Workspace):** Người dùng kéo thả trực tiếp tệp tin hoặc thư mục vào trình duyệt để tải lên.
- **Giám Sát Thời Gian Thực (Realtime Metrics):** Biểu đồ đo kiểm hiệu năng đồng bộ (Latency, Throughput) tự động cập nhật liên tục mà không cần click chuột.
- **Bảo Vệ Phiên Bằng Capability Ticket:** Ngăn chặn truy cập trái phép bằng vé ngẫu nhiên 192-bit sinh từ CSPRNG, lưu trữ phiên hoàn toàn trong bộ nhớ RAM của máy chủ.
