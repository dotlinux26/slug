# Slug - Hướng Dẫn Sử Dụng & Triển Khai Toàn Diện (Tiếng Việt)

> **Slug: Chia Sẻ & Đồng Bộ Workspace Bảo Mật P2P, Hậu Lượng Tử (Post-Quantum)**
> Giấy phép: Apache-2.0 | Kiến trúc: C++20 Portable, Độc lập runtime (Zero Dependencies)

---

## Mục Lục

1. [Giới thiệu Slug](#1-giới-thiệu-slug)
2. [Cài đặt trên mọi bản phân phối Linux](#2-cài-đặt-trên-mọi-bản-phân-phối-linux)
3. [Cài đặt trên Microsoft Windows](#3-cài-đặt-trên-microsoft-windows)
4. [3 Bộ mã hóa (Crypto Suites)](#4-3-bộ-mã-hóa-crypto-suites)
5. [Khởi động nhanh: Chia sẻ Folder P2P](#5-khởi-động-nhanh-chia-sẻ-folder-p2p)
6. [Cơ chế xác thực: One-Time TOTP & Phân quyền RBAC](#6-cơ-chế-xác-thực-one-time-totp--phân-quyền-rbac)
7. [Đồng bộ vi sai kiểu Git (Delta Sync 64 KiB)](#7-đồng-bộ-vi-sai-kiểu-git-delta-sync-64-kib)
8. [Bộ lọc bảo mật & Stateful AI Secret Guard](#8-bộ-lọc-bảo-mật--stateful-ai-secret-guard)
9. [EnvShield: Chạy ứng dụng với RAM-only Secret](#9-envshield-chạy-ứng-dụng-với-ram-only-secret)
10. [Bộ đo đạc hiệu năng (Benchmark Suite)](#10-bộ-đo-đạc-hiệu-năng-benchmark-suite)
11. [Kịch bản thực chiến: Red Team, Pentest & Dev Team](#11-kịch-bản-thực-chiến-red-team-pentest--dev-team)
12. [Bảng tra cứu lệnh CLI (Cheatsheet)](#12-bảng-tra-cứu-lệnh-cli-cheatsheet)

---

## 1. Giới thiệu Slug

Slug được thiết kế để giải quyết bài toán: **Làm thế nào để chuyển giao và đồng bộ code/workspace an toàn giữa 2 máy mà không phải đẩy lên cloud, không cần Git repository công khai, không để lộ secret và không bị nghe lén bởi máy tính lượng tử?**

### So sánh Slug với Git, Rsync và SSH:

- **Khác Git:** Git lưu toàn bộ lịch sử commit vĩnh viễn trên server. Slug chỉ tạo phiên chia sẻ tạm thời (ephemeral), tự hủy theo thời gian (TTL) và không cần git remote.
- **Khác Rsync/SCP:** Rsync chuyển nguyên vẹn file chứa mật khẩu, key, token. Slug tích hợp **Stateful AI Secret Guard** tự động chặn leak key và mã hóa đường truyền bằng **ML-KEM-768 / XChaCha20-Poly1305**.
- **Khác SSH:** Không cần tạo tài khoản hệ điều hành, không cần quản lý file `authorized_keys`. Mỗi phiên được bảo vệ bởi mã TOTP 8 chữ số tự hủy sau lần bắt tay đầu tiên.

---

## 2. Cài đặt trên mọi bản phân phối Linux

Slug được biên dịch tĩnh hoàn toàn (`slug-static`), không phụ thuộc vào phiên bản `glibc` hay `musl` động trên máy. Nhờ đó, file thực thi chạy được trên:
- Ubuntu, Debian, Kali Linux, Linux Mint, Pop!_OS
- Fedora, CentOS, RHEL, Rocky Linux, AlmaLinux
- Arch Linux, Manjaro
- Alpine Linux (musl)
- Void Linux, openSUSE, NixOS

### Cách 1: Script cài đặt tự động (Khuyên dùng)
Chỉ cần chạy lệnh sau trên terminal:
```bash
curl -fsSL https://raw.githubusercontent.com/slugproject/slug/main/scripts/install.sh | bash
```
Hoặc nếu bạn đã tải mã nguồn về máy:
```bash
./scripts/install.sh
```

Script sẽ tự động:
1. Nhận diện kiến trúc CPU (`x86_64` hoặc `aarch64`).
2. Cài đặt file thực thi vào `/usr/local/bin/slug` (hoặc `~/.local/bin/slug`).
3. Cài đặt tính năng gợi ý lệnh (Bash tab-completion).
4. Kiểm tra phiên bản bằng `slug version`.

### Cách 2: Gói cài đặt Debian / Ubuntu (.deb)
```bash
# Đóng gói file .deb:
./scripts/package_deb.sh

# Cài đặt qua dpkg:
sudo dpkg -i dist/slug_1.0.0-rc1_amd64.deb
```

### Cách 3: Sử dụng trực tiếp file nén Tarball
```bash
tar -xzf dist/slug-1.0.0-rc1-linux-x86_64.tar.gz
cd slug-1.0.0-rc1-linux-x86_64/
sudo mv slug /usr/local/bin/
sudo chmod +x /usr/local/bin/slug
```

---

## 3. Cài đặt trên Microsoft Windows

Slug hỗ trợ đầy đủ Windows 10, Windows 11, Windows Server (x64).

### Cách 1: Cài đặt qua PowerShell (Khuyên dùng)
Mở PowerShell và chạy lệnh:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```
Script sẽ tự động sao chép `slug.exe` vào `%LOCALAPPDATA%\slug\bin` và thêm đường dẫn vào biến môi trường `PATH` vĩnh viễn.

### Cách 2: Tự biên dịch trên Windows với Visual Studio 2022
Yêu cầu:
- Visual Studio 2022 (MSVC C++20).
- CMake 3.20+.
- OpenSSL (qua vcpkg hoặc Chocolatey: `choco install openssl.light`).

Chạy file script biên dịch:
```cmd
scripts\build_windows.bat
```
File thực thi độc lập sẽ nằm tại `bin\slug.exe`.

---

## 4. 3 Bộ mã hóa (Crypto Suites)

Slug cung cấp 3 bộ mã hóa phù hợp với các cấp độ bảo mật khác nhau:

- **Suite 1 (Classical):** SHA-256 + X25519 + Ed25519 + XChaCha20-Poly1305.
- **Suite 2 (Modern):** BLAKE3 + X25519 + Ed25519 + XChaCha20-Poly1305.
- **Suite 3 (PurePQC - Mặc định):** BLAKE3 + ML-KEM-768 (Kyber FIPS 203) + ML-DSA-65 (Dilithium FIPS 204) + XChaCha20-Poly1305.

> **Tại sao nên dùng Suite 3?**
> Các thuật toán RSA hay ECC có nguy cơ bị bẻ khóa bởi máy tính lượng tử trong tương lai. Suite 3 sử dụng mật mã mạng tinh thể (lattice-based) theo chuẩn NIST FIPS 203/204, vô hiệu hóa hoàn toàn chiến thuật tấn công "Thu thập hôm nay, giải mã sau này".

---

## 5. Khởi động nhanh: Chia sẻ Folder P2P

### Bước 1: Máy A (Host) mở chia sẻ thư mục
Chia sẻ thư mục `./du_an` tại cổng `9443`, mã hóa Suite 3, thời hạn sống (TTL) 4 tiếng:
```bash
slug add ./du_an -p 9443 -s 3 --ttl 4h -ai --daemon
```

Kết quả hiển thị:
```text
+----------------------------------------------------------------------------+
| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |
+----------------------------------------------------------------------------+
  Port:            9443
  Crypto Suite:    Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)
  AI Secret Guard: ENABLED (Stateful BLAKE3 Audit)
  Session TTL:     4h
  One-Time TOTP:   49182305 (Rotates in 30s)
  Directory Drop:  http://127.0.0.1:9443/drop
  Admin Dashboard: http://127.0.0.1:9443/admin
+----------------------------------------------------------------------------+
```

### Bước 2: Máy B kiểm tra kết nối & bắt tay bảo mật
```bash
slug connect -i 192.168.1.50 -p 9443 -o 49182305
```

### Bước 3: Máy B kéo dữ liệu về máy (Pull)
```bash
slug pull ./du_an_tai_ve -i 192.168.1.50 -p 9443 -o 49182305
```

### Bước 4: Máy B đẩy sửa đổi ngược lại Máy A (Push)
```bash
slug push ./du_an_tai_ve src/tinh_nang_moi.cpp -i 192.168.1.50 -p 9443 -u alice -W mat_khau_alice
```

### Bước 5: Truy cập qua Web GUI & Trình duyệt
Máy trong mạng có thể mở trình duyệt:
- `http://192.168.1.50:9443/drop`: Tải nhanh từng file.
- `http://192.168.1.50:9443/admin`: Bảng điều khiển xem thống kê, log và chạy benchmark trực tiếp.

---

## 6. Cơ chế xác thực: One-Time TOTP & Phân quyền RBAC

### 1. Mã OTP dùng một lần (One-Time TOTP)
- Sinh mã 8 chữ số tuân thủ RFC 6238, xoay vòng mỗi 30 giây.
- **Tự hủy (Burn-on-use):** Ngay khi client bắt tay thành công với mã TOTP hiện tại, mã đó lập tức bị hủy bỏ trong server để chống phát lại (replay attack).

### 2. Phân quyền người dùng tạm thời (RBAC)
Cấu hình trong file `.slug/users.conf`:
- `r` (Chỉ đọc): Cho phép xem manifest và tải file.
- `rw` (Đọc/Ghi): Cho phép đẩy file sửa đổi vào phạm vi được cấp phép.
- `audit` (Kiểm toán): Chỉ xem log và trạng thái bảo mật.

---

## 7. Đồng bộ vi sai kiểu Git (Delta Sync 64 KiB)

Slug không tải lại toàn bộ file nếu file đó chỉ sửa một phần nhỏ.
1. Cắt file thành các khối 64 KiB và băm bằng BLAKE3.
2. Client so sánh hash của từng block với server.
3. Chỉ truyền tải các khối block bị thay đổi qua kênh mã hóa XChaCha20.
4. Kiểm tra trạng thái thay đổi trước khi pull bằng `slug status` và `slug diff`.

---

## 8. Bộ lọc bảo mật & Stateful AI Secret Guard

Khi bật cờ `-ai`, Slug tự động quét mã nguồn trước khi truyền tải:
- Quét entropy thông tin (Shannon entropy) tìm chuỗi ngẫu nhiên có độ dài lớn.
- Quét biểu thức chính quy (Regex): AWS Access Key, Stripe Live Key, GitHub PAT, RSA/EC Private Key.
- Tự động bỏ qua `.env`, `.git`, `node_modules`, `build/`.

### Cache trạng thái (`.slug/index.db`)
Kết quả quét được lưu theo mã băm BLAKE3. File không đổi sẽ được bỏ qua tức thì (chỉ mất **0.015 μs** tra cứu cache).

### Tùy chỉnh luật (`.slug/rules.conf`)
```bash
# Chặn toàn bộ file có đuôi .pem:
slug rule block --ext pem

# Chặn file chứa cụm từ nhạy cảm:
slug rule block --contains "BEGIN PRIVATE KEY"

# Cho phép ngoại lệ một file mẫu:
slug rule allow --path ./.env.example

# Xem danh sách luật:
slug rule list
```

### Xử lý dương tính giả (False Positives)
Nếu file test chứa mock token bị nhận nhầm là secret:
```bash
# Đưa vào danh sách ngoại lệ được người dùng phê duyệt:
slug audit allow tests/mock_token.ts --reason "Key mock phục vụ unit test"

# Kiểm tra lại:
slug audit recheck tests/mock_token.ts
```

---

## 9. EnvShield: Chạy ứng dụng với RAM-only Secret

Để bảo vệ file `.env` chứa mật khẩu cơ sở dữ liệu và API key:

1. **Mã hóa file `.env`**:
   ```bash
   slug env init -s 3
   ```
   File `.env` dạng văn bản rõ sẽ bị xóa an toàn khỏi đĩa cứng và thay thế bằng `.env.pqc` được mã hóa bởi Suite 3.

2. **Chạy ứng dụng trực tiếp từ RAM**:
   ```bash
   slug env run -- python3 app.py
   # hoặc
   slug env run -- npm start
   ```
   Slug giải mã secret vào bộ nhớ RAM của tiến trình, tiêm biến môi trường cho ứng dụng con và xóa sạch vùng nhớ ngay lập tức (zeroize). Secret không bao giờ ghi xuống ổ cứng.

---

## 10. Bộ đo đạc hiệu năng (Benchmark Suite)

Slug tích hợp sẵn công cụ đo đạc chuẩn xác tốc độ mật mã và thông lượng:

### Chạy từ Terminal:
```bash
# Đo nhanh:
slug bench --quick

# Xuất dữ liệu JSON cho hệ thống tự động:
slug bench --json --quick
```

Kết quả đo đạc thực tế:
- **ML-KEM-768 Encap/Decap:** ~36–79 μs (đạt gần 6.000–7.000 ops/s).
- **ML-DSA-65 Sign/Verify:** ~109–548 μs.
- **XChaCha20-Poly1305:** ~500–600 MB/s.
- **BLAKE3 Tree Hashing:** ~1.050 MB/s.
- **Tra cứu Cache AI Guard:** 0.015 μs / file (không tốn tài nguyên khi file không đổi).
- **Delta Chunker:** > 1.000 MB/s (16.700 chunks/giây).

### Chạy từ Web GUI:
Truy cập `http://<IP>:<Port>/admin` và nhấn nút **"Run Real-Time Benchmark"** để kích hoạt đo đạc trực tiếp trên máy chủ.

---

## 11. Kịch bản thực chiến: Red Team, Pentest & Dev Team

Trong các đợt kiểm thử xâm nhập (Pentest) hoặc tác chiến mạng (Red Team):
- Cần chuyển report, payload lab, wordlist giữa máy Linux và máy Windows trong mạng nội bộ.
- Mở một cổng ephemeral với TTL 30 phút: `slug add ./payloads -p 18443 -s 3 --ttl 30m --daemon`.
- Phía máy đích chỉ cần chạy: `slug.exe pull C:\staging -i <IP> -p 18443 -o <TOTP>`.
- Hết 30 phút, server tự động đóng, xóa sạch dấu vết mạng, không để lại artifact trên bất kỳ dịch vụ lưu trữ trung gian nào.

---

## 12. Bảng tra cứu lệnh CLI (Cheatsheet)

| Lệnh | Ý nghĩa |
| :--- | :--- |
| `slug add <path> -p <port> -s 3 --ttl 2h -ai --daemon` | Khởi tạo và chia sẻ workspace ngầm |
| `slug list` | Xem danh sách workspace đang chạy |
| `slug stop -p <port>` | Tắt workspace trên cổng chỉ định |
| `slug connect -i <ip> -p <port> -o <totp>` | Kết nối kiểm tra bắt tay bảo mật |
| `slug pull <dir> -i <ip> -p <port> -o <totp>` | Tải toàn bộ file trong workspace |
| `slug push <dir> <file> -i <ip> -p <port> -u <u> -W <p>` | Đẩy file sửa đổi lên host |
| `slug diff <dir> -i <ip> -p <port> -o <totp>` | So sánh sự khác biệt nội dung file |
| `slug status` | Kiểm tra trạng thái đồng bộ và cảnh báo secret |
| `slug rule list` | Xem danh sách bộ lọc bảo mật |
| `slug rule block --ext pem` | Chặn chia sẻ file theo đuôi |
| `slug audit allow <path> --reason "..."` | Bỏ chặn cho file ngoại lệ |
| `slug env init -s 3` | Mã hóa `.env` thành `.env.pqc` |
| `slug env run -- <lệnh>` | Chạy ứng dụng với secret nạp thẳng vào RAM |
| `slug bench --quick` | Đo đạc hiệu năng mật mã và thông lượng |
| `slug version` | Hiển thị phiên bản phần mềm |
