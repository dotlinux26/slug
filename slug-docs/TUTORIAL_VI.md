# Slug - Hướng Dẫn Sử Dụng & Triển Khai Toàn Diện (Tiếng Việt)

> **Slug: Chia Sẻ & Đồng Bộ Workspace Bảo Mật P2P, Mật Mã Hậu Lượng Tử (Post-Quantum)**  
> Giấy phép: Apache-2.0 | Kiến trúc: C++20 Portable, Độc lập runtime (Zero-Dependency Static Binary ~8.4 MB)

---

## Mục Lục

1. [Giới thiệu Slug & Tôn chỉ No-Overclaim](#1-giới-thiệu-slug--tôn-chỉ-no-overclaim)
2. [Cài đặt & Biên dịch nhanh](#2-cài-đặt--biên-dịch-nhanh)
3. [Giao diện Web Viewing Engine & Lối tắt Desktop](#3-giao-diện-web-viewing-engine--lối-tắt-desktop)
4. [3 Bộ mật mã (Crypto Suites) & Kiến trúc Directional AEAD](#4-3-bộ-mật-mã-crypto-suites--kiến-trúc-directional-aead)
5. [Khởi động nhanh: Chia sẻ & Đồng bộ Workspace](#5-khởi-động-nhanh-chia-sẻ--đồng-bộ-workspace)
6. [Cơ chế xác thực: 3 Mã OTP phân quyền & RBAC Ephemeral](#6-cơ-chế-xác-thực-3-mã-otp-phân-quyền--rbac-ephemeral)
7. [Đồng bộ vi sai kiểu Git (Delta Sync 64 KiB) & Tải file đơn](#7-đồng-bộ-vi-sai-kiểu-git-delta-sync-64-kib--tải-file-đơn)
8. [Bộ lọc bảo mật: Slug Guard, Whitelist & Cố vấn AI](#8-bộ-lọc-bảo-mật-slug-guard-whitelist--cố-vấn-ai)
9. [EnvShield & Central Vault: Bảo vệ file .env khỏi AI Assistants](#9-envshield--central-vault-bảo-vệ-file-env-khỏi-ai-assistants)
10. [Bộ đo đạc hiệu năng (Benchmark Suite)](#10-bộ-đo-đạc-hiệu-năng-benchmark-suite)
11. [Kịch bản thực chiến: Lớp học nộp bài, Red Team & Dev Team](#11-kịch-bản-thực-chiến-lớp-học-nộp-bài-red-team--dev-team)
12. [Bảng tra cứu lệnh CLI chuẩn mực (Cheatsheet)](#12-bảng-tra-cứu-lệnh-cli-chuẩn-mực-cheatsheet)

---

## 1. Giới thiệu Slug & Tôn chỉ No-Overclaim

Slug được thiết kế để giải quyết bài toán: **Làm thế nào để chia sẻ và đồng bộ mã nguồn/workspace an toàn giữa các máy tính mà không phải đẩy lên cloud, không cần Git repository công khai, không lãng phí băng thông WAN, không để lộ bí mật và không bị nghe lén bởi máy tính lượng tử trong tương lai?**

### So sánh Slug với Git, Rsync và HTTP Server:
- **Khác Git:** Git lưu toàn bộ lịch sử commit vĩnh viễn trên remote repository. Slug tạo phiên chia sẻ tạm thời (ephemeral), tự hủy theo thời gian (TTL) và đồng bộ vi sai trực tiếp P2P.
- **Khác Rsync/SCP:** Rsync chuyển nguyên vẹn file chứa mật khẩu, key, token. Slug tích hợp **Slug Guard** (100% offline, Regex + Shannon Entropy $H(X) \ge 4.0$) tự động cách ly credential và hỗ trợ kênh truyền mã hóa **ML-KEM-768 / XChaCha20-Poly1305**.
- **Khác `python -m http.server`:** Không phơi bày plaintext HTTP ra mạng LAN. Kênh truyền trên dây mạng là **100% nhị phân PQC an toàn lượng tử (Zero Remote HTTP)**; hỗ trợ phân quyền rõ ràng (`[rw]` Đọc/Ghi, `[r]` Chỉ Đọc, `[w]` Hộp Thư Nộp Bài chống nhìn trộm).

---

## 2. Cài đặt & Biên dịch nhanh

Slug được biên dịch tĩnh hoàn toàn (`slug-static`), không phụ thuộc vào `glibc` của hệ thống máy chủ, chạy mượt mà trên mọi hệ điều hành.

### 2.1. Cài đặt trên Linux / macOS
```bash
# Script cài đặt tự động 1 lệnh:
curl -fsSL https://raw.githubusercontent.com/dotlinux26/slug/main/scripts/install.sh | bash

# Hoặc cài đặt gói Debian / Ubuntu (.deb):
sudo dpkg -i dist/slug_1.0.0_amd64.deb

# Hoặc tải file thực thi tĩnh độc lập:
chmod +x slug-linux-x86_64 && sudo mv slug-linux-x86_64 /usr/local/bin/slug
```

### 2.2. Cài đặt trên Microsoft Windows
```powershell
# Script cài đặt tự động qua PowerShell:
irm https://raw.githubusercontent.com/dotlinux26/slug/main/scripts/install.ps1 | iex

# Hoặc giải nén và thiết lập PATH:
Expand-Archive slug-1.0.0-windows-x86_64.zip -DestinationPath "$env:LOCALAPPDATA\slug\bin"
[Environment]::SetEnvironmentVariable("PATH", "$([Environment]::GetEnvironmentVariable('PATH','User'));$env:LOCALAPPDATA\slug\bin", "User")
```

### 2.3. Tự biên dịch từ mã nguồn (Build From Source)
Yêu cầu: Trình biên dịch C++20 (`g++-11+`, `clang++-14+`, hoặc MSVC 2022 v143), thư viện OpenSSL 3.0+.
```bash
# Trên Linux: Biên dịch binary tĩnh:
make static -j$(nproc)

# Trên Windows (MSVC 2022 Prompt / PowerShell):
scripts\build_windows.bat
```

---

## 3. Giao diện Web Viewing Engine & Lối tắt Desktop

Slug tích hợp sẵn Web Command Center và Web Dropbox Explorer tinh gọn theo phong cách **Techno B2B** (bo góc sắc cạnh 2px, font JetBrains Mono, 100% SVG vector offline không phụ thuộc internet).

### 3.1. Khởi chạy 1-Chạm (Zero-Config GUI)
Chỉ cần gõ lệnh không tham số:
```bash
slug
# hoặc
slug portal
```
Slug sẽ tự động:
1. Kích hoạt Web Viewing Engine trên loopback cục bộ `http://127.0.0.1:8080/` (tự động tịnh tiến cổng nếu 8080 bận).
2. Tự động mở trình duyệt web mặc định của bạn.
3. Toàn bộ lưu lượng truyền tải từ xa qua mạng LAN/Internet đều là các gói nhị phân PQC đã mã hóa, hoàn toàn **Zero Remote HTTP**.

### 3.2. Tạo lối tắt màn hình Desktop (Windows)
```powershell
slug shortcut
```
Lệnh này tạo lối tắt `Slug Workspace.lnk` trên màn hình Desktop. Khi khởi chạy từ lối tắt hoặc File Explorer, Slug tự động kích hoạt chế độ **Absolute Stealth** (ẩn hoàn toàn cửa sổ terminal đen), mang lại trải nghiệm phần mềm Desktop chuyên nghiệp.

---

## 4. 3 Bộ mật mã (Crypto Suites) & Kiến trúc Directional AEAD

Slug cung cấp 3 bộ mật mã phù hợp với từng nhu cầu:

| Tiêu chí | Suite 1: Classical | Suite 2: Modern | Suite 3: PurePQC (Mặc định) |
| :--- | :--- | :--- | :--- |
| **KEM / Trao đổi khóa** | X25519 (ECDH 128-bit) | X25519 (ECDH 128-bit) | **ML-KEM-768 (Kyber NIST FIPS 203)** |
| **Chữ ký số (Sign/Verify)** | Ed25519 (128-bit) | Ed25519 (128-bit) | **ML-DSA-65 (Dilithium NIST FIPS 204)** |
| **Hàm băm (Hashing)** | SHA-256 | BLAKE3 (Băm cây đa luồng) | **BLAKE3 (Băm cây đa luồng)** |
| **Mã hóa luồng (AEAD)** | XChaCha20-Poly1305 | XChaCha20-Poly1305 | **XChaCha20-Poly1305 (256-bit)** |
| **Kháng Lượng Tử (PQC)** | ❌ Không | ❌ Không | ✅ **Kháng lượng tử 100% FIPS 203/204** |

### Kỹ thuật mật mã chuyên sâu (Hardcore Crypto Internals):
- **Directional Salt AEAD:** Khóa phiên được dẫn xuất qua `BLAKE3-KDF` thành 2 muối độc lập: `ClientToServer_Salt` (16B) và `ServerToClient_Salt` (16B). Đảm bảo 2 chiều gửi và nhận không bao giờ dùng chung Nonce, triệt tiêu hoàn toàn rủi ro Nonce-Reuse trong XChaCha20.
- **Cửa sổ trượt chống phát lại (Anti-Replay Window 64-bit):** Mỗi frame nhị phân mang số thứ tự tăng dần `tx_seq`. Phía nhận duy trì bitmap 64-bit để phát hiện và hủy ngay các gói tin phát lại.
- **Chunk-Level AEAD:** File lớn được chia thành các khối 64 KiB. Mỗi khối đều được xác thực độc lập bằng mã MAC Poly1305 (16B) trước khi giải mã, bảo vệ chống giả mạo dữ liệu trung gian (MITM).
- **Ephemeral KEM Forward Secrecy:** Mỗi phiên kết nối sinh một cặp khóa KEM tạm thời, khóa phiên bị hủy sạch khỏi RAM ngay khi đóng kết nối.

---

## 5. Khởi động nhanh: Chia sẻ & Đồng bộ Workspace

### Bước 1: Phía Máy Chủ (Host) mở chia sẻ thư mục
Chia sẻ thư mục `./du_an` tại cổng `9443`, mã hóa Suite 3 (PurePQC), thời hạn sống (TTL) 24 tiếng, bật Slug Guard:
```bash
slug add ./du_an -p 9443 -s pqc -t 24h -d
```
Màn hình xuất hiện bảng thông số và bộ 3 mã OTP phân quyền:
```text
+----------------------------------------------------------------------------+
| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |
| Path:            D:/du_an                                                  |
| Port:            9443                                                      |
| Crypto Suite:    Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)   |
| AI Secret Guard: ON                                                        |
| Session TTL:     24h                                                       |
| Role OTPs (Rotates in 30s):                                                |
|   [rw] Read-Write OTP: 12822565 (Full Sync & Web Dropbox)                  |
|   [r]  Read-Only OTP:  08796195 (Read/Pull/View files only)                |
|   [w]  Write-Only OTP: 70788146 (Blind Drop/Upload only)                   |
+----------------------------------------------------------------------------+
```

### Bước 2: Phía Máy Khách (Client) kết nối và đồng bộ

#### Cách A: Đồng bộ toàn bộ thư mục bằng lệnh `slug pull` (CLI)
```bash
slug pull -i 192.168.1.105 -p 9443 -o 12822565 --to ./du_an_tai_ve
```
Tiến trình sẽ tự động hiển thị kế hoạch truyền tải vi sai (Transfer Plan Preview), yêu cầu xác nhận và kéo các khối thay đổi về máy.

#### Cách B: Tải ĐÚNG 1 tệp tin cụ thể bằng lệnh `slug get`
```bash
slug get 192.168.1.105:9443?otp=12822565 src/main.cpp ./main.cpp
```

#### Cách C: Trải nghiệm trực quan qua Web Viewing Engine
Mở giao diện Web Viewing Engine cục bộ:
```bash
slug
```
Trình duyệt tự mở `http://127.0.0.1:8080/`. Nhập IP `192.168.1.105:9443` và mã OTP `12822565` -> Bấm **Kết Nối Nhanh** -> Vào **Tab 3: Web Dropbox Explorer** để duyệt tệp hoặc nhấn **Tải Toàn Bộ Thư Mục (ZIP)**.

---

## 6. Cơ chế xác thực: 3 Mã OTP phân quyền & RBAC Ephemeral

### 6.1. Bộ ba mã OTP phân quyền (Role-Based One-Time Tokens)
Slug sinh 3 mã OTP 8 chữ số phân quyền độc lập, xoay vòng mỗi 30–60 giây:
- **`[rw]` Read-Write OTP:** Quyền cao nhất, cho phép duyệt cây thư mục, kéo toàn bộ workspace và đẩy sửa đổi lên.
- **`[r]` Read-Only OTP:** Quyền chỉ đọc, chỉ cho phép tải file hoặc pull về máy, cấm ghi sửa đổi.
- **`[w]` Write-Only OTP:** Quyền hộp thư một chiều (Blind Drop), chỉ cho phép tải file lên máy chủ, cấm hoàn toàn xem danh sách thư mục hoặc đọc file.
- **Cơ chế Burn-On-Use:** Mã OTP là vé dùng 1 lần cho từng thiết bị cá nhân; sau khi bắt tay thành công, mã đó lập tức bị hủy bỏ để chống phát lại.

### 6.2. Tài khoản phân quyền RBAC cho nhóm / lớp học đông người
Khi cần cho cả lớp 40–50 sinh viên cùng nộp bài đồng thời:
```bash
# Tạo tài khoản chung quyền Ghi [w] có thời hạn 4 giờ:
slug user add -u sinhvien -P 123456 -r w -t 4h -p 9443

# Xem danh sách tài khoản đang kích hoạt:
slug user list -p 9443
```

---

## 7. Đồng bộ vi sai kiểu Git (Delta Sync 64 KiB) & Tải file đơn

Slug không truyền lại toàn bộ dữ liệu nếu file chỉ sửa đổi một phần nhỏ:
1. **Phân mảnh khối 64 KiB:** Tệp tin được chia thành các khối 64 KiB và băm bằng BLAKE3.
2. **So khớp vi sai In-Memory:** Client so sánh bảng hash của các block với Host.
3. **Chỉ truyền block thay đổi:** Chỉ những block có hash khác biệt mới được mã hóa qua kênh XChaCha20 và gửi đi.
4. **Xem trước kế hoạch đồng bộ:**
   ```bash
   slug pull -i 192.168.1.105 -p 9443 -o 12822565 --dry-run
   ```

---

## 8. Bộ lọc bảo mật: Slug Guard, Whitelist & Cố vấn AI

### 8.1. Slug Guard (100% Offline, Deterministic Core)
- **Tự động áp dụng `.gitignore`:** Loại bỏ sạch sẽ các thư mục build rác (`node_modules/`, `target/`, `build/`, `*.log`).
- **Phân tích Heuristic & Shannon Entropy:** Đo độ hỗn loạn $H(X) \ge 4.0$ để phát hiện API token, private key và tự động cách ly (`Quarantined`).
- **BLAKE3 Content Cache (`.slug/index.db`):** Tra cứu kết quả quét chỉ mất **0.015 μs**, không tốn CPU quét lại các file không đổi.

### 8.2. Hỗ trợ Whitelist ngoại lệ (`!.env.example`)
Slug Guard hỗ trợ tiền tố chấm than `!` theo chuẩn `.gitignore`:
```text
# Trong .slug/rules.conf hoặc trên Web Command Center:
.env*
!.env.example
!*.example
```
Các file khớp luật `!` sẽ được đánh dấu `Whitelisted / Clean` và cho phép truyền tải an toàn.

### 8.3. Slug AI Contextual Advisor (Tùy chọn với `--ai`)
Khi truyền cờ `--ai` và có cấu hình Ollama hoặc Cloud API, Slug AI gửi đoạn code mẫu để nhận về schema JSON cấu trúc (`has_secret`, `reason`, `line`). Slug AI chỉ đóng vai trò cố vấn ngữ cảnh hỗ trợ người dùng, **tuyệt đối không ghi đè hoặc thay thế luật cứng của Slug Guard**.

---

## 9. EnvShield & Central Vault: Bảo vệ file .env khỏi AI Assistants

Ngăn chặn các trợ lý AI (Cursor, Copilot, Claude Code) đọc lén khóa API trên ổ đĩa:

```bash
# 1. Niêm phong file .env vào Central Vault (~/.slug/env_vault/) và mã hóa thành .env.pqc
slug env init

# 2. Sinh hướng dẫn chuẩn cho AI coding agents (tạo .slug/ai-rule.md)
slug env prompt

# 3. Chạy ứng dụng từ RAM: Slug giải mã duy nhất trong RAM tiến trình
slug env run -- python3 app.py
# hoặc
slug env run -- npm test

# 4. Khôi phục lại .env nguyên trạng khi cần cấu hình
slug env restore

# 5. Xem lịch sử các bản backup đã niêm phong
slug env history
```

---

## 10. Bộ đo đạc hiệu năng (Benchmark Suite)

Slug tích hợp công cụ đo đạc hiệu năng CPU mật mã, phân mảnh vi sai In-Memory và I/O đĩa:
```bash
# Đo nhanh hiệu năng:
slug bench --quick

# Xuất kết quả dạng JSON:
slug bench --json --quick
```

Kết quả đo đạc thực tế trên CPU phổ thông:
- **ML-KEM-768 Encap/Decap:** ~36–79 μs (~6.000–7.000 ops/s).
- **ML-DSA-65 Sign/Verify:** ~109–548 μs.
- **XChaCha20-Poly1305 AEAD:** ~500–600 MB/s.
- **BLAKE3 Tree Hashing:** ~1.050 MB/s.
- **Tra cứu Cache Slug Guard:** 0.015 μs / file.
- **Delta Chunker:** > 1.000 MB/s (16.700 chunks/s).

---

## 11. Kịch bản thực chiến: Lớp học nộp bài, Red Team & Dev Team

### Kịch bản 1: Giảng viên thu bài tập phòng máy một chạm (Blind Drop)
1. **Giáo viên:** Chạy `slug add ./nop_bai -p 9443`, tạo tài khoản lớp `slug user add -u sinhvien -P 123456 -r w -p 9443`.
2. **Sinh viên:** Mở Web Viewing Engine `slug` (hoặc chạy `slug push ./bai_lam.zip -i 192.168.1.107 -p 9443 -u sinhvien -P 123456`).
3. **Bảo mật:** `SlugVFS Jail` cưỡng chế quyền `WRITE_ONLY`, sinh viên nộp bài thành công nhưng hoàn toàn không thể xem hoặc tải bài của các bạn khác về.

### Kịch bản 2: Red Team / Pentest chuyển giao payload an toàn
1. Mở trạm chia sẻ có TTL tự hủy 30 phút: `slug add ./payloads -p 18443 -s pqc -t 30m -d`.
2. Máy đích kéo dữ liệu: `slug pull -i <IP> -p 18443 -o <OTP> --to ./staging`.
3. Hết 30 phút, server tự hủy, dọn sạch bộ nhớ và không để lại bất kỳ dấu vết mạng nào.

---

## 12. Bảng tra cứu lệnh CLI chuẩn mực (Cheatsheet)

| Lệnh CLI | Chức năng chính |
| :--- | :--- |
| `slug` | Mở ngay Web Viewing Engine trên `http://127.0.0.1:8080/` (Aliases: `slug portal`, `slug web`) |
| `slug shortcut` | Tạo lối tắt Desktop Windows (`Slug Workspace.lnk`) mở 1-chạm ẩn cửa sổ console |
| `slug add <path> -p 9443 -s pqc -t 1d --ai -d` | Khởi tạo trạm chia sẻ workspace an toàn lượng tử chạy ngầm |
| `slug status` | Xem danh sách các workspace đang host, cổng, PID và trạng thái OTP |
| `slug totp [-p <port>]` | Xem bảng 3 mã OTP phân quyền (`[rw]`, `[r]`, `[w]`) hoặc lấy mã nhanh |
| `slug stop [-p <port>\|-a]` | Dừng server trên cổng chỉ định hoặc dừng toàn bộ server |
| `slug serve -p <port> -w` | Mở giao diện Web Host Admin Dashboard trên loopback máy chủ |
| `slug connect -i <ip> -p <port> -o <otp>` | Xác thực và lưu chứng chỉ phiên vào danh bạ kết nối |
| `slug pull -i <ip> -p <port> -o <otp> --to <dir>` | Đồng bộ vi sai toàn bộ workspace về thư mục cục bộ (kèm kế hoạch preview) |
| `slug get <IP:PORT?otp=CODE> <remote_path> [dest]` | Tải ĐÚNG 1 file đơn lẻ cụ thể từ xa về máy |
| `slug push <file> -i <ip> -p <port> -o <otp>\|-u <u>` | Đẩy tệp lên trạm từ xa (hộp thư nộp bài hoặc cập nhật mã nguồn) |
| `slug ls` | Duyệt danh sách file từ xa với trạng thái (Available, Blocked, Quarantined) |
| `slug user add -u <user> -P <pass> -r <rw\|r\|w> -t <ttl>` | Quản lý tài khoản phân quyền RBAC cho nhóm hoặc lớp học |
| `slug session <list\|kill <id>>` | Giám sát và hủy các phiên client đang kết nối |
| `slug audit <list\|scan\|allow\|recheck>` | Quản lý các file bị cách ly bởi Slug Guard; phê duyệt ngoại lệ Whitelist |
| `slug rule <list\|block\|allow>` | Quản lý quy tắc lọc `.slug/rules.conf` (hỗ trợ whitelist tiền tố `!`) |
| `slug env init` | Niêm phong `.env` vào Central Vault, mã hóa `.env.pqc` và dọn sạch plaintext |
| `slug env prompt` | Sinh chỉ thị chuẩn cho AI coding agents (`.slug/ai-rule.md`) |
| `slug env run -- <command>` | Chạy ứng dụng hoặc test: giải mã secret duy nhất trong RAM tiến trình |
| `slug env restore` | Khôi phục 1 chạm file `.env` bản rõ từ Vault khi cần chỉnh sửa cấu hình |
| `slug bench [--quick\|--json]` | Đo hiệu năng mật mã (ML-KEM, ML-DSA, BLAKE3, ChaCha20) và I/O đĩa |
| `slug completion <bash\|zsh>` | Sinh script gợi ý lệnh tự động cho shell (Tab completion) |
| `slug version` | Hiển thị thông tin phiên bản, giấy phép Apache-2.0 và chi tiết build |
| `slug uninstall [-y]` | Gỡ cài đặt hoàn toàn Slug khỏi hệ thống máy tính |
