# Slug: Secure, Ephemeral, Git-like Workspace Sharing & Synchronization

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++ Standard](https://img.shields.io/badge/Language-C%2B%2B20-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B20)
[![Post-Quantum Cryptography](https://img.shields.io/badge/PQC-ML--KEM--768%20%7C%20ML--DSA--65-success.svg)](https://csrc.nist.gov/Projects/post-quantum-cryptography)
[![Zero-Dependency Static Binary](https://img.shields.io/badge/Linux_Static-100%25_Portable-brightgreen.svg)](BUILD.md)

```text
   _____ _             
  / ____| |            
 | (___ | |_   _  __ _ 
  \___ \| | | | |/ _` |
  ____) | | |_| | (_| |
 |_____/|_|\__,_|\__, |
                  __/ |
                 |___/ 
  Slug: Secure, Ephemeral, Git-like Workspace Sharing & Synchronization
  Version: 1.0.0 | Post-Quantum Cryptography & AI Guard (Apache-2.0)
```

> **Slug** là giải pháp chia sẻ và đồng bộ không gian làm việc (workspace) tức thì dành cho lập trình viên, kỹ sư bảo mật và chuyên gia DevOps. Kết hợp tốc độ chia sẻ một chạm tương tự AirDrop với nền tảng mật mã hậu lượng tử (Post-Quantum Cryptography), hệ thống phân quyền hạt nhân tự hủy và lá chắn bảo vệ bí mật khỏi các trợ lý AI.

---

## 1. Tổng Quan & Triết Lý Thiết Kế

Trong kỷ nguyên phát triển phần mềm hiện đại và sự bùng nổ của các trợ lý AI (Cursor, Copilot, ChatGPT), việc chia sẻ nhanh mã nguồn, tệp thử nghiệm và artifact giữa các máy tính (laptop cá nhân, máy trạm lab, cloud server) thường vấp phải hai thái cực:
1. **Thiếu an toàn:** Dùng `python3 -m http.server` gửi bản rõ qua Wi-Fi/LAN, mở cổng không bảo vệ, hoặc gửi file qua ứng dụng chat đám mây bên thứ ba.
2. **Nặng nề và dư thừa:** Dùng Git commit/push làm ô nhiễm lịch sử repo, hoặc cấp quyền tài khoản SSH/rsync vĩnh viễn gây ra rủi ro tài khoản mồ côi.

**Slug dung hòa trọn vẹn hai yếu tố trên:**
- **Trải nghiệm tức thì ("Mì ăn liền như AirDrop"):** Kéo toàn bộ workspace về máy chỉ bằng đúng 1 lệnh duy nhất (`slug get`).
- **Mã hóa hậu lượng tử mặc định (NIST FIPS 203 / 204):** Chống lại nguy cơ thu thập dữ liệu giải mã tương lai của máy tính lượng tử.
- **Không để lại rác hệ thống (Zero Footprint):** Các phiên làm việc và mã xác thực TOTP tự hủy ngay sau khi dùng hoặc hết hạn theo thời gian sống (TTL).
- **Lá chắn AI Secret Guard & EnvShield:** Chủ động ngăn chặn các extension AI đọc trộm khóa API và file `.env` trên đĩa cứng.

---

## 2. Hệ Thống Tài Liệu Kỹ Thuật (Architecture & Technical Specs)

Hệ thống tài liệu chuyên sâu được phân định chi tiết theo từng khía cạnh kỹ thuật:

| Tài liệu | Nội dung trọng tâm |
| :--- | :--- |
| **[01-PROBLEM.md](docs/01-PROBLEM.md)** | Phân tích thực trạng: Lỗ hổng của `python -m http.server`, rủi ro tài khoản mồ côi SSH, ô nhiễm Git và nguy cơ rò rỉ secret vào AI coding assistants. |
| **[02-SOLUTION.md](docs/02-SOLUTION.md)** | Giải pháp toàn diện của Slug: Quy hoạch 9 lệnh cốt lõi, cơ chế một chạm `slug get`, 3 bộ Suite mật mã, hệ thống tập tin ảo `SlugVFS` và Web Dropbox. |
| **[03-AI-USAGE.md](docs/03-AI-USAGE.md)** | Phòng thủ dữ liệu AI: Stateful AI Secret Guard với bộ nhớ đệm băm BLAKE3 (`index.db`), cơ chế kiểm toán `slug audit`, và công nghệ RAM-only PQC EnvShield. |
| **[04-ARCHITECTURE.md](docs/04-ARCHITECTURE.md)** | Kiến trúc 5 tầng nghiêm ngặt, giao thức đóng khung nhị phân Directional AEAD (`XChaCha20-Poly1305`), cửa sổ trượt 64-bit chống phát lại, và cơ chế xuyên NAT đa tầng ("SLUG-ICE"). |
| **[MODULE-MAP.md](docs/MODULE-MAP.md)** | Bản đồ kiến trúc chi tiết, phân rã mã nguồn các tầng và đặc tả luồng kiểm duyệt dữ liệu (Gatekeepers). |

---

## 3. Quy Hoạch 9 Lệnh Cốt Lõi ("The Essential 9")

Toàn bộ hệ thống CLI của Slug tuân thủ nghiêm ngặt chuẩn POSIX/GNU, tổ chức thành 3 nhóm nghiệp vụ chính và các công cụ tiện ích:

```text
SLUG THE ESSENTIAL 9 CORE CLI

[HOST WORKSPACE]
  slug add [path]             Khởi tạo và host workspace an toàn (-p <port>, -s <suite>, -t <ttl>, --ai)
  slug status [-p <port>]     Kiểm tra danh sách hoặc chi tiết server đang chạy (-s rút gọn)
  slug totp [-p <port>]       Xem bảng 3 mã OTP phân quyền hoặc xuất mã nhanh (-r <role> --code-only)
  slug stop [-p <port>|--all] Dừng server cụ thể hoặc toàn bộ server đang mở

[ACCESS CONTROL & SECURITY]
  slug user                   Quản lý tài khoản phân quyền: add, list, mod, del, chpass
  slug audit                  Quản lý các file bị AI Guard chặn: list, allow, recheck

[CLIENT WORKSPACE SYNC]
  slug get <ENDPOINT?otp=...> Kéo toàn bộ workspace về máy trong đúng 1 lệnh (One-Shot Sync)
  slug pull                   Đồng bộ vi sai cập nhật từ Host về máy cục bộ (--dry-run, --prune)
  slug push                   Đẩy các thay đổi cục bộ lên Host (--dry-run)

[SYSTEM UTILITIES]
  slug serve -p <port> [-w]   Xem chi tiết server hoặc mở Web Dashboard quản trị
  slug conn                   Quản lý danh sách kết nối lưu trên máy client (list, use, prune)
  slug env                    Bảo vệ biến môi trường nhạy cảm trong bộ nhớ RAM (init, run)
  slug completion <bash|zsh>  Sinh script tự động hoàn thành lệnh cho shell (Tab completion)
  slug bench                  Đo kiểm tốc độ truyền tải vi sai và hiệu năng thuật toán mật mã
  slug version                Hiển thị thông tin phiên bản, commit hash và giấy phép bản quyền
```

---

## 4. Hướng Dẫn Sử Dụng Nhanh (Quickstart)

### Kịch Bản 1: Host Workspace Và Chia Sẻ Bằng Lệnh Một Chạm (`slug get`)

**Bước 1: Trên máy chủ (Host):**
Khởi tạo workspace chia sẻ thư mục hiện tại trên cổng 9443 với thuật toán Hậu Lượng Tử và bật AI Guard:
```bash
slug add . -p 9443 -s pqc -t 1d --ai
```
Màn hình terminal sẽ xuất hiện bảng thông số và dòng hướng dẫn kết nối một chạm:
```text
+----------------------------------------------------------------------------+
| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |
+----------------------------------------------------------------------------+
  Port:            9443
  Crypto Suite:    Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)
  AI Secret Guard: ON
  Session TTL:     1d
  Role OTPs (Rotates in 50s):
    [rw] Read-Write OTP: 12822565 (Full Sync & Web Dropbox)
    [r]  Read-Only OTP:  08796195 (Read/Pull/View files only)
    [w]  Write-Only OTP: 70788146 (Blind Drop/Upload only)
+----------------------------------------------------------------------------+
Connect (One-Shot): slug get 192.168.1.107:9443?otp=12822565
+----------------------------------------------------------------------------+
```

**Bước 2: Trên máy khách (Client):**
Người nhận chỉ cần gõ đúng một câu lệnh để tải toàn bộ thư mục về máy đích:
```bash
slug get "192.168.1.107:9443?otp=12822565" ./my-project
```
Tiến trình sẽ tự động thực hiện bắt tay trao đổi khóa ML-KEM-768, đốt hủy mã OTP một lần, nhận chứng chỉ phiên, phân tích khối vi sai 64 KiB và tải dữ liệu về máy.

---

### Kịch Bản 2: Truy Cập Giao Diện Web Techno B2B (No-CLI Workspace)

Khi chia sẻ với người dùng không cài đặt sẵn CLI:
1. Chủ máy mở giao diện quản trị:
   ```bash
   slug serve -p 9443 -w
   ```
2. Người dùng mở liên kết trên trình duyệt:
   ```text
   http://192.168.1.107:9443/drop?ticket=24b3eca0480f255bae394325316c6c871cf8a41d4c7af557
   ```
   - Giao diện tối Techno Doanh nghiệp sắc nét (bo góc 2px, font JetBrains Mono).
   - Kéo thả tệp tin hoặc thư mục trực tiếp vào trình duyệt để tải lên.
   - Hiển thị thông số giám sát tốc độ và tình trạng phiên làm việc theo thời gian thực.

---

### Kịch Bản 3: Bảo Vệ File `.env` Khỏi AI Coding Agents Với PQC EnvShield

Để ngăn ngừa các công cụ AI (như Cursor hoặc Copilot) đọc lén file cấu hình chứa API key trên đĩa cứng:

```bash
# 1. Mã hóa .env thành .env.pqc và xóa hoàn toàn bản rõ khỏi ổ đĩa
slug env init

# 2. Chạy ứng dụng: Slug giải mã duy nhất trong RAM và nạp biến môi trường cho tiến trình
slug env run -- python3 app.py
# hoặc
slug env run -- npm start
```

---

## 5. Cài Đặt & Biên Dịch (Installation & Build)

Slug được đóng gói dưới dạng binary tĩnh độc lập (100% Static Binary, ~8.4 MB) không phụ thuộc vào `glibc` của hệ thống máy chủ, chạy mượt mà trên mọi bản phân phối Linux (Ubuntu, Debian, Alpine, RHEL, CentOS, Arch, Kali).

### 5.1. Cài Đặt Nhanh (Quick Install)

#### Quick Install (Linux / macOS)
```bash
# Automated 1-liner installer:
curl -fsSL https://raw.githubusercontent.com/dotlinux26/slug/main/scripts/install.sh | bash

# Or Debian/Ubuntu .deb:
sudo dpkg -i dist/slug_1.0.0_amd64.deb

# Or standalone portable binary:
chmod +x slug-linux-x86_64 && sudo mv slug-linux-x86_64 /usr/local/bin/slug
```

#### Quick Install (Microsoft Windows)
```powershell
# Automated 1-liner installer (PowerShell):
irm https://raw.githubusercontent.com/dotlinux26/slug/main/scripts/install.ps1 | iex

# Or extract ZIP distribution archive:
Expand-Archive slug-1.0.0-windows-x86_64.zip -DestinationPath "$env:LOCALAPPDATA\slug\bin"
[Environment]::SetEnvironmentVariable("PATH", "$([Environment]::GetEnvironmentVariable('PATH','User'));$env:LOCALAPPDATA\slug\bin", "User")

# Or run standalone portable binary directly:
.\slug.exe version
```

### 5.3. Bật Tính Năng Tự Động Gợi Ý Lệnh (Shell Autocompletion)
Slug hỗ trợ tự động gợi ý cờ và các cổng workspace đang chạy cho Bash và Zsh:
```bash
# Đối với Bash:
slug completion bash > ~/.bash_completion.d/slug
source ~/.bash_completion.d/slug

# Đối với Zsh:
slug completion zsh > ~/.zsh/completion/_slug
```

### 5.4. Tự Biên Dịch Từ Mã Nguồn (Build From Source)
Yêu cầu: Trình biên dịch hỗ trợ C++20 (`g++` hoặc `clang++`), thư viện OpenSSL 3.0+ hoặc OpenSSL 3.6.3 (hỗ trợ NIST PQC).
```bash
# Biên dịch binary động thông thường:
make -j$(nproc)

# Biên dịch binary tĩnh hoàn chỉnh:
make static -j$(nproc)

# Chạy toàn bộ 50 kịch bản kiểm thử tích hợp tự động:
bash scripts/test_local.sh
```

---

## 6. Giấy Phép Bản Quyền (License)

Dự án được phân phối dưới giấy phép mã nguồn mở **Apache License 2.0**. Xem chi tiết tại tệp [LICENSE](LICENSE).
