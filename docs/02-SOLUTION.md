# GIẢI PHÁP TOÀN DIỆN CỦA SLUG: QUY TRÌNH BÀN GIAO WORKSPACE CÓ KIỂM SOÁT

## 1. Triết Lý Cốt Lõi: "Kết Nối Không Đồng Nghĩa Với Tải Dữ Liệu"

Trong các công cụ truyền file cũ, việc kết nối thường gắn liền với tải toàn bộ hoặc yêu cầu cấu hình đường dẫn phức tạp. Slug tách bạch rõ ràng 4 giai đoạn của một quy trình bàn giao workspace:

```text
+-------------------+      +--------------------+      +--------------------+      +-------------------+
| 1. KẾT NỐI (AUTH) | ---> | 2. KHÁM PHÁ (LS)   | ---> | 3. XEM TRƯỚC (PLAN)| ---> | 4. TRUYỀN TẢI     |
|   slug connect    |      |   slug ls          |      |   Transfer Preview |      | slug get / pull   |
|   Bắt tay PQC,    |      |   Duyệt cấu trúc,  |      |   Dung lượng, ghi  |      | Kéo đúng 1 file   |
|   lưu conn context|      |   xem trạng thái   |      |   đè, file bị chặn |      | hoặc delta scope  |
+-------------------+      +--------------------+      +--------------------+      +-------------------+
```

1. **Kết nối (`slug connect`):** Bắt tay mật mã hậu lượng tử, xác thực mã OTP hoặc tài khoản, lưu vé phiên vào context (`conn_1`). **Không tải bất kỳ file nào về máy**.
2. **Khám phá (`slug ls`):** Duyệt xem cây thư mục từ xa dạng bảng kỹ thuật rõ ràng với thông tin kích thước và trạng thái kiểm duyệt mà không tốn băng thông kéo nội dung.
3. **Xem trước kế hoạch (`Transfer Plan Preview`):** Biết trước bao nhiêu file sẽ được tải, bao nhiêu file bị loại bởi `.gitignore` hay chính sách bảo vệ, và dung lượng thực tế cần truyền.
4. **Truyền tải chọn lọc (`slug get` / `slug pull`):**
   - Lấy đúng 1 file duy nhất: `slug get <path>`
   - Đồng bộ một phạm vi thư mục: `slug pull [scope] --to <dir>`

---

## 2. Quy Hoạch 9 Lệnh Cốt Lõi (The Essential 9 POSIX/GNU CLI)

Hệ thống dòng lệnh của Slug tuân thủ nghiêm ngặt tiêu chuẩn POSIX/GNU:

```text
SLUG ESSENTIAL 9 ARCHITECTURE

HOST WORKSPACE               ACCESS & SECURITY            CLIENT WORKSPACE SYNC
  slug add                     slug user                    slug connect (Auth Only)
  slug status                  slug audit                   slug ls (Technical Explorer)
  slug totp                                                 slug get (Single File Only)
  slug stop                                                 slug pull (Delta with Plan Preview)
                                                            slug push (Upload under RBAC)
```

### Bảng Chi Tiết Hành Vi Lệnh

| Nhóm | Lệnh | Hành vi & Ý nghĩa kỹ thuật | Ví dụ thực tế |
| :--- | :--- | :--- | :--- |
| **Host** | **`slug add <path>`** | Khởi tạo và host workspace với PQC và AI Guard | `slug add . -p 9443 -s pqc -t 2h -a` |
| | **`slug status`** | Kiểm tra danh sách server, port, suite và các file bị gắn cờ | `slug status --flagged` |
| | **`slug totp`** | Xuất mã One-Time TOTP phân quyền (`rw`, `r`, `w`) | `slug totp -p 9443 -r r --code-only` |
| | **`slug stop`** | Dừng một server cụ thể hoặc dừng toàn bộ | `slug stop -p 9443` hoặc `slug stop -a` |
| **Security** | **`slug user`** | Quản lý tài khoản tạm thời theo vai trò (RBAC) | `slug user add bob -p 9443 -r r -t 4h` |
| | **`slug audit`** | Quản lý, kiểm tra hoặc bỏ chặn file bị AI Guard cách ly | `slug audit list -p 9443` hoặc `slug audit allow <file>` |
| **Client** | **`slug connect`** | Bắt tay PQC, xác thực OTP/User, lưu context (`conn_N`), **không tải file** | `slug connect -i 192.168.1.107 -p 9443 -o 12822565` |
| | **`slug ls [subpath]`** | Duyệt cấu trúc workspace từ xa dạng bảng (`NAME`, `TYPE`, `SIZE`, `STATUS`) | `slug ls` hoặc `slug ls src/ -r` |
| | **`slug get <path>`** | **Chỉ tải duy nhất 1 file được chỉ định**, tuyệt đối không kéo cả thư mục | `slug get src/main.rs ./main.rs` |
| | **`slug pull [scope]`** | Đồng bộ vi sai Git-like có hiển thị **Transfer Plan Preview** | `slug pull src/ --to ./local_src -y` |
| | **`slug push <file>`** | Tải file lên workspace từ xa (yêu cầu quyền `w` hoặc `rw`) | `slug push ./fix.rs src/fix.rs` |

---

## 3. Minh Họa Luồng Trải Nghiệm Thực Tế Phía Client

### Bước 1: Kết Nối Xác Thực
```bash
$ slug connect -i 192.168.1.107 -p 9443 -o 12822565
[*] Connecting to 192.168.1.107:9443...
[+] Handshake OK! Negotiated: Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)
[*] Authenticating with single-use TOTP: 12822565...
[+] Authenticated via TOTP
[+] Connection saved: conn_1
[+] Your active connection changed to: conn_1 (192.168.1.107:9443 - my_project)
    Role:        rw (Read-Write)
    Certificate: 8f4e2a1b9c0d... (TTL: 2h)
    Web Drop:    http://192.168.1.107:9443/drop?ticket=8f4e2a1b9c0d...

Quick Actions:
  slug ls                Browse remote files
  slug get <file>        Download a specific single file
  slug pull ./clone      Pull remote files incrementally
  slug push <file>       Push file to remote workspace
```

### Bước 2: Khám Phá Workspace Từ Xa Bằng `slug ls`
```bash
$ slug ls
REMOTE WORKSPACE: my_project (conn_1 @ 192.168.1.107:9443)
Scope: [root] | Role: rw | Crypto: Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)

NAME                             TYPE      SIZE        STATUS
--------------------------------------------------------------------------------
src/                             folder    12.4 KB     Available
docs/                            folder    4.8 KB      Available
build/                           folder    -           Excluded (gitignore)
tests/                           folder    6.1 KB      Available
.env                             file      120 B       Quarantined (AI Secret Guard: Environment Secret File)
Cargo.toml                       file      340 B       Available
README.md                        file      1.2 KB      Available
--------------------------------------------------------------------------------
Total: 15 available file(s) (24.5 KB) | 4 excluded/quarantined item(s)
```

### Bước 3A: Chỉ Lấy Đúng 1 File Bằng `slug get`
```bash
$ slug get src/main.rs ./main.rs
[*] Downloading single file: src/main.rs -> ./main.rs...
Downloaded: src/main.rs -> ./main.rs (340 B) [BLAKE3: a1b2c3d4e5f6...]
```
*(Nếu người dùng chạy `slug get` không truyền tên file, Slug từ chối kéo cả thư mục và hướng dẫn dùng `slug ls` hoặc `slug pull`).*

### Bước 3B: Đồng Bộ Vi Sai Phạm Vi Bằng `slug pull` Kèm Plan Preview
```bash
$ slug pull src/ --to ./my_src
--- Workspace Transfer Plan Preview ---
Remote scope:        src/
Local destination:   ./my_src
Files selected:      8 (12.4 KB)
Files excluded:      2 (gitignore / policy)
Files quarantined:   1 (AI Secret Guard)
Estimated download:  12.4 KB
Overwriting:         0 local file(s)
---------------------------------------
Proceed with transfer? [y/N]: y
[*] Starting Delta Sync into ./my_src...
Synced: src/main.rs (340 B)
Synced: src/lib.rs (1.2 KB)
...
Pull complete! Transferred 12.4 KB, saved 0.0 B (Git-like Delta Sync)
```

---

## 4. Giao Diện Web Explorer: Strict Light Theme & 2px Border Radius

Khi lập trình viên cần duyệt file trực quan hoặc kéo-thả, Web UI của Slug cung cấp một trải nghiệm đồng nhất với CLI:

* **Phong cách thiết kế:** Tông màu Light kỹ thuật (`#f6f8fa` canvas, `#ffffff` surface, `#d0d7de` border, font đơn sắc Mono).
* **Bo góc:** Chuẩn hóa tuyệt đối **`2px border-radius`** trên mọi card, button, table, badge, modal (loại bỏ hoàn toàn phong cách bo tròn dạng pill).
* **Bảng Remote Explorer:**
  * Cột: `[ ]` (Checkbox đa chọn) | `NAME` | `TYPE` | `SIZE` | `STATUS` | `ACTION`.
  * Huy hiệu trạng thái 3 tầng: `Available` (xanh lá nhạt), `Excluded` (xám nhạt - gitignore), `Blocked` (vàng nhạt - policy), `Quarantined` (đỏ nhạt - AI Secret Guard).
  * Thanh điều khiển: `Selected: X files • Estimated: Y MB` kèm hai nút `[Preview Transfer]` (mở popup danh sách file) và `[Download Selected]`.
  * Hỗ trợ kéo thả (Drag-and-Drop) upload trực tiếp nếu tài khoản có quyền `w` hoặc `rw`.

---

## 5. Tương Thích Tuyệt Đối Đa Nền Tảng (Windows & Linux)

Slug được thiết kế để hoạt động hoàn hảo trong môi trường đa hệ điều hành (ví dụ: host chạy Linux, client chạy Windows hoặc ngược lại):

1. **Chuẩn Hóa Đường Dẫn Giao Thức (Protocol Path):**
   * Toàn bộ manifest, dữ liệu gói tin PQC và policy nội bộ luôn sử dụng ký tự phân cách chuẩn **`/`** (Forward Slash).
   * Tuyệt đối không để đường dẫn tuyệt đối hoặc ký tự `\` đặc thù của Windows lọt vào gói tin mạng.
2. **Tự Động Chuyển Đổi Tại Biên CLI (Boundary Normalization):**
   * Nếu người dùng Windows gõ `slug get src\main.rs` hoặc `slug push src\contrib.rs`, hệ thống tự động chuẩn hóa dấu `\` thành `/` trước khi tra cứu hoặc gửi lên máy chủ.
   * Khi ghi xuống đĩa cứng, `std::filesystem::path` tự động chuyển đổi sang đường dẫn bản địa tương ứng của hệ điều hành.
