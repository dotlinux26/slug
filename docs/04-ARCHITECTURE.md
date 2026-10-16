# KIẾN TRÚC HỆ THỐNG VÀ BẢO MẬT GIAO THỨC TRUYỀN DẪN SLUG

## 1. Mô Hình Phân Lớp Toàn Diện (Strict Layered Architecture)

Slug được xây dựng theo nguyên tắc phân lớp đơn hướng nghiêm ngặt, đảm bảo tính mô-đun hóa cao và đóng gói thành một file nhị phân độc lập (~10 MB, zero external dependencies):

```text
+-----------------------------------------------------------------------------------+
| TẦNG 1: TRÌNH DIỄN & GIAO DIỆN (PRESENTATION & UX LAYER)                          |
|  ├── CLI Dispatcher (src/main.cpp)      : Parse POSIX args, ANSI Terminal Table   |
|  └── Web Assets (src/net/web_assets.hpp): Light Theme, 2px border-radius Explorer |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 2: GIAO VẬN MÃ HÓA & TRẠM GÁC (TRANSPORT & WIRE ENCRYPTION)                  |
|  ├── PQC Handshake Engine               : NIST FIPS 203/204 (ML-KEM-768, ML-DSA)  |
|  ├── Directional AEAD Wire Protocol     : XChaCha20-Poly1305, 64-bit Anti-Replay  |
|  │                                        Muối độc lập: ClientToServer / ServerToClient
|  ├── Localhost Web Proxy (Kiến trúc A)  : Trình duyệt giao tiếp qua loopback 127.0.0.1
|  └── Multi-Tier NAT Traversal           : IPv6 Direct -> STUN Punch -> TURN Relay |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 3: NGHIỆP VỤ LÕI & VFS JAIL (WORKSPACE CORE & VFS JAIL)                      |
|  ├── SlugVFS (src/core/vfs.hpp)         : Virtual path '/', Chống vượt ngục (Jail)|
|  │                                        Thực thi quyền (r/w/rw) ở tầng filesystem|
|  ├── DeltaSyncEngine (src/sync/*)       : Phân khối 64 KiB, Manifest so khớp BLAKE3|
|  └── Protocol Path Normalizer           : Chuẩn hóa '/' xuyên suốt Linux & Windows|
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 4: CHÍNH SÁCH BẢO MẬT & KIỂM DUYỆT (POLICY, RBAC & AI AUDIT ENGINE)          |
|  ├── ACL & TotpManager (src/core/acl*)  : 3-Role TOTP (rw/r/w), Single-Use Burn   |
|  ├── PolicyEngine (src/policy/*)        : .gitignore phân tầng + .slug/rules.conf |
|  └── Stateful AI Guard (src/ai/*)       : Heuristic + Shannon Entropy + index.db  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 5: MẬT MÃ CẤP THẤP (CRYPTO PRIMITIVES)                                       |
|  ├── NIST FIPS 203 & 204                : ML-KEM-768, ML-DSA-65 (Post-Quantum)    |
|  ├── BLAKE3 & BLAKE3-KDF                : Băm siêu tốc & Phái sinh khóa chuẩn     |
|  └── XChaCha20-Poly1305                 : Mã hóa xác thực khối 256-bit AEAD       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Kiến Trúc Web UI & Mô Hình Bảo Mật Đường Truyền (Kiến Trúc A)

### 2.1. Vấn Đề Khi Trình Duyệt Giao Tiếp Trực Tiếp Qua Mạng
Khi máy chủ host mở port và trình duyệt của máy khách truy cập trực tiếp qua địa chỉ `http://<remote_ip>:<port>/drop?ticket=<ticket>`:
* Trình duyệt web tiêu chuẩn (Chrome, Firefox) không hỗ trợ giao thức mật mã hậu lượng tử tùy biến (ML-KEM-768) qua HTTP thuần.
* Mặc dù tầng `SlugVFS` trên máy chủ vẫn kiểm tra quyền hạn, chặn path traversal và chặn file AI-flagged rất nghiêm ngặt, nhưng **kênh truyền dẫn vật lý (wire transport) giữa trình duyệt và máy chủ lại là HTTP bản rõ (plaintext)**.
* Kẻ tấn công bắt gói tin trên cùng mạng Wi-Fi (Wireshark / ARP Spoofing) có thể nhìn thấy nội dung file tải về và ticket xác thực.

### 2.2. Lựa Chọn Kiến Trúc A: Web UI Là Localhost Proxy Của Slug Client
Để đảm bảo **100% dữ liệu bay trên dây mạng LAN/Internet đều là PQC AEAD Ciphertext**, Slug áp dụng **Kiến trúc A (Localhost Client Proxy)** tương tự mô hình của `kubectl proxy`, Tor Browser hoặc SSH Dynamic SOCKS:

```text
[MÁY KHÁCH - CLIENT MACHINE]                                    [MÁY CHỦ - HOST MACHINE]
+--------------------------+
| Trình Duyệt (Browser)    |
| Giao diện Web Explorer   |
+------------+-------------+
             | HTTP nội bộ (Loopback)
             | http://127.0.0.1:<random_port>
             v
+------------+-------------+                                    +-----------------------+
| Slug CLI Client          |     KÊNH TRUYỀN DẪN VẬT LÝ         | Slug Server Engine    |
| (Localhost Proxy Engine) | =================================> | (PQC Listener + VFS)  |
| - Nhận lệnh từ browser   |   100% PQC AEAD CIPHERTEXT         | - SlugVFS Jail        |
| - Đóng gói PQC Chunks    |   - ML-KEM-768 Shared Secret       | - RBAC Enforcement    |
| - Giải mã an toàn        |   - XChaCha20-Poly1305             | - Stateful AI Guard   |
+--------------------------+   - Directional Salts              +-----------------------+
                               (Không ai ngửi được trên Wi-Fi!)
```

* **Nguyên lý hoạt động:**
  1. Người dùng chạy lệnh `slug web` trên máy khách.
  2. Slug CLI thiết lập kết nối socket PQC tới máy chủ từ xa, thương lượng khóa ML-KEM-768 và thiết lập kênh mã hóa AEAD.
  3. Slug CLI khởi tạo một máy chủ web nội bộ chỉ lắng nghe trên giao diện loopback `127.0.0.1` của chính máy khách.
  4. Trình duyệt mở giao diện tại `http://127.0.0.1:<random_port>`. Mọi thao tác tải file hoặc duyệt thư mục từ trình duyệt chỉ truyền nội bộ trong RAM/loopback của máy khách.
  5. Slug CLI nhận request từ trình duyệt, kéo các khối 64 KiB qua kênh mạng PQC từ máy chủ, giải mã an toàn trên máy khách, rồi mới stream nội bộ trả về cho trình duyệt.
  6. **Kết quả:** Kẻ tấn công đứng giữa mạng chỉ nhìn thấy các gói tin nhị phân ngẫu nhiên có entropy cao của giao thức PQC, hoàn toàn không có bất kỳ byte HTTP hay plaintext nào trên đường truyền.

---

## 3. Giao Thức Đóng Khung Dữ Liệu Phân Hướng (Directional AEAD Wire Protocol)

Trong kết nối TCP song công (Full-Duplex), việc tái sử dụng Nonce (Nonce Reuse) là lỗi chí mạng đối với họ mật mã ChaCha20, dẫn đến việc mất tính bảo mật của luồng mã hóa. Slug triệt tiêu hoàn toàn nguy cơ này bằng cơ chế phân hướng muối phái sinh (`src/net/aead_frame.hpp`):

### 3.1. Phái Sinh Khóa Phân Hướng Qua BLAKE3-KDF
Từ `SharedSecret` (32 bytes) sinh ra sau bước bắt tay ML-KEM-768, hai đầu độc lập tính toán:

$$\text{SessionKey} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_AEAD_SESSION_KEY_V1"})$$
$$\text{ClientToServer\_Salt} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_C2S_NONCE_SALT_V1"})[0..15]$$
$$\text{ServerToClient\_Salt} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_S2C_NONCE_SALT_V1"})[0..15]$$

### 3.2. Cấu Trúc Khung Tin AEAD
```text
+-------------------+--------------------+------------------------+-------------------+
| Length (4 bytes)  | SeqNum (8 bytes)   | Encrypted Payload      | Tag (16 bytes)    |
| Big-Endian uint32 | Big-Endian uint64  | (Variable Length)      | Poly1305 MAC      |
+-------------------+--------------------+------------------------+-------------------+
|<------- Associated Data (AAD) -------->|
```

1. **Khởi Tạo Nonce Phân Hướng (24 bytes):**
   * Chiều Client -> Server: $\text{Nonce}_{\text{c2s}} = \text{ClientToServer\_Salt}\ (16\text{ bytes}) \parallel \text{SeqNum}_{\text{tx}}\ (8\text{ bytes})$
   * Chiều Server -> Client: $\text{Nonce}_{\text{s2c}} = \text{ServerToClient\_Salt}\ (16\text{ bytes}) \parallel \text{SeqNum}_{\text{tx}}\ (8\text{ bytes})$
   * Nhờ tách biệt 2 salt độc lập, hai chiều gửi đồng thời gói tin `SeqNum = 1` sẽ có hai Nonce hoàn toàn khác biệt, không bao giờ đụng độ.
2. **Associated Data (AAD) Chống Sửa Đổi Header:** Toàn bộ 12 bytes đầu `[Length || SeqNum]` được gắn vào trường AAD, đảm bảo kẻ tấn công không thể sửa độ dài hoặc cắt ghép thứ tự gói tin.
3. **Cửa Sổ Trượt Chống Phát Lại (64-Bit Anti-Replay Sliding Window):** Ngăn chặn kẻ tấn công ghi lại gói tin cũ và phát lại trên đường truyền.

---

## 4. Tương Thích Đa Nền Tảng (Windows & Linux Path Engine)

Hệ thống chia sẻ workspace phải đảm bảo việc một host chạy Linux gửi dữ liệu cho client chạy Windows (hoặc ngược lại) diễn ra thông suốt mà không gặp lỗi phân cách đường dẫn:

1. **Chuẩn Hóa Giao Thức (Protocol Path):**
   * Mọi đường dẫn lưu trong Manifest JSON, trong gói tin PQC và trong `.slug/rules.conf` luôn sử dụng định dạng tương đối với dấu **`/`** (ví dụ: `src/core/main.cpp`).
   * Không bao giờ lưu đường dẫn tuyệt đối của hệ điều hành (`/home/...` hay `C:\...`).
2. **Bộ Chuyển Đổi Biên Giới (Boundary Translation):**
   * Trên Windows, nếu người dùng nhập `src\main.cpp` trên dòng lệnh, Slug CLI tự động chuyển đổi tất cả dấu `\` thành `/` trước khi gửi truy vấn.
   * Khi ghi xuống đĩa, Slug sử dụng `std::filesystem::path::preferred_separator` để ánh xạ chính xác sang cấu trúc thư mục bản địa của hệ điều hành.
3. **Cơ Chế Khóa VFS (Path Jailing):**
   * Hàm `resolve_safe_path` thực hiện chuẩn hóa `weakly_canonical` và kiểm tra tiền tố thư mục gốc, lập tức từ chối mọi thủ thuật vượt ngục thư mục như `../../etc/passwd` hoặc `..\..\Windows\System32`.
