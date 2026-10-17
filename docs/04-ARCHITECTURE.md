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
| TẦNG 4: CHÍNH SÁCH BẢO MẬT & KIỂM DUYỆT (POLICY, RBAC & 4-LEVEL FILTER)          |
|  ├── ACL & TotpManager (src/core/acl*)  : RBAC (rw/r/w), Configurable TTL Step    |
|  ├── PolicyEngine (src/policy/*)        : .gitignore phân tầng + .slug/rules.conf |
|  └── Stateful Guard (src/ai/*)          : 4 Cấp độ lọc + SQLite index.db (WAL)    |
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

---

## 5. Kiến Trúc Mật Mã Toàn Diện & Sự Khác Biệt Giữa 3 Bộ Suite

Slug thiết kế kiến trúc mật mã theo mô hình trừu tượng hóa đa tầng (`ICryptoSuite`), cho phép hệ thống linh hoạt chuyển đổi giữa mật mã cổ điển, mật mã hiện đại tốc độ cao và mật mã Hậu Lượng Tử (Post-Quantum Cryptography - PQC) mà không làm thay đổi tầng giao vận hay giao thức tệp ảo.

### 5.1. Bảng So Sánh Chi Tiết 3 Bộ Suite Mật Mã

| Tiêu Chí / Thuật Toán | **Suite 1: Classical** | **Suite 2: Modern (Mặc định)** | **Suite 3: Pure PQC** |
| :--- | :--- | :--- | :--- |
| **Mã định danh (Suite ID)** | `0x01` (`classical`) | `0x02` (`modern`) | `0x03` (`pqc`) |
| **Hàm băm (Hashing)** | SHA-256 (NIST FIPS 180-4) | **BLAKE3** (Merkle Tree 256-bit) | **BLAKE3** (Merkle Tree 256-bit) |
| **Phái sinh khóa (KDF)** | HKDF-SHA256 (RFC 5869) | **BLAKE3-KDF** (Key Derivation) | **BLAKE3-KDF** (Key Derivation) |
| **Trao đổi khóa (KEM / ECDH)**| **X25519** (Curve25519 ECDH, 32B) | **X25519** (Curve25519 ECDH, 32B) | **ML-KEM-768** (NIST FIPS 203 PQC) |
| **Chữ ký số (Signature)** | **Ed25519** (RFC 8032, 64B sig) | **Ed25519** (RFC 8032, 64B sig) | **ML-DSA-65** (NIST FIPS 204 PQC) |
| **Mã hóa đối xứng (AEAD)** | **XChaCha20-Poly1305** (24B Nonce)| **XChaCha20-Poly1305** (24B Nonce)| **XChaCha20-Poly1305** (24B Nonce)|
| **Kích thước Public Key** | 32 bytes | 32 bytes | **1.184 bytes** |
| **Kích thước Ciphertext KEM**| 32 bytes | 32 bytes | **1.088 bytes** |
| **Kháng Máy Tính Lượng Tử** | ❌ Không (Bị thuật toán Shor phá) | ⚠️ Kháng lượng tử tầng đối xứng | ✅ **100% Kháng Lượng Tử Toàn Diện** |
| **Tốc độ bắt tay (Handshake)**| Cực nhanh (< 1 ms LAN) | Siêu tốc (< 0.5 ms LAN) | Rất nhanh (~1–2 ms LAN) |
| **Mục đích sử dụng** | Thiết bị nhúng, CPU đời cũ, chuẩn tương thích quốc tế rộng rãi | Cân bằng hoàn hảo tốc độ & hiệu năng cao cho môi trường lập trình hàng ngày | Bảo mật tuyệt đối trước mối đe dọa "Thu thập trước, giải mã sau" (Store-Now-Decrypt-Later) |

---

### 5.2. Bản Chất Khác Biệt Của Từng Bộ Suite

1. **Suite 1 (Classical - Chuẩn Cổ Điển Tin Cậy):**
   - Sử dụng hoàn toàn các nguyên thủy mật mã đã được kiểm chứng qua hàng chục năm: **SHA-256**, **HKDF-SHA256**, **X25519**, **Ed25519**.
   - Phù hợp nhất cho môi trường yêu cầu tuân thủ nghiêm ngặt các chứng chỉ kế thừa hoặc chạy trên phần cứng vi điều khiển/nhúng không có tập lệnh mở rộng SIMD.

2. **Suite 2 (Modern - Hiện Đại Tối Ưu Tốc Độ):**
   - Đột phá về tốc độ nhờ thay thế toàn bộ tầng băm và KDF bằng **BLAKE3**.
   - BLAKE3 tận dụng cấu trúc cây Merkle kết hợp song song hóa phần cứng SIMD (AVX-512, AVX2, ARM Neon), cho tốc độ băm tệp nhanh hơn SHA-256 từ 6–12 lần, giúp việc tính toán checksum của các file dự án lớn hàng gigabyte diễn ra tức thì.
   - Vẫn sử dụng khóa trao đổi X25519 siêu nhẹ (32 bytes), giữ độ trễ kết nối ở mức tối thiểu.

3. **Suite 3 (Pure PQC - Hậu Lượng Tử Thuần Khiết):**
   - Triển khai đầy đủ hai bộ tiêu chuẩn mật mã Hậu Lượng Tử chính thức được Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ ban hành vào tháng 8/2024:
     - **ML-KEM-768 (FIPS 203)**: Cơ chế đóng gói khóa dựa trên bài toán Mạng Tinh Thể (Module Lattice - M-LWE), thay thế hoàn toàn thuật toán Diffie-Hellman / RSA.
     - **ML-DSA-65 (FIPS 204)**: Thuật toán chữ ký số hậu lượng tử dựa trên Module Learning with Errors, đảm bảo định danh không thể bị giả mạo ngay cả khi máy tính lượng tử quy mô lớn xuất hiện.
   - Triệt tiêu hoàn toàn kịch bản tấn công **"Thu thập dữ liệu hôm nay, chờ có máy tính lượng tử để giải mã trong tương lai" (Store-Now-Decrypt-Later)**.

---

### 5.3. Các Kỹ Thuật Mật Mã "Hardcore" Được Ứng Dụng Tổng Quát Trong Toàn Bộ Slug

Kiến trúc mật mã của Slug không dừng lại ở việc gọi API thư viện, mà áp dụng các nguyên lý bảo mật thực chiến ở mức sâu nhất:

#### 1. Forward Secrecy Tuyệt Đối (Bảo Mật Chuyển Tiếp Từng Phiên)
- Mọi phiên kết nối đều sinh ra cặp khóa KEM dùng một lần (**Ephemeral Keypair**). 
- `SharedSecret` chỉ tồn tại trong bộ nhớ RAM tạm thời và được dọn dẹp bằng kỹ thuật ghi đè an toàn (`explicit_bzero` / `SecureZeroMemory`) ngay khi phiên làm việc chấm dứt.
- Kể cả khi kẻ tấn công đánh cắp được máy tính của Host hoặc Client sau đó, toàn bộ dữ liệu gói tin bắt được trên mạng trước đây vĩnh viễn không thể giải mã được.

#### 2. Kỹ Thuật Directional Salt & Nonce Anti-Collision (Chống Đụng Độ Nonce Cho XChaCha20)
- Với mật mã dòng ChaCha20, việc **tái sử dụng Nonce với cùng một khóa (Nonce Reuse)** là thảm họa bảo mật (dẫn đến việc giải mã được cả hai luồng bản rõ qua phép XOR).
- Slug giải quyết triệt để vấn đề này trong môi trường mạng Full-Duplex (cả hai chiều gửi nhận đồng thời) bằng cơ chế:
  - Sinh **2 Muối Độc Lập** từ `SharedSecret`: `ClientToServer_Salt` (16 bytes) và `ServerToClient_Salt` (16 bytes).
  - Ghép với bộ đếm gói tin đơn điệu tăng dần (**Monotonic 64-bit SeqNum**): $\text{Nonce} = \text{Salt}_{16} \parallel \text{SeqNum}_8$.
  - Dù hai bên gửi gói tin số `SeqNum = 1` tại cùng một tích tắc, Nonce 24 bytes ở hai chiều vẫn hoàn toàn độc lập, đảm bảo an toàn tuyệt đối.

#### 3. Bọc Khối Dữ Liệu Phân Mảnh Kèm AAD (Chunk-Level Authenticated Streaming)
- Slug không mã hóa cả file lớn vào một mảng bộ nhớ (tránh cạn kiệt RAM). Dữ liệu được băm nhỏ thành các khối chuẩn 64 KiB.
- Mỗi khối dữ liệu được bọc bởi **XChaCha20-Poly1305 AEAD** với trường dữ liệu bổ sung (**Associated Data - AAD**) chứa:
  $$\text{AAD} = \text{PacketLength}\ (4\text{ bytes}) \parallel \text{SeqNum}\ (8\text{ bytes})$$
- Phép xác thực MAC Poly1305 (16 bytes tag) bảo vệ toàn vẹn cả phần thân dữ liệu lẫn header. Kẻ tấn công trên đường truyền không thể:
  - Cắt ngắn hoặc chèn thêm byte vào gói tin.
  - Tráo đổi thứ tự giữa các chunk.
  - Phát lại gói tin cũ (nhờ cửa sổ trượt Anti-Replay Sliding Window).

#### 4. EnvShield: Phòng Vệ Bí Mật Trong RAM (Zero-Plaintext In-Memory Injection)
- Giải quyết bài toán bảo vệ file `.env` trước các AI coding agent:
  - **Lúc nghỉ (At Rest):** File `.env` gốc được mã hóa thành `.env.pqc` trong workspace và cất bản dự phòng vào Central Vault (`~/.slug/env_vault/`), hoàn toàn xóa sổ file `.env` plaintext trên ổ cứng.
  - **Lúc chạy (In Execution):** Lệnh `slug env run -- <lệnh>` đọc `.env.pqc`, giải mã trực tiếp vào bộ nhớ RAM, phân tích thành các cặp biến môi trường rồi tiêm thẳng vào khối `Environment Block` khi tạo tiến trình con của hệ điều hành (`CreateProcessW` trên Windows, `execve` trên Linux).
  - Tiến trình con thực thi với đầy đủ biến môi trường, trong khi ổ cứng hoàn toàn sạch sẽ, không có bất kỳ byte plaintext nào cho AI đọc trộm.

#### 5. Cơ Chế Xác Thực Đa Lớp: Vé Phiên Dùng 1 Lần (TOTP / Ephemeral Ticket)
- Trước khi nâng cấp lên kênh PQC AEAD đầy đủ, Slug xác thực người dùng bằng mã OTP 8 chữ số (chu kỳ xoay vòng 30 giây, tự hủy ngay khi xác thực thành công) hoặc vé phiên có chữ ký số.
- Phân tách quyền hạn rõ ràng thành 3 mức cố định tại tầng VFS: `READ_WRITE` (`[rw]`), `READ_ONLY` (`[r]`), và `WRITE_ONLY` (`[w]`), ngăn ngừa triệt để mọi hành vi lạm quyền hoặc vượt ranh giới tài nguyên.

---

## 6. Kiến Trúc Lưu Trữ & Chỉ Mục Trạng Thái (Zero-Dependency State & Indexing Engine)

Để kiên định với triết lý **Zero-Dependency Portable Binary** (~8 MB, chạy ngay trên mọi máy tính mà không cần cài đặt runtime hay cơ sở dữ liệu ngoài), Slug chủ động chọn mô hình lưu trữ phân tầng hướng hiệu năng cao (tương tự triết lý thiết kế của Git `.git/index` và Docker container metadata):

```text
+---------------------------------------------------------------------------------+
| KIẾN TRÚC LƯU TRỮ VÀ QUẢN LÝ DỮ LIỆU SLUG (ZERO-DEPENDENCY STORAGE ARCHITECTURE) |
+---------------------------------------------------------------------------------+
|                                                                                 |
| 1. IN-MEMORY HASH INDEX (RAM O(1) Lookup - 0ms Cache Hit)                       |
|    std::unordered_map<string, AuditIndexEntry>                                  |
|    - Ánh xạ đường dẫn -> BLAKE3 hash -> AuditStatus (CLEAN / FLAGGED / ALLOWED) |
|                                                                                 |
| 2. ATOMIC FLAT-FILE PERSISTENCE (.slug/index.db)                                |
|    Định dạng: Atomic JSON Document (ghi ra .tmp rồi đổi tên nguyên tử)          |
|    - Miễn nhiễm hoàn toàn trước rủi ro hỏng file (file corruption) khi crash    |
|                                                                                 |
| 3. APPEND-ONLY EVENT LOGGING (.slug/audit.log)                                  |
|    Định dạng: JSON Lines (JSONL) Streaming Log                                  |
|    - Ghi nối đuôi O(1) thời gian thực, triệt tiêu hoàn toàn Database Lock       |
|                                                                                 |
| 4. GLOBAL WORKSPACE REGISTRY (~/.slug/registry.json)                            |
|    - Quản lý danh bạ port, PID, TTL, Filter Mode và dọn rác tiến trình chết    |
+---------------------------------------------------------------------------------+
```

### 6.1. Bộ Nhớ Đệm Chỉ Mục Kiểm Toán Trạng Thái (`.slug/index.db`)
- **Bản chất lưu trữ:** Tệp `.slug/index.db` được quản lý bởi engine SQLite 3.46.1 nhúng trực tiếp dưới dạng C-amalgamation độc lập (`third_party/sqlite/sqlite3.c`), không đòi hỏi bất kỳ thư viện ngoài nào (100% zero-dependency).
- **Cơ chế WAL Mode (Write-Ahead Logging):** Slug kích hoạt `PRAGMA journal_mode=WAL` và `PRAGMA synchronous=NORMAL`, cho phép các tiến trình đọc (Web Portal, CLI list) và tiến trình ghi (Scanner, Host Admin) hoạt động đồng thời mà không bị khóa bảng (`database is locked`).
- **Tối ưu tra cứu $O(1)$:** Kết hợp giữa SQLite database trên đĩa và bảng băm `std::unordered_map` trong RAM. Mỗi tệp được kiểm tra qua BLAKE3 hash; nếu hash không thay đổi, Slug trả về trạng thái ngay lập tức (0ms).
- **Cơ chế Tự Động Chữa Lành (Auto-Healing):** Khi nạp database, hệ thống tự động chạy truy vấn dọn dẹp các cờ lỗi lịch sử trên các file nhị phân, compiled hoặc media (như `.pyd`, `.dll`, `.png`), khôi phục trạng thái sạch tức thì.
- **Mở khóa theo phân cấp thư mục (`allow_folder`):** Khi Host thêm một quy tắc ALLOW cho thư mục (ví dụ `ALLOW path apps/marknote/_internal/`), truy vấn SQL mở khóa tức thời toàn bộ các tệp con:
  $$\text{WHERE } (\text{file\_path} = ? \text{ OR } \text{file\_path LIKE } ? \parallel \text{'/{\%}'})$$
  đồng thời kích hoạt xóa cache manifest để tái đánh giá tức thì mà không cần khởi động lại server.

### 6.2. Nhật Ký Kiểm Toán Nối Đuôi An Toàn (`.slug/audit.log`)
- Được lưu theo định dạng **JSON Lines (JSONL)**: Mỗi sự kiện kiểm toán (`AI_UPLOAD_BLOCKED`, `FILE_DOWNLOAD`, `DECISION_OVERRIDE`...) là một dòng JSON độc lập.
- **Ghi nối đuôi thời gian thực (O(1)):** Ghi tuần tự không phụ thuộc transaction dài, đảm bảo vết kiểm toán không bị gián đoạn hay mất mát khi crash.

### 6.3. Sổ Đăng Bạ Workspace Toàn Cục (`~/.slug/registry.json`)
- Đặt tại thư mục người dùng (`$HOME/.slug/`), đóng vai trò như một Service Registry cục bộ.
- Cho phép lệnh `slug list` và Web Portal tra cứu tức thì toàn bộ các workspace đang được chia sẻ, kiểm tra trạng thái sống còn của tiến trình nền (`ProcessUtils::is_process_alive`), và tự động thanh lọc các workspace của tiến trình đã kết thúc mà không để lại rác tài nguyên.

---

## 7. Bất Biến Hiển Thị Cây Thư Mục & Hệ Thống 4 Cấp Độ Lọc

### 7.1. Directory Visibility Invariant (Bất biến hiển thị)
> **Nguyên tắc cốt lõi:** Slug không bao giờ tự ý tỉa cành, cắt bỏ hay giấu file/thư mục khỏi cây thư mục chỉ vì chúng bị `.gitignore`, rules hoặc scanner đánh dấu. Cấu trúc dự án phải luôn được bảo toàn nguyên vẹn.

| Trạng thái | Hiển thị Explorer | Tải file qua mạng | Ý nghĩa kỹ thuật |
| :--- | :---: | :---: | :--- |
| `AVAILABLE` | Có | Được phép tải | Vượt qua các chốt kiểm duyệt chính sách và bảo mật. |
| `BLOCKED` | Có | Bị từ chối | Bị chặn bởi `.gitignore`, rule của Host, hoặc bộ quét secret. |
| `.slug/`, `.git/` | Không hiển thị | Tuyệt đối cấm | Thư mục metadata nội bộ, được bảo vệ ở tầng thấp nhất (`is_internal_slug_path`). |

Mọi thao tác cấm tải được cưỡng chế trực tiếp tại backend (`vfs_.read_file`, `get_chunk`). Frontend không bao giờ quyết định quyền truy cập dữ liệu.

### 7.2. Định Nghĩa 4 Cấp Độ Lọc Tích Lũy (4 Filter Levels)

```text
Level 1: Rules (.gitignore + .slug/rules.conf)
    └── Level 2: Regex (Bổ sung bộ mẫu phát hiện Secret / Token / Private Key / JWT)
            └── Level 3: Entropy (Bổ sung Shannon Entropy H(X) >= 4.0 trên scannable text/code)
                    └── Level 4: AI (Bổ sung Contextual LLM Advisor: Ollama / OpenAI / Gemini)
```

- **Tách biệt với Scope Override:** Các cờ `--include-ignored` và `--no-filter` chỉ là tùy chọn phạm vi chia sẻ (scope), tuyệt đối không bao giờ làm vô hiệu hóa xác thực, mã hóa AEAD, RBAC, chống path traversal hoặc bảo vệ thư mục metadata `.slug/`.

---

## 8. Hệ Thống Phân Cấp 4 Loại TTL & Quản Trị Vòng Đời Phiên (Session Lifecycle)

Slug xây dựng mô hình thời gian sống (TTL) 4 tầng độc lập và chặt chẽ:

1. **OTP Step TTL (Chu kỳ xoay vòng mã xác thực):** Cấu hình linh hoạt qua `--otp-step <seconds>` (30s, 60s, 120s, 300s, 600s). Tự hủy vé ngay sau khi bắt tay thành công.
2. **Workspace TTL (Thời hạn sống của trạm host):** Cấu hình qua `--workspace-ttl <seconds>`. Khi hết hạn, bộ dọn dẹp `check_expired_workspaces()` tự động thu hồi tài nguyên và đóng trạm host an toàn.
3. **User TTL (Thời hạn hiệu lực tài khoản RBAC):** Lưu trong `.slug/acl.db` (`expires_at = now + ttl`). Khi quá hạn, user bị từ chối đăng nhập.
4. **Session TTL (Thời hạn phiên kết nối client):** Ràng buộc theo nguyên tắc:
   $$\text{SessionTTL} = \min(\text{CertTTL}, \text{UserRemainingTTL})$$
   Đảm bảo một phiên kết nối không bao giờ tồn tại lâu hơn thời hạn tài khoản.

- **Thu Hồi Phiên Tức Thì (Immediate Session Revocation):** Khi Host sửa mật khẩu, đổi quyền hoặc xóa tài khoản, hệ thống lập tức kích hoạt `revoke_sessions_by_identity` ngắt kết nối toàn bộ các client đang online của user đó.
- **Trạng thái hiển thị rành mạch:** Admin Dashboard phân định chính xác huy hiệu `ACTIVE (Còn sống)`, `EXPIRED (Đã hết hạn)` và `REVOKED (Đã hủy)`, triệt tiêu hoàn toàn trạng thái lai sai lệch.

---

## 9. Kiểm Định An Toàn Kênh Mật Mã Bằng Wireshark (Deep Packet Inspection)

Mọi gói tin truyền qua mạng giữa Client và Host (trên cổng `9443`) đều được mã hóa hoàn toàn bằng **ML-KEM-768 + XChaCha20-Poly1305 AEAD**. Dưới đây là bộ truy vấn Wireshark chính xác để kiểm chứng:

### 9.1. Bộ Lọc Hiển Thị (Display Filters) Kiểm Tra Bảo Mật

```text
# 1. Bắt toàn bộ luồng dữ liệu của Slug
tcp.port == 9443

# 2. Chứng minh KHÔNG có HTTP bản rõ trên mạng (Kỳ vọng: 0 packets)
tcp.port == 9443 && (http || http2)

# 3. Quét tìm bản rõ từ khóa nhạy cảm / headers (Kỳ vọng: 0 packets)
tcp.port == 9443 && (frame contains "GET " || frame contains "POST " || frame contains "HTTP/" || frame contains "password" || frame contains "token" || frame contains "secret" || frame contains "api_key")

# 4. Quét tìm bản rõ tên file hoặc nội dung code (Kỳ vọng: 0 packets)
tcp.port == 9443 && (frame contains "main.cpp" || frame contains "include" || frame contains "import" || frame contains "class " || frame contains "def ")

# 5. Phân tích các khối dữ liệu mã hóa nhị phân
tcp.port == 9443 && tcp.len > 100
```

### 9.2. Phân Tích Thực Tế Dòng Luồng TCP Stream
Khi nhấp chuột phải vào một gói tin và chọn **Follow -> TCP Stream**:
- **Khung bắt tay (Handshake Frame):** Ciphertext ML-KEM-768 (1088 bytes) và Public Key (1184 bytes) có phân bổ entropy ngẫu nhiên cao.
- **Khung dữ liệu (Data Frames):** Từng chunk 64 KiB được bọc trong 16-byte Poly1305 Auth Tag, Nonce độc lập phân hướng và ciphertext.
- **Kết luận:** Dù kẻ tấn công đứng cùng mạng Wi-Fi và dump toàn bộ gói tin bằng `tcpdump` hay `Wireshark`, 100% dữ liệu thu được chỉ là ciphertext ngẫu nhiên thuần túy, bảo vệ tuyệt đối tính riêng tư của dữ liệu người dùng. Mẫu capture thực tế: [`docs/real_capture_from_a_to_b.pcapng`](real_capture_from_a_to_b.pcapng).


