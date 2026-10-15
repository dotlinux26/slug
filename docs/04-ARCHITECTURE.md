# KIẾN TRÚC HỆ THỐNG VÀ GIAO THỨC TRUYỀN DẪN SLUG (SYSTEM ARCHITECTURE)

## 1. Mô Hình 5 Tầng Phân Lớp Tuyệt Đối (Strict 5-Layer Architecture)

Slug được thiết kế theo nguyên lý kiến trúc 5 tầng đơn hướng (unidirectional hierarchy). Các tầng cấp cao chỉ được gọi xuống các tầng cấp thấp hơn qua giao diện chuẩn hóa; các tầng cấp thấp tuyệt đối không gọi ngược lên trên hoặc phụ thuộc vòng lẫn nhau.

```text
+-----------------------------------------------------------------------------------+
| TẦNG 1: TRÌNH DIỄN & GIAO DIỆN (PRESENTATION & UX LAYER)                          |
|  ├── CLI Dispatcher (src/main.cpp)      : Parse POSIX args, ANSI terminal render  |
|  └── Web Assets (src/net/web_assets.hpp): Techno B2B UI, CSS variables, JS Drop   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 2: GIAO VẬN & TRẠM GÁC PHIÊN (TRANSPORT & SESSION GATEKEEPER)                |
|  ├── PQC Handshake Engine               : NIST FIPS 203/204 Key Exchange          |
|  ├── Directional AEAD Framing           : XChaCha20-Poly1305 + 64-bit Anti-Replay |
|  │                                        Muối độc lập: ClientToServer / ServerToClient
|  ├── Web Gatekeeper                     : 403 Barrier, 192-bit CSPRNG Ticket Auth |
|  └── Multi-Tier NAT Traversal           : IPv6 Direct -> STUN Punch -> TURN Relay |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 3: NGHIỆP VỤ LÕI & VFS JAIL (WORKSPACE CORE & VFS JAIL)                      |
|  ├── SlugVFS (src/core/vfs.hpp)         : Virtual path '/', Chống vượt ngục (Jail)|
|  │                                        Thực thi quyền (r/w/rw) ở tầng filesystem|
|  ├── DeltaSyncEngine (src/sync/*)       : Phân khối 64 KiB, Manifest so khớp BLAKE3|
|  └── WorkspaceManager                   : Registry PID, flock() khóa đồng thời    |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 4: CHÍNH SÁCH BẢO MẬT & KIỂM DUYỆT (SECURITY, RBAC & POLICY ENGINE)          |
|  ├── ACL & TotpManager (src/core/acl*)  : 3-Role TOTP (rw/r/w), Single-Use Burn   |
|  ├── PolicyEngine (src/policy/*)        : .gitignore phân tầng + .slug/rules.conf |
|  └── Stateful AI Guard (src/ai/*)       : Heuristic + Shannon Entropy + index.db  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| TẦNG 5: MẬT MÃ CẤP THẤP (CRYPTO PRIMITIVES - OpenSSL 3.6.3 & BLAKE3)              |
|  ├── NIST FIPS 203 & 204                : ML-KEM-768, ML-DSA-65 (Post-Quantum)    |
|  ├── BLAKE3 & BLAKE3-KDF                : Băm siêu tốc & Phái sinh khóa chuẩn     |
|  └── XChaCha20-Poly1305                 : Mã hóa xác thực khối 256-bit AEAD       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Giao Thức Đóng Khung Dữ Liệu Phân Hướng (Directional AEAD Wire Protocol)

Trong các giao thức truyền tải nhị phân qua TCP song công (Full-Duplex), việc tái sử dụng Nonce (Nonce Reuse) là lỗi chí mạng đối với thuật toán ChaCha20, dẫn đến nguy cơ lộ khóa luồng và bản rõ. Slug triệt tiêu hoàn toàn nguy cơ này bằng cơ chế **Directional AEAD Framing** (`src/net/aead_frame.hpp`).

### 2.1. Phái Sinh Khóa Phân Hướng Qua BLAKE3-KDF
Sau khi kết thúc quá trình bắt tay PQC và tạo được `SharedSecret` (32 bytes), cả hai đầu client và server độc lập dẫn xuất 3 giá trị thông qua bộ hàm phái sinh chuẩn:

$$\text{SessionKey} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_AEAD_SESSION_KEY_V1"})$$
$$\text{ClientToServer\_Salt} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_C2S_NONCE_SALT_V1"})[0..15]$$
$$\text{ServerToClient\_Salt} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_S2C_NONCE_SALT_V1"})[0..15]$$

### 2.2. Cấu Trúc Khung Tin AEAD (Frame Format)
Mỗi gói tin trao đổi trên kênh nhị phân được bao bọc trong một cấu trúc chặt chẽ:

```text
+-------------------+--------------------+------------------------+-------------------+
| Length (4 bytes)  | SeqNum (8 bytes)   | Encrypted Payload      | Tag (16 bytes)    |
| Big-Endian uint32 | Big-Endian uint64  | (Variable Length)      | Poly1305 MAC      |
+-------------------+--------------------+------------------------+-------------------+
|<------- Associated Data (AAD) -------->|
```

1. **Khởi Tạo Nonce Phân Hướng (24 bytes):**
   - Chiều Client gửi lên Server:
     $$\text{Nonce}_{\text{c2s}} = \text{ClientToServer\_Salt}\ (16\text{ bytes}) \parallel \text{SeqNum}_{\text{tx}}\ (8\text{ bytes})$$
   - Chiều Server gửi về Client:
     $$\text{Nonce}_{\text{s2c}} = \text{ServerToClient\_Salt}\ (16\text{ bytes}) \parallel \text{SeqNum}_{\text{tx}}\ (8\text{ bytes})$$
   - Do 2 miền muối (salt) hoàn toàn khác biệt, `Nonce` giữa 2 chiều không bao giờ trùng lặp ngay cả khi cả hai bên cùng gửi gói tin số 1 (`SeqNum = 1`).
2. **Dữ Liệu Xác Thực Kèm Theo (Associated Data - AAD):**
   - Toàn bộ 12 bytes đầu gói tin `[Length || SeqNum]` được gắn trực tiếp vào trường AAD của thuật toán XChaCha20-Poly1305.
   - Kẻ tấn công đứng giữa không thể sửa đổi chiều dài gói tin, không thể đánh tráo số thứ tự gói tin hoặc cắt ghép dữ liệu mà không làm hỏng Poly1305 MAC Tag.
3. **Cửa Sổ Trượt Chống Tấn Công Phát Lại (64-Bit Anti-Replay Sliding Window):**
   - Phía nhận duy trì cấu trúc `AntiReplaySlidingWindow` với bitmap 64-bit.
   - Bất kỳ gói tin nào có `SeqNum` trùng lặp với gói tin đã nhận hoặc có `SeqNum` quá cũ nằm ngoài phạm vi cửa sổ 64 vị trí đều bị hủy bỏ ngay lập tức trước khi đưa vào hàm giải mã.

---

## 3. Kiến Trúc Xuyên NAT Đa Tầng (Multi-Tier NAT Traversal & "SLUG-ICE")

Để cho phép hai máy tính kết nối P2P trực tiếp qua Internet mà không cần người dùng phải mở port trên router (Port Forwarding), Slug thiết lập kiến trúc xuyên NAT gồm 3 tầng lũy tiến theo mô hình "SLUG-ICE":

```text
                              BẮT ĐẦU KẾT NỐI
                                     │
                                     v
                 [TẦNG 1: IPv6 DIRECT CONNECT]
                   Có địa chỉ Global IPv6?
                         ├── (CÓ) ──> Thiết lập kênh PQC trực tiếp thành công!
                         │
                         └── (KHÔNG / BỊ CHẶN FIREWALL)
                                     │
                                     v
                 [TẦNG 2: STUN UDP HOLE PUNCHING (RFC 8489)]
                   Dò tìm Public IP:Port qua STUN Server
                   Thực hiện bắt tay đục lỗ đồng thời (Simultaneous Punch)
                         ├── (THÀNH CÔNG) ──> Kết nối P2P trực tiếp tốc độ tối đa!
                         │
                         └── (THẤT BẠI: Symmetric NAT / CGNAT kép)
                                     │
                                     v
                 [TẦNG 3: ZERO-KNOWLEDGE TURN RELAY (RFC 8656)]
                   Chuyển tiếp qua TURN Relay Server
                   Mã hóa đầu cuối hoàn toàn: Server chỉ thấy AEAD Blob
```

### 3.1. Tầng 1: Kết Nối Trực Tiếp Qua IPv6 (IPv6 Direct Connect)
- Với sự phổ cập của mạng di động 4G/5G và mạng cáp quang hiện đại, phần lớn các thiết bị đều được cấp một địa chỉ IPv6 toàn cầu (Global Unicast Address).
- Slug tự động kiểm tra sự hiện diện của IPv6: Nếu cả Host và Client đều có IPv6 và tường lửa cho phép, kết nối PQC sẽ được thiết lập thẳng mà không cần bất kỳ kỹ thuật xuyên NAT nào, giải phóng hoàn toàn rào cản cạn kiệt IPv4.

### 3.2. Tầng 2: Đục Lỗ UDP Qua Giao Thức STUN (STUN UDP Hole Punching)
- Khi cả hai máy nằm sau IPv4 NAT (Router gia đình, văn phòng):
  1. Client và Host gửi gói tin thăm dò (Binding Request) tới máy chủ STUN công cộng tiêu chuẩn (tuân thủ RFC 5389 / RFC 8489).
  2. Máy chủ STUN phản hồi địa chỉ công khai ánh xạ (`Mapped Public IP:Port`).
  3. Kênh tín hiệu ("SLUG-ICE" Rendezvous Control Channel) trao đổi các cặp địa chỉ công khai này giữa hai bên.
  4. Cả hai máy đồng thời bắn các gói tin UDP đục lỗ tới địa chỉ của đối phương. Router tại hai đầu sẽ mở bảng ánh xạ NAT stateful, biến kết nối P2P thành hiện thực mà không tốn băng thông trung gian.

### 3.3. Tầng 3: Chuyển Tiếp Tối Hậu Zero-Knowledge TURN Relay (RFC 8656)
- Trong trường hợp xấu nhất: Một trong hai máy nằm sau Symmetric NAT (thường gặp trong mạng doanh nghiệp nghiêm ngặt hoặc mạng 4G CGNAT di động) khiến kỹ thuật đục lỗ không thể đoán được cổng:
  - Hệ thống tự động chuyển tiếp qua máy chủ trung chuyển TURN Relay.
  - **Nguyên lý Zero-Knowledge (Không thể đọc trộm):**
    - Toàn bộ nội dung chuyển tiếp qua TURN Relay đều được đóng gói bằng khung AEAD XChaCha20-Poly1305 với khóa bắt tay từ ML-KEM-768 giữa hai đầu máy trạm.
    - Máy chủ TURN Relay **hoàn toàn không có khóa giải mã**. Máy chủ này chỉ đóng vai trò một "người chuyển phát bưu kiện bịt mắt", chuyển các khối byte nhị phân đã mã hóa và kiểm tra chiều dài gói tin. Kể cả khi máy chủ TURN bị kiểm soát bởi bên thứ ba độc hại, dữ liệu mã nguồn của người dùng vẫn được bảo vệ an toàn 100%.

---

## 4. Tầng Dữ Liệu Đồng Bộ Vi Sai (Differential Delta Engine)

Quá trình truyền tải tập tin trong Slug áp dụng mô hình Content-Addressable lưu trữ phân khối tương tự Git và rsync:
1. **Phân Khối Cố Định 64 KiB (Chunking):** Mọi tập tin lớn đều được chia thành các khối 64 KiB liên tục.
2. **Cây Băm BLAKE3:** Mỗi khối được định danh bằng mã băm BLAKE3 256-bit. Thuật toán BLAKE3 đạt băng thông xử lý lên tới hàng Gigabyte/giây, vượt trội hoàn toàn so với SHA-256 cổ điển.
3. **So Khớp Manifest (Delta Planner):**
   - Phía Client nhận file manifest chứa danh sách các hash khối từ Host.
   - So khớp với các khối đã có sẵn tại đĩa cục bộ.
   - Chỉ yêu cầu truyền tải chính xác các khối bị thay đổi hoặc còn thiếu.
   - Bỏ qua các tệp nguyên vẹn, tiết kiệm 100% băng thông đường truyền và thời gian xử lý.
