# SLUG SYSTEM ARCHITECTURE BLUEPRINT (5-LAYER STRICT ARCHITECTURE)
## Post-Quantum Ephemeral Workspace Sharing & AI Secret Guard (v1.0.0 Production)

---

```text
+-----------------------------------------------------------------------------------+
| LAYER 1: PRESENTATION & UX LAYER (Tầng Giao Diện)                                 |
|  ├── CLI Dispatcher (src/main.cpp)      : Parse POSIX commands/flags, ANSI render |
|  ├── Loopback Web Viewing Engine        : Zero Remote HTTP (127.0.0.1:8080)       |
|  └── Web Assets (src/net/web_assets.hpp): Techno B2B UI (HTML/CSS/JS, JetBrains)  |
+-----------------------------------------+-----------------------------------------+
                                          | (Standardized Struct Requests)
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 2: TRANSPORT & SESSION GATEKEEPER (Tầng Giao Vận & Trạm Gác)                |
|  ├── Binary PQC Engine                  : Handshake ML-KEM-768 / ML-DSA-65        |
|  ├── AEAD Framing (aead_frame.hpp)      : XChaCha20-Poly1305 + Anti-Replay Window |
|  │                                        Directional Nonces: (c2s_salt / s2c_salt)
|  ├── NAT Traversal (SLUG-ICE)           : Direct P2P UDP/TCP Hole Punching        |
|  └── Localhost Tunnel Gateway           : Proxies GUI actions into PQC frames     |
+-----------------------------------------+-----------------------------------------+
                                          | (SessionToken & Capability Verification)
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 3: WORKSPACE CORE & VFS JAIL (Tầng Nghiệp Vụ Lõi & Quản Lý Vị Trí)         |
|  ├── SlugVFS (src/core/vfs.hpp)         : Single-source of path truth, Anti-Escape|
|  │                                        Enforces Role (r/w/rw) at Filesystem Lvl|
|  ├── DeltaSyncEngine (src/sync/*)       : 64 KiB BLAKE3 chunking, Fast-Path diff  |
|  └── WorkspaceManager                   : Registry, PID, socket concurrency guard |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 4: SECURITY, RBAC & POLICY ENGINE (Tầng Chính Sách & Kiểm Duyệt)            |
|  ├── ACL & TotpManager (src/core/acl*)  : 3-Role OTP (rw/r/w) + Ephemeral RBAC    |
|  ├── PolicyEngine (src/policy/*)        : Hierarchical .gitignore + rules.conf    |
|  │                                        Whitelist Exception Support (!prefix)   |
|  ├── Slug Guard (Offline Core)           : Heuristic Regex + Shannon Entropy H>=4.0|
|  │                                        BLAKE3 Content Cache (index.db: 0.015us)|
|  └── Slug AI (Optional Advisory)        : LLM Structured JSON Schema Advisory     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 5: CRYPTO PRIMITIVES (Tầng Mật Mã Cấp Thấp - OpenSSL 3.6.3 & BLAKE3)        |
|  ├── ICryptoSuite (Suite 1, 2, 3)       : Classical / Modern / PurePQC            |
|  ├── NIST FIPS 203 & 204                : ML-KEM-768, ML-DSA-65 (Post-Quantum)   |
|  ├── BLAKE3 & BLAKE3-KDF                : High-throughput hashing & key derivation|
|  └── XChaCha20-Poly1305                 : 256-bit AEAD authenticated encryption   |
+-----------------------------------------------------------------------------------+
```

---

## 1. Luồng Dữ Liệu & Các Chốt Chặn Bảo Mật (Gatekeepers)

### Chốt chặn 1: Tầng Giao Vận (Layer 2)
1. **PQC Handshake:** Trao đổi cặp khóa ML-KEM-768 và chữ ký ML-DSA-65. Không có khóa bí mật hay plaintext nào bay trên mạng LAN/Internet.
2. **Directional AEAD Framing:**
   - Dẫn xuất qua BLAKE3-KDF: `SessionKey` (32B), `ClientToServer_Salt` (16B), `ServerToClient_Salt` (16B).
   - Chiều Client -> Server: Nonce = ClientToServer_Salt || tx_seq.
   - Chiều Server -> Client: Nonce = ServerToClient_Salt || tx_seq.
   - AAD = [Len (4B) || SeqNum (8B)] bảo vệ toàn vẹn Header.
   - Bộ lọc `AntiReplaySlidingWindow` (64-bit) ở phía nhận ngăn chặn tấn công phát lại.
3. **Zero Remote HTTP Architecture:** Không mở cổng Web HTTP ra ngoài Internet. Giao diện Web chạy cục bộ trên loopback `127.0.0.1:8080/` và chuyển tiếp các thao tác qua kết nối nhị phân PQC.

### Chốt chặn 2: Tầng Hệ Thống Tập Tin Ảo `SlugVFS` (Layer 3)
1. **Jail & Path Traversal Prevention:**
   - Client chỉ được nhìn thấy `VirtualPath` (bắt đầu bằng `/`).
   - Mọi truy cập đều đi qua `vfs.resolve_and_jail(virtual_path, role)`.
   - Bất kỳ nỗ lực `../../` hoặc symlink trỏ ra ngoài `ServerRootPath` đều lập tức bị từ chối `AccessDenied`.
2. **RBAC Enforcement tại VFS:**
   - `Role::WRITE_ONLY`: Bị cấm gọi `list_dir()` hoặc `read_file()` (bảo vệ mã nguồn của Host không bị đọc lén, hỗ trợ bài toán thu bài tập một chiều cho lớp học 40–50 sinh viên).
   - `Role::READ_ONLY`: Bị cấm gọi `write_file()` hoặc `delete_file()`.
3. **Unified Filter Integration & Whitelist:**
   - Tích hợp đồng nhất `.gitignore` phân tầng + `.slug/rules.conf` + danh sách `QUARANTINED`.
   - Hỗ trợ luật ngoại lệ Whitelist bằng tiền tố `!` (ví dụ: `!.env.example`, `!*.example` vẫn được truyền an toàn).

### Chốt chặn 3: Tầng Kiểm Duyệt Bí Mật Slug Guard & AI (Layer 4)
- **Slug Guard (Chặn cứng offline):** Heuristic Regex quét các mẫu key phổ biến (AWS, OpenAI, Stripe, Private Key) + Shannon Entropy Analyzer ($H(X) \ge 4.0$) phát hiện token sinh ngẫu nhiên.
- **Slug AI (Cố vấn tùy chọn):** Khi có cờ `--ai`, gửi trích đoạn mã đến LLM nội bộ hoặc Cloud để nhận schema JSON (`has_secret`, `reason`, `line`) tham vấn ngữ cảnh, không thay thế luật cứng của Slug Guard.
- File nghi vấn tự động bị đánh dấu `QUARANTINED` và ghi nhật ký kiểm toán `.slug/audit.log`.
