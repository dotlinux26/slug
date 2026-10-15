# SLUG SYSTEM ARCHITECTURE BLUEPRINT (5-LAYER STRICT ARCHITECTURE)
## Post-Quantum Ephemeral Workspace Sharing & AI Secret Guard (v1.0.0-rc2)

---

```text
+-----------------------------------------------------------------------------------+
| LAYER 1: PRESENTATION & UX LAYER (Tầng Giao Diện)                                 |
|  ├── CLI Dispatcher (src/main.cpp)    : Parse POSIX args/flags, ANSI rendering    |
|  └── Web Assets (src/net/web_assets.h): Modular HTML/CSS/JS for Drop & Admin UI   |
+-----------------------------------------+-----------------------------------------+
                                          | (Standardized Struct Requests)
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 2: TRANSPORT & SESSION GATEKEEPER (Tầng Giao Vận & Trạm Gác)                |
|  ├── Binary PQC Engine                : Handshake ML-KEM-768 / ML-DSA-65          |
|  ├── AEAD Framing (aead_frame.hpp)    : XChaCha20-Poly1305 + Anti-Replay Window   |
|  │                                      Directional Nonces: (c2s_salt / s2c_salt) |
|  ├── HTTP Web Gatekeeper              : 403 Barrier, Session Ticket Auth, Cookie  |
|  └── Future Localhost Web Proxy       : Secure Loopback Tunnel                    |
+-----------------------------------------+-----------------------------------------+
                                          | (SessionToken & Capability Verification)
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 3: WORKSPACE CORE & VFS JAIL (Tầng Nghiệp Vụ Lõi & Quản Lý Vị Trí)         |
|  ├── SlugVFS (src/core/vfs.hpp)       : Single-source of path truth, Anti-Escape  |
|  │                                      Enforces Role (r/w/rw) at Filesystem Level|
|  ├── DeltaSyncEngine (src/sync/*)     : 64 KiB BLAKE3 chunking, Manifest builder  |
|  └── WorkspaceManager                 : Registry, PID, flock() concurrency guard  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 4: SECURITY, RBAC & POLICY ENGINE (Tầng Chính Sách & Kiểm Duyệt)            |
|  ├── ACL & TotpManager (src/core/acl*): 3-Role TOTP (rw/r/w) + Permanent User     |
|  ├── PolicyEngine (src/policy/*)      : Hierarchical .gitignore + rules.conf      |
|  └── Stateful AI Guard (src/ai/*)     : Content-addressable cache (index.db) +    |
|                                         Entropy & Heuristic Scanner               |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| LAYER 5: CRYPTO PRIMITIVES (Tầng Mật Mã Cấp Thấp - OpenSSL 3.6.3 & BLAKE3)        |
|  ├── ICryptoSuite (Suite 1, 2, 3)     : Classical / Modern / PurePQC              |
|  ├── NIST FIPS 203 & 204              : ML-KEM-768, ML-DSA-65 (Post-Quantum)      |
|  ├── BLAKE3 & BLAKE3-KDF              : High-throughput hashing & key derivation  |
|  └── XChaCha20-Poly1305               : 256-bit AEAD authenticated encryption     |
+-----------------------------------------------------------------------------------+
```

---

## 1. Luồng Dữ Liệu & Các Chốt Chặn Bảo Mật (Gatekeepers)

### Chốt chặn 1: Tầng Giao Vận (Layer 2)
1. **PQC Handshake:** Trao đổi cặp khóa ML-KEM-768 và chữ ký ML-DSA-65. Không khóa bí mật nào bay trên mạng.
2. **Directional AEAD Framing:**
   - Dẫn xuất qua BLAKE3-KDF: `SessionKey` (32B), `ClientToServer_Salt` (16B), `ServerToClient_Salt` (16B).
   - Chiều Client -> Server: Nonce = ClientToServer_Salt || tx_seq.
   - Chiều Server -> Client: Nonce = ServerToClient_Salt || tx_seq.
   - AAD = [Len (4B) || SeqNum (8B)] bảo vệ toàn vẹn Header.
   - Bộ lọc `AntiReplaySlidingWindow` (64-bit) ở phía nhận ngăn chặn tấn công phát lại.
3. **Web Gatekeeper:** Chặn 100% request không mang `ticket` hợp lệ (HTTP 403 Forbidden).

### Chốt chặn 2: Tầng Hệ Thống Tập Tin Ảo `SlugVFS` (Layer 3)
1. **Jail & Path Traversal Prevention:**
   - Client chỉ được nhìn thấy `VirtualPath` (bắt đầu bằng `/`).
   - Mọi truy cập đều đi qua `vfs.resolve_and_jail(virtual_path, role)`.
   - Bất kỳ nỗ lực `../../` hoặc symlink trỏ ra ngoài `ServerRootPath` đều lập tức bị từ chối `AccessDenied`.
2. **RBAC Enforcement tại VFS:**
   - `Role::WRITE_ONLY`: Bị cấm gọi `list_dir()` hoặc `read_file()` (bảo vệ tuyệt đối mã nguồn của Host).
   - `Role::READ_ONLY`: Bị cấm gọi `write_file()` hoặc `delete_file()`.
3. **Unified Filter Integration:**
   - Tích hợp đồng nhất `.gitignore` phân tầng + `.slug/rules.conf` + danh sách `AI_FLAGGED`. Mọi lệnh `ls`, `pull`, hay Web `/drop` đều dùng chung một logic lọc.

### Chốt chặn 3: Tầng Kiểm Duyệt Bí Mật AI Guard (Layer 4)
- Mọi file trước khi thêm vào Manifest hoặc khi upload qua `push_file` / Web Upload đều được kiểm tra qua `AiScanner`.
- Nếu phát hiện API key, token bí mật: Lập tức bị đánh dấu `BLOCKED` và ghi nhật ký kiểm toán.
