# BẢO VỆ DỮ LIỆU TRONG KỶ NGUYÊN AI: VỊ TRÍ THỰC TẾ CỦA AI TRONG SLUG

## 1. Định Vị Đúng: AI Nên Đứng Ở Đâu Trong Một Công Cụ Chia Sẻ Workspace?

Trong bối cảnh các cuộc thi công nghệ và sản phẩm bảo mật, việc lạm dụng AI hoặc "gắn nhãn AI lên mọi thứ" rất dễ tạo ra cảm giác an toàn giả (False Sense of Security). 

Slug tiếp cận AI theo một triết lý kỹ thuật thực dụng và có kiểm soát:

```text
+---------------------------------------------------------------------------------+
| TẦNG 1: SLUG GUARD - LOGIC TOÁN HỌC & HỆ THỐNG XÁC ĐỊNH (100% OFFLINE)           |
| - Mật mã học: NIST FIPS 203/204 (ML-KEM-768, ML-DSA-65), AEAD XChaCha20-Poly1305|
| - Phân quyền: RBAC (r / w / rw), TTL tự hủy, TOTP Anti-Replay                   |
| - Lọc cấu trúc: Đọc phân tầng file .gitignore                                   |
| - Chính sách máy chủ: File cấu hình .slug/rules.conf & Whitelist (!)            |
| - Quét Heuristic / Regex: Bắt AWS, GitHub, Stripe, Private Key, JWT, DB URLs    |
| - Phân tích Shannon Entropy: Đo độ hỗn loạn toán học (H(X) >= 4.0) bắt token lạ |
| - Khóa cứng VFS Jail: Chặn hàm đọc vfs_.read_file() ngay tại tầng hệ thống tệp  |
+---------------------------------------------------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
| TẦNG 2: SLUG AI - CỐ VẤN NGỮ NGHĨA TÙY CHỌN (OPTIONAL ADVISORY ONLY)             |
| - Kích hoạt khi có cấu hình LLM (Ollama / Cloud API với cờ --ai)                |
| - Gửi trích đoạn mã để nhận định dạng JSON cấu trúc (has_secret, reason, line)  |
| - Hỗ trợ con người tham khảo thêm góc nhìn ngữ cảnh, KHÔNG thay thế Slug Guard  |
+---------------------------------------------------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
| TẦNG 3: QUYẾT ĐỊNH CỦA CHỦ MÁY (HOST ADMIN / MANUAL GUARD)                      |
| - Chủ máy giữ quyền tối thượng để Whitelist (!.env.example) hoặc cưỡng chế chặn|
| - Toàn bộ quyết định được băm BLAKE3 và lưu trạng thái vào .slug/index.db      |
+---------------------------------------------------------------------------------+
```

---

## 2. Mô Hình 3 Tầng Phân Loại Bảo Vệ Dữ Liệu (3-Tier Protection Model)

Slug phân định rạch ròi thành **Hệ thống 4 Cấp Độ Lọc Tích Lũy (Cumulative Filter Levels)**:

| Cấp | Cơ chế tích lũy | Nguồn cấu hình | Hành vi bắt buộc |
| :---: | :--- | :--- | :--- |
| **Level 1** | **Rules** | `.gitignore` + `.slug/rules.conf` | Lọc theo đường dẫn và quy tắc Host chỉ định, hỗ trợ Whitelist (`!.env.example`). Không quét Regex hay Entropy. |
| **Level 2** | **Regex** | Level 1 + Mẫu nhận diện Secret | Tự động phát hiện AWS/GitHub/Stripe keys, Private Keys, JWT, URLs chứa password. |
| **Level 3** | **Entropy** | Level 2 + Shannon Entropy | Tính toán $H(X) \ge 4.0$ **chỉ trên tệp văn bản/code (`is_scannable_file`)**. Miễn nhiễm hoàn toàn false positive cho `.pyd`, binary, video, ảnh, archive. |
| **Level 4** | **AI** | Level 3 + AI Contextual Advisor | Kết nối LLM (Ollama / OpenAI / Gemini) phân tích ngữ cảnh, trả về schema JSON (`has_secret`, `reason`, `line`). |

- **Directory Visibility Invariant:** Trên giao diện Explorer của người dùng cuối, toàn bộ cây thư mục được giữ nguyên vẹn với 2 trạng thái chuẩn hóa: `AVAILABLE` (màu xanh lá) và `BLOCKED` (màu đỏ). Lý do chi tiết (`RULE_BLOCKED`, `SECRET_DETECTED`, `ENTROPY_FLAGGED`) được chuyển vào bảng quản trị của Host.

---

## 3. Slug Guard & Stateful Audit Index: Kiến Trúc & Cơ Chế Hoạt Động

Hệ thống bảo vệ cốt lõi của Slug (`src/ai/stateful_audit.hpp`, `src/ai/scanner.cpp`, `src/policy/rules.cpp`) hoạt động như một trạm kiểm soát dữ liệu tự động ngay tại tầng giao vận.

### 3.1. Cơ Chế Phòng Thủ Xác Định Của Slug Guard (Deterministic Defense)
1. **Quét Mẫu Heuristic & Regex Chuẩn Xác (Level 2):**
   * **Nhận diện chuyên sâu file môi trường:** Tự động phát hiện `.env`, `.env.local`, `.env.production` và các biến thể (loại trừ an toàn các file mẫu tài liệu như `.env.example`, `.env.sample`, `.env.template`).
   * **Nhận diện Unquoted & Quoted Token:** Quét các dòng gán biến `KEY=VALUE` hoặc `KEY: VALUE` cho các từ khóa nhạy cảm (`api_key`, `secret`, `token`, `password`, `auth`) ngay cả khi không đặt trong dấu ngoặc kép.
   * **Mẫu định danh nhà cung cấp phổ biến:** OpenAI (`sk-proj-...`, `sk-...`), Stripe (`sk_live_...`), GitHub (`ghp_...`), AWS (`AKIA...`), Private Key Headers (`-----BEGIN ... PRIVATE KEY-----`).
2. **Phân Tích Độ Hỗn Loạn Toán Học Có Chọn Lọc (Shannon Entropy Analyzer - Level 3):**
   * **Bộ lọc tệp có thể quét (`is_scannable_file`):** Loại trừ tuyệt đối toàn bộ file nhị phân, compiled, media, nén (`.pyd`, `.dll`, `.exe`, `.bin`, `.pak`, `.so`, `.png`, `.jpg`, `.mp4`, `.zip`, `.iso`...).
   * **Tính toán Shannon Entropy:** Chỉ áp dụng cho các file văn bản/mã nguồn:
     $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   * Bất kỳ chuỗi nào dài $\ge 20$ ký tự có $H(X) \ge 4.0$ bits/byte sẽ được đánh dấu cảnh báo.

### 3.2. Cơ Sở Dữ Liệu Chỉ Mục SQLite 3.46.1 WAL (`.slug/index.db`)
Để xử lý mượt mà dự án có hàng chục nghìn tệp:
* Tệp `.slug/index.db` sử dụng SQLite nhúng trực tiếp với chế độ **WAL (Write-Ahead Logging)**, triệt tiêu lỗi khóa bảng giữa Web Admin và CLI.
* **Cơ chế Tự Động Chữa Lành (Auto-Healing):** Ngay khi khởi động, hệ thống tự động xóa sạch các cờ lỗi cũ trên các tệp non-scannable (`.pyd`, `.dll`, `.png`...), khôi phục ngay trạng thái sạch.
* **Khớp tiền tố mở khóa thư mục (`allow_folder`):** Khi Host thêm luật ALLOW cho thư mục, lệnh SQL unblock tức thì các file con `(file_path = ? OR file_path LIKE ? || '/%')` và xóa manifest cache, phản hồi trạng thái `AVAILABLE` ngay trong 0ms.
* Mỗi file được kiểm tra qua BLAKE3 hash; nếu hash không đổi, kết quả trả về tức thì $O(1)$ mà không tốn CPU quét lại.

---

## 4. Quy Trình Phản Ứng & Phê Duyệt Của Chủ Máy (`slug audit`)

Slug không để AI tự quyết định một cách mù quáng. Mọi hành động của AI đều minh bạch và có thể được chủ máy can thiệp:

### 4.1. Liệt Kê Các Tệp Bị Cách Ly
```bash
$ slug audit list -p 9443
AUDIT QUARANTINE INDEX (Port 9443):

[FILE PATH]                [STATUS]      [LOCATION]   [REASON]
------------------------------------------------------------------------------------------
tests/leaked_token.ts      AI_FLAGGED    L1           Stripe Live Secret Key
.env                       AI_FLAGGED    L1           Environment Secret File (.env)
config/jwt.key             AI_FLAGGED    L4           High-entropy Secret Token
```

### 4.2. Phê Duyệt File Báo Nhầm (Whitelist False Positive)
Nếu `tests/leaked_token.ts` chỉ là mock token phục vụ cho việc chạy test tự động:
```bash
$ slug audit allow tests/leaked_token.ts --reason "Safe mock token for unit testing" -p 9443
[+] Whitelisted: tests/leaked_token.ts (USER_ALLOWED)
```
Quyết định này được ghi nhận vĩnh viễn trong nhật ký kiểm toán `.slug/audit.log` và cập nhật vào `.slug/index.db`. File này sẽ được phép chuyển sang trạng thái `Available` trong lần `slug pull` tiếp theo.

---

## 5. PQC EnvShield: Lá Chắn Bảo Vệ Bí Mật Chủ Động Khỏi AI Assistants

### 5.1. Bối Cảnh Thực Tế & Rủi Ro Rò Rỉ Secret Vào Context Window
Trong quy trình phát triển hiện đại với sự hỗ trợ của các trợ lý AI (Cursor, Copilot, Claude Code, Antigravity, Devin):
* Các trợ lý AI liên tục quét cấu trúc thư mục và đọc nội dung file để nạp context vào LLM và gửi lên server cloud của nhà cung cấp AI.
* Nếu tệp `.env` hoặc khóa bí mật nằm dưới dạng bản rõ (plaintext) trên ổ đĩa, AI sẽ tự động đọc lén (passive ingestion) và đưa toàn bộ secret vào context window, lịch sử chat hoặc log hệ thống bên thứ ba.

### 5.2. Cách Thức Slug Phòng Vệ Chủ Động
Slug cung cấp module **PQC EnvShield** (`slug env`):
* **Mã hóa tĩnh (At-Rest Encryption):** Lệnh `slug env init` sử dụng mật mã hậu lượng tử mã hóa file `.env` thành `.env.pqc`, đồng thời xóa sạch bản rõ `.env` khỏi ổ đĩa.
* **Thực thi qua công cụ (Tool-Assisted Execution):** Lập trình viên dạy trợ lý AI cách chạy ứng dụng thông qua công cụ:
  ```bash
  slug env run -- npm start
  # hoặc
  slug env run -- python3 main.py
  ```
* **Bơm biến môi trường trực tiếp trong RAM:** Slug giải mã bí mật duy nhất trong bộ nhớ RAM tạm thời của tiến trình con, nạp trực tiếp vào biến môi trường của hệ điều hành mà **không ghi byte plaintext nào xuống đĩa cứng**. AI hoàn toàn không có cơ hội tiếp xúc trực tiếp với file secret bản rõ từ hệ thống tệp.

### 5.3. Nhận Thức Thực Tế & Tránh Overclaim (No-Overclaim Principle)
* **Secret có thể bị đọc khi ứng dụng đang chạy không?**
  **Có!** Để phần mềm hoạt động, các biến môi trường hiển nhiên phải tồn tại trong bộ nhớ tiến trình (RAM). Một đoạn mã cố tình chạy `printenv` hoặc cố tình dump bộ nhớ tiến trình vẫn có thể lấy được giá trị đó.
* **Vậy giá trị bảo vệ thực tế của Slug là gì?**
  Các trợ lý AI là tác nhân hỗ trợ (cooperative assistants), chúng **không bao giờ chủ động tìm cách bypass hay viết mã exploit để trích xuất bộ nhớ RAM** (trừ phi lập trình viên cố tình viết prompt hướng dẫn AI làm điều đó).
* **Kết luận:** Slug cung cấp một **lớp ma sát bảo vệ chủ động (proactive friction barrier)** ngăn chặn hành vi đọc plaintext thụ động từ ổ đĩa, hạn chế tối đa nguy cơ secret bị nạp vào context window của LLM trong quá trình làm việc hàng ngày. Đồng thời khi chia sẻ workspace giữa người với người, hệ thống **Slug Guard đa cơ chế** (`.gitignore` -> `rules.conf` -> `Smart Regex & Entropy Guard` -> `AI Semantic Guard`) giúp tự động loại bỏ rác build và rà soát, cách ly các file bí mật nghi vấn trước khi truyền tải.

### 5.4. Centralized Env Vault & Nghệ Thuật Dạy AI (Agent Directive)

#### A. Kho Lưu Trữ Trung Tâm Ngoài Workspace (`~/.slug/env_vault/`)
Khi chạy `slug env init`:
1. Slug tính mã băm định danh duy nhất của Workspace (BLAKE3 16-hex dựa trên canonical path).
2. Tự động lưu bản sao `.env` ra ngoài workspace vào Central Vault của người dùng:
   ```text
   ~/.slug/env_vault/<workspace_hash>/
   ├── meta.json                      # Lưu: workspace_path, timestamp, blake3 hash, size, version
   ├── env_20261016_205000_v1.bak     # Bản backup v1
   └── env_20261016_213000_v2.bak     # Bản backup v2 (nếu init lại)
   ```
3. Trong workspace: Tạo file mã hóa `.env.pqc` và xóa sạch `.env` cùng `.env.bak` khỏi workspace để AI không thể đọc trộm (trừ khi dùng cờ `slug env init --keep`).

#### B. Khôi Phục 1 Chạm (`slug env restore`) & Lịch Sử (`slug env history`)
* Khi developer cần khôi phục lại `.env` bản rõ trên đĩa:
  ```bash
  slug env restore
  ```
  Slug tự động lấy bản backup mới nhất từ Central Vault (hoặc giải mã trực tiếp từ `.env.pqc` nếu vault thất lạc) và dọn sạch `.env.pqc`.
* Để kiểm tra các phiên bản backup đã lưu:
  ```bash
  slug env history
  ```

#### C. Nghệ Thuật Dạy AI (`slug env prompt`)
Lệnh `slug env prompt` in ra chỉ dẫn chuẩn cho AI coding agents (đồng thời tự động tạo `.slug/ai-rule.md`):
```markdown
# SLUG ENVSHIELD AGENT DIRECTIVE
- In this repository, sensitive environment variables are sealed in `.env.pqc`.
- DO NOT attempt to create or read plaintext `.env` on disk.
- ALWAYS execute runtime commands (npm start, pytest, python, cargo, etc.) through Slug EnvShield:
    slug env run -- <command>
- Slug will decrypt secrets directly in process memory (RAM).
```
Nhờ chỉ dẫn này, AI hiểu cách dùng công cụ để chạy lệnh test/start (`slug env run -- pytest`) thay vì đọc file trên đĩa hoặc tạo `.env` rác.
