# BẢO VỆ DỮ LIỆU TRONG KỶ NGUYÊN AI: VỊ TRÍ THỰC TẾ CỦA AI TRONG SLUG

## 1. Định Vị Đúng: AI Nên Đứng Ở Đâu Trong Một Công Cụ Chia Sẻ Workspace?

Trong bối cảnh các cuộc thi công nghệ và sản phẩm bảo mật, việc lạm dụng AI hoặc "gắn nhãn AI lên mọi thứ" rất dễ tạo ra cảm giác an toàn giả (False Sense of Security). 

Slug tiếp cận AI theo một triết lý kỹ thuật thực dụng và có kiểm soát:

```text
+---------------------------------------------------------------------------------+
| QUY TẮC CỐT LÕI (DETERMINISTIC CORE) - LOGIC TOÁN HỌC & HỆ THỐNG XÁC ĐỊNH        |
| - Mật mã học: NIST FIPS 203/204 (ML-KEM-768, ML-DSA-65), AEAD XChaCha20-Poly1305|
| - Phân quyền: RBAC (r / w / rw), TTL tự hủy, TOTP Anti-Replay                   |
| - Phân loại Workspace: Đọc phân tầng file .gitignore                            |
| - Chính sách máy chủ: File cấu hình .slug/rules.conf                            |
+---------------------------------------------------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
| VAI TRÒ CỦA AI: TÍN HIỆU PHÂN TÍCH HỖ TRỢ (ADVISORY & CONTEXT-AWARE AUDIT)      |
| - Nhận diện bí mật ngữ nghĩa (Semantic Secret Detection) mà rule tĩnh bỏ sót    |
| - Quét Heuristic kết hợp phân tích độ hỗn loạn Shannon Entropy                   |
| - Gắn cờ cảnh báo (Flag/Quarantine) đưa vào bảng kiểm toán (.slug/index.db)      |
+---------------------------------------------------------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------+
| THỰC THI BẢO MẬT: DO POLICY CỦA HOST QUYẾT ĐỊNH (HOST POLICY ENFORCEMENT)       |
| - AI chỉ cung cấp tín hiệu phân tích, KHÔNG tự ý cấp quyền vượt qua rule chặn    |
| - Chủ máy (Host Admin) giữ quyền tối thượng để Whitelist hoặc cưỡng chế chặn   |
+---------------------------------------------------------------------------------+
```

---

## 2. Mô Hình 3 Tầng Phân Loại Bảo Vệ Dữ Liệu (3-Tier Protection Model)

Slug phân định rạch ròi giữa **Quy tắc lọc cấu trúc**, **Chính sách của chủ máy**, và **Kiểm toán bí mật bằng AI**:

| Tầng | Tên Cơ Chế | Nguồn Cấu Hình | Trạng Thái Hiển Thị (Status) | Ý Nghĩa Kỹ Thuật |
| :---: | :--- | :--- | :--- | :--- |
| **1** | **Workspace Filter** | `.gitignore` (phân tầng theo thư mục) | `Excluded (gitignore)` | Lọc bỏ các file rác phát sinh trong quá trình build (`node_modules/`, `target/`, `*.o`, `*.log`). Không phải cơ chế bảo mật mà là bộ lọc cấu trúc dự án. |
| **2** | **Host Sharing Policy** | `.slug/rules.conf` | `Blocked (policy: <lý do>)` | Chính sách kiểm soát do chủ máy định nghĩa (chặn theo đuôi `.pem`, `.key`, `.sqlite`, hoặc chặn cứng tên file `.env`). Có hiệu lực ưu tiên cao nhất. |
| **3** | **Secret Audit** | Stateful AI Secret Guard | `Quarantined (AI Secret Guard: <lý do>)` | Hệ thống AI phát hiện chuỗi khóa bí mật, token có entropy cao hoặc file môi trường. Tự động cách ly khỏi manifest và chặn tải về. |

---

## 3. Stateful AI Secret Guard: Kiến Trúc & Cơ Chế Hoạt Động

Hệ thống AI Guard của Slug (`src/ai/stateful_audit.hpp`, `src/ai/scanner.cpp`) hoạt động như một trạm kiểm soát dữ liệu tự động ngay tại tầng giao vận.

### 3.1. Hai Tầng Quét Thông Minh
1. **Quét Mẫu Ngữ Cảnh Nâng Cao (Context-Aware Heuristics):**
   * **Nhận diện chuyên sâu file môi trường:** Tự động phát hiện `.env`, `.env.local`, `.env.production` và các biến thể (loại trừ các file mẫu tài liệu như `.env.example`, `.env.sample`).
   * **Nhận diện Unquoted & Quoted Token:** Quét các dòng gán biến `KEY=VALUE` hoặc `KEY: VALUE` cho các từ khóa nhạy cảm (`api_key`, `secret`, `token`, `password`, `auth`) ngay cả khi không đặt trong dấu ngoặc kép.
   * **Mẫu định danh nhà cung cấp phổ biến:** OpenAI (`sk-proj-...`), Stripe (`sk_live_...`), GitHub (`ghp_...`), AWS (`AKIA...`), Private Key Headers (`-----BEGIN ... PRIVATE KEY-----`).
2. **Phân Tích Độ Hỗn Loạn Thông Tin (Shannon Entropy Analyzer):**
   * Với các chuỗi secret được sinh ngẫu nhiên (không có tiền tố cố định), AI Guard tính toán độ hỗn loạn Shannon:
     $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   * Bất kỳ giá trị nào có độ dài $\ge 20$ ký tự và entropy $H(X) \ge 4.0$ bits/byte sẽ bị nghi vấn là khóa mật mã sinh ngẫu nhiên và đưa vào diện cách ly.

### 3.2. Bộ Nhớ Đệm Trạng Thái BLAKE3 (`.slug/index.db`)
Để không làm chậm tiến trình làm việc khi dự án có hàng chục nghìn tệp:
* Mỗi file được định danh bằng mã băm nội dung BLAKE3 (32 bytes).
* Trạng thái quét (`CLEAN`, `AI_FLAGGED`, `USER_ALLOWED`) được lưu vào SQLite/B-Tree index.
* Khi file không đổi nội dung (khớp BLAKE3 hash), thời gian kiểm tra là **0 ms**, hoàn toàn không tốn CPU quét lại.
* Khi nội dung file thay đổi, hash thay đổi, hệ thống sẽ tự động kích hoạt quét lại.

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
