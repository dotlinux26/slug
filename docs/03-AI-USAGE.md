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
| **2** | **Host Sharing Policy** | `.slug/rules.conf` | `Blocked (policy: <lý do>)` | Chính sách kiểm soát do chủ máy định nghĩa (chặn theo đuôi `.pem`, `.key`, `.sqlite`, hoặc chặn cứng tên file `.env`). Có hiệu lực tuyệt đối. |
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

## 5. PQC EnvShield: Cách Ly Biến Môi Trường Trong Bộ Nhớ RAM

Bên cạnh việc quét file trên đĩa cứng, Slug cung cấp module **EnvShield** (`slug env`) nhằm giải quyết rủi ro các AI agent đọc trộm file `.env` khi chạy tiến trình:
* File cấu hình được mã hóa tĩnh thành `.env.pqc`.
* Khi lập trình viên chạy ứng dụng (`slug env run -- npm start`), Slug giải mã khóa trong RAM và inject trực tiếp vào môi trường tiến trình con qua biến môi trường OS mà **không bao giờ ghi file `.env` bản rõ xuống đĩa cứng**.
