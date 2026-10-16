# 03. Ứng dụng Trí tuệ Nhân tạo (AI) trong Slug

> **Mục tiêu tiêu chí AI trong SICT Innovation Challenge (25 điểm):**  
> AI không phải là "từ khóa quảng cáo" mà phải mang lại giá trị thực tế, giải quyết được bài toán con người khó tự xử lý thủ công, đồng thời có cơ chế kiểm soát chi phí và ranh giới an toàn rõ ràng.

---

## 1. Hai vai trò của AI trong Slug: Đối tượng cần bảo vệ & Trợ lý phân tích

Trong môi trường phát triển phần mềm có AI hiện nay, Slug nhìn nhận AI ở cả hai khía cạnh:

```text
+-----------------------------------------------------------------------------------+
| HAI MẶT CỦA AI TRONG HỆ SINH THÁI SLUG                                            |
+-----------------------------------------------------------------------------------+

     [MẶT 1: AI LÀ ĐỐI TƯỢNG CẦN BẢO VỆ]         [MẶT 2: AI LÀ TRỢ LÝ PHÂN TÍCH]
     (AI Coding Assistants: Cursor, Copilot)      (Stateful AI Secret Guard)
     
     - AI tự động đọc code và index context.      - AI đọc ngữ cảnh code để giải thích rủi ro.
     - Dễ làm lộ secret bản rõ vào LLM Cloud.     - Phân biệt giữa mock token và real secret.
     
     --> Slug bảo vệ bằng cách:                   --> Slug sử dụng AI để:
         + Xóa .env bản rõ khỏi ổ đĩa.                + Hỗ trợ sinh viên hiểu vì sao file bị gắn cờ.
         + Nạp secret trực tiếp vào RAM tiến trình.   + Đề xuất cách khắc phục trước khi share/push.
         + Cung cấp Agent Directive (.slug/ai-rule).  + Lưu bộ nhớ đệm (BLAKE3) để tiết kiệm chi phí.
```

---

## 2. AI Guard: Phân tích ngữ nghĩa và Giải thích rủi ro cho sinh viên

### 2.1. Giới hạn của các công cụ quét regex truyền thống
Các bộ lọc regex tĩnh (`gitleaks`, regex script) thường gặp 2 nhược điểm lớn đối với sinh viên:
1. **Quá máy móc (Nhiều cảnh báo giả - False Positive):** Khi sinh viên viết các bộ test unit (ví dụ `test_auth.py`), họ thường gán chuỗi giả như `api_key = "sk-fake1234567890abcdef"`. Regex tĩnh sẽ báo lỗi đỏ lòm và chặn lại dù chuỗi này vô hại.
2. **Khó hiểu với sinh viên mới:** Regex chỉ báo dòng `Line 45: Matched rule 'openai-key'`. Sinh viên không hiểu vì sao dòng code này nguy hiểm, có cần sửa không và sửa như thế nào.

### 2.2. Cách tiếp cận của AI Guard trong Slug
Slug kết hợp **3 tầng phát hiện**:
- **Tầng 1 - Heuristic & Entropy (Cục bộ, siêu tốc, miễn phí):** Quét nhanh các mẫu từ khóa nhạy cảm và tính toán độ hỗn loạn Shannon Entropy ($H(X) \ge 4.0$).
- **Tầng 2 - AI Semantic Analysis (Trợ lý thông minh):** Với các đoạn code bị nghi vấn, Slug trích xuất một đoạn ngữ cảnh ngắn (snippet) và gửi tới mô hình AI (hỗ trợ mô hình cục bộ như Ollama/Local AI hoặc API đám mây) để đánh giá ngữ nghĩa:
  - *"Đoạn mã này nằm trong thư mục nào? (src/ hay tests/)? Tên biến là gì? Đây là dữ liệu giả lập hay cấu hình kết nối thực tế?"*
- **Tầng 3 - Giải thích thân thiện bằng ngôn ngữ tự nhiên:** AI trả về kết quả bằng tiếng Việt rõ ràng:
  > *"File `config/database.js` dòng 14 chứa chuỗi kết nối PostgreSQL có mật khẩu thật `postgres:admin123@db.prod...`. Nguy cơ: Kẻ xấu có thể truy cập cơ sở dữ liệu nếu file này bị đẩy lên GitHub. Khuyến nghị: Hãy chuyển mật khẩu vào biến môi trường `DATABASE_URL` và quản lý bằng `slug env init`."*

---

## 3. Bộ nhớ đệm kiểm toán (Stateful Audit Index) — Tiết kiệm chi phí và thời gian

Một trong những rào cản lớn nhất khi ứng dụng AI vào công cụ lập trình là: **gọi AI liên tục sẽ làm chậm máy và tốn chi phí token.**

Slug giải quyết bài toán này bằng **Stateful Audit Index** (`.slug/index.db`):

```text
File mã nguồn  --->  Tính băm BLAKE3  --->  Tra cứu .slug/index.db
                                                    |
             +--------------------------------------+--------------------------------------+
             |                                                                             |
      [Hash trùng khớp]                                                             [Hash khác / Mới]
      File chưa hề bị sửa đổi                                                       File vừa mới được chỉnh sửa
             |                                                                             |
      Lấy kết quả cũ từ Cache                                                       Chuyển trạng thái sang STALE
      (Không tốn 1 ms, không tốn token AI!)                                         Ép kiểm tra lại trước khi chia sẻ!
```

### Lợi ích thực tế:
- **Khởi động tức thì:** Khi sinh viên chạy lệnh `slug add .` lần thứ hai, Slug kiểm tra nhanh mã băm của toàn bộ file trong chưa đầy 50 mili-giây. Các file đã kiểm tra sạch sẽ không bao giờ bị quét lại bằng AI.
- **Phát hiện sửa đổi tức thời (Anti-TOCTOU):** Nếu sinh viên vừa sửa một file mã nguồn và dán thêm khóa bí mật vào, mã băm BLAKE3 thay đổi ngay lập tức $\rightarrow$ Slug nhận diện trạng thái `STALE` và tự động kích hoạt kiểm tra lại, ngăn chặn việc lén chèn secret vào phút chót.

---

## 4. Dạy AI Agent dùng công cụ an toàn (Agent Directive)

Thay vì cố gắng "chiến đấu" hoặc chặn hoàn toàn trợ lý AI lập trình, Slug chủ động **hướng dẫn AI làm việc đúng cách**:

Khi chạy `slug env init`, Slug tự động tạo ra tệp chỉ thị:
- Đường dẫn: `.slug/ai-rule.md` (đồng thời xuất ra khi gõ `slug env prompt`).

### Nội dung chỉ thị gửi AI Coding Agent:
```markdown
# SLUG WORKSPACE SECURITY DIRECTIVE
- In this repository, sensitive environment variables are securely sealed in `.env.pqc`.
- DO NOT attempt to create or read plaintext `.env` on disk.
- ALWAYS execute runtime commands (tests, builds, server start) through Slug:
    slug env run -- <command>
- Slug will automatically inject decrypted secrets directly into RAM for the child process.
```

Nhờ chỉ thị này:
1. Khi sinh viên bảo AI: *"Hãy chạy test kiểm tra hàm đăng nhập"*, AI sẽ tự động gõ `slug env run -- npm test` thay vì cố tình tìm file `.env` trên ổ cứng.
2. Trợ lý AI trở thành một tác nhân hợp tác (cooperative agent), tuân thủ đúng quy trình bảo mật mà không gây cản trở trải nghiệm lập trình.

---

## 5. Ranh giới an toàn: AI chỉ đóng vai trò Cố vấn (Advisory Only)

Để đảm bảo tính tin cậy tuyệt đối và khả năng kiểm thử của hệ thống:
- **AI không có quyền tự ý mở khóa các file vi phạm luật cứng:** Nếu một file nằm trong danh sách cấm tuyệt đối của chủ máy (ví dụ `deny *.pem` trong `.slug/rules.conf`) hoặc các file nhạy cảm của hệ thống (`.slug/`, `.git/`), AI tuyệt đối không thể can thiệp để mở khóa file đó.
- **Quyền quyết định thuộc về con người (Human-in-the-Loop):** Nếu AI gắn cờ một file là nghi vấn nhưng sinh viên khẳng định đó là dữ liệu an toàn, sinh viên có thể dùng lệnh:
  ```bash
  slug audit allow <tên_file> --reason "Dữ liệu mock test đã được kiểm tra"
  ```
  Hành động này được ghi vết minh bạch vào `audit.log`, gắn chặt với mã băm BLAKE3 của đúng nội dung đó. Nếu sau này nội dung file bị thay đổi, quyền ngoại lệ sẽ tự động bị hủy bỏ.
