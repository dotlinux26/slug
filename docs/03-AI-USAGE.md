# BẢO VỆ DỮ LIỆU TRONG KỶ NGUYÊN AI: STATEFUL AI GUARD VÀ PQC ENVSHIELD

## 1. Mối Đe Dọa Mới Từ Các Trợ Lý Lập Trình Tự Động (AI Coding Agents)

Trong môi trường phát triển hiện đại, việc sử dụng các trợ lý lập trình như Cursor, GitHub Copilot Workspace, Claude Dev hay Antigravity đã trở thành tiêu chuẩn. Tuy nhiên, kiến trúc hoạt động của các công cụ này đặt ra những thách thức bảo mật nghiêm trọng:

1. **Quét Chỉ Mục Tự Động (Background Workspace Indexing):**
   - Để xây dựng ngữ cảnh (context window) cho các mô hình ngôn ngữ lớn (LLM), các extension AI tự động đọc và lập chỉ mục toàn bộ các tệp tin trong thư mục dự án.
   - Các tệp cấu hình chứa thông tin nhạy cảm như `.env`, `.aws/credentials`, chứng chỉ `server.key`, hoặc token database vô tình bị đưa vào bộ nhớ đệm của AI.
2. **Nguy Cơ Rò Rỉ Ra Máy Chủ Đám Mây Bên Thứ Ba:**
   - Dữ liệu ngữ cảnh sau đó được gửi lên các API máy chủ AI từ xa (OpenAI, Anthropic, Google, v.v.).
   - Một khi secret bị đẩy vào prompt hoặc telemetry log của nhà cung cấp, nguy cơ lộ thông tin nội bộ hoặc vi phạm chính sách tuân thủ dữ liệu (SOC2/GDPR) là rất lớn.
3. **Hiểm Họa Khi Đồng Bộ File:**
   - Khi chia sẻ nhanh workspace qua mạng, nếu không có cơ chế lọc tự động, các file secret này sẽ lập tức được gửi sang máy đối tác hoặc máy ảo thử nghiệm.

Để triệt tiêu hoàn toàn rủi ro này, Slug tích hợp hai tầng phòng vệ độc lập: **Stateful AI Secret Guard** và **PQC EnvShield**.

---

## 2. Stateful AI Secret Guard (Bộ Kiểm Duyệt Bí Mật Trạng Thái)

Hệ thống kiểm duyệt của Slug (`src/ai/stateful_audit.hpp`, `src/ai/stateful_audit.cpp`) hoạt động như một bức tường lửa nội tại, quét và cô lập các dữ liệu nhạy cảm trước khi chúng có cơ hội xuất hiện trong manifest hoặc đi qua mạng.

### 2.1. Hai Tầng Quét Thông Minh
1. **Bộ Phân Tích Mẫu Nhận Diện (Heuristic Pattern Matcher):**
   - Nhận dạng chính xác cấu trúc định danh của các nhà cung cấp dịch vụ phổ biến:
     - OpenAI API Keys (`sk-proj-...`, `sk-live-...`)
     - Anthropic API Keys (`sk-ant-...`)
     - AWS Access Key & Secret Key (`AKIA...`)
     - GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`)
     - Stripe Secret Keys (`sk_live_...`, `rk_live_...`)
     - Slack Bot Tokens (`xoxb-...`, `xoxp-...`)
     - Chuỗi kết nối cơ sở dữ liệu (`postgres://...`, `mongodb+srv://...`)
     - Khóa riêng mật mã (`-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`)
     - Chuỗi mã thông báo JWT (`eyJ...`)
2. **Máy Phân Tích Độ Hỗn Loạn Thông Tin (Shannon Entropy Analyzer):**
   - Với các khóa bí mật không có tiền tố cố định (ví dụ: chuỗi secret sinh ngẫu nhiên từ CSPRNG), hệ thống tính toán độ hỗn loạn Shannon (Entropy) trên từng dòng dữ liệu:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   - Các chuỗi ký tự có độ dài $\ge 20$ ký tự và entropy vượt ngưỡng $4.5$ bits/byte sẽ được đánh dấu nghi vấn là khóa mật mã.

### 2.2. Cơ Chế Bộ Nhớ Đệm Trạng Thái BLAKE3 (`.slug/index.db`)
Một trong những điểm yếu của các công cụ quét mã truyền thống là làm chậm tiến trình làm việc khi dự án có hàng chục nghìn tệp. Slug giải quyết bài toán này bằng cơ chế Content-Addressable Index:

```text
File Hệ Thống ---> Băm Nội Dung BLAKE3 (32 bytes)
                        |
                        v
                 Tra Cứu Trong .slug/index.db
                   ├── Khớp Hash Đã Quét Sạch: Trả kết quả SẠCH ngay lập tức (0ms Overhead)
                   └── Hash Mới / File Đã Đổi: Thực hiện quét sâu -> Cập nhật index.db
```

- **Hiệu năng vượt trội:** Quá trình quét chỉ diễn ra với các file mới hoặc vừa được chỉnh sửa. Các lần đồng bộ tiếp theo đạt tốc độ tức thì (0ms CPU overhead).
- **Tính tự động:** Bất kỳ file nào bị gắn cờ `FLAGGED` sẽ tự động bị loại khỏi danh sách manifest đồng bộ và bị chặn trên giao diện Web Dropbox.

---

## 3. Quản Trị Kiểm Toán Qua Dòng Lệnh (`slug audit`)

Chủ máy có toàn quyền kiểm tra, chấp thuận hoặc quét lại các tệp tin trong workspace:

### 3.1. Liệt Kê Các Tệp Bị Chặn
```bash
slug audit list -p 9443
```
*Kết quả hiển thị trên terminal:*
```text
FLAGGED FILES AUDIT REPORT (WORKSPACE: /home/user/project):

[STATUS]    [FILE PATH]                [REASON / PATTERN]
---------------------------------------------------------------------------------
BLOCKED     config/jwt_secret.key      Shannon Entropy Exceeded (4.82 bits/byte)
BLOCKED     .env.production            Matched Pattern: AWS Secret Key / Stripe
BLOCKED     keys/id_ed25519            Matched Pattern: OpenSSH Private Key

Total Flagged Files: 3 (Auto-quarantined from network transfer and web view)
```

### 3.2. Bỏ Chặn File Báo Nhầm (Whitelist False Positives)
Khi một file chứa dữ liệu ngẫu nhiên nhưng không phải là secret thực tế:
```bash
slug audit allow config/jwt_secret.key -p 9443
```
Hệ thống sẽ cập nhật cờ whitelist cho hash nội dung tương ứng trong `.slug/index.db`. File này sẽ được phép đồng bộ bình thường.

### 3.3. Buộc Quét Lại Toàn Bộ Workspace
```bash
slug audit recheck -p 9443
```
Xóa cache tạm thời và thực hiện kiểm tra sâu lại toàn bộ cây thư mục.

---

## 4. PQC EnvShield: Cách Ly Biến Môi Trường Trong Bộ Nhớ RAM

Các tệp cấu hình `.env` là nơi tập trung nhiều bí mật nhất của lập trình viên, nhưng đồng thời là mục tiêu hàng đầu bị các extension AI đọc trộm. Lệnh **`slug env`** cung cấp giải pháp triệt để: **Mã hóa file trên đĩa cứng và chỉ giải mã trong bộ nhớ RAM khi chạy tiến trình**.

```text
ĐĨA CỨNG (DISK STORAGE)                     BỘ NHỚ (RAM) - KHÔNG ĐỌC ĐƯỢC TỪ NGOÀI
  .env.pqc (Mã hóa PurePQC)                  Giải mã AES/XChaCha20 chỉ tồn tại trong RAM
  [Plaintext .env BỊ XÓA HOÀN TOÀN]                       │
                                                          v
                                            execve() nạp trực tiếp vào ENV của app
                                                          │
                                                          v
                                            Tiến Trình Ứng Dụng Chạy Bình Thường
```

### 4.1. Khởi Tạo Mã Hóa (`slug env init`)
```bash
slug env init
```
1. Đọc nội dung tệp `.env` hiện tại.
2. Mã hóa toàn bộ dữ liệu bằng bộ Suite 3 PurePQC (sử dụng cặp khóa ML-KEM-768 và phái sinh khóa XChaCha20-Poly1305).
3. Ghi kết quả mã hóa vào tệp nhị phân an toàn `.env.pqc`.
4. **Ghi đè và xóa hoàn toàn tệp `.env` bản rõ khỏi đĩa cứng.**

*Kết quả:* Các extension AI hoặc kẻ xâm nhập đọc thư mục dự án chỉ thấy tệp nhị phân `.env.pqc`, không thể đọc được nội dung bản rõ.

### 4.2. Khởi Chạy Ứng Dụng An Toàn (`slug env run`)
Khi lập trình viên hoặc kịch bản kiểm thử cần chạy ứng dụng:
```bash
slug env run -- python3 server.py
# hoặc
slug env run -- npm start
```
1. Slug đọc `.env.pqc` và giải mã dữ liệu **duy nhất trong không gian bộ nhớ RAM của tiến trình cha**.
2. Phân tích các cặp khóa-giá trị (`KEY=VALUE`).
3. Khởi tạo mảng môi trường của tiến trình và thực hiện gọi hàm hệ thống `execve()` để chuyển quyền thực thi cho ứng dụng con (`python3`, `node`, `go`).
4. **Không có bất kỳ tệp tạm hay bản rõ nào được ghi xuống đĩa cứng.** Ứng dụng con nhận đầy đủ các biến môi trường và hoạt động bình thường, trong khi các công cụ AI chạy nền trên máy hoàn toàn mù thông tin về các secret này.
