# 02. Giải pháp và Quy trình 3 bước của Slug

> **Định vị sản phẩm:** Công cụ kiểm tra và bảo vệ mã nguồn trước khi công khai hoặc chia sẻ.  
> **Hình thức sản phẩm:** Ứng dụng dòng lệnh (CLI Tool) đa nền tảng viết bằng C++20, đóng gói 1 file thực thi duy nhất (~8MB, zero-dependency) tích hợp Web Explorer cục bộ.

---

## 1. Triết lý thiết kế: Tối giản bên ngoài, Chắc chắn bên trong

Một sản phẩm dành cho sinh viên và kỹ sư phần mềm phải dễ sử dụng như các công cụ quen thuộc hằng ngày (`git`, `npm`, `python`), không bắt người dùng phải cấu hình máy chủ phức tạp hay nhớ hàng chục tham số rườm rà.

Slug chuẩn hóa toàn bộ quy trình bảo vệ và chia sẻ workspace thành **Quy trình 3 bước trực quan**:

```text
+-----------------------------------------------------------------------------------+
| QUY TRÌNH 3 BƯỚC BẢO VỆ WORKSPACE VỚI SLUG                                        |
+-----------------------------------------------------------------------------------+

  [BƯỚC 1: KIỂM TRA MÃ NGUỒN]
       slug audit scan .
       ├── Quét heuristic và Shannon Entropy tìm API keys, tokens, credentials
       └── AI Guard đọc ngữ cảnh, giải thích mức độ nguy hiểm của từng file
                                     |
                                     v
  [BƯỚC 2: CẤT BÍ MẬT & CHẠY ỨNG DỤNG AN TOÀN]
       slug env init  --->  slug env run -- <lệnh test / start>
       ├── Cất file .env vào Central Vault (~/.slug/env_vault/)
       ├── Khóa lại thành file mã hóa .env.pqc trong repo
       └── Nạp biến môi trường thẳng vào RAM tiến trình khi chạy, không để plaintext trên đĩa
                                     |
                                     v
  [BƯỚC 3: CHIA SẺ P2P KHÔNG LO THỪA RÁC / LỘ BÍ MẬT]
       slug add .  --->  slug get <link_kèm_otp>
       ├── Tự động lọc bỏ rác build (node_modules/, target/, build/) theo .gitignore
       ├── Ngăn chặn tuyệt đối các file nhạy cảm đã bị cảnh báo ở Bước 1
       └── Kênh truyền P2P mã hóa, xác thực bằng mã OTP 8 số dùng một lần
```

---

## 2. Chi tiết Bước 1: Kiểm tra mã nguồn trước khi công khai (`slug audit`)

Trước khi sinh viên đẩy code lên GitHub công khai (để nộp bài hoặc dự thi) hoặc gửi cho đồng đội:

- **Lệnh thực thi:**
  ```bash
  slug audit scan .
  ```
- **Hành vi hệ thống:**
  1. **Sàng lọc tự động:** Quét toàn bộ cây thư mục, tìm kiếm các mẫu định danh secret phổ biến (AWS Key, Google Gemini/OpenAI API Key, Stripe Token, Private Key, Database connection string).
  2. **Phân tích Entropy:** Tính toán độ hỗn loạn ký tự (Shannon Entropy) để nhận diện các khóa mật mã ngẫu nhiên dù không khớp regex cố định.
  3. **Trợ lý AI phân tích ngữ cảnh (`-a / --ai`):** Nếu có kết nối AI, Slug gửi đoạn trích mã nghi vấn để AI giải thích: *"File này chứa Google API Key thật hay chỉ là chuỗi mock data trong file test unit?"*.
  4. **Báo cáo rõ ràng:** Xuất bảng trạng thái minh bạch: file nào sạch (`CLEAN`), file nào nghi vấn bị cách ly (`QUARANTINED`), file nào bị chặn bởi chính sách (`RULE_BLOCKED`).

---

## 3. Chi tiết Bước 2: Bảo vệ biến môi trường và Chạy ứng dụng (`slug env`)

Để vừa có thể code và chạy test mượt mà với AI, vừa không để file `.env` bản rõ trên đĩa cứng:

### 3.1. Đóng băng và cất giữ bí mật vào Central Vault
```bash
slug env init
```
- Slug tính toán mã băm định danh duy nhất của workspace.
- Tự động sao lưu bản `.env` ra **Kho lưu trữ trung tâm ngoài workspace của người dùng** (`~/.slug/env_vault/<workspace_hash>/`).
- Mã hóa `.env` trong repo thành `.env.pqc` (sử dụng mật mã hậu lượng tử ML-KEM-768 kết hợp AES-256-GCM) và **xóa bỏ hoàn toàn file `.env` bản rõ khỏi thư mục dự án**.
- Tự động sinh file chỉ dẫn AI (`.slug/ai-rule.md`) để dặn trợ lý AI không cố đọc hay tạo file `.env` rác.

### 3.2. Chạy ứng dụng và chạy test trực tiếp từ RAM
```bash
# Ví dụ chạy test hoặc chạy server phát triển
slug env run -- npm test
slug env run -- pytest
slug env run -- python main.py
```
- Slug đọc file `.env.pqc`, giải mã trực tiếp trong bộ nhớ RAM của Slug.
- Nạp toàn bộ các cặp `KEY=VALUE` vào khối môi trường của tiến trình con thông qua hàm hệ điều hành (`execve` trên Linux, `CreateProcessW` trên Windows).
- **Kết quả:** Ứng dụng con nhận đầy đủ 100% biến môi trường và chạy bình thường, trong khi trên ổ đĩa hoàn toàn không hề có file `.env` bản rõ nào để AI hay người khác đọc lén.

### 3.3. Khôi phục một chạm khi cần cấu hình lại
```bash
slug env restore          # Khôi phục lại bản .env mới nhất từ Central Vault
slug env history          # Xem lịch sử các phiên bản backup trong Vault
slug env prompt           # Xuất nội dung chỉ thị để paste vào prompt của AI
```

---

## 4. Chi tiết Bước 3: Chia sẻ Workspace an toàn qua mạng (`slug add` & `slug get`)

Khi cần gửi nhanh thư mục dự án cho bạn cùng nhóm trong mạng LAN trường học, phòng lab hoặc ký túc xá:

### 4.1. Phía máy gửi (Host):
```bash
slug add .
```
- Slug tự động quét và áp dụng 3 bộ lọc:
  - **Lọc rác:** Đọc file `.gitignore` để tự động loại bỏ các thư mục khổng lồ như `node_modules/`, `build/`, `dist/`.
  - **Lọc secret:** Chặn tuyệt đối các file cấu hình nhạy cảm (`.env`, `.key`, `.pem`, file bị gắn cờ kiểm toán).
- Hệ thống in ra màn hình một liên kết kèm **mã OTP 8 chữ số** dùng một lần (hết hạn sau phiên kết nối đầu tiên).
- Hỗ trợ các chế độ lọc linh hoạt khi người dùng yêu cầu:
  - `--filter-mode protected` (Mặc định): Bật đầy đủ bảo vệ gitignore và kiểm duyệt secret.
  - `--include-ignored`: Cho phép chia sẻ cả file build/ignored nhưng vẫn giữ nguyên rào chắn chặn secret.
  - `--no-filter`: Chia sẻ nguyên trạng cho máy tin cậy (nhưng vẫn bảo vệ an toàn các file khóa nội bộ `.slug/`).

### 4.2. Phía máy nhận (Client):
Chỉ cần 1 lệnh duy nhất:
```bash
slug get <link_host_cung_cap>
# Hoặc mở trực tiếp trên trình duyệt Web Explorer: http://127.0.0.1:8080/drop
```
- Máy nhận kéo toàn bộ mã nguồn sạch về máy trong vài giây.
- Không bị nghẽn mạng vì không phải tải hàng trăm MB file build rác.
- Người nhận an tâm tuyệt đối rằng trong mã nguồn không hề bị lẫn khóa bí mật của người gửi.

---

## 5. Bảng so sánh trải nghiệm thực tế giữa các cách làm

| Tác vụ thông thường | Cách làm truyền thống của sinh viên | Quy trình tối ưu với **Slug** |
| :--- | :--- | :--- |
| **Chạy ứng dụng với API key** | Để nguyên file `.env` bản rõ trong thư mục, AI lập chỉ mục đọc được toàn bộ. | Chạy qua `slug env run -- <lệnh>`, nạp biến vào RAM, không có file `.env` trên đĩa. |
| **Kiểm tra trước khi push GitHub** | Mắt đọc lướt qua từng file hoặc dùng lệnh `git status` đơn giản (dễ bỏ sót). | Chạy `slug audit scan .`, AI giải thích rõ ràng từng file rủi ro. |
| **Gửi dự án cho bạn qua mạng LAN** | Gõ `python -m http.server 8000` (bản rõ, lộ sạch `.env`, gửi cả `node_modules` nặng máy). | Gõ `slug add .`, P2P mã hóa, xác thực OTP 8 số, tự lọc rác và chặn hoàn toàn secret. |
| **Khôi phục khi cần sửa cấu hình** | Phải tự tìm lại file backup hoặc xin lại key từ đầu nếu lỡ tay xóa. | Gõ `slug env restore`, khôi phục bản sao từ Central Vault trong 1 giây. |
