# Slug EnvShield - Automated Showcase Demo

Thư mục này chứa các script tái tạo môi trường thử nghiệm (Showcase Playground) cho tính năng **Slug EnvShield (Tab 4)**. 

Script được thiết kế để:
1. **Tạo ra một dự án mẫu hoàn chỉnh** (`demo_env_workspace`) ngay tại vị trí bạn chạy script.
2. **Sinh ngẫu nhiên 100% các biến môi trường nhạy cảm** (Database Password, Stripe API Key, AI Token, JWT Secret) bằng GUID và Random Bytes tại runtime.
   > **Lưu ý bảo mật:** Script hoàn toàn **không chứa static secret / hardcoded credential** để đảm bảo không kích hoạt cảnh báo của GitHub Secret Scanning / Push Protection.
3. **Cung cấp ứng dụng mẫu Python Zero-Dependency** (`app.py`), chỉ sử dụng thư viện chuẩn của hệ điều hành (`os.environ`), không cần cài thêm bất kỳ thư viện ngoài nào (`pip install`).

---

## 1. Cách Chạy Thử Nhanh

### Trên Windows (PowerShell)
Mở PowerShell tại thư mục dự án và chạy:
```powershell
# Chạy script khởi tạo môi trường demo
.\docs\demo\setup_demo.ps1

# Chuyển vào thư mục vừa tạo
cd demo_env_workspace

# Chạy kịch bản kiểm thử tự động 5 bước
.\run_demo.ps1
```

### Trên Linux / macOS (Bash)
Mở terminal và chạy:
```bash
# Cấp quyền thực thi và khởi tạo môi trường demo
chmod +x ./docs/demo/setup_demo.sh
./docs/demo/setup_demo.sh

# Chuyển vào thư mục vừa tạo
cd demo_env_workspace

# Chạy kịch bản kiểm thử tự động 5 bước
./run_demo.sh
```

---

## 2. Kịch Bản Kiểm Thử Chi Tiết (5 Bước)

```text
                           KỊCH BẢN MÔ PHỎNG (LƯU ĐỒ HOẠT ĐỘNG)
  
   [ .env Thô Chứa API KEY ] 
              │
              ▼  (Chạy: slug env init)
   ┌───────────────────────────────────────────────────────────────┐
   │ 1. .env plaintext trên đĩa bị XÓA BỎ                          │
   │ 2. Sinh .env.pqc (Mã hóa lượng tử ML-KEM-1024 + XChaCha20)    │
   │ 3. Khóa giải mã cất tại Central Vault (~/.slug/env_vault/)    │
   │ 4. Sinh file chỉ thị cho AI: .slug/ai-rule.md                 │
   └───────────────────────────────────────────────────────────────┘
              │
              ▼  (AI đọc directive từ .slug/ai-rule.md)
   [ AI Agent thực thi lệnh ] ──> slug env run -- python app.py
                                          │
                                          ▼ (Giải mã trên RAM & Inject vào Process)
                                  App chạy thành công!
                                  (Ổ đĩa vẫn sạch 100%, 0 byte plaintext)
```

### Bước 1: Trạng thái ban đầu (Chưa bảo vệ)
Khi tệp `.env` còn ở dạng plaintext trên ổ đĩa, chạy:
```bash
python app.py
```
Ứng dụng đọc được secret từ file `.env` (hoặc biến môi trường nạp sẵn). Nhưng rủi ro: file `.env` này rất dễ bị commit nhầm lên Git hoặc bị AI Agent đọc trộm context.

### Bước 2: Niêm phong hậu lượng tử với Slug EnvShield
Thực hiện niêm phong bảo vệ dự án:
```bash
slug env init
```
**Điều gì xảy ra:**
- File `.env` thô trên đĩa **biến mất hoàn toàn** (được xóa an toàn).
- Xuất hiện file `.env.pqc` – file nhị phân được mã hóa bằng chuẩn **ML-KEM-1024 + XChaCha20-Poly1305**.
- Khóa bí mật và bản backup được cất ngoài thư mục làm việc tại Central Vault (`~/.slug/env_vault/`).
- Tự động sinh file chỉ thị cho AI Agent: `.slug/ai-rule.md`.

### Bước 3: Mô phỏng trường hợp không có bảo vệ
Chạy lại ứng dụng như thông thường:
```bash
python app.py
```
**Kết quả:** Ứng dụng báo lỗi crash ngay lập tức vì không tìm thấy biến môi trường trên RAM hay trên ổ đĩa. Ổ đĩa hoàn toàn sạch 0 byte plaintext!

### Bước 4: Thực thi an toàn qua RAM Injection
Chạy ứng dụng qua cơ chế nạp bộ nhớ tạm của Slug:
```bash
slug env run -- python app.py
```
**Kết quả:** 
Slug giải mã `.env.pqc` trực tiếp trên RAM, bơm biến môi trường vào Process Table của `python app.py` và khởi chạy thành công. Ổ đĩa vẫn sạch 100%, không sinh ra bất kỳ file tạm plaintext nào.

### Bước 5: Xem lịch sử và Khôi phục (1-Touch Restore)
Xem lịch sử các phiên bản niêm phong:
```bash
slug env history
```
Khi cần hoàn trả lại `.env` plaintext (ví dụ khi đóng dự án hoặc bàn giao):
```bash
slug env restore
```
File `.env` ban đầu được khôi phục nguyên vẹn và file `.env.pqc` được tự động dọn sạch.
