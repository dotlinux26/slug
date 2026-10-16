# THỰC TRẠNG VÀ BÀI TOÁN BÀN GIAO WORKSPACE TRONG PHÁT TRIỂN PHẦN MỀM

## 1. Đặt Vấn Đề Thực Tế

Trong quy trình phát triển phần mềm hiện đại, nhu cầu chia sẻ nhanh một không gian làm việc (workspace) giữa các lập trình viên hoặc giữa máy trạm cá nhân và máy chủ thử nghiệm diễn ra hàng ngày:
- Chuyển giao mã nguồn đang sửa dở (uncommitted hotfix, stash) cho đồng đội rà soát lỗi mà không muốn tạo commit rác lên Git repository.
- Bàn giao workspace cho cộng tác viên, tester, hoặc AI Coding Agent kèm các file build, artifact thử nghiệm nhưng **bắt buộc phải loại bỏ các file cấu hình bí mật (`.env`, private keys, database credentials)**.
- Người nhận chỉ cần lấy 1 hoặc 2 file mã nguồn cụ thể, hoặc một thư mục con (`src/`), nhưng các công cụ truyền thống buộc họ phải kéo cả thư mục hàng chục GB gồm cả `node_modules`, `build/`, `target/`.

Vấn đề cốt lõi: **"Làm sao để người nhận duyệt xem workspace từ xa, biết rõ dữ liệu nào được phép lấy, và chỉ truyền đúng thứ họ cần — trong khi người gửi vẫn kiểm soát tuyệt đối quyền truy cập và ngăn chặn rò rỉ dữ liệu nhạy cảm?"**

---

## 2. So Sánh Khách Quan Với Các Công Cụ Hiện Nay

Để thấy rõ đóng góp thực sự của Slug, ta cần đặt Slug cạnh 4 nhóm công cụ phổ biến mà kỹ sư đang sử dụng hàng ngày:

### 2.1. SFTP / SCP (SSH File Transfer Protocol)
* **Điểm mạnh:** Chuẩn mực công nghiệp lâu đời, truyền file an toàn qua kênh SSH, hỗ trợ duyệt thư mục và lấy từng file.
* **Điểm mù trong bài toán Workspace:**
  1. **"Ống nước vô tri" (Zero Context-Awareness):** SFTP không hiểu cấu trúc dự án. Nếu người gửi chia sẻ thư mục, SFTP sẵn sàng truyền thẳng các file nhạy cảm (`.env`, `id_rsa.pem`) và các thư mục rác (`.git`, `node_modules`, `build/`) mà không hề có bộ lọc workspace.
  2. **Gánh nặng hạ tầng và quản trị:** Đòi hỏi phải cấu hình máy chủ SSH (`sshd`), mở port, cấp tài khoản hệ điều hành (Linux user accounts) hoặc cấu hình SSH keys. Việc này tạo ra rủi ro cấp thừa quyền (Over-privileged access) và tài khoản mồ côi (Orphaned accounts) khi hết phiên làm việc tạm thời.

### 2.2. rsync (Remote Sync)
* **Điểm mạnh:** Thuật toán đồng bộ vi sai (delta transfer) kinh điển cực kỳ tối ưu về băng thông, hỗ trợ bộ lọc `--exclude`.
* **Điểm mù trong bài toán Workspace:**
  1. **Thiếu khả năng khám phá trực quan:** Người nhận không thể duyệt xem từ xa để biết host đang có những file gì, dung lượng bao nhiêu trước khi kéo, trừ khi chạy lệnh `rsync --dry-run` phức tạp.
  2. **Phụ thuộc vào SSH:** Không có cơ chế xác thực tự hủy ngắn hạn (One-Time TOTP), không có phân quyền RBAC (`r`/`w`/`rw`) ở tầng ứng dụng, không có giao diện Web đi kèm cho người dùng không thạo CLI.

### 2.3. Git Remote (GitHub, GitLab)
* **Điểm mạnh:** Quản lý lịch sử phiên bản, phân nhánh (branching), cộng tác code review chuẩn mực.
* **Điểm mù trong bài toán Workspace:**
  1. **Ô nhiễm lịch sử Commit (History Pollution):** Chia sẻ vài file nháp buộc phải tạo commit tạm (`git commit -m "wip"`), đẩy lên nhánh riêng trên remote, sau đó phải rebase hoặc xóa nhánh.
  2. **Nguy cơ rò rỉ khóa bí mật vĩnh viễn:** Nếu vô tình `git add .` lọt file `.env`, khóa API sẽ nằm vĩnh viễn trong Git tree objects.
  3. **Bất lực với file không thuộc Git:** Git không giải quyết được việc chia sẻ file build nhị phân lớn, log sự cố hoặc workspace đang sửa dở chưa commit.

### 2.4. Cloud Drive (Google Drive, Dropbox, WeTransfer)
* **Mất chủ quyền dữ liệu (Data Sovereignty):** Mã nguồn độc quyền bị tải lên hạ tầng bên thứ ba, vi phạm tiêu chuẩn tuân thủ (SOC2, ISO 27001).
* **Không hỗ trợ quy trình developer:** Không hiểu `.gitignore`, không có đồng bộ vi sai, người nhận phải tải cả file ZIP nặng nề và giải nén thủ công.

---

## 3. Ma Trận So Sánh Tính Năng

| Tiêu chí | SFTP / SCP | rsync | Git Remote | Cloud Drive | **Slug (v1.0.0-rc2)** |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Kích thước & Triển khai** | Cần `sshd` OS service | Cần SSH/rsyncd | Cần Git Server | Trình duyệt / App nặng | **10 MB Portable Binary duy nhất** |
| **Hiểu cấu trúc dự án (.gitignore)** | Không | Phải cấu hình flag thủ công | Có | Không | **Tự động đọc phân tầng theo cấu trúc** |
| **Chính sách bảo vệ bí mật (DLP)** | Không | Không | Không (cần hook bên ngoài) | Không | **Stateful AI Secret Guard + Policy** |
| **Duyệt xem trước khi tải (ls)** | Có (lệnh ftp) | Không trực quan | Không | Có | **CLI Table chuẩn mực + Web Explorer** |
| **Kế hoạch truyền trước khi tải (Preview)** | Không | Dry-run text | Không | Không | **Transfer Plan Preview (hỏi [y/N])** |
| **Đồng bộ vi sai theo khối (Delta Sync)** | Không | Có (rolling checksum) | Có (packfiles) | Tùy app | **Có (Content-Addressable 64 KiB BLAKE3)** |
| **Tải duy nhất 1 file (`get`)** | Có (`get`) | Phải chỉ định path dài | Không (kéo cả repo) | Có | **Có (`slug get <remote_path>`)** |
| **Xác thực ngắn hạn tự hủy** | Không | Không | Token cá nhân | Link công khai | **TOTP 3-Role tự hủy sau 1 lần bind** |
| **Mật mã an toàn lượng tử** | Cần cấu hình OpenSSH mới | Phụ thuộc SSH | Phụ thuộc TLS | TLS truyền thống | **NIST FIPS 203/204 (ML-KEM, ML-DSA) + AEAD** |

---

## 4. Định Vị Sản Phẩm: "Git-aware Secure Workspace Sharing"

Slug không cố gắng thay thế Git (không làm quản lý version), cũng không tự định vị là "công cụ truyền file thay thế mọi thứ".

**Định vị của Slug là:**
> **Công cụ chia sẻ workspace qua mạng, hiểu cấu trúc dự án, hỗ trợ lựa chọn dữ liệu cần lấy và đồng bộ phần thay đổi, với quyền truy cập và chính sách bảo vệ file được tích hợp sẵn.**
> 
> *Slogan: Share only what you need. Sync only what changed.*

### 3 Nguyên Tắc Cốt Lõi:
1. **Kết nối không đồng nghĩa với tải dữ liệu (`connect != pull`):** Kết nối chỉ để xác thực danh tính và lưu session context. Người dùng phải có quyền duyệt (`slug ls`), xem trước kế hoạch truyền (Transfer Plan Preview), rồi mới quyết định lấy 1 file (`slug get`) hay đồng bộ một thư mục (`slug pull`).
2. **Chính sách của Host luôn tối thượng:** File bị chặn bởi `.gitignore`, `.slug/rules.conf`, hoặc bị AI Guard cách ly sẽ tuyệt đối không thể bị client tải về.
3. **Nhẹ nhàng, độc lập, đa nền tảng:** Toàn bộ engine gói gọn trong 1 file thực thi ~10 MB, không phụ thuộc thư viện ngoài, tương thích chuẩn hóa đường dẫn giữa Linux và Windows.
