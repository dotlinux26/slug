# BÁO CÁO TOÀN DIỆN VỀ THỰC TRẠNG KIẾN TRÚC, ĐỐI SÁNH HIỆU NĂNG VÀ BẢN THIẾT KẾ ADAPTIVE DATA PLANE STREAMING ĐẠT CHUẨN 100 GB CHO SLUG

**Người thực hiện:** Antigravity AI  
**Thời gian:** 18/10/2026  
**Vị trí tài liệu:** `slug-docs/BÁO_CÁO_KIẾN_TRÚC_VÀ_GIẢI_PHÁP_HIỆU_NĂNG.md`  
**Trạng thái mã nguồn:** ĐÃ TIẾP THU TOÀN BỘ ĐỐI SÁNH VÀ CHỈ ĐẠO CHUYÊN SÂU; NGHIÊM TÚC DỪNG MỌI THAO TÁC SỬA CODE ĐỂ BÁO CÁO ĐỐI CHIẾU VÀ HỎI Ý KIẾN ANH.

---

## 1. Bản Chất Kiến Trúc Cốt Lõi Của Slug (Truth of Architecture)

Slug **hoàn toàn KHÔNG PHẢI** là một Web Server từ xa truyền thống (như Apache/Nginx/NodeJS) mở port ra Internet để trình duyệt truy cập thẳng:

1. **Slug là MỘT BINARY CLI DUY NHẤT (All-in-One)**:
   * Khi người dùng gõ `slug` (không tham số), gõ `slug web`, gõ `slug portal`, hoặc click shortcut desktop `.lnk`, ứng dụng đều thực thi đúng một entrypoint: `cmd_portal()` trong `src/main.cpp`.
2. **Mô Hình Localhost Client Proxy (Kiến trúc A trong `docs/04-ARCHITECTURE.md`)**:
   * Khi mở giao diện Web, tiến trình `slug` khởi tạo một web server nội bộ (loopback) chỉ lắng nghe tại `127.0.0.1:8080` trên **chính máy của người dùng (Client)**.
   * Trình duyệt Web (Chrome, Edge, Firefox) chỉ đóng vai trò là **tầng hiển thị đồ họa (Visual GUI)** cho CLI `slug` cục bộ.
3. **Kênh Truyền Dẫn Vật Lý (Wire Transport) 100% PQC AEAD**:
   * Mọi dữ liệu bay trên dây mạng LAN/Wi-Fi giữa Client và Station Host đều là các gói tin nhị phân mã hóa hậu lượng tử (ML-KEM-768, BLAKE3, XChaCha20-Poly1305 phân hướng muối).
   * **Không có bất kỳ gói tin HTTP rõ nào bay trên mạng.**
4. **Hệ Quả Kiến Trúc**:
   * Khi anh ngồi trên máy Linux chạy `slug web`, tiến trình `slug` đang chạy trực tiếp trên máy Linux của anh và **hoàn toàn có quyền truy cập ổ đĩa `/home/nguyenduccanh/...`**. Mọi thao tác kéo/đẩy file đều do tiến trình `slug` cục bộ này thực hiện.

---

## 2. Đối Sánh Kiến Trúc: Vì Sao Python HTTP Server Chạm Được 80–100 MB/s Còn Slug Bị Nghẽn?

Điểm khác biệt cốt lõi là **Python HTTP Server truyền file như một dòng dữ liệu liên tục (Continuous Stream)**; trong khi đó, Slug hiện tại đang biến việc truyền file thành **hàng nghìn lượt hỏi – đáp ở tầng ứng dụng (Application-Layer Ping-Pong)**. Không phải Python nhanh vì nó có nhiều luồng truyền song song.

```text
PYTHON HTTP SERVER (CONTINUOUS TCP STREAM):
[Client: GET /file.bin] ----------------------------------------> [Server: Mở file]
                                                                        |
                                                     shutil.copyfileobj(src, sock)
                                                                        |
[Client: Đọc buffer] <====== DÒNG DỮ LIỆU LIÊN TỤC (KERNEL TCP) <========+
[Ghi đĩa ngay]       (TCP tự quản lý Window, ACK, Retransmit)
(Chỉ tốn đúng 1 RTT duy nhất cho toàn bộ file 100 GB!)

-----------------------------------------------------------------------------------------

SLUG HIỆN TẠI (APPLICATION-LAYER STOP-AND-WAIT):
[Client: get_chunk(0)] ---------> [Server: Đọc đĩa, Encode Base64, Bọc JSON]
[Client: Decode B64, ghi đĩa] <--- [Gửi frame chunk 0] (64 KiB)
[Client: get_chunk(1)] ---------> [Server: Đọc đĩa, Encode Base64, Bọc JSON]
[Client: Decode B64, ghi đĩa] <--- [Gửi frame chunk 1] (64 KiB)
... (Lặp lại 1.640.000 lần cho file 100 GB -> Chịu 1.640.000 lần RTT tầng ứng dụng!)
```

### 2.1. Python HTTP Server thực sự làm gì?
* Theo mã nguồn của CPython, `SimpleHTTPRequestHandler.copyfile()` gọi `shutil.copyfileobj(source, outputfile)` để sao chép nội dung file sang socket phản hồi.
* Việc sao chép sử dụng buffer đệm hữu hạn (mặc định 64KB - 1MB), **tránh tải cả file vào RAM**.
* **Luồng truyền cơ bản:**
  1. Mở file trên ổ đĩa.
  2. Đọc buffer $\rightarrow$ Ghi liên tục vào socket TCP.
  3. Tầng Kernel TCP bên dưới tự động quản lý cửa sổ truyền dẫn (Sliding Window), TCP ACKs và cơ chế truyền lại (Retransmission).
  4. Client đọc socket và ghi thẳng xuống file.
* **Mấu chốt:** Sau khi yêu cầu tải ban đầu được thụ lý, Server không hề phải chờ Client gửi `get_chunk(1)`, `get_chunk(2)`, `get_chunk(3)` rồi mới gửi tiếp. Toàn bộ dữ liệu được đẩy liên tục trong cùng một dòng TCP duy nhất.
* Lớp `ThreadingHTTPServer` chỉ có nhiệm vụ xử lý nhiều kết nối client khác nhau đồng thời, **hoàn toàn không chia nhỏ một file thành nhiều luồng TCP để tải song song**.

### 2.2. Tại sao Slug hiện tại chậm hơn?
* `SlugClient::fetch_chunk()` gửi `get_chunk`, chặn chờ phản hồi qua mạng rồi mới trả dữ liệu cho vòng lặp xin chunk kế tiếp.
* Mỗi khối chỉ 64 KiB bị ép chuyển đổi qua Base64 và bọc trong cấu trúc JSON text.
* `SlugClient::pull()` giữ buffer của cả file trong RAM (`file_buf`) và chỉ xử lý băm hash sau khi đã ghép toàn bộ file.
* `SlugClient::push()` đọc toàn bộ file vào RAM rồi mới đóng gói thành request.
* **Hậu quả:** Slug vừa phải chịu chi phí trễ RTT ở tầng ứng dụng (Application RTT), vừa tiêu tốn chu kỳ CPU và dung lượng RAM khổng lồ cho việc đóng gói JSON/Base64. Nếu chỉ tăng số thread một cách mù quáng mà giữ nguyên giao thức này thì không thể giải quyết được gốc rễ vấn đề.

---

## 3. Bốn Nút Thắt Thực Tế Trong Mã Nguồn Hiện Tại (Code Bottlenecks)

### 3.1. Stop-and-Wait và Base64 trên từng chunk
* **Trong code:** Trong `src/net/client.cpp`, `fetch_chunk()` gửi request `get_chunk`, chờ response qua `recv_json()`, rồi giải mã `data_b64`. Mặc định mỗi chunk chỉ 64 KiB.
* **Hậu quả hiệu năng:**
  * Với RTT 2 ms (LAN), giới hạn lý thuyết của kiểu tuần tự này chỉ đạt tối đa $\approx 32.8\text{ MB/s}$ trước khi tính overhead. Trên Wi-Fi (RTT 5ms), tốc độ tụt xuống $\approx 12.8\text{ MB/s}$.
  * Đây là nguyên nhân trực tiếp của cảm giác truyền dữ liệu **"rất là theo nhịp :))"**.
  * Base64 làm phình to dữ liệu thêm **33%** và đốt CPU vô ích ở cả 2 đầu cho hàng triệu lần encode/decode.

### 3.2. Truyền file lớn phụ thuộc vào RAM (Nguy cơ Out-Of-Memory trên file 100 GB)
* **Trong code:**
  * `SlugClient::pull()` tạo `std::vector<uint8_t> file_buf` để giữ toàn bộ file trong RAM, sau đó ghép chunk và tính hash BLAKE3.
  * `src/sync/delta.cpp` đọc toàn bộ file local vào bộ nhớ (`platform::PathUtils::read_binary_file`) để so sánh hash.
  * `SlugClient::get_file()` giữ toàn bộ file trong vector.
  * `SlugClient::push()` đọc cả file vào RAM rồi Base64 hóa vào một chuỗi JSON khổng lồ.
* **Hậu quả:** Với file **100 GB**, kiến trúc hiện tại đòi hỏi lượng RAM xấp xỉ kích thước file (100 GB RAM!), dẫn đến **sập tiến trình ngay lập tức vì Out-Of-Memory (OOM-Killed)**.

### 3.3. Giới hạn 4GB & OOM của ZIP 32-bit và XHR Blob
* **Trong code:** Trong `src/net/web_server.cpp`, endpoint `/download-folder` gom toàn bộ archive vào `zip_bytes` trong RAM. Code ZIP hiện tại dùng các trường kích thước 32-bit (trần 4 GiB, chưa có ZIP64).
* **Phía Client:** Đổi link thành XHR với `responseType = 'blob'` không giải quyết được vấn đề vì trình duyệt phải giữ toàn bộ Blob trong RAM của tab browser. Trình duyệt sẽ crash ngay nếu giữ một Blob nặng hàng chục GB. Không thể coi ZIP/Blob là giải pháp cho file lớn.

### 3.4. Bùng nổ metadata Manifest
* Manifest lưu danh sách chunk 64 KiB kèm mã băm cho từng chunk.
* Riêng một file 100 GiB tương đương khoảng **1,64 triệu chunk**.
* Việc nạp và serialize 1.64 triệu hash chunk trong một file JSON manifest sẽ ngốn hàng trăm MB RAM và tiêu tốn CPU lớn khi parse.

---

## 4. Có Nên Bắt Buộc Dùng Nhiều Luồng Song Song (Multi-Stream) Không?

**Câu trả lời:** Slug **phải hỗ trợ** kiến trúc Multi-Stream / Adaptive Transfer, nhưng **tuyệt đối không được mặc định rằng càng nhiều luồng càng nhanh**.

### 4.1. Bài học từ `iperf3` và giới hạn của Multi-Stream
* Các công cụ benchmark chuẩn mực như `iperf3` hỗ trợ đo 1 luồng hoặc nhiều luồng song song (`-P <parallel>`). Tài liệu chính thức của `iperf3` chỉ ra rằng: Multi-stream chỉ có tác dụng tăng thông lượng trong trường hợp một luồng TCP đơn bị giới hạn bởi CPU (CPU-bound) hoặc trên đường truyền có độ trễ lớn (High Bandwidth-Delay Product).
* Nếu mạng LAN có độ trễ cực thấp (RTT < 1ms) và CPU đủ mạnh để mã hóa AEAD, **một luồng streaming đơn tối ưu đã có thể đạt 90 – 115 MB/s và vét cạn băng thông Gigabit LAN**.
* Ngược lại, nếu ép nhiều luồng song song mà không kiểm soát, các luồng sẽ tranh chấp tài nguyên (I/O đĩa đọc/ghi bị nhảy đầu đọc, CPU context switch, nghẽn contention), làm giảm hiệu năng thực tế.

### 4.2. Bảng So Sánh Hai Chế Độ Truyền Tải

| Chế độ | Cách hoạt động | Ưu điểm | Mục tiêu áp dụng |
| :--- | :--- | :--- | :--- |
| **Streaming Đơn (Single Stream)** | 1 kết nối TCP chuyên dụng, stream nhị phân liên tục với buffer hữu hạn (Ring Buffer $\le 4\text{ MB}$). | Cực ít overhead, ghi đĩa tuần tự (Sequential I/O), zero CPU contention. | Đạt gần giới hạn mạng 1GbE (90–115 MB/s) một cách ổn định nhất. |
| **Adaptive Multi-Stream** | Nhiều kết nối TCP đồng thời ($2 - 4$ streams), chia file thành các dải offset không chồng lấn. | Tận dụng đa nhân CPU cho mã hóa AEAD trên mạng 10GbE hoặc khi 1 luồng chưa bão hòa. | Kích hoạt khi benchmark phát hiện 1 luồng chưa chạm trần băng thông và hệ thống còn dư CPU/Disk. |

### 4.3. Ràng Buộc An Toàn Mật Mã Tuyệt Đối Khi Dùng Multi-Stream
* **Quy tắc bất di bất dịch:** Trong mật mã dòng ChaCha20-Poly1305, việc tái sử dụng Nonce (Nonce Reuse) là lỗ hổng chí mạng làm lộ bản rõ.
* Do đó, **tuyệt đối không cho nhiều thread dùng chung một socket hoặc dùng chung trạng thái mã hóa (Session Keys / Sequence Number)**.
* **Bắt buộc:** Mỗi luồng truyền song song phải là một kết nối socket TCP độc lập, có Session Ticket xác thực riêng, phái sinh bộ khóa AEAD riêng biệt và Sequence Number độc lập hoàn toàn.
* Các luồng ghi dữ liệu vào các dải offset không chồng lấn trên file tạm (`.slug_partial`), sau đó ráp nối và kiểm tra mã băm BLAKE3 toàn thể trước khi hoàn tất.

---

## 5. Đánh Giá Mục Tiêu Tốc Độ (90 – 115 MB/s Có Thực Tế Không?)

### 5.1. Giới hạn vật lý của Gigabit Ethernet (1GbE)
* Đường truyền 1 Gbps = $1.000.000.000\text{ bits/s} = 125.000.000\text{ bytes/s} \approx \mathbf{119.2\text{ MiB/s}}$ (lý thuyết tuyệt đối).
* Sau khi trừ chi phí đóng gói Ethernet Header, IP Header, TCP Header (3–5%) và AEAD Authentication Tag (16 bytes/frame), **thông lượng payload thực tế tối đa của 1GbE nằm trong khoảng 90 – 115 MB/s**.
* **130 MB/s qua 1GbE:** Là **không khả thi bền vững** vì vượt trần vật lý của đường truyền 1 Gbps.
* **90 – 115 MB/s qua 1GbE:** Là **hoàn toàn khả thi** nếu chuyển sang streaming nhị phân liên tục và bỏ Base64/JSON.
* **Đối với 10GbE / Local NVMe:** Kiến trúc streaming mới sẽ dễ dàng bứt phá lên **200 – 500+ MB/s**.

### 5.2. Thời gian truyền tải thực tế của file 100 GB
* Một file 100 GB ($100 \times 10^9\text{ bytes}$) truyền ở 100 MB/s mất:
  $$\frac{100.000\text{ MB}}{100\text{ MB/s}} = 1.000\text{ giây} \approx \mathbf{16.6\text{ phút}}$$
* Mọi phép đo phải được tính bằng **thông lượng payload thực tế ghi xuống đĩa**, không phải tốc độ gửi dữ liệu mà UI tự suy diễn.

---

## 6. Kiến Trúc 6 Trụ Cột Đã Chốt Cho Slug (Enterprise Blueprint)

```text
========================================================================================
[TRÌNH DUYỆT (CHROME/EDGE)]                    [SLUG ENGINE CỤC BỘ (127.0.0.1:8080)]
========================================================================================

  [Nút: Download Folder (ZIP)]
            |
            |-- (1) downloadFolderZipWithProgress(dir) qua XHR Streaming (Có trần an toàn)
            v
     [POPOUP TIẾN TRÌNH ZIP] (Hiển thị tốc độ MB/s, %; Cảnh báo chuyển Native Sync nếu > 4GB)

----------------------------------------------------------------------------------------

  [Nút: Bắt Đầu Đồng Bộ Về Máy]
            |
            |-- (2) POST /api/transfer/start {dest, dir, mode: "adaptive"}
            v
     [POLLING MONITOR (200ms)] <------------ GET /api/transfer/progress
     * Tốc độ tức thời có làm mượt (MB/s)     (Đọc atomic state, ZERO LOCK MUTEX)
     * Tốc độ trung bình (Avg MB/s)
     * [CACHE HIT]: Số tệp & dung lượng bỏ qua nhờ BLAKE3 (0 byte over wire!)
     * Số luồng hoạt động (Active Streams: 1 -> N)
     * Terminal log cuộn trực tiếp; Hỗ trợ nút [HỦY] an toàn

----------------------------------------------------------------------------------------

[SLUG BACKEND]: TÁCH BIỆT CONTROL PLANE VÀ DATA PLANE
  ├── Control Plane : g_portal.client (Xác thực, duyệt cây thư mục, ping - KHÔNG BỊ KHÓA)
  └── Bulk Data Plane: Dedicated Transfer Client (Stream nhị phân liên tục, 0 Base64)
        ├── Bounded-Memory Direct I/O : Đọc/ghi Ring Buffer <= 16 MB ra đĩa (.slug_partial)
        ├── BLAKE3 Incremental        : blake3_hasher_update theo luồng
        └── Adaptive Controller       : Bắt đầu 1 stream -> Tăng N streams nếu cần
========================================================================================
```

### Chi Tiết 6 Trụ Cột:

1. **Trụ Cột 1: Tách Biệt Control Plane & Data Plane**:
   * Control Plane: Quản lý xác thực, manifest, quyền truy cập và điều phối transfer.
   * Data Plane: Phiên socket chuyên dụng truyền dữ liệu nhị phân liên tục qua AEAD, **hoàn toàn loại bỏ Base64 và JSON khỏi payload file**.
2. **Trụ Cột 2: Bounded-Memory Direct I/O Streaming**:
   * Đọc/ghi theo buffer có giới hạn (Ring Buffer 1–4 MB), **hỗ trợ file 100 GB mà lượng RAM sử dụng luôn là hằng số ($\le 16–32\text{ MB}$)**.
   * Dữ liệu ghi trực tiếp xuống file tạm (`.slug_partial`) bằng offset xác định.
   * Tính mã băm BLAKE3 liên tục theo luồng (`blake3_hasher_update`), xác minh toàn vẹn trước khi đổi tên nguyên tử thành file chính thức.
3. **Trụ Cột 3: Scalable Manifest & Persistent Delta Cache**:
   * Tránh serialize hàng triệu chunk hash trong 1 JSON khổng lồ; áp dụng chunking theo kích cỡ file và cache hash bền vững có cơ chế vô hiệu hóa an toàn dựa trên `(mtime, size)`.
4. **Trụ Cột 4: Managed Multi-Stream Có Phân Lập An Toàn**:
   * Hỗ trợ chia các vùng dữ liệu theo offset không trùng lặp khi cần tải đa luồng.
   * Mỗi kết nối có socket riêng, Session Ticket riêng, bộ khóa AEAD và Sequence Number độc lập hoàn toàn.
5. **Trụ Cột 5: Adaptive Controller Dựa Trên Đo Kiểm**:
   * Khởi đầu bằng streaming đơn tối ưu.
   * Bộ điều khiển tự động đo thông lượng thực tế: nếu CPU/Disk còn dư và mạng chưa bão hòa, tự động mở thêm luồng; dừng tăng ngay khi hệ thống đạt đỉnh để tránh contention.
6. **Trụ Cột 6: Realtime Progress Dashboard Đo Từ Dữ Liệu Thật**:
   * Đo từ byte payload thực tế ghi xuống đĩa, hiển thị tốc độ tức thời có làm mượt, tốc độ trung bình, dung lượng đã truyền / tổng dung lượng, số tệp Cache Hit.
   * Luồng ZIP có giới hạn an toàn rõ ràng, cảnh báo người dùng chuyển sang cơ chế Native Sync khi kích thước vượt ngưỡng.

---

## 7. Quyết Định Kỹ Thuật Cuối Cùng

> **Không bắt Slug luôn chạy nhiều luồng; bắt Slug có streaming tối ưu và có khả năng tăng lên nhiều luồng theo kết quả benchmark thực tế.**
> 
> Đây là hướng đi vừa có cơ sở kỹ thuật vững chắc để chạm ngưỡng tốc độ tối đa của mạng LAN (90 – 115 MB/s trên 1GbE và 200–500+ MB/s trên 10GbE), vừa giữ cho hệ thống tinh gọn, ổn định, tránh lãng phí tài nguyên và loại bỏ 100% nguy cơ tràn RAM khi xử lý file 100 GB.

---

## 8. Lộ Trình Triển Khai Tuần Tự (Phase-by-Phase Implementation)

| Giai đoạn | Nội dung kỹ thuật chi tiết |
| :--- | :--- |
| **Pha 1: Bounded Streaming & Binary Wire** | Xóa bỏ `std::vector` giữ toàn bộ file; triển khai đọc/ghi buffer 4MB trực tiếp xuống đĩa kèm BLAKE3 incremental; xây dựng giao thức stream nhị phân nhúng trong AEAD frame (bỏ Base64/JSON cho file content). |
| **Pha 2: Dedicated Transfer & Zero-Lock** | Xây dựng `TransferJobManager` có vòng đời (Start/Cancel/Resume); mở kết nối riêng bằng Session Ticket; giải phóng hoàn toàn khóa `g_portal.mtx` để Web Portal luôn mượt 100%. |
| **Pha 3: Adaptive Multi-Stream Engine** | Cài đặt cơ chế chia dải offset không chồng lấn; phân lập khóa AEAD độc lập cho từng luồng; tích hợp bộ điều khiển Adaptive dựa trên benchmark. |
| **Pha 4: Web UI Dashboard & Progress Thực** | Nâng cấp giao diện `/drop` với bảng hiển thị tốc độ thực (MB/s có làm mượt), % tiến trình, thông số Cache Hit; sửa lỗi đường dẫn và loại bỏ việc tự ý redirect sang tải ZIP. |
| **Pha 5: Benchmark & Kiểm Thử Toàn Diện** | Đo kiểm thực tế với file nhị phân lớn và thư mục phức tạp; kiểm chứng mức tiêu thụ RAM tĩnh, tải CPU và throughput ghi đĩa thực tế. |

---

## 9. Phụ Lục Tham Chiếu: Toàn Bộ Kiến Trúc Luồng (Execution Flow) Thật Sự Của Hệ Thống Hiện Tại

Dưới đây là sơ đồ và phân tích chi tiết từng bước của **toàn bộ 7 luồng thực thi (Flows)** đang chạy trên mã nguồn `main` hiện tại (`src/net/client.cpp`, `src/net/control_server.cpp`, `src/net/web_server.cpp`, `src/sync/delta.cpp`, `src/main.cpp`). Phần này dùng làm **mốc tham chiếu chuẩn (Baseline Reference)** để đối chiếu khi nâng cấp Data Plane.

---

### Sơ Đồ Tổng Thể Luồng Thực Thi Hiện Tại (Baseline Architecture Flow)

```text
+---------------------------------------------------------------------------------------------------+
| KHÁCH HÀNG / CLIENT (LINUX / WINDOWS)                             MÁY CHỦ TRẠM / STATION HOST     |
+---------------------------------------------------------------------------------------------------+
| [Trình Duyệt Browser]                                                                             |
|         |                                                                                         |
|         | HTTP nội bộ (127.0.0.1:8080)                                                            |
|         v                                                                                         |
| [cmd_portal() in src/main.cpp]                                                                    |
|    |                                                                                              |
|    +-- FLOW 1: PQC Handshake & KDF (ML-KEM-768 / Dilithium) ===> ControlServer (PQC Listener)     |
|    |                                                                                              |
|    +-- FLOW 2: Authentication & Ticket (TOTP / Account)    ===> Xác thực & Cấp Web Ticket         |
|    |                                                                                              |
|    +-- FLOW 3: Manifest & Delta Plan (BLAKE3 64KB Chunks)  ===> Quét VFS, Hash 64KB Chunks        |
|    |                                                                                              |
|    +-- FLOW 4: Kéo Tệp (SlugClient::pull)                  ===> Vòng lặp get_chunk(i)             |
|    |           * STOP-AND-WAIT 64KB                             * Đọc VFS, Base64 encode          |
|    |           * std::vector<uint8_t> file_buf (RAM!)           * JSON packet qua AEAD Frame      |
|    |                                                                                              |
|    +-- FLOW 5: Đẩy Tệp (SlugClient::push)                  ===> Nhận JSON Base64 file             |
|    |           * Đọc cả file vào RAM, Base64 encode JSON        * Ghi VFS qua AI Guard            |
|    |                                                                                              |
|    +-- FLOW 6: Web Portal Tunneling (g_portal.mtx)         ===> Tunnel raw HTTP sang WebServer    |
|    |           * KHÓA TOÀN BỘ PORTAL KHI ĐANG PULL/PUSH!        * Trả về HTML/CSS Explorer        |
|    |                                                                                              |
|    +-- FLOW 7: Tải Thư Mục ZIP (/download-folder)          ===> Nén zip_bytes trong RAM          |
|                * Link <a href>, Không có thanh tốc độ/ tiến trình  * Trần 32-bit (<= 4GB)         |
+---------------------------------------------------------------------------------------------------+
```

---

### Chi Tiết Từng Luồng Thực Thi Hiện Tại:

#### 1. FLOW 1: Kết Nối & Bắt Tay Mật Mã Hậu Lượng Tử (PQC Handshake Flow)
* **Tệp mã nguồn:** [`src/net/client.cpp:L81-145`](file:///d:/slugdoc/src/net/client.cpp#L81-L145) và [`src/net/control_server.cpp:L313-347`](file:///d:/slugdoc/src/net/control_server.cpp#L313-L347).
* **Trình tự thực thi:**
  1. `SlugClient::connect(host, port)`: Mở socket TCP, khởi tạo `tx_seq_ = 1`, `is_encrypted_ = false`.
  2. Client sinh ngẫu nhiên 32 bytes `client_random`, gửi packet nhị phân 4-byte độ dài:
     `{"type": "client_hello", "version": 1, "client_random": "<hex>"}`.
  3. `ControlServer::handle_client()`: Nhận `client_hello`, sinh 32 bytes `server_random`, gửi lại `server_hello` gồm:
     * `suite_id`: Mức mật mã (1, 2, hoặc 3).
     * `server_kem_pub`: Khóa công khai KEM (ML-KEM-768 trong Suite 3, X25519 trong Suite 1/2).
     * `server_sig_pub`: Khóa công khai ký số (ML-DSA-65 trong Suite 3, Ed25519 trong Suite 1/2).
     * `server_sig`: Chữ ký số ký trên `server_kem_pub` để chống tấn công Man-In-The-Middle (MITM).
  4. Client gọi `suite_->verify(...)` kiểm tra chữ ký số. Nếu hợp lệ, gọi `suite_->encapsulate(server_kem_pub)` để sinh ra `shared_secret` (32 bytes) và `ciphertext`.
  5. Client gửi packet: `{"type": "kem_exchange", "ciphertext": "<hex>"}`.
  6. Server gọi `suite_->decapsulate(ciphertext, server_kem_priv)` để khôi phục `shared_secret`.
  7. **Phái sinh khóa phân hướng (`src/net/aead_frame.hpp:L35-48`):**
     Cả hai đầu Client và Server độc lập thực thi hàm BLAKE3-KDF:
     $$\text{SessionKey} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_AEAD_SESSION_KEY_V1"})$$
     $$\text{C2S\_Salt} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_C2S_NONCE_SALT_V1"})[0..15]$$
     $$\text{S2C\_Salt} = \text{BLAKE3-KDF}(\text{SharedSecret}, \text{"SLUG_S2C_NONCE_SALT_V1"})[0..15]$$
  8. Thiết lập cờ `is_encrypted_ = true`. Từ thời điểm này, **100% gói tin qua socket đều đóng khung nhị phân AEAD**:
     `[4 bytes Payload Length] + [8 bytes Sequence Number] + [XChaCha20 Ciphertext] + [16 bytes Poly1305 Tag]`.

---

#### 2. FLOW 2: Xác Thực Quyền Hạn & Cấp Phiên (Authentication & Session Ticket Flow)
* **Tệp mã nguồn:** [`src/net/client.cpp:L147-285`](file:///d:/slugdoc/src/net/client.cpp#L147-L285) và [`src/net/control_server.cpp:L348-473`](file:///d:/slugdoc/src/net/control_server.cpp#L348-L473).
* **Trình tự thực thi:**
  * **Chế độ TOTP:** Client gửi `{"type": "auth_totp", "code": "12345678"}`. Server gọi `totp_manager_.verify_and_burn_role(code)`. Nếu đúng, token bị hủy (burn) ngay lập tức để chống Replay.
  * **Chế độ Account:** Client gửi `{"type": "auth_user", "username": u, "password": p, "role": r}`. Server gọi `acl_manager_.authenticate(u, p, role)`.
  * **Chế độ Ticket (Chứng chỉ tái kết nối):** Client gửi `{"type": "auth_ticket", "ticket": "<hex>"}`. Server kiểm tra danh sách `sessions_` trong RAM.
* **Kết quả phản hồi:** Server sinh `session_id`, gán quyền `granted_role` (`READ_ONLY`, `WRITE_ONLY`, `READ_WRITE`), sinh `web_ticket` (chuỗi 24 bytes ngẫu nhiên), trả về cho Client. Client lưu `session_ticket_`, `session_id_`, `role_` để dùng cho mọi thao tác kế tiếp.

---

#### 3. FLOW 3: Lấy Manifest & Tính Toán Vi Sai (Manifest & Delta Plan Flow)
* **Tệp mã nguồn:** [`src/net/client.cpp:L334-350`](file:///d:/slugdoc/src/net/client.cpp#L334-L350), [`src/net/control_server.cpp:L474-489`](file:///d:/slugdoc/src/net/control_server.cpp#L474-L489), và [`src/sync/delta.cpp:L12-158`](file:///d:/slugdoc/src/sync/delta.cpp#L12-L158).
* **Trình tự thực thi:**
  1. Client gửi frame AEAD: `{"type": "get_manifest"}`.
  2. Server gọi `control_server_.get_or_build_manifest_json()`:
     * Quét toàn bộ thư mục `workspace_root_`.
     * Áp dụng luật lọc `.gitignore`, `.slug/rules.conf` qua `PolicyEngine`.
     * Quét bí mật AI qua `AiScanner`.
     * Chia mỗi file hợp lệ thành các khối cố định 64 KiB (`sync::Chunker::kDefaultChunkSize`).
     * Tính mã băm BLAKE3 cho từng chunk và mã băm cho toàn bộ file.
     * Đóng gói toàn bộ cây thư mục thành JSON chứa mảng `files` và `skipped`.
  3. Client nhận JSON, chuyển đổi thành `sync::WorkspaceManifest`.
  4. Client thực thi `sync::DeltaCalculator::compute_plan(manifest, local_target_dir, options)`:
     * Duyệt từng `rem_file` trong manifest.
     * Ghép đường dẫn cục bộ: `local_file = local_target_dir / rem_file.relative_path`.
     * **Nếu file chưa có ở local:** Đánh dấu `is_new = true`, đưa toàn bộ chỉ số `needed_chunk_indices = [0, 1, 2, ...]`.
     * **Nếu file đã có ở local:**
       * Đọc toàn bộ file local vào RAM (`PathUtils::read_binary_file`).
       * Tính băm BLAKE3 toàn file.
       * Nếu hash trùng khớp 100%: Đánh dấu `is_unchanged = true`, cộng dồn `bytes_saved += rem_file.size` (**CACHE HIT - Bỏ qua, 0 byte gửi qua mạng**).
       * Nếu hash lệch: Chia nhỏ file local thành các chunk 64KB, đưa mã băm vào `std::unordered_set<std::string> local_hashes`. So sánh từng chunk của remote: chunk nào có trong `local_hashes` thì bỏ qua, chunk nào chưa có thì thêm vào `needed_chunk_indices`.

---

#### 4. FLOW 4: Luồng Kéo Tệp Đang Hoạt Động (Current `SlugClient::pull` Flow - Nút thắt Stop-and-Wait)
* **Tệp mã nguồn:** [`src/net/client.cpp:L375-482`](file:///d:/slugdoc/src/net/client.cpp#L375-L482) và [`src/net/control_server.cpp:L491-568`](file:///d:/slugdoc/src/net/control_server.cpp#L491-L568).
* **Trình tự chi tiết:**
  ```cpp
  for (const auto& delta : plan.file_deltas) {
      if (delta.is_unchanged) continue; // Bỏ qua file đã khớp BLAKE3

      // VẤN ĐỀ 1: Cấp phát vector giữ TOÀN BỘ file trong RAM!
      std::vector<uint8_t> file_buf;
      if (file_buf.size() < delta.total_size) {
          file_buf.resize(delta.total_size); // File 100GB -> Tốn 100GB RAM -> SẬP OOM!
      }

      // VẤN ĐỀ 2: Vòng lặp Stop-and-Wait tuần tự từng khối 64KB
      for (uint32_t chunk_idx : delta.needed_chunk_indices) {
          // BƯỚC A: Client tạo JSON request
          json req;
          req["type"] = "get_chunk";
          req["path"] = delta.relative_path;
          req["chunk_index"] = chunk_idx;
          send_json(req); // Gửi 1 frame AEAD

          // BƯỚC B: Client CHẶN ĐỨNG CHỜ ĐỢI (Blocking Wait)
          auto resp_opt = recv_json(10000); 

          // BƯỚC C: Phía Server (control_server.cpp:L491-568)
          // - Kiểm tra cache 8 file gần nhất (chunk_file_cache_)
          // - Tính offset = chunk_idx * 65536
          // - Cắt mảng byte 64KB
          // - VẤN ĐỀ 3: Chuyển 64KB binary thành chuỗi Base64 (+33% dung lượng)
          // - resp["data_b64"] = core::Utils::to_base64(chunk_bytes);
          // - Mã hóa AEAD frame gửi ngược về Client

          // BƯỚC D: Client nhận frame, giải mã AEAD, parse JSON
          std::string b64 = resp["data_b64"];
          auto chunk_data = core::Utils::from_base64(b64); // Tốn CPU giải mã Base64

          // BƯỚC E: Copy chunk vào buffer RAM
          uint64_t offset = chunk_idx * 65536;
          std::memcpy(file_buf.data() + offset, chunk_data.data(), chunk_data.size());

          // Sau khi hoàn thành chunk_idx này MỚI TIẾP TỤC gửi xin chunk kế tiếp!
      }

      // BƯỚC F: Băm lại toàn bộ file_buf trong RAM để đối chiếu
      std::string computed_hash = crypto::Blake3::hash_hex(file_buf);
      
      // BƯỚC G: Ghi toàn bộ buffer RAM xuống đĩa nguyên tử
      platform::PathUtils::write_binary_file_atomic(dest, file_buf);
  }
  ```

---

#### 5. FLOW 5: Luồng Đẩy Tệp Đang Hoạt Động (Current `SlugClient::push` Flow)
* **Tệp mã nguồn:** [`src/net/client.cpp:L581-643`](file:///d:/slugdoc/src/net/client.cpp#L581-L643) và [`src/net/control_server.cpp:L569-633`](file:///d:/slugdoc/src/net/control_server.cpp#L569-L633).
* **Trình tự chi tiết:**
  1. Client gọi `platform::PathUtils::read_binary_file(local_file)`. **Đọc toàn bộ file vào RAM** `std::vector<uint8_t> data`.
  2. Client bọc toàn bộ nội dung file thành một chuỗi Base64 duy nhất trong JSON:
     ```cpp
     json req;
     req["type"] = "push_file";
     req["path"] = norm_dest;
     req["data_b64"] = core::Utils::to_base64(*data);
     req["blake3_hash"] = crypto::Blake3::hash_hex(*data);
     ```
  3. Gửi nguyên một chuỗi JSON khổng lồ qua socket. (Nếu file 1 GB $\rightarrow$ JSON phình to 1.33 GB text $\rightarrow$ Rất dễ nghẽn buffer hoặc OOM).
  4. Server nhận frame, giải mã Base64 thành `std::vector<uint8_t> file_bytes`, kiểm tra quyền `WRITE`, quét AI Guard, rồi ghi file xuống đĩa qua `vfs_.write_file(...)`.

---

#### 6. FLOW 6: Luồng Web Portal Proxy & HTTP Tunneling (Nguyên nhân gây khóa cứng Web UI)
* **Tệp mã nguồn:** [`src/main.cpp:L3050-4840`](file:///d:/slugdoc/src/main.cpp#L3050-L4840).
* **Trình tự chi tiết:**
  1. `cmd_portal()` lắng nghe loopback `127.0.0.1:8080`.
  2. Trình duyệt mở `http://127.0.0.1:8080/drop`:
     * Request đi vào vòng lặp chấp nhận socket của Portal.
     * Portal kiểm tra `path == "/drop"`.
     * **Treo khóa Mutex (`main.cpp:L4780`):** `std::lock_guard<std::mutex> lk(g_portal.mtx);`.
     * Portal đóng gói toàn bộ raw HTTP request vào Base64: `g_portal.client->tunnel_http(raw)`.
     * Gửi qua socket PQC AEAD tới `ControlServer` trên Host.
     * Host chuyển cho `WebServer::handle_http_request()` xử lý và render HTML/CSS trả về.
  3. Khi người dùng click nút **"Bắt Đầu Đồng Bộ Về Máy"** trên giao diện Web:
     * Trình duyệt gửi `POST /api/pull/execute` với `{ dest: "...", dir: "..." }`.
     * **VẤN ĐỀ CHÍ MẠNG (`main.cpp:L4645`):**
       ```cpp
       std::lock_guard<std::mutex> lk(g_portal.mtx); // KHÓA CỨNG g_portal.mtx!
       bool ok = g_portal.client->pull(target_dir, opts, nullptr, manifest_opt);
       ```
     * Lệnh `pull()` chạy đồng bộ (blocking) mất nhiều phút.
     * **Hậu quả:** Khóa `g_portal.mtx` bị giữ suốt nhiều phút. Bất kỳ request nào khác từ trình duyệt (mở tab mới, xem ping, duyệt file) đều gọi `std::lock_guard<std::mutex> lk(g_portal.mtx)` $\rightarrow$ **TOÀN BỘ GIAO DIỆN WEB BỊ TREO CỨNG (FREEZE)**.

---

#### 7. FLOW 7: Luồng Tải Thư Mục ZIP Hiện Tại (`/download-folder`)
* **Tệp mã nguồn:** [`src/net/web_server.cpp:L1448-1602`](file:///d:/slugdoc/src/net/web_server.cpp#L1448-L1602) và [`src/net/web_assets.hpp:L575`](file:///d:/slugdoc/src/net/web_assets.hpp#L575).
* **Trình tự chi tiết:**
  1. Người dùng bấm nút link: `<a href='/download-folder?dir=...'>Download Folder (ZIP)</a>`.
  2. Phía máy chủ (`web_server.cpp`):
     * Tạo một mảng động trong RAM: `std::vector<uint8_t> zip_bytes`.
     * Duyệt đệ quy toàn bộ file trong thư mục.
     * Đọc từng file vào `file_data`, tính CRC32, ghi Local File Header (30 bytes) + tên file + dữ liệu file vào `zip_bytes`.
     * Ghi Central Directory Headers (46 bytes/file) + End of Central Directory Record (22 bytes).
     * Gọi `send_resp(200, "OK", "application/zip", body, extra)`.
  3. **Hạn chế:**
     * Toàn bộ gói nén ZIP được gom trong RAM máy chủ (nếu thư mục 3GB thì tốn 3GB RAM server).
     * Cấu trúc ZIP 32-bit tiêu chuẩn, giới hạn tối đa 4 GiB.
     * Trình duyệt chỉ hiển thị icon quay tròn trên tab trong lúc server nén, không có % tiến trình, không có thông số MB/s.

---

### Ma Trận Đối Chiếu: Thực Trạng Hiện Tại vs. Giải Pháp Đã Chốt

| Luồng (Flow) | Thành phần code hiện tại | Điểm nghẽn thực tế | Giải pháp kiến trúc mới thay thế |
| :--- | :--- | :--- | :--- |
| **Kéo File (Pull)** | `SlugClient::pull()` (`client.cpp:L375`) | Stop-and-Wait tuần tự 64KB; nghẽn RTT; bọc JSON Base64 (+33% size); giữ toàn bộ file trong `std::vector` RAM (OOM nếu 100GB). | **Dedicated Bulk Data Plane Streaming**: Stream nhị phân liên tục qua AEAD; Bounded Memory Ring Buffer $\le 4\text{ MB}$; ghi trực tiếp đĩa bằng offset; BLAKE3 incremental. |
| **Đẩy File (Push)** | `SlugClient::push()` (`client.cpp:L581`) | Đọc cả file vào RAM, mã hóa Base64 toàn bộ file vào một chuỗi JSON khổng lồ. | **Binary Stream Push**: Stream các khối nhị phân trực tiếp từ đĩa lên server qua kênh AEAD chuyên dụng; RAM hằng số $\le 4\text{ MB}$. |
| **Khóa Hệ Thống** | `g_portal.mtx` (`main.cpp:L4645, 4718`) | `std::lock_guard` giữ chặt mutex suốt thời gian kéo/đẩy file nặng, làm đơ toàn bộ Web Portal. | **Tách Biệt Connection & Job Lifecycle**: Web UI dùng `g_portal.client` (zero lock); Transfer chạy socket chuyên dụng riêng bằng Session Ticket; background job có quản lý vòng đời. |
| **Web UI Progress** | Nút kéo file & nút tải ZIP (`web_assets.hpp`) | Link ZIP trần `<a href>`, không hiện tiến trình; Nút Pull đồng bộ gây timeout HTTP rồi tự ý văng sang tải ZIP. | **Realtime Metrics Dashboard**: XHR streaming với thanh % động và tốc độ tức thời `MB/s` thật; Polling tiến trình `/api/transfer/progress` không lock; Xóa bỏ auto-redirect sang ZIP. |
| **Đồng Bộ Vi Sai** | `DeltaCalculator::compute_plan` (`delta.cpp:L82`) | Đọc toàn bộ file local vào RAM để hash; Picker browser làm cụt đường dẫn; không bung `~`; lỗi lặp thư mục con. | Tự động bung `~`; tính hash incremental đĩa; sửa logic đường dẫn con; tận dụng tối đa **BLAKE3 Cache Hit (0 byte truyền mạng)**. |

## 10. Chốt Lựa Chọn Công Nghệ: Quyết Định Thực Thi Option A (TCP Binary Streaming Data Plane)

### 10.1. So Sánh 3 Hướng Đi Công Nghệ Được Đặt Lên Bàn Cân

| Hướng Đi | Mô Tả & Bản Chất | Đánh Đổi & Thách Thức | Kết Luận Lựa Chọn |
| :--- | :--- | :--- | :--- |
| **Hướng A: TCP Binary Streaming** | Giữ nguyên socket TCP OS; bỏ cơ chế hỏi-đáp từng chunk; dùng kết nối chuyên dụng stream liên tục các binary frames mã hóa AEAD với buffer hữu hạn. | Cần thiết kế framing protocol nhị phân chuẩn xác; tách biệt rõ ràng Control Plane và Data Plane. | **ĐƯỢC CHỌN (KHUYÊN DÙNG)**: Giữ binary gọn nhẹ (zero third-party lib), bảo toàn 100% PQC cốt lõi, đường ngắn nhất tới 90-115 MB/s Gigabit LAN. |
| **Hướng B: MsQuic / QUIC** | Sử dụng thư viện C đa nền tảng MsQuic chạy trên UDP; có sẵn multiplexing, congestion control và packet recovery. | QUIC gắn chặt với TLS 1.3 và thêm phụ thuộc build/runtime nặng nề. Rất khó tích hợp bộ mật mã PQC riêng (ML-KEM/BLAKE3/XChaCha20) mà không phá vỡ kiến trúc QUIC. | **DỰ PHÒNG NGHIÊN CỨU**: Chỉ làm Proof-of-Concept sau này nếu thực sự cần migration toàn bộ sang UDP. |
| **Hướng C: KCP trên UDP** | KCP là thư viện ARQ tin cậy trên UDP, tối ưu giảm độ trễ (latency) bằng cách đánh đổi băng thông (bandwidth). | Cần ứng dụng tự cung cấp socket UDP; KCP không tự cung cấp bảo mật PQC; trên mạng LAN không có bằng chứng KCP nhanh hơn TCP (thậm chí tốn bandwidth do retransmit sớm). | **LOẠI BỎ**: Không phù hợp với mục tiêu tối đa hóa thông lượng (Throughput) cho file lớn 100 GB. |

### 10.2. Vì Sao Chưa Áp Dụng Zero-Copy (`sendfile()` & kTLS)?
* Linux có `sendfile()` và Kernel TLS (kTLS) giúp giảm việc copy giữa user space và kernel space.
* Tuy nhiên, Slug sử dụng **XChaCha20-Poly1305 phân hướng muối (Directional AEAD) với phái sinh BLAKE3-KDF ở tầng ứng dụng (User Space)**.
* Không thể gửi thẳng plaintext bằng `sendfile()` mà vẫn bảo toàn mật mã PQC tầng ứng dụng. Do đó, bước đi đầu tiên thực tế và chuẩn xác nhất là: **Xóa bỏ Stop-and-Wait, xóa Base64/JSON, streaming với bộ đệm hữu hạn (Bounded-Memory Buffer $\le 4\text{ MB}$) và giải phóng Mutex Lock**.

### 10.3. Tách Biệt Hai Khái Niệm: Storage/Delta Chunk vs. Transport Frame
* **Delta Chunk (64 KiB)**: Dùng để băm BLAKE3 tìm phần dữ liệu trùng nhau phục vụ đồng bộ vi sai (Metadata & Indexing).
* **Transport Frame (128 KiB – 1 MiB)**: Dùng để bơm liên tục trên socket TCP, cân bằng giữa throughput, độ trễ, RAM và chi phí gắn tag AEAD.
* **Quy tắc:** Không bắt buộc mỗi Delta Chunk 64 KiB phải tương ứng với một lần request qua mạng. Hệ thống đóng gói dữ liệu thành các dải payload nhị phân liên tục (Contiguous Byte Range Streaming).

---

## 11. Đặc Tả Chỉ Thị Triển Khai OPTION A (Implementation Blueprint)

Theo chỉ thị của anh, dự án triển khai theo quy trình chuẩn 8 Phase:
1. **Phase 0 — Kiểm tra trước khi sửa (Baseline Audit & Callers Mapping)**.
2. **Phase 1 — Thiết kế Binary Streaming Protocol (Tách Control/Data Plane, 64-bit offsets, zero Base64/JSON)**.
3. **Phase 2 — Bounded-Memory Streaming cho Pull / Get_file (Direct I/O đĩa, Ring Buffer $\le 4\text{ MB}$, BLAKE3 incremental)**.
4. **Phase 3 — Bounded-Memory Streaming cho Push / Upload (Stream nhị phân ngược chiều từ đĩa)**.
5. **Phase 4 — Dedicated Transfer Connection & Zero-Lock (Job Lifecycle, không lock `g_portal.mtx`)**.
6. **Phase 5 — BLAKE3, Integrity & Security Enforcement (Hash verification, symlink/path traversal/policy guard)**.
7. **Phase 6 — Progress UI/API Đo Bằng Số Liệu Thực (Tốc độ MB/s làm mượt, % thật, bỏ auto-redirect ZIP)**.
8. **Phase 7 — Benchmark & Nghiệm Thu**.

---

*Toàn bộ đối sánh, kiến trúc luồng hiện tại và bản đặc tả Option A đã được lưu trữ hoàn chỉnh tại `slug-docs/BÁO_CÁO_KIẾN_TRÚC_VÀ_GIẢI_PHÁP_HIỆU_NĂNG.md`.*

