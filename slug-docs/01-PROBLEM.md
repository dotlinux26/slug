# 01. Đặt vấn đề và nhu cầu thực tế

> **Trạng thái tài liệu:** Hồ sơ đề xuất kỹ thuật cho SICT Innovation Challenge 2026. Các tính năng, số liệu hiệu năng và tuyên bố bảo mật trong tài liệu này là mục tiêu thiết kế cho đến khi được hiện thực hóa, kiểm thử và đo đạc trên bản phát hành cụ thể.

## 1. Bối cảnh

Sinh viên, nhóm nghiên cứu và lập trình viên thường xuyên chia sẻ mã nguồn, tệp nhị phân, tài liệu đồ án và dữ liệu thử nghiệm giữa các máy tính trong phòng lab, ký túc xá, mạng LAN hoặc qua Internet. Việc chia sẻ cần đủ nhanh để dùng hằng ngày, nhưng cũng cần kiểm soát được danh tính người nhận, quyền đọc/ghi, phạm vi thư mục và các tệp không nên gửi ra ngoài.

Nhiều công cụ truyền tệp giải quyết tốt một phần nhu cầu nhưng không phải lúc nào cũng kết hợp được thao tác đơn giản, lọc dữ liệu nhạy cảm, quyền truy cập có thời hạn và đồng bộ tăng dần trong cùng một workflow.

## 2. Các vấn đề cần giải quyết

### 2.1. Chia sẻ nhanh nhưng thiếu lớp bảo vệ phù hợp

Một HTTP server tĩnh khởi chạy nhanh có thể phù hợp với dữ liệu công khai trong mạng tin cậy. Tuy nhiên, nếu dùng HTTP không mã hóa trên mạng không đáng tin cậy, nội dung truyền tải và một số thông tin điều khiển có thể bị quan sát hoặc sửa đổi trên đường truyền. Các server tối giản thường không có sẵn cơ chế quản lý người dùng, phân quyền theo workspace hoặc thu hồi phiên.

Slug không giả định rằng mọi công cụ hiện có đều không an toàn; mục tiêu là cung cấp một lựa chọn tiện dụng hơn khi thư mục được chia sẻ chứa mã nguồn riêng tư hoặc dữ liệu cần giới hạn quyền.

### 2.2. Chia sẻ nhầm tệp nhạy cảm

Workspace phát triển thường chứa `.env`, khóa riêng tư, token truy cập, cơ sở dữ liệu cục bộ, bản dump hoặc dữ liệu thử nghiệm. Một lệnh chia sẻ toàn thư mục có thể vô tình đưa các tệp này cho người nhận. Bộ lọc chỉ dựa trên tên hoặc phần mở rộng có thể bỏ sót secret được hard-code trong mã nguồn; ngược lại, bộ lọc quá cứng có thể gây false positive và làm trải nghiệm tải thư mục khó hiểu.

Slug cần kết hợp quy tắc tĩnh dễ dự đoán với một AI Guard tùy chọn, đồng thời cung cấp danh sách cảnh báo, lý do, cơ chế quét lại và quyết định ngoại lệ có lưu vết.

### 2.3. Quyền truy cập tồn tại lâu hơn nhu cầu

Khi công việc nhóm kết thúc, tài khoản hoặc quyền chia sẻ đôi khi vẫn còn hiệu lực vì người quản trị quên thu hồi. Tài khoản hệ thống dùng chung cũng có thể khiến phạm vi quyền rộng hơn nhu cầu thực tế.

Slug hướng tới quyền theo từng workspace, vai trò tối thiểu `r`, `w`, `rw` và thời hạn hết hiệu lực (`--ttl`). Hết hạn phải được kiểm tra ở phía server khi thực hiện từng thao tác được bảo vệ, không chỉ dựa vào đồng hồ hoặc trạng thái hiển thị trên GUI.

### 2.4. Độ trễ và chi phí khi quét lại toàn bộ Workspace

Nếu AI phân tích lại tất cả tệp mỗi lần bật server, thời gian chờ và chi phí gọi mô hình có thể tăng nhanh theo kích thước dự án. Tương tự, nếu mỗi lần cập nhật phải tải lại toàn bộ thư mục, việc đổi một vài tệp trong workspace lớn sẽ lãng phí băng thông.

Slug đề xuất một chỉ mục trạng thái theo nội dung, lưu dấu vân tay BLAKE3 và trạng thái kiểm tra; cùng một giao thức manifest/diff để client chỉ lấy tệp hoặc các khối dữ liệu cần cập nhật.

### 2.5. Bảo vệ secret khi lưu trữ cục bộ

Tệp `.env` dạng văn bản rõ có thể bị vô tình đọc bởi công cụ lập chỉ mục, backup, đồng bộ đám mây hoặc AI coding agent có quyền truy cập workspace. Mã hóa tệp khi lưu trữ giúp giảm rủi ro đọc trộm ở trạng thái nghỉ, nhưng không loại bỏ mọi rủi ro trong lúc ứng dụng sử dụng secret. Khi secret được đưa vào biến môi trường của tiến trình, tiến trình đó và các chủ thể có đủ quyền hệ điều hành vẫn có thể truy cập chúng.

Slug đề xuất lệnh `slug env` để mã hóa tệp cấu hình nhạy cảm và cung cấp secret cho một tiến trình khi chạy, với giới hạn bảo mật được công bố rõ.

## 3. Mục tiêu của Slug

Slug là một công cụ dòng lệnh đa nền tảng, hướng đến việc chia sẻ và đồng bộ workspace trực tiếp giữa máy chủ lưu trữ và client, với các đặc tính:

- Thiết lập workspace chia sẻ độc lập, có quy tắc và ACL riêng.
- Ba bộ cấu hình mật mã nhằm cân bằng tính tương thích, hiệu năng băm và khả năng chống lại các đối thủ có máy tính lượng tử đủ mạnh.
- Xác thực nhanh bằng mã 8 chữ số dùng một lần, cùng tài khoản phân quyền có thời hạn.
- Bộ lọc phân tầng dựa trên `.gitignore`, quy tắc bảo mật riêng và AI Guard tùy chọn.
- Đồng bộ vi sai dựa trên manifest và hash tệp/khối, kèm chế độ xem trước và chọn lọc.
- Công cụ mã hóa secret lưu trữ cục bộ, với giới hạn rõ ràng về môi trường thực thi.

## 4. Phạm vi và ngoài phạm vi

**Trong phạm vi đề xuất:** chia sẻ trực tiếp host–client khi mạng cho phép; xác thực và phân quyền; lọc tệp; truyền tệp/thư mục; đồng bộ tăng dần; kiểm tra secret; quản lý trạng thái và audit.

**Ngoài phạm vi mặc định:** thay thế Git để quản lý lịch sử phiên bản, cung cấp một dịch vụ relay công cộng, bảo đảm ẩn danh mạng, hoặc tuyên bố rằng mọi cuộc tấn công MITM/relay đều bị ngăn chặn. Khả năng đi qua NAT/firewall sẽ phụ thuộc môi trường mạng và cần được thiết kế, kiểm thử riêng nếu bổ sung.

## 5. Người dùng và tình huống sử dụng

- **Sinh viên/nhóm đồ án:** gửi mã nguồn hoặc nhận bài tập từ thành viên khác mà không phải nén thủ công.
- **Nhóm nghiên cứu:** chia sẻ thư mục dữ liệu có giới hạn quyền và thời gian truy cập.
- **Kỹ sư phần mềm:** đồng bộ workspace lớn, chỉ kéo các tệp hoặc khối nội dung thay đổi.
- **Chủ workspace:** rà soát secret trước khi chia sẻ và chủ động quyết định cách xử lý cảnh báo.
- **Người phát triển ứng dụng cục bộ:** lưu secret ở dạng được mã hóa khi không sử dụng và cấp chúng cho đúng tiến trình khi chạy.

## 6. Tiêu chí đánh giá đề xuất

Các chỉ tiêu cần được xác minh bằng bản triển khai và benchmark có thể lặp lại:

1. **Tính đúng đắn:** ACL, TTL, quy tắc lọc và quyết định AI được thực thi nhất quán ở CLI, GUI và giao thức.
2. **An toàn giao thức:** kiểm thử replay, giả mạo header, sai transcript, hết hạn phiên, rollback manifest và truyền dữ liệu sai thứ tự.
3. **Hiệu năng:** thời gian khởi động, thời gian tạo manifest, tốc độ truyền, tỷ lệ byte tiết kiệm khi đồng bộ vi sai và chi phí gọi AI.
4. **Khả năng sử dụng:** dry-run, báo cáo file bị bỏ qua, lý do chặn rõ ràng, thao tác recheck và xử lý false positive có kiểm soát.
5. **Quyền riêng tư:** phân biệt rõ chế độ AI local và cloud; mặc định không gửi nội dung mã nguồn tới nhà cung cấp bên ngoài.

## 7. Tuyên bố trung thực về mức độ hoàn thiện

Các cụm từ như “khởi động dưới 0,5 giây”, “AI Fast-Scan dưới 10 giây” hoặc “chỉ truyền các chunk thay đổi” phải được coi là **mục tiêu kiểm thử**, không phải kết quả đã đạt, trừ khi báo cáo benchmark ghi rõ commit, cấu hình máy, kích thước dữ liệu, số lần chạy và phương pháp đo. Tương tự, khả năng chống tấn công phải được diễn đạt theo mô hình đe dọa, không dùng các khẳng định tuyệt đối như “an toàn tuyệt đối” hay “triệt tiêu 100%”.

## 8. Tóm tắt

Slug nhắm đến khoảng trống giữa lệnh chia sẻ tệp tức thời và hệ thống đồng bộ có kiểm soát: giữ trải nghiệm dòng lệnh gọn nhẹ nhưng bổ sung quyền theo workspace, thời hạn truy cập, kiểm tra secret, delta sync và một giao thức truyền tải được thiết kế có chủ đích.
