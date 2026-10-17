# TASK: Sửa toàn diện Slug — Workspace Admin, Filter Levels, Audit, Account và Explorer

## 1. Mục tiêu

Làm việc trực tiếp trên repository `dotlinux26/slug`. Đọc cấu trúc và trạng thái hiện tại của code trước khi sửa; triển khai hoàn chỉnh, kiểm thử và báo cáo những thay đổi thực sự đã thực hiện.

Slug là ứng dụng chia sẻ file trong mạng LAN, có CLI, Portal và giao diện Workspace Explorer/Admin. Mục tiêu lần này là thống nhất quản trị theo từng workspace, sửa lỗi tạo tài khoản, hoàn thiện cấu hình và chạy bộ lọc bốn cấp, quản lý audit/scanning, sửa trạng thái hiển thị file và rà soát vòng đời workspace.

**Không chỉ phân tích rồi đưa ra gợi ý. Hãy thực hiện các sửa đổi có thể thực hiện trong môi trường hiện tại.** Không được tuyên bố đã sửa, build, commit hoặc push nếu chưa thực sự hoàn thành bước tương ứng.

## 2. Nguyên tắc bắt buộc

1. **Mỗi workspace có cấu hình và quyền quản trị riêng.** Cấu hình bộ lọc, provider/model AI, audit, tài khoản và các chính sách thuộc workspace phải được xử lý trong phạm vi workspace tương ứng. Không vô tình áp dụng cài đặt của workspace này sang workspace khác.
2. **Không phá cơ chế truyền file hiện tại.** Có báo cáo rằng phần clone/filter enforcement đang hoạt động đúng ở các trường hợp đã kiểm tra, trong khi một số nhãn trạng thái trên Explorer đang hiển thị sai. Ưu tiên sửa phần tính trạng thái/render trước; không viết lại cơ chế truyền file nếu không có bằng chứng về lỗi.
3. Không tự động ẩn file hoặc folder chỉ vì file bị filter/block. Giữ cấu trúc cây thư mục và hiển thị trạng thái đúng để người dùng nhận biết file nào khả dụng, file nào bị chặn.
4. `.slug/` là vùng metadata nội bộ, phải được bảo vệ khỏi truy cập từ giao diện và API dành cho người dùng thường. Không cho phép tải trực tiếp, đọc, liệt kê hoặc vượt đường dẫn để lấy nội dung `.slug/`.
5. Giữ nguyên `.gitignore` của project. Không tạo `.slugignore`. Quy tắc riêng của Slug lưu tại `.slug/rules.conf`.
6. Chế độ `none` nếu đang được hỗ trợ chỉ tắt phần kiểm tra nội dung theo đúng thiết kế; không được tắt các invariant bảo mật, kiểm soát quyền, bảo vệ `.slug/`, path traversal guard hoặc các quy tắc bắt buộc khác.
7. Không làm giao diện quá phức tạp. Admin Dashboard cần gọn, dễ sử dụng, hiển thị đúng dữ liệu từ backend và không có các nút giả hoặc chức năng chỉ thay đổi giao diện mà không lưu thực sự.
8. Trước khi xóa, đổi schema hoặc di chuyển chức năng, kiểm tra tương thích dữ liệu workspace cũ và các API đang được sử dụng.

## 3. Rà soát kiến trúc và các file mục tiêu

Các vị trí đã được xem trong source ở lượt kiểm tra trước; line number có thể thay đổi, vì vậy phải tìm lại trong checkout hiện tại.

- `src/net/web_assets.hpp`: HTML/CSS/JS của Portal, Workspace Explorer và Admin Dashboard; các form host workspace; render directory listing; các mặc định filter.
- `src/net/web_server.cpp`: các endpoint quản trị theo workspace như `/api/admin/users`, `/api/admin/audit`, `/api/admin/rules` và phần phục vụ `/admin`.
- `src/main.cpp`: API Portal/host, tạo workspace, endpoint audit Portal, các lệnh CLI liên quan đến tạo workspace và scan.
- `src/core/types.hpp`: chuyển đổi tên filter level, enum và giá trị fallback.
- `src/ai/stateful_audit.hpp`, `src/ai/stateful_audit.cpp`: lưu trữ và truy vấn audit/scanning trong SQLite.
- `src/ai/scanner.cpp`: lựa chọn scanner theo filter level và nhà cung cấp AI.
- `src/net/control_server.hpp`: cấu hình mặc định hoặc trạng thái filter nếu vẫn được khai báo tại đây.
- Các file quản lý workspace, ACL, session, OTP và cấu hình: tìm trong project để xác định chính xác nơi lưu và cập nhật các TTL.

Các phát hiện trước cần được xác minh lại trước khi sửa:

- HTML tạo workspace có chỗ đang chọn Level 3 làm mặc định.
- API tạo workspace từng dùng fallback `level3`.
- Có các giá trị mặc định Level 3 ở CLI, phần render directory listing hoặc những vị trí liên quan.
- Portal từng có endpoint `/api/audit/clear` xóa `.slug/index.db`, nhưng luôn báo thành công mà không xử lý đầy đủ lỗi xóa file.
- Workspace Admin có endpoint đọc audit và cho phép file/folder, nhưng chưa thấy endpoint clear toàn bộ audit riêng cho workspace.
- `StatefulAuditIndex` chưa thấy phương thức clear toàn bộ audit entry.
- Endpoint tạo người dùng thực có dạng `/api/admin/users/add`, nhưng chức năng tạo tài khoản đang bị báo lỗi. Chưa kết luận nguyên nhân nằm ở frontend hay backend; phải tái hiện và tìm nguyên nhân thật.
- Đã có báo cáo thư mục hiển thị tương đối ổn, nhưng trạng thái AVAILABLE/BLOCKED của file hoặc thư mục có thể bị tính sai do cách gom các entry vào cây.

Không giả định những phát hiện này chắc chắn vẫn đúng ở branch hiện tại. Kiểm tra source và hành vi thực tế trước khi áp dụng bản sửa.

## 4. Hạng mục P0 — Sửa chức năng tạo tài khoản Admin

Rà soát toàn bộ luồng tạo account trong Workspace Admin Dashboard:

- UI nhập username, password, role và TTL.
- Kiểm tra input ở frontend.
- Request gửi đến API.
- Xác thực session/quyền admin phía backend.
- Parse và validate JSON.
- Gọi ACL manager.
- Lưu tài khoản và phản hồi kết quả cho UI.
- Refresh danh sách tài khoản sau khi tạo thành công.

Các endpoint đã thấy trong code trước đây gồm:

- `GET /api/admin/users`
- `POST /api/admin/users/add`
- `POST /api/admin/users/update`
- `POST /api/admin/users/delete`

Giữ đúng API contract thực tế của project, không tự dựng một API song song nếu endpoint hiện tại đã đủ khả năng mở rộng.

### Yêu cầu

1. Tái hiện lỗi tạo tài khoản và xác định chính xác lỗi ở đâu: frontend validation, request payload, HTTP status, JSON parsing, ACL manager, lưu trữ hay refresh UI.
2. Sửa tận gốc, không chỉ hiện thông báo “thành công”.
3. Nếu backend từ chối request, UI phải hiện lỗi thực tế đủ để xử lý; không nuốt lỗi hoặc giả lập dữ liệu.
4. Username, password, role và TTL phải được kiểm tra thống nhất trước khi lưu. Không ghi password hoặc dữ liệu xác thực nhạy cảm vào log.
5. Tài khoản tạo trong một workspace không được tự động có hiệu lực trong workspace khác.
6. Role phải lấy từ các role hợp lệ mà hệ thống thực sự hỗ trợ; không tùy tiện mở thêm quyền.
7. Chức năng sửa/xóa tài khoản phải tiếp tục hoạt động. Xóa tài khoản cần duy trì hành vi revoke session theo thiết kế hiện tại.
8. Kiểm tra trường hợp username trùng, input rỗng, password không hợp lệ, TTL không hợp lệ, request không có quyền admin, database lỗi và workspace bị đóng.
9. Sau khi tạo thành công, danh sách phải phản ánh dữ liệu đã lưu thực tế.

Không thêm lại modal account CRUD giả ở Portal. CRUD tài khoản thật thuộc Workspace Admin.

## 5. Hạng mục P0 — Chuẩn hóa bộ lọc bốn cấp

Bộ lọc phải tuân thủ chính xác định nghĩa dưới đây. Các cấp cao hơn **cộng thêm** kiểm tra của cấp thấp hơn, không thay thế chúng.

### Level 1 — Path Rules

- Áp dụng `.gitignore` theo hành vi tương thích với project.
- Áp dụng quy tắc đường dẫn riêng của Slug trong `.slug/rules.conf`.
- Không chạy regex quét secret, entropy hay AI content scan ở cấp này.
- Không tạo `.slugignore` hoặc thay thế `.gitignore`.

### Level 2 — Secret Pattern Scan

Bao gồm toàn bộ Level 1, cộng thêm:

- Regex hoặc pattern detection để nhận diện nội dung nhạy cảm theo cơ chế scanner hiện tại.
- Quản lý kết quả scan, trạng thái blocked/allowed và audit theo workspace.
- Xử lý rõ lỗi đọc file, file thay đổi trong lúc scan và kết quả scan chưa hoàn tất.

### Level 3 — Entropy Scan

Bao gồm toàn bộ Level 2, cộng thêm:

- Kiểm tra Shannon entropy trên các file nguồn hoặc văn bản phù hợp.
- Không áp dụng entropy scan đại trà cho binary, media hoặc định dạng không phù hợp như ảnh, video, audio, DLL, PYD và những file nhị phân tương tự.
- Dựa vào cơ chế xác định loại file hiện có; nếu chưa đủ chắc chắn thì ưu tiên bỏ qua entropy scan cho file không xác định rõ thay vì tạo false positive.
- Không coi việc bỏ qua entropy là tự động cho phép file nếu file vẫn bị chặn bởi các rule hoặc detector khác.

### Level 4 — AI Scan

Bao gồm toàn bộ Level 3, cộng thêm:

- Quét nội dung bằng model AI được người quản trị workspace lựa chọn.
- Hỗ trợ các provider đã có trong project, bao gồm Ollama, OpenAI và Gemini, trong phạm vi mà scanner hiện tại thực sự hỗ trợ.
- Không gọi AI ở Level 1–3.
- Không âm thầm fallback sang một model/provider khác khi cấu hình sai. Trả lỗi cấu hình rõ ràng.
- Xử lý timeout, provider không khả dụng, API key thiếu/sai và response không hợp lệ.
- Không gửi dữ liệu file ra ngoài provider từ các cấp không yêu cầu AI.
- Giữ nguyên hành vi bảo mật của hệ thống khi AI không khả dụng; không tự động coi lỗi AI là kết quả ALLOW.

### Đồng bộ mặc định Level 2

Đặt **Level 2** làm giá trị mặc định khi tạo workspace mới. Rà soát và đồng bộ:

- Giá trị mặc định trong form Portal.
- Payload khi tạo workspace.
- Fallback tại API backend.
- Giá trị fallback khi parse filter string.
- Mặc định trong CLI tạo workspace và CLI scan nếu lệnh không truyền level.
- Giá trị mặc định tại `ControlServer`, `WorkspaceManager` và các lớp liên quan.
- Giá trị được truyền vào `ManifestBuilder`/directory listing nếu caller không chỉ định level.
- Giá trị được lưu và load lại từ workspace registry/config.

Các chuỗi `"level3"` hoặc enum Level 3 mặc định cần được tìm kiếm có hệ thống, không chỉ đổi một dropdown.

Lưu ý: mặc định Level 2 áp dụng cho workspace mới hoặc cấu hình bị thiếu/không hợp lệ. Không tự ý ghi đè cấu hình Level 3 mà chủ workspace đã chọn rõ ràng và đã được lưu.

### Lựa chọn model chỉ xuất hiện ở Level 4

- Tạo hoặc hoàn thiện select riêng cho AI provider/model trong Workspace Admin.
- Dropdown model chỉ hiển thị hoặc được kích hoạt khi Level 4 đang được chọn.
- Khi chuyển về Level 1–3, không chạy AI scan; cấu hình model đã lưu có thể được giữ lại để dùng khi chuyển lại Level 4.
- Khi đổi provider, chỉ hiển thị các trường thật sự cần thiết cho provider tương ứng.
- Các trường endpoint, model, API key hoặc JSON config phải dùng lại cơ chế có sẵn trong project nếu phù hợp.
- Mask API key; không trả secret về frontend trong response; không ghi secret vào audit hoặc log.

Không để UI báo đang chạy Level 4 trong khi backend dùng Level 3 hoặc Level 2. Giá trị hiển thị, request, cấu hình đã lưu và scanner thực thi phải nhất quán.

## 6. Hạng mục P0 — Đưa quản trị về Workspace Admin Dashboard

Mục tiêu là một nơi quản trị duy nhất cho từng workspace.

### Portal

Portal vẫn chịu trách nhiệm cho các thao tác cấp Portal, chẳng hạn tạo workspace, xem workspace, kết nối hoặc vào workspace theo thiết kế hiện có.

- Loại bỏ các màn hình/drawer quản lý account trùng lặp ở Portal nếu chúng chỉ mô phỏng quản trị hoặc không có backend tương ứng.
- Không giữ hai giao diện độc lập cùng quản lý một tập tài khoản nhưng cho ra kết quả khác nhau.
- Chuyển chức năng cấu hình filter, chạy scan, chọn model AI, xem audit và xóa audit vào Admin Dashboard của workspace.
- Gỡ các code JS, form hoặc event handler chỉ phục vụ giao diện cũ khi đã xác minh không còn được sử dụng. Không xóa bừa các API hoặc dữ liệu còn được CLI hay client khác dùng.

### Workspace Admin Dashboard

Bố cục ưu tiên nhỏ gọn, trực tiếp và nhất quán. Tích hợp tối thiểu các nhóm chức năng:

1. **Workspace Settings** — filter level, trạng thái/filter mode và cấu hình AI chỉ khi Level 4.
2. **Scanning** — xem cấu hình áp dụng, chạy scan hoặc re-scan và xem trạng thái/kết quả.
3. **Audit** — xem các kết quả bị flag, trạng thái và lý do dành cho admin; xử lý allow/approve theo chính sách hiện tại; xóa lịch sử scan/audit.
4. **Users & Access** — tạo, sửa và xóa tài khoản; xem role, TTL/session có liên quan.
5. **Rules** — xem/thêm/xóa quy tắc qua API và cơ chế `.slug/rules.conf` đang có.
6. **Sessions** — xem hoặc revoke session nếu chức năng này đã được hỗ trợ.

Không tạo sáu màn hình cồng kềnh chỉ để chia nhỏ chức năng. Dùng nhóm hoặc tab gọn, ưu tiên thao tác dễ hiểu. Mỗi nút phải nối đến backend thật, có loading/error state hợp lý và cập nhật dữ liệu sau khi thao tác thành công.

Tất cả endpoint quản trị phải xác minh quyền admin của **workspace đích**. Không tin các giá trị `workspace`, `path`, `role` hoặc định danh do client tự gửi nếu không được kiểm tra phía server.

## 7. Hạng mục P0 — Quản lý scan và xóa audit/index.db

Hiện audit và scanning index dùng `.slug/index.db` theo workspace. Cần cung cấp nút **Clear Scan/Audit Records** tại Workspace Admin Dashboard.

### Hành vi yêu cầu

- Có xác nhận trước khi xóa, vì thao tác không thể hoàn tác theo cách thông thường.
- Chỉ xóa các bản ghi lịch sử scan/audit thuộc workspace đang thao tác.
- Không xóa `.slug/rules.conf`, allow rules, khóa, cấu hình workspace, tài khoản hoặc dữ liệu bảo mật khác.
- Không coi việc xóa audit là tương đương với “Allow All”. Hai hành động phải hoàn toàn độc lập.
- Sau khi xóa, giao diện refresh và hiển thị trạng thái rỗng đúng theo dữ liệu backend.
- Phải xử lý trường hợp database không tồn tại, database đang mở, lỗi transaction, lỗi I/O, permission denied hoặc lỗi SQLite.
- Không trả `status: "ok"` nếu thao tác thất bại.
- Trả số bản ghi đã xóa hoặc thông tin tương đương nếu triển khai được mà không làm phức tạp API.

### Cách triển khai

Rà soát `StatefulAuditIndex` tại:

- `src/ai/stateful_audit.hpp`
- `src/ai/stateful_audit.cpp`

Nếu phù hợp, bổ sung phương thức dạng `clear_all()` cho phép xóa audit entries bằng câu lệnh SQL trong transaction, kiểm tra return code và rollback khi lỗi. Dùng đúng kết nối/đối tượng SQLite đang quản lý database để tránh xóa file database trong khi handle vẫn đang mở.

Bổ sung endpoint quản trị theo workspace, dự kiến `POST /api/admin/audit/clear`, tại `src/net/web_server.cpp`. Xác thực quyền admin và workspace như các endpoint admin hiện hữu. Dùng response contract phù hợp với conventions trong code hiện tại.

Nếu Portal vẫn có `/api/audit/clear`, sửa luồng cũ để không còn báo thành công giả và không xóa nhầm dữ liệu. Ưu tiên gọi qua logic dùng chung thay vì duy trì hai cách xóa khác nhau.

### Phân biệt các thao tác

- **Clear Audit:** xóa lịch sử scan/audit entries.
- **Allow File/Folder:** tạo quyết định allow theo logic hiện có, bao gồm thao tác thêm rule nếu thiết kế đang dùng cách đó.
- **Allow All:** giữ chức năng cho phép hàng loạt theo chính sách hiện tại.

Không trộn lẫn ba chức năng trên.

## 8. Hạng mục P1 — Sửa trạng thái file/folder trên Explorer

Mục tiêu là sửa phần hiển thị đang sai nhưng không làm hỏng việc clone/tải file vốn đang hoạt động.

### Quy tắc trạng thái

- File khả dụng phải hiện `AVAILABLE`.
- File bị block bởi filter/policy phải hiện `BLOCKED`.
- Trạng thái phải lấy từ manifest hoặc kết quả backend đã xác định; không tự suy ra chỉ từ tên file hoặc từ vị trí của nó trong cây.
- Không hiện `AVAILABLE` cho file bị block.
- Không bỏ file/folder khỏi cây chỉ vì bị block.
- Lý do block chi tiết dành cho Admin; không vô tình công khai secret pattern, regex, detector internals hoặc lý do nhạy cảm cho người dùng thường.

### Kiểm tra logic tạo tree

Ở phần render directory listing trong `src/net/web_assets.hpp`, có logic sử dụng `manifest.files`, `manifest.skipped` và tập `seen_dirs`. Kiểm tra trường hợp thư mục được tạo từ file AVAILABLE trước, sau đó có file BLOCKED ở cùng folder/subtree nhưng trạng thái folder không được cập nhật vì thư mục đã nằm trong `seen_dirs`.

Sửa logic aggregation để trạng thái không phụ thuộc vào thứ tự duyệt manifest.

- Với **file**, trạng thái phải luôn chính xác và nhất quán.
- Với **folder**, không gắn nhãn AVAILABLE chỉ vì file đầu tiên của folder khả dụng. Nếu folder không có một trạng thái tổng hợp rõ ràng, hãy để node folder là node điều hướng, còn các file con hiển thị trạng thái riêng. Nếu vẫn hiển thị trạng thái folder, phải dùng quy tắc aggregate nhất quán và không gây hiểu nhầm rằng mọi file trong folder đều tải được.
- Đảm bảo không mất node thư mục rỗng hoặc thư mục chỉ chứa file bị block.
- Kiểm tra nhiều cấp thư mục, tên file trùng ở các thư mục khác nhau, file bị allow sau khi scan, và cập nhật manifest sau khi policy thay đổi.

### Backend enforcement không được suy yếu

UI hiển thị BLOCKED chưa đủ. Tiếp tục giữ enforcement thực tại backend:

- Kiểm tra path traversal, canonical path và symlink theo các guard hiện có.
- Kiểm tra quyền và policy cho cả listing, metadata, download và các cách lấy chunk.
- Không cho phép bypass bằng cách gọi endpoint trực tiếp thay vì dùng UI.
- Khi file đang được truyền mà policy chuyển sang BLOCKED, rà soát cache và race condition: không cho các chunk tiếp theo tiếp tục được phục vụ vô thời hạn chỉ vì request đã bắt đầu trước đó.
- Không thay đổi giao thức hoặc luồng truyền hiện tại ngoài phạm vi thực sự cần để đảm bảo policy được áp dụng nhất quán.

Nếu tìm thấy lỗ hổng enforcement thực sự, bổ sung regression test riêng, không trộn lỗi giao diện với lỗi backend trong cùng một bản vá khó kiểm chứng.

## 9. Hạng mục P1 — TTL cho workspace, OTP, account và session

Rà soát form tạo workspace, API payload, workspace manager, ACL và session manager. Đảm bảo UI phản ánh đúng các trường hiện có trong bản build đang sử dụng.

Cần phân biệt rõ bốn khái niệm:

- **OTP TTL / OTP step:** thời lượng hiệu lực hoặc chu kỳ OTP theo đúng semantics hiện tại.
- **User/account TTL:** thời gian tồn tại của tài khoản hoặc thời điểm hết hạn tài khoản.
- **Session TTL:** thời gian hiệu lực phiên đăng nhập.
- **Workspace TTL/lifetime:** thời gian workspace được phép tồn tại theo thiết kế hiện tại.

Không dùng chung một giá trị để điều khiển nhiều TTL khác nhau.

### Form tạo workspace

Kiểm tra tất cả entry point tạo workspace, không chỉ một form HTML:

- Có trường cấu hình OTP TTL với lựa chọn hợp lý và đơn vị hiển thị rõ ràng.
- Có trường workspace lifetime độc lập.
- Form gửi đúng key mà backend nhận. Đặc biệt rà soát quan hệ giữa `otp_ttl` và `otp_step`, vì code đã xem trước đây chấp nhận fallback giữa hai tên này trong khi form gửi `otp_step`.
- Xác minh giá trị mặc định, min/max, giá trị không hợp lệ và giá trị không có trong payload.
- Không đưa OTP TTL vào trường workspace lifetime hoặc account TTL.

### TTL của user/session

- Form tạo/sửa account cần hiển thị TTL đúng với semantics trong ACL manager.
- Giá trị “giữ nguyên TTL hiện tại” khi cập nhật phải khác với “permanent” nếu API cần phân biệt hai trường hợp này.
- Kiểm tra semantics TTL hiện hữu trước khi thay đổi: code ACL đã xem trước đây dùng TTL dương để tính thời điểm hết hạn và giá trị không dương để biểu diễn không hết hạn ở một luồng cập nhật. Không tự đổi semantics khi chưa kiểm tra các caller khác.
- Thông báo hết hạn và dữ liệu trong UI phải phản ánh trạng thái backend thật.

Nếu source hiện tại đã có `host-otp-ttl` và `host-ttl` nhưng người dùng không thấy trong build, xác định nguyên nhân bằng cách kiểm tra HTML đang được render, asset được đóng gói và đường chạy thực tế. Không thêm trùng trường chỉ để tạo cảm giác đã sửa.

## 10. Hạng mục P1 — AI model settings theo workspace

Di chuyển phần model configuration cần cho scan về Workspace Admin thay vì giữ một AI Guard độc lập ở Portal.

Rà soát scanner và các field hiện hữu, gồm những khái niệm tương đương với:

- AI provider.
- Model ID/name.
- Endpoint/base URL nếu provider cần.
- API key nếu provider cần.
- JSON/model configuration nếu scanner hỗ trợ.

Yêu cầu:

1. Mỗi workspace dùng cấu hình model của chính nó.
2. Level 4 mới kích hoạt việc gọi AI scanner.
3. Chuyển sang Level 1–3 phải ngăn AI scan được gọi, kể cả từ request trực tiếp nếu backend nhận filter level từ client.
4. Backend phải dùng cấu hình đã validate, không tin việc UI ẩn dropdown để thực thi chính sách.
5. Không trả API key về client sau khi lưu; chỉ hiển thị trạng thái đã cấu hình hoặc masked value nếu thật sự cần.
6. Không tự động log nội dung file nhạy cảm hoặc secret đi kèm model request.
7. Hỗ trợ provider lỗi, timeout, quota/auth error và response không hợp lệ với thông báo dễ xử lý.
8. Cấu hình của workspace A không được ghi đè cấu hình workspace B.

Rà soát `src/ai/scanner.cpp` và logic `AiScanner::create_for_level()` hiện có trước khi thêm abstraction mới; tái sử dụng code sẵn có nếu đáp ứng yêu cầu.

## 11. Hạng mục P2 — SQLite amalgamation

Kiểm tra phiên bản SQLite được đóng gói trong repository, gồm `sqlite3.c` và `sqlite3.h`.

- Xác định phiên bản thực tế qua macro/version trong source hoặc build.
- Đối chiếu các bản vá bảo mật và tính tương thích của phiên bản hiện tại.
- Nếu cần nâng cấp, dùng bản amalgamation chính thức phù hợp, cập nhật cả header/source đồng bộ và giữ nguyên cách link/build của project.
- Kiểm tra schema, mở database cũ, tạo mới, migration/auto-heal và các truy vấn audit.
- Không nâng cấp mù quáng chỉ để có số phiên bản mới hơn. Ghi lại lý do và version được chọn.
- Chạy regression test cho `index.db`; không làm mất dữ liệu workspace cũ trong quá trình nâng cấp.

## 12. Kế hoạch triển khai theo thứ tự

### Phase A — Audit và tái hiện

1. Kiểm tra branch, commit HEAD, working tree và build instructions.
2. Kiểm tra source hiện tại của các file mục tiêu.
3. Tái hiện lỗi tạo account.
4. Xác minh endpoint và trạng thái UI thật của Admin.
5. Ghi lại các giá trị mặc định Level 3 và các đường dẫn cấu hình liên quan.
6. Xác minh hiện tượng trạng thái file/folder không chính xác bằng manifest có cả file AVAILABLE và BLOCKED.
7. Kiểm tra code clear audit hiện tại và các thao tác SQLite.
8. Ghi lại baseline test/build trước sửa nếu môi trường cho phép.

### Phase B — Sửa backend và state

Ưu tiên backend trước UI:

1. Sửa lỗi tạo account và test ACL flow.
2. Đồng bộ filter defaults thành Level 2 cho workspace mới/fallback.
3. Hoàn thiện API lưu cấu hình filter/model theo workspace.
4. Bổ sung phương thức clear audit an toàn và endpoint Admin theo workspace.
5. Kiểm tra TTL và payload tạo workspace.
6. Đảm bảo enforcement, quyền admin và workspace isolation.
7. Kiểm tra binary exclusion của entropy scanner.
8. Chỉ thực hiện sửa SQLite nếu việc audit cho thấy cần thiết.

### Phase C — Sửa giao diện

1. Đưa filter level vào Workspace Admin.
2. Đặt Level 2 là lựa chọn mặc định ở luồng tạo workspace mới.
3. Tách model selector, chỉ hiện/kích hoạt ở Level 4.
4. Tích hợp nút chạy scan/re-scan, xem audit và clear audit.
5. Sửa status render của Explorer.
6. Hoàn thiện create/edit/delete account với TTL.
7. Kiểm tra các trường OTP TTL và workspace TTL trong mọi form tạo workspace.
8. Gỡ phần quản trị trùng hoặc AI Guard độc lập ở Portal sau khi chức năng thay thế đã hoạt động.
9. Dọn event handlers và endpoint call không còn sử dụng nếu chắc chắn không ảnh hưởng CLI/API client.

### Phase D — Regression và nghiệm thu

Chạy build và test hiện có, thêm test cho hành vi mới. Không đánh dấu hoàn tất chỉ vì code đã compile.

## 13. Bộ test bắt buộc

### Account/ACL

- Tạo account hợp lệ thành công và đọc lại thấy account đó.
- Username trùng bị từ chối.
- Thiếu trường bắt buộc bị từ chối.
- Role không hợp lệ bị từ chối.
- TTL không hợp lệ bị từ chối hoặc xử lý đúng theo contract.
- User không phải admin không thể gọi API admin.
- Tài khoản của workspace A không xuất hiện ở workspace B.
- Sửa và xóa account hoạt động; session bị revoke theo thiết kế.

### Filter levels

- Workspace mới không truyền filter level nhận Level 2.
- Form và backend cùng cho ra Level 2 mặc định.
- Level 1 chỉ áp dụng path rules và `.gitignore`.
- Level 2 thêm secret-pattern scan.
- Level 3 thêm entropy chỉ cho loại file phù hợp.
- Level 4 thêm AI scan bằng model đã cấu hình.
- Không gọi AI ở Level 1–3.
- Provider lỗi không được mặc định trả kết quả ALLOW.
- Config Level 3 đã lưu rõ ràng của workspace cũ vẫn được giữ.
- Workspace A và B có thể dùng filter level/provider khác nhau.

### Audit clearing

- Clear audit xóa bản ghi của workspace hiện tại.
- Không xóa `.slug/rules.conf`, account, key hoặc workspace config.
- Allow All và Clear Audit vẫn là hai thao tác khác nhau.
- Xóa audit xong UI refresh chính xác.
- Quyền không đủ bị từ chối.
- SQLite/I/O failure không trả success giả.
- Database đang sử dụng không bị đóng/mất kết nối ngoài ý muốn.
- Workspace khác không bị ảnh hưởng.

### Explorer và enforcement

- Folder có cả file AVAILABLE và BLOCKED.
- Folder chỉ chứa file BLOCKED.
- Folder chỉ chứa file AVAILABLE.
- Folder rỗng.
- File nằm nhiều cấp sâu.
- Status file không đổi sai theo thứ tự manifest.
- File BLOCKED không thể đọc/tải trực tiếp bằng API.
- Không thể vượt path traversal hoặc lấy `.slug/`.
- Policy chuyển sang BLOCKED được áp dụng với thao tác đọc/tải phù hợp, kể cả các đường dẫn chunk.
- File blocked vẫn xuất hiện trong cây ở trạng thái thích hợp, không âm thầm biến mất.

### TTL/workspace

- OTP TTL gửi và lưu đúng.
- Workspace TTL gửi và lưu đúng.
- Account TTL và session TTL không bị trộn.
- Giá trị mặc định được áp dụng đúng.
- Cập nhật giữ nguyên TTL không vô tình biến account thành permanent hoặc hết hạn ngay.
- Kiểm tra workspace hết hạn theo hành vi vốn được thiết kế.

### Kiểm thử project

- Build theo hướng dẫn của repository.
- Chạy toàn bộ test hiện có, bao gồm CTest nếu project cấu hình hỗ trợ.
- Thêm regression test thích hợp cho lỗi đã sửa.
- Kiểm tra `git diff` để chắc chắn không có thay đổi ngoài phạm vi, không sửa `.gitignore` và không tạo `.slugignore`.
- Nếu môi trường không thể chạy test/build, ghi rõ lệnh đã thử và blocker; không tuyên bố pass.

## 14. Tiêu chí hoàn thành

Chỉ được xem là xong khi:

- Tài khoản được tạo thực sự và persist thành công.
- Level 2 là mặc định của workspace mới trên mọi luồng tương ứng.
- Định nghĩa Level 1–4 được áp dụng thật ở backend, không chỉ được chọn trên UI.
- Model settings được quản lý ở đúng workspace và chỉ dùng cho Level 4.
- Clear Scan/Audit hoạt động với kiểm tra lỗi đúng, không xóa nhầm cấu hình hoặc rules.
- Explorer hiển thị status chính xác mà không làm suy yếu filter enforcement.
- TTL workspace, OTP, account và session phân biệt rõ, payload/form nhất quán.
- Portal không còn giao diện quản trị trùng với Workspace Admin.
- Build/test có kết quả cụ thể và không có regression đã biết.

## 15. Kết quả phải báo cáo

Khi hoàn tất, báo cáo theo cấu trúc:

1. **Root cause:** nguyên nhân cụ thể của từng lỗi.
2. **Files changed:** file nào được sửa và mục đích từng file.
3. **Implementation:** hành vi mới, endpoint/schema mới nếu có, migration nếu có.
4. **Tests:** các lệnh thực sự đã chạy và kết quả từng nhóm.
5. **Known limitations:** những gì chưa làm được và lý do.
6. **Git status:** branch, commit hash và PR chỉ khi đã thực sự tạo được.

Ưu tiên sửa xong và kiểm chứng các hạng mục P0 trước. Không che lỗi bằng UI giả, không bỏ qua test thất bại, không tự ý làm lại toàn bộ kiến trúc hoặc thêm tính năng ngoài phạm vi khi chưa cần thiết.

---

## 16. Tiến độ thực tế đã hoàn thành (Checklist cập nhật)

### Hạng mục P0 — Sửa chức năng tạo tài khoản Admin
- [x] **Sửa tận gốc luồng tạo tài khoản Admin**:
  - Giao diện Admin Dashboard `/admin` modal tạo tài khoản gửi request chuẩn đến `POST /api/admin/users/add` với đầy đủ `username`, `password`, `role`, `ttl_sec`.
  - Backend xác thực quyền `host_admin`, băm mật khẩu chuẩn PBKDF2 HMAC-SHA256 với salt ngẫu nhiên 16 bytes và lưu bền vững vào `.slug/acl.db` qua `AclManager`.
  - Reload trang dữ liệu vẫn còn nguyên vẹn, tài khoản đăng nhập thực sự và được phân quyền RBAC chính xác.
  - Sửa lỗi hiển thị TTL người dùng: hàm `core::Utils::format_ttl` và hàm JS `formatSec` đã phân biệt chính xác giữa timestamp epoch tuyệt đối và thời lượng relative seconds (`remaining_sec`), loại bỏ hoàn toàn lỗi hiển thị `Active (Expired)`.
  - Sửa và xóa tài khoản hoạt động chuẩn xác, tự động kích hoạt `revoke_sessions_by_identity` thu hồi ngay lập tức các phiên kết nối đang mở của tài khoản bị xóa.

### Hạng mục P0 — Chuẩn hóa bộ lọc bốn cấp & Mặc định Level 2
- [x] **Đồng bộ mặc định Level 2 (Regex Secret Guard) xuyên suốt toàn bộ hệ thống**:
  - Đặt `LEVEL_2_REGEX` làm giá trị mặc định trong `src/core/types.hpp` (`filter_level_to_string` trả về `"level2"`, `filter_level_from_string` fallback về `LEVEL_2_REGEX`).
  - Đặt `LEVEL_2_REGEX` làm mặc định trong `ManifestBuilder::build` (`src/sync/manifest.hpp`).
  - Đặt `LEVEL_2_REGEX` làm mặc định trong `ControlServer` (`src/net/control_server.hpp`).
  - Đặt `LEVEL_2_REGEX` làm mặc định trong `WorkspaceInfo` và `WorkspaceManager::add_workspace` (`src/core/workspace.hpp`).
  - Đặt `LEVEL_2_REGEX` làm mặc định cho CLI `slug host` và `slug scan` trong `src/main.cpp`.
  - Đặt mặc định `level2` (`selected`) trong form tạo trạm chia sẻ tại Portal (`src/net/web_assets.hpp`).
  - Sửa lỗi ánh xạ trong `loadHostedWorkspaces()` và `renderHostedWorkspaces()`: lưu `suite` và `filter_level` thật, loại bỏ tình trạng "GUI troll" hiển thị sai mức mật mã (Suite 2 Modern Hybrid) và mức lọc mặc định.
- [x] **Tích hợp bộ quét 4 cấp độ và cấu hình AI theo workspace vào Admin Dashboard**:
  - Thêm thẻ `BỘ QUÉT BẢO MẬT 4 CẤP ĐỘ & CẤU HÌNH AI WORKSPACE` tại `/admin`.
  - Cho phép chọn 4 cấp độ lọc (Level 1: Rules & Gitignore, Level 2: Regex Secret Guard, Level 3: Shannon Entropy, Level 4: AI Model Scan).
  - Nút `Quét Lại (Scan Now)` gọi `POST /api/admin/scan/run` kích hoạt quét lại theo cấp độ đã chọn, tự động làm mới manifest cache và cập nhật kết quả audit.
  - Bảng cấu hình mô hình AI (`#admin-ai-panel`) chỉ kích hoạt và hiển thị khi chọn Mức 4 (AI Model Scan); các mức 1–3 chạy hoàn toàn offline không gọi AI.
  - Hỗ trợ đầy đủ 3 provider: Ollama Local (Offline), OpenAI Cloud, Google Gemini Cloud với các trường endpoint, model, masked API key (`••••••••`). Cấu hình lưu riêng biệt từng workspace vào `.slug/ai.json` qua `POST /api/admin/ai/config` và kiểm tra kết nối qua `POST /api/admin/ai/test`.

### Hạng mục P0 — Quản lý scan và xóa audit / index.db an toàn
- [x] **Xóa sạch dữ liệu kiểm toán an toàn qua transaction SQLite**:
  - Bổ sung phương thức `StatefulAuditIndex::clear_all()` trong `src/ai/stateful_audit.hpp` và `src/ai/stateful_audit.cpp`.
  - Thực thi xóa an toàn thông qua câu lệnh SQL `DELETE FROM audit_entries;` bên trong transaction `BEGIN IMMEDIATE; ... COMMIT;` và `PRAGMA wal_checkpoint(TRUNCATE);`, không xóa file vật lý `.slug/index.db` khi file handle đang mở để tránh crash/lock trên Windows.
  - Bổ sung endpoint `POST /api/admin/audit/clear` trong `src/net/web_server.cpp`: chỉ xóa các bản ghi lịch sử quét của workspace hiện tại, không xóa `.slug/rules.conf`, tài khoản hay cấu hình; ghi nhật ký `AUDIT_CLEAR` và trả về số lượng bản ghi đã xóa.
  - Thêm nút `Xóa Dữ Liệu Quét` trên giao diện Admin Dashboard với hộp thoại xác nhận trước khi xóa, dọn sạch dữ liệu và làm mới giao diện về trạng thái rỗng.
- [x] **Bộ lọc truy vấn SQL đa tiêu chí và phân trang cho dữ liệu audit**:
  - Bổ sung phương thức `StatefulAuditIndex::query_entries()` hỗ trợ lọc đồng thời nhiều trường thông tin: Trạng thái (`all`, `blocked`, `clean`), Loại Detector (`all`, `regex`, `entropy`, `ai`, `manual`), Đuôi tệp (`all`, `.env`, `.key`, `.json`, `.py`, `.cpp`, `.txt`), Từ khóa tìm kiếm đường dẫn / lý do (`q`), cùng phân trang `LIMIT / OFFSET`.
  - Bổ sung endpoint `GET /api/admin/audit/query` trả về tổng số bản ghi SQLite (`total`), số bản ghi khớp bộ lọc (`filtered`) và danh sách bản ghi theo trang.
  - Tích hợp thanh công cụ truy vấn SQL và thanh điều hướng phân trang (Trang trước, Trang sau, số lượng bản ghi/trang) trực tiếp vào bảng `Flagged & Quarantined Files`.

### Hạng mục P1 — Sửa trạng thái hiển thị file/folder trên Workspace Explorer
- [x] **Chuẩn hóa hiển thị cây thư mục Explorer**:
  - Trong `render_directory_listing` (`src/net/web_assets.hpp`), sửa logic nhận diện thư mục: hàng thư mục luôn hiển thị huy hiệu `DIR` (`badge-excluded`), không bị gán nhãn `AVAILABLE` sai lệch chỉ vì file con đầu tiên khả dụng.
  - Từng file con hiển thị độc lập và chính xác: `AVAILABLE` (xanh lá) nếu khả dụng tải về, hoặc `BLOCKED` (đỏ) nếu bị chặn bởi rule hoặc bộ lọc bảo mật.
  - Nút tải về (`Download`) chỉ hiển thị trên file `AVAILABLE`, ẩn hoàn toàn trên file `BLOCKED`.
  - Backend VFS duy trì bảo vệ cứng: chặn path traversal, chặn truy cập vào vùng nội bộ `.slug/` và `.git/`, thực thi policy khi tải chunk/file.

### Hạng mục P1 — Phân định rõ các loại TTL
- [x] **Rà soát và đồng bộ 4 loại TTL độc lập**:
  - `otp_ttl` / `otp_step`: chu kỳ đổi mã TOTP (mặc định 60s), form Portal gửi và backend `/api/host/start` nhận xử lý chính xác.
  - `user_ttl`: thời hạn tài khoản người dùng, lưu `expires_at` trong `.slug/acl.db`.
  - `session_ttl`: thời hạn phiên kết nối client PQC, được giới hạn không vượt quá user TTL còn lại.
  - `workspace_ttl` (`ttl`): thời gian sống của workspace host, lưu và quản lý độc lập.

### Hạng mục P2 — Rà soát SQLite amalgamation
- [x] **Kiểm tra phiên bản SQLite**:
  - Đã đối chiếu phiên bản `third_party/sqlite/sqlite3.h` và `sqlite3.c`: đang dùng phiên bản **SQLite 3.46.1** (phát hành tháng 8/2024).
  - Phiên bản ổn định, an toàn, hỗ trợ đầy đủ WAL mode, JSON và parameterized queries, tương thích hoàn toàn với kiến trúc hiện tại của dự án.

### Hạng mục Cải Tiến Toàn Diện — Khắc Phục Lỗi JavaScript, Giao Diện Responsive & Cấu Hình AI / Dynamic Scanner (Admin Dashboard)
- [x] **Khắc phục tận gốc lỗi cú pháp JavaScript gây tê liệt nút bấm Admin Dashboard**:
  - Loại bỏ hoàn toàn các ký tự `\n` chưa được escape trong các chuỗi JS của `confirm()` và `prompt()`, sửa lỗi phân tích chuỗi thoát kép `\\'` trong các thuộc tính sự kiện inline.
  - Chuyển đổi toàn bộ cơ chế gắn sự kiện hành động sang chuẩn HTML5 DOM dataset (`this.dataset.path`, `this.dataset.u`, `this.dataset.r`, `this.dataset.id`), ngăn chặn triệt để xung đột ký tự đặc biệt, dấu nháy kép/đơn hay đường dẫn chứa khoảng trắng/ký tự unicode.
  - Nút `Xóa Dữ Liệu Quét`, các nút điều hướng phân trang (`Trước`, `Sau`), các bộ lọc truy vấn SQL đa tiêu chí (`Trạng Thái`, `Detector`, `Đuôi tệp`, `Tìm kiếm`, `Limit`), nút `Whitelist`, và `Làm Mới` hoạt động trơn tru 100%, không còn bất kỳ lỗi console nào.
- [x] **Thiết kế Responsive hoàn chỉnh cho Admin Dashboard**:
  - Loại bỏ `min-width: 1040px` cố định, chuyển `.container` sang layout co giãn tự động `max-width: 1360px` với padding thích ứng.
  - Thêm media queries CSS responsive: tự động chuyển layout lưới `.grid` 2 cột sang 1 cột toàn màn hình khi chiều rộng màn hình <= 1080px (đặc biệt tối ưu khi mở DevTools cạnh bên), tự động co giãn bảng số liệu `metric-grid` từ 3 cột xuống 2 cột và 1 cột.
  - Mọi bảng dữ liệu được bọc trong `.table-scroll-container` có `overflow-x: auto` và cuộn cảm ứng di động mượt mà, modal popup tự động giới hạn `max-width: 100%`, loại bỏ hoàn toàn lỗi tràn khung ngang màn hình.
- [x] **Hoàn thiện cấu hình AI Workspace qua file `.slug/ai.json` và giao diện Form/JSON**:
  - Thẻ cấu hình AI trên Admin Dashboard hỗ trợ chuyển đổi linh hoạt 2 chế độ: Form trực quan (Provider, Model, Endpoint, API Key) và Trình chỉnh sửa trực tiếp file raw JSON (`#ai-json-raw`).
  - Hỗ trợ lưu cấu hình nguyên bản vào `.slug/ai.json` qua `POST /api/admin/ai/config` và kiểm tra kết nối AI theo thời gian thực qua `POST /api/admin/ai/test`.
  - Kết nối trực tiếp `AiScanner` với cấu hình workspace: khi khởi tạo `AiScanner::create_for_level` ở Level 4, máy chủ tự động đọc cấu hình `.slug/ai.json` của workspace tương ứng (bao gồm cả model, custom endpoint và api_key), loại bỏ hoàn toàn sự phụ thuộc vào biến môi trường cục bộ.
- [x] **Cho phép thay đổi mức lọc và quét lại trực tiếp trong Admin Dashboard (Dynamic Re-Scan)**:
  - Thêm thẻ điều khiển mức lọc trực tiếp tại Admin Dashboard với dropdown chọn 4 cấp độ lọc (Level 1, Level 2, Level 3, Level 4).
  - Nút `⚡ Áp Dụng Mức Lọc & Quét Lại Ngay` gọi `POST /api/admin/scan/run`: máy chủ cập nhật ngay tức thì `FilterLevel` runtime, xóa cache manifest, kích hoạt quét lại toàn bộ workspace và trả về kết quả số tệp khả dụng / số tệp bị cách ly.
  - Giao diện Admin Dashboard tự động cập nhật huy hiệu mức lọc đang hoạt động (`#active-filter-badge`, `#scan-status-badge`) và làm mới ngay lập tức bảng `Flagged & Quarantined Files`, cho phép người dùng thay đổi mức bảo mật tự do bất kỳ lúc nào mà không cần khởi động lại server.

### Hạng mục Cải Tiến & Sửa Lỗi Tinh Chỉnh — Đồng Hồ Thời Gian Phiên Workspace (Realtime TTL Clock) & Sửa Bộ Lọc Chi Tiết Audit
- [x] **Loại bỏ hiển thị cố định mức lọc ở Tab 2 Portal và thay thế bằng đồng hồ đếm ngược thời gian phiên Workspace**:
  - Tại Tab 2 (`renderHostedWorkspaces`), loại bỏ hoàn toàn thẻ hiển thị mức lọc cố định (`CẤP ĐỘ LỌC BẢO MẬT (CỐ ĐỊNH THEO PHIÊN)` và badge `Cố Định`) theo đúng yêu cầu người dùng, chỉ giữ cấu hình mật mã Cipher Suite.
  - Thay thế bằng **Đồng hồ thời gian sống phiên Workspace (Workspace Session TTL Clock)** `#ws-ttl-clock-${w.id}`: hiển thị thời gian sống còn lại dưới định dạng đồng hồ `HH:MM:SS` (hoặc `Vĩnh viễn (∞)` nếu TTL = 0) cùng huy hiệu trạng thái `Đang Đếm Ngược` / `Đã Hết Hạn`.
  - Bộ đếm thời gian realtime `setInterval` tự động trừ lùi mỗi 1 giây trong background và cập nhật trực tiếp lên giao diện DOM, tự động đổi màu cảnh báo đỏ khi phiên kết thúc.
  - Đồng thời bổ sung hiển thị và bộ đếm realtime thời gian sống của workspace (`#ws-admin-ttl-badge`) trong thẻ `Active Server Workspace` trên trang Admin Dashboard `/admin`.
- [x] **Sửa tận gốc lỗi truy vấn SQL khiến bảng Audit chỉ hiển thị tệp CLEAN và không hiển thị tệp bị chặn**:
  - **Phát hiện Root Cause**: Trong `src/ai/stateful_audit.cpp`, hàm `list_flagged_or_all` và `query_entries` truy vấn `WHERE status IN (1, 2, 5)` và gán clean là `status = 0`. Tuy nhiên trong enum `core::AuditStatus`, `CLEAN = 1`, `AI_FLAGGED = 2`, `RULE_BLOCKED = 5`, `SMART_FILTER_FLAGGED = 6`, `UNKNOWN = 0`. Do đó, câu lệnh cũ vô tình gom toàn bộ file `CLEAN` (`status = 1`) vào danh sách bị chặn và bỏ sót `SMART_FILTER_FLAGGED` (`status = 6`), trong khi bộ lọc `Clean` truy vấn `status = 0` nên trả về 0 kết quả. Ngoài ra, frontend gửi `status=blocked` không khớp với chuỗi `"quarantined"` khiến backend bỏ qua bộ lọc và trả về toàn bộ database.
  - **Sửa triệt để**:
    - Sửa câu SQL trong `list_flagged_or_all`: chuẩn hóa thành `WHERE status IN (2, 5, 6)` (chỉ lấy đúng các tệp bị cách ly bởi AI Guard, Manual/Policy Rule và Smart Regex).
    - Sửa `query_entries`: hỗ trợ cả `blocked` và `quarantined` ánh xạ về `status IN (2, 5, 6)`; ánh xạ `clean` về `status = 1`; ánh xạ `allowed` / `whitelisted` về `status = 4`; ánh xạ `rule` / `manual` về `status = 5`.
    - Sửa điều kiện detector filter để `status = 1` không bị nhận diện nhầm thành AI.
    - Cập nhật `web_server.cpp` khi khởi tạo trang Admin Dashboard gọi `list_flagged_or_all(true)` thay vì `false`, đảm bảo bảng ban đầu chỉ hiển thị tệp bị cách ly, loại bỏ hoàn toàn các tệp CLEAN khỏi bảng `Flagged & Quarantined Files`.

### Hạng mục Khắc Phục Lỗi Logic Client Linux, Quản Lý Phiên Kết Nối, Phân Quyền RBAC & Giới Hạn Tải Nén ZIP
- [x] **Khắc phục lỗi xác thực vai trò người dùng (RBAC User Authentication)**:
  - **Nguyên nhân**: `SlugClient::authenticate_user` trước đây gán cứng yêu cầu quyền `"rw"`, khiến các tài khoản được cấp quyền chỉ đọc (`r`) hoặc chỉ ghi (`w`) như `r/r`, `w/w` luôn bị máy chủ từ chối với thông báo `[AUTH_USER_FAIL] ... Invalid credentials or expired`.
  - **Khắc phục**: Chuyển tham số `required_role` trong `AclManager::authenticate` thành `std::optional<Role>`, mặc định kiểm tra hợp lệ tài khoản và thời hạn mà không áp đặt vai trò; cập nhật `control_server.cpp` và `SlugClient` cho phép người dùng đăng nhập tự do với bất kỳ vai trò hợp lệ nào (`r`, `w`, `rw`).
- [x] **Khắc phục triệt để lỗi bỏ qua thu hồi phiên (Kill Session Bypass)**:
  - **Nguyên nhân**:
    - Khi Admin bấm "Thu hồi phiên (Kill Session)", `ControlServer::revoke_session` chỉ đánh dấu `is_revoked = true` trong map nội bộ của ControlServer mà không báo hiệu sang `WebServer` để hủy `session_ticket`.
    - Vòng lặp `http_tunnel` trong `ControlServer` trước đây không kiểm tra trạng thái của `cur_session_id`, khiến client vẫn gửi được các request tunneled HTTP.
    - Trong `WebServer::dispatch_http_core`, điều kiện `is_localhost` trước đây bao gồm cả `tunneled_session_id > 0`, và khi phát hiện cookie bị hủy, hệ thống tự động gán quyền `host_admin` cho localhost loopback thay vì chặn truy cập.
  - **Khắc phục**:
    - `ControlServer::revoke_session` và `revoke_sessions_by_identity` đồng bộ ngay lập tức sang `WebServer` qua `revoke_session_by_ticket` và `revoke_sessions_by_identity`.
    - Vòng lặp `http_tunnel` kiểm tra nghiêm ngặt `get_session(cur_session_id)`. Nếu phiên đã bị thu hồi hoặc hết hạn, gửi ngay HTTP 401 Session Revoked và ngắt kết nối socket (`break`).
    - `WebServer::dispatch_http_core` tách bạch `is_tunneled` và `is_localhost`. Thiết lập Strict Gatekeeper: nếu phiên đã bị thu hồi, trả về ngay HTTP 401 Unauthorized kèm trang cảnh báo tiếng Việt và xóa sạch cookie, tuyệt đối không bao giờ nhận `host_admin`.
    - `cmd_portal` tại client khi nhận phản hồi 401 hoặc Session Revoked qua HTTP tunnel tự động reset `client` và xóa bản ghi kết nối khỏi `ConnectionManager`.
- [x] **Sửa tận gốc lỗi Pull và Upload trên client Linux khi kết nối máy chủ Windows qua PQC Portal**:
  - **Nguyên nhân**:
    - Khi người dùng truy cập web Portal tại client (`http://127.0.0.1:8080/drop`), các endpoint thực thi hệ thống tệp cục bộ `/api/pull/execute`, `/api/pull/dry-run`, `/api/fs/upload-local-path` trước đây bị forward qua kênh `tunnel_http` sang máy chủ Windows.
    - Hệ quả: Máy chủ Windows nhận đường dẫn Linux (vd `/home/nguyenduccanh/...`), tự tạo thư mục và ghi toàn bộ 3727 tệp lên đĩa của máy chủ Windows rồi báo thành công, trong khi đĩa của client Linux không hề có tệp nào; tương tự, tải tệp từ máy client lên bị máy chủ báo lỗi `Đường dẫn không tồn tại trên máy`.
  - **Khắc phục**:
    - Bổ sung xử lý trực tiếp ngay tại local client bên trong `cmd_portal` (`src/main.cpp`):
      * `GET /api/pull/dry-run`: Lấy manifest từ trạm từ xa qua `g_portal.client->fetch_manifest()`, tính toán kế hoạch vi sai FastCDC/BLAKE3 ngay trên thư mục đích của máy client và trả kết quả dry-run.
      * `POST /api/pull/execute`: Gọi trực tiếp `g_portal.client->pull(target_dir, opts, nullptr, manifest_opt)`, kéo toàn bộ các tệp vi sai từ xa về ghi trực tiếp vào đúng thư mục đích trên đĩa của máy client.
      * `POST /api/fs/upload-local-path`: Đọc tệp/thư mục cục bộ từ đĩa của client và đẩy lên workspace từ xa qua `g_portal.client->push()`.
      * Các thao tác `/api/fs/pick-file`, `/api/fs/pick-folder`, `/api/fs/open-folder`, `/api/fs/open-file` được xử lý native ngay trên hệ điều hành của client.
- [x] **Khắc phục lỗi nén ZIP trực tiếp thư mục dung lượng lớn (441 MB)**:
  - **Nguyên nhân**: Kênh mã hóa khung lượng tử AEAD (`AeadFrameChannel`) áp đặt giới hạn bảo vệ tối đa 16 MB/frame (`cipher_len > 16*1024*1024`). Việc nén toàn bộ thư mục 441 MB vào một khối ZIP đơn khối trong bộ nhớ vượt quá giới hạn khung, khiến socket ngắt kết nối và client nhận lỗi `Error: Remote Post-Quantum workspace failed to respond`.
  - **Khắc phục**: Trong `WebServer` `/download-folder`, tính toán trước tổng dung lượng thư mục. Nếu vượt quá 12 MB, trả về mã HTTP 413 Payload Too Large với giao diện thông báo tiếng Việt rõ ràng, giải thích giới hạn đóng gói của kênh khung AEAD và hướng dẫn người dùng chuyển sang sử dụng tính năng "ĐỒNG BỘ THƯ MỤC VỀ MÁY BẠN (PULL)" để đồng bộ toàn bộ workspace an toàn với phân luồng vi sai và mã băm BLAKE3.
- [x] **Chuẩn hóa danh sách các kết nối gần đây (Recent Connections - Tab 1)**:
  - **Nguyên nhân**: Khi kết nối qua `/api/portal/connect`, các trường `ci.workspace`, `ci.identity`, `ci.auth_type`, `ci.expires_at` trước đây không được ghi nhận vào `ConnectionInfo`, dẫn đến việc hiển thị thời hạn `Permanent (∞)` sai lệch, mất tên workspace và loại xác thực.
  - **Khắc phục**:
    - Lưu đầy đủ thông tin định danh (`identity`), loại xác thực (`auth_type`), tên workspace và timestamp hết hạn (`expires_at`) vào `.slug/connections.json`.
    - Hiển thị rõ ràng huy hiệu xác thực: `TOTP [rw]`, `Acc: <username>`, và đồng hồ đếm ngược `Còn HH:MM:SS` với thuộc tính `data-exp`, tự động trừ lùi thời gian sống theo từng giây trong thời gian thực.
    - Khi người dùng bấm "Duyệt Thư Mục" vào một kết nối đã bị thu hồi hoặc hết hạn, `/api/portal/open` tự động xóa kết nối đã chết khỏi danh sách và trả về thông báo lỗi rõ ràng.