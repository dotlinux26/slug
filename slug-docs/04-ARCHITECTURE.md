# 04. Kiến trúc hệ thống, giao thức và bảo mật

> **Trạng thái tài liệu:** Thiết kế đề xuất để triển khai và kiểm thử. Các luồng, cấu trúc header và quy tắc dưới đây là đặc tả sơ bộ; cần được đóng băng thành protocol version, kèm test vector, review mật mã và fuzzing trước khi dùng thực tế.

## 1. Mục tiêu kiến trúc

Slug tổ chức thành các lớp tách biệt:

1. **CLI / GUI:** thao tác tạo share, ACL, rule, audit và pull/push.
2. **Workspace Manager:** cấu hình từng workspace, đường dẫn gốc, cổng, trạng thái server.
3. **Identity & Authorization:** xác thực, role `r/w/rw`, TTL, session revocation.
4. **Policy Engine:** `.gitignore`, `rules.conf`, trạng thái AI Guard và chính sách bắt buộc.
5. **Crypto Layer:** suite negotiation, xác thực handshake, trao đổi khóa, key derivation, AEAD.
6. **Control Plane:** handshake, manifest, ACL decisions, transfer negotiation.
7. **Data Plane:** truyền tệp/khối, ACK/retry, chống replay và kiểm tra hash.
8. **State Store & Audit:** ACL, scan index, manifest epoch, audit events.

Mỗi lớp cần có API rõ ràng và được kiểm thử độc lập. Không để GUI quyết định quyền truy cập thay cho server; không để AI quyết định quyền vượt qua policy engine.

## 2. Mô hình tin cậy

### Thành phần được tin cậy theo thiết kế

- Thư viện mật mã và bộ sinh số ngẫu nhiên được lựa chọn, cấu hình đúng.
- Host OS và tài khoản chạy Slug ở mức quyền đã công bố.
- Public key/fingerprint server được client xác minh bằng cơ chế trust-on-first-use có xác nhận hoặc enrollment đáng tin.
- Policy engine và state store không bị sửa trái phép.

### Thành phần không được tin cậy

- Mạng LAN/WAN, gói tin UDP/TCP đến từ mạng và metadata chưa xác thực.
- Client chưa được xác thực.
- Tên tệp, đường dẫn và nội dung workspace.
- Nội dung do AI phân tích.
- Manifest chưa được xác thực/chưa gắn với request hiện tại.
- Metadata cache cũ khi nội dung hoặc phiên bản scanner đã thay đổi.

### Các giới hạn quan trọng

Mã hóa đường truyền không bảo vệ endpoint bị chiếm quyền, host chạy mã độc, secret đã bị log hoặc người dùng có quyền đọc bộ nhớ. Hệ thống cũng không tự ngăn được mọi kiểu tấn công relay chỉ bằng nonce, chữ ký hay ngưỡng RTT.

## 3. Crypto Suite và vai trò các thuật toán

| Suite | Hash/transcript | Định danh chữ ký | Thiết lập khóa | Dữ liệu |
|---|---|---|---|---|
| `0x01 classical` | SHA-256 | Ed25519 | X25519 | XChaCha20-Poly1305 |
| `0x02 modern` | BLAKE3 | Ed25519 | X25519 | XChaCha20-Poly1305 |
| `0x03 pure-pqc` | BLAKE3 | ML-DSA-65 | ML-KEM-768 | XChaCha20-Poly1305 |

FIPS 203 định nghĩa ML-KEM; FIPS 204 định nghĩa ML-DSA. ML-KEM thiết lập bí mật chung, ML-DSA ký/xác minh dữ liệu. Suite 1 và 2 chứa X25519/Ed25519 nên không được gọi là hậu lượng tử. Suite 3 tránh các thành phần public-key cổ điển trong handshake, nhưng vẫn phụ thuộc cách triển khai, quản lý khóa, entropy, thư viện và chính sách phiên.

XChaCha20-Poly1305 dùng nonce 192-bit. Mỗi key phải có kế hoạch nonce duy nhất và key phải được phân tách theo phiên, hướng gửi và mục đích. Không dùng một key/nonce stream chung cho hai hướng dữ liệu. Khóa phiên được dẫn xuất qua một KDF phù hợp với shared secret, salt và transcript; không dùng BLAKE3 hoặc ML-KEM thay thế AEAD.

## 4. Luồng handshake đề xuất

Giao thức cần có version, suite ID, identity/fingerprint và transcript được xác thực để chống downgrade.

1. **ClientHello:** version được hỗ trợ, suite được hỗ trợ, nonce ngẫu nhiên của client, ephemeral key hoặc thông tin cần cho KEM, capability và giới hạn giao thức.
2. **ServerHello:** suite được chọn, nonce ngẫu nhiên của server, danh tính/fingerprint server và thông tin khóa công khai cần thiết.
3. **Xác minh server:** client xác minh chữ ký/identity của server trên thông điệp handshake và suite được thương lượng. Trust-on-first-use phải hiển thị fingerprint và cho phép xác nhận; không âm thầm tin mọi key mới.
4. **Thiết lập bí mật chung:** Suite 1/2 dùng X25519; Suite 3 dùng ML-KEM-768. Trong suite 3, client encapsulate tới public key ML-KEM của server và chuyển ciphertext KEM; server decapsulate để lấy cùng shared secret.
5. **Dẫn xuất khóa:** hai bên tính transcript hash trên encoding canonical của toàn bộ handshake và dẫn xuất các key độc lập cho client→server, server→client, control và data.
6. **Xác thực người dùng:** sau khi kênh đã bảo mật, client hoàn thành thử thách TOTP hoặc xác thực tài khoản. Mã ngắn không được coi là bí mật đủ mạnh để làm key encryption hoặc làm đầu vào cho một bằng chứng có thể kiểm tra ngoại tuyến.
7. **Cấp quyền phiên:** server tạo session authorization record/ticket chứa `workspace_id`, role, `expires_at`, session ID và hash của khóa công khai ephemeral của client. Ticket phải được xác minh và ràng buộc với đúng session/credential; tên “certificate” chỉ nên dùng nếu có định dạng chứng chỉ và quy trình quản lý chứng chỉ thực sự.
8. **Thiết lập Data Plane:** hai bên xác nhận phiên và key epoch trước khi gửi manifest hoặc chunk.

Transcript binding ngăn một bằng chứng của phiên cũ được chuyển nguyên xi sang một transcript khác nếu mọi trường được xác thực đúng. Nó không thay thế kiểm soát rate, bảo vệ credential, kiểm tra TTL hoặc quản lý danh tính server.

## 5. TOTP 8 số và one-time consumption

Nếu mã 8 số được sinh theo cơ chế TOTP, một mã có thời gian sống ngắn nhưng có thể bị đoán hoặc replay trong cửa sổ hợp lệ nếu hệ thống không lưu trạng thái. Slug bổ sung chính sách tiêu thụ một lần:

- Tạo `token_id` hoặc xác định time-step TOTP.
- Khi xác thực thành công, trong một giao dịch nguyên tử, đánh dấu token/time-step đã dùng và gắn với session vừa được cấp.
- Các yêu cầu cạnh tranh không được đồng thời nhận quyền.
- Giới hạn tốc độ, khóa tạm thời/backoff và ghi audit cho lần thử thất bại.
- Xác thực diễn ra bên trong kênh bảo mật và ràng buộc với challenge/session hiện tại.
- Token đã tiêu thụ không được dùng để cấp một session khác; token hết hạn không được chấp nhận.

Không được tính `AuthProof = HMAC(TOTP, transcript)` như thể TOTP là một khóa ngẫu nhiên dài: không gian 8 chữ số đủ nhỏ để tạo rủi ro đoán ngoại tuyến nếu thiết kế làm lộ một bộ kiểm tra. Dùng cơ chế xác thực đã được thiết kế cho mã ngắn, hoặc chuyển mã vào kênh bảo mật rồi kiểm tra ở server với rate-limit và one-time state.

## 6. Chống Replay ở tầng điều khiển

### Transcript và request binding

Handshake dùng nonce ngẫu nhiên mới cho từng bên, transcript hash và signature/MAC theo giao thức. Mọi thông điệp nhạy cảm như AuthProof, yêu cầu manifest hoặc xác nhận transfer gắn với session ID và challenge tương ứng.

### Manifest epoch

Mỗi workspace duy trì `manifest_epoch` tăng đơn điệu và `tree_root_hash`. Manifest được ký bởi khóa danh tính server và bao gồm tối thiểu:

- `protocol_version`, `workspace_id`, `manifest_epoch`;
- `request_nonce` hoặc transfer challenge của client;
- `tree_root_hash`, thời điểm/tính hiệu lực theo chính sách;
- phiên bản/hàm hash/ruleset có liên quan;
- danh sách mục được phép công bố và hash tương ứng.

Client kiểm tra chữ ký, workspace identity, request nonce và epoch đã lưu. Epoch nhỏ hơn epoch đã tin cậy là dấu hiệu rollback. Cùng epoch nhưng root hash khác nhau là bất thường và cần từ chối hoặc xử lý theo quy trình phục hồi. Manifest lặp lại đúng cho cùng một request không nhất thiết phải bị cấm về mặt tuyệt đối; điều cần ngăn là manifest cũ được chấp nhận như trạng thái mới của workspace.

Để epoch hữu ích qua lần restart, host phải lưu trạng thái bền vững và xử lý phục hồi/backup có xác thực. Epoch không tự bảo vệ được client vừa mất toàn bộ state tin cậy; client cần pin identity và có chính sách bootstrap.

## 7. Chống Replay trong UDP Data Plane

### 7.1. Nguyên tắc

Mỗi datagram được bảo vệ bằng AEAD với key theo phiên/hướng truyền, nonce duy nhất và header quan trọng đưa vào AAD. Receiver kiểm tra tính hợp lệ trước khi cập nhật trạng thái anti-replay, tránh để kẻ tấn công gửi gói có sequence giả lớn làm trượt cửa sổ.

### 7.2. Trường gói đề xuất

Ví dụ header logic (độ dài/encoding cần được cố định trong protocol spec):

| Trường | Mục đích |
|---|---|
| `version/type` | Version và loại thông điệp |
| `session_id` | Phiên đã xác thực |
| `transfer_id` | Transfer đang diễn ra |
| `packet_seq` | Số thứ tự 64-bit theo hướng/key |
| `chunk_index` | Khối logic thuộc tệp nào |
| `flags` | Cờ có quy định rõ |
| `ciphertext` | Payload được mã hóa |
| `tag` | Tag xác thực do AEAD tạo |

Độ dài datagram thực tế phải nằm trong giới hạn MTU/PMTU. “Chunk file 64 KiB” là khối logic của tệp, **không có nghĩa** gửi một UDP datagram 64 KiB; một chunk logic có thể được phân thành nhiều datagram nhỏ để tránh IP fragmentation.

### 7.3. Nonce và AAD

Một phương án là nonce 24 byte = `session_salt[16] || packet_seq[8]`, với điều kiện:

- salt được tạo ngẫu nhiên và session key riêng biệt;
- `packet_seq` không lặp trong cùng key/hướng;
- hai hướng dùng key hoặc miền nonce riêng;
- key không được dùng lại sau khi reset sequence;
- mã hóa header canonical vào AAD để ràng buộc các trường điều khiển với ciphertext.

Nếu encoding số nguyên, endian và cách serialize không được chuẩn hóa, hai bên có thể tính AAD khác nhau hoặc diễn giải header không nhất quán.

### 7.4. Sliding window

Receiver có thể dùng bitmap 64-bit cho một cửa sổ 64 sequence gần nhất, hoặc cửa sổ lớn hơn nếu độ lệch thứ tự của mạng yêu cầu. Quy trình:

1. Kiểm tra phiên/key epoch và loại gói.
2. Có thể bỏ sớm sequence quá cũ/đã thấy theo trạng thái đã xác thực hiện có.
3. Xác minh AEAD tag.
4. Chỉ sau khi xác minh thành công mới cập nhật `highest_seq` và bitmap.
5. Nếu là duplicate/old packet thì bỏ và không ghi dữ liệu lần hai.
6. Với sequence ngoài cửa sổ do gói hợp lệ đến quá lệch thứ tự, yêu cầu retry qua ARQ hoặc xử lý bằng cửa sổ phù hợp.

Cửa sổ replay không tự bảo đảm truyền tin cậy. Data Plane cần selective ACK, timeout, retry có giới hạn, congestion control, tránh queue vô hạn và logic khôi phục transfer.

## 8. Relay: điều gì có và không thể bảo đảm

Channel binding có thể gắn bằng chứng xác thực vào transcript, khóa ephemeral, session ID và identity server; điều này hạn chế việc chuyển credential/ticket giữa các phiên không tương thích. Pinning danh tính server và xác minh chữ ký cũng giúp phát hiện server giả.

Tuy nhiên, **một relay trong suốt có thể chuyển tiếp nguyên vẹn các gói live giữa client và server thật mà không cần giải mã**. Chống replay không tự ngăn kiểu relay này. Địa chỉ IP/endpoint có thể dùng như tín hiệu chính sách hoặc audit nhưng không phải bằng chứng danh tính mạnh, nhất là qua NAT, roaming hoặc VPN. RTT threshold (ví dụ ngưỡng 15 ms) không phải cơ chế chống relay đáng tin cậy vì độ trễ biến động và relay ở gần có thể đáp ứng ngưỡng.

Vì vậy, Slug nên tuyên bố theo mức có thể kiểm chứng:

- chống phát lại thông điệp xác thực cũ bằng challenge/transcript/session binding;
- ngăn dùng lại datagram đã xác thực trong cửa sổ replay;
- xác minh danh tính server theo key/fingerprint đã tin cậy;
- phát hiện rollback manifest dựa trên epoch/root hash đã lưu;
- không tuyên bố loại bỏ mọi live relay. Nếu cần chống relay theo khoảng cách, cần giao thức distance-bounding hoặc giả định mạng/phần cứng bổ sung được thiết kế và đánh giá riêng.

## 9. Manifest, Delta Sync và selective pull

### 9.1. Manifest an toàn

Server tạo manifest từ tập tệp đã qua ACL và Policy Engine. Trước khi công bố, Slug áp dụng các quy tắc loại trừ tệp nội bộ, `.gitignore`, `rules.conf`, trạng thái AI audit và các giới hạn quyền. Manifest không được tiết lộ metadata mà client không có quyền xem.

Mỗi entry có thể chứa `relative_path`, `size`, `mtime` mang tính thông tin, hash nội dung, hash theo khối nếu có và trạng thái. Root hash của manifest cần được tính trên encoding canonical, có version và được ký/gắn với request challenge.

### 9.2. Đối chiếu client

1. Client yêu cầu manifest mới với challenge ngẫu nhiên.
2. Server xác thực quyền và trả manifest đã ký, chỉ bao gồm các mục client được phép thấy.
3. Client xác minh server signature, challenge, epoch và root hash.
4. Client tính/đối chiếu hash của tệp hiện có.
5. Tệp khớp hash được bỏ qua; tệp mới/đã đổi được đưa vào hàng đợi transfer.
6. Với tệp lớn có hash khối, chỉ khối khác biệt được yêu cầu.
7. Sau khi nhận dữ liệu, client xác minh hash của khối và hash toàn tệp trước khi thay thế nội dung đích.
8. Dùng ghi tạm và atomic rename khi phù hợp để tránh file đích bị hỏng khi transfer gián đoạn.

### 9.3. Chiến lược chia khối

Fixed-size chunk dễ triển khai và phù hợp để làm MVP. Nhược điểm là chèn bytes ở đầu file có thể làm thay đổi ranh giới nhiều chunk phía sau. Với mục tiêu tiết kiệm băng thông cho tệp lớn thay đổi nhỏ, có thể cân nhắc content-defined chunking (CDC). Đây là phần tăng độ phức tạp cần benchmark và đánh giá rủi ro hash/index.

### 9.4. Các cờ đồng bộ

```bash
slug pull --dry-run
slug pull --only "src/core/**"
slug pull --ext ".cpp,.hpp,.md"
slug pull --max-size 50MB
slug pull --prune
```

`--prune` có tính phá hủy: chỉ chạy khi người dùng yêu cầu rõ, hiển thị danh sách xóa trước và tránh xóa dữ liệu không thuộc phạm vi được quản lý. Cần xác định rõ các file local chưa thuộc manifest, file bị ignore và file đã bị server thu hồi sẽ được xử lý khác nhau thế nào.

## 10. Path confinement và truyền tệp an toàn

- Giải quyết mọi đường dẫn theo root share; từ chối đường dẫn tuyệt đối, `..` thoát root, ADS/đặc tính riêng của filesystem không được hỗ trợ và tên không hợp lệ.
- Không dựa duy nhất vào nối chuỗi đường dẫn hoặc `weakly_canonical()`. Phải xử lý symlink, TOCTOU và khác biệt Windows/Linux ở bước mở/ghi file.
- Không theo symlink ra ngoài root theo mặc định; phải có chính sách rõ cho symlink nội bộ.
- Kiểm tra ACL ở mọi thao tác list/read/write/delete.
- Đặt giới hạn số tệp, độ sâu, tổng kích thước, kích thước từng tệp, tốc độ, bộ nhớ và thời gian xử lý.
- Ghi file nhận vào thư mục tạm, xác minh hash rồi mới commit.
- Dùng tên đích đã chuẩn hóa; không cho overwrite file tùy ý nếu policy/role không cho phép.
- Có audit cho upload, download, delete và rule override.

## 11. Trạng thái AI và tính nhất quán lúc truyền

`index.db` lưu trạng thái audit gắn với hash nội dung. Tại thời điểm truyền, server phải kiểm tra rằng hash của nội dung thực gửi khớp hash đã được quét và trạng thái còn hiệu lực. Nếu khác, chuyển `STALE` và dừng chia sẻ nội dung đó cho đến khi recheck hoặc ngoại lệ rõ ràng được phê duyệt.

Khi một tệp bị chặn, server có thể bỏ qua tệp trong transfer batch nhưng phải gửi summary chính xác về `skipped`/reason, không giả báo “full success”. Đối với folder pull, client cần nhận manifest cuối/transfer result để biết danh sách file nào thiếu do policy, file nào thất bại vì lỗi mạng.

## 12. `slug env` — envelope encryption và giới hạn runtime

Thiết kế cần phân tách ba việc:

1. **Mã hóa nội dung:** sinh DEK ngẫu nhiên và dùng AEAD mã hóa dữ liệu `.env`.
2. **Bảo vệ DEK:** bọc DEK bằng key được quản lý theo recipient/local identity. Nếu sử dụng ML-KEM-768, KEM tạo shared secret để dẫn xuất wrapping key; không mã hóa trực tiếp plaintext `.env`.
3. **Xác thực metadata:** chữ ký ML-DSA-65 có thể xác minh metadata/nguồn phát hành nếu có quy trình quản lý khóa ký rõ ràng. Chữ ký không thay thế mã hóa và không tự bảo đảm bí mật.

`slug env run -- command` giải mã vào bộ nhớ rồi đưa giá trị cho tiến trình đích. Không ghi file plaintext ra đĩa là mục tiêu tốt, nhưng không bảo đảm secret vô hình với mọi AI Agent hoặc người có đặc quyền hệ điều hành. Tiến trình đích cần đọc secret, nên secret tồn tại trong RAM và môi trường của nó; log, crash dump, process inspection hoặc tiến trình con có thể tạo bề mặt rò rỉ. Tài liệu cần định nghĩa cách xử lý lỗi, xóa bộ nhớ best-effort, key rotation, backup/recovery và quy tắc quyền file.

## 13. Web GUI và khả năng truyền

Frontend React chạy trong trình duyệt không thể mở raw UDP socket tùy ý. Có các phương án kiến trúc:

- GUI dùng HTTPS/WebSocket với server và chuyển file qua giao thức web; phù hợp cho MVP.
- Native CLI/helper thực hiện UDP transfer, GUI chỉ điều khiển helper qua một kênh localhost đã xác thực.
- Dùng WebTransport/HTTP/3 nếu mục tiêu nền tảng, server và trình duyệt thực sự hỗ trợ.

Phải chọn một phương án cụ thể trong implementation spec và kiểm thử origin/authentication, CORS, CSRF nếu có cookie, binding localhost, xác thực helper và giới hạn upload. Không nên mô tả browser UI như thể tự gửi các datagram UDP của giao thức native.

## 14. Threat model và kiểm thử bắt buộc

| Nhóm tấn công | Biện pháp đề xuất | Kiểm thử tối thiểu |
|---|---|---|
| Nghe lén/sửa gói | AEAD và xác minh danh tính | Bắt gói, sửa ciphertext/header, xác minh lỗi tag |
| Replay handshake | Nonce, transcript, one-time state | Phát lại ClientHello/AuthProof cũ |
| Replay datagram | Sequence + sliding window + AEAD | Gửi lại gói đúng, gói cũ, gói out-of-order |
| Giả mạo manifest | Chữ ký, request challenge, epoch/root hash | Sửa manifest, phát manifest cũ, đổi root cùng epoch |
| Downgrade suite | Xác thực negotiated suite trong transcript | Sửa suite ID và ép fallback |
| Lạm quyền/TTL | Kiểm tra server-side mỗi operation | Tài khoản hết hạn, bị thu hồi, `w` thử đọc |
| Path traversal/symlink | Confinement và mở file an toàn | `../`, symlink, race lúc thay đường dẫn |
| Rò secret | Static rules, AI Guard, skip có audit | Secret thường gặp, false positive, đổi file sau scan |
| AI prompt injection | Mô hình là dữ liệu không tin cậy | Chỉ dẫn độc hại trong source/comment |
| Delta corruption | Hash khối và hash toàn file | Chunk thiếu/sai thứ tự/bị đổi/transfer bị ngắt |
| DoS tài nguyên | Giới hạn, rate limiting, queue có bound | Tệp quá lớn, số lượng tệp lớn, nhiều client |
| Relay thời gian thực | Channel binding hạn chế tráo phiên; giới hạn tuyên bố | Relay transparent thử nghiệm; ghi nhận giới hạn mô hình |

## 15. Kế hoạch triển khai và tiêu chí nghiệm thu

### Giai đoạn A — Core transfer
- Tạo/đóng share, đường dẫn confinement, ACL `r/w/rw`, TTL và audit log.
- Truyền tải qua một giao thức bảo mật đã chọn; có test upload/download.
- Kiểm thử traversal, symlink và thu hồi quyền.

### Giai đoạn B — Crypto protocol
- Chốt serialization, suite negotiation, identity verification và key derivation.
- Dùng thư viện mật mã được duy trì; không tự sáng tạo thuật toán.
- Có test vector, downgrade test, replay test, fuzz parser và benchmark.

### Giai đoạn C — Policy và AI Guard
- Parser `.gitignore` với phạm vi tương thích được ghi rõ.
- `rules.conf`, hash index, trạng thái `STALE`, recheck và override có audit.
- Test file thay đổi giữa quét và gửi.

### Giai đoạn D — Manifest/Delta
- Manifest xác thực, dry-run, selective pull và hash toàn tệp.
- Delta theo chunk, phục hồi transfer và tránh ghi file đích chưa xác minh.
- Benchmark lượng byte thực gửi giữa bản mới và bản cập nhật.

### Giai đoạn E — UDP data plane và EnvShield
- Chỉ triển khai sau khi Data Plane có framing, MTU, ACK/retry, congestion control và chống replay được xác định.
- Với EnvShield, chốt key ownership, envelope format, backup/recovery, rotation và threat model runtime.

**Tiêu chí nghiệm thu:** tính năng chỉ được coi là hoàn thành khi có mã nguồn, test tự động và kết quả kiểm thử/benchmark phù hợp. Hồ sơ dự thi phải phân biệt các phần đã triển khai, đang phát triển và là lộ trình.

## 16. Tài liệu tham chiếu

- NIST, **FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)**: https://csrc.nist.gov/pubs/fips/203/final
- NIST, **FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)**: https://csrc.nist.gov/pubs/fips/204/final
- IETF, **RFC 6238: TOTP — Time-Based One-Time Password Algorithm**: https://www.rfc-editor.org/rfc/rfc6238
- Git, **gitignore documentation**: https://git-scm.com/docs/gitignore
- IETF CFRG, **XChaCha: eXtended-nonce ChaCha and AEAD_XChaCha20_Poly1305 (Internet-Draft)**: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

Các tài liệu tham chiếu mô tả primitive hoặc hành vi liên quan; chúng không tự chứng minh rằng giao thức Slug đã được triển khai đúng hoặc được đánh giá an toàn.
