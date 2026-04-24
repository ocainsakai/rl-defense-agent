# Tài liệu nguồn — Sơ đồ Schematic Model: Hệ thống phòng thủ mạng dựa trên học tăng cường

## Yêu cầu sơ đồ cần vẽ

Tài liệu này cung cấp thông tin để vẽ **Sơ đồ Schematic Model** (sơ đồ mô hình tổng thể) cho đồ án tốt nghiệp. Sơ đồ cần thể hiện:

### Mục tiêu chính
Trình bày **toàn bộ luồng dữ liệu** của hệ thống phòng thủ mạng dựa trên học tăng cường — từ lúc lưu lượng mạng đi vào hệ thống cho đến khi hành động phòng thủ được thực thi, bao gồm cả vòng phản hồi kín.

### Các thành phần cần có trên sơ đồ

1. **Hạ tầng mạng vật lý** (mục 2): Sơ đồ mạng gồm 4 node (Attacker, Router, Webserver, Honeypot) với địa chỉ IP và kết nối giữa chúng. Router là trung tâm, nơi đặt cả NIDS và tường lửa.

2. **Pipeline xử lý dữ liệu** (mục 3): Chuỗi 9 giai đoạn biến đổi dữ liệu, mỗi giai đoạn cần thể hiện:
   - Dữ liệu đầu vào (dạng gì, bao nhiêu chiều)
   - Phép biến đổi (gom, trích xuất, chuẩn hóa, bổ sung)
   - Dữ liệu đầu ra (dạng gì, bao nhiêu chiều)
   - Điểm nhấn quan trọng: **dữ liệu thay đổi dạng** tại mỗi giai đoạn (bytes → cấu trúc → luồng → vector 20D → vector 34D → hành động → lệnh tường lửa)

3. **3 vòng phản hồi** (mục 4): Vẽ rõ 3 vòng lặp lồng nhau:
   - Vòng suy luận thời gian thực (1 giây/chu kỳ)
   - Vòng phản hồi hiệu quả (trễ 1 bước, từ nginx log)
   - Vòng học liên tục (theo đợt, thu thập → gán nhãn → huấn luyện lại)

4. **Cơ chế leo thang** (mục 5): Thể hiện quá trình Agent tích lũy bằng chứng qua honeypot trước khi được phép chặn — đây là điểm đặc trưng của thiết kế.

5. **Không gian hành động** (mục 3, giai đoạn 8-9): 4 hành động phòng thủ (Cho phép / Giới hạn tốc độ / Chuyển hướng / Chặn) và hiệu ứng tương ứng trên tường lửa.

### Phong cách sơ đồ
- Ưu tiên **logic luồng dữ liệu**, không cần chi tiết triển khai kỹ thuật (không cần code, tên hàm, tên file)
- Dùng mũi tên có chú thích để mô tả dữ liệu di chuyển giữa các khối
- Phân biệt rõ **luồng chính** (đường liền) và **vòng phản hồi** (đường đứt nét)
- Ghi chú thuật ngữ song ngữ Anh-Việt tại các khối quan trọng
- Bảng thuật ngữ tham chiếu ở mục 10 giải thích tất cả thuật ngữ sử dụng

### Dữ liệu chi tiết bên dưới

Toàn bộ thông tin cần thiết để vẽ chính xác sơ đồ nằm trong 10 mục bên dưới. Đặc biệt chú ý:
- **Mục 2**: Topo mạng và địa chỉ IP
- **Mục 3**: 9 giai đoạn biến đổi dữ liệu (phần quan trọng nhất)
- **Mục 4**: 3 vòng phản hồi kín
- **Mục 5**: Cơ chế leo thang (điểm đặc trưng thiết kế)
- **Mục 9**: Tóm tắt luồng dữ liệu dạng ống (bản tổng hợp nhanh)
- **Mục 10**: Bảng thuật ngữ (dùng để ghi chú trên sơ đồ)

---

## 1. Tổng quan hệ thống

Hệ thống gồm 3 thành phần chính hoạt động nối tiếp nhau:

- **NIDS** (Network Intrusion Detection System — Hệ thống phát hiện xâm nhập mạng): Có nhiệm vụ thu thập lưu lượng mạng, phân tích từng gói tin, gom chúng thành luồng dữ liệu theo thời gian, và trích xuất 20 chỉ số hành vi từ mỗi luồng. Kết quả được ghi ra file JSONL.
- **RL Agent** (Reinforcement Learning Agent — Tác tử học tăng cường): Đọc file JSONL từ NIDS, bổ sung thêm ngữ cảnh (lịch sử hành động, hiệu quả phòng thủ), rồi đưa vào mô hình PPO để chọn hành động phòng thủ tối ưu.
- **Enforcement** (Thực thi phòng thủ): Áp dụng hành động được chọn lên tường lửa iptables của router, trực tiếp ảnh hưởng đến lưu lượng mạng.

Ba thành phần này tạo thành một **vòng kín** (closed loop): hành động phòng thủ thay đổi lưu lượng mạng → NIDS quan sát sự thay đổi → RL Agent điều chỉnh hành động tiếp theo.

---

## 2. Hạ tầng mạng mô phỏng

Hệ thống được triển khai trên một mạng mô phỏng Mininet gồm các thành phần:

- **Attacker** (Kẻ tấn công): Máy tính tại địa chỉ 10.0.10.10, đóng vai nguồn phát tấn công.
- **Router** (Bộ định tuyến): Nằm giữa attacker và các máy chủ nội bộ. Router chạy NIDS để giám sát lưu lượng và là nơi iptables được áp dụng. Router có 3 cổng mạng nối tới 3 mạng con:
  - Cổng ngoài (r-ext, 10.0.10.254): kết nối với attacker
  - Cổng web (r-web, 192.168.10.1): kết nối với webserver
  - Cổng honeypot (r-honey, 192.168.30.1): kết nối với honeypot
- **Webserver** (Máy chủ web): Tại 192.168.10.10, cổng 8080. Đây là mục tiêu thật cần bảo vệ.
- **Honeypot** (Bẫy mạng): Tại 192.168.30.10, cổng 8081. Đây là máy chủ giả, dùng để dụ kẻ tấn công vào khi bị chuyển hướng.

Router chạy nginx reverse proxy: cổng 80/443 chuyển tới webserver thật, cổng 4443 chuyển tới honeypot. Khi RL Agent chọn hành động "Chuyển hướng", iptables sẽ đổi cổng đích từ 443 sang 4443, khiến kẻ tấn công bị dẫn vào bẫy mà không hay biết.

---

## 3. Luồng dữ liệu chính — Từ gói tin thô đến hành động phòng thủ

### Giai đoạn 1: Thu thập gói tin (Packet Capture)

NIDS "lắng nghe" trên cổng mạng ngoài (r-ext) của router, bắt mọi gói tin đi qua. Có hai luồng thu thập song song:

- **Luồng chính**: Dùng thư viện Scapy bắt gói tin trực tiếp ở tầng mạng (L3/L4 — IP, TCP, UDP).
- **Luồng phụ** (tùy chọn): Dùng tshark để giải mã HTTPS. Khi lưu lượng được mã hóa TLS, tshark cần file khóa phiên (SSLKEYLOGFILE) để đọc được nội dung HTTP bên trong. Luồng phụ có thời gian chờ tối đa 600ms để đợi khóa giải mã.

Gói tin từ cả hai luồng được đặt vào **Hàng đợi gói tin** (Packet Queue) — một bộ đệm an toàn đa luồng chứa tối đa 10.000 gói tin, đảm bảo không bị mất gói khi hệ thống xử lý chậm hơn tốc độ mạng.

### Giai đoạn 2: Phân tích gói tin (Packet Parsing)

Mỗi gói tin thô được "mở ra" để lấy thông tin có cấu trúc, gọi là **LayerInfo** (Thông tin theo tầng). Quá trình này tách ra:

- **Tầng mạng (IP)**: Địa chỉ nguồn, địa chỉ đích, giao thức (TCP/UDP/ICMP)
- **Tầng vận chuyển (TCP/UDP)**: Cổng nguồn, cổng đích, cờ TCP (SYN, ACK, RST, FIN)
- **Tầng ứng dụng (HTTP)**: Phương thức (GET/POST), đường dẫn URL, User-Agent, nội dung body
- **Payload tổng hợp**: Hệ thống nối URL + User-Agent + Body thành một chuỗi duy nhất để phục vụ phân tích tấn công ở tầng ứng dụng (SQLi, XSS).

Kết quả: từ một khối bytes thô, ta có một bản ghi có cấu trúc chứa đầy đủ thông tin từ tầng mạng đến tầng ứng dụng.

### Giai đoạn 3: Gom luồng dữ liệu (Flow Aggregation)

Đây là bước biến đổi quan trọng nhất. Một gói tin đơn lẻ không thể cho biết hành vi — giống như nhìn 1 bước chân không biết người đó đang đi hay chạy.

Hệ thống gom các gói tin thuộc cùng một kết nối thành một **luồng** (flow). Mỗi luồng được xác định bởi **5 thông tin** (5-tuple): địa chỉ IP nguồn, địa chỉ IP đích, cổng nguồn, cổng đích, và giao thức. Ví dụ: tất cả gói tin từ 10.0.10.10:45678 gửi đến 192.168.10.10:443 qua TCP sẽ thuộc cùng một luồng.

Mỗi luồng duy trì hai hàng đợi:
- **Gói tin thuận** (forward packets): gói tin từ nguồn đến đích (ví dụ: request từ attacker)
- **Gói tin ngược** (backward packets): gói tin từ đích về nguồn (ví dụ: response từ server)

Điểm đặc biệt: hệ thống chỉ giữ gói tin trong **cửa sổ 1 giây** gần nhất. Gói tin cũ hơn 1 giây tự động bị loại bỏ. Điều này có nghĩa tại mỗi thời điểm, mỗi luồng chỉ chứa "lát cắt" 1 giây của kết nối — đây là đơn vị thời gian cơ bản của toàn hệ thống.

### Giai đoạn 4: Trích xuất đặc trưng (Feature Extraction)

Từ trạng thái luồng (chứa hàng trăm gói tin trong 1 giây), hệ thống tính ra **20 chỉ số hành vi** (20-dimensional feature vector). Mỗi chỉ số phản ánh một khía cạnh khác nhau của hành vi mạng:

**Nhóm Mạng (11 chỉ số — F1 đến F11)**: Đo đặc điểm lưu lượng ở tầng mạng và vận chuyển.

| Ký hiệu | Tên | Ý nghĩa | Dấu hiệu tấn công |
|----------|-----|---------|-------------------|
| F1 | PacketRate (Tốc độ gói tin) | Số gói tin mỗi giây | DDoS: tốc độ rất cao (>100 pps) |
| F2 | SynAckRatio (Tỷ lệ SYN/ACK) | Số gói SYN chia cho số gói ACK | SYN Flood: tỷ lệ rất cao (>5) vì attacker gửi SYN nhưng không hoàn thành kết nối |
| F3 | InterArrivalTime (Khoảng cách giữa các gói) | Thời gian trung bình giữa 2 gói tin liên tiếp | Bot tự động: khoảng cách rất đều |
| F4 | RstRatio (Tỷ lệ gói RST) | Phần trăm gói tin mang cờ RST (Reset) | Port Scan: server từ chối nhiều kết nối → nhiều RST |
| F5 | DistinctPorts (Số cổng khác nhau) | Số lượng cổng đích khác nhau trong cửa sổ | Port Scan: quét hàng chục cổng cùng lúc |
| F6 | URLConcentration (Mức tập trung URL) | Tỷ lệ request nhắm vào cùng một URL | Brute Force: lặp lại cùng trang đăng nhập |
| F7 | HttpIatUniformity (Độ đều thời gian HTTP) | Mức độ đều đặn của khoảng cách giữa các HTTP request | Bot: thời gian rất đều, người thật thì ngẫu nhiên |
| F8 | RequestSizeUniformity (Độ đều kích thước request) | Mức độ đều đặn về kích thước payload các request | Bot: payload giống nhau, người thật thì khác nhau |
| F9 | AvgPayloadSize (Kích thước payload trung bình) | Kích thước trung bình nội dung gói tin (bytes) | SYN Flood: rất nhỏ; Upload attack: rất lớn |
| F10 | FwdBwdRatio (Tỷ lệ gói thuận/ngược) | Số gói thuận chia cho số gói ngược | DDoS: tỷ lệ rất cao vì chỉ gửi mà không nhận phản hồi |
| F11 | PacketsPerPort (Số gói tin trên mỗi cổng) | Trung bình số gói tin gửi đến mỗi cổng | DDoS: nhiều gói/cổng; Scan: ít gói/cổng nhưng nhiều cổng |

**Nhóm SQLi (6 chỉ số — F12 đến F17)**: Phân tích nội dung payload để phát hiện tấn công SQL Injection.

| Ký hiệu | Tên | Ý nghĩa | Dấu hiệu tấn công |
|----------|-----|---------|-------------------|
| F12 | SqlSpecialChar (Ký tự đặc biệt SQL) | Tỷ lệ ký tự đặc biệt trong payload (', ", ;, --, #) | SQLi: nhiều ký tự đặc biệt |
| F13 | CrsSqliScore (Điểm CRS cho SQLi) | Điểm đánh giá theo bộ quy tắc ModSecurity CRS | SQLi: điểm cao (>5) |
| F14 | SqlUnionSelect (UNION SELECT) | Có chứa cú pháp UNION SELECT hay không | SQLi: có (=1) → đang cố trích xuất dữ liệu |
| F15 | SqlComment (Chú thích SQL) | Có chứa ký hiệu chú thích (--, #, /* */) hay không | SQLi: có (=1) → đang cố vô hiệu hóa phần còn lại của câu SQL |
| F16 | SqlStackedQuery (Truy vấn xếp chồng) | Có chứa dấu chấm phẩy (;) để nối nhiều câu SQL hay không | SQLi: có (=1) → đang cố thực thi nhiều câu lệnh |
| F17 | SqlSelectCount (Số lần SELECT) | Số lần xuất hiện từ khóa SELECT trong payload | SQLi: nhiều SELECT → đang cố truy vấn dữ liệu |

**Nhóm XSS (3 chỉ số — F18 đến F20)**: Phân tích payload để phát hiện tấn công Cross-Site Scripting.

| Ký hiệu | Tên | Ý nghĩa | Dấu hiệu tấn công |
|----------|-----|---------|-------------------|
| F18 | CrsXssScore (Điểm CRS cho XSS) | Điểm đánh giá theo bộ quy tắc ModSecurity CRS cho XSS | XSS: điểm cao (>1) |
| F19 | JsFunctionCall (Hàm JavaScript) | Có chứa lời gọi hàm nguy hiểm (alert, eval, document.cookie) hay không | XSS: có (=1) → đang cố chạy mã JavaScript |
| F20 | HtmlEventHandler (Trình xử lý sự kiện HTML) | Có chứa thuộc tính sự kiện (onload, onerror, onclick) hay không | XSS: có (=1) → đang cố gắn mã JavaScript vào sự kiện HTML |

### Giai đoạn 5: Chuẩn hóa (Normalization)

20 chỉ số có đơn vị và phạm vi rất khác nhau — F1 có thể lên tới 500 (gói/giây), F4 nằm trong khoảng 0-1, F13 từ 0-20. Để mô hình AI so sánh được, tất cả được đưa về **cùng thang đo từ 0 đến 1** bằng ba phương pháp:

- **Thang logarit** (cho F1, F2, F3, F5, F10, F11): Dùng cho các chỉ số có dải giá trị rất rộng. Ví dụ F1 (tốc độ gói tin) có thể từ 1 đến 500, nhưng sự khác biệt giữa 1 và 50 quan trọng hơn nhiều so với giữa 400 và 500. Thang logarit nén phần giá trị cao lại, giữ độ nhạy ở vùng giá trị thấp.
- **Thang tuyến tính** (cho F9, F13, F17, F18): Chia giá trị cho mức trần cố định. Ví dụ F13 (điểm SQLi) chia cho 20, nếu vượt 20 thì cắt về 1.0.
- **Giữ nguyên** (cho F4, F6, F7, F8, F12, F14-F16, F19, F20): Các chỉ số đã nằm sẵn trong khoảng 0-1 (tỷ lệ phần trăm hoặc giá trị nhị phân có/không).

Kết quả: **vector 20 chiều**, mỗi chiều nằm trong [0, 1].

### Giai đoạn 6: Ghi ra JSONL (Serialization)

Vector đặc trưng cùng metadata được ghi ra file `/tmp/sniffer_output.jsonl`. Mỗi dòng là một bản ghi JSON chứa:
- Thời gian (timestamp)
- Địa chỉ IP nguồn (src_ip)
- 20 giá trị đặc trưng thô (chưa chuẩn hóa)
- Các thông tin phụ về chất lượng giải mã HTTPS

Đây là **điểm nối** giữa NIDS và RL Agent — hai thành phần giao tiếp qua file này. Nhờ đó có thể chạy chúng độc lập: NIDS ghi, RL Agent đọc.

### Giai đoạn 7: Bổ sung ngữ cảnh (Context Enrichment)

RL Agent đọc file JSONL và chuẩn hóa 20 chỉ số. Nhưng 20 chiều chưa đủ để quyết định tốt — Agent cần thêm **ngữ cảnh** để hiểu tình huống đầy đủ hơn.

**Trạng thái thời gian** (Temporal State — 10 chiều bổ sung):
- **Hành động trước đó** (4 chiều, one-hot): Mã hóa hành động cuối cùng đã chọn. Ví dụ nếu lần trước chọn "Chuyển hướng" thì vector là [0, 0, 1, 0]. Giúp Agent biết mình đang ở trạng thái nào.
- **Thời gian giữ hành động** (1 chiều): Đã giữ hành động hiện tại bao nhiêu bước liên tiếp. Tránh Agent liên tục đổi ý.
- **Xu hướng thiệt hại** (2 chiều): Mức thiệt hại trung bình (EMA) và hướng thay đổi (tăng hay giảm). Giúp Agent biết tình hình đang tốt lên hay xấu đi.
- **Tiến trình phiên** (1 chiều): Đã thu thập bao nhiêu cửa sổ quan sát trong phiên theo dõi hiện tại.
- **Điểm leo thang** (1 chiều): Mức độ bằng chứng tích lũy cho thấy đây là tấn công nghiêm trọng cần leo thang hành động (xem mục 5).
- **Ngân sách sai lầm** (1 chiều): Số lần Agent chọn sai hành động trong phiên hiện tại, chia cho ngưỡng tối đa.

**Phản hồi hiệu quả** (Effect Feedback — 4 chiều bổ sung):
Thông tin này đến từ log truy cập của nginx trên router, **trễ 1 bước** so với hành động:
- **Tỷ lệ truy cập web** (F21): Phần trăm request đến được webserver thật. Nếu cao → phòng thủ chưa hiệu quả.
- **Tỷ lệ truy cập honeypot** (F22): Phần trăm request bị dẫn vào bẫy. Nếu cao → chuyển hướng thành công.
- **Hiện diện** (F23): Kẻ tấn công có gửi request trong giây vừa qua hay không (0 hoặc 1).
- **Mức thiệt hại dịch vụ** (F24): Kết hợp mức độ tấn công và tỷ lệ lọt qua phòng thủ.

Kết quả: **vector 34 chiều** = 20 (NIDS) + 10 (thời gian) + 4 (hiệu quả). Đây mới là đầu vào thực sự của mô hình RL.

### Giai đoạn 8: Quyết định của RL Agent

Mô hình PPO (Proximal Policy Optimization) nhận vector 34 chiều và chọn **1 trong 4 hành động**:

| Mã | Hành động | Tên tiếng Anh | Khi nào dùng | Chi phí |
|----|-----------|---------------|-------------|---------|
| 0 | Cho phép | Allow | Lưu lượng bình thường, không có dấu hiệu tấn công | Không |
| 1 | Giới hạn tốc độ | Rate Limit | Lưu lượng đáng ngờ nhẹ, người dùng "ồn ào" nhưng chưa chắc là tấn công | Rất thấp |
| 2 | Chuyển hướng | Redirect | Tấn công ứng dụng (SQLi, XSS, Brute Force) — dẫn kẻ tấn công vào honeypot để thu thập bằng chứng | Thấp |
| 3 | Chặn | Block | Tấn công DDoS, quét cổng, hoặc sau khi đã thu thập đủ bằng chứng từ honeypot | Cao |

**Chi phí** phản ánh mức độ nghiêm trọng: chặn hoàn toàn có thể gây ảnh hưởng đến người dùng hợp lệ, nên Agent bị "phạt" nhiều hơn khi chọn Block. Điều này buộc Agent phải cân nhắc kỹ trước khi chọn hành động mạnh.

**Lưới an toàn** (Safety Override): Ngoài quyết định của mô hình, có 3 quy tắc an toàn cứng:
- Nếu phát hiện tấn công SQLi/XSS nhưng mô hình chọn Cho phép → Buộc chuyển thành Chuyển hướng
- Nếu phát hiện SQLi/XSS nhưng mô hình chọn Chặn quá sớm (chưa đủ bằng chứng) → Hạ về Chuyển hướng
- Nếu đang Chặn và kẻ tấn công vẫn còn → Không cho hạ cấp hành động

### Giai đoạn 9: Thực thi trên tường lửa (Enforcement)

Hành động được chuyển thành lệnh iptables trên router:

| Hành động | Lệnh iptables | Hiệu ứng thực tế |
|-----------|--------------|-------------------|
| Cho phép | Xóa mọi quy tắc cho IP này | Lưu lượng đi qua bình thường |
| Giới hạn tốc độ | Thêm quy tắc hashlimit 2 gói/giây | Chỉ cho tối đa 2 gói/giây đi qua, còn lại bị hủy |
| Chuyển hướng | Thêm quy tắc REDIRECT cổng 443→4443 | Request bị chuyển sang honeypot, kẻ tấn công không biết |
| Chặn | Thêm quy tắc DROP | Mọi gói tin bị hủy hoàn toàn, kẻ tấn công bị cắt kết nối |

Lệnh iptables được thực thi trong không gian mạng (network namespace) của router thông qua nsenter — một công cụ Linux cho phép chạy lệnh bên trong namespace của tiến trình khác.

---

## 4. Vòng phản hồi kín (Closed-Loop Feedback)

Hệ thống có **3 vòng phản hồi** lồng nhau:

### Vòng 1: Phản hồi thời gian thực (Real-time Inference Loop)

Chu kỳ: **mỗi 1 giây**

```
NIDS thu thập lưu lượng mạng
→ Trích xuất 20 chỉ số hành vi
→ Ghi ra JSONL
→ RL Agent đọc, bổ sung ngữ cảnh (34 chiều)
→ Mô hình PPO chọn hành động
→ Áp dụng iptables lên router
→ Lưu lượng mạng thay đổi (bị chặn, giới hạn, hoặc chuyển hướng)
→ NIDS quan sát sự thay đổi ở chu kỳ tiếp theo
→ Quay lại bước đầu
```

Vòng này chạy liên tục, mỗi giây một lần. Hành động ở giây thứ N ảnh hưởng đến quan sát ở giây thứ N+1. Đây chính là "vòng kín" — Agent không chỉ quan sát mà còn **tác động ngược** lên môi trường.

### Vòng 2: Phản hồi hiệu quả (Effect Feedback Loop)

Chu kỳ: **trễ 1 bước so với vòng 1**

Nginx trên router ghi log mọi request HTTP. RL Agent đọc log này để biết hành động trước đó có hiệu quả không:
- Sau khi chọn "Chuyển hướng": kiểm tra xem request có thực sự đến honeypot không (F22 tăng?)
- Sau khi chọn "Chặn": kiểm tra xem kẻ tấn công có còn gửi request không (F23 giảm?)
- Sau khi chọn "Cho phép": kiểm tra xem webserver có bị ảnh hưởng không (F24 tăng?)

Thông tin này (4 chiều) được đưa vào observation ở bước tiếp theo, giúp Agent tự đánh giá và điều chỉnh.

### Vòng 3: Học liên tục (Continuous Learning Loop)

Chu kỳ: **theo đợt, sau nhiều giờ/ngày triển khai**

Gồm 3 bước:
1. **Thu thập**: Trong quá trình chạy thực tế, Agent ghi lại mọi quyết định vào file (đặc trưng, hành động đã chọn, hiệu quả đo được).
2. **Gán nhãn tự động**: Một chương trình riêng phân tích dữ liệu thu thập và gán nhãn tấn công dựa trên quy tắc heuristic. Ví dụ: nếu điểm CRS SQLi > 5 → gán nhãn "sqli", nếu tốc độ gói > 100 và tỷ lệ SYN/ACK > 5 → gán nhãn "syn_flood".
3. **Huấn luyện lại**: Dữ liệu đã gán nhãn được dùng để tiếp tục huấn luyện mô hình, bắt đầu từ mô hình hiện tại (warm-start). Mỗi đợt thêm 50.000 bước huấn luyện mới.

Vòng này cho phép hệ thống **thích nghi** với các kiểu tấn công mới mà nó gặp trong thực tế.

---

## 5. Cơ chế leo thang (Escalation Mechanism)

Đây là một thiết kế đặc biệt: Agent không nhảy thẳng từ "Cho phép" lên "Chặn". Thay vào đó, nó phải **tích lũy bằng chứng** trước khi được phép chặn.

**Quy trình leo thang cho tấn công ứng dụng (SQLi/XSS)**:

1. **Phát hiện tín hiệu L7**: NIDS phát hiện F12-F20 bất thường → Agent chọn "Chuyển hướng" (dẫn vào honeypot)
2. **Tích lũy bằng chứng**: Trong suốt quá trình chuyển hướng, hệ thống theo dõi qua cửa sổ trượt 15 bước:
   - Bao nhiêu lần đã chuyển hướng thành công? (redirect_hits)
   - Bao nhiêu lần kẻ tấn công thực sự đến honeypot? (honeypot_hits)
   - Kẻ tấn công có còn hiện diện không? (presence_hits)
   - Agent có bỏ lỡ cơ hội nào không? (miss_count)
3. **Tính điểm leo thang** (escalation_score): Kết hợp tất cả yếu tố trên thành một điểm duy nhất [0, 1]
4. **Điều kiện chặn**: Chỉ khi đạt đủ ngưỡng (đã chuyển hướng ≥6 lần, honeypot bắt được ≥5 lần, điểm leo thang ≥0.60), Agent mới được phép chọn "Chặn"
5. **Chặn sớm bị phạt**: Nếu chọn "Chặn" trước khi đủ bằng chứng → bị đếm là sai lầm, Agent bị phạt

Ý nghĩa: Honeypot không chỉ là bẫy — nó là **công cụ thu thập bằng chứng**. Agent dùng honeypot để xác nhận đây thực sự là tấn công trước khi chặn hoàn toàn.

---

## 6. Hệ thống phần thưởng trong huấn luyện (Reward System)

Khi huấn luyện, Agent học qua thử và sai. Mỗi bước, nó nhận một **phần thưởng** (reward) cho biết hành động vừa chọn tốt hay xấu.

### Phần thưởng cơ bản (Base Reward)

Dựa trên sự thay đổi mức thiệt hại:
- Nếu thiệt hại **giảm** sau hành động → phần thưởng dương (tốt)
- Nếu thiệt hại **tăng** sau hành động → phần thưởng âm (xấu)

Mức thiệt hại (network damage) được tính từ:
- Thiệt hại do tốc độ gửi gói cao (trọng số 25%) — DDoS
- Thiệt hại do gói RST nhiều (15%) — quét cổng
- Thiệt hại do quét nhiều cổng (15%) — dò tìm dịch vụ
- Thiệt hại do payload bất thường (10%) — tải trọng đáng ngờ
- Thiệt hại do SYN flood (10%) — làm ngập kết nối
- Thiệt hại do tấn công tầng ứng dụng (25%) — SQLi + XSS

### Chi phí hành động (Action Cost)

Mỗi hành động có chi phí riêng, trừ vào phần thưởng:
- Cho phép: 0 (miễn phí)
- Giới hạn tốc độ: 0.01 (rất rẻ)
- Chuyển hướng: 0.04 (hơi tốn)
- Chặn: 0.15 (đắt nhất)

Chi phí buộc Agent ưu tiên hành động nhẹ nhất có hiệu quả, chỉ dùng hành động mạnh khi thực sự cần.

### Thưởng theo vùng tấn công (Zone-Based Bonus)

Hệ thống chia lưu lượng thành 4 vùng dựa trên đặc trưng:

| Vùng | Điều kiện nhận diện | Hành động đúng | Thưởng | Hành động sai | Phạt |
|------|---------------------|---------------|--------|--------------|------|
| DDoS / Quét cổng | F1 cao (>80 pps) hoặc F2 cao (>10) hoặc F5 cao (>50 cổng) | Chặn | +0.30 | Cho phép | −0.50 |
| Tấn công ứng dụng (L7) | F6-F8 cao (brute force) hoặc F12-F20 cao (SQLi/XSS) | Chuyển hướng | +0.35 | Cho phép | −0.40 |
| Ồn ào (Noisy) | F1 ở mức trung bình (15-80 pps), tín hiệu tấn công thấp | Giới hạn tốc độ | +0.46 | Chặn | −0.20 |
| Bình thường | Thiệt hại thấp (<0.08), không có tín hiệu bất thường | Cho phép | +0.12 | Chặn | −0.60 |

### Phạt đặc biệt
- Chặn khi chưa đủ bằng chứng (premature block): −0.20
- Chặn người dùng bình thường (false positive): −0.60

---

## 7. Mô phỏng hành vi tấn công trong huấn luyện (MockIPBehavior)

Trong quá trình huấn luyện, hệ thống không dùng lưu lượng thật mà tạo ra các "nhân vật" giả lập với hành vi khác nhau:

| Loại | Tốc độ gửi | Đặc điểm nổi bật | Hành vi thích ứng khi bị phòng thủ |
|------|-----------|-------------------|-------------------------------------|
| Người bình thường (benign) | ~8 gói/giây | Lướt web bình thường, URL đa dạng | Không thay đổi |
| Người ồn ào (noisy_normal) | ~30 gói/giây | Click nhanh, nhiều request nhưng vô hại | Không thay đổi |
| Quét cổng (scan) | ~160 gói/giây | Thử kết nối hàng chục cổng khác nhau | Giảm tốc độ khi bị giới hạn |
| SYN Flood | ~200 gói/giây | Gửi SYN tràn lan, không hoàn thành kết nối | Dừng hẳn khi bị chặn |
| Brute Force | ~120 gói/giây | Lặp lại cùng URL đăng nhập liên tục | Chuyển chiến thuật khi bị chuyển hướng |
| Brute Force Keep-Alive | ~100 gói/giây | Như brute force nhưng dùng kết nối giữ sẵn, khó phát hiện hơn | Giảm tín hiệu khi bị chuyển hướng |
| SQL Injection | ~15 gói/giây | Tốc độ thấp, nhưng payload chứa mã SQL độc hại | Nhận ra đang nói chuyện với honeypot → tín hiệu yếu đi |
| XSS | ~12 gói/giây | Tốc độ thấp, payload chứa mã JavaScript độc hại | Tương tự SQLi |

Điểm quan trọng: kẻ tấn công **thay đổi hành vi** dựa trên hành động phòng thủ. Nếu Agent chặn, attacker dừng lại. Nếu Agent chuyển hướng, attacker phát hiện đang nói chuyện với máy chủ giả và tín hiệu yếu đi. Đây chính là **vòng kín** trong huấn luyện — Agent phải học cách phản ứng với kẻ tấn công cũng đang phản ứng lại mình.

---

## 8. Huấn luyện mô hình (Training)

### Thuật toán PPO (Proximal Policy Optimization)

Mô hình RL sử dụng PPO — một thuật toán học tăng cường phổ biến. Cách nó hoạt động đơn giản:

1. Agent tương tác với môi trường mô phỏng (MockIPBehavior), thu thập kinh nghiệm (quan sát + hành động + phần thưởng)
2. Sau mỗi 2.048 bước, Agent dùng kinh nghiệm vừa thu thập để cập nhật "bộ não" (mạng neural)
3. PPO đảm bảo mỗi lần cập nhật không thay đổi quá nhiều (clipping), giúp quá trình học ổn định

### Kiến trúc mạng neural

- **Mạng Actor** (chọn hành động): 2 tầng ẩn, 256 → 128 nơ-ron → 4 đầu ra (xác suất cho mỗi hành động)
- **Mạng Critic** (đánh giá tình huống): 3 tầng ẩn, 256 → 256 → 128 nơ-ron → 1 đầu ra (giá trị ước lượng)

Critic sâu hơn Actor vì việc đánh giá tình huống phức tạp hơn (đặc biệt là đánh giá giá trị dài hạn của cơ chế leo thang).

### Quá trình huấn luyện

- Tổng cộng 500.000 bước tương tác
- Chạy 4 môi trường song song để tăng tốc
- Đánh giá mỗi 5.000 bước, lưu mô hình tốt nhất
- Lưu checkpoint mỗi 10.000 bước để phòng gián đoạn
- Đánh giá cuối cùng trên 100 episode

---

## 9. Tóm tắt luồng dữ liệu theo dạng ống

```
Gói tin thô (bytes)
  ↓ [Thu thập — Scapy + tshark]
Gói tin có cấu trúc (LayerInfo)
  ↓ [Gom — theo 5 thông tin kết nối, cửa sổ 1 giây]
Luồng dữ liệu (FlowState — chứa N gói tin)
  ↓ [Trích xuất — 20 phép đo hành vi]
Vector 20 chiều (raw)
  ↓ [Chuẩn hóa — log/tuyến tính/giữ nguyên]
Vector 20 chiều (chuẩn hóa, [0,1])
  ↓ [Ghi file — JSONL]
  ↓ [Đọc — RL Agent]
  ↓ [Bổ sung — +10 ngữ cảnh thời gian, +4 phản hồi hiệu quả]
Vector 34 chiều (observation đầy đủ)
  ↓ [Suy luận — mạng neural PPO]
Hành động (1 trong 4)
  ↓ [Thực thi — iptables trên router]
Lưu lượng mạng thay đổi
  ↓ [Vòng phản hồi → quay lại bước thu thập]
```

---

## 10. Bảng thuật ngữ tham chiếu

| Thuật ngữ tiếng Anh | Thuật ngữ tiếng Việt | Giải thích ngắn |
|---------------------|---------------------|----------------|
| Packet | Gói tin | Đơn vị dữ liệu nhỏ nhất truyền trên mạng |
| Flow | Luồng dữ liệu | Tập hợp các gói tin thuộc cùng một kết nối |
| 5-tuple | 5 thông tin kết nối | IP nguồn, IP đích, cổng nguồn, cổng đích, giao thức — xác định duy nhất một kết nối |
| Sliding Window | Cửa sổ trượt | Khoảng thời gian 1 giây, liên tục dịch chuyển, chỉ giữ dữ liệu gần nhất |
| Feature Vector | Vector đặc trưng | Dãy các con số đại diện cho hành vi mạng trong 1 cửa sổ |
| Normalization | Chuẩn hóa | Đưa các giá trị về cùng thang đo [0,1] để AI so sánh được |
| Observation | Quan sát | Toàn bộ thông tin mà Agent nhận được tại mỗi bước (34 chiều) |
| Action | Hành động | Quyết định phòng thủ: Cho phép / Giới hạn / Chuyển hướng / Chặn |
| Reward | Phần thưởng | Điểm số đánh giá hành động tốt hay xấu, dùng để huấn luyện |
| Escalation | Leo thang | Quá trình tích lũy bằng chứng trước khi nâng cấp hành động phòng thủ |
| Honeypot | Bẫy mạng | Máy chủ giả, dùng để dụ kẻ tấn công và thu thập bằng chứng |
| PPO | Tối ưu chính sách gần | Thuật toán học tăng cường, cập nhật mô hình từng bước nhỏ ổn định |
| iptables | Tường lửa Linux | Công cụ quản lý quy tắc lọc gói tin trên Linux |
| NIDS | Hệ thống phát hiện xâm nhập mạng | Phần mềm giám sát và phân tích lưu lượng mạng |
| Closed Loop | Vòng kín | Hệ thống mà đầu ra ảnh hưởng ngược lại đầu vào |
| CRS | Bộ quy tắc lõi (ModSecurity) | Tập quy tắc chấm điểm tấn công web phổ biến |
| SQLi | SQL Injection | Tấn công chèn mã SQL vào input để truy cập trái phép cơ sở dữ liệu |
| XSS | Cross-Site Scripting | Tấn công chèn mã JavaScript vào trang web để đánh cắp dữ liệu người dùng |
| DDoS | Từ chối dịch vụ phân tán | Tấn công bằng cách gửi lượng lớn request để làm sập dịch vụ |
| SYN Flood | Tràn ngập SYN | Dạng DDoS gửi hàng loạt gói SYN mà không hoàn thành kết nối |
| Port Scan | Quét cổng | Dò tìm dịch vụ đang chạy trên máy chủ bằng cách thử kết nối nhiều cổng |
| Brute Force | Tấn công vét cạn | Thử lặp lại nhiều lần (ví dụ: thử mật khẩu) cho đến khi thành công |
| Temporal State | Trạng thái thời gian | Thông tin về lịch sử gần nhất của Agent (hành động trước, xu hướng) |
| Effect Feedback | Phản hồi hiệu quả | Thông tin cho biết hành động phòng thủ trước đó có tác dụng không |
| Network Namespace | Không gian mạng | Cơ chế Linux cô lập ngăn xếp mạng giữa các tiến trình |
| Warm-start | Khởi đầu nóng | Tiếp tục huấn luyện từ mô hình đã có, thay vì bắt đầu từ đầu |
| Mock | Mô phỏng giả lập | Tạo dữ liệu/hành vi giả để huấn luyện mà không cần hệ thống thật |
| Mininet | Mininet | Nền tảng giả lập mạng tạo ra các máy ảo, switch và liên kết ảo |
| nsenter | nsenter | Công cụ Linux chạy lệnh bên trong namespace mạng của tiến trình khác |
| nginx | nginx | Reverse proxy trên Router chuyển tiếp lưu lượng đến webserver hoặc honeypot |
| SSLKEYLOGFILE | File khóa phiên TLS | File chứa khóa phiên TLS, cho phép tshark giải mã lưu lượng HTTPS |

---

## 11. Quy trình vận hành thực tế trong môi trường mô phỏng

Mục này mô tả **trình tự thực thi cụ thể** khi toàn bộ hệ thống chạy trong môi trường mô phỏng Mininet. Đây là cầu nối giữa pipeline lý thuyết (mục 1–9) và những gì thực sự xảy ra trên màn hình.

### Giai đoạn 1: Dựng hạ tầng mạng

Bản demo khởi động bằng việc tạo mạng ảo với Mininet. Các node sau được tạo ra dưới dạng các namespace mạng Linux cô lập:

| Node | Địa chỉ IP | Vai trò |
|------|-----------|---------|
| Attacker | 10.0.10.10 | Nguồn phát mọi cuộc tấn công |
| Router | r-ext: 10.0.10.254, r-web: 192.168.10.1, r-honey: 192.168.30.1 | Hub trung tâm — chạy NIDS, nginx và iptables |
| Webserver | 192.168.10.10 (cổng 8080) | Mục tiêu thật cần bảo vệ — ứng dụng web Flask có lỗ hổng ("Tech Store") |
| Honeypot | 192.168.30.10 (cổng 8081) | Trang web mồi nhử ("T3ch Stor3") — giao diện gần giống, tên thương hiệu khác |

Router được cấu hình với:
- **iptables cơ bản**: Chính sách mặc định FORWARD là DROP. Chỉ cho phép kết nối đã thiết lập và lưu lượng attacker→webserver/honeypot.
- **nginx reverse proxy**: Cổng 443 → webserver:8080 (trang thật), cổng 4443 → honeypot:8081 (bẫy). Chứng chỉ TLS tự ký được tạo cho cả hai.
- **NIDS sniffer**: Tự động khởi động bên trong namespace Router, lắng nghe trên giao diện ngoài (r-ext) hướng về phía attacker.

Bốn cửa sổ terminal mở ra — mỗi cái cho một node (Attacker, Router, Webserver, Honeypot).

### Giai đoạn 2: Khởi động dịch vụ

Ba dịch vụ khởi động song song trên các node tương ứng:

1. **Webserver** (trên node webserver): Ứng dụng Flask phục vụ trang web "Tech Store" cố ý có lỗ hổng SQL injection ở tham số tìm kiếm.
2. **Honeypot** (trên node honeypot): Ứng dụng Flask gần giống nhưng phục vụ "T3ch Stor3" — bắt lại payload của kẻ tấn công để làm bằng chứng. Tên thương hiệu khác biệt nhỏ giúp người vận hành xác minh lưu lượng đến trang thật hay bẫy.
3. **RL Agent** (trên máy chủ): Script suy luận bắt đầu theo dõi `/tmp/sniffer_output.jsonl`, tải mô hình PPO đã huấn luyện (không gian quan sát 34 chiều), và chờ dữ liệu NIDS mới.

### Giai đoạn 3: Thiết lập giám sát

Hai chế độ xem giám sát trực tiếp chạy đồng thời:

- **Giám sát tường lửa** (trên terminal Router): Làm mới mỗi 1 giây, hiển thị các quy tắc iptables hiện tại trên chuỗi FORWARD và PREROUTING. Người vận hành thấy quy tắc xuất hiện và biến mất khi RL Agent ra quyết định.
- **Log hành động AI**: Mỗi quyết định được ghi dưới dạng bản ghi JSON chứa: IP nguồn, hành động thô của mô hình RL, hành động cuối cùng (sau lưới an toàn), phân phối xác suất của mạng neural trên cả 4 hành động, trạng thái thời gian (điểm leo thang, sẵn sàng chặn, xu hướng thiệt hại) và giá trị phản hồi hiệu quả.

### Giai đoạn 4: Thực thi tấn công & Phòng thủ thời gian thực

Node attacker cung cấp menu các kịch bản tấn công. Khi một cuộc tấn công được phát động:

**Mỗi 1 giây, pipeline sau thực thi đầy đủ từ đầu đến cuối:**

```
Attacker gửi HTTPS request đến Router:443
  ↓
nginx chuyển tiếp đến webserver:8080 (hoặc honeypot:8081 nếu bị chuyển hướng)
  ↓
Scapy bắt gói tin trên giao diện r-ext
  ↓
tshark giải mã HTTPS bằng file khóa TLS chung → trích xuất phương thức HTTP, URL, body
  ↓
FlowManager gom gói tin theo IP nguồn → cửa sổ 1 giây
  ↓
20 đặc trưng được trích xuất → ghi vào /tmp/sniffer_output.jsonl
  ↓
RL Agent đọc dòng mới → chuẩn hóa → thêm 10 thời gian + 4 hiệu quả → vector 34 chiều
  ↓
Mô hình PPO chọn hành động → áp dụng lưới an toàn
  ↓
Lệnh iptables thực thi bên trong namespace Router qua nsenter
  ↓
Giây tiếp theo: NIDS quan sát hiệu ứng của quy tắc tường lửa mới
```

**Giải mã TLS** là chi tiết quan trọng: curl/sqlmap của attacker ghi khóa phiên TLS vào file chung (`SSLKEYLOGFILE`). Nếu không có file này, tshark không thể đọc lưu lượng HTTPS mã hóa, và các đặc trưng F6–F20 (phân tích URL, phát hiện SQLi/XSS) sẽ bị "mù". Đây là lý do luồng thu thập phụ có thời gian chờ 600ms — chờ khóa xuất hiện trước khi xử lý.

### Giai đoạn 5: Các kịch bản tấn công và phản ứng phòng thủ mong đợi

| Loại tấn công | Attacker làm gì | Người vận hành thấy gì | Phản ứng mong đợi của Agent |
|---------------|-----------------|----------------------|----------------------------|
| **Ồn ào bình thường** | 18 lượt tải trang nhanh, cách nhau 0.09s | F1 (Tốc độ gói) tăng vọt, không có payload L7 | **Giới hạn tốc độ** — hashlimit 2 gói/giây |
| **Brute Force** | Gửi POST liên tục đến /login với mật khẩu khác nhau | F6 (Tập trung URL) + F7 (Đồng đều thời gian) cao | **Chuyển hướng** — lưu lượng âm thầm gửi đến honeypot |
| **SQL Injection** | sqlmap dò tham số tìm kiếm với --delay=1 | F13 (Điểm CRS SQLi) vượt ngưỡng | **Chuyển hướng** trước → sau ~15 cửa sổ, điểm leo thang ≥0.60 → **Chặn** |
| **XSS** | xsser gửi payload chứa script tag và event handler | F18–F20 (chỉ số XSS) bật sáng | **Chuyển hướng** đến honeypot |
| **SYN Flood** | hping3 --flood gửi 500+ gói SYN/giây | F1 cực cao, F2 (Tỷ lệ SYN/ACK) rất cao | **Chặn** ngay lập tức — phát hiện vùng DDoS |
| **Quét cổng** | nmap -sS quét nhiều cổng | F5 (Số cổng khác nhau) cao, F4 (Tỷ lệ RST) cao | **Chặn** — phát hiện vùng quét cổng |

### Giai đoạn 6: Quan sát quá trình leo thang (Ví dụ SQLi)

Kịch bản SQL Injection minh họa rõ nhất cơ chế vòng kín và leo thang đang hoạt động:

| Cửa sổ | Diễn biến | Hành động Agent | Điểm leo thang | Tại sao |
|---------|----------|----------------|----------------|---------|
| 1–3 | sqlmap thăm dò với payload cơ bản | **Chuyển hướng** | 0.0 → 0.15 | F13 (SQLi) phát hiện → lưới an toàn buộc Chuyển hướng |
| 4–8 | Attacker giờ đang truy cập honeypot (T3ch Stor3), không nhận ra | **Chuyển hướng** | 0.15 → 0.40 | F22 (tỷ lệ truy cập honeypot) xác nhận chuyển hướng thành công |
| 9–12 | Tín hiệu attacker yếu đi (honeypot trả về thành công giả) | **Chuyển hướng** | 0.40 → 0.58 | Bằng chứng tích lũy: redirect_hits ≥6, honeypot_hits ≥5 |
| 13–15 | Đạt ngưỡng: escalation_score ≥ 0.60 | **Chặn** | 0.60+ | block_ready_latched = True → mô hình hoặc soft-guard nâng lên Chặn |
| 16+ | Mọi lưu lượng attacker bị hủy | **Chặn** (giữ) | 1.0 | F23 (hiện diện) giảm về 0, xác nhận attacker đã dừng |

Người vận hành có thể quan sát toàn bộ tiến trình này trong log hành động — thấy điểm leo thang tăng từ 0 lên 1, phân phối xác suất chuyển từ Chuyển hướng sang Chặn, và cuối cùng quy tắc DROP xuất hiện trong giám sát tường lửa.

### Giai đoạn 7: Những gì người vận hành thấy trên màn hình

Tại bất kỳ thời điểm nào trong bản demo, người vận hành có 4 chế độ xem:

1. **Terminal Attacker**: Hiển thị đầu ra curl/sqlmap — phản hồi từ "Tech Store" (thật) hoặc "T3ch Stor3" (honeypot), cho thấy chuyển hướng có hoạt động không
2. **Terminal Router**: Quy tắc iptables trực tiếp cập nhật mỗi giây — quy tắc xuất hiện (Giới hạn, Chuyển hướng, Chặn) và biến mất (Cho phép)
3. **Log hành động AI**: Bản ghi JSON hiển thị mọi quyết định 1 giây với đầy đủ minh bạch: xác suất mô hình, trạng thái lưới an toàn, trạng thái thời gian, phản hồi hiệu quả
4. **Đầu ra NIDS** (tùy chọn): Dòng JSONL thô hiển thị 20 đặc trưng trích xuất mỗi giây

Cách bố trí nhiều chế độ xem này cho phép người vận hành xác minh vòng kín theo thời gian thực: tấn công bắt đầu → đặc trưng thay đổi → Agent phản ứng → tường lửa cập nhật → lưu lượng dịch chuyển → đặc trưng thay đổi lại.
