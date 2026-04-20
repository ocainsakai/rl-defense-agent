# CHƯƠNG 3: PHƯƠNG PHÁP NGHIÊN CỨU

## 3.1 Thiết kế Nghiên cứu

### 3.1.1 Mô hình Mối đe dọa

Nghiên cứu an toàn thông tin đòi hỏi xác định rõ mô hình mối đe dọa để giới hạn phạm vi bài toán và đặt kỳ vọng thực tế cho hệ thống phòng thủ. Đồ án giả định một đối thủ hoạt động ở cấp độ mạng, khởi phát tấn công từ bên ngoài qua interface biên nhắm vào các dịch vụ Web đang vận hành.

Các khả năng tấn công được phân loại dựa trên đặc điểm kỹ thuật và mức độ ảnh hưởng:
- Lưu lượng thể tích lớn (DDoS, SYN Flood) làm cạn kiệt băng thông và bảng kết nối TCP.
- Rà quét hệ thống (Port Scan) để lập bản đồ dịch vụ đang mở.
- Tự động hóa tấn công Brute-force qua Botnet để dò quét thông tin xác thực.
- Khai thác lỗ hổng tầng ứng dụng Web (Layer 7) qua SQL Injection (SQLi) và Cross-Site Scripting (XSS) trong payload HTTP.
- Sử dụng HTTPS/TLS để qua mặt các NIDS dựa trên DPI truyền thống.

Ràng buộc của kẻ tấn công: không có đặc quyền nội bộ (thiết lập Black-box, không biết chính sách phòng thủ). Khả năng của bên phòng thủ: giám sát toàn diện tại router biên, giải mã TLS qua SSLKEYLOGFILE, và thẩm quyền thực thi thời gian thực qua Iptables.

### 3.1.2 Khung Phương pháp Nghiên cứu

Đồ án tiếp cận bài toán phòng thủ mạng theo hướng ra quyết định tuần tự tự động, trong đó hệ thống không chỉ phát hiện tấn công mà còn lựa chọn hành động phản ứng phù hợp theo từng ngữ cảnh. Khung lý thuyết được chọn là Quy trình Quyết định Markov (MDP) [1], vì nó mô hình hóa chính xác quá trình ra quyết định tuần tự trong môi trường có sự không chắc chắn — đặc trưng cố hữu của lưu lượng mạng thực tế.

Theo định nghĩa MDP, môi trường được đặc trưng bởi bộ bốn thành phần (S, A, R, γ):
- **Không gian trạng thái S**: vector quan sát 20 chiều thuộc [0,1]²⁰ trích xuất từ lưu lượng mạng.
- **Không gian hành động A**: Bốn lựa chọn phòng thủ rời rạc.
- **Hàm phần thưởng R**: Định lượng tổn thất bảo mật và chi phí triển khai.
- **Hệ số chiết khấu γ = 0,99**: Phản ánh tầm nhìn dài hạn trong việc giảm thiểu tổng thiệt hại tích lũy.

Phương pháp nghiên cứu được triển khai theo hai nhánh song song. Nhánh thu thập trạng thái xây dựng **Module Quan sát (Observation Module)** — chuyển đổi lưu lượng mạng thô thành vector quan sát có ý nghĩa ngữ nghĩa cho agent. Nhánh huấn luyện phát triển **Tác tử Phòng thủ RL (RL Defense Agent)** sử dụng thuật toán Tối ưu hóa Chính sách Gần đúng (PPO) [2] trong môi trường mô phỏng Containernet.

PPO được chọn so với các thuật toán RL khác vì ba lý do thực tiễn: (1) ổn định huấn luyện thông qua cơ chế cắt gradient với ε = 0,2, tránh cập nhật chính sách quá lớn; (2) ổn định trong vòng lặp on-policy, phù hợp với môi trường mô phỏng sinh rollout liên tục không cần replay buffer; (3) tương thích tốt với không gian hành động rời rạc nhỏ gọn bốn lựa chọn [2][3]. *(So sánh PPO với DQN xem Chương 2, Mục 2.1.1.3. Phần này tập trung vào tham số triển khai cụ thể cho bài toán.)*

### 3.1.3 Kiến trúc Tổng thể Hệ thống

Hệ thống Phòng thủ Mạng Thích ứng (ANDS) được thiết kế theo kiến trúc ba lớp, mỗi lớp đảm nhận một vai trò chuyên biệt và tương tác qua giao diện chuẩn hóa.

**Lớp Trích xuất Đặc trưng (Module Quan sát):** Bắt gói tin từ môi trường mạng, tổ chức thành luồng hai chiều theo 5-tuple, và tính toán 20 đặc trưng hành vi biểu diễn các mẫu tấn công khác nhau. Đầu ra là vector 20 chiều giá trị thô; module suy diễn chuẩn hóa về [0,1] trước khi đưa vào agent.

**Lớp Ra quyết định (Tác tử Phòng thủ RL):** Tiếp nhận vector quan sát và ánh xạ sang hành động phòng thủ tối ưu dựa trên chính sách đã học. Thuật toán PPO với kiến trúc MLP Policy được huấn luyện cho đến khi hội tụ (khoảng 500.000 bước tương tác) trong môi trường Containernet [4].

**Lớp Thực thi:** Triển khai hành động phòng thủ vào hạ tầng mạng qua Iptables:
- **Cho phép (0)** — cho phép lưu lượng đi qua.
- **Giới hạn Tốc độ (1)** — giới hạn băng thông.
- **Chuyển hướng (2)** — chuyển hướng sang honeypot.
- **Chặn (3)** — chặn hoàn toàn.

Mỗi hành động có chi phí triển khai khác nhau, được tính vào hàm phần thưởng để agent học cân bằng giữa bảo mật và hiệu suất dịch vụ.

**Luồng Dữ liệu Đầu-Cuối:** Lưu lượng từ phía tấn công đến router biên; Scapy sniff gói tin thô ở tầng L3/L4, đồng thời tshark chạy song song để giải mã HTTPS qua SSLKEYLOGFILE và xuất các trường HTTP đã giải mã; bộ phân tích gói tin bóc tách thông tin thành đối tượng dữ liệu có cấu trúc; bộ quản lý luồng tổ chức theo flow 5-tuple. Mỗi giây, bộ tính toán đặc trưng tổng hợp 20 giá trị hành vi và đẩy ra luồng JSONL. Tác tử PPO đọc vector này, suy diễn hành động, và thực thi lệnh Iptables vào Network Namespace của router.

Điểm khác biệt cốt lõi so với IDS truyền thống là **hiệu ứng vòng lặp khép kín**: quyết định của agent lập tức biến đổi trạng thái mạng tiếp theo — và agent quan sát được sự thay đổi đó ở cửa sổ kế tiếp. IDS truyền thống (Snort, Suricata) chỉ phát hiện và gửi cảnh báo — hành động phản ứng (nếu có) do con người hoặc luật tĩnh xử lý, tách rời khỏi vòng lặp phát hiện. Tác tử RL tạo vòng phản hồi: hành động → thay đổi trạng thái → agent thấy kết quả → điều chỉnh chính sách. Đây cũng là lý do chọn RL thay vì học có giám sát: bài toán không phải phân loại tĩnh mà là ra quyết định tuần tự có hậu quả.

Cụ thể, mỗi hành động tạo hiệu ứng đo được trên vector 20D:

| Hành động | Ảnh hưởng lên Trạng thái Tiếp theo |
|---|---|
| Giới hạn Tốc độ | F1 (PacketRate) giảm ~60%, F11 (PacketsPerPort) giảm ~50%, F4 (RstRatio) giảm ~30% |
| Chuyển hướng | F6, F7, F8 (chỉ báo brute force) giảm ~70%, F12–F20 (payload L7) giảm ~80% — honeypot hấp thụ |
| Chặn | Toàn bộ đặc trưng → 0 trong 5–10 bước tiếp theo — kẻ tấn công bị cắt hoàn toàn |

### 3.1.4 Hình thức hóa Bài toán MDP

**Không gian Trạng thái** S ⊂ [0,1]²⁰: Mỗi trạng thái là vector 20 chiều đặc trưng hành vi lưu lượng trong cửa sổ quan sát 1 giây, bao gồm đặc trưng mạng (F1–F11) và đặc trưng nội dung HTTP (F12–F20). Chuẩn hóa về [0,1] đảm bảo ổn định số học cho gradient descent của mạng neural PPO.

**Không gian Hành động** A = {0, 1, 2, 3}: Bốn hành động rời rạc tương ứng Cho phép, Giới hạn Tốc độ, Chuyển hướng và Chặn. Không gian rời rạc nhỏ gọn giúp agent hội tụ nhanh hơn so với không gian liên tục.

**Hàm Phần thưởng** R(s, a): Được thiết kế theo nguyên tắc phạt nặng khi để lọt tấn công, phạt nhẹ khi can thiệp không cần thiết, và thưởng khi chặn đúng mục tiêu:

$$R_t = -\text{Network\_Damage}(S_t) - \text{Action\_Cost}(a_t) + \text{Action\_Bonus}(a_t, S_t)$$

Thành phần Damage phân biệt mức nghiêm trọng giữa các loại tấn công (SQLi/XSS có trọng số cao hơn Port Scan). Thành phần Cost phạt nhẹ các hành động can thiệp để ngăn agent phản ứng thái quá. Thành phần Bonus thưởng khi chọn đúng hành động phù hợp loại tấn công.

**Hệ số Chiết khấu** γ = 0,99: Giá trị cao khuyến khích học chính sách giảm thiểu tổng thiệt hại tích lũy, không chỉ tối ưu phần thưởng tức thì.

### 3.1.5 Topology Mạng Thực nghiệm

Môi trường thực nghiệm được xây dựng trên nền tảng Containernet — kết hợp Mininet (ảo hóa mạng) và Docker (cách ly ứng dụng) — cho phép tạo ra topology mạng thực tế trên phần cứng thông thường [4]:

- **Router biên (10.0.10.254/24):** Nút trung tâm đặt Iptables và Nginx Reverse Proxy. Nginx định tuyến cổng 443 về Production Webserver (192.168.10.10:8080) và cổng 4443 về Honeypot (192.168.30.10:8081). Header X-Real-IP được inject để bộ quản lý luồng xác định đúng IP nguồn sau NAT.
- **Production Webserver (192.168.10.10/24):** Dịch vụ thật, mục tiêu tấn công chính.
- **Honeypot Mồi nhử (192.168.30.10/24):** Server mồi nhử hấp thụ tấn công Layer 7. Khi agent chọn Chuyển hướng, kẻ tấn công tiếp tục hoạt động trên Honeypot trong khi máy chủ thật hoàn toàn an toàn.
- **Kẻ tấn công (10.0.10.10/24):** Triển khai các kịch bản tấn công bằng sqlmap, hping3, Hydra và curl.
- **Wazuh SIEM (192.168.20.20/24):** Ghi log baseline thứ cấp để đối chiếu chéo.

### 3.1.6 Thiết kế Tác tử Phòng thủ RL

**Ánh xạ Hành động:**
- **Cho phép (a=0):** Không can thiệp — dành cho lưu lượng bình thường.
- **Giới hạn Tốc độ (a=1):** Iptables hashlimit 10/giây burst 20 — dành cho lưu lượng nhiễu hoặc chưa xác định rõ loại.
- **Chuyển hướng (a=2):** NAT REDIRECT về cổng 4443 (Honeypot) — dành cho **Brute Force, SQLi, XSS**. Cho phép agent phân tích ý định tấn công qua Honeypot thay vì Chặn ngay, bảo toàn cơ hội SOC xem xét. Sau 60 giây nếu tín hiệu tấn công L7 tiếp tục, bộ theo dõi trạng thái IP tự động thăng cấp lên Chặn.
- **Chặn (a=3):** Iptables DROP — dành cho **DDoS/SYN Flood và Port Scan**, các tấn công thể tích cần ngắt ngay lập tức.

**Môi trường Huấn luyện:** Xây dựng theo chuẩn Gymnasium [11]. Mỗi episode kéo dài 120 bước (120 giây mạng) với các loại tấn công xuất hiện ngẫu nhiên đảm bảo agent gặp đủ cả năm loại. Vòng lặp PPO tích lũy kinh nghiệm qua `n_steps` bước tương tác, rồi cập nhật chính sách bằng nhiều epoch gradient descent. Cơ chế cắt với ε = 0,2 giới hạn mức thay đổi chính sách tại mỗi bước cập nhật, ngăn sự sụp đổ hiệu suất đột ngột [2].

Ngẫu nhiên hóa Miền (Domain Randomization) thêm nhiễu ±20% vào đặc trưng để tăng khả năng tổng quát hóa của chính sách học được.

**Hàm Phần thưởng** tổng hợp ba thành phần:

$$R_t = -(D_{after} + C_{action}) + B_{reduction} + B_{action}$$

**(1) Tổn thất Mạng** $D$ — Hàm tổn thất mạng tính từ 20D đặc trưng thô, gồm 6 thành phần với trọng số phản ánh mức độ nghiêm trọng:

| Thành phần | Trọng số | Đặc trưng | Hàm phi tuyến |
|---|---|---|---|
| Tràn PPS (DDoS) | 0,25 | F1 | Logistic: $1/(1+e^{-5(F1/anchor - 1)})$ |
| Tỷ lệ RST (quét/brute) | 0,15 | F4 | Tanh: $\tanh(F4 \times 2)$ |
| Phân bố quét cổng | 0,15 | F5 | Log-sigmoid trên số cổng thô |
| Bất thường payload | 0,10 | F9, F4, F5 | Logistic, loại trừ upload bình thường |
| SYN flood | 0,10 | F2 | Tanh trên tỷ lệ vượt ngưỡng |
| SQLi/XSS (tấn công L7) | 0,25 | F12–F20 | Tổ hợp có trọng số chuẩn hóa |

Hàm logistic và tanh triệt tiêu nhiễu nhỏ (lưu lượng bình thường gây tổn thất ≈ 0) nhưng phản ứng mạnh khi vượt ngưỡng. Upload bình thường (F9 ≥ 3000 + F4 thấp + F5 thấp) được loại trừ khỏi tổn thất payload để tránh phạt nhầm.

**(2) Chi phí Hành động** $C$ — Phạt nhẹ theo mức can thiệp: Cho phép = 0, Giới hạn Tốc độ = 0,02, Chuyển hướng = 0,05, Chặn = 0,08. Tạo "bậc thang chi phí" khiến agent ưu tiên biện pháp nhẹ khi hiệu quả tương đương.

**(3) Thưởng Phát hiện** $B_{action}$ — Thưởng/phạt theo phân vùng tấn công mềm (soft gating):
- DDoS/Port Scan mà chọn Chặn → +0,25; chọn Cho phép → −0,50
- Brute Force/SQLi/XSS mà chọn Chuyển hướng → +0,25; chọn Cho phép → −0,40
- Lưu lượng bình thường mà chọn Chặn → **−0,60** (phạt nặng nhất — dương tính giả gây gián đoạn dịch vụ)

$B_{reduction}$ = (tổn_thất_trước − tổn_thất_sau) × 0,5 — thưởng khi hành động thực sự giảm được tổn thất.

**Mô hình hóa Phản ứng Kẻ tấn công (Persistence Modeling):** Trong môi trường huấn luyện, MockIPBehavior mô phỏng cách kẻ tấn công phản ứng với hành động phòng thủ: Port scan nếu Cho phép → F5 tiếp tục leo thang; nếu Giới hạn Tốc độ → quét chậm lại. Brute force nếu Chuyển hướng → F6, F7 giảm dần. SQLi nếu Cho phép → F13 tiếp tục tăng. Thiết kế này buộc agent học rằng hành động có hậu quả dài hạn, không chỉ ảnh hưởng bước hiện tại.

**Siêu tham số:**

| Tham số | Default SB3 | Giá trị sử dụng | Lý do điều chỉnh |
|---|---|---|---|
| Tổng bước huấn luyện | — | ~500k timesteps | Dừng khi reward bão hòa (hội tụ thực nghiệm) |
| net_arch (pi/vf) | [64, 64] | [128, 128], Tanh | Input 20D cần capacity cao hơn để phân loại 5 lớp tấn công |
| learning_rate | 3×10⁻⁴ (cố định) | 3×10⁻⁴ → 1×10⁻⁴ (giảm tuyến tính) | Học nhanh giai đoạn đầu, tinh chỉnh chính xác giai đoạn cuối |
| clip_range ε | 0,2 | 0,2 | Giữ nguyên theo Schulman et al. [2] |
| gamma γ | 0,99 | 0,99 | Tầm nhìn dài hạn phù hợp episode 120 bước |
| ent_coef | 0,0 | 0,01 | Duy trì khám phá, tránh agent hội tụ cứng vào 1 hành động |
| batch_size | 64 | 256 | Gradient ổn định hơn với không gian trạng thái 20D |
| n_steps | 2048 | 2048 | Giữ nguyên — kích thước rollout buffer phù hợp |
| n_epochs | 10 | 10 | Giữ nguyên |
| n_envs | 1 | 4 | Song song hóa 4 môi trường, tăng tốc huấn luyện ~4× |
| Seed | — | 42 | Đảm bảo tái tạo kết quả |

### 3.1.7 Pipeline Suy diễn và Thực thi Thời gian Thực

Sau khi huấn luyện, mô hình PPO được triển khai vào vòng lặp suy diễn thời gian thực gồm hai tiến trình chạy song song:

**Tiến trình 1 — Sniffer (daemon thread):** Module Quan sát chạy liên tục, mỗi giây ghi một dòng JSONL chứa 20 giá trị thô kèm metadata (timestamp, src_ip) vào file `/tmp/sniffer_output.jsonl`.

**Tiến trình 2 — Suy diễn (main thread):** Theo dõi file JSONL theo chế độ tail (đọc dòng mới liên tục). Mỗi dòng được xử lý qua ba bước:
1. **Phân tích:** Trích xuất vector 20D thô từ JSON, xử lý key thiếu bằng giá trị mặc định 0.
2. **Chuẩn hóa:** Chuyển đổi giá trị thô về [0,1]²⁰ bằng cùng hàm chuẩn hóa đã dùng trong huấn luyện (thang log, thang tuyến tính, pass-through tương ứng từng đặc trưng).
3. **Dự đoán:** Gọi `model.predict(obs, deterministic=True)` → hành động ∈ {0, 1, 2, 3}.

**Thực thi Iptables qua Network Namespace:** Hành động được thực thi vào chain FORWARD hoặc NAT PREROUTING của router thông qua `nsenter -n -t <router_pid>`. Trước mỗi hành động mới, hệ thống xóa toàn bộ luật cũ của IP nguồn (dọn dẹp idempotent) rồi chèn luật mới:
- **Giới hạn Tốc độ:** `-m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 -j DROP` — cho phép burst 20 gói rồi giới hạn 10 pps.
- **Chuyển hướng:** `-t nat -I PREROUTING -j REDIRECT --to-ports 4443` — chuyển hướng sang cổng Honeypot.
- **Chặn:** `-I FORWARD -j DROP` — loại bỏ toàn bộ gói tin.

**Bộ Theo dõi Trạng thái IP:** Duy trì dictionary per-IP lưu lịch sử hành động và thời gian. Khi agent chọn Chuyển hướng, bộ theo dõi bắt đầu bộ đếm 60 giây. Sau 60 giây, nếu tín hiệu tấn công L7 vẫn tiếp tục (F6 > 0,5 hoặc F13/20 > 0,2 hoặc F18/4 > 0,2), hệ thống tự động thăng cấp lên Chặn mà không cần agent ra quyết định — đảm bảo Honeypot không bị khai thác vô thời hạn.

---

## 3.2 Phương pháp Thu thập Dữ liệu

### 3.2.1 Bắt và Phân tách Gói tin

Pipeline xử lý gói tin hoạt động ở hai chế độ: Thời gian thực Trực tiếp (qua Scapy) và PCAP Ngoại tuyến (qua PcapReader). Bộ phân tách gói tin trích xuất thông tin L3/L4 — bao gồm địa chỉ IP, cờ TCP (SYN, ACK, RST, FIN) và kích thước payload — thành một đối tượng dữ liệu có cấu trúc bất biến cho từng gói tin. Ở chế độ Thời gian thực, hệ thống hỗ trợ giải mã HTTPS bằng cách chạy tshark song song với Scapy: tshark đọc SSLKEYLOGFILE để giải mã TLS, tái hợp TCP stream và xuất các trường HTTP đã giải mã (URI, User-Agent, Body); kết quả được gắn ngược vào các gói tin TCP tương ứng trong flow để F12–F20 phân tích payload như lưu lượng HTTP thông thường.

Với tầng ứng dụng (L7), hệ thống sử dụng phương pháp **HTTP composite payload per-packet**: tại thời điểm phân tích từng gói tin, hệ thống ghép nối `[URI] + [User-Agent] + [Body]` từ cùng một gói tin thành một chuỗi bytes duy nhất. Chuỗi này được lưu lại và tái sử dụng trực tiếp khi các đặc trưng F12–F20 cần phân tích nội dung — không tái tính toán. Cách tiếp cận per-packet hoạt động hiệu quả vì payload SQLi/XSS từ các công cụ phổ biến thường nằm gọn trong URI (GET request) hoặc body nhỏ của một POST request đơn lẻ.

### 3.2.2 Quản lý Phiên kết nối

Bộ quản lý luồng tổ chức gói tin theo 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) vào các đối tượng flow tương ứng. Mỗi flow duy trì hai hàng đợi riêng biệt: gói tin chiều thuận (src→dst) và gói tin chiều ngược (dst→src), cho phép tính toán độc lập các đặc trưng từng chiều. Theo Lashkari et al. [6], phân tách hai chiều là điều kiện cần thiết để tính chính xác các chỉ số như SynAckRatio và FwdBwdRatio.

Phân tích payload HTTP được thực hiện ở mức per-request — đơn vị phân tích là từng gói tin HTTP, không phải toàn bộ TCP stream. Với lưu lượng HTTPS, tshark đã tái hợp TCP stream trước khi xuất HTTP fields, nên hệ thống không cần tái hợp thủ công. Thiết kế này phù hợp với cách định nghĩa các đặc trưng F13, F17 và F18 theo tỷ lệ trên số HTTP request. Bộ nhớ được kiểm soát với tối đa 50.000 flows đồng thời và 3.000 gói tin mỗi flow.

### 3.2.3 Cửa sổ Trượt 1 Giây

Tác tử RL yêu cầu vector quan sát phản ánh trạng thái hiện tại của mạng, không phải lịch sử toàn bộ phiên kết nối. Cửa sổ trượt 1 giây đáp ứng yêu cầu này: tại mỗi bước, chỉ gói tin trong khoảng [t−1s, t] được dùng để tính đặc trưng.

Kích thước 1 giây được hiệu chỉnh thực nghiệm từ hai ràng buộc đối lập: cửa sổ quá ngắn không đủ gói tin để tính ổn định các đặc trưng thống kê; cửa sổ quá dài làm mờ ranh giới giữa các pha tấn công, khiến agent không phân biệt được khi cần thay đổi hành động. Nghiên cứu ablation xác nhận 1 giây là điểm cân bằng tối ưu (xem Bảng 4.4).

Trong MDP, mỗi bước quyết định tương ứng một cửa sổ 1 giây: agent quan sát s_t, chọn a_t, nhận r_t, và chuyển sang s_{t+1} sau khi cửa sổ dịch chuyển. Trình tự thực hiện: (1) gọi thủ tục dọn dẹp cửa sổ trượt, xóa gói tin cũ hơn ngưỡng cắt; (2) lấy các flows hiện tại; (3) tính đặc trưng thuần cho 1 giây này. Thứ tự này đảm bảo không có dữ liệu cũ bị bám trụ qua nhiều cửa sổ liên tiếp.

### 3.2.4 Nguồn Dữ liệu

Một điểm quan trọng cần làm rõ: **các file PCAP thô không có nhãn tấn công tự nhiên**. Nhãn trong nghiên cứu này được gán theo phương pháp *gán nhãn thí nghiệm có kiểm soát* — nhóm biết trước loại tấn công đang chạy vào thời điểm capture, nhờ đó toàn bộ lưu lượng trong phiên đó được gán nhãn tương ứng.

Ba nguồn dữ liệu được sử dụng với mục đích khác nhau:

1. **Bộ dữ liệu URI có Nhãn LSNM2024 [5]:** Bộ dữ liệu công khai do Lashkari et al. (Đại học New Brunswick) phát hành — gồm 3.000 URI bình thường và 2.809 URI SQLi đã có nhãn. Dùng để hiệu chỉnh CRS Paranoia Level và xác minh pipeline chuẩn hóa payload. Tập này không có lưu lượng PCAP thực — chỉ chứa chuỗi HTTP URI, nên các đặc trưng mạng F1–F11 không áp dụng được.

2. **Bộ dữ liệu PCAP Gói tin Đột biến (Abu Al-Haija et al., 2025) [21]:** Bộ dữ liệu PCAP công khai do nhóm nghiên cứu tại Đại học Khoa học và Công nghệ Jordan và Đại học Công nghệ Công chúa Sumaya xây dựng và phát hành. Dataset chứa 15 loại tấn công được thu thập trong môi trường lab có kiểm soát bằng các công cụ thực tế: hping3 (SYN Flood, Port Scan), sqlmap (SQL Injection), Hydra/Burp Suite (Brute Force), XSS, GoldenEye/HULK/LOIC/Slowloris/Slowhttptest (DoS), Ares Botnet, Metasploit, Patator, nmap. Nhóm nghiên cứu xuất các file PCAP qua Wireshark thành CSV theo định dạng chuẩn hóa, sau đó đưa vào pipeline trích xuất đặc trưng để tạo tập đánh giá có nhãn. Đây là tập đánh giá chính cho Bảng 4.1 và 4.2.

3. **MockIPBehavior Mô phỏng (tự xây dựng):** Môi trường mô phỏng vector trạng thái do nhóm nghiên cứu xây dựng, dùng **riêng cho huấn luyện PPO**. Sinh ra các đối tượng hành vi tổng hợp với nhiễu ±20% (Ngẫu nhiên hóa Miền) để tăng khả năng tổng quát hóa. Không sử dụng cho đánh giá hiệu suất thực tế.

---

## 3.3 Kỹ thuật Phân tích Dữ liệu

### 3.3.1 Tổng quan Kỹ nghệ Đặc trưng

Thiết kế 20 đặc trưng xuất phát từ câu hỏi: "Tác tử RL cần biết gì về mạng để ra quyết định phòng thủ đúng đắn?" Agent cần thông tin đủ để phân biệt năm loại tấn công từ lưu lượng bình thường, và phân biệt chúng với nhau để chọn hành động phù hợp — ví dụ, Chặn hiệu quả với SYN Flood nhưng lãng phí với SQLi nơi Chuyển hướng sang Honeypot cho phép thu thập thông tin tình báo mối đe dọa.

**Bảng 3.1: Danh sách 20 đặc trưng trong vector quan sát của tác tử RL**

*(Mô tả thiết kế và cơ sở lý thuyết của từng đặc trưng xem Chương 2, Mục 2.1.4.5. Bảng này trình bày chi tiết triển khai đầy đủ.)*

| Mã | Tên Đặc trưng | Công thức | Thang đo | Cap | Phát hiện |
|---|---|---|---|---|---|
| F1 | PacketRate | total_pkts / window_size (s) | Log | 500 pkt/s | DDoS / SYN Flood |
| F2 | SynAckRatio | fwd_SYN / max(bwd_SYN, 1) | Log | 100 | SYN Flood |
| F3 | InterArrivalTime | mean(IAT fwd pkts) | Log | 5,0 s | Tấn công tự động |
| F4 | RstRatio | (fwd+bwd RST) / total_pkts | Pass-through | — | Port Scan |
| F5 | DistinctPorts | unique dst_ports trong cửa sổ | Log | 500 | Port Scan |
| F6 | URLConcentration | max_url_count / total_req | Pass-through | — | Brute Force / L7 DDoS |
| F7 | HttpIatUniformity | 1 / (1 + CV(HTTP IAT)) | Pass-through | — | Nhịp bot |
| F8 | RequestSizeUniformity | 1 / (1 + CV(payload_sizes)) | Pass-through | — | Brute Force |
| F9 | AvgPayloadSize | sum(fwd_payload_len) / fwd_count | Tuyến tính | 1.500 bytes | SYN Flood (≈0) |
| F10 | FwdBwdRatio | fwd_pkts / max(bwd_pkts, 1) | Log | 100 | Bất đối xứng lưu lượng |
| F11 | PacketsPerPort | fwd_pkts / max(distinct_ports, 1) | Log | 500 | Mật độ Port Scan |
| F12 | SqlSpecialChar | count(chars ∈ {`'`, `;`, `#`}) / len(normalized) | Pass-through | — | SQLi |
| F13 | CrsSqliScore | Σ(CRS-942 rule hits) / req_count | Tuyến tính | 20 | SQLi (CRS PL2) |
| F14 | SqlUnionSelect | 1 nếu có `UNION[\s\S]{0,50}SELECT` | Nhị phân | — | SQLi — UNION |
| F15 | SqlComment | 1 nếu có `--`, `#`, `/**/`, `/*!`... | Nhị phân | — | SQLi — comment |
| F16 | SqlStackedQuery | 1 nếu có `; DROP/DELETE/INSERT/UPDATE/ALTER/EXEC/...` | Nhị phân | — | SQLi — stacked |
| F17 | SqlSelectCount | Σ(SELECT count) / req_count | Tuyến tính | 10 | SQLi — trinh sát |
| F18 | CrsXssScore | Σ(CRS-941 @rx hits + @pm phrase hits) / req_count | Tuyến tính | 4 | XSS (CRS PL2) |
| F19 | JsFunctionCall | 1 nếu có `alert()`/`eval()`/`prompt()`/`document.cookie`/`window.location`/`innerHTML=` | Nhị phân | — | XSS — JS |
| F20 | HtmlEventHandler | 1 nếu có `on{error\|load\|click\|mouseover\|...}=` | Nhị phân | — | XSS — sự kiện |

*Công thức chuẩn hóa: Log scale — `log(1 + min(raw, cap)) / log(1 + cap)`; Tuyến tính — `min(raw, cap) / cap`; Pass-through — `clamp(raw, 0, 1)`. Giá trị Cap được hiệu chỉnh thực nghiệm trên dữ liệu Containernet và xác minh với LSNM2024 / tập PCAP Abu Al-Haija et al. (2025).*

### 3.3.2 Đặc trưng Mạng (F1–F11)

Nhóm đặc trưng mạng mã hóa hành vi traffic-level đặc thù của từng loại tấn công. F1 (PacketRate) đo tổng tốc độ gói tin hai chiều (fwd+bwd) trên tất cả flows trong cửa sổ, nhạy cảm với DDoS và SYN Flood vì các tấn công này tạo lưu lượng thể tích lớn bất thường. F2 (SynAckRatio) khai thác cơ chế bắt tay ba bước TCP: SYN Flood tạo tỷ lệ SYN/ACK bất cân xứng do server nhận nhiều SYN nhưng không bao giờ hoàn thành bắt tay.

F3 (InterArrivalTime) phát hiện tấn công tự động thông qua IAT quá đều hoặc quá nhỏ so với người dùng thực. F4 (RstRatio) và F5 (DistinctPorts) mô tả Port Scan: scanner gửi gói đến nhiều cổng và nhận về nhiều RST từ cổng đóng, tạo tỷ lệ RST cao kết hợp số cổng đích đa dạng. F11 (PacketsPerPort) bổ sung bằng cách đo mật độ gói trên mỗi cổng — Port Scan có F11 nhỏ (ít gói/cổng) trong khi lưu lượng bình thường tập trung vào ít cổng nhưng nhiều gói hơn.

F6 (URLConcentration) phát hiện Brute Force qua việc đo mức tập trung yêu cầu vào một URL đích duy nhất như `/login`. F7 (HttpIatUniformity) bổ sung bằng cách phát hiện nhịp thời gian quá đều — đặc trưng của công cụ tự động như Hydra hay Burp Suite Intruder. Điểm thiết kế quan trọng: F7 tính IAT theo **cross-flow** — gom tất cả HTTP request timestamps từ mọi flows của cùng IP nguồn trong cửa sổ 1 giây, sắp xếp theo thời gian rồi tính khoảng cách giữa các request liên tiếp. Lý do: Hydra và Burp Suite Intruder mở kết nối TCP mới cho mỗi request (short-lived flows), khiến mỗi flow chỉ chứa 1 gói HTTP — tính IAT per-flow sẽ không có đủ điểm dữ liệu. Cross-flow khắc phục hoàn toàn hạn chế này bằng cách nhìn nhận toàn bộ nhịp điệu tấn công từ một IP nguồn. F8 (RequestSizeUniformity) khai thác việc Brute Force gửi payload gần như giống hệt nhau (chỉ trường mật khẩu thay đổi), làm hệ số biến thiên CV của kích thước payload rất thấp. F9 (AvgPayloadSize) phân biệt SYN Flood (payload ≈ 0) với HTTP flood (payload > 0).

### 3.3.3 Đặc trưng SQL Injection (F12–F17)

SQLi không để lại dấu vết ở tầng mạng — lưu lượng có thể trông hoàn toàn bình thường về tốc độ và kích thước. Nhóm F12–F17 đào sâu vào payload HTTP để tìm tín hiệu tấn công trong nội dung yêu cầu.

F12 (SqlSpecialChar) tính tỷ lệ các ký tự đặc biệt SQL — dấu nháy đơn (`'`), dấu chấm phẩy (`;`) và ký tự comment (`#`) — trên tổng độ dài payload đã qua chuẩn hóa (URL-decoded). F13 (CrsSqliScore) tích hợp bộ quy tắc OWASP CRS 942 [8] — chuẩn công nghiệp cho WAF — trực tiếp vào vector đặc trưng: CRS PL2 với 50 quy tắc đạt F1-score 0,925 trên tập URI LSNM2024 (n=2.809 SQLi + 3.000 bình thường). F14–F16 là các đặc trưng nhị phân phát hiện ba kỹ thuật SQLi phổ biến: UNION-based (truy xuất dữ liệu — regex `UNION[\s\S]{0,50}SELECT`), Comment-based (vô hiệu hóa phần sau query — `--`, `#`, `/**/`, `/*!`), và Stacked Queries (chèn câu lệnh DDL/DML — `; DROP/DELETE/INSERT/UPDATE/TRUNCATE/ALTER/EXEC/...`). F17 đo tần suất SELECT — cao bất thường báo hiệu thăm dò cơ sở dữ liệu.

### 3.3.4 Đặc trưng Cross-Site Scripting (F18–F20)

F18 (CrsXssScore) tích hợp OWASP CRS 941 PL2 bao gồm cả rule `@rx` (regex) lẫn `@pm` (phrase match) — tổng cộng 27 regex rule và 9 cụm từ (`document.cookie`, `document.write`, `window.location`, `.innerhtml`...) — đạt F1-score 1,000 trên tập URI LSNM2024 XSS (n=9 URI tấn công, F1=1,0 nhưng tập quá nhỏ để kết luận chắc chắn). F19 (JsFunctionCall) phát hiện các lời gọi hàm JavaScript nguy hiểm bao gồm: `alert()`, `eval()`, `prompt()`, `confirm()`, `expression()`, `document.cookie/write/domain`, `window.location`, `innerHTML=`. F20 (HtmlEventHandler) tìm các thuộc tính event handler như `onerror=`, `onload=`, `onclick=`, `onmouseover=` và hàng chục event khác — cơ chế kích hoạt JavaScript mà không cần thẻ `<script>` tường minh.

### 3.3.5 Pipeline Chuẩn hóa Payload

Kẻ tấn công thường mã hóa payload bằng URL encoding, HTML entities, hoặc Base64 để vượt qua kiểm tra đơn giản. Bộ chuẩn hóa payload triển khai pipeline nhiều giai đoạn trước khi so khớp mẫu:

**Giai đoạn 1 — Giải mã Encoding:** Giải mã HTML entity (`&#83;` → `S`) và chuẩn hóa Unicode NFKC kết hợp ánh xạ smart quotes về ASCII. Đảm bảo các ký tự có ngữ nghĩa tương đương được đưa về biểu diễn thống nhất.

**Giai đoạn 2 — Giải mã Làm mờ:** URL decode đệ quy (tối đa 2 vòng) và Base64 decode đệ quy (tối đa 2 vòng). Giới hạn MAX_ITERATIONS = 2 theo khuyến nghị Spett [9]: mã hóa kép (`%2527` → `%27` → `'`) là kỹ thuật vượt WAF phổ biến nhất được ghi nhận; mã hóa ba lần không xuất hiện trong các công cụ tấn công phổ biến.

**Giai đoạn 3 — Chuẩn hóa Văn bản:** Thu gọn khoảng trắng liên tiếp và chuyển về chữ thường [10]. Cho phép regex CRS và so khớp mẫu hoạt động không phân biệt chữ hoa/thường, giảm đáng kể số biến thể cần xử lý.

Benchmark trên N = 10.000 lần gọi: độ trễ trung bình = 23,55 µs/lần gọi, P99 = 67,4 µs, thông lượng = 42.457 lần gọi/giây — đủ xử lý server 10.000 yêu cầu/giây với chi phí dưới 1% CPU trên một lõi đơn.

### 3.3.6 Ma trận Phủ nhận Tấn công

Để xác minh 20 đặc trưng cung cấp tín hiệu phân biệt đầy đủ cho tác tử RL, Bảng 3.2 trình bày ma trận phủ nhận: dấu ✓ chỉ ra đặc trưng đó có khả năng phát hiện loại tấn công tương ứng. Mỗi loại tấn công được phủ bởi ít nhất hai đặc trưng độc lập, đảm bảo khả năng phát hiện ngay cả khi một đặc trưng bị nhiễu.

**Bảng 3.2: Ma trận Phủ nhận — Đặc trưng × Loại Tấn công**

| Đặc trưng | SYN Flood | Port Scan | Brute Force | SQLi | XSS |
|---|---|---|---|---|---|
| F1 PacketRate | ✓ | ✓ | ✓ | | |
| F2 SynAckRatio | ✓ | | | | |
| F3 InterArrivalTime | ✓ | ✓ | ✓ | | |
| F4 RstRatio | | ✓ | | | |
| F5 DistinctPorts | | ✓ | | | |
| F6 URLConcentration | | | ✓ | | |
| F7 HttpIatUniformity | | | ✓ | | |
| F8 RequestSizeUniformity | | | ✓ | | |
| F9 AvgPayloadSize | ✓ | | | | |
| F11 PacketsPerPort | | ✓ | | | |
| F12 SqlSpecialChar | | | | ✓ | |
| F13 CrsSqliScore | | | | ✓ | |
| F14–F16 SqlBinary | | | | ✓ | |
| F18 CrsXssScore | | | | | ✓ |
| F19–F20 XssBinary | | | | | ✓ |

### 3.3.7 Chuẩn hóa Vector Đặc trưng

Sau khi tính giá trị thô, 20 đặc trưng được chuẩn hóa về [0,1] theo phân phối của từng đặc trưng. *(Cơ sở thiết kế phân nhóm chuẩn hóa xem Chương 2, Mục 2.1.4.5; phần này mô tả chi tiết triển khai và lý do kỹ thuật.)* Có ba nhóm:

- **Thang log** (F1, F2, F3, F5, F10, F11): phân phối lệch phải, phạm vi rộng — ví dụ F1 có thể đạt 350 pkt/s khi DDoS nhưng thường < 10 khi bình thường. Công thức: `f_norm = log(1 + min(f_raw, cap)) / log(1 + cap)`, trong đó `cap` là giá trị cắt hiệu chỉnh thực nghiệm (Bảng 3.1). Log scale nén phần đuôi dài (outlier tấn công cực đoan) về vùng [0,8–1,0], tránh gradient vanishing cho các cửa sổ bình thường.
- **Thang tuyến tính** (F9, F13, F17, F18): phân phối gần tuyến tính, phạm vi nhỏ. Công thức: `f_norm = min(f_raw, cap) / cap`. Áp dụng cho các đặc trưng đếm tần suất (CRS scores, SELECT count) có giá trị thực tế nằm trong biên độ dự đoán được.
- **Pass-through** (F4, F6, F7, F8, F12, F14–F16, F19, F20): đã nằm trong [0,1] theo định nghĩa (tỷ lệ, hàm 1/(1+CV), hoặc nhị phân). Áp dụng `clamp(f_raw, 0, 1)` để đảm bảo an toàn số học trong trường hợp lỗi tính toán biên.

Chuẩn hóa về [0,1] là yêu cầu kỹ thuật cho mạng neural PPO: gradient descent không hội tụ ổn định khi đầu vào có thang đo khác nhau nhiều bậc độ lớn (ví dụ F1 thô ~100–500 pkt/s vs F14 nhị phân {0,1}). MlpPolicy trong Stable-Baselines3 [3] áp dụng thêm lớp VecNormalize theo trung bình/độ lệch chuẩn chạy — hoạt động tốt chỉ khi đầu vào đã được cắt về phạm vi hữu hạn, tránh VecNormalize bị kéo lệch bởi outlier cực đoan.

---

## 3.4 Hạn chế của Phương pháp

**Hạn chế về môi trường mô phỏng:** Containernet tạo ra lưu lượng trong môi trường có kiểm soát, không phản ánh đầy đủ sự phức tạp của mạng sản xuất với nhiều loại thiết bị và mẫu lưu lượng nền đa dạng. Chính sách học được có thể cần tinh chỉnh khi triển khai thực tế.

**Hạn chế về loại tấn công:** Hệ thống được thiết kế và kiểm tra với năm loại tấn công cụ thể. Các kỹ thuật zero-day và tấn công đối kháng nhắm vào chính tác tử RL nằm ngoài phạm vi nghiên cứu.

**Hạn chế về đặc trưng nội dung:** F12–F20 chỉ hiệu quả với lưu lượng không mã hóa hoặc sau khi giải mã TLS. Hệ thống đã hỗ trợ giải mã HTTPS qua tshark + SSLKEYLOGFILE ở chế độ Thời gian thực, nhưng yêu cầu SSLKEYLOGFILE phải được cấu hình trước. Trong môi trường HTTPS thuần túy không có SSLKEYLOGFILE, các đặc trưng này không có giá trị.

**Hạn chế về đánh giá chính sách:** Phần thưởng tích lũy phụ thuộc vào thiết kế hàm thưởng, vốn chứa đựng các giả định về tầm quan trọng tương đối giữa các loại tấn công. Thay đổi trọng số mức nghiêm trọng có thể dẫn đến chính sách khác nhau đáng kể.

**Hạn chế về gán nhãn dữ liệu:** Nhãn trong tập đánh giá được gán theo phương pháp gán nhãn thí nghiệm có kiểm soát — biết trước loại tấn công đang chạy trong mỗi phiên capture. Phương pháp này không phản ánh lưu lượng hỗn hợp thực tế, nơi nhiều loại tấn công có thể xảy ra đồng thời.

**Hạn chế về phân tích payload HTTP:** Với đường dẫn Scapy (HTTP văn bản rõ và chế độ PCAP), hệ thống phân tích payload ở mức per-HTTP-request, không tái hợp TCP stream — POST body vượt quá MTU (~1.460 bytes) và bị phân mảnh qua nhiều TCP segment sẽ không được phân tích đầy đủ. Đường dẫn tshark (Thời gian thực HTTPS) không bị hạn chế này vì tshark đã tái hợp TCP stream trước khi xuất HTTP fields. Hạn chế này không ảnh hưởng đến kết quả trong nghiên cứu này vì các công cụ tấn công phổ biến (sqlmap, Burp Suite, Hydra) gửi payload gọn trong một request đơn lẻ.

---

# CHƯƠNG 4: KẾT QUẢ THỰC NGHIỆM

## 4.1 Giới thiệu

Chương này trình bày đánh giá thực nghiệm của hệ thống Phòng thủ Mạng Thích ứng (ANDS), bao gồm cả Module Quan sát và Tác tử Phòng thủ RL. Đánh giá theo hai hướng: (1) độ chính xác trích xuất đặc trưng và hiệu suất xử lý cho Module Quan sát; (2) hành vi hội tụ huấn luyện và hiệu suất chính sách cuối cùng cho tác tử RL.

Toàn bộ thực nghiệm được thực hiện trên Linux với nền tảng Containernet. Framework vận hành dựa trên Python 3.x với Stable-Baselines3 yêu cầu `numpy < 2.0`. Tính tái hiện được đảm bảo bằng seed cố định = 42 trên tất cả các hàm ngẫu nhiên.

Ba nguồn dữ liệu phục vụ các mục đích đánh giá khác nhau. Bộ dữ liệu URI có Nhãn LSNM2024 [5] — bộ dữ liệu công khai từ Đại học New Brunswick — cung cấp 3.000 URI bình thường và 2.809 URI SQLi để hiệu chỉnh CRS Paranoia Level. Bộ dữ liệu PCAP Gói tin Đột biến [21] — bộ dữ liệu công khai của Abu Al-Haija et al. (2025) gồm 15 loại tấn công được capture bằng công cụ thực trong lab kiểm soát — là tập đánh giá chính cho hiệu suất phát hiện đặc trưng. Môi trường mô phỏng MockIPBehavior — do nhóm xây dựng với nhiễu ngẫu nhiên hóa miền ±20% — được dùng riêng cho huấn luyện PPO.

---

## 4.2 Trình bày Dữ liệu

### 4.2.1 Kết quả Pipeline Chuẩn hóa Payload

Pipeline chuẩn hóa payload được kiểm tra trên 10 trường hợp đại diện, bao gồm các kỹ thuật vượt qua thực tế: mã hóa HTML entity, mã hóa URL kép và Base64. Kết quả: **10/10 trường hợp kiểm tra đạt** — pipeline phát hiện đúng mẫu tấn công trong toàn bộ payload được mã hóa thử nghiệm.

Benchmark hiệu suất trên N = 10.000 lần gọi: độ trễ trung bình = **23,55 µs/lần gọi**, trung vị = 22,1 µs, P95 = 38,2 µs, P99 = 67,4 µs, thông lượng = **42.457 lần gọi/giây**. Pipeline đủ xử lý server 10.000 yêu cầu/giây với chi phí dưới 1% CPU trên một lõi đơn.

### 4.2.2 Phân tích CRS Paranoia Level

Chạy benchmark CRS với tập LSNM2024 SQLi để xác định Paranoia Level tối ưu cho F13:

| PL | Số luật | TP | FP | F1-Score | FPR | Quyết định |
|---|---|---|---|---|---|---|
| PL1 | 19 | 1.695 | 0 | 0,753 | 0,0% | FPR=0 nhưng bỏ sót 40% tấn công |
| **PL2** | **50** | **2.809** | **459** | **0,925** | **15,3%** | **Tốt nhất — được chọn** |
| PL3 | 57 | 2.809 | 520 | 0,915 | 17,3% | FP cao hơn, không tốt hơn PL2 |

*n = 2.809 URI SQLi + 3.000 URI bình thường từ LSNM2024 (Lashkari et al., 2024). Đây là đánh giá trên URI đơn lẻ (không phải cửa sổ 1 giây), nên các giá trị TP/FP/FPR phản ánh hiệu quả của F13 khi xét riêng lẻ trước khi tổ hợp vào vector 20D.*

PL2 được chọn: F1-score 0,925, Recall = 1,0 (không bỏ sót tấn công), FPR = 15,3% — giao phần xử lý dương tính giả còn lại cho tác tử RL.

**Phân tích CRS XSS (F18):** Benchmark CRS 941 PL2 trên tập LSNM2024 XSS (n = 9 URI tấn công + 3.000 URI bình thường) cho F1-score = 1,000, FPR = 0,0%. Tuy nhiên, tập tấn công chỉ gồm 9 mẫu — quá nhỏ để kết luận thống kê chắc chắn. Kết quả này có giá trị tham khảo về hướng sai số (recall cao, không có false positive), nhưng cần xác nhận thêm trên tập XSS lớn hơn. Trong hệ thống ANDS, F18 đóng vai trò phụ trợ cho F19/F20 (binary signals) — tác tử RL không phụ thuộc vào F18 đơn lẻ để phân loại XSS.

### 4.2.3 Hiệu suất Phát hiện theo Đặc trưng

Mỗi nhóm đặc trưng được đánh giá độc lập bằng phân loại nhị phân (RandomForest 200 cây, lấy mẫu cân bằng, chia train-test 70/30, seed=42) trên tập CSV cửa sổ 1 giây trích xuất từ Bộ dữ liệu PCAP Gói tin Đột biến. **Đơn vị đánh giá là cửa sổ 1 giây** (không phải phiên kết nối) — phù hợp với đầu vào thực tế của tác tử RL.

**Bảng 4.1: Kết quả phân loại của từng nhóm đặc trưng** *(nguồn: Bộ dữ liệu PCAP Gói tin Đột biến, Abu Al-Haija et al., 2025; đánh giá RandomForest 200 cây, lấy mẫu cân bằng, chia train-test 70/30, seed=42)*

*Đơn vị đánh giá là **cửa sổ 1 giây** (không phải phiên kết nối). Mỗi "mẫu" là một vector 20D từ một cửa sổ thời gian. Một phiên tấn công điển hình kéo dài 30–120 giây tạo ra 30–120 cửa sổ, nhưng chỉ một số trong đó chứa payload tấn công thực sự.*

| Loại Tấn công | Đặc trưng Chính | Precision | Recall | F1-Score | Tập Kiểm tra (cửa sổ) |
|---|---|---|---|---|---|
| SYN Flood | F1, F2, F9 | 0,991 | 1,000 | 0,995 | 426 cửa sổ |
| Port Scan | F4, F5, F11 | 1,000 | 0,508 | 0,674 | 969 cửa sổ |
| Brute Force | F6, F7, F8 | 0,520 | 1,000 | 0,684 | 1.749 cửa sổ |
| SQLi | F13, F14–F16 | 1,000 | 0,263 | 0,417 | 532 cửa sổ |
| XSS | F18, F19–F20 | 1,000 | 0,075 | 0,140 | 187 cửa sổ |

**Diễn giải Kết quả:** SYN Flood đạt F1 = 0,995 vì các đặc trưng mạng (F1, F2, F9) phân biệt rõ ràng toàn bộ cửa sổ tấn công — lưu lượng flood lấp đầy mọi cửa sổ trong phiên. Ngược lại, Recall thấp của SQLi (0,263) và XSS (0,075) là hệ quả tất yếu của thiết kế **phân tích per-window**: chỉ những cửa sổ 1 giây có HTTP request chứa payload thực sự mới kích hoạt F12–F20 — phân tích trên ft_sqli.csv xác nhận 75,4% cửa sổ trong phiên SQLi không chứa payload tấn công (chỉ TCP setup/teardown/response), và 92,6% cửa sổ trong phiên XSS tương tự.

**Quan trọng — phân biệt per-window và per-session:** Recall = 0,263 với SQLi có nghĩa là 26,3% *cửa sổ 1 giây trong phiên SQLi* được phân loại đúng là tấn công — không phải 26,3% *phiên tấn công* bị bỏ sót. Ở cấp độ phiên (session-level), nếu ít nhất một cửa sổ trong phiên được phát hiện đúng, tác tử RL có thể phản ứng kịp thời. Phân tích trên tập kiểm tra xác nhận **100% phiên SQLi có ít nhất 1 cửa sổ** vượt ngưỡng phát hiện, tương tự cho XSS.

Precision = 1,000 cho SQLi và XSS xác nhận không có dương tính giả — mọi cửa sổ được phân loại là tấn công đều thực sự chứa payload độc hại. Recall thấp với Port Scan (0,508) và Brute Force (Precision 0,520) phản ánh tương tự: nhiều cửa sổ trong phiên quét hoặc brute force chứa lưu lượng bình thường xen kẽ. Precision 0,520 với Brute Force nghĩa là ~48% cửa sổ được phân loại là Brute Force thực ra là bình thường — một số lưu lượng web hợp lệ có URLConcentration cao (ví dụ: phiên đăng nhập nhiều lần trong cùng cửa sổ). Trong triển khai thực tế, tác tử RL không cần phát hiện 100% các cửa sổ — chỉ cần tín hiệu đủ sớm trong phiên tấn công để phản ứng.

### 4.2.4 Trọng số Đặc trưng và Phân cụm

Random Forest Feature Importances trên tập CSV đã trích xuất xác nhận F1 (PacketRate) và F13 (CRS SQLi) đóng góp lớn nhất, phù hợp với đặc thù tấn công DDoS và SQLi. Biểu đồ t-SNE (perplexity = 30) đưa vector 20 chiều về 2 trục chính cho thấy các cụm tấn công và lưu lượng bình thường tách rời rõ ràng — xác nhận F1–F20 có sức phân biệt cao và không bị chồng chéo nhãn.

### 4.2.5 Đường cong Học tập của Tác tử RL

Tác tử Phòng thủ RL được huấn luyện cho đến khi hội tụ (khoảng 500.000 timesteps, seed cố định 42, n_envs=4). Kết quả huấn luyện được ghi nhận qua TensorBoard với tần suất đánh giá mỗi 10.000 bước.

*(Hình 4.1: Đường cong học tập `eval/mean_reward` và `train/entropy_loss` theo số bước huấn luyện — trích từ TensorBoard log tại `AI RL/runs/run_final_v4/`.)*

`eval/mean_reward` cải thiện từ **0,4** tại lần đánh giá đầu tiên (bước 10.000) lên **2,3** tại điểm hội tụ (bước ~350.000) — tăng **+475%**. Giai đoạn cải thiện nhanh nhất diễn ra từ bước 50.000 đến 250.000 khi agent học phân biệt tấn công thể tích (SYN Flood, Port Scan) từ lưu lượng bình thường; từ bước 250.000 đến 350.000 học tinh chỉnh phân biệt tấn công L7. Từ bước 350.000 trở đi reward ổn định trong biên độ ±0,05, cho thấy chính sách đã đạt gần tối ưu.

Độ dài episode (`eval/mean_ep_length`) giữ nguyên ở **120 bước** suốt quá trình huấn luyện, xác nhận môi trường không bị ngắt sớm (không có terminal state do lỗi).

`train/entropy_loss` giảm từ **−1,1** xuống khoảng **−0,1** — agent ngày càng tự tin hơn. Giá trị entropy cuối ≈ 0,1 (tương ứng ~1,1 nats) cho thấy agent vẫn duy trì mức khám phá nhất định nhờ `ent_coef = 0,01` trong siêu tham số, không bị hội tụ cứng về một hành động duy nhất.

### 4.2.6 Chỉ số Chẩn đoán PPO

Bảng 4.2 trình bày các chỉ số nội bộ của thuật toán PPO ghi nhận qua TensorBoard, xác nhận quá trình huấn luyện ổn định và không có dấu hiệu bất thường.

**Bảng 4.2: Chỉ số chẩn đoán PPO trong quá trình huấn luyện**

| Chỉ số | Giá trị Đầu | Giá trị Cuối | Trạng thái | Diễn giải |
|---|---|---|---|---|
| approx_kl | 0,012 | 0,003 | ✓ Tốt | Dưới ngưỡng 0,02 — cập nhật chính sách an toàn |
| clip_fraction | 0,14 | 0,02 | ✓ Tốt | Cắt gradient hiếm khi kích hoạt tại hội tụ |
| clip_range | 0,20 | 0,20 | ✓ Cố định | ε = 0,2 theo thiết kế |
| entropy_loss | −1,10 | −0,10 | ✓ Tốt | Agent tự tin; vẫn duy trì khám phá |
| explained_variance | 0,06 | 0,26 | ⚠ Thấp | Chấp nhận được: phương sai return cao do 5 loại tấn công ngẫu nhiên |
| value_loss | 2,50 | ~0,00 | ✓ Tốt | Critic hội tụ — ước lượng return chính xác |
| learning_rate | 3×10⁻⁴ | 1×10⁻⁴ | ✓ Tốt | Giảm tuyến tính hoạt động đúng thiết kế |

Tất cả chỉ số nằm trong ngưỡng khỏe mạnh của PPO. `explained_variance` = 0,26 thấp hơn mức lý tưởng (≥ 0,8) nhưng phản ánh đặc thù của môi trường: mỗi episode trộn ngẫu nhiên 5 loại tấn công với hồ sơ reward rất khác nhau, khiến phương sai của return cao tự nhiên. Mức cải thiện +475% của `eval/mean_reward` xác nhận mạng chính sách học hiệu quả bất chấp critic chưa hoàn hảo.

### 4.2.7 Kết quả Đánh giá Cuối cùng

Agent được đánh giá trên tập kiểm tra độc lập gồm 2.000 episodes, mỗi episode chứa hỗn hợp ngẫu nhiên lưu lượng bình thường và tấn công.

**Bảng 4.3: Kết quả phân loại hành động của Tác tử Phòng thủ RL** *(nguồn: đánh giá 2.000 episodes trên **môi trường mô phỏng MockIPBehavior** — vector trạng thái tổng hợp với nhiễu ±20%, không phải lưu lượng mạng thực)*

*Lưu ý về phạm vi đánh giá: tác tử RL được huấn luyện và đánh giá trên cùng loại môi trường tổng hợp (MockIPBehavior). Kết quả phản ánh khả năng ra quyết định của chính sách đã học trong điều kiện mô phỏng. Xác minh trên lưu lượng thực được thực hiện định tính qua 4 kịch bản Containernet (Mục 4.4.2).*

| Loại Lưu lượng | Hành động Tối ưu | Tỷ lệ Đúng | Dương tính Giả | Ghi chú |
|---|---|---|---|---|
| Bình thường | Cho phép (0) | 93,2% | 6,8% | Agent đôi khi Giới hạn Tốc độ nhầm |
| SYN Flood | Chặn (3) | 96,4% | — | Phân biệt rõ qua F1, F2, F9 |
| Port Scan | Chặn (3) | 91,8% | — | F4 + F5 cao → triệt tiêu ngay |
| Brute Force | Chuyển hướng (2) | 84,7% | — | → Honeypot, thăng cấp sau 60s |
| SQLi | Chuyển hướng (2) | 91,3% | — | Điểm CRS → Honeypot mồi nhử |
| XSS | Chuyển hướng (2) | 94,8% | — | CRS XSS + JS → Honeypot |

*"Tỷ lệ Đúng" = tỷ lệ episode trong đó agent chọn hành động phòng thủ tối ưu theo thiết kế hàm phần thưởng. Mỗi loại lưu lượng được đánh giá trên tập episode riêng biệt có nhãn đã biết. Kết quả tổng hợp (tất cả loại): tỷ lệ phát hiện = **91,6%**, dương tính giả = **6,8%**.*

---

## 4.3 Phân tích Kết quả

### 4.3.1 Đóng góp Thành phần (Nghiên cứu Ablation)

Để định lượng đóng góp của từng thành phần, nhóm lần lượt loại bỏ từng thành phần và đo sự suy giảm hiệu suất agent.

**Bảng 4.4: Nghiên cứu Ablation — Ảnh hưởng khi loại bỏ từng thành phần**

*(Đánh giá trên 2.000 episodes/cấu hình, môi trường MockIPBehavior, seed=42. Tất cả cấu hình chạy với cùng tập kiểm tra và cùng điều kiện ban đầu.)*

| Cấu hình | Tỷ lệ Phát hiện | Dương tính Giả | Δ Phát hiện | Ghi chú |
|---|---|---|---|---|
| Hệ thống đầy đủ (baseline) | 91,6% | 6,8% | — | |
| Không có F12–F20 (bỏ đặc trưng HTTP) | 73,2% | 5,1% | **−18,4 pp** | Mất khả năng phát hiện SQLi/XSS |
| Không có luật CRS (F13, F18) | 81,4% | 6,9% | −10,2 pp | Giảm mạnh với SQLi phức tạp |
| Không có PayloadNormalizer | 78,8% | 7,2% | **−12,8 pp** | Bỏ sót tấn công được mã hóa |
| Cửa sổ 5s thay vì 1s | 88,1% | 9,3% | −3,5 pp | Dương tính giả tăng +2,5 pp đáng kể |
| Không có luồng hai chiều | 86,7% | 8,1% | −4,9 pp | Giảm với SYN Flood, Port Scan |

Ba đóng góp kỹ thuật quan trọng nhất: (1) Nhóm F12–F20 là thiết yếu — loại bỏ làm tỷ lệ phát hiện giảm 18,4 điểm, chủ yếu do mất SQLi/XSS; (2) PayloadNormalizer đóng góp 12,8 điểm — không có nó, payload được mã hóa sẽ bị bỏ sót; (3) Cửa sổ 1 giây là điểm cân bằng tối ưu — tăng lên 5 giây làm FPR tăng 2,5 điểm do trộn lẫn nhiều hành vi trong cùng cửa sổ.

### 4.3.2 Hiệu năng Phản ứng Thời gian Thực

Chu kỳ phòng thủ đầu-cuối bao gồm bốn bước:

1. **Tích lũy cửa sổ:** ~1.000ms — tích lũy gói tin trong cửa sổ 1 giây (thành phần chi phối).
2. **Tính toán đặc trưng (20D):** ~5ms.
3. **Suy diễn PPO (Forward Pass):** ~1ms.
4. **Thực thi Iptables:** ~10ms.

**Tổng cộng ≈ 1.016ms.** Dù trễ hơn rule engine như Snort (< 1ms), bù lại agent phân tích hành vi tích lũy thay vì từng gói tin lẻ, dẫn đến FPR thấp hơn đáng kể và khả năng thích ứng với tấn công mới.

### 4.3.3 Phân tích Hành vi Chính sách

Với lưu lượng bình thường, agent chọn Cho phép (0) trong 93,2% trường hợp. Tỷ lệ dương tính giả 6,8% chủ yếu là Giới hạn Tốc độ (1) chứ không phải Chặn (3) — agent nghiêng về biện pháp nhẹ nhàng khi không chắc chắn, phù hợp với thiết kế hàm phần thưởng.

Với tấn công thể tích (SYN Flood, Port Scan), agent áp dụng Chặn (3) trực tiếp — phản ứng đúng đắn và triệt để. Với tấn công Layer 7 (Brute Force, SQLi, XSS), agent ưu tiên Chuyển hướng (2) sang Honeypot — bảo toàn cơ hội phân tích ý định tấn công và SOC xem xét. Sau 60 giây nếu tín hiệu tấn công L7 tiếp tục, bộ theo dõi trạng thái IP tự động thăng cấp lên Chặn (3). Hành vi phân tầng này chứng tỏ agent đã học được sự khác biệt về mức độ đe dọa giữa các loại tấn công, không chỉ phân biệt tấn công/bình thường.

---

## 4.4 Diễn giải Kết quả

### 4.4.1 Đánh giá Tổng thể

Đồ án đạt được mục tiêu nghiên cứu: xây dựng thành công hệ thống phòng thủ mạng tự động dựa trên RL với khả năng phát hiện và phản ứng với năm loại tấn công phổ biến. Kết quả định lượng (tỷ lệ phát hiện **91,6%**, dương tính giả **6,8%**) xác nhận tính khả thi của phương pháp RL trong bài toán bảo mật mạng.

Đóng góp quan trọng nhất là thiết kế Module Quan sát — cầu nối giữa lưu lượng mạng thô và không gian trạng thái MDP. Việc tích hợp OWASP CRS trực tiếp vào vector đặc trưng (F13, F18) là hướng tiếp cận mới, kết hợp kiến thức chuyên gia bảo mật với khả năng học tự động của RL, thay vì coi hai phương pháp này là đối lập nhau.

### 4.4.2 Xác minh Kịch bản Thực tế

Bốn kịch bản thực tế được thực thi và xác minh qua log Iptables:

1. **Lưu lượng HTTPS bình thường:** F1 < 60 pps, F12 = 0, F7 = 0,1. → **Hành động 0 (Cho phép)**. Iptables sạch.

2. **SYN Flood thể tích:** hping3 flood trên cổng 443. F1 bùng nổ lên 350 pps, payload ≈ 0. → **Hành động 3 (Chặn)**. Luật DROP được đẩy vào chain FORWARD.

3. **SQLi Tránh né (sqlmap):** Phát hiện mẫu UNION SELECT — F14 = 1, F13 tăng mạnh. → **Hành động 2 (Chuyển hướng)** về cổng 4443. Kẻ tấn công tiếp tục cào CSDL trên Honeypot trong khi 192.168.10.10 hoàn toàn an toàn. Sau 60 giây bộ theo dõi IP thăng cấp → **Chặn**.

4. **XSS Botnet:** Tiêm `onerror=` — F18 tăng, F20 = 1. → **Hành động 2 (Chuyển hướng)** → thăng cấp Chặn sau 60 giây.

### 4.4.3 Phát hiện Kỹ thuật Chính

Ba quyết định thiết kế được xác nhận là then chốt cho hiệu suất hệ thống:

**Nhóm Đặc trưng HTTP (F12–F20):** Chịu trách nhiệm cho 18,4 điểm phần trăm tỷ lệ phát hiện. Nếu không có nhóm đặc trưng này, agent không thể phân biệt SQLi/XSS với lưu lượng bình thường — chúng không để lại dấu vết ở tầng mạng. Việc tích hợp bộ quy tắc OWASP CRS 942 và 941 trực tiếp vào vector đặc trưng (F13, F18) giúp tránh phải xây dựng luật phát hiện L7 từ đầu.

**PayloadNormalizer:** Chịu trách nhiệm cho 12,8 điểm phần trăm tỷ lệ phát hiện. URL decode đệ quy (tối đa 2 vòng) xử lý kỹ thuật vượt qua mã hóa kép — kỹ thuật tránh né phổ biến nhất theo Spett [9]. Không có chuẩn hóa, payload như `%27%20OR%20%271%27%3D%271` sẽ xuất hiện như văn bản không thể nhận dạng với so khớp mẫu.

**Cửa sổ Trượt 1 Giây:** Điểm cân bằng tối ưu giữa độ phân giải thời gian và ổn định thống kê. Tăng lên 5 giây làm FPR tăng 2,5 điểm do nhiều trạng thái hành vi hợp nhất trong cùng một cửa sổ — agent không còn phân biệt rõ ràng các giai đoạn chuyển đổi tấn công.

---

## 4.5 So sánh với Tài liệu

So sánh trực tiếp con số giữa các nghiên cứu khác nhau không hoàn toàn hợp lệ do sự khác biệt về tập dữ liệu, định nghĩa nhãn và phương pháp đánh giá. Phần này tập trung vào so sánh phương pháp luận.

**So sánh với trích xuất đặc trưng truyền thống:** Sharafaldin et al. [6] phát triển CICFlowMeter sử dụng hơn 80 đặc trưng thống kê luồng hai chiều và đạt accuracy > 97% trên CICIDS2017 với Random Forest. Tuy nhiên, số lượng đặc trưng lớn tăng chi phí tính toán đáng kể và thiếu đặc trưng ngữ nghĩa nội dung (L7). Nghiên cứu này chứng minh 20 đặc trưng chọn lọc — kết hợp tầng mạng và tầng payload — có thể đạt hiệu suất cạnh tranh với chi phí thấp hơn, phù hợp cho vòng lặp thời gian thực 1 giây.

**So sánh với NIDS trên UNSW-NB15:** Moustafa & Slay [16] báo cáo Random Forest đạt accuracy 85,6% và FPR 0,89% trên UNSW-NB15 cho phân loại nhị phân. Kết quả không thể so sánh trực tiếp do UNSW-NB15 có phân phối nhãn khác và sử dụng phân loại nhị phân, trong khi nghiên cứu này giải quyết bài toán đa lớp 5 loại tấn công kèm lựa chọn hành động phòng thủ — bài toán phức tạp hơn đáng kể.

**So sánh về hướng tiếp cận RL:** Theo khảo sát của Ring et al. [17], phần lớn nghiên cứu NIDS hiện tại sử dụng học có giám sát trên tập dữ liệu tĩnh. Áp dụng RL vào phòng thủ mạng với vòng phản hồi khép kín — nơi hành động phòng thủ thay đổi trạng thái môi trường — là hướng tiếp cận mới so với xu hướng chính, phù hợp với định hướng phòng thủ mạng tự trị [12].

**Điểm khác biệt then chốt:** Tích hợp OWASP CRS vào vector đặc trưng (F13, F18) là thiết kế không tìm thấy trong tài liệu khảo sát. Thay vì xây dựng bộ luật phát hiện từ đầu, hệ thống kế thừa tri thức chuyên gia bảo mật đã được cộng đồng xác thực trong nhiều năm, giúp giảm đáng kể yêu cầu dữ liệu huấn luyện có nhãn cho tấn công L7.

**Bảng 4.5: So sánh hiệu suất tác tử RL với các phương pháp cơ sở**

*(Đánh giá trên môi trường MockIPBehavior, 2.000 episodes, seed=42. Luật Tĩnh = bộ quy tắc ngưỡng cố định 5 luật tương ứng 5 loại tấn công. Random Forest 200 cây, lấy mẫu cân bằng, huấn luyện trên 70% tập dữ liệu. **Tất cả ba phương pháp được đánh giá trên cùng tập kiểm tra tổng hợp** — kết quả không thể so sánh trực tiếp với các nghiên cứu trên tập dữ liệu khác do sự khác biệt về phân phối dữ liệu và định nghĩa nhãn.)*

| Phương pháp | Tỷ lệ Phát hiện | Dương tính Giả | Thời gian Phản ứng | Khả năng Thích ứng |
|---|---|---|---|---|
| Luật Tĩnh | 74,3% | 12,1% | < 1ms | Không |
| Random Forest | 87,9% | 8,4% | ~5ms | Không — chính sách cố định sau huấn luyện |
| **Tác tử RL (PPO)** | **91,6%** | **6,8%** | ~1.016ms | **Có — vòng lặp phản hồi khép kín** |

*Ưu điểm và đánh đổi: RL đạt tỷ lệ phát hiện cao nhất (+3,7 pp so với RF) và FPR thấp nhất, nhưng có thời gian phản ứng cao nhất (~1 giây) do chu kỳ cửa sổ quan sát. Với tấn công flash (SYN Flood cường độ cực cao dưới 1 giây), luật tĩnh phản ứng nhanh hơn. Trong môi trường tấn công hỗn hợp kéo dài, RL mang lại lợi thế rõ ràng.*

---

## 4.6 Hàm ý của Kết quả

### 4.6.1 Khi nào Nên Ưu tiên RL thay vì Luật Tĩnh

RL mang lại giá trị rõ ràng khi môi trường mạng có tấn công đa dạng và thay đổi theo thời gian — đặc biệt với mạng xử lý đồng thời tấn công thể tích (SYN Flood) lẫn tấn công payload (SQLi, XSS). Với môi trường có lưu lượng đơn điệu và mẫu tấn công ổn định, Luật Tĩnh vẫn hiệu quả hơn do độ trễ < 1ms và không yêu cầu giai đoạn huấn luyện.

### 4.6.2 Yêu cầu Hạ tầng Tối thiểu

Hệ thống yêu cầu một điểm capture tập trung (router biên) với khả năng chạy Python 3 và Scapy. Suy diễn PPO chỉ cần < 1ms CPU trên MLP 2 lớp — có thể chạy trên phần cứng nhúng nhỏ gọn. Thành phần chiếm tài nguyên chủ yếu là bộ quản lý luồng (RAM cho đến 50.000 flows đồng thời) và capture gói tin (CPU).

### 4.6.3 Đánh đổi Độ trễ so với Độ chính xác

Chu kỳ phòng thủ ~1.016ms là yếu điểm cần thừa nhận rõ với người vận hành. Trong 1 giây đầu của tấn công chớp nhoáng (SYN Flood cường độ cao), hệ thống chưa kịp phản ứng. Biện pháp giảm thiểu: thiết lập một lớp giới hạn tốc độ tĩnh tối giản ở router như mạng lưới an toàn, để tác tử RL xử lý phân loại chính xác từ cửa sổ thứ hai trở đi.

### 4.6.4 Honeypot như Lợi thế Chiến lược

Hành động Chuyển hướng sang Honeypot — thay vì Chặn ngay — mang lại giá trị vượt ra ngoài phòng thủ thuần túy: kẻ tấn công tiếp tục hoạt động trong môi trường được kiểm soát, cho phép SOC thu thập thông tin tình báo mối đe dọa (TTPs, payloads, công cụ) mà không gây nguy hại cho hệ thống thật. Đây là lợi thế mà Luật Tĩnh và bộ phân loại RF không có khả năng cung cấp.

### 4.6.5 Khả năng Tái sử dụng Chính sách

Chính sách đã huấn luyện có thể được triển khai lại trên môi trường mới mà không cần huấn luyện lại, miễn là vector đặc trưng 20 chiều giữ nguyên định nghĩa. Điều này cho phép tổ chức triển khai nhanh chính sách đã được kiểm tra kỹ trong môi trường lab trước khi đưa vào sản xuất.

### 4.6.6 Hướng Phát triển Tiếp theo

**Mở rộng Không gian Hành động:** Thêm hành động chi tiết hơn như Giới hạn Tốc độ theo IP nguồn, Chuyển hướng theo loại yêu cầu, hoặc tạo honeypot động. Đòi hỏi nghiên cứu về action masking để hướng dẫn khám phá trong không gian lớn hơn.

**Đa tác tử và Phòng thủ Phân tán:** Mở rộng từ đơn tác tử sang RL đa tác tử trong đó mỗi nút mạng có agent riêng và phối hợp qua giao thức chia sẻ kinh nghiệm — bước tự nhiên để mở rộng từ topology 10 VM lên mạng sản xuất theo kiến trúc SDN.

**Nâng cấp Phân tích Payload lên mức TCP Stream:** Mở rộng pipeline từ per-HTTP-request sang tái hợp TCP để xử lý POST body bị phân mảnh — phục vụ các kịch bản tấn công qua tải file, XML/SOAP injection, hoặc multipart form data lớn. Cần thiết kế lại cách định nghĩa các đặc trưng F13, F17, F18 để tương thích với đơn vị phân tích mới.

---

## TÀI LIỆU THAM KHẢO

[1] Puterman, M. L. (1994). *Markov Decision Processes: Discrete Stochastic Dynamic Programming*. John Wiley & Sons.

[2] Schulman, J., Wolski, F., Dhariwal, P., Radford, A., & Klimov, O. (2017). Proximal Policy Optimization Algorithms. *arXiv preprint arXiv:1707.06347*.

[3] Raffin, A., Hill, A., Gleave, A., Kanervisto, A., Ernestus, M., & Dormann, N. (2021). Stable-Baselines3: Reliable Reinforcement Learning Implementations. *Journal of Machine Learning Research, 22*(268), 1–8.

[4] Peuster, M., Karl, H., & van Rossem, S. (2016). MeDICINE: Rapid Prototyping of Production-Ready Network Services in Multi-PoP Environments. Trong *Proceedings of the IEEE Conference on Network Function Virtualization and Software Defined Networks (NFV-SDN 2016)*, trang 148–153.

[5] Lashkari, A. H., et al. (2024). *LSNM2024: A Labeled Network Traffic Dataset for Intrusion Detection*. Đại học New Brunswick.

[6] Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. Trong *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)*, trang 108–116.

[7] Postel, J. (1981). *Transmission Control Protocol*. RFC 793. IETF.

[8] OWASP Foundation. (2023). *OWASP ModSecurity Core Rule Set (CRS) v4.0*. https://coreruleset.org/

[9] Spett, K. (2005). *SQL Injection: Are Your Web Applications Vulnerable?* SPI Dynamics White Paper.

[10] Kruegel, C., & Vigna, G. (2003). Anomaly Detection of Web-Based Attacks. Trong *Proceedings of the 10th ACM CCS* (trang 251–261).

[11] Towers, M., et al. (2023). Gymnasium: A Standard Interface for Reinforcement Learning Environments. *arXiv preprint arXiv:2407.17032*.

[12] Sutton, R. S., & Barto, A. G. (2018). *Reinforcement Learning: An Introduction* (Phiên bản thứ 2). MIT Press.

[13] Mnih, V., et al. (2015). Human-Level Control through Deep Reinforcement Learning. *Nature, 518*(7540), 529–533.

[14] OWASP Foundation. (2021). *OWASP Top Ten*. https://owasp.org/www-project-top-ten/

[15] Shiravi, A., Shiravi, H., Tavallaee, M., & Ghorbani, A. A. (2012). Toward Developing a Systematic Approach to Generate Benchmark Datasets for Intrusion Detection. *Computers & Security, 31*(3), 357–374.

[16] Moustafa, N., & Slay, J. (2015). UNSW-NB15: A Comprehensive Dataset for Network Intrusion Detection Systems. Trong *Proceedings of MilCIS 2015*.

[17] Ring, M., et al. (2019). A Survey of Network-Based Intrusion Detection Data Sets. *Computers & Security, 86*, 147–167.

[18] ModSecurity. (2023). *ModSecurity Web Application Firewall Documentation*. https://modsecurity.org/

[19] Fielding, R., & Reschke, J. (2014). *Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing*. RFC 7230. IETF.

[20] Schmitt, F., Gassen, J., & Gerhards-Padilla, E. (2012). HTTP Antivirus Proxy — An Approach to Defend Against Slow HTTP DoS Attacks. Trong *Proceedings of IEEE ICCNC 2012*.

[21] Abu Al-Haija, Q., Masoud, Z., Yasin, A., Alesawi, K., & Alkarnawi, Y. (2025). End-to-End Threat Hunting with a Novel Multiclass Dataset for Intelligent Intrusion Detection. *arXiv preprint arXiv:2508.05609*. Đại học Khoa học và Công nghệ Jordan & Đại học Công nghệ Công chúa Sumaya.
