# Script Thuyết Trình KLTN — IAP491 Nhóm 3
# RL Defense Agent: NIDS Pipeline & Feature Extraction

> **Thời lượng dự kiến:** Phần chính 12–15 phút | Q&A kỹ thuật 7–10 phút

---

## PHẦN 1: FORMAL DEFENSE

---

### [Slide 1] Mở đầu

> "Kính chào hội đồng. Em tên [**tên**], đại diện nhóm 3. Hôm nay em xin trình bày đề tài: **Xây dựng hệ thống phát hiện xâm nhập mạng sử dụng Reinforcement Learning** — cụ thể là thiết kế và triển khai pipeline trích xuất đặc trưng cho RL defense agent."

---

### [Slide 2] Bối cảnh & Vấn đề

> "Các hệ thống NIDS truyền thống như Snort hay Suricata dựa trên rule tĩnh — chúng phát hiện tốt các mẫu tấn công đã biết nhưng không thích nghi được với các biến thể mới. Câu hỏi nghiên cứu của chúng em là: liệu một RL agent có thể học chính sách bảo vệ mạng hiệu quả hơn rule tĩnh không?"

> "Để trả lời câu hỏi đó, hệ thống cần một **sensor** — tức là một NIDS — có khả năng trích xuất đặc trưng thời gian thực từ traffic mạng và cung cấp observation vector cho RL agent. Đây chính là phần `System/` mà nhóm em thiết kế."

> "Yêu cầu đặt ra có 3 ràng buộc cứng: **(1)** output phải là vector số thực [0,1] — RL không làm việc với dữ liệu thô; **(2)** phải chạy được theo thời gian thực, tức mỗi window 1 giây phải có kết quả; **(3)** phải phủ được cả tầng network lẫn tầng application layer để detect đa dạng attack."

---

### [Slide 3] Kiến trúc tổng thể

> "Pipeline xử lý gồm 5 tầng theo thứ tự từ trái sang phải."

> "**Tầng 1 — Thu thập:** Hệ thống hỗ trợ 3 nguồn đầu vào. Mode 1 là realtime capture — Scapy lắng nghe trực tiếp trên network interface, đẩy gói tin vào một `PacketQueue` thread-safe với kích thước tối đa 10,000. Mode 2 là PCAP offline — đọc file `.pcap` theo từng gói, giả lập timestamp từ metadata gói tin. Mode 3 là Wireshark CSV — import bảng thống kê đã export sẵn."

> "**Tầng 2 — Parse:** Mỗi gói tin được `PacketLayerExtractor` phân tích theo pipeline đơn chiều: IP layer → TCP layer → HTTP layer. Kết quả là một `LayerInfo` dataclass — cấu trúc dữ liệu chuẩn hóa chứa src_ip, dst_ip, ports, TCP flags, HTTP method, URI, User-Agent, body payload."

> "**Tầng 3 — Flow Management:** `FlowManager` gom các `LayerInfo` vào flows theo **5-tuple**: `(src_ip, dst_ip, src_port, dst_port, protocol)`. Mỗi flow theo dõi hai chiều độc lập: forward là gói tin từ client đến server, backward là ngược lại. Kỹ thuật sliding window loại bỏ packets cũ hơn 1 giây để đảm bảo tính thời gian thực."

> "**Tầng 4 — Feature Calculation:** `FlowFeatureCalculator` tính 20 đặc trưng từ mỗi flow trong window hiện tại. Trước khi tính các đặc trưng L7, payload HTTP được chuẩn hóa qua 6 bước để chống evasion."

> "**Tầng 5 — Normalize & Output:** 20 giá trị thô được chiếu về [0,1] bằng công thức log-scale hoặc linear tùy loại feature, tạo thành observation vector 20D. Kết hợp thêm 10D temporal state và 4D effect phản hồi từ agent, tổng cộng 34D đầu vào cho RL model."

---

### [Slide 4] Flow Management — Kỹ thuật xử lý lõi

> "Trước khi nói đến features, em muốn giải thích kỹ thuật xử lý ở tầng FlowManager vì đây là nơi quyết định chất lượng dữ liệu cho toàn bộ pipeline."

> "**Flow key 5-tuple:** Với mỗi gói tin đến, hệ thống tạo flow key dạng `(src_ip, dst_ip, src_port, dst_port, proto)`. Đồng thời tạo **reverse key** `(dst_ip, src_ip, dst_port, src_port, proto)` — nếu reverse key đã tồn tại trong bảng flows, gói tin này thuộc về flow đó theo chiều backward. Cách này xử lý đúng traffic bidirectional mà không cần phân tích TCP state machine phức tạp."

> "**Sliding window:** Thay vì giữ toàn bộ lịch sử flow, mỗi `FlowState` chỉ giữ packets trong cửa sổ 1 giây gần nhất. Khi window tiến lên, phương thức `_cleanup_old_packets(current_time)` duyệt deque từ đầu và pop các packet có timestamp nhỏ hơn `current_time - 1.0`. Vì deque được sắp xếp theo thứ tự thời gian, thao tác này có độ phức tạp O(k) với k là số packets bị loại — không cần duyệt toàn bộ."

> "**Memory safety:** Tổng số flows được giới hạn ở 50,000. Mỗi flow lưu tối đa 3,000 packets mỗi chiều. Khi đạt ngưỡng, hệ thống thử cleanup flows đã timeout (120 giây không có gói mới) trước khi từ chối gói tin mới — tránh OOM trong DDoS scenario."

> "**X-Real-IP support:** Trong môi trường có Nginx reverse proxy, địa chỉ IP thực của attacker nằm trong header `X-Real-IP`, không phải src_ip của TCP packet. `FlowState` đọc header này khi có và expose qua property `effective_src_ip` — đảm bảo features được tính theo IP thực của nguồn tấn công."

---

### [Slide 5] Feature Extraction — Lý do lựa chọn 20 Đặc trưng

> "Chúng em thiết kế 20 đặc trưng từ nguyên tắc: mỗi attack type có ít nhất 2 features đặc trưng riêng, và không có feature nào dư thừa."

> "**Nhóm mạng — F1 đến F5 — tấn công tầng network:**"
> "F1 **PacketRate** (packets/giây): DDoS volumetric gửi hàng trăm nghìn gói/giây — đây là signal mạnh nhất và đơn giản nhất. Lý do dùng log-scale: traffic bình thường ~10–50 pkt/s, DDoS ~500+ pkt/s, khoảng cách này quá lớn để linear scale phân biệt hiệu quả."
> "F2 **SynAckRatio** (fwd_SYN / bwd_SYN): SYN Flood gửi SYN liên tục nhưng server không kịp reply ACK — ratio này tăng vọt. Giá trị bình thường ~1.0 vì mỗi SYN có một SYN-ACK tương ứng."
> "F4 **RstRatio** và F5 **DistinctPorts**: Port Scan gửi SYN đến nhiều cổng — các cổng đóng trả RST ngay lập tức, tạo RST ratio cao. Số lượng distinct destination ports trong 1 giây >50 là dấu hiệu scan."

> "**F6 đến F11 — traffic asymmetry và L7 behavior:**"
> "F6 **URLConcentration**: Brute force tập trung vào một URL duy nhất như `/login` — ratio max_requests_to_url/total_requests tiến gần 1.0. Guard condition: nếu <3 requests thì trả 0.0 vì không đủ sample để kết luận."
> "F7 **HttpIatUniformity**: Bot gửi request đều đặn theo cron job — Inter-Arrival Time rất đều. Metric `1/(1+CV)` biến CV gần 0 thành uniformity gần 1.0. Đặc biệt, F7 gom IAT **across multiple TCP connections** của cùng một source IP — phát hiện được Hydra/Burp chạy nhiều thread song song."
> "F8 **RequestSizeUniformity**: Brute force dùng template cố định nên payload size rất đều — đây là complement của F7 để phân biệt bot với human erratic traffic."

> "**Nhóm SQLi — F12 đến F17 — và nhóm XSS — F18 đến F20 — sẽ được giải thích chi tiết ở slide tiếp theo về CRS."

---

### [Slide 5b] Nhóm SQLi & XSS — Cơ chế tính điểm CRS

> "Chúng em sẽ giải thích chi tiết cách F12–F20 được tính, vì đây là phần kỹ thuật phức tạp nhất và cũng là điểm đóng góp chính của pipeline."

> "**F12 SqlSpecialChar — tỷ lệ ký tự escape SQL:**"
> "Ký tự được chọn là `'`, `;`, `#` — ba ký tự hiếm gặp trong HTTP request bình thường nhưng thiết yếu trong SQL injection. Lưu ý chúng em **không đưa** `=` hay `-` vào vì `=` xuất hiện trong mọi GET parameter và `-` dùng trong UUID, header, date format. Công thức: `count(chars in {';#}) / len(normalized_payload)`. Feature này hoạt động trên **normalized payload** — nghĩa là `%27` đã được URL-decode thành `'` trước khi đếm."

> "**F13 CrsSqliScore — điểm CRS 942 bình quân mỗi request:**"
> "Đây là feature phức tạp nhất. Hệ thống tải 50 regex rules từ file `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` của OWASP CRS ở Paranoia Level 2 — mỗi rule được compile thành `re.Pattern` Python một lần duy nhất lúc khởi động."
> "Với mỗi HTTP request trong window, hệ thống chạy **tất cả 50 patterns** lần lượt qua normalized payload. Mỗi pattern match được = cộng 1.0 điểm. Cuối cùng: `F13 = total_score / http_request_count`."
> "Ví dụ cụ thể: 10 requests SQLi, mỗi request trigger trung bình 4 rules → `40 / 10 = 4.0`. 60 requests bình thường, mỗi request trigger 1 rule do false positive → `60 / 60 = 1.0`. Normalize theo request count là yếu tố quan trọng — nếu không chia, một session dài với traffic bình thường sẽ tích lũy score cao giả."
> "Lý do chọn **PL2**: chúng em benchmark trên LSNM2024 dataset — PL1 có 19 rules, F1=0.753 nhưng bỏ sót 40% tấn công (recall thấp). PL2 có 50 rules, F1=0.9245, recall=100% — không bỏ sót tấn công nào, dù FPR tăng lên 15.3%. PL3 thêm 7 rules nữa nhưng F1 giảm xuống 0.915 do FP tăng mà không tăng TP."

> "**F14 SqlUnionSelect — binary UNION-based injection:**"
> "Pattern: `\bunion\b[\s\S]{0,50}\bselect\b` với flag `IGNORECASE`. Cho phép tối đa 50 ký tự tùy ý giữa UNION và SELECT — đủ để bắt `UNION ALL SELECT` hay `UNION /*comment*/ SELECT` nhưng không quá rộng để match ngẫu nhiên. Đây là binary feature: trả 1.0 nếu bất kỳ packet nào trong window match, 0.0 nếu không."

> "**F15 SqlComment — binary comment injection:**"
> "Bốn patterns: `--(?:\s|$|[^a-zA-Z])` cho inline comment, `#` không theo sau hex color code, `/\*[\s\S]*?\*/` cho block comment, và `/\*![0-9]*` cho MySQL version comment. Điểm tinh tế: pattern `--` phải theo sau bởi whitespace hoặc end-of-string để tránh match CSS custom property như `--primary-color`."

> "**F16 SqlStackedQuery — binary stacked DDL:**"
> "Pattern: `;\s*(?:drop|delete|insert|update|truncate|alter|exec|call|grant|revoke|create|load\s+data|shutdown|xp_\w+)\b`. Dấu chấm phẩy theo sau là DDL/DML destructive hoặc stored procedure call — kỹ thuật nguy hiểm nhất trong SQLi vì có thể xóa database, tạo backdoor user."

> "**F17 SqlSelectCount — tần suất SELECT:**"
> "Đếm số lần xuất hiện của từ khóa `\bselect\b` trong tất cả requests và normalize theo request count — tương tự F13. UNION chaining thường có nhiều SELECT: `SELECT * FROM users UNION SELECT * FROM passwords` = 2 SELECT / 1 request = 2.0."

> "**F18 CrsXssScore — điểm CRS 941 bình quân mỗi request:**"
> "Tương tự F13 nhưng dùng 27 `@rx` regex rules từ `REQUEST-941-APPLICATION-ATTACK-XSS.conf` PL2 **cộng thêm** các `@pm` phrase-match terms. `@pm` là danh sách từ khóa dạng `document.cookie`, `window.location`, `.innerhtml` — mỗi từ khóa xuất hiện trong payload cũng cộng 1.0 điểm. Công thức: `(rx_hits + pm_hits) / request_count`. Benchmark: F1=1.0 trên test set XSS của LSNM2024."

> "**F19 JsFunctionCall và F20 HtmlEventHandler — binary XSS:**"
> "F19 kiểm tra 8 patterns: `alert(`, `eval(`, `prompt(`, `confirm(`, `expression(`, `document.cookie/write/domain`, `window.location`, `innerHTML=`. F20 kiểm tra 7 nhóm event handler HTML: `onerror=`, `onload=`, `onclick=` và 30+ biến thể khác. Cả hai là binary: 1.0 nếu bất kỳ packet nào trong window match."

---

### [Slide 6] Pipeline chuẩn hóa payload — Kỹ thuật xử lý evasion

> "Đây là thành phần phức tạp nhất và cũng là điểm đóng góp kỹ thuật chính. Nếu không chuẩn hóa, attacker có thể bypass toàn bộ F12-F20 bằng cách encode payload."

> "**Lý do cần chuẩn hóa:** Ví dụ payload `%27%4fR%55NI%4f%4e%20SELECT` khi decode ra là `'UNION SELECT` — một SQLi rõ ràng. Nhưng nếu match regex trực tiếp trên chuỗi encoded thì không có rule nào trúng."

> "**6 bước theo thứ tự nghiêm ngặt — thứ tự quan trọng vì mỗi bước tạo điều kiện cho bước sau:**"

> "**Bước 1 — Bytes → String:** Thử decode UTF-8 trước. Nếu fail (byte sequence không hợp lệ UTF-8), fallback sang Latin-1 — Latin-1 decode mọi byte thành ký tự 1-1 nên không bao giờ fail. Đây là safety net đảm bảo bước 2 luôn nhận được string."

> "**Bước 2 — URL decode đệ quy:** Gọi `urllib.parse.unquote_plus()` tối đa 2 lần, dừng sớm nếu output == input. Tại sao tối đa 2 lần? Double encoding như `%2527` cần 2 pass: lần 1 ra `%27`, lần 2 ra `'`. Ba lần trở lên hiếm gặp trong thực tế và tăng risk false positive. **Quan trọng:** bước này phải đứng TRƯỚC HTML decode vì `&amp;` → `&` → `%26` sẽ bị decode sai thứ tự."

> "**Bước 3 — HTML entity decode:** `html.unescape()` xử lý `&lt;script&gt;` → `<script>`, `&#x27;` → `'`. Attacker thường dùng kỹ thuật này để bypass WAF ở tầng HTTP."

> "**Bước 4 — Unicode NFKC + smart quotes:** NFKC normalization thu gọn các ký tự tương đương về dạng canonical — ví dụ `ﬁ` (ligature) → `fi`. Thêm vào đó, 12 loại smart quotes như `"` `"` `'` `'` được map về ASCII `"` và `'`. Điều này chặn homoglyph attack dùng Unicode để vượt qua keyword matching."

> "**Bước 5 — Decode Hex SQL và Base64 (conditional):** Chỉ kích hoạt khi phát hiện pattern Hex SQL dạng `0x414243...` (ít nhất 4 hex digits) hoặc Base64 substring dài ≥20 ký tự. Điều kiện decode: >80% ký tự sau decode phải là printable ASCII. Ngưỡng 80% này lọc binary data ngẫu nhiên ra — ảnh JPEG hay file binary encode Base64 sẽ fail điều kiện này."

> "**Bước 6 — Whitespace collapse và lowercase:** `\s+` → single space, trim đầu đuôi, convert về lowercase. Chặn các trick như `SeLeCt` hay tab-separated keywords."

> "**Caching FeatureContext:** Sau khi normalize, kết quả được cache theo `id(packet)`. Khi F13, F14, F15, F16, F17, F18, F19, F20 cùng cần payload của một packet — chỉ gọi normalize 1 lần, 7 lần sau lấy từ cache. Giảm từ O(N×8) xuống O(N) normalize calls."

---

### [Slide 7] Normalization — Kỹ thuật chiếu về [0,1]

> "20 giá trị thô có range rất khác nhau — F1 PacketRate có thể là 0–500+, F12 SqlSpecialChar đã là [0,1], F14 SqlUnionSelect chỉ là 0 hoặc 1. Chúng em dùng 3 chiến lược normalization tùy loại feature."

> "**Log-scale** cho F1, F2, F3, F5, F10, F11: `log(1 + min(raw, cap)) / log(1 + cap)`. Lý do dùng log: DDoS tạo ra giá trị cực lớn (F1 = 5000 pkt/s trong flood) trong khi traffic bình thường chỉ ~10–50 pkt/s. Log scale cho phép phân biệt tốt trong vùng giá trị thấp — quan trọng hơn là phân biệt 500 vs 5000 (cả hai đều là attack)."

> "**Linear-scale** cho F9, F13, F17, F18: `min(raw, cap) / cap`. Các features này có phân phối đều hơn — CRS score ít khi vượt quá 20, SELECT count ít khi quá 10."

> "**Pass-through** cho F4, F6, F7, F8, F12, F14-F16, F19, F20: Đã là [0,1] hoặc binary {0,1} — không cần xử lý thêm."

> "**Clip bounds** được calibrate trên dữ liệu thực nghiệm với window 1.0s. Đây là lý do window size bị lock cứng: thay đổi window → bounds không còn hợp lệ → toàn bộ normalized features drift → RL model predict sai."

---

### [Slide 8] RL Agent — Observation Space 34D

> "Observation vector 34 chiều được chia làm 3 phần với ý nghĩa khác nhau."

> "**[0..19] — 20D NIDS features:** Trạng thái mạng hiện tại tại thời điểm t. Agent nhìn vào đây để biết đang có attack gì xảy ra."

> "**[20..29] — 10D PerIPTemporalState:** Ngữ cảnh lịch sử của IP nguồn. Gồm: last_action one-hot 4D (action nào vừa thực hiện với IP này), action_hold_norm (bao nhiêu window đã giữ action đó), damage_ema + trend 2D (mức nguy hiểm tích lũy theo Exponential Moving Average và xu hướng tăng/giảm), window_fill_norm (tỷ lệ sử dụng buffer), escalation_score_norm và miss_budget_norm. Nhóm này giúp agent tránh lặp lại action khi đã escalate, và biết khi nào nên de-escalate."

> "**[30..33] — 4D effect_{t-1}:** Phản hồi từ môi trường sau action tại t-1. Webserver reachability: server còn alive không? Honeypot capture ratio: honeypot đang trap được bao nhiêu connections? Service presence và service damage đo lường impact của action lên legitimate traffic. Nhóm này tạo **closed-loop feedback** — agent học được hậu quả của quyết định, không chỉ quan sát trạng thái."

> "Thiết kế 34D thay vì 20D ban đầu được thêm vào commit `589ce29` sau khi nhận thấy agent 20D có xu hướng over-block — vì không có memory về lịch sử action và không nhận feedback từ môi trường."

---

### [Slide 9] Kết quả thực nghiệm

> "Để trả lời **RQ1** — so sánh hiệu quả — PPO agent đạt mean reward **2.446** (±0.021 over 5 seeds) so với Static Rule-Based 1.8, DQN 1.9, A2C 2.0 trong cùng môi trường Containernet. Sự vượt trội này đến từ khả năng chọn action linh hoạt — honeypot redirect thay vì block ngay, rate-limit thay vì block cứng — giảm false positive."

> "Về **RQ2** — cân bằng mitigation và availability — agent duy trì False Positive Rate **6.8%** và sử dụng honeypot redirection như action ưu tiên cho SQL/XSS attacks. Chiến lược này giữ legitimate traffic vẫn được serve trong khi suspicious traffic bị redirect sang honeypot để phân tích."

> "Về **RQ3** — policy stability — đường reward tăng từ 0.4 lên 2.3 (+475%), entropy_loss giảm đều từ −1.1 xuống −0.1 — agent ngày càng confident nhưng không collapse về một action duy nhất. approx_kl duy trì ở 0.003 — policy updates nhỏ và an toàn, không có divergence. Đây là bằng chứng cho thấy PPO phù hợp với bài toán này."

> "**Về hiệu quả training:** Config PPO-Tuned với n_envs=4 chạy song song đạt convergence sau 220k steps trong 197 giây wall-clock — nhanh hơn 4× so với Default SB3 (786 giây) với mức giảm reward chỉ 1.5% (2.446 vs 2.482). Đây là trade-off có lợi cho deployment."

---

### [Slide 10] Kết luận

> "Chúng em đã xây dựng thành công một NIDS pipeline với 20 đặc trưng đa tầng, tích hợp OWASP CRS Paranoia Level 2 với 50 SQLi rules và 27 XSS rules, 6-step payload canonicalization chống evasion, và cung cấp observation 34D cho RL agent."

> "Điểm đóng góp chính so với các công trình trước: **(1)** kết hợp network-level và application-level features trong một vector duy nhất; **(2)** payload canonicalization pipeline chống được double-encoding, homoglyphs, và Base64 obfuscation; **(3)** closed-loop observation 34D cho phép RL agent học chính sách có memory và feedback."

> "Hướng phát triển tiếp theo: multi-agent distributed NIDS, adversarial robustness testing với evasion-aware attackers, và explainability qua SHAP/LIME cho SOC operators."

> "Xin cảm ơn hội đồng. Nhóm em sẵn sàng trả lời câu hỏi."

---

## PHẦN 2: Q&A KỸ THUẬT

---

### [Q1] Tại sao chọn đúng 20 features — không nhiều hơn, không ít hơn?

> "Chúng em bắt đầu từ phân tích **attack signatures** của 5 attack types trong scope. Mỗi attack type có ít nhất 2 discriminating features để tránh false negative khi một feature bị adversarially suppressed."

> "DDoS cần F1 + F9 (high rate, no payload). SYN Flood cần F2 + F9 (SYN không có ACK reply, payload ~0). Port Scan cần F4 + F5 (RST từ closed ports, nhiều distinct ports). Brute Force cần F6 + F8 (URL concentration, size uniformity). Bot timing cần F7 (HTTP IAT uniformity). SQLi cần F12-F17 (6 features — L7 detection phức tạp hơn). XSS cần F18-F20."

> "Tổng cộng là 20. Chúng em đã thử giảm xuống 15 (bỏ F6, F7, F8, F11, F17) nhưng detection rate cho Brute Force và Port Scan giảm rõ rệt trong môi trường thực nghiệm. Thêm features vượt 20 không cải thiện thêm nhưng tăng observation space — RL cần nhiều steps hơn để converge."

---

### [Q2] CRS OWASP được tích hợp như thế nào ở cấp độ kỹ thuật?

> "Toàn bộ quá trình có 3 giai đoạn: **load**, **parse**, và **score**."

> "**Giai đoạn Load — khởi động một lần:**"
> "`crs_loader.py` đọc file `.conf` gốc của OWASP CRS bằng `_split_into_blocks()` — hàm này gộp các dòng kết thúc bằng dấu `\` thành một block rule duy nhất (vì SecRule thường kéo dài 3–5 dòng trong file thật). Mỗi block được classify là: comment paranoia level header, hoặc rule block."
> "Với mỗi rule block, extractor dùng 4 regex: `_RX_RE` để lấy pattern `@rx`, `_PM_RE` để lấy phrases `@pm`, `_ID_RE` để lấy rule ID số, `_MSG_RE` để lấy description. Paranoia level được track bằng biến `current_pl` — cập nhật mỗi khi gặp comment `# Paranoia Level N` trong file."
> "Rules `@rx` được compile ngay thành `re.Pattern` với `IGNORECASE | DOTALL`. Rules `@pm` được split theo whitespace thành list keyword lowercase. Rules dùng `@detectSQLi`/`@detectXSS` bị skip vì cần libinjection C extension."
> "Kết quả: `_CRS_SQLI_PATTERNS` = list 50 tuples `(rule_id, msg, compiled_pattern)`, `_CRS_XSS_PATTERNS` = 27 tuples, `_CRS_XSS_PHRASES` = ~9 keywords. Toàn bộ việc này chỉ xảy ra **một lần lúc import module** — không tốn thời gian lúc runtime."

> "**Giai đoạn Parse — mỗi gói tin:**"
> "Với mỗi HTTP request packet, `FeatureContext.get_normalized(pkt)` trả về chuỗi đã qua 6 bước chuẩn hóa (URL decode, HTML decode, Unicode NFKC, lowercase...). Chuỗi này là input duy nhất cho tất cả rules."

> "**Giai đoạn Score — F13:**"
> "F13 duyệt 50 patterns bằng vòng lặp `for rule_id, msg, pattern in _CRS_SQLI_PATTERNS: if pattern.search(normalized): total_score += 1.0`. Mỗi pattern match = +1, bất kể pattern đó có score gốc là gì trong ModSecurity. Lý do đơn giản hóa này: ModSecurity dùng score cộng dồn để block khi vượt ngưỡng — trong bối cảnh RL feature, chúng em cần giá trị liên tục để agent có gradient, không phải binary block/allow."
> "Công thức cuối: `F13 = total_score / http_request_count`. Ví dụ: payload `' OR 1=1--` trigger F942130 (tautology), F942100 (SQL char), F942370 (comment injection) = 3 rules / 1 request = **3.0**. Sau normalize log-scale với cap=20: `log(1+min(3.0,20)) / log(1+20) ≈ 0.354`."

> "**F18 — thêm @pm phrases:**"
> "F18 cộng thêm phrase match sau @rx: `for phrase in _CRS_XSS_PHRASES: if phrase in normalized: total_score += 1.0`. Ví dụ payload `<script>document.cookie='stolen'</script>` trigger 5 @rx rules + 1 phrase `document.cookie` = **6.0 / 1 request**."

> "**Limitation đã biết:**"
> "Rules `@detectSQLi` dùng thuật toán libinjection (trie-based lexer viết bằng C) — detect được các advanced evasion như `1'OORR'2'='2` mà regex không bắt được. Chúng em skip 8 rules này. Compensation: F12 SqlSpecialChar vẫn bắt được `'` và `;` trong payload, F14-F16 cover các kỹ thuật cụ thể, nên tổng thể recall vẫn đạt F1=0.9245 trên test set."

---

### [Q3] Tại sao window 1.0 giây — và điều gì xảy ra nếu thay đổi?

> "Window size 1.0s là kết quả của một trade-off cụ thể: phải đủ nhỏ để detect **SYN Flood** (burst xảy ra trong <2 giây) nhưng đủ lớn để tích lũy **statistical signal** cho Port Scan (cần >50 distinct ports, tức >50 SYN packets trong window)."

> "Quan trọng hơn, window size **ràng buộc cứng với normalization bounds**. Ví dụ F1 cap=500 pkt/s — calibrated cho window 1.0s. Nếu window = 2.0s, với cùng attack rate, F1_raw = 1000 pkt → min(1000, 500)/log(501) = 1.0. Normalized value đạt ceiling sớm hơn, mất thông tin phân biệt giữa medium và high-rate attack. Thay đổi window mà không recalibrate bounds → feature distribution shift → RL model predict sai từ bước đầu tiên."

> "Trong code, WINDOW_SIZE được define ở `config/data_params.py:16` và được cảnh báo rõ ràng trong menu nếu user cố thay đổi."

---

### [Q4] Known limitations — cả về bài toán lẫn implementation

> "**Về bài toán:**"
> "Một: simulation gap — Containernet với ±20% domain randomization tạo traffic giống production nhưng không phải production. Đặc biệt, application-layer traffic (HTTP patterns, session behavior) khó randomize chính xác."
> "Hai: response latency 1.016ms bình quân — với SYN Flood 'flash' (<1s), agent không thể stop đợt đầu trong window đầu tiên. Cần kết hợp với stateful firewall rule ở tầng kernel."
> "Ba: F12-F20 bị vô hiệu với HTTPS thuần — cần `SSLKEYLOGFILE` từ Firefox/Chrome để decrypt TLS. Trong lab dùng HTTP plaintext, không ảnh hưởng; trong production cần thêm bước này."

> "**Về implementation — qua code review:**"
> "Issue HIGH: `flow_manager.py:113` — nếu SYN-ACK đến trước SYN (out-of-order capture ở mirror port), flow key bị tạo ngược, fwd/bwd packets bị hoán đổi. F9, F10, F11 tính sai. Trong môi trường lab (capture tại điểm đầu connection) không xảy ra, nhưng cần fix trước production bằng cách canonical sort 5-tuple khi tạo flow."
> "Issue MEDIUM: `flow_state.py:57` — check `if timestamp` là falsy check, ts=0.0 sẽ fall về `time.time()`. Fix bằng `if timestamp is not None`. Ảnh hưởng PCAP với timestamps gần epoch."

---

### [Q5] So sánh với CICFlowMeter — lý do không dùng tool có sẵn?

> "CICFlowMeter là gold standard cho flow-based feature extraction trong research. Chúng em cân nhắc kỹ trước khi tự xây."

> "Điểm khác biệt kỹ thuật quan trọng nhất: CICFlowMeter tính features **theo flow lifecycle** — tức đợi đến khi flow timeout (120s) hoặc FIN/RST mới output. Trong realtime NIDS, điều này có nghĩa là phát hiện trễ 2 phút. Chúng em cần **sliding window 1.0s** để RL agent có observation mới mỗi giây."

> "Thứ hai: CICFlowMeter không có payload canonicalization hay CRS integration — không thể detect SQLi/XSS qua payload matching."

> "Thứ ba: CICFlowMeter output là 80+ features — quá nhiều cho observation space của RL agent. Curse of dimensionality sẽ yêu cầu exponentially nhiều training data hơn."

> "Trade-off: chúng em tự xây pipeline nên phải tự validate, trong khi CICFlowMeter đã được cộng đồng kiểm chứng. Đây là limitation về độ tin cậy mà chúng em acknowledge trong thesis."

---

### [Q6] Tại sao dùng PPO thay vì DQN hay A2C?

> "Ba lý do kỹ thuật. Một: **action space nhỏ, discrete** — PPO không yêu cầu Q-value approximation phức tạp như DQN. Hai: **continuous observation 34D** — PPO với Actor-Critic handle tốt continuous input hơn DQN vốn thiết kế cho discrete/tabular. Ba: **training stability** — clipped objective của PPO ngăn policy update quá lớn (KL divergence), quan trọng khi reward signal sparse (attacker không attack mọi window)."

> "Trong thực nghiệm, DQN converge chậm hơn và có variance cao hơn giữa các seeds. A2C converge nhanh nhưng cuối cùng đạt reward thấp hơn PPO do không có experience replay. PPO-Tuned với n_envs=4 là lựa chọn cân bằng nhất."

---

## PHỤ LỤC: CODE REVIEW SUMMARY

Dành cho Q&A sâu nếu hội đồng hỏi về chất lượng code.

### Điểm mạnh thiết kế

| Pattern | Mô tả kỹ thuật | File |
|---------|---------------|------|
| Plugin architecture | `@register_feature(FeatureMetadata(...))` decorator tự đăng ký class vào `FeatureRegistry._features` dict. `FlowFeatureCalculator` instantiate tất cả theo `FEATURE_ORDER` — thêm feature mới chỉ cần tạo file mới, không sửa core | `feature/base.py` |
| Caching O(N×F)→O(N) | `FeatureContext` dùng `id(pkt)` làm cache key. 100 packets × 8 L7 features = 800 normalize() calls → 100 calls nhờ cache. Object identity an toàn vì FeatureContext sống đúng 1 calculate() call | `feature/context.py` |
| Error isolation | `calculate()` trả `(features: List[float], missing: List[int])`. Feature lỗi append 0.0 và ghi index vào missing — pipeline không crash, caller biết feature nào thiếu | `feature/calculator.py` |
| Cross-flow brute force | F7 gom HTTP timestamps **across all flows của cùng src_ip** trong window — phát hiện Hydra chạy 16 threads song song (mỗi thread là 1 TCP connection ngắn) | `feature/calculators/` |
| Bidirectional tracking | `FlowManager` dùng forward key + reverse key lookup — O(1) per packet, không cần sort hay compare IP pairs | `core/flow_manager.py` |
| Composite payload | `URI + " " + User-Agent + " " + Body` — một pass normalize, một pass CRS matching thay vì 3 passes riêng | `core/packet_parser.py` |

### Issues đã biết (Known Limitations)

| Mức | File:dòng | Vấn đề | Tác động | Fix hướng |
|-----|-----------|--------|----------|-----------|
| 🔴 HIGH | `flow_manager.py:113` | Reversed flow khi SYN-ACK đến trước SYN | F4/F9/F10/F11 tính sai | Canonical sort 5-tuple: min(src,dst) first |
| 🟠 MED | `flow_state.py:83` | `ts is None` check — ts=0.0 không evict | Packets cũ tồn tại trong window | Đổi thành `ts is None or ts < cutoff` |
| 🟠 MED | `flow_state.py:57` | `if ts` falsy — ts=0.0 dùng `time.time()` | PCAP mode: flow timeout sai | Đổi thành `if ts is not None` |
| 🟠 MED | `main.py:244` | File handle không dùng context manager | Resource leak nếu exception | Bọc trong `with open(...) as out_fd` |
| 🟠 MED | `network_features.py` F2 | SynAckRatio unbounded khi bwd_SYN=0 | Normalization downstream nhận giá trị cực lớn | Cap về max hoặc trả binary flag |
| 🟡 LOW | `nids_config.py:58` | WINDOW_SIZE định nghĩa 2 lần (cả `data_params.py`) | Có thể drift nếu sửa một chỗ | Import từ `data_params.py` |
| 🟡 LOW | `crs_loader.py:86` | Paranoia level từ comment — fragile | Silent fallback về PL=1 | Validate và log warning |
| 🟡 LOW | `packet_parser.py:207` | Cross-field composite payload | False positive nếu URI+UA vô tình match SQLi | Per-field matching (long-term refactor) |
