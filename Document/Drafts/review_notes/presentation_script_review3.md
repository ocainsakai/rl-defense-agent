# Kịch bản Thuyết trình: Review 3 - Hệ thống Phòng thủ mạng bằng AI (RL Agent)

## Slide 1: Review 3 - CHAPTER 03: SYSTEM ARCHITECTURE
*(Trạng thái: Đang hiển thị Slide 1)*

**Người nói:** 
"Kính thưa hội đồng, tiếp nối phần trình bày trước, trong phần Review 3 này, em xin phép đi sâu vào Chương 3: Kiến trúc Hệ thống (System Architecture). Mục tiêu của phần này là làm rõ cách thức hệ thống phòng thủ của chúng em được xây dựng từ cơ sở hạ tầng mạng, mô hình mối đe dọa, cho đến luồng ra quyết định và cách trích xuất đặc trưng để huấn luyện tác tử AI (RL Agent)."

*(Click chuyển sang Slide 2)*

---

## Slide 2: SYSTEM INFRASTRUCTURE ARCHITECTURE
*(Trạng thái: Đang hiển thị Slide 2)*

**Người nói:**
"Đầu tiên là Kiến trúc Cơ sở hạ tầng của hệ thống. Để giải quyết bài toán phòng thủ mạng, nhóm chúng em tiếp cận dưới góc độ một quá trình ra quyết định tuần tự khép kín (closed-loop control system). Hệ thống được chia làm 3 lớp chính:
1. **Lớp Quan sát (Observation Layer):** Nằm tại Edge Router, làm nhiệm vụ phân tích gói tin và trích xuất đặc trưng theo thời gian thực mỗi giây một lần.
2. **Lớp Ra quyết định (Decision-Making Layer):** Đây là cốt lõi của hệ thống, nơi RL Agent xử lý dữ liệu đầu vào và đưa ra hành động tối ưu dựa trên mô hình Markov Decision Process (MDP).
3. **Lớp Thực thi (Enforcement Layer):** Chuyển đổi quyết định của Agent thành các chính sách mạng (network policies) cụ thể thông qua `iptables` ở tầng kernel để đảm bảo độ trễ thấp nhất.

Về mô hình mạng thực nghiệm, chúng em xây dựng trên môi trường Containernet, bao gồm các thành phần: Router biên, Webserver thật (Production), một máy chủ chim mồi (Honeypot) để hứng chịu các cuộc tấn công Layer 7, và hệ thống SIEM Wazuh để theo dõi log độc lập."

*(Click chuyển sang Slide 3)*

---

## Slide 3: THREAT MODEL
*(Trạng thái: Đang hiển thị Slide 3)*

**Người nói:**
"Để thiết kế chiến lược phòng thủ, chúng em đã xác định rõ Mô hình Mối đe dọa (Threat Model). Hệ thống giả định một kẻ tấn công từ bên ngoài (black-box), nhắm mục tiêu vào các dịch vụ web đang hoạt động với 5 loại hình tấn công chính:

1. **DDoS / SYN Flood:** Các cuộc tấn công tràn ngập nhằm làm cạn kiệt băng thông và kết nối.
2. **Port Scan:** Hành vi dò quét để thu thập thông tin cổng dịch vụ.
3. **Brute Force:** Các mạng Botnet tự động dò thông tin đăng nhập.
4. **SQL Injection (SQLi)** và **Cross-Site Scripting (XSS):** Các lỗ hổng tầng Ứng dụng (Layer 7) được ẩn giấu trong payload HTTP/HTTPS.

Ở phe phòng thủ, hệ thống của chúng ta có khả năng giám sát toàn diện tại router biên, giải mã TLS theo thời gian thực và có thẩm quyền thực thi can thiệp lập tức."

*(Click chuyển sang Slide 4)*

---

## Slide 4: DECISIONS FLOWCHART
*(Trạng thái: Đang hiển thị Slide 4)*

**Người nói:**
"*(Chỉ tay vào sơ đồ trên slide)* Đây là Luồng Quyết định (Decisions Flowchart) của hệ thống. 

Từ lưu lượng mạng (Traffic), hệ thống đi qua bộ theo dõi và giải mã (Sniffer). Đầu ra được chuẩn hóa thành một Vector Trạng thái (State Vector) và đưa vào RL Agent. 
Tại mỗi bước thời gian, hệ thống có thể chọn một trong 4 hành động (Action Space):
1. **Allow (Cho phép):** Không can thiệp nếu lưu lượng là an toàn.
2. **Rate Limit (Giới hạn tốc độ):** Hạn chế lưu lượng nhiễu.
3. **Redirect (Chuyển hướng):** Điều hướng lưu lượng độc hại tầng L7 sang Honeypot. Đây là một chiến lược quan trọng để thu thập thông tin tình báo mà vẫn bảo vệ được máy chủ thật.
4. **Block (Chặn):** Lập tức Drop các gói tin đối với các cuộc tấn công bạo lực như DDoS.

Trước khi thực thi, luồng quyết định đi qua một lớp bảo vệ gọi là **SafetyNet** nhằm tránh các dao động nguy hiểm, đảm bảo sự ổn định của hệ thống trước khi áp dụng rule xuống `iptables`."

*(Click chuyển sang Slide 5)*

---

## Slide 5: MODEL SCHEMANTIC
*(Trạng thái: Đang hiển thị Slide 5)*

**Người nói:**
"Tiếp theo là Sơ đồ Mô hình Học tăng cường (RL Model Schematic). Chúng em sử dụng thuật toán **PPO (Proximal Policy Optimization)** vì tính ổn định cao và phù hợp với không gian trạng thái liên tục.

Mô hình học theo phương thức **Actor-Critic**. Đầu vào là một ma trận trạng thái có không gian 34 chiều (34-dimensional state space). Đầu ra Actor quyết định một trong 4 hành động rời rạc, trong khi Critic ước lượng giá trị của trạng thái đó.

Một điểm đột phá ở đây là thiết kế **Hàm phần thưởng (Reward Function)**. Thay vì chỉ thưởng phạt cố định, hàm phần thưởng của chúng em kết hợp: chi phí can thiệp (intervention cost), mức độ thiệt hại của dịch vụ (service damage), cùng với các yếu tố 'shaping' nhằm thưởng cho sự nhất quán trong hành động và điều tiết quá trình leo thang từ Redirect lên Block. Nhờ vậy, Agent học được cách tối ưu hóa sự cân bằng giữa An ninh và Tính sẵn sàng (Security-Availability trade-off)."

*(Click chuyển sang Slide 6)*

---

## Slide 6: FEATURE EXTRACTION (F1-F20)
*(Trạng thái: Đang hiển thị Slide 6)*

**Người nói:**
"Để mô hình PPO hiểu được tình trạng mạng, chúng em áp dụng kỹ thuật trích xuất đặc trưng với cửa sổ trượt 1 giây (1-second sliding window). Tổng cộng có 34 không gian đặc trưng. Bảng 4.1 trên slide trình bày **20 đặc trưng lưu lượng tức thời (F1 đến F20)**.

- Từ **F1 đến F11** là các **đặc trưng mạng (Network Features)**: Ví dụ như PacketRate (F1), SynAckRatio (F2), hay DistinctPorts (F5). Những chỉ số này cực kỳ nhạy cảm và giúp mô hình nhận diện ngay lập tức các cuộc tấn công như DDoS, SYN Flood, hay Port Scan.
- Từ **F12 đến F20** là các **đặc trưng phân tích nội dung (Payload Features)**: Do các tấn công SQLi và XSS không có dấu hiệu bất thường ở tầng mạng, chúng em xây dựng một Pipeline chuẩn hóa Payload gồm 8 bước và sử dụng quy tắc của OWASP CRS. Ví dụ, F13 đo lường điểm CRS của SQLi, F14 tìm kiếm lệnh UNION SELECT, còn F19 phát hiện việc gọi hàm JavaScript nguy hiểm."

*(Click chuyển sang Slide 7)*

---

## Slide 7: FEATURE EXTRACTION (T0-T9 & F21-F24)
*(Trạng thái: Đang hiển thị Slide 7)*

**Người nói:**
"Tuy nhiên, 20 đặc trưng tức thời chỉ là một 'bức ảnh chụp nhanh' (snapshot). Để Agent có thể đưa ra quyết định dựa trên tính nhân quả (causal reasoning), chúng em bổ sung thêm 14 đặc trưng lưu trữ ngữ cảnh và phản hồi lịch sử, được liệt kê trong Bảng 4.2 và 4.3:

- **10 Đặc trưng Trạng thái Thời gian (T0-T9):** Lưu giữ lại hành động trước đó, số lượng cửa sổ thời gian đã trôi qua, và điểm bằng chứng leo thang (Escalation Score). Nó giúp Agent biết được mình đã áp dụng hành động chặn này được bao lâu và liệu áp lực tấn công có đang tăng lên hay không.
- **4 Đặc trưng Phản hồi Khép kín (F21-F24):** Đây là những thông số phản hồi trực tiếp tác động từ hành động trước đó. Ví dụ, WebHitRatio (F21) xem máy chủ thật có còn bị tấn công không, hay HoneypotRatio (F22) kiểm tra hiệu quả chuyển hướng. 

Việc thiết kế không gian trạng thái 34 chiều (20 + 10 + 4) này chính là chìa khóa giúp Agent học được chiến thuật ứng phó theo chuỗi thời gian một cách thông minh, thay vì chỉ là một hệ thống dựa trên luật (rule-based) cứng nhắc."

*(Click chuyển sang Slide 8)*

---

## Slide 8: CHAPTER 04: TRAINING AND EVALUATION
*(Trạng thái: Đang hiển thị Slide 8)*

**Người nói:**
"Và từ nền tảng thiết kế mô hình mạnh mẽ, cùng bộ dữ liệu trạng thái đầy đủ ngữ cảnh đó, chúng em đã đưa RL Agent vào quá trình huấn luyện và đánh giá trên các bộ dữ liệu chuẩn. Quá trình huấn luyện này, cùng với những phân tích về biểu đồ hiệu năng, sự hội tụ của Reward, cũng như khả năng tổng quát hóa của Agent trên các Dataset (như CIC-IDS) sẽ được trình bày chi tiết trong Chương 4: Huấn luyện và Đánh giá (Training and Evaluation) ngay sau đây.

Em xin chân thành cảm ơn hội đồng đã lắng nghe phần trình bày về Kiến trúc Hệ thống."
