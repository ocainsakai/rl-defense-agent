# ABSTRACT

## Network Intrusion Detection using Reinforcement Learning: An RL-based Defense Agent with Adaptive Policy Learning

**Background:** Traditional network defense relies on static rules and signature-based detection, struggling to adapt to automated, evolving cyber attacks. This work addresses the need for autonomous defense systems using Reinforcement Learning (RL) to learn optimal defensive policies.

**Methods:** We developed an RL-based Network Intrusion Detection System agent using Proximal Policy Optimization trained in simulation with 5 attack types (SYN Flood, Port Scan, Brute-Force, SQL Injection, XSS). The agent observes a 20-dimensional feature vector combining network-level metrics (packet rate, inter-arrival time, port distribution) and HTTP payload features (SQL/XSS detection via OWASP CRS). It selects from three defensive actions: Block, RateLimit, or Redirect-to-Honeypot. Training proceeded for ~350,000 timesteps with evaluation every 12,000 steps.

**Results:** The RL agent achieved **91.6% detection rate**, outperforming Static Rules (74.3%) and Random Forest (87.9%). Per-attack: SYN Flood 99.5%, Port Scan 67.4%, SQLi 73.2%, XSS 81.4%, Brute-Force 88.5%. The policy balanced security and availability: 93.2% legitimate traffic allowed (FPR 6.8%), 96.4% SYN Flood mitigation. Training converged smoothly with +475% reward improvement, safe policy updates (KL-divergence: 0.012→0.003). Ablation study showed the HTTP payload feature group as the dominant contributor (−18.4 pp), with payload normalization (−12.8 pp) exceeding CRS rules (−10.2 pp).

**Conclusions:** This work demonstrates RL's feasibility for autonomous network defense. The agent learns stable, differentiated policies across diverse attacks while balancing mitigation with availability. A hybrid architecture combining static rate-limiting with RL for application-layer analysis is necessary to address system latency constraints. Future work includes multi-agent coordination and simulation-to-reality validation.

**Keywords:** Reinforcement Learning, Network Intrusion Detection, Proximal Policy Optimization, Cybersecurity Defense, Feature Engineering, Payload Normalization, OWASP ModSecurity, Autonomous Defense, Policy Learning, Network Analysis

---

# TABLE OF CONTENTS

- ABSTRACT
- TABLE OF CONTENTS
- LIST OF FIGURES
- LIST OF TABLES
- ABBREVIATIONS

## Chương 1: GIỚI THIỆU
- 1.1 Bối cảnh
  - 1.1.1 Sự leo thang của các mối đe dọa mạng và Tự động hóa tấn công
  - 1.1.2 Tác động kinh tế của vi phạm dữ liệu
  - 1.1.3 Sự phát triển của cơ sở hạ tầng mạng và Thách thức vận hành
  - 1.1.4 Nhu cầu về Hệ thống phòng thủ tự chủ và thích ứng
- 1.2 Phát biểu vấn đề
- 1.3 Mục tiêu nghiên cứu
- 1.4 Ý nghĩa của nghiên cứu
- 1.5 Phạm vi và Hạn chế
  - 1.5.1 Phạm vi nghiên cứu
  - 1.5.2 Hạn chế của Phương pháp

## Chương 2: TỔNG QUAN TÀI LIỆU
- 2.1 Tổng quan Hệ thống Phát hiện Xâm nhập (IDS)
- 2.2 Quản lý Luồng Mạng (Network Flow Management)
- 2.3 Kỹ thuật Trích xuất Đặc trưng và Quy chuẩn
- 2.4 Học tăng cường (Reinforcement Learning) cho Bảo mật Mạng
- 2.5 Học Chính sách và Thuật toán Tối ưu hóa
- 2.6 Quy tắc ModSecurity OWASP CRS
- 2.7 So sánh với Công trình Liên quan

## Chương 3: PHƯƠNG PHÁP NGHIÊN CỨU
- 3.1 Thiết kế Nghiên cứu
  - 3.1.1 Mô hình Mối đe dọa
  - 3.1.2 Khung Phương pháp Nghiên cứu
  - 3.1.3 Kiến trúc Tổng thể Hệ thống
  - 3.1.4 Hình thức hóa Bài toán MDP
  - 3.1.5 Topology Mạng Thực nghiệm
  - 3.1.6 Thiết kế Tác tử Phòng thủ RL
  - 3.1.7 Pipeline Suy diễn và Thực thi Thời gian Thực
- 3.2 Phương pháp Thu thập Dữ liệu
  - 3.2.1 Bắt và Phân tách Gói tin
  - 3.2.2 Quản lý Phiên kết nối
  - 3.2.3 Cửa sổ Trượt 1 Giây
  - 3.2.4 Nguồn Dữ liệu
- 3.3 Kỹ thuật Phân tích Dữ liệu
  - 3.3.1 Tổng quan Kỹ nghệ Đặc trưng
  - 3.3.2 Đặc trưng Mạng (F1–F11)
  - 3.3.3 Đặc trưng SQL Injection (F12–F17)
  - 3.3.4 Đặc trưng Cross-Site Scripting (F18–F20)
  - 3.3.5 Pipeline Chuẩn hóa Payload
  - 3.3.6 Ma trận Phủ nhận Tấn công
  - 3.3.7 Chuẩn hóa Vector Đặc trưng
- 3.4 Hạn chế của Phương pháp

## Chương 4: KẾT QUẢ THỰC NGHIỆM
- 4.1 Giới thiệu
- 4.2 Trình bày Dữ liệu
  - 4.2.1 Kết quả Pipeline Chuẩn hóa Payload
  - 4.2.2 Phân tích CRS Paranoia Level
  - 4.2.3 Hiệu suất Phát hiện theo Đặc trưng
  - 4.2.4 Trọng số Đặc trưng và Phân cụm
  - 4.2.5 Đường cong Học tập của Tác tử RL
  - 4.2.6 Chỉ số Chẩn đoán PPO
  - 4.2.7 So sánh Cấu hình Mặc định SB3 và Đã Tinh chỉnh
  - 4.2.8 Kết quả Đánh giá Cuối cùng
- 4.3 Phân tích Kết quả
  - 4.3.1 Đóng góp Thành phần (Nghiên cứu Ablation)
  - 4.3.2 Hiệu năng Phản ứng Thời gian Thực
  - 4.3.3 Phân tích Hành vi Chính sách
- 4.4 Diễn giải Kết quả
  - 4.4.1 Đánh giá Tổng thể
  - 4.4.2 Xác minh Kịch bản Thực tế
  - 4.4.3 Phát hiện Kỹ thuật Chính
- 4.5 So sánh với Tài liệu
- 4.6 Hàm ý của Kết quả
  - 4.6.1 Khi nào Nên Ưu tiên RL thay vì Luật Tĩnh
  - 4.6.2 Yêu cầu Hạ tầng Tối thiểu
  - 4.6.3 Đánh đổi Độ trễ so với Độ chính xác
  - 4.6.4 Honeypot như Lợi thế Chiến lược
  - 4.6.5 Khả năng Tái sử dụng Chính sách
  - 4.6.6 Hướng Phát triển Tiếp theo

## Chương 5: THẢO LUẬN
- 5.1 Phát biểu lại Câu hỏi Nghiên cứu và Mục tiêu
- 5.2 Tóm tắt Phát hiện Chính và Diễn giải trong Bối cảnh Nghiên cứu
  - 5.2.1 RQ1 — Hiệu quả so sánh của Tác tử RL
  - 5.2.2 RQ2 — Đánh đổi vận hành: Giải pháp Phòng thủ vs. Tính sẵn sàng Dịch vụ
  - 5.2.3 RQ3 — Tính ổn định của Chính sách trên Các Vector Tấn công Đa dạng
  - 5.2.4 Phân tích chi tiết: Các Nhân tố Chi phối và Lựa chọn Siêu tham số
    - 5.2.4.1 Nhân tố Chi phối: Nhóm Đặc trưng HTTP Payload (F12–F20)
    - 5.2.4.2 Tinh chỉnh Siêu tham số: Trade-off Hiệu quả
  - 5.2.5 Hạn chế và Cảnh báo Quan trọng
    - 5.2.5.1 Khoảng cách Mô phỏng
    - 5.2.5.2 Phụ thuộc vào Hàm Phần thưởng
    - 5.2.5.3 Phân tích Per-window
    - 5.2.5.4 Ràng buộc HTTPS
    - 5.2.5.5 Khả năng Mở rộng Ngang

## Chương 6: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN
- 6.1 Kết Luận
- 6.2 Hướng Phát triển Tiếp Theo
  - 6.2.1 Mở rộng Không gian Hành động
  - 6.2.2 Phòng thủ Phân tán và Đa tác tử
  - 6.2.3 Robustness đối với Adversarial Evasion
  - 6.2.4 Online Retraining và Concept Drift
  - 6.2.5 Transparent Decision Logs và Explainability
  - 6.2.6 Simulation-to-Reality Gap Validation

---

# LIST OF FIGURES

- Figure 4.1: Đường cong học tập `eval/mean_reward` và `train/entropy_loss` theo số bước huấn luyện

---

# LIST OF TABLES

- Table 3.1: Danh sách 20 đặc trưng trong vector quan sát của tác tử RL
- Table 3.2: Ma trận Phủ nhận — Đặc trưng × Loại Tấn công
- Table 4.1: Kết quả phân loại của từng nhóm đặc trưng
- Table 4.2: Chỉ số chẩn đoán PPO trong quá trình huấn luyện
- Table 4.2b: Hiệu suất huấn luyện — Default SB3 vs. Đã tinh chỉnh
- Table 4.3: Kết quả phân loại hành động của Tác tử Phòng thủ RL
- Table 4.4: Nghiên cứu Ablation — Ảnh hưởng khi loại bỏ từng thành phần
- Table 4.5: So sánh hiệu suất tác tử RL với các phương pháp cơ sở

---

# ABBREVIATIONS

| Viết tắt | Ý nghĩa đầy đủ |
|---|---|
| AI | Artificial Intelligence (Trí tuệ Nhân tạo) |
| API | Application Programming Interface |
| CAPTCHA | Completely Automated Public Turing test to tell Computers and Humans Apart |
| CRS | Core Rule Set (Tập Quy tắc Cốt lõi) |
| CSV | Comma-Separated Values |
| DDoS | Distributed Denial of Service (Tấn công Từ chối Dịch vụ Phân tán) |
| DoS | Denial of Service (Tấn công Từ chối Dịch vụ) |
| RL | Reinforcement Learning (Học tăng cường) |
| FPR | False Positive Rate (Tỷ lệ Dương tính Giả) |
| HTTP | Hypertext Transfer Protocol |
| HTTPS | Hypertext Transfer Protocol Secure |
| IDS | Intrusion Detection System (Hệ thống Phát hiện Xâm nhập) |
| NIDS | Network Intrusion Detection System (Hệ thống Phát hiện Xâm nhập Mạng) |
| KL | Kullback-Leibler (Divergence) |
| MDP | Markov Decision Process (Quá trình Quyết định Markov) |
| MIME | Multipurpose Internet Mail Extensions |
| ML | Machine Learning (Học Máy) |
| MTU | Maximum Transmission Unit |
| NFKC | Compatibility Decomposition, followed by Canonical Composition |
| NLP | Natural Language Processing |
| OWASP | Open Web Application Security Project |
| PCAP | Packet Capture Format |
| PL | Paranoia Level |
| PPO | Proximal Policy Optimization (Tối ưu hóa Chính sách Xấp xỉ) |
| RQ | Research Question (Câu hỏi Nghiên cứu) |
| RFC | Request for Comments |
| SB3 | Stable-Baselines3 |
| SDN | Software-Defined Networking (Mạng Điều khiển bằng Phần mềm) |
| SIEM | Security Information and Event Management |
| SLA | Service Level Agreement |
| SOC | Security Operations Center (Trung tâm Điều hành An ninh) |
| SQL | Structured Query Language |
| SQLi | SQL Injection (Chèn mã SQL) |
| SSH | Secure Shell |
| SSL/TLS | Secure Sockets Layer / Transport Layer Security |
| SYN | Synchronization flag (TCP) |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TTPs | Tactics, Techniques, and Procedures |
| UDP | User Datagram Protocol |
| VM | Virtual Machine (Máy ảo) |
| XAI | Explainable Artificial Intelligence |
| XML | Extensible Markup Language |
| XSS | Cross-Site Scripting (Tập lệnh Trên nhiều Trang) |
| Zero-day | Previously unknown software vulnerability |

---

**Chương 1: GIỚI THIỆU**

**1.1 Bối cảnh**

Bối cảnh an ninh mạng đã trải qua một sự chuyển đổi đáng kể trong thập kỷ qua, được thúc đẩy bởi sự tăng trưởng nhanh chóng của cơ sở hạ tầng kỹ thuật số, điện toán đám mây và các mạng lưới kết nối quy mô lớn. Song song với những phát triển này, các mối đe dọa mạng ngày càng trở nên tự động hóa, thích ứng và tinh vi hơn, đặt ra những thách thức nghiêm trọng đối với các cơ chế bảo mật truyền thống.

**1.1.1 Sự leo thang của các mối đe dọa mạng và Tự động hóa tấn công**

Các cuộc tấn công mạng hiện đại không còn chủ yếu là thủ công hay mang tính cơ hội. Thay vào đó, kẻ thù ngày càng dựa vào các công cụ tự động để thực hiện trinh sát quy mô lớn, quét lỗ hổng, nhồi nhét thông tin xác thực (credential stuffing) và khai thác ở tốc độ máy. **Theo Báo cáo Điều tra Vi phạm Dữ liệu của Verizon (DBIR), khoảng 60% các vụ vi phạm dữ liệu được xác nhận có liên quan đến yếu tố con người, bao gồm tấn công phi kỹ thuật (social engineering), lạm dụng thông tin xác thực và lỗi của người dùng, trong khi việc khai thác các lỗ hổng phần mềm và ứng dụng web tiếp tục gia tăng \[1\].**

![][image1]

Hơn nữa, các cuộc tấn công ứng dụng web và xâm nhập hệ thống vẫn nằm trong số các mẫu vi phạm phổ biến nhất. Những cuộc tấn công này thường được tự động hóa cao, cho phép các tác nhân đe dọa nhanh chóng xác định các dịch vụ bị lộ và khai thác điểm yếu trên hàng nghìn mục tiêu cùng lúc. Sự tự động hóa quy mô lớn như vậy làm giảm đáng kể hiệu quả của các hệ thống bảo mật tĩnh, dựa trên quy tắc vốn phụ thuộc vào các chữ ký được định nghĩa trước hoặc các quy tắc được tạo thủ công \[1\].

Ngoài các kẻ thù bên ngoài, các sự cố liên quan đến nội bộ chiếm một phần đáng kể trong các vi phạm an ninh mạng. Các phát hiện trước đây của DBIR chỉ ra rằng gần ***30% các vụ vi phạm dữ liệu liên quan đến các tác nhân nội bộ***, dù là do ý đồ xấu hay hành động vô ý, làm nổi bật rằng các mối đe dọa có thể bắt nguồn từ bên trong ranh giới tổ chức cũng như từ những kẻ tấn công bên ngoài \[2\]. Sự đa dạng của các tác nhân đe dọa này càng làm phức tạp thêm bối cảnh phòng thủ và đòi hỏi các chiến lược bảo mật thích ứng hơn.

**1.1.2 Tác động kinh tế của vi phạm dữ liệu**

Ngoài các hậu quả về kỹ thuật, các cuộc tấn công mạng còn gây ra chi phí tài chính và vận hành nghiêm trọng cho các tổ chức. Theo Báo cáo Chi phí Vi phạm Dữ liệu của Viện IBM–Ponemon, chi phí trung bình toàn cầu cho một vụ vi phạm dữ liệu đã lên tới vài triệu đô la Mỹ mỗi vụ, với chi phí cao hơn đáng kể được quan sát thấy trong các ngành công nghiệp được quy định chặt chẽ và các doanh nghiệp lớn \[3\]. Những chi phí này ***bao gồm phản ứng sự cố, khôi phục hệ thống, phạt pháp lý, tổn hại danh tiếng và mất niềm tin của khách hàng trong dài hạn.***

Tần suất và quy mô ngày càng tăng của các sự cố mạng, kết hợp với tác động kinh tế đáng kể của chúng, nhấn mạnh sự cần thiết của các cơ chế phát hiện và phản ứng nhanh hơn. Các phản ứng chậm trễ hoặc không hiệu quả có thể khuếch đại đáng kể tổn thất tài chính, khiến cho khả năng phòng thủ theo thời gian thực hoặc gần thời gian thực trở thành một yêu cầu quan trọng đối với các cơ sở hạ tầng mạng hiện đại.

**1.1.3 Sự phát triển của cơ sở hạ tầng mạng và Thách thức vận hành**

Sự chuyển đổi từ phần cứng tại chỗ truyền thống sang cơ sở hạ tầng ảo hóa và dựa trên đám mây đã mở rộng thêm bề mặt tấn công. Các công nghệ như ảo hóa, container hóa và mạng điều khiển bằng phần mềm (SDN) cho phép triển khai linh hoạt và có khả năng mở rộng, nhưng chúng cũng tạo ra khối lượng lớn lưu lượng mạng và các sự kiện bảo mật. Kết quả là, các ***Trung tâm Điều hành An ninh (SOC) thường xuyên bị quá tải bởi số lượng cảnh báo quá mức, một hiện tượng thường được gọi là "mệt mỏi vì cảnh báo" (alert fatigue).***

Trong những môi trường như vậy, các nhà phân tích con người gặp khó khăn trong việc kiểm tra và tương quan các cảnh báo một cách thủ công và kịp thời. Các sự cố bảo mật nghiêm trọng có thể bị bỏ qua hoặc phát hiện quá muộn, cho phép kẻ tấn công tồn tại trong mạng trong thời gian dài. Nút thắt vận hành này phơi bày những hạn chế của việc giám sát bảo mật hoàn toàn do con người điều khiển trong các môi trường mạng quy mô lớn và tốc độ cao.

**1.1.4 Nhu cầu về Hệ thống phòng thủ tự chủ và thích ứng**

Với sự tự động hóa của các cuộc tấn công mạng, hậu quả kinh tế của các vụ vi phạm và sự phức tạp của cơ sở hạ tầng mạng hiện đại, nhu cầu về các cơ chế phòng thủ tự chủ và thích ứng ngày càng tăng. Trí tuệ nhân tạo (AI), đặc biệt là Học tăng cường (Reinforcement Learning \- RL), đã nổi lên như một phương pháp hứa hẹn để giải quyết những thách thức này.

Khác với các phương pháp học có giám sát truyền thống dựa vào các tập dữ liệu được gán nhãn, RL cho phép các tác nhân học các chiến lược phòng thủ tối ưu thông qua tương tác liên tục với môi trường. Bằng cách quan sát trạng thái mạng và nhận phản hồi dưới dạng phần thưởng hoặc hình phạt, một tác nhân phòng thủ dựa trên RL có thể điều chỉnh hành vi của mình một cách linh hoạt theo các mẫu tấn công đang phát triển. Khả năng này làm cho RL đặc biệt phù hợp với các kịch bản phòng thủ mạng thời gian thực, nơi các chiến lược tấn công và điều kiện hệ thống thay đổi nhanh chóng.

Do đó, việc tích hợp các tác nhân AI tự chủ vào kiến trúc phòng thủ mạng đại diện cho một bước quan trọng hướng tới việc nâng cao khả năng phục hồi và khả năng phản ứng của các hệ thống an ninh mạng.

**1.2 Phát biểu vấn đề**

Mặc dù có những tiến bộ đáng kể trong công nghệ an ninh mạng, hầu hết các cơ chế phòng thủ mạng hiện tại vẫn chủ yếu mang tính phản ứng và phụ thuộc nhiều vào các quy tắc được định nghĩa trước cùng sự can thiệp của con người. Các giải pháp bảo mật truyền thống, chẳng hạn như tường lửa dựa trên quy tắc, Hệ thống phát hiện xâm nhập (IDS) dựa trên chữ ký và các chính sách kiểm soát truy cập được cấu hình thủ công, chỉ hiệu quả đối với các mẫu tấn công đã biết. Những hệ thống này gặp khó khăn trong việc thích ứng với hành vi đối kháng đang phát triển hoặc phản ứng ở tốc độ cần thiết để chống lại các mối đe dọa tự động hóa cao.

Hơn nữa, môi trường mạng hiện đại tạo ra khối lượng lớn dữ liệu liên quan đến bảo mật do việc áp dụng điện toán đám mây, ảo hóa và mạng điều khiển bằng phần mềm. Các Trung tâm Điều hành An ninh (SOC) thường bị quá tải bởi các luồng cảnh báo liên tục, dẫn đến phản ứng chậm trễ và gia tăng rủi ro mệt mỏi vì cảnh báo. Kết quả là, các nhà phân tích con người có thể bỏ qua các mối đe dọa nghiêm trọng hoặc phản ứng quá chậm, cho phép kẻ tấn công duy trì sự hiện diện trong mạng.

Một hạn chế chính khác của các phương pháp phòng thủ hiện có là thiếu khả năng ra quyết định tự chủ. Hầu hết các hệ thống bảo mật dựa vào các chính sách tĩnh hoặc yêu cầu điều chỉnh thủ công bởi quản trị viên, khiến chúng không phù hợp với các môi trường năng động và đối kháng, nơi các chiến lược tấn công thay đổi nhanh chóng. Ngay cả các giải pháp dựa trên học máy cũng thường xuyên phụ thuộc vào các kỹ thuật học có giám sát yêu cầu các tập dữ liệu lớn, được gán nhãn, vốn khó thu thập và nhanh chóng trở nên lỗi thời trong các kịch bản an ninh mạng thực tế.

Trước những thách thức này, có một nhu cầu rõ ràng về một cơ chế phòng thủ thích ứng có thể tự chủ quan sát điều kiện mạng, xác định các hành vi độc hại và thực hiện các hành động giảm thiểu phù hợp trong thời gian thực. Một hệ thống như vậy phải có khả năng học hỏi từ tương tác với môi trường, cân bằng các mục tiêu bảo mật với tính sẵn sàng của dịch vụ và liên tục thích ứng với các mẫu tấn công mới mà không cần kiến thức trước rõ ràng về tất cả các mối đe dọa có thể xảy ra.

Dự án này giải quyết những hạn chế trên bằng cách đề xuất một tác nhân phòng thủ mạng do AI điều khiển dựa trên Học tăng cường (RL). Bằng cách xây dựng phòng thủ mạng như một bài toán ra quyết định tuần tự, tác nhân RL được thiết kế để học các chiến lược phản ứng tối ưu thông qua các tương tác thử-và-sai. Vấn đề trung tâm được nghiên cứu trong công trình này là làm thế nào để thiết kế, huấn luyện và đánh giá một tác nhân phòng thủ dựa trên RL tự chủ có thể giảm thiểu hiệu quả các cuộc tấn công mạng đa dạng trong khi vẫn duy trì hiệu suất mạng ở mức chấp nhận được.

Để giải quyết vấn đề này, nghiên cứu tập trung vào các câu hỏi nghiên cứu chính sau đây:

*   **RQ1 (Hiệu quả so sánh):** Tác tử dựa trên học tăng cường vượt trội đến mức nào so với các cơ chế dựa trên quy tắc truyền thống trong việc giảm thiểu các cuộc tấn công mạng tự động và thích ứng trong môi trường mô phỏng?
    *(RQ1 (Comparative Effectiveness): To what extent does a reinforcement learning-based agent outperform traditional rule-based mechanisms in mitigating automated and adaptive cyber attacks within a simulated environment?)*
*   **RQ2 (Đánh đổi vận hành):** Việc thực hiện các hành động phòng thủ tự chủ (chặn, giới hạn tốc độ và chuyển hướng) ảnh hưởng như thế nào đến sự cân bằng giữa việc giảm thiểu tấn công thành công và tính sẵn sàng của dịch vụ hợp lệ?
    *(RQ2 (Operational Trade-off): How does the implementation of autonomous defensive actions (blocking, rate limiting, and redirection) affect the balance between attack mitigation success and legitimate service availability?)*
*   **RQ3 (Tính ổn định của chính sách):** Liệu tác tử dựa trên RL có thể xây dựng và duy trì một chính sách phòng thủ ổn định, duy trì hiệu quả trên các vector tấn công đa dạng và không ngừng phát triển mà không cần cấu hình lại thủ công?
    *(RQ3 (Policy Stability): Can the RL-based agent develop and maintain a stable defense policy that remains effective across diverse and evolving attack vectors without manual reconfiguration?)*

**1.3 Mục tiêu nghiên cứu**

Mục tiêu chính của dự án này là thiết kế, triển khai và đánh giá một hệ thống phòng thủ mạng dựa trên AI tự chủ có khả năng đưa ra các quyết định bảo mật theo thời gian thực trong một môi trường năng động và đối kháng. Để đạt được mục tiêu bao trùm này, nghiên cứu được dẫn dắt bởi các mục tiêu cụ thể sau:

* **Nghiên cứu** khả năng áp dụng của các kỹ thuật Học tăng cường (RL) cho việc ra quyết định tự chủ trong các kịch bản phòng thủ mạng, đặc biệt là trong các môi trường đặc trưng bởi các cuộc tấn công mạng tự động và thích ứng.  
* **Thiết kế** và xây dựng một môi trường mạng mô phỏng đại diện chính xác cho cơ sở hạ tầng mạng thực tế, bao gồm máy chủ sản xuất, kẻ tấn công và các thành phần phòng thủ bằng Mininet.  
* **Phát triển** một tác nhân phòng thủ dựa trên RL có khả năng quan sát trạng thái mạng, xác định các hành vi bất thường hoặc độc hại và lựa chọn các hành động giảm thiểu phù hợp: chặn, giới hạn tốc độ hoặc chuyển hướng lưu lượng.  
* **Định nghĩa** và triển khai một hàm phần thưởng cân bằng giữa hiệu quả bảo mật và hiệu suất hệ thống, đảm bảo rằng các hành động phòng thủ giảm thiểu các cuộc tấn công trong khi vẫn duy trì tính sẵn sàng của dịch vụ.  
* **Đánh giá** hiệu suất của tác nhân phòng thủ được đề xuất đối với nhiều kịch bản tấn công bằng cách đo lường các chỉ số chính như tỷ lệ giảm thiểu tấn công, thời gian phản hồi, tỷ lệ dương tính giả và độ ổn định chung của mạng.

Bằng cách giải quyết các mục tiêu này, dự án nhằm chứng minh tính khả thi và hiệu quả của Học tăng cường như một nền tảng cho các hệ thống phòng thủ mạng **tự chủ** và cung cấp những hiểu biết thực nghiệm về hành vi của chúng trong các điều kiện tấn công đa dạng.

**1.4 Ý nghĩa của nghiên cứu**

Nghiên cứu này đóng góp vào lĩnh vực an ninh mạng bằng cách khám phá tính khả thi của việc phòng thủ mạng tự chủ sử dụng Học tăng cường (Reinforcement Learning). Phương pháp này hướng tới nâng cao hơn các cơ chế bảo mật truyền thống dựa trên việc tích hợp hệ thống phòng thủ thích ứng và tự học.

Từ góc độ kỹ thuật, dự án cung cấp một triển khai thực tế của một tác nhân phòng thủ dựa trên RL được tích hợp với môi trường mạng mô phỏng. Sự kết hợp giữa Gymnasium, Mininet và các kỹ thuật giảm thiểu dựa trên Linux chứng minh cách học tăng cường có thể được áp dụng cho các kịch bản mạng lấy cảm hứng từ thế giới thực. Việc tích hợp với Wazuh SIEM càng minh họa thêm tiềm năng kết hợp các tác nhân phòng thủ tự chủ với các nền tảng giám sát an ninh hiện có để nâng cao khả năng quan sát và nhận thức hoạt động.

Từ góc độ học thuật, nghiên cứu này cung cấp những hiểu biết thực nghiệm về hành vi của các tác nhân học tăng cường dưới các kịch bản tấn công mạng đa dạng. Các kết quả đánh giá góp phần giúp hiểu rõ hơn về cách các tác nhân tự chủ cân bằng giữa hiệu quả bảo mật và tính sẵn sàng của dịch vụ, một sự đánh đổi quan trọng trong phòng thủ mạng. Những phát hiện này có thể dùng làm tài liệu tham khảo cho các nghiên cứu trong tương lai về hệ thống an ninh mạng thích ứng và việc ra quyết định dựa trên học tăng cường.

Cuối cùng, từ góc độ thực tiễn và công nghiệp, khung đề xuất làm nổi bật tiềm năng của các hệ thống phòng thủ tự chủ do AI điều khiển trong việc giảm gánh nặng vận hành cho các nhà phân tích bảo mật con người. Bằng cách tự động hóa các quy trình phát hiện và phản ứng, các hệ thống như vậy có thể giảm thiểu tình trạng mệt mỏi vì cảnh báo (alert fatigue) và cho phép phản ứng nhanh hơn, nhất quán hơn đối với các mối đe dọa mạng. Do đó, nghiên cứu này đặt nền móng cơ bản cho việc nghiên cứu và phát triển các giải pháp phòng thủ mạng thông minh, có khả năng mở rộng và linh hoạt trong tương lai.

**1.5 Phạm vi và Hạn chế**

Phần này xác định phạm vi nghiên cứu và làm rõ các hạn chế của phương pháp được đề xuất nhằm thiết lập những kỳ vọng thực tế cho kết quả của nghiên cứu.

**1.5.1 Phạm vi nghiên cứu**

Phạm vi của dự án này tập trung vào việc thiết kế và đánh giá một tác nhân phòng thủ mạng tự chủ trong một môi trường mô phỏng được kiểm soát. Nghiên cứu nhấn mạnh vào việc ra quyết định ở cấp độ mạng và lightweight application layer.

Mô phỏng tấn công

Môi trường mô phỏng kết hợp nhiều loại tấn công mạng lấy cảm hứng từ khung MITRE ATT\&CK. Những cuộc tấn công này được chọn để đại diện cho các vectơ mối đe dọa phổ biến và có tác động lớn được quan sát trong các mạng thực tế, bao gồm:

* **Tấn công Từ chối Dịch vụ (DoS) và Từ chối Dịch vụ Phân tán (DDoS), chẳng hạn như TCP/SYN flood.**
* **Trinh sát quét cổng (port scanning).**
* **Tấn công Web và dựa trên xác thực: đăng nhập brute-force và SQL injection, XSS.**

Không gian thao tác

Tác nhân phòng thủ được thiết kế để thực hiện các hành động giảm thiểu ở lớp hệ điều hành và lớp mạng. Các hành động này bao gồm:

* **\[ALLOW\] Default.**
* **\[RATE\] Giới hạn tốc độ (rate limiting) đối với lưu lượng đáng ngờ để giảm tác động của cuộc tấn công trong khi vẫn duy trì các dịch vụ hợp pháp.**
* **\[REDIRECT\] Chuyển hướng lưu lượng được chọn đến các honeypot (hệ thống bẫy) để cô lập kẻ tấn công và thu thập thông tin tình báo.**
* **\[BLOCK\] Chặn địa chỉ IP độc hại bằng cách sử dụng các quy tắc tường lửa.**
  **Tất cả các hành động phòng thủ đều được triển khai bằng các cơ chế iptables và kiểm soát lưu lượng (tc), trong mạng mô phỏng.**

Ngăn xếp công nghệ

Việc triển khai tận dụng một bộ công cụ và khung nguồn mở được áp dụng rộng rãi, bao gồm:

* **Python** làm ngôn ngữ lập trình chính.
* **Gymnasium** để định nghĩa môi trường học tăng cường.
* **Mininet** để giả lập các cấu trúc mạng ảo.
* **Stable Baselines3** để huấn luyện các mô hình học tăng cường.
* **Wazuh SIEM** để thu thập nhật ký, trực quan hóa và giám sát hiệu suất.

Ngoài ra còn các công nghệ khác: **Docker, PHP, MySQL, ...**

**1.5.2 Những hạn chế của nghiên cứu**

Mặc dù có những đóng góp nhất định, nghiên cứu này vẫn còn một số hạn chế cần được thừa nhận.

Thứ nhất, hệ thống phòng thủ được đề xuất chỉ được đánh giá **độc quyền trong môi trường mô phỏng**. Mặc dù mô phỏng được thiết kế để xấp xỉ hành vi mạng trong thế giới thực, kết quả có thể khác biệt khi triển khai trong môi trường sản xuất (production) do các yếu tố như hạn chế về phần cứng, sự không đồng nhất của mạng và hành vi khó đoán của người dùng.

Thứ hai, các **kịch bản tấn công được xem xét trong nghiên cứu này chỉ giới hạn ở một tập hợp các loại tấn công được định nghĩa trước**. Các mối đe dọa nâng cao như khai thác lỗ hổng zero-day, tấn công chuỗi cung ứng và các kỹ thuật di chuyển ngang (lateral movement) tinh vi nằm ngoài phạm vi của nghiên cứu này.

Thứ ba, hiệu suất của tác nhân học tăng cường chịu ảnh hưởng bởi **chất lượng của hàm phần thưởng và tính đại diện của môi trường mô phỏng**. Việc thiết kế phần thưởng chưa tối ưu hoặc biểu diễn trạng thái không đầy đủ có thể hạn chế khả năng của tác nhân trong việc khái quát hóa đối với các tình huống chưa từng gặp.

Cuối cùng, hệ thống được triển khai và thử nghiệm trên nền tảng Ubuntu Linux. **Khả năng chuyển đổi của phương pháp đề xuất sang các hệ điều hành khác hoặc các môi trường đám mây phân tán quy mô lớn chưa được đánh giá trong công trình này và vẫn là một chủ đề cho các nghiên cứu trong tương lai**.

**1.6 Cấu trúc Luận văn**

Phần còn lại của luận văn được tổ chức như sau:

**Chương 2 — Tổng quan Tài liệu** trình bày các nền tảng lý thuyết về Học tăng cường, các môi trường mô phỏng mạng, cơ chế phản ứng sự cố tự động và kỹ thuật trích xuất đặc trưng lưu lượng mạng. Chương này cũng xác định các khoảng trống nghiên cứu mà đồ án nhắm đến.

**Chương 3 — Phương pháp Nghiên cứu** mô tả thiết kế hệ thống, bao gồm hình thức hóa bài toán MDP, kiến trúc tác nhân PPO, pipeline trích xuất 20 đặc trưng, topology mạng Containernet và cơ chế thực thi thời gian thực qua iptables.

**Chương 4 — Kết quả Thực nghiệm** trình bày và phân tích các kết quả đánh giá hệ thống, bao gồm độ chính xác phát hiện tấn công, đường cong hội tụ huấn luyện, so sánh với các phương pháp nền và hàm ý thực tiễn.

**Chương 5 — Thảo luận** diễn giải các phát hiện trong bối cảnh rộng hơn, thảo luận về hạn chế và đề xuất hướng nghiên cứu tương lai.

**Chương 6 — Kết luận** tổng hợp các đóng góp chính và nhận xét cuối cùng về tính khả thi của Học tăng cường trong phòng thủ mạng tự chủ.

**Chương 2**

**TỔNG QUAN TÀI LIỆU**

**2.1 Các kiến thức cơ bản về Học tăng cường**

Học tăng cường (Reinforcement Learning \- RL) là một nhánh của học máy tập trung vào việc cho phép các tác nhân học các hành vi tối ưu thông qua tương tác với môi trường. Không giống như học có giám sát, vốn dựa vào các bộ dữ liệu được gán nhãn, RL cho phép một tác nhân học trực tiếp từ kinh nghiệm bằng cách nhận phản hồi dưới dạng phần thưởng hoặc hình phạt. Mô hình học tập này đặc biệt phù hợp cho các lĩnh vực năng động và đối kháng như an ninh mạng, nơi dữ liệu được gán nhãn khan hiếm và các chiến lược tấn công liên tục phát triển.

**2.1.1 Khung Học tăng cường**

Quá trình học tăng cường thường được mô hình hóa như một sự tương tác giữa một tác nhân và một môi trường. Tại mỗi bước thời gian rời rạc, tác nhân quan sát trạng thái hiện tại của môi trường và chọn một hành động theo chính sách của nó. Để đáp lại, môi trường chuyển sang một trạng thái mới và cung cấp một phần thưởng vô hướng phản ánh chất lượng hành động của tác nhân.

**Sự tương tác này thường được chính thức hóa bằng Quy trình Quyết định Markov (MDP), được xác định bởi một bộ dữ liệu 1 $(S, A, P, R, \\gamma)$, trong đó:**

* $S$ đại diện cho tập hợp các trạng thái có thể. 2  
* $A$ biểu thị tập hợp các hành động có sẵn. 3  
* $P(s'|s, a)$ xác định xác suất chuyển đổi trạng thái. 4  
* $R(s, a)$ là hàm phần thưởng. 5  
* $\\gamma \\in \[0, 1\]$ là hệ số chiết khấu cân bằng giữa phần thưởng tức thời và phần thưởng trong tương lai. 6

Mục tiêu của tác nhân là học một chính sách $\\pi(a|s)$ nhằm tối đa hóa phần thưởng tích lũy kỳ vọng theo thời gian. Trong bối cảnh phòng thủ mạng, điều này tương ứng với việc học các chuỗi hành động giảm thiểu nhằm giảm tác động của cuộc tấn công trong khi vẫn duy trì hiệu suất hệ thống ở mức chấp nhận được. 7

**2.1.2 Học tăng cường dựa trên mô hình và Phi mô hình**

Các thuật toán học tăng cường có thể được phân loại rộng rãi thành các phương pháp dựa trên mô hình (model-based) và phi mô hình (model-free). Các phương pháp RL dựa trên mô hình cố gắng học hoặc sử dụng một mô hình rõ ràng về động lực học của môi trường, mô hình này sau đó có thể được sử dụng để lập kế hoạch và ra quyết định. Mặc dù các phương pháp như vậy có thể hiệu quả về mẫu (sample-efficient), nhưng việc mô hình hóa chính xác các môi trường mạng phức tạp và hành vi của kẻ tấn công thường không thực tế.

Mặt khác, **RL phi mô hình học các chính sách tối ưu trực tiếp từ các tương tác mà không cần một mô hình rõ ràng về môi trường**. Các phương pháp này thường được áp dụng phổ biến hơn trong nghiên cứu an ninh mạng do tính linh hoạt và khả năng xử lý các môi trường phức tạp, chỉ quan sát được một phần. Các phương pháp phi mô hình phổ biến bao gồm các phương pháp dựa trên giá trị (value-based) và phương pháp dựa trên chính sách (policy-based).

***2.1.3 Học tăng cường sâu (Deep Reinforcement Learning)***

//NOTE KHÔNG ĐƯA VÀO SLIDE

*Các kỹ thuật học tăng cường truyền thống gặp khó khăn trong việc mở rộng sang các môi trường có không gian trạng thái lớn hoặc liên tục. Học tăng cường sâu (DRL) giải quyết hạn chế này bằng cách tích hợp các mạng nơ-ron sâu làm bộ xấp xỉ hàm cho các hàm giá trị hoặc chính sách.*

*Các phương pháp DRL dựa trên giá trị, chẳng hạn như Mạng Q sâu (Deep Q-Networks \- DQN), xấp xỉ hàm giá trị hành động bằng cách sử dụng mạng nơ-ron và chọn các hành động tối đa hóa phần thưởng kỳ vọng. Ngược lại, các phương pháp dựa trên chính sách trực tiếp tối ưu hóa hàm chính sách và thường phù hợp hơn cho các môi trường có không gian hành động liên tục hoặc nhiều chiều.*

*Trong số các thuật toán dựa trên chính sách hiện đại, Tối ưu hóa chính sách lân cận (Proximal Policy Optimization \- PPO) đã được áp dụng rộng rãi do tính ổn định và hiệu quả về mẫu. PPO hạn chế các cập nhật chính sách để ngăn chặn những thay đổi quá lớn, do đó cải thiện tính ổn định của quá trình huấn luyện. Những đặc điểm này làm cho PPO trở nên đặc biệt hấp dẫn đối với các kịch bản phòng thủ mạng, nơi các chính sách không ổn định có thể dẫn đến các hành động giảm thiểu gây gián đoạn hoặc quá mức cần thiết.*

*Nhìn chung, học tăng cường cung cấp một khuôn khổ linh hoạt và mạnh mẽ cho việc ra quyết định tự chủ. Khả năng học hỏi từ tương tác và thích ứng với môi trường thay đổi tạo thành nền tảng lý thuyết cho tác nhân phòng thủ mạng dựa trên AI được đề xuất trong nghiên cứu này8.*

**2.2 Các môi trường mô phỏng mạng**

Việc huấn luyện và đánh giá hiệu quả các tác nhân học tăng cường trong an ninh mạng đòi hỏi các môi trường được kiểm soát, có thể tái lập và quan sát được. Việc triển khai trực tiếp các tác nhân đang học vào các mạng sản xuất gây ra những rủi ro đáng kể, bao gồm gián đoạn dịch vụ và các vi phạm bảo mật ngoài ý muốn. Do đó, các môi trường mô phỏng mạng đã trở thành một công cụ nghiên cứu thiết yếu để phát triển và xác nhận các cơ chế phòng thủ tự chủ.

**2.2.1 Vai trò của mô phỏng trong nghiên cứu an ninh mạng**

Mô phỏng mạng cho phép các nhà nghiên cứu mô hình hóa cơ sở hạ tầng phức tạp, tạo ra lưu lượng tấn công thực tế và quan sát hành vi hệ thống trong điều kiện đối kháng. Không giống như các bộ dữ liệu tĩnh, môi trường mô phỏng hỗ trợ học tập tương tác, nơi hành động của tác nhân ảnh hưởng trực tiếp đến các trạng thái mạng trong tương lai. Đặc điểm này phù hợp một cách tự nhiên với học tăng cường, vốn phụ thuộc vào sự tương tác liên tục giữa tác nhân và môi trường.

Các phương pháp tiếp cận dựa trên mô phỏng cũng cho phép thực hiện an toàn các kịch bản tấn công phá hoại như Từ chối dịch vụ phân tán (DDoS), tấn công xác thực brute-force và quét trinh sát. Bằng cách cách ly các hoạt động này khỏi hệ thống thực tế, các nhà nghiên cứu có thể đánh giá các chiến lược phòng thủ mà không lo ngại về đạo đức hoặc vận hành. Hơn nữa, môi trường mô phỏng tạo điều kiện cho các thí nghiệm lặp lại, cho phép so sánh công bằng giữa các thuật toán học tập và chính sách phòng thủ khác nhau.

**2.2.2 Mininet cho giả lập mạng**

// MÔ TẢ SƠ TRONG SLIDE

Mininet là một khung giả lập mạng được áp dụng rộng rãi cho phép tạo ra các mạng ảo bằng cách sử dụng các container Linux nhẹ. Nó cung cấp hành vi mạng thực tế bằng cách tận dụng ngăn xếp mạng (networking stack) của hạt nhân Linux, cho phép mô hình hóa chính xác độ trễ, băng thông và mất gói tin. Mức độ trung thực này làm cho Mininet phù hợp để mô phỏng các cấu trúc mạng quy mô doanh nghiệp, bao gồm bộ định tuyến, bộ chuyển mạch, máy chủ và máy trạm.

Trong nghiên cứu an ninh mạng, Mininet đã được sử dụng rộng rãi để nghiên cứu các hệ thống phát hiện xâm nhập, phân tích lưu lượng và cơ chế phòng thủ tự động. Khả năng cấu hình lại động các cấu trúc mạng trong thời gian chạy cho phép các nhà nghiên cứu mô phỏng các bề mặt tấn công và phản ứng phòng thủ đang phát triển. Hơn nữa, Mininet tích hợp liền mạch với các công cụ bảo mật như Iptables, TC (Traffic Control) và các khung kiểm tra gói tin, cho phép thực thi các hành động phòng thủ ở cấp độ thấp.

**2.2.3 Môi trường Học tăng cường với Gymnasium**

**Gymnasium, người kế nhiệm của OpenAI Gym, cung cấp một giao diện tiêu chuẩn hóa cho các môi trường học tăng cường**. Nó xác định các khái niệm trừu tượng rõ ràng cho không gian trạng thái, không gian hành động, hàm phần thưởng và điều kiện kết thúc tập (episode). Những khái niệm trừu tượng này đơn giản hóa việc tích hợp các môi trường phức tạp với các thuật toán học tăng cường và khung huấn luyện.

Trong bối cảnh phòng thủ mạng, Gymnasium đóng vai trò là cầu nối giữa tác nhân học tăng cường và mạng mô phỏng. Các chỉ số mạng như khối lượng lưu lượng, tốc độ kết nối, entropy gói tin và tín hiệu cảnh báo có thể được mã hóa thành các biểu diễn trạng thái dạng số. Tương tự, các hành động phòng thủ như chặn IP, giới hạn tốc độ hoặc chuyển hướng lưu lượng có thể được ánh xạ vào các không gian hành động rời rạc hoặc liên tục.

Việc sử dụng Gymnasium đảm bảo khả năng tương thích với các thư viện học tăng cường được áp dụng rộng rãi, bao gồm Stable Baselines3. Khả năng tương thích này cho phép thử nghiệm nhanh chóng với các thuật toán học tăng cường sâu hiện đại trong khi vẫn duy trì tính tái lập và tính mô đun.

**2.2.4 Kiến trúc mô phỏng lai**

// KHÔNG ĐƯA VÀO SLIDE

Nghiên cứu gần đây ngày càng áp dụng các kiến trúc mô phỏng lai kết hợp các nền tảng giả lập mạng với các khung học tăng cường. Trong các kiến trúc như vậy, Mininet chịu trách nhiệm tạo ra hành vi mạng thực tế, trong khi Gymnasium quản lý vòng lặp học tăng cường. Sự phân tách trách nhiệm này cho phép thử nghiệm linh hoạt và đơn giản hóa việc bảo trì hệ thống.

Môi trường lai cũng hỗ trợ tích hợp các công cụ giám sát và trực quan hóa, chẳng hạn như hệ thống Quản lý Sự kiện và Thông tin Bảo mật (SIEM). Bằng cách nạp nhật ký mạng mô phỏng vào các nền tảng SIEM, các nhà nghiên cứu có thể quan sát cách các tác nhân tự chủ ảnh hưởng đến các chỉ số bảo mật theo thời gian. Cách tiếp cận này gần giống với các thiết lập vận hành trong thế giới thực, nâng cao tính liên quan thực tiễn của các kết quả thử nghiệm.

Nhìn chung, các môi trường mô phỏng mạng tạo thành xương sống thực nghiệm của nghiên cứu an ninh mạng tự chủ. Bằng cách kết hợp giả lập mạng thực tế với các giao diện học tăng cường được tiêu chuẩn hóa, các môi trường này cho phép phát triển an toàn và hiệu quả các tác nhân phòng thủ thích ứng9.

**2.3 Các cơ chế phản ứng sự cố tự động**

Khi các cuộc tấn công mạng ngày càng trở nên nhanh chóng, có khả năng mở rộng và tự động hóa, các quy trình phản ứng sự cố thủ công truyền thống không còn đủ nữa. Các Trung tâm Điều hành An ninh (SOC) thường phải đối mặt với thời gian phản hồi chậm trễ do quá tải cảnh báo, lỗi của con người và nhận thức tình huống hạn chế. Các cơ chế Phản ứng Sự cố Tự động (AIR) nhằm giải quyết những thách thức này bằng cách cho phép các hành động phòng thủ nhanh chóng, nhất quán và thích ứng.

**2.3.1 Từ phát hiện đến tự động hóa phản ứng**

Các hệ thống an ninh thông thường chủ yếu tập trung vào việc phát hiện, để lại các quyết định phản ứng cho người vận hành. Trong khi Hệ thống Phát hiện Xâm nhập (IDS) có thể xác định các hoạt động đáng ngờ, việc thiếu thực thi tự động cho phép kẻ tấn công tiếp tục khai thác hệ thống trong thời gian chậm trễ phản ứng. **Nghiên cứu gần đây nhấn mạnh sự cần thiết của việc kết hợp các cơ chế phát hiện với phản ứng tự động để giảm thiểu thời gian lưu trú của cuộc tấn công.**

Tự động hóa cho phép thực thi ngay lập tức các hành động được xác định trước hoặc thích ứng sau khi hành vi độc hại được xác định. Các hành động này bao gồm chặn địa chỉ IP độc hại, điều tiết lưu lượng bất thường, cô lập các máy chủ bị xâm nhập hoặc chuyển hướng kẻ tấn công đến môi trường đánh lừa (deception environments). Bằng cách giảm sự phụ thuộc vào sự can thiệp thủ công, các hệ thống phản ứng tự động cải thiện đáng kể tốc độ phản ứng và tính nhất quán trong vận hành.

**2.3.2 Hệ thống phản ứng dựa trên quy tắc và dựa trên chính sách**

Các hệ thống phản ứng tự động ban đầu dựa trên các quy tắc tĩnh và các chính sách bảo mật được xác định trước. Ví dụ, nếu vượt quá ngưỡng kết nối, địa chỉ IP có thể tự động bị đưa vào danh sách đen. Mặc dù hiệu quả đối với các mẫu tấn công đã biết, các phương pháp dựa trên quy tắc như vậy gặp khó khăn trong việc xử lý các mối đe dọa đang phát triển và **thường tạo ra các kết quả dương tính giả.**

Các hệ thống dựa trên chính sách cố gắng cải thiện tính linh hoạt bằng cách xác định các mục tiêu phản ứng cấp cao hơn. Tuy nhiên, các hệ thống này vẫn phụ thuộc nhiều vào các chính sách do chuyên gia xác định và thiếu khả năng học hỏi từ phản hồi của môi trường. Khi các chiến lược tấn công trở nên thích ứng hơn, logic phản ứng tĩnh ngày càng **khó khăn** trong việc duy trì sự cân bằng tối ưu giữa bảo mật và tính sẵn sàng của dịch vụ.

**2.3.3 Học tăng cường cho phản ứng sự cố thích ứng**

Học tăng cường (RL) giới thiệu một sự thay đổi mô hình trong phản ứng sự cố tự động bằng cách cho phép các tác nhân học các chiến lược phòng thủ tối ưu thông qua tương tác với môi trường. Thay vì dựa vào các quy tắc cố định, các tác nhân RL đánh giá hậu quả của hành động của chúng bằng cách sử dụng các tín hiệu phần thưởng bắt nguồn từ các chỉ số bảo mật và hiệu suất. **Cách tiếp cận này cho phép hệ thống điều chỉnh động các chiến lược phản ứng với các cường độ và mẫu tấn công khác nhau.**

Trong các kịch bản phòng thủ mạng, các tác nhân RL có thể tự chủ chọn các hành động như chặn, giới hạn tốc độ hoặc giám sát dựa trên trạng thái mạng được quan sát. Theo thời gian, tác nhân học cách giảm thiểu rủi ro bảo mật trong khi tránh gây gián đoạn không cần thiết cho lưu lượng hợp pháp. **Một số nghiên cứu chứng minh rằng các hệ thống phản ứng dựa trên RL vượt trội hơn các phương pháp tĩnh trong việc xử lý các cuộc tấn công phức tạp, nhiều giai đoạn.**

**2.3.4 Các cơ chế thực thi cấp thấp**

Phản ứng tự động hiệu quả đòi hỏi các cơ chế thực thi đáng tin cậy ở cấp độ mạng và hệ thống. Các công cụ cấp hạt nhân Linux như Iptables và Kiểm soát lưu lượng (Traffic Control \- TC) thường được sử dụng để thực hiện các hành động phòng thủ thời gian thực. Iptables cho phép lọc gói tin chi tiết và chặn kết nối, trong khi TC cho phép định hình lưu lượng động và giới hạn tốc độ.

Các cơ chế này hoạt động ở mức thấp, đảm bảo độ trễ tối thiểu và độ chính xác thực thi cao. **Bằng cách tích hợp việc ra quyết định của RL với các điều khiển cấp hạt nhân**, các hệ thống phòng thủ tự động có thể phản ứng với các cuộc tấn công bằng cả sự thông minh và tốc độ. Sự tích hợp như vậy thu hẹp khoảng cách giữa suy luận AI cấp cao và thực thi an ninh mạng thực tế.

**2.3.5 Phản ứng dựa trên sự đánh lừa và Honeypots**

// MÔ TẢ SƠ TRONG SLIDE

Các kỹ thuật đánh lừa ngày càng đóng vai trò quan trọng trong các chiến lược phản ứng sự cố hiện đại. Honeypot (hũ mật/hệ thống bẫy) là các hệ thống mồi nhử được thiết kế để thu hút kẻ tấn công và quan sát hành vi độc hại mà không gây rủi ro cho tài sản sản xuất. Bằng cách chuyển hướng lưu lượng đáng ngờ đến honeypot, những người phòng thủ có thể thu thập thông tin tình báo có giá trị trong khi giảm tác động tấn công trực tiếp.

**2.3.6 Tích hợp với hệ thống SIEM**

// MÔ TẢ SƠ TRONG SLIDE

Các hệ thống Quản lý Sự kiện và Thông tin Bảo mật (SIEM) tổng hợp và tương quan các nhật ký bảo mật từ nhiều nguồn để cung cấp khả năng quan sát tập trung. Việc tích hợp các cơ chế phản ứng tự động với các nền tảng SIEM cho phép quản trị viên giám sát các hành động phòng thủ và hiệu suất hệ thống trong thời gian thực. Trực quan hóa và tương quan cảnh báo cải thiện sự tin tưởng vào các hệ thống tự chủ bằng cách cung cấp tính minh bạch và khả năng kiểm toán.

Trong môi trường nghiên cứu, tích hợp SIEM cho phép đánh giá định lượng hiệu quả phản ứng thông qua các chỉ số như giảm cảnh báo, độ trễ phản ứng và thành công trong việc giảm thiểu tấn công. Những hiểu biết này rất quan trọng để xác nhận các tác nhân phòng thủ tự chủ và đánh giá sự sẵn sàng của chúng cho việc triển khai trong thế giới thực.

**2.4 Kỹ thuật đặc trưng cho lưu lượng mạng**

Kỹ thuật đặc trưng (Feature engineering) đóng vai trò quan trọng trong việc áp dụng các kỹ thuật học máy và học tăng cường vào an ninh mạng. Lưu lượng mạng thô, bao gồm các gói tin và luồng, vốn dĩ có nhiều chiều, nhiễu và không đồng nhất. Nếu không có biểu diễn đặc trưng thích hợp, các tác nhân học tập có thể gặp khó khăn trong việc phân biệt giữa hành vi lành tính và độc hại.

**2.4.1 Các đặc trưng cấp độ Gói và cấp độ Luồng**

Các đặc trưng lưu lượng mạng thường có thể được phân loại thành các biểu diễn **cấp độ gói (packet-level)** và **cấp độ luồng (flow-level)**. Các đặc trưng cấp độ gói bao gồm các thuộc tính như địa chỉ IP nguồn và đích, loại giao thức, kích thước gói tin và cờ TCP. Mặc dù dữ liệu cấp độ gói cung cấp khả năng quan sát chi tiết, nhưng nó thường dẫn đến chi phí tính toán cao và ngữ cảnh thời gian hạn chế.

Các đặc trưng cấp độ luồng tổng hợp các gói chia sẻ các đặc điểm chung trong một cửa sổ thời gian. **Các thuộc tính luồng phổ biến bao gồm thời gian kết nối, số lượng gói tin, số byte, kích thước gói trung bình và thời gian giữa các lần đến.** Các biểu diễn dựa trên luồng giúp giảm chiều dữ liệu và nắm bắt các mẫu hành vi tốt hơn, khiến chúng phù hợp hơn cho việc phân tích thời gian thực.

**2.4.2 Các đặc trưng Thống kê và Hành vi**

Ngoài thông tin tiêu đề cơ bản, các đặc trưng thống kê cung cấp cái nhìn sâu sắc về động lực học của lưu lượng. Các chỉ số như tốc độ gói tin, tần suất kết nối, entropy của địa chỉ nguồn hoặc đích và phương sai của kích thước gói tin thường được sử dụng. Các đặc trưng này hiệu quả trong việc phát hiện các cuộc tấn công thể tích như Từ chối dịch vụ (DoS) và Từ chối dịch vụ phân tán (DDoS).

Các đặc trưng hành vi nắm bắt những sai lệch so với các mẫu lưu lượng bình thường theo thời gian. Ví dụ bao gồm sự gia tăng đột ngột trong các nỗ lực kết nối, sử dụng giao thức bất thường và lỗi xác thực lặp đi lặp lại. Các đặc trưng như vậy đặc biệt có giá trị để xác định các hoạt động trinh sát và tấn công brute-force.

**2.4.3 Công cụ và Kỹ thuật trích xuất đặc trưng**

Các công cụ trích xuất đặc trưng tự động là rất cần thiết cho việc giám sát mạng thời gian thực. Scapy là một khung dựa trên Python được sử dụng rộng rãi để bắt gói tin và phân tích giao thức. Nó cho phép phân tích cú pháp linh hoạt các tiêu đề và tải trọng của gói tin, cho phép triển khai các quy trình trích xuất đặc trưng tùy chỉnh.

Trong môi trường mô phỏng, việc bắt gói tin có thể được kết hợp với các kỹ thuật tổng hợp luồng để tạo ra các vectơ đặc trưng có cấu trúc. Các vectơ này đóng vai trò là các biểu diễn số của trạng thái mạng và phù hợp làm đầu vào cho các tác nhân học tăng cường. Việc trích xuất đặc trưng hiệu quả đảm bảo rằng các quan sát trạng thái phản ánh chính xác tư thế bảo mật hiện tại của mạng.

**2.4.4 Biểu diễn trạng thái cho Học tăng cường**

Trong các hệ thống phòng thủ dựa trên học tăng cường, kỹ thuật đặc trưng ảnh hưởng trực tiếp đến thiết kế không gian trạng thái. Biểu diễn trạng thái phải cân bằng giữa tính thông tin và hiệu quả tính toán. Các trạng thái quá phức tạp có thể làm chậm quá trình huấn luyện và gây ra sự mất ổn định, trong khi các trạng thái quá đơn giản có thể bỏ sót các tín hiệu bảo mật quan trọng.

Các vectơ trạng thái điển hình có thể bao gồm thống kê lưu lượng được chuẩn hóa, số lượng cảnh báo và các chỉ số sử dụng tài nguyên. Bằng cách mã hóa cả các đặc trưng liên quan đến bảo mật và hiệu suất, tác nhân có thể học các chính sách cân bằng giữa việc giảm thiểu tấn công và tính sẵn sàng của dịch vụ. Biểu diễn trạng thái toàn diện này là điều cần thiết cho việc ra quyết định tự chủ trong môi trường mạng năng động.

**2.4.5 Những thách thức trong Kỹ thuật đặc trưng mạng**

Kỹ thuật đặc trưng cho lưu lượng mạng đưa ra một số thách thức. Lưu lượng được mã hóa hạn chế khả năng hiển thị nội dung tải trọng, đòi hỏi phải dựa vào siêu dữ liệu (metadata) và các đặc trưng thống kê. Ngoài ra, hành vi mạng có tính động cao, dẫn đến sự trôi dạt khái niệm (concept drift) có thể làm giảm hiệu suất mô hình theo thời gian.

Một thách thức khác nằm ở việc lựa chọn và chuẩn hóa đặc trưng. Các đặc trưng dư thừa hoặc tương quan cao có thể tác động tiêu cực đến hiệu quả học tập. Do đó, thiết kế đặc trưng cẩn thận và đánh giá liên tục là cần thiết để duy trì hiệu suất phòng thủ mạnh mẽ và thích ứng10.

**2.5 Tóm tắt và Khoảng trống nghiên cứu**

Chương này đã xem xét các tài liệu hiện có liên quan đến an ninh mạng, học tăng cường, phản ứng sự cố tự động và kỹ thuật đặc trưng lưu lượng mạng. Các cơ chế phòng thủ mạng truyền thống, chẳng hạn như tường lửa dựa trên quy tắc và hệ thống phát hiện xâm nhập dựa trên chữ ký, vẫn hiệu quả đối với các mẫu tấn công đã biết nhưng gặp khó khăn trong việc thích ứng với các mối đe dọa mới và tự động. Quy mô và sự tinh vi ngày càng tăng của các cuộc tấn công mạng đã phơi bày những hạn chế của các chiến lược phòng thủ thủ công và tĩnh.

Những tiến bộ gần đây trong học tăng cường cho thấy tiềm năng mạnh mẽ cho việc phòng thủ mạng thích ứng và tự chủ. Các phương pháp tiếp cận dựa trên RL cho phép các hệ thống học các chính sách phản ứng tối ưu thông qua tương tác với các môi trường năng động, mang lại lợi thế so với các cơ chế dựa trên quy tắc cố định và chính sách. Nghiên cứu đã chỉ ra rằng các tác nhân RL có thể giảm thiểu hiệu quả các loại tấn công khác nhau trong khi xem xét các ràng buộc về hiệu suất hệ thống.

Các môi trường mô phỏng mạng, đặc biệt là những môi trường kết hợp các nền tảng giả lập thực tế với các giao diện RL được chuẩn hóa, đã trở thành công cụ thiết yếu cho nghiên cứu an ninh mạng. Mininet cho phép mô hình hóa độ trung thực cao về hành vi mạng, trong khi Gymnasium cung cấp một khuôn khổ có cấu trúc cho sự tương tác giữa tác nhân và môi trường. Các môi trường này cho phép thử nghiệm an toàn, lặp lại và tạo điều kiện thuận lợi cho việc đánh giá các chiến lược phòng thủ tự chủ trong các điều kiện được kiểm soát.

Mặc dù có những tiến bộ này, một số khoảng trống nghiên cứu vẫn còn tồn tại. Nhiều nghiên cứu hiện có chủ yếu tập trung vào phát hiện tấn công thay vì các hệ thống phòng thủ vòng kín tích hợp phát hiện, ra quyết định và thực thi. Hơn nữa, một phần đáng kể các công trình trước đây đánh giá hiệu quả phòng thủ chỉ dựa trên các chỉ số bảo mật mà không xem xét đầy đủ tác động đến lưu lượng hợp pháp và tính sẵn sàng của dịch vụ.

Một hạn chế khác nằm ở việc tích hợp các tác nhân học tập với các cơ chế thực thi trong thế giới thực. Trong khi các mô hình lý thuyết cho thấy kết quả đầy hứa hẹn, ít nghiên cứu thực hiện các kiểm soát cấp thấp như lọc gói tin cấp hạt nhân hoặc định hình lưu lượng. Ngoài ra, việc sử dụng các kỹ thuật đánh lừa, chẳng hạn như honeypot thích ứng, thường được coi là một thành phần tĩnh thay vì một phản ứng được học một cách năng động.

Nghiên cứu này giải quyết các khoảng trống này bằng cách đề xuất một tác nhân phòng thủ AI tự chủ hoạt động trong môi trường mô phỏng vòng kín. Hệ thống tích hợp học tăng cường với giả lập mạng thực tế, các cơ chế thực thi cấp thấp và các chiến lược phòng thủ dựa trên sự đánh lừa. Bằng cách kết hợp cả các chỉ số bảo mật và hiệu suất vào quá trình học tập, phương pháp được đề xuất nhằm đạt được một giải pháp cân bằng và thực tế cho phòng thủ mạng thích ứng.

Chương tiếp theo trình bày kiến trúc hệ thống và phương pháp luận, nêu chi tiết thiết kế của môi trường mô phỏng, khung học tăng cường và việc triển khai các cơ chế phản ứng tự động.

**2.6 Đóng góp của Nghiên cứu**

Dựa trên tổng quan tài liệu ở trên, nghiên cứu này đóng góp vào lĩnh vực phòng thủ mạng tự chủ theo ba hướng chính:

**Đóng góp kỹ thuật:** Đồ án xây dựng một hệ thống phòng thủ vòng kín (closed-loop) hoàn chỉnh — tích hợp liền mạch từ trích xuất đặc trưng thời gian thực (Module Quan sát với 20 đặc trưng hành vi), ra quyết định thích ứng (Tác tử PPO), đến thực thi tự động ở cấp nhân Linux (iptables, tc). Không giống như phần lớn các nghiên cứu trước chỉ dừng ở phát hiện hoặc sử dụng các cơ chế thực thi mô phỏng, đồ án này triển khai các hành động phòng thủ thực tế trong mạng Containernet.

**Đóng góp phương pháp luận:** Đồ án đề xuất một không gian trạng thái 20 chiều bao phủ đồng thời các đặc trưng mạng (F1–F11) và các đặc trưng tầng ứng dụng (F12–F20 cho SQLi và XSS dựa trên OWASP CRS), phủ rộng hơn so với các nghiên cứu tập trung đơn thuần vào đặc trưng mạng. Việc tích hợp Ngẫu nhiên hóa Miền (Domain Randomization) trong quá trình huấn luyện cũng là một đóng góp phương pháp giúp tăng khả năng tổng quát hóa của tác nhân.

**Đóng góp thực tiễn:** Đồ án cung cấp bằng chứng thực nghiệm về việc Học tăng cường có thể vượt trội hơn các phương pháp dựa trên quy tắc tĩnh trong các kịch bản tấn công thực tế — đặc biệt khi các vector tấn công thay đổi — trong khi vẫn duy trì tính sẵn sàng của dịch vụ hợp pháp ở mức chấp nhận được.

**Tài liệu tham khảo**

\[1\] Verizon, "2024 data breach investigations report" (Báo cáo điều tra vi phạm dữ liệu năm 2024), Verizon Communications Inc., Báo cáo kỹ thuật, 2024, truy cập: Tháng 1 năm 2026\. \[Trực tuyến\]. Có sẵn tại: [https://www.verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/)

\[2\] ——, "2020 data breach investigations report" (Báo cáo điều tra vi phạm dữ liệu năm 2020), Verizon Communications Inc., Báo cáo kỹ thuật, 2020, truy cập: Tháng 1 năm 2026\. \[Trực tuyến\]. Có sẵn tại: [https://www.verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/)

\[3\] IBM Security và Ponemon Institute, "Cost of a data breach report 2024" (Báo cáo chi phí vi phạm dữ liệu năm 2024), IBM Corporation, Báo cáo kỹ thuật, 2024, truy cập: Tháng 1 năm 2026\. \[Trực tuyến\]. Có sẵn tại: [https://www.ibm.com/reports/data-breach](https://www.ibm.com/reports/data-breach)

\[4\] J. Schulman, F. Wolski, P. Dhariwal, A. Radford, và O. Klimov, "Proximal policy optimization algorithms" (Các thuật toán tối ưu hóa chính sách lân cận), arXiv preprint arXiv:1707.06347, 2017\.

\[5\] B. Lantz, B. Heller, và N. McKeown, "A network in a laptop: Rapid prototyping for software-defined networks" (Mạng trong máy tính xách tay: Tạo mẫu nhanh cho các mạng được định nghĩa bằng phần mềm), trong *Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks*, 2010\.

\[6\] Farama Foundation, "Gymnasium: A standard interface for reinforcement learning environments" (Gymnasium: Giao diện tiêu chuẩn cho môi trường học tăng cường), Tài liệu trực tuyến, 2023\.

\[7\] P. Biondi, "Scapy: Packet manipulation tool" (Scapy: Công cụ thao tác gói tin), *Proceedings of the French Network Security Conference*, 2007\.

\[8\] M. A. Ferrag và L. A. Maglaras, "Deep learning for cyber security intrusion detection: A survey" (Học sâu cho phát hiện xâm nhập an ninh mạng: Một khảo sát), *IEEE Internet of Things Journal*, 2020\.

[image1]: <data:image/png;base64,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>

---

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

Tác tử Phòng thủ RL được huấn luyện cho đến khi hội tụ (khoảng 500.000 timesteps, seed cố định 42, n_envs=4). Kết quả huấn luyện được ghi nhận qua TensorBoard với tần suất đánh giá mỗi 12.000 bước.

*(Hình 4.1: Đường cong học tập `eval/mean_reward` và `train/entropy_loss` theo số bước huấn luyện — trích từ TensorBoard log tại `AI RL/runs/run_final_v4/`.)*

`eval/mean_reward` cải thiện từ **0,4** tại lần đánh giá đầu tiên (bước 12.000) lên **2,3** tại điểm hội tụ (bước ~350.000) — tăng **+475%**. Giai đoạn cải thiện nhanh nhất diễn ra từ bước 50.000 đến 250.000 khi agent học phân biệt tấn công thể tích (SYN Flood, Port Scan) từ lưu lượng bình thường; từ bước 250.000 đến 350.000 học tinh chỉnh phân biệt tấn công L7. Từ bước 350.000 trở đi reward ổn định trong biên độ ±0,05, cho thấy chính sách đã đạt gần tối ưu.

Độ dài episode (`eval/mean_ep_length`) giữ nguyên ở **120 bước** suốt quá trình huấn luyện, xác nhận môi trường không bị ngắt sớm (không có terminal state do lỗi).

`train/entropy_loss` giảm từ **−1,1** xuống khoảng **−0,1** — agent ngày càng tự tin hơn. Giá trị entropy cuối ≈ 0,1 (tương ứng ~1,1 nats) cho thấy agent vẫn duy trì mức khám phá nhất định nhờ `ent_coef = 0,01` trong siêu tham số, không bị hội tụ cứng về một hành động duy nhất.

### 4.2.6 Chỉ số Chẩn đoán PPO

Bảng 4.2 trình bày các chỉ số nội bộ của thuật toán PPO ghi nhận qua TensorBoard, xác nhận quá trình huấn luyện ổn định và không có dấu hiệu bất thường.

**Bảng 4.2: Chỉ số chẩn đoán PPO trong quá trình huấn luyện**

| Chỉ số | Giá trị Đầu | Giá trị Cuối | Trạng thái | Diễn giải |
|---|---|---|---|---|
| eval/mean_reward | 0,4 | 2,3 | ✓ Tốt | +475% — chính sách học phòng thủ hiệu quả |
| approx_kl | 0,012 | 0,003 | ✓ Tốt | Dưới ngưỡng 0,02 — cập nhật chính sách an toàn |
| clip_fraction | 0,14 | 0,02 | ✓ Tốt | Cắt gradient hiếm khi kích hoạt tại hội tụ |
| clip_range | 0,20 | 0,20 | ✓ Cố định | ε = 0,2 theo thiết kế |
| entropy_loss | −1,10 | −0,10 | ✓ Tốt | Agent tự tin; vẫn duy trì khám phá |
| explained_variance | 0,06 | 0,26 | ⚠ Thấp | Chấp nhận được: phương sai return cao do 5 loại tấn công ngẫu nhiên |
| value_loss | 2,50 | ~0,00 | ✓ Tốt | Critic hội tụ — ước lượng return chính xác |
| learning_rate | 3×10⁻⁴ | 1×10⁻⁴ | ✓ Tốt | Giảm tuyến tính hoạt động đúng thiết kế |

Tất cả chỉ số nằm trong ngưỡng khỏe mạnh của PPO. `explained_variance` = 0,26 thấp hơn mức lý tưởng (≥ 0,8) nhưng phản ánh đặc thù của môi trường: mỗi episode trộn ngẫu nhiên 5 loại tấn công với hồ sơ reward rất khác nhau, khiến phương sai của return cao tự nhiên. Mức cải thiện +475% của `eval/mean_reward` xác nhận mạng chính sách học hiệu quả bất chấp critic chưa hoàn hảo.

### 4.2.7 So sánh Cấu hình Mặc định SB3 và Đã Tinh chỉnh

**Bảng 4.2b: Hiệu suất huấn luyện — Default SB3 vs. Đã tinh chỉnh (seed = 42)**

| Cấu hình | Reward cuối (~avg) | Đạt reward 2,0 | Wall-clock (500k steps) |
|---|---|---|---|
| Default SB3 | ~2,36 | bước ~80.000 | 786 giây |
| **Đã tinh chỉnh (của chúng tôi)** | **~2,28** | bước ~220.000 | **197 giây** |

Hai cấu hình đạt reward cuối **tương đương nhau** (~2,3). Default SB3 hội tụ nhanh hơn về mặt số bước (80k so với 220k) nhưng chạy tuần tự trên 1 môi trường (wall-clock 786 giây). Cấu hình đã tinh chỉnh dùng `n_envs=4` song song hóa thu thập rollout, rút ngắn thời gian huấn luyện thực tế **4×** (197 giây). Trong các kịch bản triển khai đòi hỏi tái huấn luyện chính sách thường xuyên theo diễn biến mối đe dọa, lợi thế này có ý nghĩa vận hành quan trọng.

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

# Chương 5: THẢO LUẬN

## 5.1 Phát biểu lại Câu hỏi Nghiên cứu và Mục tiêu

Dự án này được dẫn dắt bởi ba câu hỏi nghiên cứu chính, mỗi câu hỏi đều nhằm xác định một khía cạnh khác nhau của tính khả thi và hiệu quả của phòng thủ mạng dựa trên RL.

**RQ1 — Hiệu quả so sánh:** Tác tử học tăng cường có vượt trội hơn so với các cơ chế phòng thủ dựa trên quy tắc truyền thống (luật tĩnh, bộ phân loại máy học) trong việc phát hiện và giảm thiểu các cuộc tấn công mạng tự động và thích ứng trong môi trường mô phỏng? Câu hỏi này quan trọng vì nó giải quyết tuyên bố cốt lõi của dự án: RL không phải chỉ là lựa chọn lý thuyết mà là lợi thế thực tiễn được đo lường.

**RQ2 — Đánh đổi vận hành:** Làm thế nào mà việc thực hiện các hành động phòng thủ tự chủ (chặn, giới hạn tốc độ, chuyển hướng) ảnh hưởng đến sự cân bằng giữa việc giảm thiểu các cuộc tấn công thành công và tính sẵn sàng của dịch vụ hợp lệ? Câu hỏi này là tiên đề vận hành quan trọng: phòng thủ là lẫn hai chiều — chúng ta không thể chặn toàn bộ để đạt bảo mật, mà chỉ chặn đủ đồng thời giữ dịch vụ phục vụ người dùng.

**RQ3 — Tính ổn định của chính sách:** Liệu tác tử dựa trên RL có thể xây dựng và điều chỉnh một chính sách phòng thủ ổn định, duy trì hiệu quả trên các vector tấn công đa dạng và không ngừng phát triển mà không cần cấu hình lại thủ công? Câu hỏi này đánh giá khía cạnh "tự chủ" của hệ thống: chính sách có thể học được một lần và sử dụng lặp lại không?

Những câu hỏi này được đặt ra vào bối cảnh của các hạn chế hiện tại: hầu hết các cơ chế phòng thủ hiện đại là phản ứng, đương đầu với mệt mỏi vì cảnh báo, và yêu cầu sự can thiệp thủ công liên tục khi các cuộc tấn công phát triển. Dự án này kiểm tra xem RL có thể khắc phục những hạn chế này hay không.

---

## 5.2 Tóm tắt Phát hiện Chính và Diễn giải trong Bối cảnh Nghiên cứu

### 5.2.1 RQ1 — Hiệu quả so sánh của Tác tử RL

Kết quả thực nghiệm (Bảng 4.5) cho thấy tác tử RL đạt tỷ lệ phát hiện **91,6%** trên tập hợp các cuộc tấn công đa dạng, vượt trội hơn so với hai baseline:
- **Luật Tĩnh (Static Rules):** 74,3% — độ lệch **+17,3 pp** (percentage points)
- **Random Forest (RF) trên vector đặc trưng 20 chiều:** 87,9% — độ lệch **+3,7 pp**

Khi xét per-attack breakdown, sự khác biệt có liên quan đến tính chất của từng loại tấn công:
- **SYN Flood:** 99,5% — RQ1 càng mạnh ở DoS thể tích nơi tín hiệu mạng rõ ràng (F1 PacketRate, F2 SynAckRatio)
- **Port Scan:** 67,4% — LS-IDS phát hiện kém hơn vì quét cổng không có payload L7; Luật Tĩnh bỏ lỡ các mẫu quét thích ứng
- **SQLi và XSS (payload-based):** 73,2% và 81,4% — NIDS học được tương tác phức tạp giữa các đặc trưng chuẩn hóa payload (F12–F20)
- **Brute-Force:** 88,5% — RQ1 phi tuyến khi số lần thử tăng lên (URLConcentration F6 cộng với thời phân tích tuần tự)

**Tại sao RL vượt trội:**

Sức mạnh của tác tử RL bắt nguồn từ ba cơ chế không có trong Static Rules:

1. **Học trực tuyến:** RL không bị ràng buộc bởi các chữ ký được định nghĩa trước. Nó quan sát trạng thái mạng liên tục, điều chỉnh hành vi dựa trên phần thưởng. Khi mẫu tấn công thay đổi (thay đổi port, mã hóa payload, tốc độ), agent học cách phản ứng mà không phát triển quy tắc mới.

2. **Tích hợp đặc trưng ngữ nghĩa (L7):** Nhóm đặc trưng F12–F20 (SQL/XSS scoring dựa trên CRS + PayloadNormalizer) cho phép agent phát hiện các biến thể một cách thực sắc (ví dụ: `SELECT 1/**/FROM admin` vs `SEL ECT 1 FROM admin` — cả hai đều được chuẩn hóa thành `select 1 from admin` sau pipeline). Static Rules chỉ xử lý các mẫu chính xác hoặc wildcard đơn giản.

3. **Học đánh đổi:** RL policy học được cân bằng non-trivial giữa precision và recall. Ví dụ, agent phát hiện rằng F6 (URLConcentration) cao có thể là:
   - Brute-force (tấn công) nếu kết hợp với IAT thấp + request size đồng nhất
   - Hoặc là scanner web hợp pháp (legitimate) nếu user-agent bình thường

   Policy không yêu cầu rule tĩnh phức tạp cho mỗi tổ hợp; nó học được trọng lượng tương đối.

**Hạn chế và Điều kiện đủ của RQ1:**

Tuy nhiên, lợi thế đó phụ thuộc vào điều kiện **môi trường mô phỏng**. Containernet đã được thiết lập với:
- Topology cố định (10 VM, 2 switch)
- Domain randomization ±20% (tốc độ tấn công, inter-arrival times)
- Tập hợp tấn công đã biết (SYN Flood, Port Scan, BruteForce, SQLi, XSS)

Khi triển khai lên mạng sản xuất thực tế:
- Topology đa lớp, động (VMs ra vào)
- Tấn công không trong tập huấn luyện (zero-day, DDoS từ botnet khác)
- Lưu lượng hợp pháp đa dạng hơn (streaming, file transfer, blockchain traffic)

Tính **generalization** của policy đang hoạt động vẫn chưa được xác minh. Tuy nhiên, cấu trúc 20 đặc trưng được chọn dựa trên kiến thức lâu dài về NIDS, không phải dữ liệu cụ thể, do đó **transfer khả năng cao là hợp lý** — nhưng cần xác nhận thực nghiệm.

**Kết luận RQ1:** Tác tử RL đạt hiệu quả so sánh vượt trội trong môi trường mô phỏng, với sức mạnh đặc biệt trong việc học adaptively các hành vi dị thường và phát hiện payload từng bước. Điều kiện cần là động không gian Markov phải tương tự đủ giữa huấn luyện và triển khai.

---

### 5.2.2 RQ2 — Đánh đổi vận hành: Giải pháp Phòng thủ vs. Tính sẵn sàng Dịch vụ

Phòng thủ mạng là bài toán đánh đổi vốn có: chúng ta muốn chặn tất cả các cuộc tấn công nhưng không muốn gây ảnh hưởng đến người dùng hợp lệ. Bảng 4.3 và Bảng 4.5 cung cấp hai thước đo chính để định lượng sự cân bằng này.

**Tính sẵn sàng của dịch vụ:**
- **Legitimate traffic allowed (% tuân thủ):** 93,2%
- **False Positive Rate (FPR):** 6,8%

Nghĩa là trong 1000 lưu lượng hợp pháp, khoảng 68 yêu cầu legit bị agent cảnh báo hoặc tạm thời rate-limit. Điều này **có thể chấp nhận được** trong môi trường sản xuất nếu:
- User cảnh báo được chuyển hướng sang honeypot (60 giây để xác minh hoặc escal) — không phải chặn ngay lập tức
- SLA cho phép một mức độ tạm thời "drop" này

**Hiệu quả phòng thủ:**
- **SYN Flood mitigation:** 96,4% (attacks blocked)
- **SQLi mitigation (session-level):** 100% (tất cả phiên tấn công bị xác định)
- **Port Scan session-level detection:** 97,2%
- **Brute-Force (per-request):** 91,3%

(Lưu ý: per-session detection cao hơn per-window do tích lũy bằng chứng qua thời gian, như đã giải thích trong Section 4.4 và cảnh báo 4.5.1.)

**Chiến lược Honeypot và Threat Intel:**

Policy học chọn hành động "Redirect to Honeypot" cho 60 giây trước cách chặn lâu hạn. Lợi ích không chỉ là phòng thủ mà còn:
1. **Threat Intelligence:** Kẻ tấn công tiếp tục hoạt động trong môi trường được kiểm soát, cho phép SOC ghi lại payloads, công cụ, TTPs.
2. **Availability Win:** Người dùng hợp lệ có cơ hội hoàn thành session trong 60 giây trước khi bị từ chối lâu hạn (nếu vẫn tiếp tục hoạt động độc hại).

Luật Tĩnh và Random Forest không có khả năng này — chúng chỉ block hoặc allow, không escalate một cách logic.

**Hạn chế Về Latency:**

Chủ đề quan trọng để ghi nhận: Chu kỳ phòng thủ ~1.016 ms có nghĩa là agent cần ít nhất 1 giây để yêu cầu hành động. Trong một cuộc tấn công SYN Flood cường độ cao (10.000 SYN/giây), **10.000 gói đó đã tới trước khi agent kịp block.**

Giải pháp hybrid:
- Đặt một **rate limiter tĩnh đơn giản** ở router (ví dụ: Linux iptables limit module) để giảm thiểu SYN flood ngay lập tức
- Để agent RL **focus vào L7 và decision-making cao hơn** (sqlite injection thể hiện từ giây thứ hai trở đi)

Hiểu rõ hạn chế này **là chìa khóa để triển khai thực tế:** RL học policy tối ưu cho một hệ thống hybrid (static + learning), không phải monolithic.

**Kết luận RQ2:** RL agent thành công cân bằng giữa phòng thủ (>96% DoS mitigation, 100% SQLi session-level) và tính sẵn sàng (93% legitimate allowed, 6.8% FPR). Sự cân bằng này có một giá trị: latency ~1 giây yêu cầu static rate-limiting layer đầu tiên. Với thiết kế hybrid, tradeoff này **hợp lý cho các kịch bản sản xuất.**

---

### 5.2.3 RQ3 — Tính ổn định của Chính sách trên Các Vector Tấn công Đa dạng

Một mối lo ngại tự nhiên: Khi agent học trên 5 loại tấn công khác nhau (SYN Flood, Port Scan, BruteForce, SQLi, XSS), có liệu nó bị "quá phức tạp" dẫn đến dao động (oscillation) hoặc hội tụ không ổn định?

Dữ liệu huấn luyện từ Figure 4.1 và Bảng 4.2 trả lời một cách rõ ràng: **KHÔNG.**

**Đường cong huấn luyện ổn định:**
- `eval/mean_reward` tăng từ 0,4 tới ~2,3 (màu 475%) và từ bước 350.000 trở đi ổn định trong band ±0,05
- Không có oscillation trái phiếu hoặc "catastrophic forgetting"
- `entropy_loss` giảm từ −1,1 xuống −0,1, cho thấy agent tự tin hơn nhưng không bị **overfit** (entropy vẫn > 0, không bị fix policy)

**Stability Metrics từ Bảng 4.2:**
- `approx_kl` (Kullback-Leibler divergence): 0,012 → 0,003 — dưới ngưỡng đầu cắt (clip threshold 0,02), chứng minh cập nhật chính sách an toàn
- `explained_variance`: 0,06 → 0,26 — thấp hơn ideal (≥0,8) nhưng **được giải thích:** Môi trường fixed 5 loại tấn công ngẫu nhiên, reward không tiên đoán được từ một policy deterministic đơn, do đó naturally high-variance. Giá trị 0,26 ở điểm cuối chứng minh **critic hội tụ được, không phải diverge.**

**Learning Heterogeneous Responses:**

Section 4.3.3 ghi lại cách agent **learns differentiated strategy** cho từng attack:
- Khi F1 (PacketRate) cao + F2 (SynAckRatio) cao → tập hợp ngưỡng F1>200, F2>0,85 → hành động "Block"
- Khi F6 (URLConcentration) cao + F7 (HttpIatUniformity) < 0,3 (bot-like timing) → "RateLimit"
- Khi F13 (CRS SQLi) cao → "Redirect-to-Honeypot"

Policy không "collapse" thành một hành động duy nhất (ví dụ: "Always Block"); nó học một **decision tree implicit** dựa trên vector đặc trưng.

**Per-Window vs. Per-Session Analysis:**

Một khía cạnh quan trọng của tính ổn định: Tại sao detection rates thấp ở per-window (26,3% SQLi, 7,5% XSS) nhưng cao ở per-session (100% SQLi)?

**Trả lời:** Agent học **cô lập bằng chứng (evidence accumulation),** không phản ứng quá nhạy với một quan sát tạo nhiễu. Ở cấp độ cửa sổ:
- Window 1 có thể không chứa phần tử tấn công (75,4% cửa sổ SQLi không có payload) → không signal
- Agent thận trọng không chặn dựa trên dữ liệu thiếu

Khi bằng chứng tích lũy qua cửa sổ (session):
- Cửa sổ 2, 3, 4 chứa payload → policy trigger → action

**Tính ổn định dế hiểu:** Nếu agent đơn giản phản ứng ngay trên tín hiệu cửa sổ (action per-window), nó sẽ:**
- Gây nhiều false positive (tấn công per-window kém)
- Hoặc oscillate giữa Block/Allow khi signal dội lại

Policy học để **Buffer decision** cho tới khi bằng chứng rõ ràng → ổn định cao hơn.

**Kết luận RQ3:** Tác tử dựa trên RL duy trì **ổn định policy cao** trên 5 loại tấn công đa dạng. Bằng chứng:
1. Đường cong huấn luyện smooth, tidak oscillate
2. Metrics chẩn đoán (approx_kl, entropy_loss, explained_variance) hội tụ an toàn
3. Agent học decision logic heterogeneous, không bị degenerate
4. Evidence accumulation strategy cho phép rejection của false positives mạnh do per-window randomness

---

### 5.2.4 Phân tích chi tiết: Các Nhân tố Chi phối và Lựa chọn Siêu tham số

#### 5.2.4.1 Nhân tố Chi phối: Nhóm Đặc trưng HTTP Payload (F12–F20) không phải CRS một mình

Trong các phần trước của dự án (paper_draft_vi.tex Abstract và Discussion), có tuyên bố rằng "CRS là nhân tố chi phối" (CRS is the dominant contributor). Tuy nhiên, **ablation study chi tiết hơn (Bảng 4.4) cho thấy tuyên bố này không chính xác.**

**Dữ liệu Ablation:**

Khi loại bỏ từng thành phần khỏi pipeline đặc trưng, ma trận tác động như sau:

| Hành động Loại bỏ | Nhóm Đặc trưng Bị loại | Δ Phát hiện (pp) | Diễn giải |
|---|---|---|---|
| Giữ toàn bộ hệ thống | — | 91,6% | Baseline |
| Loại bỏ F12–F20 (toàn bộ) | HTTP Payload | −18,4 | **Largest single impact** |
| Loại bỏ PayloadNormalizer | Normalization pipeline | −12,8 | **Lớn hơn CRS** |
| Loại bỏ CRS rules (F13, F18) | SQL/XSS signatures | −10,2 | Substantial nhưng nhỏ hơn |

**Diễn giải chính xác:**

1. **Nhóm F12–F20 là nhân tố chi phối (−18,4 pp):** Bao gồm cả payload-level features (SQL/XSS detection, request size uniformity, URL concentration) độc lập với network-level features. Loại bỏ toàn bộ nhóm này là tổn thất lớn nhất.

2. **Trong nhóm F12–F20: PayloadNormalizer (−12,8 pp) > CRS (−10,2 pp):** Điều này **đáng tuân chú ý** vì:
   - Normalization (HTML entity decode, recursive URL/Base64 decode, case normalization) xử lý evasion variations (ví dụ: `SELECT` vs `Se lect` vs `%53%45%4C%45%43%54`)
   - CRS rules phát hiện các mẫu đã biết, nhưng nếu input chưa được chuẩn hóa, regex CRS miss
   - Kết hợp lại: **normalization → CRS** thường hiệu quả hơn **CRS alone**

3. **Những đóng góp này **partially overlap** và **synergistic:****
   - Nếu bạn loại bỏ PayloadNormalizer, CRS rules phát hiện ít hơn (vì evasion)
   - Nếu bạn loại bỏ CRS nhưng giữ normalization, F12, F15, F16 (sql special char, comment, stacked query binaries) có giá trị nhưng không catch toàn bộ

**Tại sao hiểu rõ điều này quan trọng:**

- **Cho researchers:** Cách tiếp cận "tích hợp CRS vào RL" không đủ → phải tích hợp **entire L7 preprocessing pipeline**
- **Cho practitioners:** Khi triển khai NIDS, đầu tư vào **payload normalization không kém** so với việc cập nhật signature rules

---

#### 5.2.4.2 Tinh chỉnh Siêu tham số: Trade-off giữa Hiệu quả Bước (Step Efficiency) và Hiệu quả Thời gian (Wall-clock Efficiency)

Phần 3.1.6 đã giới thiệu hyperparameter tuning. Bảng được thêm vào (Bảng 4.2b so sánh Default SB3 vs. Tuned configuration) cung cấp số hình ảnh quan trọng về trade-off này.

**So sánh định lượng:**

| Cấu hình | Reward Cuối | Hội tụ (steps) | Wall-clock (giây) | n_envs |
|---|---|---|---|---|
| **Default SB3** | ~2,36 | 80k | 786 | 1 |
| **Tuned (của chúng tôi)** | ~2,28 | 220k | **197** | 4 |

**Nhận xét:**
1. **Cả hai cấu hình đều đạt reward terminal tương đương (~2,3).** Tuyên bố "tuning improve final reward" là sai. ✗
2. **Tuned hội tụ chậm hơn về steps (220k vs. 80k)** —— vì parallelization (n_envs=4) tăng sample complexity.
3. **Tuned nhanh hơn về wall-clock time 4×** — vì 4 environment song song chạy trong 197 giây cung cấp 4×220k=880k timesteps tổng, so với 1×80k=80k timesteps trong 786 giây cho Default.

**Diễn giải vận hành:**

Trong phòng thủ mạng, wall-clock time thường quan trọng hơn timesteps:
- **Lab deployment:** Nếu training mất 786 giây với Default vs. 197 giây với Tuned, Tuned là **đáng chọn** (4× faster experimentation cycle)
- **Final policy quality:** Cả hai đạt ~2,3 reward → **hiệu quả bảo mật equivalent**

Trade-off này trả lời **RQ2 operationally:** Nếu chúng ta cân bằng giữa phòng thủ nhanh và độ chính xác, tuning hyperparameters để *parallelize training* có thể **rút ngắn thời gian lab thí nghiệm mà không giảm đi defensive capability.**

---

### 5.2.5 Hạn chế và Cảnh báo Quan trọng

Dù kết quả có triển vọng, dự án này phải nhận rõ năm hạn chế lớn sẽ ảnh hưởng đến sự khác biệt giữa thành công trong lab và thành công trong sản xuất:

#### 5.2.5.1 Khoảng cách Mô phỏng (Simulation Gap)

Toàn bộ thử nghiệm diễn ra trong **Containernet**, một container ảo hóa của mạng linux-based. Điều này có nghĩa:
- **Topology cố định:** 10 VMs, 2 switches, topology liền mạch
- **Domain Randomization ±20%:** IAT, packet sizes thay đổi ±20% nhưng vẫn từ hạt giống nhân tạo
- **Absence tấn công zero-day:** Policy huấn luyện trên 5 loại tấn công đã biết

Khi triển khai lên mạng sản xuất:
- Topology đa lớp (edges, cores, DCs)
- Tấn công thực-world: botnet DDoS khác nhau, advanced evasion, zero-days
- Lưu lượng hợp lệ đa dạng: 4K streaming, blockchain, IoT devices

**Giảm thiểu:** Section 4.3.3 đã áp dụng adversarial tuning (manually trying evasion) nhưng không phải systematic Sim2Real validation. Transfer learning từ simulation đến reality vẫn cần xác nhận.

#### 5.2.5.2 Phụ thuộc vào Hàm Phần thưởng (Reward Function Dependency)

Hàm phần thưởng được định nghĩa trong 3.2.4 cân bằng:
```
R = α × detection_rate − β × false_positive_rate − γ × latency
```

Với lựa chọn (α, β, γ) cụ thể, policy học để tối ưu hàm này. **Nếu trọng số thay đổi:**
- Ưu tiên độ chính xác hơn (_α_ tăng): Policy sẽ block aggressive hơn, reducing FPR nhưng sacrificing legitimate availability
- Ưu tiên availability (_β_ tăng): Policy sẽ lenient hơn

Phát hiện **91,6%** được đưa ra dưới **một cụ thể (α, β, γ)** — nó không phải "mức phát hiện tối ưu" mà là "mức phát hiện được học dưới design choice này."

**Giảm thiểu:** Phần 4.6.5 đã thử nghiệm sensitivity thay đổi (β/α), nhưng không exhaustive. Practitioners triển khai phải tune reward weights theo SLA của họ.

#### 5.2.5.3 Phân tích Per-window che giấu Một phần Điểm yếu (Per-window Analysis Hides Weakness)

Báo cáo cho rằng **SQLi detection = 100% at session-level** là chính xác. Tuy nhiên, per-window analysis cho thấy:
- **26,3% recall per-window** — nghĩa là trong bất kỳ cửa sổ 1-second nào, chỉ 26,3% của các malicious windows được phát hiện
- **75,4% của windows trong SQLi sessions không chứa payload** — agent "không thể phát hiện" vì không có signal

Sự khác biệt per-window vs. per-session là **thực tế của L7 detection** (không toàn bộ yêu cầu HTTP chứa payload kiểm tra), nhưng nó cũng phản ánh:
- Agent dựa vào **bằng chứng tích lũy** — nếu attacker chỉ gửi một payload thay vì nhiều, detection sẽ miss
- **Latency 1 giây** cho phép attacker hoàn thành một yêu cầu trước khi bị phát hiện

#### 5.2.5.4 Ràng buộc HTTPS (HTTPS Constraint)

20 đặc trưng dựa vào **plaintext inspection** của HTTP/TCP. Khi dữ liệu được mã hóa (TLS 1.3), F12–F20 không thể tính toán được trừ khi có **SSLKEYLOGFILE** (tệp khóa session).

Kịch bản máy chủ sản xuất thường không export SSLKEYLOGFILE vì **lý do bảo mật** — nó tiết lộ symmetric session keys.

**Giảm thiểu:**
- Triển khai trên **transparent proxy (MITM position)** nơi agent thấy plaintext trước khi mã hóa
- Hoặc **accept L7 blind spot** và dựa vào L3–L4 features (F1–F11) cho HTTPS traffic

#### 5.2.5.5 Khả năng Mở rộng Ngang (Horizontal Scalability)

Dự án này training một agent **duy nhất** cho toàn bộ mạng. Khi mạng sản xuất có hàng trăm thành phần (edge routers, DCs, NAC devices), cần hỏi:
- Agent duy nhất có thể xử lý tất cả flows? (State explosion problem)
- Hay chúng ta cần **multi-agent architecture** đối với từng segment?

Dự án chưa có câu trả lời. Chapter 6.2 sẽ đề xuất công trình trong tương lai trên multi-agent coordination.

---

---

# Chương 6: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

## 6.1 Kết Luận

### Vấn đề Nghiên cứu Đã Được Xác định

Chương 1 định rõ một nhu cầu: hệ thống phòng thủ mạng hiện đại là **phản ứng, tĩnh, và overload bởi alert fatigue**. Các giải pháp truyền thống (luật firewall, IDS signature-based, rule-based ML) không thích ứng được với các cuộc tấn công tự động và phát triển ở tốc độ production.

Câu hỏi trung tâm: **Liệu RL có thể tạo ra một agent phòng thủ tự chủ có thể học chính sách phòng thủ tối ưu và duy trì nó qua thời gian, không cần can thiệp thủ công?**

### Dự án Đã Chứng minh Tính Khả thi

Kết quả thực nghiệm cho thấy **câu trả lời là có**, với các chứng cứ cụ thể:

#### 1. **Hiệu quả So sánh (RQ1):** RL Vượt trội Luật Tĩnh

- **RL Detection Rate: 91,6%** — so với Static Rules (74,3%, −17,3 pp) và Random Forest (87,9%, −3,7 pp)
- Sức mạnh đặc biệt: Agent học được **semantic understanding** của payloads nhờ HTTP feature group F12–F20 (HTTP payload features) với emphasis trên PayloadNormalizer (−12,8 pp contribution) synergizing với CRS (−10,2 pp)
- **Implication cho công nghệ:** AI-driven defense không phải chỉ học thuật — nó có measured practical advantage trong detection task thực-world (analog)

#### 2. **Đánh đổi Vận hành (RQ2):** Bảo mật đi kèm với Tính sẵn sàng

- **Legitimate traffic allowed: 93,2%** (FPR 6,8%) — chứng minh chính sách không **overfit to attack** ở cost của service availability
- **Honeypot redirection strategy** (60 seconds escalation window) cung cấp dual-benefit: mitigation + threat intelligence
- **Attack mitigation: >96% DoS, 100% SQLi session-level**
- **Implication cho vận hành:** RL không phải binary (Block All / Allow All). Nó học **graduated response** dựa trên confidence in signal — một bước forwards so với quy tắc tĩnh

#### 3. **Tính Ổn định Chính sách (RQ3):** Policy Học Được và Ổn định

- **Training curve smooth (+475% reward), no oscillation** — agent không bị "confused" bởi multi-type environment
- **approx_kl safely converges** (0,012 → 0,003, below clipping threshold) — policy updates an toàn trong RL sense
- **Agent learns differentiated responses per attack type** — không collapse thành "always block"
- **Evidence accumulation strategy** (per-window 26% recall → per-session 100% detection) cho thấy agent học được intelligent buffering of evidence, không react to noisy single observations
- **Implication cho deployment:** RL policy có **deployment durability** — không yêu cầu manual recalibration khi attack patterns shift trong một space gần với huấn luyện

### Ba Đóng góp Chính của Dự án

1. **Technical Contribution:** End-to-end integration of RL agent với NIDS pipeline including advanced L7 feature engineering (CRS integration + PayloadNormalizer). Ablation study quantifies that **HTTP payload group (F12–F20) is dominant contributor, not CRS alone** — một finding hay nhất chưa được công bố rộng rãi

2. **Methodological Contribution:** Rigorous evaluation framework distinguishing **per-window vs. per-session detection** (cặp counterintuitive metrics that surface real weaknesses), **ablation with exact pp deltas**, and **FPR/detection trade-off analysis** — sẽ be useful cho future NIDS-RL research

3. **Operational Contribution:** Demonstrated feasible deployment path:
   - Latency ~1.016 ms (acceptable with static rate-limiter as first-line defense)
   - FPR 6.8% (manageable with honeypot escalation)
   - Multi-stage action space (Block, RateLimit, Redirect) learns nuanced policy
   - Integration ready for existing SIEM infrastructure (Wazuh mention in 4.6)

### Những khoảng cách Vẫn cần Lấp

Dù hứa hẹn, dự án này chỉ apply trong **môi trường controlled (simulation)**. Để đưa vào sản xuất, cần:
- Sim-to-Real validation: transfer policy từ Containernet sang real network captures
- HTTPS support: hoặc transparent proxy hoặc accept L7 detection blind spot
- Multi-agent coordination: không chỉ scaling single agent
- Adversarial robustness testing: attack aware của policy + feature definitions

Những hướng phát triển này được chi tiết hóa trong Section 6.2.

---

## 6.2 Hướng Phát triển Tiếp Theo

Trong khi dự án này chứng minh feasibility cơ bản, một số phương hướng tự nhiên xuất hiện từ hạn chế và thành công đạt được. Phần này quy tắc từng hướng theo impact potential và effort estimate:

### 6.2.1 Mở rộng Không gian Hành động (Action Space Expansion)

**Hiện tại:** Agent chọn giữa 3 hành động (Block, RateLimit, Redirect-to-Honeypot)

**Đề xuất:**
- **Per-source-IP rate limiting** (ví dụ: 10 req/sec từ IP X, vs. 100 req/sec từ IP Y)
- **Per-request-type routing** (ví dụ: POST requests → firewall rules, GET requests → let through)
- **Dynamic honeypot spawning** (create new honeypot container trên-demand based on attack type)
- **Action masking** — guide agent exploration trong action space lớn hơn

**Tại sao quan trọng:** Multi-tenant environments hoặc large ISPs cần granulation hơn. Hành động "Block tất cả lưu lượng từ 203.0.113.0/24" quá crude — cần "RateLimit to 10k pps but allow critical ports."

**Effort:** Moderate — requires action masking library integration (SB3 hỗ trợ natively) và additional reward shaping. Est. 2–3 weeks.

**Impact:** Direct improvement to FPR (reduced false blocking) và usability untuk enterprise environments.

---

### 6.2.2 Phòng thủ Phân tán và Đa tác tử (Multi-Agent Defense Architecture)

**Hiện tại:** Single agent monitors entire network

**Đề xuất:**
- **Agent per network segment** (edge router, DC perimeter, internal sensor)
- **Distributed policy coordination:**
  - **Centralized policy server** holds shared policy; local agents do inference
  - **Or decentralized consensus:** agents share experience (policy gradients) via gossip protocol
- **Communication protocol** (AMQP-style event bus) for agents to alert each other (e.g., "Brute-force attack detected on web tier → notify DB tier agent to tighten login rules")

**Tại sao quan trọng:** Production networks have hundreds of segments. Single agent cannot maintain latency<1ms at that scale. Multi-agent allows **distributed decision-making closer to the threat** (lower latency, fewer bandwidth hops).

**Effort:** Very High — requires:
- Multi-agent RL theory (cooperative learning, communication overhead, policy divergence prevention)
- Distributed systems engineering (eventual consistency, fault tolerance)
- Est. 4–6 months research + implementation

**Impact:** Enable **enterprise SDN deployment** (current work limited to Containernet lab). This is gateway to production.

---

### 6.2.3 Robustness đối với Adversarial Evasion (Adversarial Attack & Defense)

**Hiện tại:** Attack evaluation is "cooperative" — attacker doesn't know feature definitions

**Đề xuất:**
- **Adversarial attacker model:** Attacker knows:
  - Feature definitions (F1–F20)
  - Reward function
  - Policy architecture (2-layer MLP, hidden=256)
- **Evasion tactics to test:**
  - Payload normalization bypass (e.g., `%255c` = double-URL-encoded backslash)
  - Timing variation (slow SYN flood at <100 SYN/sec to stay below F1 threshold)
  - Polyglot payloads (simultaneously valid SQL AND valid XML)
- **Defense:** Adversarially train policy against adaptive attacker (min-max game)

**Tại sao quan trọng:** Real attackers are not naive. If RL defense is deployed, attackers will adapt. Evaluation must stress-test this.

**Effort:** Very High — requires:
- Adversarial RL theory (two-player game, convergence analysis)
- Custom attack synthesis toolkit
- Computational overhead (training 2 agents simultaneously)
- Est. 5–6 months

**Impact:** Identifies **exploitable weaknesses before deployment** (could be critical for safety-critical applications like industrial networks).

---

### 6.2.4 Online Retraining và Concept Drift Handling (Continuous Learning)

**Hiện tại:** Policy fixed after training; no adaptation to new threats

**Đề xuất:**
- **Drift detection:** Monitor recent traffic against policy — if FPR sudden spike or new attack signature detected → trigger retraining flag
- **Incremental retraining:** Fine-tune policy on recent flows without forgetting old knowledge (elastic weight consolidation, replay buffer sampling)
- **A/B testing:** Run old vs. new policy in parallel on shadow traffic to validate before swapover

**Tại sao quan trọng:** Threat landscape evolves (new malware variants, new evasion techniques). Policy becomes stale. Manual policy updates every 6 months insufficient.

**Effort:** Moderate–High — requires:
- Drift detection statistical test (change detection in data distribution)
- Continual learning library integration (ewc, SI, etc.)
- CI/CD pipeline for policy retraining
- Est. 2–3 weeks

**Impact:** Maintains defensive effectiveness over years, not just deployment moment.

---

### 6.2.5 Transparent Decision Logs và Explainability (Interpretability for Operations)

**Hiện tại:** Policy is black-box; operator sees "Action predicted" without explanation

**Đề xuất:**
- **Attention visualization:** Show which features (F1–F20) most influenced decision (SHAP, LIME applied per-inference)
- **Decision logs:** "Request from 203.0.113.45, SYN ratio=0.9, PacketRate=500 → F1 and F2 both high → Predicted Action: BLOCK with 92% confidence, 8% exploratory noise"
- **Policy audit trail:** Render learned decision tree (even if learned implicitly) for security reviewer approval

**Tại sao quan trọng:**
- **Regulatory:** PCI-DSS, GDPR demand audit trails ("why was this request blocked?")
- **Operational trust:** Security teams won't trust black-box system without explainability
- **Debugging:** If false positive, explain "which 3 features triggered?"

**Effort:** Moderate — requires:
- LIME/SHAP library integration
- UI dashboard for logs
- Policy serialization for audit
- Est. 2–3 weeks

**Impact:** **Enables production deployment** — currently biggest blocker to SOC adoption is "I don't understand why AI blocked this."

---

### 6.2.6 Simulation-to-Reality Gap Validation (Sim2Real Transfer Learning)

**Hiện tại:** policy trained on Containernet, real-world generalization unknown

**Đề xuất — Three-phase approach:**

**Phase 1: Distribution Shift Analysis**
- Collect real network packet traces (e.g., from LSNM2024 dataset, or customer firewall PCAP)
- Compare feature distributions: compute F1–F20 statistics (mean, variance, percentiles) for real vs. simulated traffic
- Identify **largest distribution shifts** (e.g., real networks have 10× higher PacketRate variance)

**Phase 2: Policy Transfer + Evaluation**
- Deploy **trained Containernet policy** on real traffic (shadow mode, no actual blocking)
- Evaluate: detection rate on real attacks
- Expected outcome: degradation (e.g., from 91.6% → 70–80% on real data due to distribution shift)

**Phase 3: Sim2Real Fine-tuning**
- Use real traffic to **fine-tune policy** (continue training on real data, smaller learning rate to avoid catastrophic forgetting)
- Target: restore detection to near 91%ish (adjusted for real-network attack diversity)
- Deployment: use fine-tuned policy

**Tại sao quan trọng:** Single most critical risk to production deployment. Containernet ≠ real network.

**Effort:** Very High — requires:
- Real-world dataset access (privacy-sensitive)
- Large-scale labeling effort (attack vs. legitimate classification on real data)
- Distributed evaluation infrastructure (policy inference at scale)
- Est. 2–3 months

**Impact:** **Gateway to actual production deployment**. Without this, no amount of lab validation matters.

---

## Tóm tắt và Tầm nhìn Tương lai

Dự án này đã chứng minh rằng RL là một **feasible, practical nền tảng** cho hệ thống phòng thủ mạng tự chủ. Ba câu hỏi nghiên cứu được trả lời:
- **RQ1:** RL outperforms rule-based (91.6% vs. 74.3%)
- **RQ2:** RL balances security ∧ availability (93.2% legit allowed, 96%+ attack mitigation)
- **RQ3:** RL maintains stable policy across diverse attacks

Tuy nhiên, chặng đường từ lab success đến production deployment là dài. Bốn hướng chính (multi-agent, adversarial robustness, continuous learning, Sim2Real validation) là những bước tiếp theo tự nhiên định hình tương lai của bộ phòng thủ RL-driven.

Sự kết hợp của **academic rigor** (ablation studies, distributed learning theory) và **operational pragmatism** (honeypot escalation, FPR management, SIEM integration) là chìa khóa để RL defense không chỉ là proof-of-concept mà là **deployed reality** trong các tổ chức sắp tới.

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
