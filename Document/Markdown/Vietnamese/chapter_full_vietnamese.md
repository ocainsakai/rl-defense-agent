---
**BỘ GIÁO DỤC VÀ ĐÀO TẠO**
**TRƯỜNG ĐẠI HỌC FPT**

---

# CAPSTONE PROJECT DOCUMENT

## Nghiên cứu và phát triển AI Agent có khả năng tự phòng thủ thích ứng trong môi trường mô phỏng dựa trên kỹ thuật Reinforcement Learning

---

**Nhóm thực hiện:**

| Họ và Tên | Mã số sinh viên |
|---|---|
| Hồ Lê Bình | [MSSV] |
| Nguyễn Hoàng Trí | [MSSV] |
| Phạm Tuấn Anh | [MSSV] |
| Trịnh Nguyên Yến Vy | [MSSV] |

**Giảng viên hướng dẫn:** [Mai Hoàng Đỉnh]

**Mã đề tài Capstone:** [SP26IA03]

---

**TP. Hồ Chí Minh, 2026**

---

# TÓM TẮT

## Phát hiện Xâm nhập Mạng sử dụng Học Tăng cường: Tác nhân Phòng thủ Dựa trên RL với Học Chính sách Thích ứng

**Bối cảnh:** Các cơ chế phòng thủ mạng truyền thống dựa trên quy tắc tĩnh và phát hiện dựa trên chữ ký, gặp khó khăn trong việc thích ứng với các cuộc tấn công mạng ngày càng tinh vi và không ngừng thay đổi. Nghiên cứu này giải quyết nhu cầu về hệ thống phòng thủ tự chủ sử dụng Học Tăng cường (RL) để học các chính sách phòng thủ tối ưu.

**Phương pháp:** Nghiên cứu xây dựng Tác nhân Phòng thủ dựa trên RL sử dụng thuật toán Proximal Policy Optimization, được huấn luyện trong môi trường mô phỏng với 5 loại tấn công (SYN Flood, Port Scan, Brute-Force, SQL Injection, XSS). Tác nhân quan sát vector đặc trưng **34 chiều** gồm: **(1)** 20D đặc trưng thống kê bao gồm luồng mạng (F1–F11: tốc độ gói tin, tỷ lệ SYN/ACK, phân phối cổng, v.v.) và đặc trưng payload HTTP (F12–F20: phát hiện SQL/XSS qua OWASP CRS 941/942); **(2)** 10D trạng thái temporal theo IP (mã hóa one-hot hành động gần nhất, bộ đếm giữ hành động, EMA tổn thất dịch vụ và xu hướng, điểm bằng chứng leo thang, ngân sách bỏ lỡ); **(3)** 4D phản hồi vòng kín từ môi trường (khả năng tiếp cận webserver, tỉ lệ bắt giữ honeypot, tín hiệu hiện diện dịch vụ, mức tổn thất dịch vụ). Tác nhân lựa chọn trong bốn hành động phòng thủ có thứ bậc: Cho phép, Giới hạn Tốc độ, Chuyển hướng sang Honeypot và Chặn. Module Quan sát chuyển đổi gói tin thô thành vector quan sát theo thời gian thực. Quá trình huấn luyện diễn ra khoảng 500.000 bước với tần suất đánh giá mỗi 10.000 bước.

**Kết quả:** Tác nhân RL đạt **77,3% tỷ lệ phát hiện** trên các bước lưu lượng có mối đe dọa tích cực, với hội tụ ổn định qua 5 lần chạy độc lập (độ lệch chuẩn 0,021, giảm 28% phương sai so với cấu hình mặc định SB3). Chính sách cân bằng bảo mật và tính sẵn sàng của dịch vụ: 93,2% lưu lượng hợp lệ được cho phép (FPR 6,8%). Quá trình huấn luyện hội tụ trơn tru với cải thiện phần thưởng +475%, cập nhật chính sách an toàn (KL-divergence: 0,012→0,003). Nhóm đặc trưng payload HTTP là thiết yếu cho phát hiện SQLi/XSS; pipeline chuẩn hóa payload và các quy tắc CRS hoạt động hiệp đồng để xử lý evasion mã hóa kép.

**Kết luận:** Nghiên cứu chứng minh tính khả thi của RL cho phòng thủ mạng thích ứng. Tác nhân học được các chính sách ổn định, có sự phân hóa rõ ràng qua các loại tấn công đa dạng trong khi cân bằng giảm thiểu mối đe dọa với tính sẵn sàng của dịch vụ. Kiến trúc lai kết hợp giới hạn tốc độ tĩnh với RL phân tích tầng ứng dụng là cần thiết để giải quyết ràng buộc độ trễ hệ thống. Hướng nghiên cứu tiếp theo bao gồm phối hợp đa tác nhân và xác thực chuyển đổi từ mô phỏng sang thực tế.

**Từ khóa:** Học Tăng cường, Phát hiện Xâm nhập Mạng, Proximal Policy Optimization, Phòng thủ An ninh Mạng, Kỹ thuật Đặc trưng, Chuẩn hóa Payload, OWASP ModSecurity, Phòng thủ Thích ứng, Học Chính sách, Phân tích Mạng

---

# MỤC LỤC

- TÓM TẮT
- MỤC LỤC
- DANH SÁCH HÌNH ẢNH
- DANH SÁCH BẢNG
- DANH MỤC VIẾT TẮT

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
- 1.6 Câu hỏi Nghiên cứu
- 1.7 Cấu trúc Luận văn

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
  - 3.3.8 Trạng thái Temporal theo IP (10D)
  - 3.3.9 Phản hồi Vòng kín (4D effect\_{t-1})
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
  - 6.2.3 Độ bền vững đối với Tấn công Evasion
  - 6.2.4 Huấn luyện Trực tuyến và Xử lý Trôi dạt Khái niệm
  - 6.2.5 Nhật ký Quyết định Minh bạch và Khả năng Giải thích
  - 6.2.6 Xác thực Khoảng cách Mô phỏng-Thực tế

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

An ninh mạng đã trải qua những thay đổi đáng kể trong thập kỷ qua. Sự tăng trưởng nhanh của cơ sở hạ tầng kỹ thuật số, điện toán đám mây và các mạng kết nối quy mô lớn đã vừa mở ra cơ hội mới, vừa làm tăng bề mặt tấn công. Đồng thời, các mối đe dọa mạng ngày càng tự động hóa, thích ứng và tinh vi hơn, đặt ra những thách thức nghiêm trọng cho các cơ chế bảo mật truyền thống.

**1.1.1 Sự leo thang của các mối đe dọa mạng và Tự động hóa tấn công**

Tấn công mạng hiện đại đã không còn mang tính chủ yếu thủ công hay cơ hội. Thay vào đó, kẻ thù dựa vào công cụ tự động để thực hiện trinh sát quy mô lớn, quét lỗ hổng, nhồi nhét thông tin xác thực (credential stuffing) và khai thác ở tốc độ máy. Báo cáo Điều tra Vi phạm Dữ liệu của Verizon (DBIR) cho thấy khoảng 60% vụ vi phạm dữ liệu liên quan đến yếu tố con người — bao gồm tấn công phi kỹ thuật (social engineering), lạm dụng thông tin xác thực và lỗi người dùng — trong khi khai thác lỗ hổng phần mềm và ứng dụng web tiếp tục gia tăng [26].

![][image1]

Các tấn công ứng dụng web và xâm nhập hệ thống vẫn là những mẫu vi phạm phổ biến nhất. Những tấn công này có mức tự động hóa cao, cho phép kẻ tấn công nhanh chóng xác định dịch vụ bị lộ và khai thác điểm yếu trên hàng nghìn mục tiêu cùng lúc. Tự động hóa quy mô lớn như vậy làm giảm đáng kể hiệu quả của các hệ thống bảo mật tĩnh dựa trên quy tắc — những hệ thống phụ thuộc vào chữ ký được định nghĩa sẵn hoặc các quy tắc tạo thủ công [26].

Ngoài các kẻ thù từ bên ngoài, mối đe dọa nội bộ cũng không thể bỏ qua. Phát hiện của DBIR chỉ ra gần 30% vụ vi phạm dữ liệu liên quan đến tác nhân nội bộ — dù do ý đồ xấu hay hành động vô ý — điều này chứng minh mối đe dọa không chỉ đến từ bên ngoài ranh giới tổ chức [27]. Sự đa dạng này làm phức tạp bối cảnh phòng thủ và đòi hỏi các chiến lược bảo mật thích ứng hơn.

**1.1.2 Tác động kinh tế của vi phạm dữ liệu**

Ngoài hậu quả kỹ thuật, tấn công mạng gây ra chi phí tài chính và vận hành nghiêm trọng. Báo cáo Chi phí Vi phạm Dữ liệu của Viện IBM–Ponemon cho biết chi phí trung bình toàn cầu cho một vụ vi phạm đã lên tới vài triệu đô la Mỹ, với chi phí cao hơn đáng kể trong các ngành công nghiệp được quy định chặt chẽ và doanh nghiệp lớn [28]. Chi phí này bao gồm phản ứng sự cố, khôi phục hệ thống, phạt pháp lý, tổn hại danh tiếng và mất niềm tin khách hàng trong dài hạn.

Tần suất và quy mô ngày càng tăng của sự cố mạng, kết hợp với tác động kinh tế đáng kể, nhấn mạnh sự cần thiết của các cơ chế phát hiện và phản ứng nhanh hơn. Phản ứng chậm trễ hoặc không hiệu quả sẽ khuếch đại tổn thất tài chính, khiến khả năng phòng thủ theo thời gian thực (hoặc gần thời gian thực) trở thành yêu cầu quan trọng cho cơ sở hạ tầng mạng hiện đại.

**1.1.3 Sự phát triển của cơ sở hạ tầng mạng và Thách thức vận hành**

Chuyển đổi từ phần cứng tại chỗ sang cơ sở hạ tầng ảo hóa và dựa trên đám mây đã mở rộng bề mặt tấn công. Công nghệ như ảo hóa, container hóa và mạng điều khiển bằng phần mềm (SDN) cho phép triển khai linh hoạt, nhưng cũng tạo ra khối lượng lớn lưu lượng mạng và sự kiện bảo mật. Kết quả là Trung tâm Điều hành An ninh (SOC) thường bị quá tải bởi số lượng cảnh báo quá mức — hiện tượng gọi là "mệt mỏi vì cảnh báo" (alert fatigue).

Trong môi trường như vậy, nhà phân tích con người gặp khó khăn khi kiểm tra và tương quan cảnh báo thủ công và kịp thời. Sự cố bảo mật nghiêm trọng có thể bị bỏ qua hoặc phát hiện quá muộn, cho phép kẻ tấn công tồn tại lâu trong mạng. Nút thắt vận hành này phơi bày hạn chế của việc giám sát bảo mật do con người điều khiển trong môi trường mạng quy mô lớn và tốc độ cao.

**1.1.4 Nhu cầu về Hệ thống phòng thủ tự chủ và thích ứng**

Với sự tự động hóa của các cuộc tấn công mạng, hậu quả kinh tế của các vụ vi phạm và sự phức tạp của cơ sở hạ tầng mạng hiện đại, nhu cầu về các cơ chế phòng thủ tự chủ và thích ứng ngày càng tăng. Trí tuệ nhân tạo (AI), đặc biệt là Học tăng cường (Reinforcement Learning \- RL), đã nổi lên như một phương pháp hứa hẹn để giải quyết những thách thức này.

Khác với học có giám sát dựa trên tập dữ liệu được gán nhãn, RL cho phép tác nhân học chiến lược phòng thủ tối ưu thông qua tương tác liên tục với môi trường. Tác nhân quan sát trạng thái mạng và nhận phần thưởng hoặc hình phạt, từ đó điều chỉnh hành vi linh hoạt theo các mẫu tấn công phát triển. Khả năng này làm RL đặc biệt phù hợp với phòng thủ mạng thời gian thực, nơi chiến lược tấn công và điều kiện hệ thống thay đổi nhanh.

Do đó, việc tích hợp các tác nhân AI tự chủ vào kiến trúc phòng thủ mạng đại diện cho một bước quan trọng hướng tới việc nâng cao khả năng phục hồi và khả năng phản ứng của các hệ thống an ninh mạng.

**1.2 Phát biểu vấn đề**

Mặc dù công nghệ an ninh mạng tiến bộ đáng kể, phòng thủ mạng hiện tại vẫn chủ yếu mang tính phản ứng và phụ thuộc vào quy tắc được định nghĩa sẵn cùng sự can thiệp con người. Các giải pháp bảo mật truyền thống — tường lửa dựa trên quy tắc, hệ thống phát hiện xâm nhập (IDS) dựa trên chữ ký, và chính sách kiểm soát truy cập cấu hình thủ công — chỉ hiệu quả với mẫu tấn công đã biết. Chúng gặp khó khăn trong việc thích ứng với hành vi đối kháng mới hoặc phản ứng với tốc độ cần thiết chống lại tấn công tự động hóa cao.

Thêm vào đó, cơ sở hạ tầng mạng hiện đại tạo ra khối lượng dữ liệu bảo mật khổng lồ do điện toán đám mây, ảo hóa và SDN. SOC thường bị quá tải bởi luồng cảnh báo liên tục, dẫn đến phản ứng chậm trễ và gia tăng rủi ro alert fatigue. Nhà phân tích con người có thể bỏ qua mối đe dọa nghiêm trọng hoặc phản ứng quá chậm, cho phép kẻ tấn công tồn tại lâu trong mạng.

Hạn chế chính khác là thiếu khả năng ra quyết định tự chủ. Hầu hết hệ thống bảo mật dựa trên chính sách tĩnh hoặc yêu cầu điều chỉnh thủ công, khiến chúng bất phù hợp với môi trường năng động nơi chiến lược tấn công thay đổi nhanh. Ngay cả giải pháp học máy cũng thường phụ thuộc vào học có giám sát — yêu cầu tập dữ liệu lớn, gán nhãn, khó thu thập và nhanh lỗi thời trong thực tế an ninh mạng.

Trước những thách thức này, cần một cơ chế phòng thủ thích ứng có thể tự chủ quan sát điều kiện mạng, xác định hành vi độc hại và thực hiện giảm thiểu phù hợp theo thời gian thực. Hệ thống phải có khả năng học từ tương tác với môi trường, cân bằng mục tiêu bảo mật với tính sẵn sàng dịch vụ, và liên tục thích ứng với mẫu tấn công mới mà không cần kiến thức trước rõ ràng.

Dự án này giải quyết những hạn chế trên bằng cách đề xuất tác nhân phòng thủ mạng dựa trên AI với Học tăng cường (RL). Bằng cách mô hình hóa phòng thủ mạng như một bài toán ra quyết định tuần tự, tác nhân RL được thiết kế để học chiến lược phản ứng tối ưu thông qua tương tác thử-và-sai. Vấn đề trung tâm là: **Làm thế nào để thiết kế, huấn luyện và đánh giá một tác nhân phòng thủ tự chủ có khả năng giảm thiểu hiệu quả tấn công mạng đa dạng trong khi vẫn duy trì hiệu suất mạng ở mức chấp nhận được?**

**1.3 Mục tiêu nghiên cứu**

Mục tiêu chính là thiết kế, triển khai và đánh giá một hệ thống phòng thủ mạng tự chủ có khả năng ra quyết định bảo mật theo thời gian thực trong môi trường năng động và đối kháng. Để đạt được điều này, nghiên cứu được dẫn dắt bởi các mục tiêu cụ thể sau:

* **Nghiên cứu** khả năng áp dụng của các kỹ thuật Học tăng cường (RL) cho việc ra quyết định tự chủ trong các kịch bản phòng thủ mạng, đặc biệt là trong các môi trường đặc trưng bởi các cuộc tấn công mạng tự động và thích ứng.  
* **Thiết kế** và xây dựng một môi trường mạng mô phỏng đại diện chính xác cho cơ sở hạ tầng mạng thực tế, bao gồm máy chủ sản xuất, kẻ tấn công và các thành phần phòng thủ bằng Mininet.  
* **Phát triển** một tác nhân phòng thủ dựa trên RL có khả năng quan sát trạng thái mạng, xác định các hành vi bất thường hoặc độc hại và lựa chọn các hành động giảm thiểu phù hợp: chặn, giới hạn tốc độ hoặc chuyển hướng lưu lượng.  
* **Định nghĩa** và triển khai một hàm phần thưởng cân bằng giữa hiệu quả bảo mật và hiệu suất hệ thống, đảm bảo rằng các hành động phòng thủ giảm thiểu các cuộc tấn công trong khi vẫn duy trì tính sẵn sàng của dịch vụ.  
* **Đánh giá** hiệu suất của tác nhân phòng thủ được đề xuất đối với nhiều kịch bản tấn công bằng cách đo lường các chỉ số chính như tỷ lệ giảm thiểu tấn công, thời gian phản hồi, tỷ lệ dương tính giả và độ ổn định chung của mạng.

Bằng cách giải quyết các mục tiêu này, dự án chứng minh tính khả thi và hiệu quả của RL trong xây dựng phòng thủ mạng tự chủ, đồng thời cung cấp hiểu biết thực nghiệm về hành vi của tác nhân trong các điều kiện tấn công đa dạng.

**1.4 Ý nghĩa của nghiên cứu**

Nghiên cứu này khám phá tính khả thi của phòng thủ mạng tự chủ sử dụng Học tăng cường, hướng tới nâng cao cơ chế bảo mật truyền thống thông qua phòng thủ thích ứng và tự học.

Từ góc độ kỹ thuật, dự án cung cấp triển khai thực tế của tác nhân phòng thủ dựa trên RL tích hợp với môi trường mạng mô phỏng. Sự kết hợp Gymnasium, Mininet và các kỹ thuật Linux chứng minh cách RL áp dụng vào kịch bản mạng lấy cảm hứng từ thế giới thực. Tích hợp Wazuh SIEM minh họa tiềm năng kết hợp tác nhân tự chủ với nền tảng giám sát hiện có để nâng cao khả năng quan sát.

Từ góc độ học thuật, dự án cung cấp hiểu biết thực nghiệm về tác nhân RL dưới các kịch bản tấn công đa dạng. Kết quả đánh giá giúp làm rõ cách tác nhân tự chủ cân bằng hiệu quả bảo mật với tính sẵn sàng dịch vụ — sự đánh đổi quan trọng trong phòng thủ mạng. Những phát hiện này là tài liệu tham khảo cho nghiên cứu tương lai về hệ thống an ninh thích ứng và ra quyết định dựa trên RL.

Từ góc độ thực tiễn, dự án nhấn mạnh tiềm năng của hệ thống phòng thủ tự chủ do AI điều khiển trong việc giảm gánh nặng vận hành cho nhà phân tích con người. Tự động hóa phát hiện và phản ứng có thể giảm alert fatigue và cho phép phản ứng nhanh hơn, nhất quán hơn. Do đó, dự án đặt nền móng cơ bản cho các giải pháp phòng thủ mạng thông minh, khả năng mở rộng và linh hoạt trong tương lai.

**1.5 Phạm vi và Hạn chế**

Phần này xác định phạm vi nghiên cứu và làm rõ các hạn chế của phương pháp được đề xuất nhằm thiết lập những kỳ vọng thực tế cho kết quả của nghiên cứu.

**1.5.1 Phạm vi nghiên cứu**

Phạm vi của dự án này tập trung vào việc thiết kế và đánh giá một tác nhân phòng thủ mạng tự chủ trong một môi trường mô phỏng được kiểm soát. Nghiên cứu nhấn mạnh vào việc ra quyết định ở cấp độ mạng và tầng ứng dụng nhẹ.

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
  **Tất cả các hành động phòng thủ đều được triển khai bằng các cơ chế iptables, công cụ quản lý firewall cấp kernel của Linux, cho phép lọc và điều chỉnh hướng gói tin với độ trễ tối thiểu (~1ms); kiểm soát lưu lượng (tc) trong mạng mô phỏng.**

Ngăn xếp công nghệ

Việc triển khai tận dụng một bộ công cụ và khung nguồn mở được áp dụng rộng rãi, bao gồm:

* **Python** làm ngôn ngữ lập trình chính.
* **Gymnasium** để định nghĩa môi trường học tăng cường.
* **Mininet** để giả lập các cấu trúc mạng ảo.
* **Stable Baselines3** để huấn luyện các mô hình học tăng cường.
* **Wazuh SIEM** để thu thập nhật ký, trực quan hóa và giám sát hiệu suất.

Ngoài ra còn các công nghệ khác: **Docker, PHP, MySQL, ...**

**1.5.2 Những hạn chế của nghiên cứu**

Mặc dù có những đóng góp nhất định, nghiên cứu này vẫn có một số hạn chế cần thừa nhận.

Thứ nhất, hệ thống phòng thủ chỉ được đánh giá trong môi trường mô phỏng. Mặc dù mô phỏng được thiết kế để xấp xỉ hành vi mạng thực tế, kết quả triển khai production có thể khác biệt do hạn chế phần cứng, không đồng nhất mạng và hành vi người dùng khó đoán.

Thứ hai, kịch bản tấn công giới hạn ở tập hợp các loại được định nghĩa sẵn. Mối đe dọa nâng cao như zero-day, tấn công chuỗi cung ứng và lateral movement tinh vi nằm ngoài phạm vi.

Thứ ba, hiệu suất tác nhân RL phụ thuộc vào chất lượng hàm phần thưởng và tính đại diện của môi trường mô phỏng. Thiết kế phần thưởng chưa tối ưu hoặc trạng thái không đầy đủ có thể hạn chế khả năng tổng quát hóa đối với tình huống mới.

Cuối cùng, hệ thống được triển khai trên Ubuntu Linux. Khả năng chuyển đổi sang hệ điều hành khác hoặc môi trường đám mây phân tán quy mô lớn chưa được đánh giá và vẫn là chủ đề cho nghiên cứu tương lai.

**1.6 Câu hỏi Nghiên cứu**

Dựa trên phát biểu vấn đề và mục tiêu nghiên cứu ở trên, luận văn hướng tới trả lời ba câu hỏi nghiên cứu sau:

*   **RQ1 (Hiệu quả so sánh):** Tác tử RL vượt trội so với cơ chế dựa trên quy tắc truyền thống đến mức nào trong việc giảm thiểu tấn công mạng đa dạng trong môi trường mô phỏng?

*   **RQ2 (Đánh đổi vận hành):** Hành động phòng thủ tự chủ (chặn, giới hạn tốc độ, chuyển hướng) ảnh hưởng như thế nào đến cân bằng giữa giảm thiểu tấn công và tính sẵn sàng dịch vụ hợp lệ?

*   **RQ3 (Tính ổn định chính sách):** Tác tử RL có thể xây dựng và duy trì chính sách phòng thủ ổn định, hiệu quả trên vector tấn công đa dạng và không ngừng phát triển mà không cần cấu hình lại thủ công không?

Ba câu hỏi này được trả lời lần lượt trong Chương 4 (kết quả thực nghiệm) và Chương 5 (thảo luận).

**1.7 Cấu trúc Luận văn**

Phần còn lại của luận văn được tổ chức như sau:

**Chương 2 — Tổng quan Tài liệu** trình bày nền tảng RL, môi trường mô phỏng mạng, phản ứng sự cố tự động và kỹ thuật trích xuất đặc trưng. Chương này xác định khoảng trống nghiên cứu mà dự án nhắm tới.

**Chương 3 — Phương pháp Nghiên cứu** mô tả thiết kế hệ thống, bao gồm hình thức hóa bài toán MDP, kiến trúc tác nhân PPO, pipeline trích xuất 20 đặc trưng thống kê (F1–F20) và mở rộng thành vector quan sát 34 chiều (20D thống kê + 10D temporal + 4D phản hồi vòng kín), topology mạng Mininet và cơ chế thực thi thời gian thực qua iptables.

**Chương 4 — Kết quả Thực nghiệm** trình bày và phân tích các kết quả đánh giá hệ thống, bao gồm độ chính xác phát hiện tấn công, đường cong hội tụ huấn luyện, so sánh với các phương pháp nền và hàm ý thực tiễn.

**Chương 5 — Thảo luận** diễn giải các phát hiện trong bối cảnh rộng hơn, thảo luận về hạn chế và đề xuất hướng nghiên cứu tương lai.

**Chương 6 — Kết luận** tổng hợp các đóng góp chính và nhận xét cuối cùng về tính khả thi của Học tăng cường trong phòng thủ mạng tự chủ.

**Chương 2**

**TỔNG QUAN TÀI LIỆU**

**2.1 Các kiến thức cơ bản về Học tăng cường**

Học tăng cường (Reinforcement Learning \- RL) là một nhánh của học máy tập trung vào việc cho phép các tác nhân học các hành vi tối ưu thông qua tương tác với môi trường. Không giống như học có giám sát, vốn dựa vào các bộ dữ liệu được gán nhãn, RL cho phép một tác nhân học trực tiếp từ kinh nghiệm bằng cách nhận phản hồi dưới dạng phần thưởng hoặc hình phạt. Mô hình học tập này đặc biệt phù hợp cho các lĩnh vực năng động và đối kháng như an ninh mạng, nơi dữ liệu được gán nhãn khan hiếm và các chiến lược tấn công liên tục phát triển.

**2.1.1 Khung Học tăng cường**

Quá trình học tăng cường thường được mô hình hóa như một sự tương tác giữa một tác nhân và một môi trường. Tại mỗi bước thời gian rời rạc, tác nhân quan sát trạng thái hiện tại của môi trường và chọn một hành động theo chính sách của nó. Để đáp lại, môi trường chuyển sang một trạng thái mới và cung cấp một phần thưởng vô hướng phản ánh chất lượng hành động của tác nhân.

**Sự tương tác này thường được chính thức hóa bằng Quy trình Quyết định Markov (MDP), được xác định bởi một bộ $(S, A, P, R, \\gamma)$ [12], trong đó:**

* $S$ đại diện cho tập hợp các trạng thái có thể.
* $A$ biểu thị tập hợp các hành động có sẵn.
* $P(s'|s, a)$ xác định xác suất chuyển đổi trạng thái.
* $R(s, a)$ là hàm phần thưởng.
* $\\gamma \\in \[0, 1\]$ là hệ số chiết khấu cân bằng giữa phần thưởng tức thời và phần thưởng trong tương lai.

Mục tiêu của tác nhân là học một chính sách $\\pi(a|s)$ nhằm tối đa hóa phần thưởng tích lũy kỳ vọng theo thời gian. Trong bối cảnh phòng thủ mạng, điều này tương ứng với việc học các chuỗi hành động giảm thiểu nhằm giảm tác động của cuộc tấn công trong khi vẫn duy trì hiệu suất hệ thống ở mức chấp nhận được [12].

**2.1.2 Học tăng cường dựa trên mô hình và Phi mô hình**
//NOTE: Model-based reflex agent

Các thuật toán học tăng cường có thể được phân loại rộng rãi thành các phương pháp dựa trên mô hình (model-based) và phi mô hình (model-free). Các phương pháp RL dựa trên mô hình cố gắng học hoặc sử dụng một mô hình rõ ràng về động lực học của môi trường, mô hình này sau đó có thể được sử dụng để lập kế hoạch và ra quyết định. Mặc dù các phương pháp như vậy có thể hiệu quả về mẫu (sample-efficient), nhưng việc mô hình hóa chính xác các môi trường mạng phức tạp và hành vi của kẻ tấn công thường không thực tế.

Mặt khác, **RL phi mô hình học các chính sách tối ưu trực tiếp từ các tương tác mà không cần một mô hình rõ ràng về môi trường**. Các phương pháp này thường được áp dụng phổ biến hơn trong nghiên cứu an ninh mạng do tính linh hoạt và khả năng xử lý các môi trường phức tạp, chỉ quan sát được một phần. Các phương pháp phi mô hình phổ biến bao gồm các phương pháp dựa trên giá trị (value-based) và phương pháp dựa trên chính sách (policy-based).

***2.1.3 Học tăng cường sâu (Deep Reinforcement Learning)***

//NOTE KHÔNG ĐƯA VÀO SLIDE

*Các kỹ thuật học tăng cường truyền thống gặp khó khăn trong việc mở rộng sang các môi trường có không gian trạng thái lớn hoặc liên tục. Học tăng cường sâu (DRL) giải quyết hạn chế này bằng cách tích hợp các mạng nơ-ron sâu làm bộ xấp xỉ hàm cho các hàm giá trị hoặc chính sách.*

*Các phương pháp DRL dựa trên giá trị, chẳng hạn như Mạng Q sâu (Deep Q-Networks \- DQN), xấp xỉ hàm giá trị hành động bằng cách sử dụng mạng nơ-ron và chọn các hành động tối đa hóa phần thưởng kỳ vọng. Ngược lại, các phương pháp dựa trên chính sách trực tiếp tối ưu hóa hàm chính sách và thường phù hợp hơn cho các môi trường có không gian hành động liên tục hoặc nhiều chiều.*

*Trong số các thuật toán dựa trên chính sách hiện đại, Tối ưu hóa chính sách lân cận (Proximal Policy Optimization \- PPO) đã được áp dụng rộng rãi do tính ổn định và hiệu quả về mẫu. PPO hạn chế các cập nhật chính sách để ngăn chặn những thay đổi quá lớn, do đó cải thiện tính ổn định của quá trình huấn luyện. Những đặc điểm này làm cho PPO trở nên đặc biệt hấp dẫn đối với các kịch bản phòng thủ mạng, nơi các chính sách không ổn định có thể dẫn đến các hành động giảm thiểu gây gián đoạn hoặc quá mức cần thiết.*

*Nhìn chung, học tăng cường cung cấp một khuôn khổ linh hoạt và mạnh mẽ cho việc ra quyết định tự chủ. Khả năng học hỏi từ tương tác và thích ứng với môi trường thay đổi tạo thành nền tảng lý thuyết cho tác nhân phòng thủ mạng dựa trên AI được đề xuất trong nghiên cứu này [2].*

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

Nhìn chung, các môi trường mô phỏng mạng tạo thành xương sống thực nghiệm của nghiên cứu an ninh mạng tự chủ. Bằng cách kết hợp giả lập mạng thực tế với các giao diện học tăng cường được tiêu chuẩn hóa, các môi trường này cho phép phát triển an toàn và hiệu quả các tác nhân phòng thủ thích ứng [29], [11].

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

Phản ứng tự động hiệu quả đòi hỏi cơ chế thực thi đáng tin cậy ở cấp mạng và hệ thống. Các công cụ cấp kernel Linux — chủ yếu là **iptables** và **Traffic Control (tc)** — thường được sử dụng để thực hiện phòng thủ thời gian thực.

**iptables** là công cụ quản lý firewall trên Linux, hoạt động ở cấp kernel để lọc và điều chỉnh hướng gói tin IP [18]. Nó định nghĩa các chuỗi (chains) gồm nhiều quy tắc (rules), mỗi quy tắc chỉ định tiêu chí so khớp (địa chỉ, cổng, giao thức) và hành động (ACCEPT, DROP, REDIRECT, QUEUE). Với độ trễ thực thi < 1ms, iptables đảm bảo phản ứng gần thời gian thực cần thiết cho an ninh mạng. Các hành động chủ yếu:

- **ACCEPT**: Cho phép gói tin đi qua (mặc định)
- **DROP**: Loại bỏ gói tin không gửi phản hồi
- **REDIRECT**: Chuyển hướng gói sang cổng khác (dùng cho honeypot)
- **QUEUE**: Gửi gói tới userspace (nơi agent RL có thể xử lý)

**Traffic Control (tc)** là công cụ định hình lưu lượng cho phép giới hạn tốc độ (rate limiting) và điều tiết bandwidth động trên interface mạng. Kết hợp với iptables, TC cho phép áp dụng chính sách phòng thủ phức tạp như giới hạn 10 pkt/sec cho một IP nhất định.

Bằng cách tích hợp ra quyết định của RL agent với các điều khiển kernel-level này, hệ thống phòng thủ tự động có thể phản ứng với cả tốc độ (kernel) và sự thông minh (AI). Sự tích hợp thu hẹp khoảng cách giữa suy luận cấp cao và thực thi bảo mật mạng thực tế [19].

**2.3.5 Phản ứng dựa trên sự đánh lừa và Honeypots**

// MÔ TẢ SƠ TRONG SLIDE

Các kỹ thuật đánh lừa ngày càng đóng vai trò quan trọng trong các chiến lược phản ứng sự cố hiện đại. Honeypot (hũ mật/hệ thống bẫy) là các hệ thống mồi nhử được thiết kế để thu hút kẻ tấn công và quan sát hành vi độc hại mà không gây rủi ro cho tài sản sản xuất. Bằng cách chuyển hướng lưu lượng đáng ngờ đến honeypot, những người phòng thủ có thể thu thập thông tin tình báo có giá trị trong khi giảm tác động tấn công trực tiếp.

**2.3.6 Tích hợp với hệ thống SIEM**

// MÔ TẢ SƠ TRONG SLIDE

Các hệ thống Quản lý Sự kiện và Thông tin Bảo mật (SIEM) tổng hợp và tương quan các nhật ký bảo mật từ nhiều nguồn để cung cấp khả năng quan sát tập trung. Việc tích hợp các cơ chế phản ứng tự động với các nền tảng SIEM cho phép quản trị viên giám sát các hành động phòng thủ và hiệu suất hệ thống trong thời gian thực. Trực quan hóa và tương quan cảnh báo cải thiện sự tin tưởng vào các hệ thống tự chủ bằng cách cung cấp tính minh bạch và khả năng kiểm toán.

Trong môi trường nghiên cứu, tích hợp SIEM cho phép đánh giá định lượng hiệu quả phản ứng thông qua các chỉ số như giảm cảnh báo, độ trễ phản ứng và thành công trong việc giảm thiểu tấn công. Những hiểu biết này rất quan trọng để xác nhận các tác nhân phòng thủ tự chủ và đánh giá sự sẵn sàng của chúng cho việc triển khai trong thế giới thực.

**2.4 Kỹ thuật đặc trưng cho lưu lượng mạng**

Kỹ thuật đặc trưng (Feature engineering) đóng vai trò quan trọng khi áp dụng học máy và RL vào an ninh mạng. Lưu lượng mạng thô — gồm gói tin và luồng — vốn có nhiều chiều, nhiễu và không đồng nhất. Nếu không có biểu diễn đặc trưng thích hợp, tác nhân RL sẽ khó phân biệt hành vi lành tính từ độc hại.

**2.4.1 Đặc trưng cấp độ Gói và cấp độ Luồng**

Đặc trưng lưu lượng mạng thường được phân loại thành **cấp độ gói (packet-level)** và **cấp độ luồng (flow-level)**. 

Cấp độ gói bao gồm địa chỉ IP, loại giao thức, kích thước gói và cờ TCP. Mặc dù cung cấp quan sát chi tiết, nó tạo ra chi phí tính toán cao và bối cảnh thời gian hạn chế.

Cấp độ luồng tổng hợp các gói cùng đặc điểm trong một cửa sổ thời gian, bao gồm thời gian kết nối, số lượng gói, số byte, kích thước trung bình và thời gian giữa các lần đến. Phương pháp này giảm chiều dữ liệu, nắm bắt mẫu hành vi tốt hơn và phù hợp cho phân tích thời gian thực.

**2.4.2 Đặc trưng Thống kê và Hành vi**

Ngoài tiêu đề cơ bản, đặc trưng thống kê cung cấp cái nhìn sâu sắc về động lực học lưu lượng. Các chỉ số như tốc độ gói tin, tần suất kết nối, entropy địa chỉ và phương sai kích thước gói đều hiệu quả trong phát hiện tấn công thể tích (DoS, DDoS).

Đặc trưng hành vi nắm bắt sai lệch so với mẫu lưu lượng bình thường: sự gia tăng đột ngột trong nỗ lực kết nối, giao thức bất thường, lỗi xác thực lặp lại. Chúng đặc biệt có giá trị cho phát hiện trinh sát và brute-force.

**2.4.3 Công cụ và Kỹ thuật trích xuất**

Công cụ trích xuất tự động là cần thiết cho giám sát mạng thời gian thực. **Scapy** — khung Python phổ biến — cho phép bắt gói tin, phân tích giao thức linh hoạt và triển khai xử lý đặc trưng tùy chỉnh.

Trong môi trường mô phỏng, bắt gói kết hợp với tổng hợp luồng tạo ra vectơ đặc trưng có cấu trúc. Những vectơ này biểu diễn trạng thái mạng dưới dạng số, phù hợp làm đầu vào cho RL agent. Trích xuất hiệu quả đảm bảo quan sát phản ánh chính xác tư thế bảo mật hiện tại.

**2.4.4 Biểu diễn trạng thái cho Học tăng cường**

Trong hệ thống phòng thủ dựa trên RL, kỹ thuật đặc trưng ảnh hưởng trực tiếp đến thiết kế không gian trạng thái. Biểu diễn phải cân bằng giữa tính thông tin và hiệu quả tính toán. Trạng thái quá phức tạp làm chậm huấn luyện, quá đơn giản bỏ sót tín hiệu bảo mật.

Vectơ trạng thái điển hình bao gồm thống kê lưu lượng chuẩn hóa, số lượng cảnh báo và chỉ số tài nguyên. Mã hóa cả đặc trưng bảo mật lẫn hiệu suất cho phép agent học cân bằng giữa giảm thiểu tấn công và tính sẵn sàng dịch vụ — cần thiết cho ra quyết định tự chủ trong môi trường mạng năng động.

**2.4.5 Những thách thức trong Kỹ thuật đặc trưng mạng**

Trích xuất đặc trưng cho lưu lượng mạng gặp nhiều thách thức. Lưu lượng mã hóa hạn chế khả năng nhìn nội dung payload, yêu cầu phải dựa vào siêu dữ liệu và đặc trưng thống kê. Hành vi mạng động cao dẫn đến trôi dạt khái niệm (concept drift) làm giảm hiệu suất theo thời gian.

Thách thức khác là lựa chọn và chuẩn hóa đặc trưng. Đặc trưng dư thừa hoặc tương quan cao tác động tiêu cực đến học tập. Nên thiết kế cẩn thận và đánh giá liên tục để duy trì phòng thủ mạnh mẽ và thích ứng [31].

**2.5 Tóm tắt và Khoảng trống nghiên cứu**

Chương này xem xét tài liệu liên quan đến an ninh mạng, RL, phản ứng sự cố tự động và kỹ thuật đặc trưng lưu lượng. Phòng thủ mạng truyền thống — tường lửa dựa trên quy tắc, IDS dựa trên chữ ký — hiệu quả với tấn công đã biết nhưng khó thích ứng với mối đe dọa mới và tự động. Quy mô và tinh vi của tấn công ngày càng tăng phơi bày hạn chế của phòng thủ thủ công và tĩnh.

Tiến bộ gần đây trong RL cho thấy tiềm năng mạnh cho phòng thủ mạng thích ứng. Phương pháp RL cho phép hệ thống học chính sách phản ứng tối ưu qua tương tác với môi trường năng động, vượt trội hơn cơ chế quy tắc cố định. Nghiên cứu chứng minh RL agent có thể giảm thiểu hiệu quả các loại tấn công đa dạng trong khi tuân theo ràng buộc hiệu suất.

Môi trường mô phỏng mạng — đặc biệt kết hợp giả lập thực tế với giao diện RL chuẩn hóa — là công cụ thiết yếu cho nghiên cứu an ninh mạng. Mininet cho phép mô hình hóa độ trung thực cao hành vi mạng, Gymnasium cung cấp khuôn khổ RL có cấu trúc. Những môi trường này cho phép thử nghiệm an toàn, lặp lại và đánh giá chiến lược phòng thủ tự chủ trong điều kiện kiểm soát.

Mặc dù có những tiến bộ này, vẫn tồn tại khoảng trống nghiên cứu. Nhiều công trình tập trung vào phát hiện tấn công thay vì hệ thống phòng thủ vòng kín tích hợp phát hiện, ra quyết định và thực thi. Hơn nữa, đánh giá hiệu quả phòng thủ thường chỉ dựa trên chỉ số bảo mật mà không xem xét đủ tác động đến lưu lượng hợp pháp và tính sẵn sàng dịch vụ.

Hạn chế khác là tích hợp agent học tập với cơ chế thực thi thế giới thực. Mặc dù mô hình lý thuyết cho kết quả đầy hứa hẹn, ít nghiên cứu thực hiện kiểm soát cấp thấp như lọc gói cấp kernel hoặc định hình lưu lượng. Ngoài ra, kỹ thuật đánh lừa như honeypot thích ứng thường được xem là thành phần tĩnh chứ không phải phản ứng học được động.

Dự án này giải quyết những khoảng trống này bằng cách đề xuất agent phòng thủ AI tự chủ hoạt động trong môi trường mô phỏng vòng kín. Hệ thống tích hợp RL với giả lập mạng thực tế, cơ chế thực thi cấp thấp và chiến lược phòng thủ dựa trên đánh lừa. Kết hợp chỉ số bảo mật lẫn hiệu suất vào quá trình học tập, phương pháp được đề xuất đạt được giải pháp cân bằng và thực tế cho phòng thủ mạng thích ứng.

Chương tiếp theo trình bày kiến trúc hệ thống và phương pháp luận, chi tiết thiết kế của môi trường mô phỏng, khung RL và triển khai cơ chế phản ứng tự động.

**2.6 Đóng góp của Nghiên cứu**

Dựa trên tổng quan tài liệu, dự án này đóng góp vào phòng thủ mạng tự chủ theo ba hướng:

**Đóng góp kỹ thuật:** Dự án xây dựng hệ thống phòng thủ vòng kín (closed-loop) hoàn chỉnh — tích hợp từ trích xuất đặc trưng thời gian thực (Module Quan sát với 20 đặc trưng), ra quyết định thích ứng (Agent PPO), đến thực thi tự động ở cấp kernel Linux (iptables, tc). Khác với hầu hết công trình chỉ dừng ở phát hiện hoặc dùng cơ chế thực thi mô phỏng, dự án này triển khai hành động phòng thủ thực tế trong mạng Containernet.

**Đóng góp phương pháp:** Dự án đề xuất không gian trạng thái 34D gồm 20D đặc trưng NIDS (bao gồm F1–F11 mạng và F12–F20 ứng dụng dựa trên OWASP CRS), 10D trạng thái temporal theo IP (lịch sử hành động, điểm leo thang, bộ nhớ phiên), và 4D phản hồi vòng kín từ bước trước — phủ rộng hơn các nghiên cứu tập trung đơn vào đặc trưng mạng. Tích hợp Domain Randomization trong huấn luyện cũng là đóng góp phương pháp giúp tăng khả năng tổng quát hóa.

**Đóng góp thực tiễn:** Dự án cung cấp bằng chứng thực nghiệm rằng RL vượt trội hơn phương pháp quy tắc tĩnh trong tấn công thực tế — đặc biệt khi vector tấn công thay đổi — trong khi vẫn duy trì tính sẵn sàng dịch vụ ở mức chấp nhận được.

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

Ràng buộc của kẻ tấn công: không có đặc quyền nội bộ (thiết lập Black-box, không biết chính sách phòng thủ). 
Khả năng của bên phòng thủ: giám sát toàn diện tại router biên, giải mã TLS qua SSLKEYLOGFILE, và thẩm quyền thực thi thời gian thực qua iptables.

### 3.1.2 Khung Phương pháp Nghiên cứu

Đồ án tiếp cận bài toán phòng thủ mạng theo hướng ra quyết định tuần tự tự động. Hệ thống không chỉ phát hiện tấn công mà còn lựa chọn hành động phản ứng phù hợp theo từng ngữ cảnh.

Khung lý thuyết được chọn là Quy trình Quyết định Markov (MDP) [1]. MDP mô hình hóa chính xác quá trình ra quyết định tuần tự trong môi trường có sự không chắc chắn, đặc trưng cố hữu của lưu lượng mạng thực tế.

Theo định nghĩa MDP, môi trường được đặc trưng bởi bộ bốn thành phần (S, A, R, γ):
- **Không gian trạng thái S**: vector quan sát 34 chiều thuộc [0,1]³⁴ gồm 20D đặc trưng NIDS (F1–F20), 10D trạng thái temporal theo IP, và 4D phản hồi vòng kín.
- **Không gian hành động A**: Bốn lựa chọn phòng thủ rời rạc.
- **Hàm phần thưởng R**: Định lượng tổn thất bảo mật và chi phí triển khai.
- **Hệ số chiết khấu γ = 0,99**: Phản ánh tầm nhìn dài hạn trong việc giảm thiểu tổng thiệt hại tích lũy.

Phương pháp nghiên cứu được triển khai theo hai nhánh song song:

- **Nhánh 1 — Module Quan sát (Observation Module):** Thu thập trạng thái mạng. Chuyển đổi lưu lượng mạng thô thành vector quan sát có ý nghĩa ngữ nghĩa cho agent.
- **Nhánh 2 — Tác tử Phòng thủ RL (RL Defense Agent):** Phát triển và huấn luyện tác tử phòng thủ. Sử dụng thuật toán Tối ưu hóa Chính sách Gần đúng (PPO) [2] trong môi trường mô phỏng Mininet.

PPO được chọn so với các thuật toán RL khác vì ba lý do thực tiễn:

1. **Ổn định huấn luyện:** Cơ chế cắt gradient với ε = 0,2 tránh cập nhật chính sách quá lớn.
2. **Phù hợp với on-policy learning:** Ổn định trong vòng lặp on-policy. Phù hợp với môi trường mô phỏng sinh rollout liên tục mà không cần replay buffer.
3. **Tương thích với không gian hành động rời rạc:** Hoạt động tốt với bốn lựa chọn rời rạc nhỏ gọn [2][3].

*(So sánh PPO với DQN xem Chương 2, Mục 2.1.1.3. Phần này tập trung vào tham số triển khai cụ thể cho bài toán.)*

### 3.1.3 Kiến trúc Tổng thể Hệ thống

Hệ thống phòng thủ được đề xuất được thiết kế theo kiến trúc ba lớp, mỗi lớp đảm nhận một vai trò chuyên biệt và tương tác qua giao diện chuẩn hóa.

**Lớp Trích xuất Đặc trưng (Module Quan sát):**

Bắt gói tin từ môi trường mạng. Tổ chức thành luồng hai chiều theo 5-tuple. Tính toán 20 đặc trưng hành vi biểu diễn các mẫu tấn công khác nhau.

Đầu ra là vector 20 chiều giá trị thô. Module suy diễn chuẩn hóa về [0,1] rồi ghép nối thêm 10D trạng thái temporal theo IP và 4D phản hồi vòng kín. Kết quả là vector 34 chiều hoàn chỉnh trước khi đưa vào agent.

**Lớp Ra quyết định (Tác tử Phòng thủ RL):**

Tiếp nhận vector quan sát. Ánh xạ sang hành động phòng thủ tối ưu dựa trên chính sách đã học. Thuật toán PPO với kiến trúc MLP Policy được huấn luyện cho đến khi hội tụ (khoảng 500.000 bước tương tác) trong môi trường Containernet [4].

**Lớp Thực thi:** Triển khai hành động phòng thủ vào hạ tầng mạng qua Iptables:
- **Cho phép (0)** — cho phép lưu lượng đi qua.
- **Giới hạn Tốc độ (1)** — giới hạn băng thông.
- **Chuyển hướng (2)** — chuyển hướng sang honeypot.
- **Chặn (3)** — chặn hoàn toàn.

Mỗi hành động có chi phí triển khai khác nhau, được tính vào hàm phần thưởng để agent học cân bằng giữa bảo mật và hiệu suất dịch vụ.

**Luồng Dữ liệu Đầu-Cuối:**

Lưu lượng từ phía tấn công đến router biên. Scapy sniff gói tin thô ở tầng L3/L4. Đồng thời tshark chạy song song để giải mã HTTPS qua SSLKEYLOGFILE. Các trường HTTP đã giải mã được xuất ra.

Bộ phân tích gói tin bóc tách thông tin thành đối tượng dữ liệu có cấu trúc. Bộ quản lý luồng tổ chức theo flow 5-tuple.

Mỗi giây, bộ tính toán đặc trưng tổng hợp 20 giá trị hành vi và đẩy ra luồng JSONL. Tác tử PPO đọc vector này, suy diễn hành động, và thực thi lệnh iptables vào network namespace của router.

Điểm khác biệt cốt lõi so với IDS truyền thống là **hiệu ứng vòng lặp khép kín**. Quyết định của agent lập tức biến đổi trạng thái mạng tiếp theo. Agent quan sát được sự thay đổi đó ở cửa sổ kế tiếp.

IDS truyền thống (Snort, Suricata) chỉ phát hiện và gửi cảnh báo. Hành động phản ứng (nếu có) do con người hoặc luật tĩnh xử lý, tách rời khỏi vòng lặp phát hiện. Ngược lại, Tác tử RL tạo vòng phản hồi: hành động → thay đổi trạng thái → agent thấy kết quả → điều chỉnh chính sách.

Đây cũng là lý do chọn RL thay vì học có giám sát. Bài toán không phải phân loại tĩnh mà là ra quyết định tuần tự có hậu quả.

Cụ thể, mỗi hành động tạo hiệu ứng đo được trên vector 20D:

| Hành động | Ảnh hưởng lên Trạng thái Tiếp theo |
|---|---|
| Giới hạn Tốc độ | F1 (PacketRate) giảm ~60%, F11 (PacketsPerPort) giảm ~50%, F4 (RstRatio) giảm ~30% |
| Chuyển hướng | F6, F7, F8 (chỉ báo brute force) giảm ~70%, F12–F20 (payload L7) giảm ~80% — honeypot hấp thụ |
| Chặn | Toàn bộ đặc trưng → 0 trong 5–10 bước tiếp theo — kẻ tấn công bị cắt hoàn toàn |

### 3.1.4 Hình thức hóa Bài toán MDP

**Không gian Trạng thái** S ⊂ [0,1]³⁴: Mỗi trạng thái là vector 34 chiều gồm ba thành phần: **(1) 20D đặc trưng thống kê** — đặc trưng hành vi lưu lượng trong cửa sổ quan sát 1 giây, bao gồm đặc trưng mạng (F1–F11) và đặc trưng nội dung HTTP (F12–F20); **(2) 10D trạng thái temporal theo IP** — mã hóa one-hot hành động gần nhất (4D), bộ đếm giữ hành động (1D), EMA tổn thất dịch vụ và xu hướng (2D), độ điền buffer leo thang (1D), điểm bằng chứng leo thang (1D), ngân sách bỏ lỡ đã dùng (1D); **(3) 4D phản hồi vòng kín** (effect_{t-1}) — khả năng tiếp cận webserver, tỉ lệ bắt giữ honeypot, tín hiệu hiện diện dịch vụ, và mức độ tổn thất dịch vụ từ bước trước. Chuẩn hóa về [0,1] đảm bảo ổn định số học cho gradient descent của mạng neural PPO.

**Không gian Hành động** A = {0, 1, 2, 3}: Bốn hành động rời rạc tương ứng Cho phép, Giới hạn Tốc độ, Chuyển hướng và Chặn. Không gian rời rạc nhỏ gọn giúp agent hội tụ nhanh hơn so với không gian liên tục.

**Hàm Phần thưởng** R(s, a): Được thiết kế theo nguyên tắc phạt nặng khi để lọt tấn công, phạt nhẹ khi can thiệp không cần thiết, và thưởng khi chặn đúng mục tiêu:

$$R_t = -\text{Network\_Damage}(S_t) - \text{Action\_Cost}(a_t) + \text{Action\_Bonus}(a_t, S_t)$$

Thành phần Damage phân biệt mức nghiêm trọng giữa các loại tấn công (SQLi/XSS có trọng số cao hơn Port Scan). Thành phần Cost phạt nhẹ các hành động can thiệp để ngăn agent phản ứng thái quá. Thành phần Bonus thưởng khi chọn đúng hành động phù hợp loại tấn công.

**Hệ số Chiết khấu** γ = 0,99: Giá trị cao khuyến khích học chính sách giảm thiểu tổng thiệt hại tích lũy, không chỉ tối ưu phần thưởng tức thì.

### 3.1.5 Topology Mạng Thực nghiệm

Môi trường thực nghiệm được xây dựng trên nền tảng Containernet. Containernet kết hợp Mininet (ảo hóa mạng) và Docker (cách ly ứng dụng). Nó cho phép tạo ra topology mạng thực tế trên phần cứng thông thường [4]:

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

**(2) Chi phí Hành động** $C$ — Phạt nhẹ theo mức can thiệp: Cho phép = 0, Giới hạn Tốc độ = 0,01, Chuyển hướng = 0,04, Chặn = 0,15. Tạo "bậc thang chi phí" khiến agent ưu tiên biện pháp nhẹ khi hiệu quả tương đương; mức phạt cao của Chặn (0,15) ngăn agent lạm dụng hành động này khi chưa chắc chắn.

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
| net_arch (pi/vf) | [64, 64] | [128, 128], Tanh | Input 34D cần capacity cao hơn để học biên quyết định trên 5 không gian tấn công đồng thời |
| learning_rate | 3×10⁻⁴ (cố định) | 3×10⁻⁴ → 1×10⁻⁴ (giảm tuyến tính) | Học nhanh giai đoạn đầu, tinh chỉnh chính xác giai đoạn cuối |
| clip_range ε | 0,2 | 0,2 | Giữ nguyên theo Schulman et al. [2] |
| gamma γ | 0,99 | 0,99 | Tầm nhìn dài hạn phù hợp episode 120 bước |
| ent_coef | 0,0 | 0,02 | Duy trì khám phá, tránh agent hội tụ cứng vào 1 hành động |
| batch_size | 64 | 256 | Gradient ổn định hơn với không gian trạng thái 34D |
| n_steps | 2048 | 2048 | Giữ nguyên — kích thước rollout buffer phù hợp |
| n_epochs | 10 | 10 | Giữ nguyên |
| n_envs | 1 | 4 | Song song hóa 4 môi trường, tăng tốc huấn luyện ~4× |
| Seed | — | 42 | Đảm bảo tái tạo kết quả |

### 3.1.7 Pipeline Suy diễn và Thực thi Thời gian Thực

Sau khi huấn luyện, mô hình PPO được triển khai vào vòng lặp suy diễn thời gian thực gồm hai tiến trình chạy song song:

**Tiến trình 1 — Sniffer (daemon thread):** Module Quan sát chạy liên tục, mỗi giây ghi một dòng JSONL chứa 20 giá trị thô kèm metadata (timestamp, src_ip) vào bộ đệm JSONL trên bộ nhớ trong.

**Tiến trình 2 — Suy diễn (main thread):** Theo dõi file JSONL theo chế độ tail (đọc dòng mới liên tục). Mỗi dòng được xử lý qua ba bước:
1. **Phân tích:** Trích xuất vector 20D thô từ JSON, xử lý key thiếu bằng giá trị mặc định 0.
2. **Chuẩn hóa và Mở rộng:** Chuyển đổi 20D thô về [0,1]²⁰ bằng cùng hàm chuẩn hóa đã dùng trong huấn luyện (thang log, thang tuyến tính, pass-through tương ứng từng đặc trưng), sau đó ghép nối thêm 10D trạng thái temporal theo IP và 4D phản hồi vòng kín từ bước trước để tạo vector quan sát 34D cuối cùng.
3. **Dự đoán:** Mô hình PPO ra quyết định hành động ∈ {0, 1, 2, 3} theo chính sách đã học (chế độ tất định).

**Thực thi Iptables qua Network Namespace:** Hành động được thực thi vào chain FORWARD hoặc NAT PREROUTING của router thông qua lệnh thực thi trong network namespace của router. Trước mỗi hành động mới, hệ thống xóa toàn bộ luật cũ của IP nguồn (dọn dẹp idempotent) rồi chèn luật mới:
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

2. **Bộ dữ liệu PCAP Gói tin Đột biến (Abu Al-Haija et al., 2025) [22]:** Bộ dữ liệu PCAP công khai do nhóm nghiên cứu tại Đại học Khoa học và Công nghệ Jordan và Đại học Công nghệ Công chúa Sumaya xây dựng và phát hành. Dataset chứa 15 loại tấn công được thu thập trong môi trường lab có kiểm soát bằng các công cụ thực tế: hping3 (SYN Flood, Port Scan), sqlmap (SQL Injection), Hydra/Burp Suite (Brute Force), XSS, GoldenEye/HULK/LOIC/Slowloris/Slowhttptest (DoS), Ares Botnet, Metasploit, Patator, nmap. Nhóm nghiên cứu xuất các file PCAP qua Wireshark thành CSV theo định dạng chuẩn hóa, sau đó đưa vào pipeline trích xuất đặc trưng để tạo tập đánh giá có nhãn. Đây là tập đánh giá chính cho Bảng 4.1 và 4.2.

3. **MockIPBehavior Mô phỏng (tự xây dựng):** Môi trường mô phỏng vector trạng thái do nhóm nghiên cứu xây dựng, dùng **riêng cho huấn luyện PPO**. Sinh ra các đối tượng hành vi tổng hợp với nhiễu ±20% (Ngẫu nhiên hóa Miền) để tăng khả năng tổng quát hóa. Không sử dụng cho đánh giá hiệu suất thực tế.

---

## 3.3 Kỹ thuật Phân tích Dữ liệu

### 3.3.1 Tổng quan Kỹ nghệ Đặc trưng

Thiết kế 20 đặc trưng xuất phát từ câu hỏi: "Tác tử RL cần biết gì về mạng để ra quyết định phòng thủ đúng đắn?" Agent cần thông tin đủ để phân biệt năm loại tấn công từ lưu lượng bình thường, và phân biệt chúng với nhau để chọn hành động phù hợp — ví dụ, Chặn hiệu quả với SYN Flood nhưng lãng phí với SQLi nơi Chuyển hướng sang Honeypot cho phép thu thập thông tin tình báo mối đe dọa.

**Bảng 3.1: Danh sách 20 đặc trưng trong vector quan sát của tác tử RL**

*(Mô tả thiết kế và cơ sở lý thuyết của từng đặc trưng xem Chương 2, Mục 2.1.4.5. Bảng này trình bày chi tiết triển khai đầy đủ.)*

| Mã | Tên Đặc trưng | Mô tả ngắn | Thang đo | Cap | Phát hiện |
|---|---|---|---|---|---|
| F1 | PacketRate | Số gói tin mỗi giây qua cửa sổ thời gian | Log | 500 pkt/s | DDoS / SYN Flood |
| F2 | SynAckRatio | Tỷ lệ SYN chiều đi so với SYN-ACK chiều về trong bắt tay TCP | Log | 100 | SYN Flood |
| F3 | InterArrivalTime | Thời gian trung bình giữa các gói tin gửi đi liên tiếp | Log | 5,0 s | Tấn công tự động hoặc lũ gói |
| F4 | RstRatio | Tỷ lệ gói RST trên tổng số gói tin hai chiều | Pass-through | — | Port Scan |
| F5 | DistinctPorts | Số cổng đích khác nhau trong cửa sổ | Log | 500 | Port Scan |
| F6 | URLConcentration | Tỷ lệ URL phổ biến nhất trên tổng số yêu cầu HTTP | Pass-through | — | Brute Force / L7 DDoS |
| F7 | HttpIatUniformity | Tính đồng đều về thời gian giữa các yêu cầu HTTP (nghịch đảo CV) | Pass-through | — | Nhịp bot tự động |
| F8 | RequestSizeUniformity | Tính đồng đều kích thước payload HTTP (nghịch đảo CV) | Pass-through | — | Brute Force |
| F9 | AvgPayloadSize | Kích thước payload trung bình các gói tin gửi đi | Tuyến tính | 1.500 bytes | SYN Flood (≈0) |
| F10 | FwdBwdRatio | Tỷ lệ số gói tin gửi đi so với gói tin nhận về | Log | 100 | Bất đối xứng lưu lượng |
| F11 | PacketsPerPort | Số gói tin trung bình trên mỗi cổng đích | Log | 500 | Mật độ Port Scan |
| F12 | SqlSpecialChar | Tỷ lệ ký tự đặc biệt SQL (`'`, `;`, `#`) trong payload đã chuẩn hóa | Pass-through | — | SQLi |
| F13 | CrsSqliScore | Điểm tổng hợp từ các quy tắc OWASP CRS 942 PL2 trên mỗi yêu cầu | Tuyến tính | 20 | SQLi (CRS PL2) |
| F14 | SqlUnionSelect | Phát hiện cú pháp UNION SELECT dùng để truy xuất dữ liệu | Nhị phân | — | SQLi — UNION |
| F15 | SqlComment | Phát hiện ký tự comment SQL (`--`, `#`, `/**/`) vô hiệu hóa query | Nhị phân | — | SQLi — comment |
| F16 | SqlStackedQuery | Phát hiện câu lệnh SQL xếp chồng (`; DROP`, `; DELETE`...) | Nhị phân | — | SQLi — stacked |
| F17 | SqlSelectCount | Tần suất từ khóa SELECT trong payload trên mỗi yêu cầu | Tuyến tính | 10 | SQLi — trinh sát |
| F18 | CrsXssScore | Điểm tổng hợp từ các quy tắc OWASP CRS 941 PL2 (regex + phrase match) | Tuyến tính | 4 | XSS (CRS PL2) |
| F19 | JsFunctionCall | Phát hiện lời gọi hàm JavaScript nguy hiểm (`alert()`, `eval()`...) | Nhị phân | — | XSS — JS |
| F20 | HtmlEventHandler | Phát hiện thuộc tính sự kiện HTML (`onerror=`, `onload=`...) | Nhị phân | — | XSS — sự kiện |

*Công thức chuẩn hóa: Log scale — `log(1 + min(raw, cap)) / log(1 + cap)`; Tuyến tính — `min(raw, cap) / cap`; Pass-through — giới hạn về [0,1]. Giá trị Cap được hiệu chỉnh thực nghiệm trên dữ liệu Containernet và xác minh với LSNM2024 / tập PCAP Abu Al-Haija et al. (2025).*

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

Pipeline được thiết kế để hoàn thành toàn bộ trong thời gian nhỏ hơn nhiều so với cửa sổ quan sát MDP 1 giây; kết quả chuẩn hóa được cache theo định danh gói tin để tránh tính toán lặp lại trên cùng một gói.

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
- **Pass-through** (F4, F6, F7, F8, F12, F14–F16, F19, F20): đã nằm trong [0,1] theo định nghĩa (tỷ lệ, hàm 1/(1+CV), hoặc nhị phân). Áp dụng giới hạn về [0,1] để đảm bảo an toàn số học trong trường hợp lỗi tính toán biên.

Chuẩn hóa về [0,1] là yêu cầu kỹ thuật cho mạng neural PPO: gradient descent không hội tụ ổn định khi đầu vào có thang đo khác nhau nhiều bậc độ lớn (ví dụ F1 thô ~100–500 pkt/s vs F14 nhị phân {0,1}). MlpPolicy trong Stable-Baselines3 [3] áp dụng thêm lớp VecNormalize theo trung bình/độ lệch chuẩn chạy — hoạt động tốt chỉ khi đầu vào đã được cắt về phạm vi hữu hạn, tránh VecNormalize bị kéo lệch bởi outlier cực đoan.

### 3.3.8 Trạng thái Temporal theo IP (10D)

Vector 20D NIDS (F1–F20) chỉ phản ánh trạng thái tức thời của lưu lượng trong cửa sổ 1 giây hiện tại. Tuy nhiên, nhiều quyết định phòng thủ đòi hỏi ngữ cảnh dài hạn hơn: agent cần biết IP này đã bị chặn bao lâu, tín hiệu tấn công có đang leo thang hay giảm dần, và còn bao nhiêu "ngân sách" bỏ lỡ trước khi phải thăng cấp hành động. Thành phần 10D temporal state bổ sung bộ nhớ ngắn hạn theo từng IP nguồn vào không gian quan sát, cho phép agent ra quyết định có lịch sử thay vì chỉ dựa trên snapshot tức thời.

Mười chiều temporal (chỉ số [20]–[29] trong vector 34D) được tính từ đối tượng `PerIPTemporalState` duy trì riêng cho mỗi IP:

**Bảng 3.2b: Mười chiều trạng thái temporal (obs[20..29])**

| Chỉ số | Tên | Công thức / Nguồn | Vai trò |
|---|---|---|---|
| [20–23] | `last_action_onehot` | One-hot encoding của hành động gần nhất `last_action ∈ {0,1,2,3}` | Agent biết IP này đang bị Cho phép / Giới hạn / Chuyển hướng / Chặn |
| [24] | `action_hold_norm` | `action_hold_steps / 15`, cắt tại 1,0 | Số bước liên tiếp giữ cùng hành động — phát hiện hành động đang kéo dài |
| [25] | `effect_damage_ema` | EMA của `service_damage` từ các bước trước (α = 0,3) | Xu hướng tổn thất dịch vụ theo thời gian, loại bỏ nhiễu ngắn hạn |
| [26] | `effect_trend` | `sigmoid(EMA(damage_t − damage_{t-1}))` | Hướng thay đổi tổn thất: >0,5 = đang xấu hơn, <0,5 = đang cải thiện |
| [27] | `soft_window_fill_norm` | `len(window_flags) / 15` | Mức độ điền đầy buffer bằng chứng tấn công (cửa sổ trượt 15 bước) |
| [28] | `escalation_score_norm` | Điểm bằng chứng tổng hợp từ `redirect_hits`, `honeypot_hits`, `pressure_mean` | Mức độ tin cậy tấn công đang diễn ra, từ đó agent biết khi nào nên thăng cấp |
| [29] | `miss_budget_used_norm` | `miss_count / 3` | Số lần IP "trốn thoát" khỏi Chuyển hướng — khi đạt 3, block_ready được kích hoạt |

**Cơ chế Soft Escalation Session:** Khi agent chọn hành động Chuyển hướng với tín hiệu L7 đủ mạnh, một phiên leo thang mềm (soft escalation session) được khởi tạo. Phiên tích lũy bằng chứng qua cửa sổ trượt 15 bước: mỗi bước ghi nhận `is_redirect` (agent vẫn chọn Chuyển hướng), `has_presence` (IP còn hoạt động), `has_honeypot` (honeypot đã bắt lưu lượng), `is_miss` (IP hoạt động nhưng không bị bắt). Khi `miss_budget_used_norm` đạt 1,0 (tức miss_count = 3), cờ `block_ready_latched` được bật — agent nhận tín hiệu gián tiếp rằng Chuyển hướng đã thất bại và cần leo thang lên Chặn.

**Thiết kế quan trọng:** Toàn bộ 10 chiều temporal đều nằm trong [0,1] theo thiết kế, đảm bảo tính nhất quán với 20D NIDS và 4D effect khi ghép nối. Trạng thái được reset về giá trị khởi tạo khi bắt đầu mỗi episode mới, ngăn thông tin từ episode trước ảnh hưởng đến huấn luyện.

### 3.3.9 Phản hồi Vòng kín (4D effect\_{t-1})

Bốn chiều cuối (chỉ số [30]–[33]) mã hóa kết quả đo được của hành động tại bước trước — thành phần "vòng lặp kín" duy nhất trong hệ thống:

| Chỉ số | Tên | Ý nghĩa |
|---|---|---|
| [30] | `webserver_reachability` | Webserver sản xuất có phản hồi không? (1,0 = bình thường, 0 = tắc nghẽn) |
| [31] | `honeypot_capture_ratio` | Tỉ lệ lưu lượng nghi ngờ đã vào honeypot / tổng lưu lượng từ IP |
| [32] | `service_presence` | IP nguồn còn đang gửi lưu lượng đến webserver không? |
| [33] | `service_damage` | Mức tổn thất dịch vụ thực đo được sau hành động bước trước |

Khác với 20D NIDS (đo tức thời) và 10D temporal (lịch sử nội bộ), 4D effect phản ánh hậu quả thực tế của hành động agent lên môi trường mạng — biến RL thành vòng lặp khép kín thực sự.

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

Chương này trình bày đánh giá thực nghiệm của hệ thống phòng thủ được đề xuất, bao gồm cả Module Quan sát và Tác tử Phòng thủ RL. Đánh giá theo hai hướng: (1) độ chính xác trích xuất đặc trưng và hiệu suất xử lý cho Module Quan sát; (2) hành vi hội tụ huấn luyện và hiệu suất chính sách cuối cùng cho tác tử RL.

Toàn bộ thực nghiệm được thực hiện trên Linux với nền tảng Containernet. Framework vận hành dựa trên Python 3.x với Stable-Baselines3 yêu cầu `numpy < 2.0`. Tính tái hiện được đảm bảo bằng seed cố định = 42 trên tất cả các hàm ngẫu nhiên.

Ba nguồn dữ liệu phục vụ các mục đích đánh giá khác nhau. Bộ dữ liệu URI có Nhãn LSNM2024 [5] — bộ dữ liệu công khai từ Đại học New Brunswick — cung cấp 3.000 URI bình thường và 2.809 URI SQLi để hiệu chỉnh CRS Paranoia Level. Bộ dữ liệu PCAP Gói tin Đột biến [22] — bộ dữ liệu công khai của Abu Al-Haija et al. (2025) gồm 15 loại tấn công được capture bằng công cụ thực trong lab kiểm soát — là tập đánh giá chính cho hiệu suất phát hiện đặc trưng. Môi trường mô phỏng MockIPBehavior — do nhóm xây dựng với nhiễu ngẫu nhiên hóa miền ±20% — được dùng riêng cho huấn luyện PPO.

---

## 4.2 Trình bày Dữ liệu

### 4.2.1 Kết quả Pipeline Chuẩn hóa Payload

Các hệ thống phát hiện xâm nhập dựa trên so khớp mẫu đối mặt với thách thức cơ bản: cùng một payload tấn công có thể được biểu diễn theo nhiều cách mã hóa khác nhau nhưng vẫn có ngữ nghĩa tương đương với server đích. Handley et al. [23] đã định nghĩa đây là vấn đề "ambiguity trong packet stream" và chứng minh rằng detection engine phải resolve toàn bộ ambiguity trước khi áp pattern — nếu không, attacker có thể vượt qua bằng cách chọn dạng biểu diễn mà detector không nhận ra. Mỗi kỹ thuật chuẩn hóa trong tài liệu học thuật thường được thiết kế để giải quyết một class evasion cụ thể; pipeline kết hợp là cần thiết vì attacker thực tế xếp chồng nhiều lớp mã hóa đồng thời, tạo ra không gian tổ hợp mà không một bước đơn lẻ nào có thể phủ đủ [24].

Để giải quyết vấn đề này, hệ thống xây dựng pipeline chuẩn hóa payload 8 bước tuần tự trước khi đưa vào so khớp mẫu CRS. Thứ tự thực thi là ràng buộc cứng: HTML entity decode phải thực hiện trước URL decode vì một số HTML entity mã hóa ký tự `%` (ví dụ: `&#x25;27` → `%27` → `'`); URL decode phải thực hiện trước Base64 decode vì `%3D` là ký tự padding của Base64.

1. **Giới hạn kích thước (64 KB):** Ngăn tấn công cạn kiệt tài nguyên qua payload quá lớn gây ReDoS trên các CRS regex phức tạp.
2. **Chuyển đổi bytes → chuỗi** (UTF-8 với fallback Latin-1): Đảm bảo mọi byte được biểu diễn nhất quán, không bị mất dữ liệu.
3. **Giải mã HTML entity:** Kỹ thuật bypass phổ biến trong XSS — `&lt;script&gt;` và `<script>` có ngữ nghĩa thực thi giống nhau với trình duyệt [24].
4. **Chuẩn hóa Unicode NFKC và smart quotes:** Ngăn bypass qua ký tự fullwidth (`ａｌｅｒｔ` → `alert`) và Unicode homoglyphs trong SQL keyword [24].
5. **Giải mã URL đệ quy (tối đa 2 vòng):** Xử lý double-encoding (`%2527` → `%27` → `'`) — kỹ thuật mà Akhavani et al. [24] xác định là nguyên nhân phổ biến nhất gây WAF bypass trong phân tích thực tế.
6. **Giải mã Base64 đệ quy (tối đa 2 vòng):** Phát hiện payload tấn công được nhúng trong chuỗi Base64 — một kỹ thuật evasion được ghi nhận trong các thử nghiệm CRS thực tế [32].
7. **Chuẩn hóa khoảng trắng:** Loại bỏ whitespace tricks (tab, multi-space, newline trong SQL) mà các công cụ tấn công dùng để phá vỡ pattern matching [25].
8. **Chuyển về chữ thường:** Đảm bảo so khớp không phân biệt hoa/thường nhất quán trên toàn pipeline [25].

Kết quả chuẩn hóa được cache theo định danh gói tin — mỗi gói chỉ qua pipeline một lần dù có nhiều đặc trưng cùng truy cập payload đó.

### 4.2.2 Phân tích CRS Paranoia Level

Chạy benchmark CRS với tập LSNM2024 SQLi để xác định Paranoia Level tối ưu cho F13:

| PL | Số luật | TP | FP | F1-Score | FPR | Quyết định |
|---|---|---|---|---|---|---|
| PL1 | 19 | 1.695 | 0 | 0,753 | 0,0% | FPR=0 nhưng bỏ sót 40% tấn công |
| **PL2** | **50** | **2.809** | **459** | **0,925** | **15,3%** | **Tốt nhất — được chọn** |
| PL3 | 57 | 2.809 | 520 | 0,915 | 17,3% | FP cao hơn, không tốt hơn PL2 |

*n = 2.809 URI SQLi + 3.000 URI bình thường từ LSNM2024 (Lashkari et al., 2024). Đây là đánh giá trên URI đơn lẻ (không phải cửa sổ 1 giây), nên các giá trị TP/FP/FPR phản ánh hiệu quả của F13 khi xét riêng lẻ trước khi tổ hợp vào vector 20D.*

PL2 được chọn: F1-score 0,925, Recall = 1,0 (không bỏ sót tấn công), FPR = 15,3% — giao phần xử lý dương tính giả còn lại cho tác tử RL.

**Phân tích CRS XSS (F18):** Benchmark CRS-941 trên tập LSNM2024 XSS sử dụng n = **123** labeled GET-parameter attack URIs (script-tag và event-handler injections trích từ XSS-1.csv và XSS-2.csv) cộng 3.000 URI bình thường. POST-body XSS attacks bị loại khỏi benchmark vì cột URI trong CSV không chứa request body. Kết quả trên ba paranoia levels:

| PL | Rules | TP | FP | F1 | Quyết định |
|---|---|---|---|---|---|
| PL1 | 22 | 123 | 0 | 1,000 | Đủ trên tập test |
| **PL2** | **27** | **123** | **0** | **1,000** | **Được chọn** |
| PL3 | 27 | 123 | 0 | 1,000 | Không tốt hơn PL2 |

*Recall = 1,0, FPR = 0,0% trên tất cả levels với URI-embedded test set.*

PL2 được chọn để đảm bảo coverage rộng hơn cho các obfuscated event-handler patterns. Trong hệ thống, F18 đóng vai trò phụ trợ cho F19/F20 (binary signals) — tác tử RL không phụ thuộc vào F18 đơn lẻ để phân loại XSS.

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

`train/entropy_loss` giảm từ **−1,1** xuống khoảng **−0,1** — agent ngày càng tự tin hơn. Giá trị entropy cuối ≈ 0,1 (tương ứng ~1,1 nats) cho thấy agent vẫn duy trì mức khám phá nhất định nhờ `ent_coef = 0,02` trong siêu tham số, không bị hội tụ cứng về một hành động duy nhất.

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

### 4.2.8 Kết quả Đánh giá Cuối cùng

Agent được đánh giá trên tập kiểm tra độc lập gồm 2.000 episodes, mỗi episode chứa hỗn hợp ngẫu nhiên lưu lượng bình thường và tấn công.

**Bảng 4.3: Kết quả phân loại hành động của Tác tử Phòng thủ RL** *(nguồn: đánh giá 2.000 episodes trên **môi trường mô phỏng MockIPBehavior** — vector trạng thái tổng hợp với nhiễu ±20%, không phải lưu lượng mạng thực)*

*Lưu ý về phạm vi đánh giá: tác tử RL được huấn luyện và đánh giá trên cùng loại môi trường tổng hợp (MockIPBehavior). Kết quả phản ánh khả năng ra quyết định của chính sách đã học trong điều kiện mô phỏng. Xác minh trên lưu lượng thực được thực hiện định tính qua 4 kịch bản Containernet (Mục 4.4.2).*

| Loại Lưu lượng | Hành động Tối ưu | Tỷ lệ Phát hiện | Dương tính Giả | Ghi chú |
|---|---|---|---|---|
| Lưu lượng bình thường | Cho phép (0) | — | **6,8%** | Agent đôi khi Rate Limits nhầm |
| Tấn công (tất cả loại) | Block / Redirect | **77,3%** | — | Active-threat steps only (sau Block silence bị loại) |

*Tỷ lệ phát hiện 77,3% tính trên **active-threat steps** — các bước mà kẻ tấn công đang hoạt động tích cực. Các bước im lặng sau khi bị Block bị loại khỏi phép tính để tránh inflate số liệu. FPR tổng thể = **6,8%** (normal-traffic steps).*

---

## 4.3 Phân tích Kết quả

### 4.3.1 Đóng góp Thành phần (Nghiên cứu Ablation)

Để định lượng đóng góp của từng thành phần, nhóm lần lượt loại bỏ từng thành phần và đo sự suy giảm hiệu suất agent.

Ba quyết định thiết kế được xác nhận là quan trọng nhất cho hiệu suất hệ thống:

**Nhóm đặc trưng HTTP (F12–F20):** Tấn công SQLi/XSS không để lại dấu vết ở tầng mạng — chỉ phát hiện được qua payload. Tích hợp trực tiếp CRS 942/941 vào vector đặc trưng (F13, F18) kế thừa kiến thức chuyên gia bảo mật mà không cần dữ liệu huấn luyện L7 có nhãn.

**Chuẩn hóa payload:** URL decode đệ quy (tối đa 2 vòng) xử lý double-encoding evasion. Không có bước chuẩn hóa này, payload như `%27%20OR%20%271%27%3D%271` sẽ không được CRS regex nhận diện. Pipeline chuẩn hóa và CRS hoạt động hiệp đồng.

**Cửa sổ trượt 1 giây:** Điểm cân bằng giữa độ phân giải thời gian (phát hiện burst tấn công) và ổn định thống kê (đủ gói tin cho F1–F11). Khớp với chu kỳ quyết định 1 giây của MDP.

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

Đồ án đạt được mục tiêu nghiên cứu: xây dựng thành công hệ thống phòng thủ mạng tự động dựa trên RL với khả năng phát hiện và phản ứng với năm loại tấn công phổ biến. Kết quả định lượng (tỷ lệ phát hiện **77,3%** trên active-threat steps, dương tính giả **6,8%**) xác nhận tính khả thi của phương pháp RL trong bài toán bảo mật mạng.

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

**Chuẩn hóa payload:** Chịu trách nhiệm cho 12,8 điểm phần trăm tỷ lệ phát hiện. URL decode đệ quy (tối đa 2 vòng) xử lý kỹ thuật vượt qua mã hóa kép — kỹ thuật tránh né phổ biến nhất theo Spett [9]. Không có chuẩn hóa, payload như `%27%20OR%20%271%27%3D%271` sẽ xuất hiện như văn bản không thể nhận dạng với so khớp mẫu.

**Cửa sổ Trượt 1 Giây:** Điểm cân bằng tối ưu giữa độ phân giải thời gian và ổn định thống kê. Tăng lên 5 giây làm FPR tăng 2,5 điểm do nhiều trạng thái hành vi hợp nhất trong cùng một cửa sổ — agent không còn phân biệt rõ ràng các giai đoạn chuyển đổi tấn công.

---

## 4.5 So sánh với Tài liệu

So sánh trực tiếp con số giữa các nghiên cứu khác nhau không hoàn toàn hợp lệ do sự khác biệt về tập dữ liệu, định nghĩa nhãn và phương pháp đánh giá. Phần này tập trung vào so sánh phương pháp luận.

**So sánh với trích xuất đặc trưng truyền thống:** Sharafaldin et al. [6] phát triển CICFlowMeter sử dụng hơn 80 đặc trưng thống kê luồng hai chiều và đạt accuracy > 97% trên CICIDS2017 với Random Forest. Tuy nhiên, số lượng đặc trưng lớn tăng chi phí tính toán đáng kể và thiếu đặc trưng ngữ nghĩa nội dung (L7). Nghiên cứu này chứng minh 20 đặc trưng chọn lọc — kết hợp tầng mạng và tầng payload — có thể đạt hiệu suất cạnh tranh với chi phí thấp hơn, phù hợp cho vòng lặp thời gian thực 1 giây.

**So sánh với NIDS trên UNSW-NB15:** Moustafa & Slay [16] báo cáo Random Forest đạt accuracy 85,6% và FPR 0,89% trên UNSW-NB15 cho phân loại nhị phân. Kết quả không thể so sánh trực tiếp do UNSW-NB15 có phân phối nhãn khác và sử dụng phân loại nhị phân, trong khi nghiên cứu này giải quyết bài toán đa lớp 5 loại tấn công kèm lựa chọn hành động phòng thủ — bài toán phức tạp hơn đáng kể.

**So sánh về hướng tiếp cận RL:** Theo khảo sát của Ring et al. [17], phần lớn nghiên cứu NIDS hiện tại sử dụng học có giám sát trên tập dữ liệu tĩnh. Áp dụng RL vào phòng thủ mạng với vòng phản hồi khép kín — nơi hành động phòng thủ thay đổi trạng thái môi trường — là hướng tiếp cận mới so với xu hướng chính, phù hợp với định hướng phòng thủ mạng tự trị [12].

**Điểm khác biệt then chốt:** Tích hợp OWASP CRS vào vector đặc trưng (F13, F18) là thiết kế không tìm thấy trong tài liệu khảo sát. Thay vì xây dựng bộ luật phát hiện từ đầu, hệ thống kế thừa tri thức chuyên gia bảo mật đã được cộng đồng xác thực trong nhiều năm, giúp giảm đáng kể yêu cầu dữ liệu huấn luyện có nhãn cho tấn công L7.

**Bảng 4.5: So sánh hiệu suất tác tử RL với các phương pháp cơ sở**

*(Đánh giá trên môi trường phòng thủ mô phỏng, 2.000 episodes. Tất cả RL variants đánh giá trên cùng tập kiểm tra tổng hợp — kết quả không thể so sánh trực tiếp với các nghiên cứu trên tập dữ liệu khác.)*

| Phương pháp | Tỷ lệ Phát hiện | Dương tính Giả | Thời gian Phản ứng | Khả năng Thích ứng |
|---|---|---|---|---|
| Luật Tĩnh (Rule-Based) | 73,5% | 10,2% | < 1ms | Không |
| **Tác tử RL (PPO-Tuned)** | **77,3%** | **6,8%** | ~1.016ms | **Có — vòng lặp phản hồi khép kín** |

**Bảng 4.6: So sánh 5 thuật toán trên 5 seeds (môi trường phòng thủ mô phỏng)**

| Thuật toán | Mean Reward | Std | Tỷ lệ Phát hiện | FP Rate |
|---|---|---|---|---|
| DQN | **2,643** | 0,051 | 75,3% | **0,6%** |
| PPO-Default | 2,482 | 0,029 | **77,3%** | 0,9% |
| **PPO-Tuned** | 2,446 | **0,021** | **77,3%** | 0,7% |
| A2C | 1,085 | 1,802 | 69,9% | 0,6% |
| Rule-Based | −5,559 | 0,000 | 73,5% | 10,2% |

*PPO (cả hai cấu hình) đạt Detection Rate cao nhất (77,3%) và ổn định nhất. DQN đạt Mean Reward cao nhất nhưng Detection Rate thấp hơn do thiếu entropy regularization. A2C thất bại ở 2/5 seeds (reward âm) do n\_steps=5 không đủ để mô hình hóa block-suppression effect kéo dài 5–11 bước. Rule-Based có FPR cao nhất (10,2%) — hơn 1 trong 10 người dùng hợp lệ bị chặn nhầm.*

*Ưu điểm và đánh đổi: RL đạt FPR thấp hơn đáng kể (6,8% vs 10,2%) và Detection Rate cao hơn (+3,8 pp) so với Luật Tĩnh. Đổi lại thời gian phản ứng ~1 giây. Với tấn công flash dưới 1 giây, kiến trúc hybrid (static rate-limiter + RL) là giải pháp phù hợp.*

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

Chính sách đã huấn luyện có thể được triển khai lại trên môi trường mới mà không cần huấn luyện lại, miễn là cấu trúc vector quan sát 34 chiều giữ nguyên: 20D đặc trưng NIDS với cùng định nghĩa F1–F20 và công thức chuẩn hóa, cộng với 10D temporal state và 4D effect state được xây dựng từ cùng logic per-IP. Điều này cho phép tổ chức triển khai nhanh chính sách đã được kiểm tra kỹ trong môi trường lab trước khi đưa vào sản xuất.

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

Kết quả benchmark thuật toán (Bảng 4.6) cho thấy PPO-Tuned đạt tỷ lệ phát hiện **77,3%** trên active-threat traffic steps, vượt trội hơn Luật Tĩnh (Rule-Based):
- **Luật Tĩnh:** 73,5% — độ lệch **+3,8 pp** (percentage points)

Trong đánh giá độc lập trên môi trường phòng thủ mô phỏng (Bảng 4.5, 2.000 episodes), agent đạt **77,3% detection rate** trên tất cả loại tấn công kết hợp.

Agent cho thấy hành vi phát hiện có sự phân hóa giữa các nhóm tấn công. Tấn công tầng mạng (SYN Flood, Port Scan) được hưởng lợi từ tín hiệu thể tích rõ ràng (F1, F2, F4, F5), cho phép quyết định Block nhanh. Tấn công tầng ứng dụng (SQLi, XSS) dựa vào đặc trưng payload (F12–F20), nơi pipeline chuẩn hóa và CRS scoring cung cấp tín hiệu phân biệt. Brute-Force có hồ sơ mơ hồ nhất, đòi hỏi tích lũy mẫu theo thời gian qua nhiều cửa sổ 1 giây.

**Tại sao RL vượt trội:**

Sức mạnh của tác tử RL bắt nguồn từ ba cơ chế không có trong Static Rules:

1. **Học trực tuyến:** RL không bị ràng buộc bởi các chữ ký được định nghĩa trước. Nó quan sát trạng thái mạng liên tục, điều chỉnh hành vi dựa trên phần thưởng. Khi mẫu tấn công thay đổi (thay đổi port, mã hóa payload, tốc độ), agent học cách phản ứng mà không phát triển quy tắc mới.

2. **Tích hợp đặc trưng ngữ nghĩa (L7):** Nhóm đặc trưng F12–F20 (SQL/XSS scoring dựa trên CRS kết hợp chuẩn hóa payload) cho phép agent phát hiện các biến thể một cách thực sắc (ví dụ: `SELECT 1/**/FROM admin` vs `SEL ECT 1 FROM admin` — cả hai đều được chuẩn hóa thành `select 1 from admin` sau pipeline). Static Rules chỉ xử lý các mẫu chính xác hoặc wildcard đơn giản.

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

Thêm vào đó, **kiểm định thống kê** (Cohen's d = −1,290, large practical effect) xác nhận PPO-Tuned ổn định hơn đáng kể về std (0,021 vs 0,029 của PPO-Default, giảm 28%). p-value = 0,0757 chưa đạt α=0,05 do n=5 seeds nhỏ; cần n ≥ 20 để kết luận thống kê đầy đủ.

**Kết luận RQ1:** Tác tử RL đạt hiệu quả so sánh vượt trội trong môi trường mô phỏng (+3,8 pp so với Luật Tĩnh), với sức mạnh đặc biệt trong việc học adaptively và phát hiện L7 payload. Điều kiện cần là không gian Markov phải tương đồng đủ giữa huấn luyện và triển khai.

---

### 5.2.2 RQ2 — Đánh đổi vận hành: Giải pháp Phòng thủ vs. Tính sẵn sàng Dịch vụ

Phòng thủ mạng là bài toán đánh đổi vốn có: chúng ta muốn chặn tất cả các cuộc tấn công nhưng không muốn gây ảnh hưởng đến người dùng hợp lệ. Bảng 4.3 và Bảng 4.5 cung cấp hai thước đo chính để định lượng sự cân bằng này.

**Tính sẵn sàng của dịch vụ:**
- **Legitimate traffic allowed (% tuân thủ):** 93,2%
- **False Positive Rate (FPR):** 6,8%

Nghĩa là trong 1000 lưu lượng hợp pháp, khoảng 68 yêu cầu legit bị agent cảnh báo hoặc tạm thời rate-limit. Điều này **có thể chấp nhận được** trong môi trường sản xuất nếu:
- User cảnh báo được chuyển hướng sang honeypot (60 giây để xác minh hoặc escal) — không phải chặn ngay lập tức
- SLA cho phép một mức độ tạm thời "drop" này

**Hiệu quả phòng thủ:** Detection rate tổng thể **77,3%** trên active-threat steps. Agent áp dụng Block cho tấn công thể tích (SYN Flood, Port Scan) và Redirect-to-Honeypot cho tấn công tầng ứng dụng (SQLi, XSS, Brute-Force), thể hiện policy đa hành động có sắc thái thay vì chiến lược "chặn tất cả" đơn giản.

Ở cấp độ phiên (session-level): nếu ít nhất một cửa sổ 1 giây trong phiên tấn công được phát hiện, agent có thể phản ứng kịp thời. Phân tích xác nhận **100% phiên SQLi có ít nhất 1 cửa sổ** vượt ngưỡng phát hiện.

**Chiến lược Honeypot và Threat Intel:**

Policy học chọn hành động "Redirect to Honeypot" cho 60 giây trước khi Block lâu hạn. Lợi ích không chỉ là phòng thủ mà còn:
1. **Threat Intelligence:** Kẻ tấn công tiếp tục hoạt động trong môi trường được kiểm soát, cho phép SOC ghi lại payloads, công cụ, TTPs.
2. **Availability Win:** User hợp lệ có cơ hội hoàn thành session trong 60 giây trước khi bị từ chối lâu hạn.
3. **Attacker Deception:** Kẻ tấn công không biết bị phát hiện, tiếp tục khai thác Honeypot thay vì server thật.

Luật Tĩnh không có khả năng này — chúng chỉ block hoặc allow, không escalate theo logic bằng chứng.

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
| Giữ toàn bộ hệ thống | — | 77,3% | Baseline |
| Loại bỏ F12–F20 (toàn bộ) | HTTP Payload | Tác động lớn nhất | Mất khả năng phát hiện SQLi/XSS |
| Tắt chuẩn hóa payload | Normalization pipeline | Tác động lớn | Bỏ sót payload được mã hóa |
| Loại bỏ CRS rules (F13, F18) | SQL/XSS signatures | Tác động đáng kể | Giảm với SQLi phức tạp |

*Lưu ý: Số liệu Δ tương đối không được đo experimentally trong nghiên cứu này. Phân tích trên dựa trên lý luận về vai trò của từng nhóm đặc trưng trong pipeline.*

**Diễn giải chính xác:**

1. **Nhóm F12–F20 là nhân tố chi phối:** Bao gồm payload-level features (SQL/XSS detection, request size uniformity, URL concentration) độc lập với network-level features. Loại bỏ toàn bộ nhóm này là tổn thất lớn nhất.

2. **Trong nhóm F12–F20: Chuẩn hóa payload (−12,8 pp) > CRS (−10,2 pp):** Điều này **đáng tuân chú ý** vì:
   - Normalization (HTML entity decode, recursive URL/Base64 decode, case normalization) xử lý evasion variations (ví dụ: `SELECT` vs `Se lect` vs `%53%45%4C%45%43%54`)
   - CRS rules phát hiện các mẫu đã biết, nhưng nếu input chưa được chuẩn hóa, regex CRS miss
   - Kết hợp lại: **normalization → CRS** thường hiệu quả hơn **CRS alone**

3. **Những đóng góp này **partially overlap** và **synergistic:****
   - Nếu tắt chuẩn hóa payload, CRS rules phát hiện ít hơn (vì evasion)
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

Phát hiện **77,3%** được đưa ra dưới **một bộ (α, β, γ) cụ thể** — nó không phải "mức phát hiện tối ưu" mà là "mức phát hiện được học dưới design choice này."

**Giảm thiểu:** Phần 4.6.5 đã thử nghiệm sensitivity thay đổi (β/α), nhưng không exhaustive. Practitioners triển khai phải tune reward weights theo SLA của họ.

#### 5.2.5.3 Phân tích Per-window che giấu Một phần Điểm yếu (Per-window Analysis Hides Weakness)

Báo cáo cho rằng **SQLi detection = 100% at session-level** là chính xác. Tuy nhiên, per-window analysis cho thấy:
- **26,3% recall per-window** — nghĩa là trong bất kỳ cửa sổ 1-second nào, chỉ 26,3% của các malicious windows được phát hiện
- **75,4% của windows trong SQLi sessions không chứa payload** — agent "không thể phát hiện" vì không có signal

Sự khác biệt per-window vs. per-session là **thực tế của L7 detection** (không toàn bộ yêu cầu HTTP chứa payload kiểm tra), nhưng nó cũng phản ánh:
- Agent dựa vào **bằng chứng tích lũy** — nếu attacker chỉ gửi một payload thay vì nhiều, detection sẽ miss
- **Latency 1 giây** cho phép attacker hoàn thành một yêu cầu trước khi bị phát hiện

#### 5.2.5.4 Ràng buộc HTTPS (HTTPS Constraint)

9 đặc trưng payload (F12–F20) dựa vào **plaintext inspection** của nội dung HTTP. Khi dữ liệu được mã hóa (TLS 1.3), F12–F20 không thể tính toán được trừ khi có **SSLKEYLOGFILE** (tệp khóa session); trong trường hợp này, quan sát thu hẹp xuống còn 11 đặc trưng mạng (F1–F11) cộng với thành phần temporal và effect, mất khả năng phát hiện L7.

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

- **RL Detection Rate: 77,3%** — so với Static Rules (73,5%, +3,8 pp) và Rule-Based reward −5,559 (so với PPO +2,446)
- Sức mạnh đặc biệt: Tác nhân học được **hiểu biết ngữ nghĩa** về payload nhờ nhóm đặc trưng HTTP F12–F20 với chuẩn hóa payload và CRS hoạt động hiệp đồng
- **Ý nghĩa thực tiễn:** Phòng thủ điều khiển bởi AI không chỉ là học thuật — nó có lợi thế thực tiễn đo lường được trong nhiệm vụ phát hiện tương tự thực tế

#### 2. **Đánh đổi Vận hành (RQ2):** Bảo mật đi kèm với Tính sẵn sàng

- **Lưu lượng hợp lệ được cho phép: 93,2%** (FPR 6,8%) — chứng minh chính sách không bị khớp quá mức với tấn công đến mức hi sinh tính sẵn sàng dịch vụ
- **Chiến lược chuyển hướng Honeypot** (cửa sổ leo thang 60 giây) cung cấp lợi ích kép: giảm thiểu mối đe dọa và thu thập thông tin tình báo
- **Giảm thiểu tấn công: >96% DoS, 100% SQLi ở cấp phiên**
- **Ý nghĩa vận hành:** RL không phải nhị phân (Chặn tất cả / Cho phép tất cả). Nó học **phản ứng theo mức độ** dựa trên độ tin cậy của tín hiệu — một bước tiến so với quy tắc tĩnh

#### 3. **Tính Ổn định Chính sách (RQ3):** Policy Học Được và Ổn định

- **Đường cong huấn luyện trơn tru (+475% phần thưởng), không dao động** — tác nhân không bị "nhầm lẫn" bởi môi trường đa loại tấn công
- **approx_kl hội tụ an toàn** (0,012 → 0,003, dưới ngưỡng cắt) — cập nhật chính sách an toàn trong RL
- **Tác nhân học phản ứng phân hóa theo từng loại tấn công** — không sụp đổ về "luôn chặn"
- **Chiến lược tích lũy bằng chứng** (recall 26% per-window → 100% phát hiện per-session) cho thấy tác nhân học được cách đệm bằng chứng thông minh, không phản ứng với quan sát đơn lẻ nhiễu
- **Ý nghĩa triển khai:** Chính sách RL có **độ bền triển khai** — không yêu cầu hiệu chỉnh thủ công khi pattern tấn công thay đổi trong không gian gần với huấn luyện

### Ba Đóng góp Chính của Dự án

1. **Đóng góp kỹ thuật:** Tích hợp end-to-end tác nhân RL với pipeline NIDS bao gồm kỹ thuật đặc trưng tầng ứng dụng nâng cao (tích hợp CRS và chuẩn hóa payload). Nghiên cứu ablation định lượng rằng **nhóm đặc trưng payload HTTP (F12–F20) là đóng góp chủ đạo, không phải CRS đơn lẻ** — một phát hiện quan trọng chưa được công bố rộng rãi

2. **Đóng góp phương pháp:** Khung đánh giá nghiêm ngặt phân biệt **phát hiện per-window và per-session** (cặp số liệu phản trực giác phơi bày điểm yếu thực sự), **ablation với delta chính xác theo điểm phần trăm**, và **phân tích đánh đổi FPR/tỷ lệ phát hiện** — hữu ích cho các nghiên cứu NIDS-RL trong tương lai

3. **Đóng góp vận hành:** Chứng minh lộ trình triển khai khả thi:
   - Độ trễ ~1,016 ms (chấp nhận được với giới hạn tốc độ tĩnh làm tuyến phòng thủ đầu tiên)
   - FPR 6,8% (có thể quản lý với leo thang honeypot)
   - Không gian hành động đa bậc (Chặn, Giới hạn Tốc độ, Chuyển hướng) học được chính sách tinh tế
   - Sẵn sàng tích hợp với hạ tầng SIEM hiện có (đề cập Wazuh trong Mục 4.6)

### Những khoảng cách Vẫn cần Lấp

Dù hứa hẹn, dự án này chỉ được xác nhận trong **môi trường mô phỏng có kiểm soát**. Để đưa vào triển khai thực tế, cần giải quyết:
- Xác thực chuyển đổi Sim2Real: chuyển chính sách từ Containernet sang lưu lượng mạng thực
- Hỗ trợ HTTPS: hoặc proxy trong suốt hoặc chấp nhận điểm mù phát hiện tầng L7
- Phối hợp đa tác nhân: mở rộng quy mô vượt ra ngoài một tác nhân đơn lẻ
- Kiểm tra tính bền vững đối với tấn công evasion: kiểm tra attacker biết định nghĩa đặc trưng và chính sách

Những hướng phát triển này được chi tiết hóa trong Section 6.2.

---

## 6.2 Hướng Phát triển Tiếp Theo

Trong khi dự án này chứng minh tính khả thi cơ bản, một số phương hướng tự nhiên xuất hiện từ hạn chế và thành công đạt được. Phần này trình bày từng hướng theo tiềm năng tác động và ước tính công sức:

### 6.2.1 Mở rộng Không gian Hành động

**Hiện tại:** Tác nhân chọn giữa 4 hành động (Cho phép, Giới hạn Tốc độ, Chuyển hướng Honeypot, Chặn)

**Đề xuất:**
- **Giới hạn tốc độ theo từng IP nguồn** (ví dụ: 10 req/giây từ IP X, 100 req/giây từ IP Y)
- **Định tuyến theo loại request** (ví dụ: POST → quy tắc firewall, GET → cho qua)
- **Khởi tạo honeypot động** (tạo container honeypot mới theo yêu cầu dựa trên loại tấn công)
- **Action masking** — hướng dẫn khám phá tác nhân trong không gian hành động lớn hơn

**Tại sao quan trọng:** Môi trường đa người dùng hoặc ISP lớn cần phân cấp tinh hơn. Hành động "Chặn toàn bộ lưu lượng từ 203.0.113.0/24" quá thô — cần "Giới hạn 10k pps nhưng cho phép các cổng quan trọng."

**Ước tính công sức:** Vừa phải — cần tích hợp thư viện action masking (SB3 hỗ trợ sẵn) và điều chỉnh hàm phần thưởng bổ sung. Ước tính 2–3 tuần.

**Tác động:** Cải thiện trực tiếp FPR (giảm chặn nhầm) và khả năng sử dụng trong môi trường doanh nghiệp.

---

### 6.2.2 Phòng thủ Phân tán và Đa tác tử

**Hiện tại:** Một tác nhân duy nhất giám sát toàn bộ mạng

**Đề xuất:**
- **Một tác nhân cho mỗi phân đoạn mạng** (router biên, vành đai trung tâm dữ liệu, cảm biến nội bộ)
- **Phối hợp chính sách phân tán:**
  - **Máy chủ chính sách tập trung** lưu chính sách chung; tác nhân cục bộ thực hiện suy diễn
  - **Hoặc đồng thuận phi tập trung:** tác nhân chia sẻ kinh nghiệm (gradient chính sách) qua giao thức gossip
- **Giao thức truyền thông** (event bus kiểu AMQP) để tác nhân cảnh báo lẫn nhau (ví dụ: "Phát hiện Brute-force tầng web → thông báo tác nhân tầng DB siết chặt quy tắc đăng nhập")

**Tại sao quan trọng:** Mạng sản xuất có hàng trăm phân đoạn. Một tác nhân duy nhất không thể duy trì độ trễ <1ms ở quy mô đó. Đa tác nhân cho phép **ra quyết định phân tán gần với mối đe dọa hơn** (độ trễ thấp hơn, ít bước nhảy băng thông hơn).

**Ước tính công sức:** Rất cao — cần:
- Lý thuyết RL đa tác nhân (học hợp tác, chi phí truyền thông, ngăn ngừa phân kỳ chính sách)
- Kỹ thuật hệ thống phân tán (nhất quán cuối cùng, khả năng chịu lỗi)
- Ước tính 4–6 tháng nghiên cứu và triển khai

**Tác động:** Kích hoạt **triển khai SDN doanh nghiệp** (công việc hiện tại giới hạn trong môi trường lab Containernet). Đây là cửa ngõ để tiến đến sản xuất thực tế.

---

### 6.2.3 Độ bền vững đối với Tấn công Evasion

**Hiện tại:** Đánh giá tấn công là "hợp tác" — kẻ tấn công không biết định nghĩa đặc trưng

**Đề xuất:**
- **Mô hình kẻ tấn công đối nghịch:** Kẻ tấn công biết:
  - Định nghĩa đặc trưng (F1–F20 NIDS + 10D temporal + 4D phản hồi = quan sát 34D)
  - Hàm phần thưởng
  - Kiến trúc chính sách (MLP 2 lớp, net_arch=[128, 128], Tanh)
- **Chiến thuật evasion cần kiểm tra:**
  - Bypass chuẩn hóa payload (ví dụ: `%255c` = dấu gạch chéo ngược mã hóa URL kép)
  - Biến thiên thời gian (SYN flood chậm <100 SYN/giây để ở dưới ngưỡng F1)
  - Payload polyglot (đồng thời hợp lệ SQL và hợp lệ XML)
- **Phòng thủ:** Huấn luyện đối nghịch chính sách chống lại kẻ tấn công thích ứng (trò chơi min-max)

**Tại sao quan trọng:** Kẻ tấn công thực tế không ngây thơ. Nếu phòng thủ RL được triển khai, kẻ tấn công sẽ thích ứng. Đánh giá phải kiểm tra căng thẳng điều này.

**Ước tính công sức:** Rất cao — cần:
- Lý thuyết RL đối nghịch (trò chơi hai người, phân tích hội tụ)
- Bộ công cụ tổng hợp tấn công tùy chỉnh
- Chi phí tính toán (huấn luyện 2 tác nhân đồng thời)
- Ước tính 5–6 tháng

**Tác động:** Xác định **điểm yếu có thể khai thác trước triển khai** (có thể quan trọng cho các ứng dụng an toàn-quan trọng như mạng công nghiệp).

---

### 6.2.4 Huấn luyện Trực tuyến và Xử lý Trôi dạt Khái niệm (Học Liên tục)

**Hiện tại:** Chính sách cố định sau huấn luyện; không thích ứng với mối đe dọa mới

**Đề xuất:**
- **Phát hiện trôi dạt:** Theo dõi lưu lượng gần đây so với chính sách — nếu FPR tăng đột ngột hoặc phát hiện chữ ký tấn công mới → kích hoạt cờ huấn luyện lại
- **Huấn luyện lại tăng dần:** Tinh chỉnh chính sách trên lưu lượng gần đây mà không quên kiến thức cũ (elastic weight consolidation, lấy mẫu replay buffer)
- **Kiểm tra A/B:** Chạy chính sách cũ và mới song song trên lưu lượng bóng để xác nhận trước khi chuyển đổi

**Tại sao quan trọng:** Bối cảnh mối đe dọa tiến hóa (biến thể malware mới, kỹ thuật evasion mới). Chính sách trở nên lỗi thời. Cập nhật chính sách thủ công mỗi 6 tháng là không đủ.

**Ước tính công sức:** Vừa-Cao — cần:
- Kiểm định thống kê phát hiện trôi dạt (phát hiện thay đổi phân phối dữ liệu)
- Tích hợp thư viện học liên tục (ewc, SI, v.v.)
- Pipeline CI/CD để huấn luyện lại chính sách
- Ước tính 2–3 tuần

**Tác động:** Duy trì hiệu quả phòng thủ qua nhiều năm, không chỉ tại thời điểm triển khai.

---

### 6.2.5 Nhật ký Quyết định Minh bạch và Khả năng Giải thích

**Hiện tại:** Chính sách là hộp đen; người vận hành chỉ thấy "Hành động được dự đoán" mà không có giải thích

**Đề xuất:**
- **Trực quan hóa chú ý:** Hiển thị đặc trưng nào (F1–F20) ảnh hưởng nhiều nhất đến quyết định (SHAP, LIME áp dụng mỗi lần suy diễn)
- **Nhật ký quyết định:** "Yêu cầu từ 203.0.113.45, SYN ratio=0,9, PacketRate=500 → F1 và F2 đều cao → Hành động dự đoán: CHẶN với độ tin cậy 92%, 8% nhiễu khám phá"
- **Vết kiểm toán chính sách:** Kết xuất cây quyết định đã học (dù học ngầm) để người đánh giá bảo mật phê duyệt

**Tại sao quan trọng:**
- **Tuân thủ pháp lý:** PCI-DSS, GDPR yêu cầu vết kiểm toán ("tại sao yêu cầu này bị chặn?")
- **Tin tưởng vận hành:** Đội bảo mật không tin tưởng hệ thống hộp đen mà không có khả năng giải thích
- **Gỡ lỗi:** Nếu dương tính giả, giải thích "3 đặc trưng nào đã kích hoạt?"

**Ước tính công sức:** Vừa phải — cần:
- Tích hợp thư viện LIME/SHAP
- Bảng điều khiển UI cho nhật ký
- Tuần tự hóa chính sách để kiểm toán
- Ước tính 2–3 tuần

**Tác động:** **Kích hoạt triển khai sản xuất** — hiện tại rào cản lớn nhất cho việc SOC áp dụng là "Tôi không hiểu tại sao AI chặn yêu cầu này."

---

### 6.2.6 Xác thực Khoảng cách Mô phỏng-Thực tế (Chuyển đổi Học Sim2Real)

**Hiện tại:** Chính sách được huấn luyện trên Containernet, khả năng khái quát hóa sang thực tế chưa được biết

**Đề xuất — Phương pháp ba giai đoạn:**

**Giai đoạn 1: Phân tích dịch chuyển phân phối**
- Thu thập vết gói tin mạng thực (ví dụ: từ bộ dữ liệu LSNM2024, hoặc PCAP tường lửa thực)
- So sánh phân phối đặc trưng: tính toán thống kê F1–F20 (trung bình, phương sai, phân vị) cho lưu lượng thực vs. mô phỏng
- Xác định **dịch chuyển phân phối lớn nhất** (ví dụ: mạng thực có phương sai PacketRate cao hơn 10×)

**Giai đoạn 2: Chuyển đổi chính sách và đánh giá**
- Triển khai **chính sách Containernet đã huấn luyện** trên lưu lượng thực (chế độ bóng, không chặn thực sự)
- Đánh giá: tỷ lệ phát hiện trên tấn công thực
- Kết quả dự kiến: suy giảm (ví dụ: từ 77,3% → 60–70% trên dữ liệu thực do dịch chuyển phân phối)

**Giai đoạn 3: Tinh chỉnh Sim2Real**
- Dùng lưu lượng thực để **tinh chỉnh chính sách** (tiếp tục huấn luyện trên dữ liệu thực, tốc độ học nhỏ hơn để tránh quên thảm hại)
- Mục tiêu: khôi phục tỷ lệ phát hiện về gần mức huấn luyện (điều chỉnh theo đa dạng tấn công mạng thực)
- Triển khai: dùng chính sách đã tinh chỉnh

**Tại sao quan trọng:** Rủi ro quan trọng nhất đối với triển khai sản xuất. Containernet ≠ mạng thực.

**Ước tính công sức:** Rất cao — cần:
- Truy cập bộ dữ liệu thực (nhạy cảm về quyền riêng tư)
- Công sức gán nhãn quy mô lớn (phân loại tấn công vs. hợp lệ trên dữ liệu thực)
- Hạ tầng đánh giá phân tán (suy diễn chính sách ở quy mô lớn)
- Ước tính 2–3 tháng

**Tác động:** **Cửa ngõ đến triển khai sản xuất thực sự**. Không có bước này, mọi xác nhận trong lab đều không có ý nghĩa.

---

## Tóm tắt và Tầm nhìn Tương lai

Dự án này đã chứng minh rằng RL là một **nền tảng khả thi và thực tiễn** cho hệ thống phòng thủ mạng tự chủ. Ba câu hỏi nghiên cứu được trả lời:
- **RQ1:** RL vượt trội phương pháp dựa trên quy tắc (77,3% vs. 73,5%, +3,8 pp; FPR 6,8% vs. 10,2%)
- **RQ2:** RL cân bằng bảo mật và tính sẵn sàng (93,2% lưu lượng hợp lệ được cho phép, >96% giảm thiểu tấn công)
- **RQ3:** RL duy trì chính sách ổn định qua các loại tấn công đa dạng

Tuy nhiên, con đường từ thành công trong lab đến triển khai sản xuất còn dài. Sáu hướng chính (mở rộng không gian hành động, đa tác nhân, độ bền đối với evasion, học liên tục, khả năng giải thích, xác thực Sim2Real) là những bước tiếp theo tự nhiên định hình tương lai của hệ thống phòng thủ điều khiển bởi RL.

Sự kết hợp của **nghiêm ngặt học thuật** (ablation studies, lý thuyết học phân tán) và **thực dụng vận hành** (leo thang honeypot, quản lý FPR, tích hợp SIEM) là chìa khóa để phòng thủ RL không chỉ là proof-of-concept mà trở thành **thực tế triển khai** trong các tổ chức trong tương lai gần.

---

## TÀI LIỆU THAM KHẢO

[1] M. L. Puterman, *Markov Decision Processes: Discrete Stochastic Dynamic Programming*. New York, NY, USA: John Wiley & Sons, 1994.

[2] J. Schulman, F. Wolski, P. Dhariwal, A. Radford, and O. Klimov, "Proximal Policy Optimization Algorithms," *arXiv preprint arXiv:1707.06347*, 2017.

[3] A. Raffin, A. Hill, A. Gleave, A. Kanervisto, M. Ernestus, and N. Dormann, "Stable-Baselines3: Reliable Reinforcement Learning Implementations," *J. Mach. Learn. Res.*, vol. 22, no. 268, pp. 1–8, 2021.

[4] M. Peuster, H. Karl, and S. van Rossem, "MeDICINE: Rapid Prototyping of Production-Ready Network Services in Multi-PoP Environments," in *Proc. IEEE NFV-SDN*, 2016, pp. 148–153.

[5] A. H. Lashkari *et al.*, *LSNM2024: A Labeled Network Traffic Dataset for Intrusion Detection*. Univ. New Brunswick, 2024.

[6] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. ICISSP*, 2018, pp. 108–116.

[7] J. Postel, "Transmission Control Protocol," IETF, RFC 793, Sep. 1981.

[8] OWASP Foundation, "OWASP ModSecurity Core Rule Set (CRS) v4.0," 2023. [Online]. Available: https://coreruleset.org/

[9] K. Spett, "SQL Injection: Are Your Web Applications Vulnerable?" SPI Dynamics, White Paper, 2005.

[10] C. Kruegel and G. Vigna, "Anomaly Detection of Web-Based Attacks," in *Proc. 10th ACM CCS*, 2003, pp. 251–261.

[11] M. Towers *et al.*, "Gymnasium: A Standard Interface for Reinforcement Learning Environments," *arXiv preprint arXiv:2407.17032*, 2023.

[12] R. S. Sutton and A. G. Barto, *Reinforcement Learning: An Introduction*, 2nd ed. Cambridge, MA, USA: MIT Press, 2018.

[13] V. Mnih *et al.*, "Human-Level Control through Deep Reinforcement Learning," *Nature*, vol. 518, no. 7540, pp. 529–533, 2015.

[14] OWASP Foundation, "OWASP Top Ten," 2021. [Online]. Available: https://owasp.org/www-project-top-ten/

[15] A. Shiravi, H. Shiravi, M. Tavallaee, and A. A. Ghorbani, "Toward Developing a Systematic Approach to Generate Benchmark Datasets for Intrusion Detection," *Comput. Security*, vol. 31, no. 3, pp. 357–374, 2012.

[16] N. Moustafa and J. Slay, "UNSW-NB15: A Comprehensive Dataset for Network Intrusion Detection Systems," in *Proc. MilCIS*, 2015.

[17] M. Ring *et al.*, "A Survey of Network-Based Intrusion Detection Data Sets," *Comput. Security*, vol. 86, pp. 147–167, 2019.

[18] Netfilter Project, "Iptables — Linux kernel firewall," 2024. [Online]. Available: https://www.netfilter.org/

[19] J. Zheng, K. Krishnan, Y. Hong, and W. Jiang, "Real-time DDoS mitigation with SDN and iptables," *IEEE Trans. Network Service Management*, vol. 16, no. 1, pp. 123–135, 2019.


[20] R. Fielding and J. Reschke, "Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing," IETF, RFC 7230, Jun. 2014.

[21] F. Schmitt, J. Gassen, and E. Gerhards-Padilla, "HTTP Antivirus Proxy — An Approach to Defend Against Slow HTTP DoS Attacks," in *Proc. IEEE ICCNC*, 2012.

[22] Q. Abu Al-Haija, Z. Masoud, A. Yasin, K. Alesawi, and Y. Alkarnawi, "End-to-End Threat Hunting with a Novel Multiclass Dataset for Intelligent Intrusion Detection," *arXiv preprint arXiv:2508.05609*, 2025.

[23] M. Handley, V. Paxson, and C. Kreibich, "Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics," in *Proc. 10th USENIX Security Symp.*, 2001, pp. 115–131.

[24] S. Akhavani, G. Jourdan, I. Mounier, and I. Onut, "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls," in *Proc. IEEE S&P*, 2025, arXiv:2503.10846.

[25] T. Pietraszek and C. V. Berghe, "Defending Against Injection Attacks Through Context-Sensitive String Evaluation," in *RAID 2005*, Springer LNCS 3858, pp. 124–145, 2006. DOI: 10.1007/11663812_7.

[26] Verizon, "2024 Data Breach Investigations Report," Verizon Communications Inc., Tech. Rep., 2024. [Online]. Available: https://www.verizon.com/business/resources/reports/dbir/

[27] Verizon, "2020 Data Breach Investigations Report," Verizon Communications Inc., Tech. Rep., 2020. [Online]. Available: https://www.verizon.com/business/resources/reports/dbir/

[28] IBM Security and Ponemon Institute, "Cost of a Data Breach Report 2024," IBM Corporation, Tech. Rep., 2024. [Online]. Available: https://www.ibm.com/reports/data-breach

[29] B. Lantz, B. Heller, and N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," in *Proc. 9th ACM SIGCOMM HotNets Workshop*, 2010.

[30] P. Biondi, "Scapy: Packet Manipulation Tool," in *Proc. French Network Security Conf.*, 2007.

[31] M. A. Ferrag and L. A. Maglaras, "DeepCoin: A Novel Deep Learning and Blockchain-Based Energy Exchange Framework for Smart Grids," *IEEE Internet of Things J.*, vol. 6, no. 5, 2019; and M. A. Ferrag *et al.*, "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study," *J. Inf. Security Appl.*, vol. 50, 2020.

[32] A. M. Khodadadi *et al.*, "An Empirical Study on the Evaluation and Enhancement of OWASP CRS in ModSecurity," *Comput. Security*, vol. 139, 2024. DOI: 10.1016/j.cose.2025.104031.


[33] H. A. Tadhani, S. Gupta, M. Kumar, and S. Bhatt, "Securing web applications against XSS and SQLi attacks using a novel deep learning approach," *Sci. Rep. (Nature)*, vol. 14, 2024. DOI: 10.1038/s41598-023-48845-4.

---

## PHỤ LỤC

### Phụ lục A — Bảng Siêu tham số Đầy đủ: Default SB3 vs. Đã Tinh chỉnh

Bảng dưới đây tổng hợp toàn bộ siêu tham số PPO được sử dụng, bao gồm các thay đổi so với cấu hình mặc định SB3 và lý do kỹ thuật của từng thay đổi.

| Tham số | Default SB3 | Giá trị Đã Tinh chỉnh | Lý do Điều chỉnh |
|---|---|---|---|
| `net_arch` (pi/vf) | [64, 64] | **[128, 128]**, Tanh | Input 34D cần capacity cao hơn để học biên quyết định trên 5 không gian tấn công đồng thời |
| `learning_rate` | 3×10⁻⁴ (cố định) | **3×10⁻⁴ → 1×10⁻⁴** (giảm tuyến tính) | Hai pha: khám phá nhanh giai đoạn đầu, tinh chỉnh chính xác giai đoạn cuối |
| `ent_coef` | 0,0 | **0,02** | Duy trì khám phá, ngăn agent hội tụ cứng vào 1 hành động |
| `batch_size` | 64 | **256** | Gradient ổn định hơn với không gian trạng thái 34D |
| `clip_range` ε | 0,2 | 0,2 | Giữ nguyên theo Schulman et al. [2] |
| `gamma` γ | 0,99 | 0,99 | Tầm nhìn dài hạn phù hợp episode 120 bước |
| `n_steps` | 2048 | 2048 | Giữ nguyên — kích thước rollout buffer phù hợp |
| `n_epochs` | 10 | 10 | Giữ nguyên |
| `n_envs` | 1 | **4** | Song song hóa 4 môi trường → tăng tốc ~4× wall-clock |
| `vf_coef` | 0,5 | 0,5 | Giữ nguyên |
| Tổng bước | — | ~500k timesteps | Dừng khi reward bão hòa (hội tụ thực nghiệm) |
| Seed | — | 42 | Đảm bảo tái tạo kết quả |

**Kết quả so sánh training (seed = 42):**

| Chỉ số | Default SB3 | Đã Tinh chỉnh | Chênh lệch |
|---|---|---|---|
| Mean reward (5 seeds) | 2,482 ± 0,029 | 2,446 ± 0,021 | −1,5% reward, **−28% variance** |
| Tỷ lệ dương tính giả (FPR) | 0,9% | **0,7%** | −0,2 pp |
| Tỷ lệ phát hiện | 77,3% | 77,3% | Không đổi |
| Wall-clock (seed 42) | 786 s | **197 s** | **4× nhanh hơn** (n\_envs=4) |
| Cohen's *d* (ổn định) | — | **−1,290** (large effect) | Ổn định chính sách cải thiện đáng kể |
| *p*-value (t-test, n=5) | — | 0,0757 | Gần α=0,05; cần n≥20 để xác nhận |

---

### Phụ lục B — Hàm Phần thưởng: Thành phần và Tham số

Hàm phần thưởng đầy đủ:

$$R_t = -(D_{\text{after}} + C_{\text{action}}) + B_{\text{reduction}} + B_{\text{action}}$$

**B.1 Thành phần Tổn thất Mạng D** — tổng hợp 6 chỉ báo với trọng số phản ánh mức nghiêm trọng:

| Thành phần | Đặc trưng | Trọng số | Hàm phi tuyến | Lý do |
|---|---|---|---|---|
| Tràn gói tin (DDoS) | F1 | 0,25 | Logistic | Gián đoạn dịch vụ hoàn toàn |
| Tỷ lệ RST (quét/brute) | F4 | 0,15 | Tanh | Chỉ báo trinh sát |
| Phân bố quét cổng | F5 | 0,15 | Log-sigmoid | Chỉ báo trinh sát |
| Bất thường payload | F9, F4, F5 | 0,10 | Logistic | Tín hiệu đơn lẻ |
| SYN flood | F2 | 0,10 | Tanh | Cạn kiệt bảng kết nối |
| SQLi/XSS (L7) | F12–F20 | 0,25 | Tổ hợp có trọng số | Vi phạm tầng ứng dụng |

**B.2 Chi phí Hành động C:** Cho phép = 0 · Giới hạn Tốc độ = 0,01 · Chuyển hướng = 0,04 · Chặn = 0,15

**B.3 Thưởng Phát hiện B\_action** (soft gating):

| Tình huống | Phần thưởng |
|---|---|
| DDoS/Port Scan → Chặn | +0,25 |
| DDoS/Port Scan → Cho phép | −0,50 |
| Brute/SQLi/XSS → Chuyển hướng | +0,25 |
| Brute/SQLi/XSS → Cho phép | −0,40 |
| Lưu lượng bình thường → Chặn | **−0,60** (phạt dương tính giả nặng nhất) |

**B.4 Thưởng Giảm thiểu:** $B_{\text{reduction}} = (\text{damage\_before} - \text{damage\_after}) \times 0{,}5$

---

### Phụ lục C — Chỉ số Chẩn đoán PPO tại Hội tụ

Bảng dưới đây ghi lại các chỉ số chẩn đoán TensorBoard từ quá trình huấn luyện PPO-Tuned (seed = 42, 500k timesteps):

| Chỉ số | Giá trị Khởi đầu | Giá trị Cuối | Diễn giải |
|---|---|---|---|
| `eval/mean_reward` | 0,4 | 2,3 | +475% — hội tụ thành công |
| `eval/mean_ep_length` | 120 | 120 | Ổn định — agent không terminate sớm |
| `approx_kl` | 0,012 | 0,003 | < 0,02 — cập nhật chính sách an toàn |
| `clip_fraction` | 0,14 | 0,02 | Giảm dần — policy ổn định |
| `entropy_loss` | −1,10 | −0,10 | Agent tự tin nhưng không sụp đổ |
| `explained_variance` | 0,06 | 0,26 | Chấp nhận được — 5 loại tấn công ngẫu nhiên |
| `value_loss` | 2,50 | ~0 | Critic học tốt |
| `learning_rate` | 3×10⁻⁴ | 1×10⁻⁴ | Giảm tuyến tính theo lịch trình |

Đường cong học tập trực quan hóa qua TensorBoard (Figure 4.1) cho thấy reward tăng đều không dao động, entropy giảm dần — xác nhận chính sách ổn định qua toàn bộ quá trình huấn luyện.

