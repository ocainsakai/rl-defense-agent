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

**1.3 Mục tiêu nghiên cứu**

Mục tiêu chính của dự án này là thiết kế, triển khai và đánh giá một hệ thống phòng thủ mạng dựa trên AI tự chủ có khả năng đưa ra các quyết định bảo mật theo thời gian thực trong một môi trường năng động và đối kháng. Để đạt được mục tiêu bao trùm này, nghiên cứu được dẫn dắt bởi các mục tiêu cụ thể sau:

* Nghiên cứu khả năng áp dụng của các kỹ thuật Học tăng cường (RL) cho việc ra quyết định tự chủ trong các kịch bản phòng thủ mạng, đặc biệt là trong các môi trường đặc trưng bởi các cuộc tấn công mạng tự động và thích ứng.  
* Thiết kế và xây dựng một môi trường mạng mô phỏng đại diện chính xác cho cơ sở hạ tầng mạng thực tế, bao gồm máy chủ sản xuất, kẻ tấn công và các thành phần phòng thủ bằng Mininet.  
* Phát triển một tác nhân phòng thủ dựa trên RL có khả năng quan sát trạng thái mạng, xác định các hành vi bất thường hoặc độc hại và lựa chọn các hành động giảm thiểu phù hợp: chặn, giới hạn tốc độ hoặc chuyển hướng lưu lượng.  
* Định nghĩa và triển khai một hàm phần thưởng cân bằng giữa hiệu quả bảo mật và hiệu suất hệ thống, đảm bảo rằng các hành động phòng thủ giảm thiểu các cuộc tấn công trong khi vẫn duy trì tính sẵn sàng của dịch vụ.  
* Đánh giá hiệu suất của tác nhân phòng thủ được đề xuất đối với nhiều kịch bản tấn công bằng cách đo lường các chỉ số chính như tỷ lệ giảm thiểu tấn công, thời gian phản hồi, tỷ lệ dương tính giả và độ ổn định chung của mạng.

Bằng cách giải quyết các mục tiêu này, dự án nhằm chứng minh tính khả thi và hiệu quả của Học tăng cường như một nền tảng cho các hệ thống phòng thủ mạng **tự chủ** và cung cấp những hiểu biết thực nghiệm về hành vi của chúng trong các điều kiện tấn công đa dạng.

**1.4 Phạm vi và Hạn chế**

Phần này xác định phạm vi nghiên cứu và làm rõ các hạn chế của phương pháp được đề xuất nhằm thiết lập những kỳ vọng thực tế cho kết quả của nghiên cứu.

**1.4.1 Phạm vi nghiên cứu**

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

**1.4.2 Những hạn chế của nghiên cứu**

Mặc dù có những đóng góp nhất định, nghiên cứu này vẫn còn một số hạn chế cần được thừa nhận.

Thứ nhất, hệ thống phòng thủ được đề xuất chỉ được đánh giá độc quyền trong môi trường mô phỏng. Mặc dù mô phỏng được thiết kế để xấp xỉ hành vi mạng trong thế giới thực, kết quả có thể khác biệt khi triển khai trong môi trường sản xuất (production) do các yếu tố như hạn chế về phần cứng, sự không đồng nhất của mạng và hành vi khó đoán của người dùng.

Thứ hai, các kịch bản tấn công được xem xét trong nghiên cứu này chỉ giới hạn ở một tập hợp các loại tấn công được định nghĩa trước. Các mối đe dọa nâng cao như khai thác lỗ hổng zero-day, tấn công chuỗi cung ứng và các kỹ thuật di chuyển ngang (lateral movement) tinh vi nằm ngoài phạm vi của nghiên cứu này.

Thứ ba, hiệu suất của tác nhân học tăng cường chịu ảnh hưởng bởi chất lượng của hàm phần thưởng và tính đại diện của môi trường mô phỏng. Việc thiết kế phần thưởng chưa tối ưu hoặc biểu diễn trạng thái không đầy đủ có thể hạn chế khả năng của tác nhân trong việc khái quát hóa đối với các tình huống chưa từng gặp.

Cuối cùng, hệ thống được triển khai và thử nghiệm trên nền tảng Ubuntu Linux. Khả năng chuyển đổi của phương pháp đề xuất sang các hệ điều hành khác hoặc các môi trường đám mây phân tán quy mô lớn chưa được đánh giá trong công trình này và vẫn là một chủ đề cho các nghiên cứu trong tương lai.

**1.5 Ý nghĩa của nghiên cứu**

Nghiên cứu này đóng góp vào lĩnh vực an ninh mạng bằng cách khám phá tính khả thi của việc phòng thủ mạng tự chủ sử dụng Học tăng cường (Reinforcement Learning). Phương pháp này hướng tới nâng cao hơn các cơ chế bảo mật truyền thống dựa trên việc tích hợp hệ thống phòng thủ thích ứng và tự học.

Từ góc độ kỹ thuật, dự án cung cấp một triển khai thực tế của một tác nhân phòng thủ dựa trên RL được tích hợp với môi trường mạng mô phỏng. Sự kết hợp giữa Gymnasium, Mininet và các kỹ thuật giảm thiểu dựa trên Linux chứng minh cách học tăng cường có thể được áp dụng cho các kịch bản mạng lấy cảm hứng từ thế giới thực. Việc tích hợp với Wazuh SIEM càng minh họa thêm tiềm năng kết hợp các tác nhân phòng thủ tự chủ với các nền tảng giám sát an ninh hiện có để nâng cao khả năng quan sát và nhận thức hoạt động.

Từ góc độ học thuật, nghiên cứu này cung cấp những hiểu biết thực nghiệm về hành vi của các tác nhân học tăng cường dưới các kịch bản tấn công mạng đa dạng. Các kết quả đánh giá góp phần giúp hiểu rõ hơn về cách các tác nhân tự chủ cân bằng giữa hiệu quả bảo mật và tính sẵn sàng của dịch vụ, một sự đánh đổi quan trọng trong phòng thủ mạng. Những phát hiện này có thể dùng làm tài liệu tham khảo cho các nghiên cứu trong tương lai về hệ thống an ninh mạng thích ứng và việc ra quyết định dựa trên học tăng cường.

Cuối cùng, từ góc độ thực tiễn và công nghiệp, khung đề xuất làm nổi bật tiềm năng của các hệ thống phòng thủ tự chủ do AI điều khiển trong việc giảm gánh nặng vận hành cho các nhà phân tích bảo mật con người. Bằng cách tự động hóa các quy trình phát hiện và phản ứng, các hệ thống như vậy có thể giảm thiểu tình trạng mệt mỏi vì cảnh báo (alert fatigue) và cho phép phản ứng nhanh hơn, nhất quán hơn đối với các mối đe dọa mạng. Do đó, nghiên cứu này đặt nền móng cơ bản cho việc nghiên cứu và phát triển các giải pháp phòng thủ mạng thông minh, có khả năng mở rộng và linh hoạt trong tương lai.

**Chương 2**

**TỔNG QUAN TÀI LIỆU**

**2.1 Các kiến thức cơ bản về Học tăng cường**

Học tăng cường (Reinforcement Learning \- RL) là một nhánh của học máy tập trung vào việc cho phép các tác nhân học các hành vi tối ưu thông qua tương tác với môi trường. Không giống như học có giám sát, vốn dựa vào các bộ dữ liệu được gán nhãn, RL cho phép một tác nhân học trực tiếp từ kinh nghiệm bằng cách nhận phản hồi dưới dạng phần thưởng hoặc hình phạt. Mô hình học tập này đặc biệt phù hợp cho các lĩnh vực năng động và đối kháng như an ninh mạng, nơi dữ liệu được gán nhãn khan hiếm và các chiến lược tấn công liên tục phát triển.

**2.1.1 Khung Học tăng cường**

Quá trình học tăng cường thường được mô hình hóa như một sự tương tác giữa một tác nhân và một môi trường. Tại mỗi bước thời gian rời rạc, tác nhân quan sát trạng thái hiện tại của môi trường và chọn một hành động theo chính sách của nó. Để đáp lại, môi trường chuyển sang một trạng thái mới và cung cấp một phần thưởng vô hướng phản ánh chất lượng hành động của tác nhân.

Sự tương tác này thường được chính thức hóa bằng Quy trình Quyết định Markov (MDP), được xác định bởi một bộ dữ liệu 1 $(S, A, P, R, \\gamma)$, trong đó:

* $S$ đại diện cho tập hợp các trạng thái có thể. 2  
* $A$ biểu thị tập hợp các hành động có sẵn. 3  
* $P(s'|s, a)$ xác định xác suất chuyển đổi trạng thái. 4  
* $R(s, a)$ là hàm phần thưởng. 5  
* $\\gamma \\in \[0, 1\]$ là hệ số chiết khấu cân bằng giữa phần thưởng tức thời và phần thưởng trong tương lai. 6

Mục tiêu của tác nhân là học một chính sách $\\pi(a|s)$ nhằm tối đa hóa phần thưởng tích lũy kỳ vọng theo thời gian. Trong bối cảnh phòng thủ mạng, điều này tương ứng với việc học các chuỗi hành động giảm thiểu nhằm giảm tác động của cuộc tấn công trong khi vẫn duy trì hiệu suất hệ thống ở mức chấp nhận được. 7

**2.1.2 Học tăng cường dựa trên mô hình và Phi mô hình**

Các thuật toán học tăng cường có thể được phân loại rộng rãi thành các phương pháp dựa trên mô hình (model-based) và phi mô hình (model-free). Các phương pháp RL dựa trên mô hình cố gắng học hoặc sử dụng một mô hình rõ ràng về động lực học của môi trường, mô hình này sau đó có thể được sử dụng để lập kế hoạch và ra quyết định. Mặc dù các phương pháp như vậy có thể hiệu quả về mẫu (sample-efficient), nhưng việc mô hình hóa chính xác các môi trường mạng phức tạp và hành vi của kẻ tấn công thường không thực tế.

Mặt khác, RL phi mô hình học các chính sách tối ưu trực tiếp từ các tương tác mà không cần một mô hình rõ ràng về môi trường. Các phương pháp này thường được áp dụng phổ biến hơn trong nghiên cứu an ninh mạng do tính linh hoạt và khả năng xử lý các môi trường phức tạp, chỉ quan sát được một phần. Các phương pháp phi mô hình phổ biến bao gồm các phương pháp dựa trên giá trị (value-based) và phương pháp dựa trên chính sách (policy-based).

***2.1.3 Học tăng cường sâu (Deep Reinforcement Learning)***

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

Mininet là một khung giả lập mạng được áp dụng rộng rãi cho phép tạo ra các mạng ảo bằng cách sử dụng các container Linux nhẹ. Nó cung cấp hành vi mạng thực tế bằng cách tận dụng ngăn xếp mạng (networking stack) của hạt nhân Linux, cho phép mô hình hóa chính xác độ trễ, băng thông và mất gói tin. Mức độ trung thực này làm cho Mininet phù hợp để mô phỏng các cấu trúc mạng quy mô doanh nghiệp, bao gồm bộ định tuyến, bộ chuyển mạch, máy chủ và máy trạm.

Trong nghiên cứu an ninh mạng, Mininet đã được sử dụng rộng rãi để nghiên cứu các hệ thống phát hiện xâm nhập, phân tích lưu lượng và cơ chế phòng thủ tự động. Khả năng cấu hình lại động các cấu trúc mạng trong thời gian chạy cho phép các nhà nghiên cứu mô phỏng các bề mặt tấn công và phản ứng phòng thủ đang phát triển. Hơn nữa, Mininet tích hợp liền mạch với các công cụ bảo mật như Iptables, TC (Traffic Control) và các khung kiểm tra gói tin, cho phép thực thi các hành động phòng thủ ở cấp độ thấp.

**2.2.3 Môi trường Học tăng cường với Gymnasium**

Gymnasium, người kế nhiệm của OpenAI Gym, cung cấp một giao diện tiêu chuẩn hóa cho các môi trường học tăng cường. Nó xác định các khái niệm trừu tượng rõ ràng cho không gian trạng thái, không gian hành động, hàm phần thưởng và điều kiện kết thúc tập (episode). Những khái niệm trừu tượng này đơn giản hóa việc tích hợp các môi trường phức tạp với các thuật toán học tăng cường và khung huấn luyện.

Trong bối cảnh phòng thủ mạng, Gymnasium đóng vai trò là cầu nối giữa tác nhân học tăng cường và mạng mô phỏng. Các chỉ số mạng như khối lượng lưu lượng, tốc độ kết nối, entropy gói tin và tín hiệu cảnh báo có thể được mã hóa thành các biểu diễn trạng thái dạng số. Tương tự, các hành động phòng thủ như chặn IP, giới hạn tốc độ hoặc chuyển hướng lưu lượng có thể được ánh xạ vào các không gian hành động rời rạc hoặc liên tục.

Việc sử dụng Gymnasium đảm bảo khả năng tương thích với các thư viện học tăng cường được áp dụng rộng rãi, bao gồm Stable Baselines3. Khả năng tương thích này cho phép thử nghiệm nhanh chóng với các thuật toán học tăng cường sâu hiện đại trong khi vẫn duy trì tính tái lập và tính mô đun.

**2.2.4 Kiến trúc mô phỏng lai**

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

Các kỹ thuật đánh lừa ngày càng đóng vai trò quan trọng trong các chiến lược phản ứng sự cố hiện đại. Honeypot (hũ mật/hệ thống bẫy) là các hệ thống mồi nhử được thiết kế để thu hút kẻ tấn công và quan sát hành vi độc hại mà không gây rủi ro cho tài sản sản xuất. Bằng cách chuyển hướng lưu lượng đáng ngờ đến honeypot, những người phòng thủ có thể thu thập thông tin tình báo có giá trị trong khi giảm tác động tấn công trực tiếp.

**2.3.6 Tích hợp với hệ thống SIEM**

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