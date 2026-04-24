# Ghi chú Tổng hợp: Ánh xạ Biểu đồ và Hiệu chỉnh Benchmark (Chương 4)

Tài liệu này lưu trữ các thông tin quan trọng để bạn hoàn thiện Chương 4 (Kết quả thực nghiệm) trong quá trình chuyển đổi sang LaTeX.

---

## 1. Ánh xạ Biểu đồ (Chart Mapping)

Dưới đây là danh sách các tệp hình ảnh trong thư mục `datasets/plots` và vị trí tương ứng trong file `part_4_results.md`:

| Tên file (.png) | Mô tả nội dung | Vị trí (Figure #) |
| :--- | :--- | :--- |
| `chart5_ids2018_confusion_L2.png` | Ma trận nhầm lẫn lớp L2 trên tập IDS2018 | **Figure 4.5** |
| `chart1_ids2018_3layers.png` | So sánh hiệu năng 3 lớp (Raw, AI, System) - IDS2018 | **Figure 4.6** |
| `chart6_false_positive_7hosts.png` | Tỉ lệ báo động giả trên 7 host sạch (Availability) | **Figure 4.7** |
| `chart3_cross_dataset_5attacks.png` | Phân phối tấn công và tỉ lệ phát hiện tổng hợp | **Figure 4.8** |
| `chart4_ids2017_friday_timeline.png` | Dòng thời gian diễn biến tấn công thực tế | Mục **4.4.2** |
| `chart7_ids2018_thursday_3layers.png` | Đánh giá 3 lớp trên dữ liệu Baseline (IDS2018 Thu 5) | Mục **4.2.9** |
| `chart2_ids2017_thursday_3layers.png` | Đánh giá 3 lớp trên dữ liệu Baseline (IDS2017 Thu 5) | Mục **4.2.9** |

---

## 2. Bản thảo Nội dung Benchmark (4.2.5) - Tiếng Việt Cao cấp

Sử dụng đoạn văn bản dưới đây để thay thế hoặc bổ sung vào mục Benchmark nhằm tăng tính chuyên nghiệp (văn phong học thuật):

### 4.2.5 Đánh giá hiệu năng (Benchmark) PPO, DQN và A2C

**a. Giao thức thực nghiệm và Thiết lập dữ liệu**
Thử nghiệm benchmark được thiết lập dựa trên nguyên tắc kiểm soát biến số nghiêm ngặt nhằm đảm bảo tính khách quan:
*   **Môi trường:** Tất cả các thuật toán đều vận hành trên cùng một môi trường mô phỏng `env_ids_harder` với không gian trạng thái 34 chiều.
*   **Cấu hình thuật toán:** Sử dụng các thiết lập mặc định của thư viện **Stable Baselines3 (SB3)**, không thực hiện tinh chỉnh siêu tham số để đánh giá khả năng hội tụ tự nhiên.
*   **Quy trình huấn luyện:** Sử dụng `n_envs=1`. Mô hình tại thời điểm kết thúc (**final model**) được trích xuất làm checkpoint chính thức để phản ánh độ ổn định cuối cùng.
*   **Phương pháp thống kê:** Huấn luyện trên 5 tập số ngẫu nhiên (train seeds: 42, 123, 456, 789, 1337). Kết quả được tổng hợp dưới dạng giá trị trung bình kèm khoảng tin cậy (CI) 95%.

**b. Các chế độ đánh giá và Trục phân tích**
Hệ thống benchmark phân tách hai trục biến số độc lập: **tính phiên (session)** và **nhiễu dữ liệu (noise/drift)**:
1.  **Trục hành vi theo phiên:** Kiểm chứng khả năng duy trì trạng thái phòng thủ ổn định khi đối mặt với một thực thể (IP) duy nhất trong thời gian dài.
2.  **Trục nhiễu và sự trôi dạt dữ liệu:** Đánh giá tính bền vững khi dữ liệu bị khuyết thiếu hoặc phân phối đặc trưng dịch chuyển.

**c. Thảo luận Kết quả (Bảng 4.4 & 4.5)**
*   **Hiệu năng phòng thủ:** DQN thể hiện ưu thế về các chỉ số phòng thủ thô (Mitigation Rate). Tuy nhiên, DQN có xu hướng "aggressive" (hung hăng) hơn, dẫn đến tỉ lệ can thiệp nhầm cao hơn.
*   **Sự đánh đổi (Trade-off):** PPO thể hiện ưu thế vượt trội trong việc bảo vệ lưu lượng hợp lệ (Benign traffic). Tần suất can thiệp sai thấp hơn đáng kể, khẳng định tính khả thi của PPO trong các kịch bản thực tế đòi hỏi sự cân bằng giữa an ninh và khả dụng.

---

## 3. Lưu ý khi đưa vào LaTeX (`main.tex`)

Khi chèn ảnh vào LaTeX, bạn nên sử dụng cấu trúc sau để đảm bảo ảnh nằm đúng vị trí:

```latex
\begin{figure}[htbp]
    \centering
    \includegraphics[width=0.8\textwidth]{datasets/plots/chart5_ids2018_confusion_L2.png}
    \caption{Ma trận nhầm lẫn lớp L2 trên tập dữ liệu CSE-CIC-IDS2018}
    \label{fig:confusion_matrix_l2}
\end{figure}
```

> [!TIP]
> Bạn có thể sử dụng lệnh `\ref{fig:label}` để trích dẫn hình ảnh trong văn bản một cách tự động, giúp duy trì tính liên kết của tài liệu.
