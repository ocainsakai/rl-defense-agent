# Phản biện Benchmark Report — PPO vs DQN vs A2C

> Tài liệu này phản biện nội dung `BENCHMARK_REPORT_GUIDE.md` dưới góc nhìn "benchmark có khớp với mục tiêu đồ án không". Mục đích: giúp nhóm tự đánh giá điểm yếu trước khi bảo vệ, và biết cần bổ sung gì.
>
> **Nguồn tham chiếu**:
> - `AI RL/Benchmark/BENCHMARK_REPORT_GUIDE.md` — tài liệu đang được phản biện
> - `AI RL/Benchmark/results/benchmark_results.json` — số liệu gốc
> - `AI RL/Benchmark/evaluate_all.py` — script đánh giá
> - `PROJECT_GOALS` slide — 3 mục tiêu (Core, Agent Design, Reward Trade-off)

---

## 1. Mapping benchmark ↔ mục tiêu đồ án

Slide "Project Goals" tuyên bố 3 mục tiêu:

1. **Core Objective**: Autonomous network defense with **real-time** RL decision-making.
2. **Agent Design**: Pipeline **Observe → Detect → Decide** (Allow, RateLimit, Redirect, Block).
3. **Reward Optimization**: **Solve** trade-off System Security ↔ Service Availability.

Đối chiếu với phạm vi benchmark:

| Goal | Benchmark có cover không? | Ghi chú |
|---|---|---|
| Autonomous defense | ❌ Không | Chạy trong mock env `env_ids_harder.py`, không có adversary đối kháng thật. |
| Real-time | ❌ Không | Không đo latency, không có decision-time metric. |
| Observe → **Detect** → Decide | ❌ Không | Không có detection metric riêng (F1/Precision/Recall per attack type). Chỉ có action correctness. |
| Security ↔ Availability trade-off | ⚠️ Một phần | Có `mitigation_rate` và `benign_intervention_rate`, nhưng **không sweep reward weights** để vẽ Pareto curve. |

**Kết luận phần này**: Benchmark đang trả lời câu hỏi *"trong họ RL, thuật toán nào trade-off tốt nhất?"* — một câu hỏi **khác** với câu hỏi *"hệ thống có đạt được mục tiêu đề ra không?"*. Đây là lỗi khớp scope cốt lõi.

---

## 2. Mười vấn đề lớn của benchmark

### 2.1. So RL với RL — không defendable câu "tại sao phải dùng RL?"

PPO vs DQN vs A2C là so sánh **nội bộ trong họ RL**. Câu đầu tiên hội đồng sẽ hỏi:

> "Tại sao không dùng ModSecurity CRS (signature-based)? Tại sao không dùng Snort/Suricata? Tại sao phải RL?"

Benchmark hiện tại không có baseline non-RL → không defendable. Repo đã có sẵn:
- `REQUEST-941-APPLICATION-ATTACK-XSS.conf`
- `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`
- `crs-rules-*.csv`, `crs-paranoia-levels-vi.csv`

Tức **ModSecurity CRS baseline hoàn toàn khả thi** với dữ liệu có sẵn.

**Phải thêm ít nhất một trong các baseline**:
- ModSecurity CRS (signature-based WAF) — bắt buộc cho SQLi/XSS arm.
- Static threshold rule (`if F1 > 100 pps → Block`) — trivial implement.
- Random Forest / XGBoost trên 20D features — classical ML baseline.

Không có baseline non-RL, đồ án chỉ chứng minh được *"trong 3 thuật toán RL, PPO trade-off tốt nhất"* — không chứng minh được *"RL đáng dùng cho bài toán này"*.

### 2.2. Evaluate trên mock env, không phải real deployment

`env_ids_harder.py` là **synthetic environment** với `MockIPBehavior`. Mọi metric benchmark đều đo trên observation được sinh bởi công thức:

- **4D effect** trong mock = `simulate_effect()` — deterministic formula theo action. Trong production = đọc nginx access.log.
- **Attack patterns** trong mock = phân phối cố định do code sinh. Trong production = sqlmap, hping3, xsser với timing stochastic.
- **Mitigation rate cao trên mock** ≠ mitigation rate cao trên real traffic.

Goals claim "real-time decision-making capabilities" nhưng benchmark không chạy trên traffic thật. Hội đồng hỏi *"kết quả có generalize sang Mininet live không?"* — không có dữ liệu trả lời.

**Fix**:
- Chạy thêm evaluation trên **replay mode** với `training_data.jsonl` thu từ sniffer thật.
- Tối thiểu 1 bảng "mock vs replay" để cho thấy gap (nếu có) giữa hai môi trường.
- Hoặc chạy live trên Mininet với 5 attack scenarios (SYN flood, Port Scan, Brute Force, SQLi, XSS) và đo mitigation per scenario.

### 2.3. Không có attack-type breakdown

Benchmark chỉ có metric tổng hợp:
- `mitigation_rate`
- `exact_response_rate`
- `service_damage_auc`

**Không có** metric per attack type:
- SQLi F1?
- XSS F1?
- SYN Flood F1?
- Port Scan F1?
- Brute Force F1?

Goals slide ngụ ý agent phòng thủ nhiều loại tấn công, nhưng benchmark không xác minh đâu là loại làm tốt, đâu là loại làm yếu. Nếu PPO xử lý SYN Flood rất tốt nhưng SQLi rất tệ, metric tổng hợp che đi điều đó.

**Fix**: Thêm confusion matrix per attack type và F1 score riêng cho từng lớp.

### 2.4. n=5 seeds là quá ít cho thống kê

`n=5 train seeds` → two-sample t-test có **degrees of freedom = 8**. Với n nhỏ như vậy:

- p-value gần ngưỡng 0.05 (như 0.0486, 0.0741) **rất không ổn định** — thêm 1 seed có thể đảo kết luận.
- Assumption normality của t-test **không kiểm chứng được** với 5 samples.
- Guide đã thừa nhận "n=5 is small" nhưng **không làm gì để bù đắp**.

**Fix**:
- Tăng lên n=10 seeds nếu còn compute.
- Hoặc dùng **non-parametric test** (Mann-Whitney U) — robust hơn với sample nhỏ, không giả định normality.
- Hoặc report **bootstrap 95% CI** thay p-value.

### 2.5. `service_damage_auc` đặt tên sai về mặt học thuật

Guide định nghĩa:

> `service_damage_auc` = mean step damage

AUC = **Area Under Curve** theo tiêu chuẩn ngành (ROC AUC, PR AUC). **Mean step damage ≠ AUC**. AUC phải là integral/sum theo thời gian, không phải mean.

Đặt tên này **misleading** về mặt học thuật. Hội đồng có background ML/stats sẽ bắt lỗi ngay.

**Fix**:
- Đổi tên thành `mean_service_damage` hoặc `avg_step_damage`.
- Nếu muốn giữ "AUC", phải đổi định nghĩa thành sum/integral theo thời gian episode (ví dụ: tổng F24 qua toàn episode — diện tích dưới đường F24(t)).

### 2.6. `benign_intervention_rate` trộn 3 severity khác nhau

Công thức:

```
benign_intervention_rate = benign_non_allow_steps / active_benign_steps
```

Trong đó `non_allow = RateLimit + Redirect + Block` — 3 mức severity rất khác. Trộn chung làm mất signal.

Guide có `benign_harm_score` weighted để bù:

```
benign_harm_score = 1·RateLimit + 2·Redirect + 3·Block
```

Nhưng **trọng số 1, 2, 3 là arbitrary**:
- Không có biện minh empirical.
- Không có biện minh theo lý thuyết vận hành.
- Tại sao không `1, 5, 10`? Hay `1, 3, 9`? Hay theo log?

Nếu hội đồng hỏi *"tại sao trọng số 1/2/3?"* → không có câu trả lời dựa trên data.

**Fix**:
- Biện minh trọng số bằng user study, domain literature, hoặc cost model cụ thể.
- Hoặc report 3 metric riêng: `benign_ratelimit_rate`, `benign_redirect_rate`, `benign_block_rate` — để người đọc tự diễn giải theo cost function riêng của họ.
- Hoặc chạy sensitivity analysis: thay trọng số, xem kết luận có đổi không.

### 2.7. Không có Pareto curve cho trade-off claim

Goal 3 claim **"Solve the trade-off between Security and Availability"**. Benchmark chỉ có:
- **1 điểm** PPO (với reward weights cố định).
- **1 điểm** DQN (với reward weights cố định).

Một điểm **không phải** trade-off curve. Không thể kết luận PPO *navigate* trade-off tốt hơn từ 1 điểm.

Để chứng minh trade-off claim một cách thực nghiệm, cần:

1. Train PPO với nhiều reward weights khác nhau — ví dụ hệ số service damage penalty $\alpha \cdot F_{24}$ với $\alpha \in \{0.05, 0.12, 0.25, 0.5, 1.0\}$.
2. Tương tự DQN.
3. Vẽ scatter plot: trục x = `benign_intervention_rate`, trục y = `mitigation_rate`. Mỗi point là một config.
4. Vẽ đường Pareto frontier cho cả hai thuật toán.
5. Kiểm tra Pareto của PPO có dominate Pareto của DQN không.

Hiện tại chỉ có 1 point each → **không đủ bằng chứng cho claim trade-off**. Đây là lỗ hổng lớn nhất về mặt khoa học.

### 2.8. Bảng chính thiếu confidence interval

Bảng "Raw defensive performance" (mục 7 của guide):

```
PPO | 58.80 | 97.65 | 90.81 | 0.0644
DQN | 60.71 | 99.54 | 92.26 | 0.0583
```

Chỉ có mean, **không có std hoặc CI**. Không biết:
- `58.80` là `58.80 ± 0.5` hay `58.80 ± 20`?
- DQN `60.71` có thực sự > PPO `58.80` không, hay nằm trong CI trùng?

Đây là chuẩn ML reporting bị vi phạm.

**Fix**: Report `mean ± std` (n=5 seeds) hoặc `mean [95% CI]` bằng bootstrap. Tất cả bảng chính phải có error bars.

### 2.9. Claim "fair" thiếu disclosure về training protocol

Guide claim benchmark fair vì cùng env, seeds, checkpoint policy. Nhưng thiếu disclosure quan trọng:

- **Hyperparameter tuning budget**: PPO đã được tune cho bài toán này từ lâu (có `runs/run_34d_v13`, chứng tỏ đã lặp v1–v13). DQN và A2C có được tune tương tự không, hay chỉ dùng default stable-baselines3? Nếu DQN/A2C default và chưa tune, **fairness đã bị phá từ gốc**.
- **Total compute**: 3 thuật toán chạy cùng 500k timesteps? Hay PPO được train lâu hơn/ngắn hơn?
- **Architecture**: policy network của 3 thuật toán có cùng hidden size, activation, depth không?

Không có disclosure này thì "fair" chỉ là claim, không verify được. Hội đồng experienced sẽ nhận ra ngay.

**Fix**: Thêm bảng "Training protocol equivalence" liệt kê:

| Thuật toán | Tuning iterations | Hidden architecture | Total timesteps | Training wall-clock |
|---|---|---|---|---|
| PPO | ? | ? | ? | ? |
| DQN | ? | ? | ? | ? |
| A2C | ? | ? | ? | ? |

### 2.10. FAQ 25 câu = defensive posture, không phải evidence

25 câu FAQ của guide phần lớn là **giải thích tại sao kết quả không xấu như nhìn**, chứ không phải bằng chứng PPO tốt:

- Q1: "Nếu DQN cao hơn thì sao?" → giải thích
- Q7: "Sao radar chart DQN chìa ngoài?" → giải thích scale
- Q8: "Sao PPO và DQN nhìn ngang nhau trên chart?" → giải thích scale
- Q15: "Có phải cherry-pick metric không?" → phản biện
- Q23: "Sao không chỉnh reward để PPO thắng?" → giải thích methodology
- Q24: "PPO chỉ hơn ở metric phụ thì sao?" → phản biện

Đây là **defensive writing** — dấu hiệu người viết biết kết quả yếu ở một số góc và đang dựng rào chắn.

Hội đồng experienced sẽ đọc FAQ dài này và nghĩ: *"nếu phải giải thích nhiều như vậy, có lẽ benchmark chưa đủ chặt về thiết kế."*

**Fix**:
- Cắt FAQ còn 5–7 câu cốt lõi.
- Nếu cần 25 câu để bảo vệ, đó là dấu hiệu phải **redesign benchmark**, không phải viết thêm giải thích.
- Mỗi câu FAQ còn lại phải link tới một metric/plot cụ thể, không phải reasoning thuần.

---

## 3. Bảng tổng kết: có gì, thiếu gì

| Yêu cầu | Có | Thiếu |
|---|---|---|
| Chọn thuật toán RL tốt nhất trong 3 | ✅ | - |
| Tách trục raw defense vs benign safety | ✅ | - |
| Stress mode (missing_prob, drift_max) | ✅ | - |
| p-value + Cohen's d | ✅ | Nhưng n=5 quá nhỏ |
| Chứng minh RL đáng dùng (vs non-RL) | ❌ | **Baseline non-RL (CRS, Snort, ML)** |
| Đo trên traffic thật | ❌ | **Evaluation replay / live Mininet** |
| Attack-type breakdown | ❌ | **Per-attack F1** |
| Real-time claim | ❌ | **Latency benchmark** |
| Detection claim (goal 2) | ❌ | **Detection metric khác action** |
| Trade-off claim (goal 3) | ⚠️ | **Pareto curve với reward sweep** |
| Confidence interval | ❌ | **mean ± std trên mọi bảng** |
| Training protocol fairness disclosure | ⚠️ | **Bảng equivalence 3 thuật toán** |
| Attack-class confusion matrix | ❌ | **Per-class CM** |

---

## 4. Ba fix quan trọng nhất (nếu còn thời gian có hạn)

Nếu phải ưu tiên, chọn 3 việc sau — mỗi việc trả lời một câu hỏi hội đồng **chắc chắn sẽ hỏi**:

### Fix #1: Thêm ModSecurity CRS baseline

**Trả lời câu**: *"Tại sao phải dùng RL?"*

- Repo đã có sẵn `REQUEST-941/942.conf`.
- Chạy CRS trên cùng tập test attack (SQLi, XSS).
- Đo F1 hoặc mitigation rate của CRS.
- So với PPO — nếu PPO không beat CRS, phải thừa nhận; nếu beat, đây là bằng chứng mạnh nhất cho giá trị của đồ án.
- **Ước lượng thời gian**: 1–2 ngày.

### Fix #2: Evaluate trên replay mode (traffic thật)

**Trả lời câu**: *"Mock env có phản ánh thực tế không?"*

- Dùng `training_data.jsonl` từ `infer.py --label` làm evaluation set.
- Chạy model hiện tại trên replay mode.
- Đo lại các metric chính.
- Bảng "mock vs replay" cho mỗi metric chính.
- Nếu gap nhỏ → generalize tốt. Nếu gap lớn → thừa nhận limitation, nhưng ít nhất có số.
- **Ước lượng thời gian**: 0.5–1 ngày (nếu đã có `training_data.jsonl` sẵn).

### Fix #3: Per-attack F1 breakdown

**Trả lời câu**: *"Agent handle được những loại tấn công gì?"*

- Label mỗi evaluation step theo attack type (đã có `ip_type`).
- Tính confusion matrix và F1 per class: benign, noisy_normal, scan, flood, sqli, xss, brute.
- Bảng: thuật toán × attack type → F1.
- Nếu model làm tốt tất cả — slide goals được support. Nếu chỉ tốt một vài loại — thu hẹp scope slide tương ứng.
- **Ước lượng thời gian**: 0.5 ngày (chỉ cần thêm logic aggregation trên kết quả eval có sẵn).

---

## 5. Các fix phụ (nếu dư thời gian)

- Thêm **mean ± std** vào mọi bảng số.
- Đổi `service_damage_auc` → `mean_service_damage` (fix terminology).
- Biện minh weight `1, 2, 3` của `benign_harm_score` hoặc chạy sensitivity analysis.
- Cắt FAQ từ 25 câu xuống 5–7 câu.
- Thêm bảng training protocol equivalence cho 3 thuật toán.
- Đổi t-test → Mann-Whitney U test cho robustness với n=5.
- Thêm **latency benchmark** (đã có script `System/benchmark_latency.py`) vào report benchmark để support claim "real-time".

---

## 6. Kết luận

Benchmark hiện tại **chặt chẽ về mặt kỹ thuật thống kê trong phạm vi đã đặt ra** — tách trục, có p-value, có stress mode, không cherry-pick thô thiển. Tốt hơn mức trung bình của thesis cùng level.

Nhưng benchmark **không khớp với mục tiêu đồ án**:

| Mục tiêu đồ án | Trạng thái |
|---|---|
| Autonomous real-time defense | Không được benchmark kiểm chứng |
| Observe → Detect → Decide | "Detect" stage không tồn tại trong metric |
| Solve Security ↔ Availability trade-off | Chỉ có 1 điểm trên trade-off, không phải curve |
| Dùng RL thay vì rule-based | Không có baseline rule-based để so |

Benchmark đang **đo đúng công cụ nhưng đo sai thứ**. Nếu không bổ sung ít nhất **Fix #1 (baseline non-RL)** và **Fix #2 (replay evaluation)**, hội đồng có thể kết luận: *"Nhóm chọn đúng thuật toán RL, nhưng chưa chứng minh được RL là lựa chọn đúng cho bài toán."*

Đây là lỗ hổng nghiêm trọng hơn bất kỳ lỗi thống kê nào trong benchmark hiện tại.
