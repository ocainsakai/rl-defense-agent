# Benchmark Report Guide: PPO vs DQN vs A2C

Tài liệu này dùng để bàn giao cho thành viên nhóm khi viết phần benchmark vào báo cáo. Mục tiêu là trình bày kết quả một cách **fair**, không "ép" PPO thắng toàn diện, nhưng vẫn chỉ ra đúng lợi thế của PPO ở khía cạnh **benign-safety**, **availability**, và **security-usability tradeoff**.

Nguồn số liệu hiện tại:

- `AI RL/Benchmark/results/benchmark_results.json`
- Script đánh giá: `AI RL/Benchmark/evaluate_all.py`
- Metric helpers: `AI RL/Benchmark/metrics.py`
- Chart: `AI RL/Benchmark/charts/`

## 1. Thông điệp chính cần giữ

Kết luận đúng và cân bằng:

> DQN đạt hiệu năng phòng thủ thô tốt hơn, đặc biệt ở reward, mitigation rate, exact response và service damage. Tuy nhiên, PPO có lợi thế về security-usability tradeoff: PPO vẫn giữ mitigation cao nhưng can thiệp lên benign traffic ít hơn đáng kể, giúp bảo toàn availability tốt hơn trong các bối cảnh cần hạn chế ảnh hưởng đến người dùng hợp lệ.

Không nên viết:

> PPO tốt hơn DQN toàn diện.

Nên viết:

> DQN wins raw defensive performance, while PPO wins benign-safety / availability-preserving tradeoff.

## 2. Vì sao benchmark này fair?

Benchmark này fair vì các model được so sánh theo cùng protocol:

- Cùng môi trường chính: `env_ids_harder.py`
- Cùng tập train seeds: `42, 123, 456, 789, 1337`
- Cùng tập eval seeds: `1001, 1002, 1003, 1004, 1005`
- Mỗi train seed được đánh giá trên `5 eval seeds x 6 episodes = 30 episodes`
- Sử dụng checkpoint final-primary, không chọn riêng best checkpoint để làm đẹp kết quả
- Eval deterministic: `model.predict(..., deterministic=True)`, nghĩa là model luôn chọn action nó tin nhất, không sampling ngẫu nhiên ở lúc đánh giá
- Có 4 eval modes tách rõ 2 trục: session behavior và noise/drift stress

Eval modes:

| Mode | session_block_size | missing_prob | drift_max | Ý nghĩa |
|---|---:|---:|---:|---|
| `round_robin` | 0 | 0.08 | 0.35 | Normal IID-like evaluation |
| `round_robin_stress` | 0 | 0.15 | 0.50 | Stress noise/drift nhưng giữ round-robin |
| `session_20` | 20 | 0.08 | 0.35 | Closed-loop/session evaluation |
| `session_20_stress` | 20 | 0.15 | 0.50 | Stress noise/drift trong closed-loop/session |

Điểm quan trọng khi viết report:

> Không so `round_robin` trực tiếp với `session_20_stress` để kết luận về noise, vì như vậy đổi cùng lúc cả session mode và noise/drift. Muốn nói về stress/noise thì phải so cùng session setting: `round_robin` với `round_robin_stress`, hoặc `session_20` với `session_20_stress`.

## 3. Ý nghĩa các metric chính

### `mean_reward`

Ý nghĩa:

- Tổng reward trung bình mỗi episode.
- Cao hơn là tốt hơn.
- Đây là metric tổng hợp theo reward function của môi trường.

Cách viết:

> Mean reward captures the overall objective optimized by the RL agent. Higher values indicate better alignment with the environment reward design.

Lưu ý:

- Reward cao không có nghĩa là model tốt hơn ở mọi khía cạnh vận hành.
- Một model có thể reward cao hơn nhưng vẫn gây nhiều can thiệp hơn lên benign users.

### `mitigation_rate`

Ý nghĩa:

- Tỷ lệ active attack steps được xử lý bằng action có tính mitigation đúng.
- Cao hơn là tốt hơn.

Công thức khái niệm:

```text
mitigation_rate = mitigated_active_attack_steps / active_attack_steps * 100
```

Cách viết:

> Mitigation rate measures how often the policy applies a meaningful defensive action to active attack traffic.

Diễn giải kết quả hiện tại:

- DQN thường cao hơn PPO ở mitigation rate.
- Điều này cho thấy DQN aggressive hơn và bắt attack mạnh hơn một chút.

### `exact_response_rate`

Ý nghĩa:

- Tỷ lệ active steps mà action của model trùng đúng action tối ưu theo taxonomy.
- Cao hơn là tốt hơn.

Ví dụ mapping action:

```text
benign        -> Allow
noisy_normal  -> RateLimit
L7 attacks    -> Redirect
scan/flood    -> Block
```

Cách viết:

> Exact response rate measures whether the agent selected the expected action for each traffic type, not merely whether it mitigated the attack.

Lưu ý:

- DQN cao hơn PPO ở metric này.
- Đây là bằng chứng cho phần "DQN wins raw response quality".

### `service_damage_auc`

Ý nghĩa:

- Mean step damage, dùng như proxy cho thiệt hại dịch vụ.
- Thấp hơn là tốt hơn.

Cách viết:

> Service damage AUC summarizes accumulated service impact during evaluation. Lower values indicate less residual damage.

Diễn giải hiện tại:

- DQN thấp hơn PPO ở metric này.
- Do đó không nên claim PPO thắng toàn diện về service damage.

## 4. Các metric benign-safety và availability

Đây là nhóm metric quan trọng để giải thích lợi thế của PPO.

### `benign_intervention_rate`

Ý nghĩa:

- Tỷ lệ benign traffic bị model can thiệp bằng bất kỳ action nào khác `Allow`.
- Thấp hơn là tốt hơn.

Công thức:

```text
benign_intervention_rate =
    benign_non_allow_steps / active_benign_steps * 100
```

Trong đó `non-Allow` gồm:

```text
RateLimit + Redirect + Block
```

Lưu ý wording:

- Không gọi trần là `false positive rate`.
- Gọi là `benign intervention rate` hoặc `broad false-positive harm proxy`.

Vì sao quan trọng:

- Rate-limit nhầm user thật làm giảm trải nghiệm.
- Redirect nhầm user thật làm sai luồng nghiệp vụ.
- Block nhầm user thật ảnh hưởng trực tiếp đến availability.
- IDS/WAF không chỉ cần chặn attack, mà còn phải tránh phá traffic hợp lệ.

Cách viết:

> Benign intervention rate measures how often legitimate users receive any non-Allow action. It is a broad operational disruption proxy rather than a pure false-positive block rate.

Kết quả hiện tại PPO vs DQN:

| Mode | PPO | DQN | p-value | Interpretation |
|---|---:|---:|---:|---|
| `round_robin` | 0.650 | 1.392 | 0.0278 | significant |
| `round_robin_stress` | 0.517 | 1.350 | 0.0021 | significant |
| `session_20` | 0.525 | 1.267 | 0.0228 | significant |
| `session_20_stress` | 0.425 | 1.158 | 0.0046 | significant |

Kết luận hợp lệ:

> PPO significantly reduces benign interventions compared with DQN across all evaluation modes.

### `benign_harm_score`

Ý nghĩa:

- Metric có trọng số cho mức độ gây hại lên benign traffic.
- Thấp hơn là tốt hơn.

Công thức:

```text
benign_harm_score =
    1 * benign_ratelimit_rate
  + 2 * benign_redirect_rate
  + 3 * benign_block_rate
```

Ý tưởng:

- RateLimit benign là nhẹ nhất.
- Redirect benign nặng hơn.
- Block benign nặng nhất.

Cách viết:

> Benign harm score is a severity-weighted version of benign intervention. It penalizes stronger benign disruption more heavily.

Kết quả hiện tại PPO vs DQN:

| Mode | PPO | DQN | p-value | Interpretation |
|---|---:|---:|---:|---|
| `round_robin` | 0.792 | 1.392 | 0.1228 | trend only |
| `round_robin_stress` | 0.650 | 1.350 | 0.0256 | significant |
| `session_20` | 0.625 | 1.267 | 0.0741 | trend only |
| `session_20_stress` | 0.558 | 1.158 | 0.0486 | significant |

Kết luận hợp lệ:

> PPO consistently lowers severity-weighted benign harm, with statistically significant reductions under stress settings.

Không nên viết:

> PPO significantly reduces benign harm score in all modes.

Vì ở `round_robin` và `session_20`, p-value chưa nhỏ hơn 0.05.

## 5. Các metric efficiency / tradeoff

Các metric này dùng để mô tả độ lớn của tradeoff. Không dùng chúng làm bằng chứng thống kê chính vì ratio metric nhạy khi denominator rất nhỏ.

### `mitigation_efficiency`

Ý nghĩa:

- Mỗi 1% benign intervention đổi lại được bao nhiêu % attack mitigation.
- Cao hơn là tốt hơn.

Công thức:

```text
mitigation_efficiency =
    mitigation_rate / benign_intervention_rate
```

Ví dụ `round_robin`:

```text
PPO = 97.65 / 0.65 = 150.2
DQN = 99.54 / 1.39 = 71.5
```

Diễn giải:

- DQN mitigation cao hơn PPO một chút.
- Nhưng DQN can thiệp benign nhiều hơn khoảng 2 lần.
- Vì vậy PPO có efficiency cao hơn: mitigation gần DQN nhưng "tốn" ít benign disruption hơn.

Cách viết:

> Mitigation efficiency summarizes the amount of attack mitigation obtained per unit of benign-user intervention. It should be interpreted as a security-usability tradeoff indicator, not as a replacement for raw mitigation or reward.

### `weighted_mitigation_efficiency`

Ý nghĩa:

- Phiên bản nghiêm hơn của `mitigation_efficiency`.
- Denominator dùng `benign_harm_score`, nên redirect/block benign bị phạt nặng hơn rate-limit benign.
- Cao hơn là tốt hơn.

Công thức:

```text
weighted_mitigation_efficiency =
    mitigation_rate / benign_harm_score
```

Cách viết:

> Weighted mitigation efficiency applies the same tradeoff idea but uses severity-weighted benign harm as the denominator, making it more conservative when policies redirect or block benign traffic.

Kết quả tradeoff PPO vs DQN:

| Mode | Metric | PPO | DQN |
|---|---|---:|---:|
| `round_robin` | `mitigation_efficiency` | 150.2 | 71.5 |
| `round_robin` | `weighted_mitigation_efficiency` | 123.3 | 71.5 |
| `round_robin_stress` | `mitigation_efficiency` | 186.5 | 73.1 |
| `round_robin_stress` | `weighted_mitigation_efficiency` | 148.3 | 73.1 |
| `session_20` | `mitigation_efficiency` | 185.9 | 78.6 |
| `session_20` | `weighted_mitigation_efficiency` | 156.1 | 78.6 |
| `session_20_stress` | `mitigation_efficiency` | 226.8 | 85.3 |
| `session_20_stress` | `weighted_mitigation_efficiency` | 172.6 | 85.3 |

Kết luận hợp lệ:

> PPO has higher efficiency ratios because it achieves near-DQN mitigation while causing substantially fewer benign interventions.

Không nên viết:

> PPO is statistically better because mitigation_efficiency is higher.

Lý do:

- Ratio metric dễ dao động mạnh khi denominator nhỏ.
- Bằng chứng thống kê chính nên dựa vào `benign_intervention_rate` và `benign_harm_score`.

## 6. Cách hiểu p-value, stars và Cohen's d

Benchmark dùng independent two-sample t-test qua 5 train seeds.

Quy ước:

| p-value | Label | Cách hiểu |
|---:|---|---|
| `< 0.001` | `***` | Very strong significance |
| `< 0.01` | `**` | Strong significance |
| `< 0.05` | `*` | Statistically significant |
| `>= 0.05` | `ns` | Trend only, chưa đủ kết luận significant |

Giải thích ngắn:

> p-value đo khả năng chênh lệch quan sát được chỉ do random seed nếu hai thuật toán thật ra không khác nhau. p < 0.05 nghĩa là khả năng này dưới 5%, nên thường được xem là có ý nghĩa thống kê.

Vì `n=5` train seeds là nhỏ, khi viết report cần đọc p-value cùng với:

- Chiều metric: cao hơn tốt hơn hay thấp hơn tốt hơn
- Effect size: Cohen's d
- Xu hướng nhất quán qua các eval modes

Cohen's d:

| `abs(d)` | Effect size |
|---:|---|
| `< 0.5` | small |
| `0.5 - 0.8` | medium |
| `>= 0.8` | large |

## 7. Bảng số chính nên đưa vào report

### Raw defensive performance, `round_robin`

| Algo | Mean Reward | Mitigation % | Exact Response % | Service Damage AUC |
|---|---:|---:|---:|---:|
| PPO | 58.80 | 97.65 | 90.81 | 0.0644 |
| DQN | 60.71 | 99.54 | 92.26 | 0.0583 |
| A2C | 24.46 | 95.97 | 85.59 | 0.0764 |

Diễn giải:

> DQN leads on raw reward, mitigation, exact response and service damage. This supports the statement that DQN has stronger raw defensive performance in the normal round-robin setting.

### Benign-safety tradeoff, `round_robin`

| Algo | Mitigation % | Benign Intervention % | Benign Harm Score | Mitig / BenignInt | Mitig / BenignHarm |
|---|---:|---:|---:|---:|---:|
| PPO | 97.65 | 0.65 | 0.79 | 150.2 | 123.3 |
| DQN | 99.54 | 1.39 | 1.39 | 71.5 | 71.5 |
| A2C | 95.97 | 22.27 | 22.27 | 4.3 | 4.3 |

Diễn giải:

> Although DQN has slightly higher mitigation, PPO causes substantially fewer benign interventions, resulting in higher security-usability efficiency.

## 8. Cách viết phần kết quả trong report

### Đoạn tiếng Anh khuyến nghị

```text
The benchmark shows a clear distinction between raw defensive performance and operational benign-safety. DQN achieves the strongest raw performance, with higher mean reward, mitigation rate, exact response rate, and lower service damage. However, PPO provides a better availability-preserving security tradeoff. It maintains high mitigation while significantly reducing interventions on benign traffic across all evaluation modes. The severity-weighted benign harm score is also consistently lower for PPO and becomes statistically significant under stress settings. Therefore, DQN is preferable when maximizing raw attack mitigation is the primary objective, while PPO is preferable when minimizing disruption to legitimate users is operationally important.
```

### Đoạn tiếng Việt khuyến nghị

```text
Kết quả benchmark cho thấy sự khác biệt rõ giữa hiệu năng phòng thủ thô và tính an toàn vận hành đối với benign traffic. DQN đạt kết quả tốt hơn ở các chỉ số thô như mean reward, mitigation rate, exact response rate và service damage. Tuy nhiên, PPO có lợi thế ở tradeoff bảo mật-availability: PPO vẫn duy trì mitigation cao trong khi giảm đáng kể can thiệp lên benign traffic ở tất cả eval modes. Benign harm score có trọng số cũng thấp hơn nhất quán với PPO và đạt ý nghĩa thống kê trong các stress settings. Vì vậy, DQN phù hợp hơn khi mục tiêu chính là tối đa hóa raw attack mitigation, còn PPO phù hợp hơn khi hệ thống cần hạn chế ảnh hưởng đến người dùng hợp lệ.
```

### Câu ngắn để chốt slide

```text
DQN wins raw defense; PPO wins availability-preserving defense.
```

Hoặc:

```text
DQN is more aggressive; PPO is more benign-safe.
```

## 9. Những câu không nên viết

Tránh các câu sau:

```text
PPO is better than DQN.
PPO wins the benchmark.
PPO has higher mitigation.
PPO significantly reduces benign_harm_score in all modes.
mitigation_efficiency proves PPO is statistically better.
PPO performs better because it uses softmax during evaluation.
```

Lý do:

- DQN thật sự thắng một số metric cơ bản.
- `benign_harm_score` chưa significant ở normal modes.
- Efficiency ratios mô tả magnitude, không phải primary statistical evidence.
- Evaluation đang deterministic, không phải stochastic softmax sampling.

## 10. Những câu nên viết

Nên dùng:

```text
DQN achieves stronger raw defensive performance.
PPO achieves a better security-usability tradeoff.
PPO significantly reduces benign intervention across all evaluation modes.
PPO consistently lowers severity-weighted benign harm, with significant reductions under stress settings.
Efficiency ratios summarize how much mitigation is obtained per unit of benign disruption.
All policies are evaluated deterministically for reproducibility.
```

## 11. Checklist trước khi nộp report

Trước khi đưa số vào báo cáo, kiểm tra:

- `python3 evaluate_all.py` đã chạy sau khi sửa code
- `python3 plot_results.py` đã chạy sau khi cập nhật JSON
- `benchmark_results.json` có `_metadata.statistical_methods`
- `_statistics.*.ppo_vs_dqn.*.significance` tồn tại
- Có đủ 4 eval modes:
  - `round_robin`
  - `round_robin_stress`
  - `session_20`
  - `session_20_stress`
- Không report CI của ratio metrics như bằng chứng chính nếu CI quá lớn
- Kết luận tách rõ:
  - DQN thắng raw defensive performance
  - PPO thắng benign-safety / availability-preserving tradeoff

## 12. Một câu giải thích cực ngắn cho người đọc không chuyên

Nếu cần giải thích cho hội đồng hoặc thành viên không chuyên:

> DQN giống một hệ thống phòng thủ mạnh tay hơn: bắt attack tốt hơn một chút nhưng dễ làm phiền user hợp lệ hơn. PPO giống một hệ thống cân bằng hơn: vẫn chặn attack tốt, nhưng ít can thiệp nhầm vào benign user, nên tốt hơn cho availability.

## 13. FAQ: Các câu hỏi hội đồng dễ hỏi và cách trả lời

Phần này dùng để chuẩn bị phản biện. Nguyên tắc chung: không cố nói PPO thắng toàn diện. Câu trả lời nên tách rõ hai trục:

```text
DQN = raw defensive performance tốt hơn
PPO = benign-safety / availability-preserving tradeoff tốt hơn
```

### 1. Nếu DQN có reward cao hơn, mitigation cao hơn, service damage thấp hơn thì DQN tốt hơn PPO chứ?

Trả lời ngắn:

> Đúng, nếu mục tiêu chính là tối đa hóa khả năng phòng thủ thô và giảm attack damage, DQN tốt hơn PPO. Nhóm không kết luận PPO thắng toàn diện. Kết luận là PPO tốt hơn ở tradeoff bảo toàn availability vì giảm can thiệp lên benign traffic.

Trả lời đầy đủ:

> Kết quả cho thấy DQN mạnh hơn ở raw defensive performance: reward cao hơn, mitigation cao hơn, exact response cao hơn và service damage thấp hơn. Tuy nhiên, hệ thống IDS/WAF thực tế không chỉ tối ưu chặn attack, mà còn cần hạn chế false positive và giảm ảnh hưởng đến người dùng hợp lệ. PPO có lợi thế ở khía cạnh đó vì benign_intervention_rate thấp hơn DQN một cách có ý nghĩa thống kê ở tất cả eval modes.

### 2. Attacker gây thiệt hại nhiều hơn mới nguy hiểm, vậy tại sao lại nhấn mạnh PPO?

Trả lời:

> Vì benchmark đang phân tích hai mục tiêu khác nhau. DQN phù hợp hơn nếu deployment ưu tiên security-first, tức giảm attack damage tối đa. PPO phù hợp hơn nếu deployment cần cân bằng security và availability, ví dụ hệ thống có nhiều user hợp lệ, nhạy cảm với rate-limit nhầm, timeout hoặc giảm trải nghiệm.

Câu chốt:

```text
DQN is security-aggressive; PPO is availability-preserving.
```

### 3. DQN chỉ rate-limit nhầm benign user, không block nhầm, vậy có nghiêm trọng không?

Trả lời:

> RateLimit nhẹ hơn Block, nên nhóm có thêm benign_harm_score để phân biệt mức độ nặng nhẹ. Tuy nhiên, rate-limit nhầm vẫn là can thiệp lên user hợp lệ: có thể gây chậm, timeout, giảm throughput hoặc ảnh hưởng giao dịch hợp lệ. Vì vậy benign_intervention_rate vẫn có ý nghĩa vận hành, còn benign_harm_score giúp đánh giá nghiêm khắc hơn theo mức độ tác động.

Nhấn mạnh:

```text
Block nhầm là nặng nhất, nhưng RateLimit nhầm không phải miễn phí.
```

### 4. Nếu reward đã phạt làm phiền benign user, tại sao DQN vẫn reward cao hơn?

Trả lời:

> Reward có phạt benign over-intervention, nhưng reward tổng còn chịu ảnh hưởng mạnh từ mitigation, exact response, service damage và escalation behavior. DQN mất điểm vì rate-limit nhầm benign nhiều hơn, nhưng được bù nhiều hơn nhờ giảm under-mitigation, kiểm soát service damage tốt hơn và exact response cao hơn.

Ví dụ nói miệng:

```text
DQN bị trừ 1 điểm vì làm phiền benign, nhưng được cộng 3 điểm vì chặn attack tốt hơn.
PPO ít bị trừ ở benign, nhưng mất điểm ở raw defense.
```

### 5. Vậy PPO có phải kém bảo mật hơn DQN không?

Trả lời:

> Nếu chỉ xét raw attack suppression thì DQN tốt hơn. Nhưng PPO không kém theo nghĩa thất bại phòng thủ: PPO vẫn đạt mitigation rất cao, chỉ thấp hơn DQN một phần nhỏ. Lợi thế của PPO là đạt mitigation gần DQN với ít benign disruption hơn nhiều.

Cách viết:

```text
PPO is not the strongest raw defender, but it is the better availability-preserving defender.
```

### 6. `service_damage_auc` đo gì?

Trả lời:

> `service_damage_auc` là mean step damage, đo mức thiệt hại còn lại lên service sau action phòng thủ. Nó tăng khi attack còn đi vào web thật hoặc vẫn hiện diện. Nó giảm khi traffic độc hại bị redirect sang honeypot hoặc bị block.

Công thức khái niệm:

```text
service_damage_auc = average(step_damage over all evaluation steps)
```

Trong env, step damage là F24:

```text
F24 = ServiceDamage = attack_conf x web exposure / residual presence
```

### 7. Nếu `service_damage_auc` thấp hơn là tốt, tại sao ở radar chart DQN lại chìa ra ngoài?

Trả lời:

> Radar chart đã chuẩn hóa theo quy ước vòng ngoài là tốt hơn. Với metric thấp hơn tốt hơn như service damage, chart đảo chiều điểm. Vì DQN có raw service_damage_auc thấp hơn PPO, nên DQN ra ngoài hơn ở trục đó là đúng.

Nên sửa label:

```text
Svc Damage -> Low Svc Damage
```

hoặc:

```text
Svc Damage -> Damage Control
```

### 8. Trên radar chart `Benign Safety` nhìn PPO và DQN gần ngang nhau, sao lại nói PPO tốt hơn rõ?

Trả lời:

> Vì radar chart đang dùng scale 0-100. Benign intervention của PPO là 0.65%, DQN là 1.39%; cả hai đều rất nhỏ trên thang 0-100 nên nhìn gần nhau. Nhưng DQN thực tế can thiệp benign nhiều hơn khoảng 2.1 lần. Efficiency ratio và bảng benign-safety mới thể hiện khác biệt này rõ hơn.

Tính nhanh:

```text
DQN / PPO = 1.39 / 0.65 ≈ 2.14 lần
```

### 9. `benign_intervention_rate` có phải false positive rate không?

Trả lời:

> Không hoàn toàn. Nó là broad false-positive harm proxy. Metric này tính mọi non-Allow action trên benign traffic, gồm RateLimit, Redirect và Block. False positive block chỉ là một phần của nó.

Viết chuẩn:

```text
benign_intervention_rate = broad operational disruption proxy for benign users
```

Không viết:

```text
benign_intervention_rate = false positive rate tuyệt đối
```

### 10. Noisy user có nên bị RateLimit không?

Trả lời:

> Có. Trong benchmark, `noisy_normal` là nhóm riêng, không phải benign sạch. Action tối ưu cho noisy_normal là RateLimit. Benign sạch thì action đúng là Allow.

Mapping:

```text
benign        -> Allow
noisy_normal  -> RateLimit
L7 attacks    -> Redirect
scan/flood    -> Block
```

Nhấn mạnh:

> benign_intervention_rate chỉ tính trên benign sạch, không tính noisy_normal bị RateLimit.

### 11. Vậy nếu DQN RateLimit noisy tốt hơn PPO thì DQN vẫn có điểm mạnh đúng không?

Trả lời:

> Đúng. DQN có noisy_exact_rate cao hơn PPO một chút, nghĩa là DQN xử lý noisy_normal bằng RateLimit tốt hơn. Đây là một phần lý do DQN có exact response và reward cao hơn. Nhưng PPO vẫn có lợi thế ở việc ít can thiệp benign sạch hơn.

### 12. Vì sao A2C có Honeypot Capture cao nhất?

Trả lời:

> Honeypot capture chỉ đo riêng việc L7 attack có bị Redirect hay không. A2C gần như Redirect toàn bộ L7 nên metric này cao. Nhưng A2C không tốt tổng thể vì benign_intervention rất cao, reward thấp, exact response thấp và dynamic escalation kém.

Số cần nhớ:

```text
A2C honeypot_capture_rate ≈ 99.95%
A2C benign_intervention_rate ≈ 22.27%
A2C dynamic_exact_response_rate ≈ 65.61%
```

Câu chốt:

```text
A2C over-prefers Redirect.
```

### 13. Honeypot Capture cao có phải lúc nào cũng tốt không?

Trả lời:

> Không. Honeypot Capture cao là tốt nếu nó không đi kèm over-redirect benign/noisy traffic và không làm chậm escalation khi cần block. Vì vậy phải đọc cùng benign-safety và dynamic escalation metrics.

Cách viết:

```text
Honeypot capture is a useful L7 metric, but not sufficient as an overall performance metric.
```

### 14. Vì sao `mitigation_efficiency` của PPO cao hơn DQN nhiều dù mitigation_rate thấp hơn?

Trả lời:

> Vì efficiency là tỷ lệ mitigation trên benign intervention. DQN mitigation cao hơn PPO một chút, nhưng benign intervention cũng cao hơn nhiều. Do mẫu số của PPO nhỏ hơn, PPO có mitigation per benign intervention cao hơn.

Tính nhanh:

```text
PPO = 97.65 / 0.65 = 150.2
DQN = 99.54 / 1.39 = 71.5
```

Câu chốt:

```text
DQN catches slightly more attacks, PPO spends much less benign disruption per mitigation.
```

### 15. Có phải nhóm đang cherry-pick metric để PPO thắng không?

Trả lời:

> Không, vì nhóm vẫn trình bày đầy đủ các metric mà DQN thắng: reward, mitigation, exact response và service damage. Metric mới không thay thế metric chính, mà bổ sung góc nhìn vận hành về benign-safety và availability.

Cách nói:

```text
We do not claim PPO wins overall; we claim PPO wins the benign-safety tradeoff.
```

### 16. Vì sao không dùng `mitigation_efficiency` làm bằng chứng thống kê chính?

Trả lời:

> Vì ratio metric nhạy khi denominator nhỏ. Nếu benign intervention gần 0, ratio có thể rất lớn. Do đó nhóm dùng p-value của benign_intervention_rate làm bằng chứng thống kê chính, còn efficiency ratio chỉ mô tả độ lớn tradeoff.

Câu chốt:

```text
Statistical evidence = benign_intervention_rate.
Tradeoff magnitude = mitigation_efficiency.
```

### 17. p-value < 0.05 nghĩa là gì?

Trả lời:

> p-value < 0.05 nghĩa là nếu thật ra hai thuật toán không khác nhau, xác suất thấy chênh lệch lớn như kết quả quan sát được do random seed chỉ dưới 5%. Vì vậy thường được xem là có ý nghĩa thống kê.

Nhưng cần caveat:

```text
n=5 seeds is small, so p-value should be read together with Cohen's d and direction.
```

### 18. Vì sao `benign_harm_score` ở normal mode chưa significant mà vẫn nhắc?

Trả lời ngắn:

> Vì `benign_harm_score` là supporting metric. PPO thấp hơn DQN ở cả 4 modes, nhưng ở 2 normal modes p-value chưa nhỏ hơn 0.05, nên chỉ được gọi là xu hướng tốt hơn. Ở 2 stress modes, p-value nhỏ hơn 0.05, nên có thể nói PPO giảm benign_harm_score có ý nghĩa thống kê trong stress settings.

Giải thích dễ hiểu:

```text
benign_harm_score thấp hơn = ít làm phiền benign user hơn, có tính nặng nhẹ.
PPO thấp hơn DQN ở tất cả modes.
Nhưng thống kê còn hỏi: chênh lệch này đủ chắc chưa, hay có thể do random seed?
```

Kết quả hiện tại:

| Mode | PPO | DQN | p-value | Cách đọc |
|---|---:|---:|---:|---|
| `round_robin` | 0.792 | 1.392 | 0.1228 | PPO tốt hơn về số, nhưng chỉ là trend |
| `round_robin_stress` | 0.650 | 1.350 | 0.0256 | PPO tốt hơn và significant |
| `session_20` | 0.625 | 1.267 | 0.0741 | PPO tốt hơn về số, nhưng chỉ là trend |
| `session_20_stress` | 0.558 | 1.158 | 0.0486 | PPO tốt hơn và significant |

Vì sao normal mode là `trend only`?

```text
p = 0.1228 và p = 0.0741 đều lớn hơn 0.05.
Nghĩa là chênh lệch nghiêng về PPO, nhưng chưa đủ chắc theo ngưỡng thống kê phổ biến.
```

Vì sao stress mode được nói mạnh hơn?

```text
p = 0.0256 và p = 0.0486 đều nhỏ hơn 0.05.
Nghĩa là dưới stress, khác biệt benign_harm_score giữa PPO và DQN đủ chắc hơn.
```

Ví dụ nói miệng:

```text
Normal mode giống như PPO đang dẫn điểm nhưng khoảng cách chưa đủ chắc.
Stress mode giống như PPO vẫn dẫn và khoảng cách đủ chắc để kết luận.
```

Nếu hội đồng hỏi:

> Vậy normal mode PPO có thật sự tốt hơn về benign_harm_score không?

Trả lời:

> Về giá trị trung bình thì PPO thấp hơn DQN ở normal mode, tức xu hướng tốt hơn. Nhưng vì p-value chưa dưới 0.05, nhóm không claim significant ở normal mode. Nhóm chỉ claim significant cho stress settings và dùng normal modes như bằng chứng xu hướng nhất quán.

Câu nên dùng:

```text
PPO consistently lowers severity-weighted benign harm, with significant reductions under stress settings.
```

Không nên viết:

```text
PPO significantly reduces benign_harm_score in all modes.
```

### 19. Vì sao phải có stress modes mới?

Trả lời:

> Stress modes kiểm tra generalization khi observation khó hơn: missing_prob tăng từ 0.08 lên 0.15 và drift_max tăng từ 0.35 lên 0.50. Benchmark tách stress theo cùng session setting để tránh confound.

So sánh đúng:

```text
round_robin        -> round_robin_stress
session_20         -> session_20_stress
```

Không so trực tiếp:

```text
round_robin        -> session_20_stress
```

### 20. Stress test có chứng minh PPO tốt hơn DQN không?

Trả lời ngắn:

> Không chứng minh PPO tốt hơn DQN toàn diện. Stress test cho thấy lợi thế của PPO về benign-safety / availability rõ hơn dưới điều kiện nhiễu và drift cao hơn. Nhưng DQN vẫn tốt hơn ở raw mitigation, exact response, reward và service damage.

Trả lời đầy đủ:

> Trong stress settings, PPO tiếp tục can thiệp benign ít hơn DQN và benign_harm_score đạt ý nghĩa thống kê. Điều này cho thấy khi môi trường khó hơn, PPO vẫn giữ lợi thế về hạn chế ảnh hưởng đến user hợp lệ. Tuy nhiên, DQN vẫn có mitigation_rate và service_damage tốt hơn, nên kết luận đúng là stress test làm rõ tradeoff giữa hai thuật toán, không phải đảo ngược kết quả tổng thể.

Số cần nhớ:

```text
round_robin_stress:
  Mitigation:          PPO 96.38%  vs DQN 98.65%   -> DQN tốt hơn
  Benign intervention: PPO 0.517%  vs DQN 1.350%   -> PPO tốt hơn
  Benign harm score:   PPO 0.650   vs DQN 1.350    -> PPO tốt hơn, p=0.0256
  Mitig efficiency:    PPO 186.5   vs DQN 73.1     -> PPO tốt hơn

session_20_stress:
  Mitigation:          PPO 96.39%  vs DQN 98.82%   -> DQN tốt hơn
  Benign intervention: PPO 0.425%  vs DQN 1.158%   -> PPO tốt hơn
  Benign harm score:   PPO 0.558   vs DQN 1.158    -> PPO tốt hơn, p=0.0486
  Mitig efficiency:    PPO 226.8   vs DQN 85.3     -> PPO tốt hơn
```

Câu nên dùng:

```text
Under stress, PPO's availability/benign-safety advantage becomes clearer, while DQN still leads in raw defensive performance.
```

Bản tiếng Việt:

```text
Trong stress test, lợi thế của PPO về benign-safety và availability rõ hơn, nhưng DQN vẫn tốt hơn ở raw mitigation và kiểm soát service damage.
```

Không nên viết:

```text
Stress test chứng minh PPO tốt hơn DQN toàn diện.
```

### 21. Nếu phải chọn một model deploy thì chọn PPO hay DQN?

Trả lời:

> Phụ thuộc mục tiêu triển khai. Nếu mục tiêu là giảm attack damage tối đa và chấp nhận rate-limit nhầm nhiều hơn, chọn DQN. Nếu mục tiêu là cân bằng bảo mật với availability, hạn chế ảnh hưởng đến user hợp lệ, chọn PPO.

Bảng quyết định:

| Mục tiêu | Model phù hợp hơn |
|---|---|
| Raw mitigation cao nhất | DQN |
| Reward cao nhất | DQN |
| Service damage thấp nhất | DQN |
| Ít can thiệp benign nhất | PPO |
| Availability-preserving defense | PPO |
| Môi trường nhạy với false positive | PPO |
| Môi trường chấp nhận aggressive defense | DQN |

### 22. Benchmark có fair với DQN không khi thêm metric mới?

Trả lời:

> Có, vì metric mới không xóa hoặc thay thế các metric DQN thắng. Báo cáo vẫn ghi rõ DQN thắng raw defense. Metric mới chỉ bổ sung một tiêu chí vận hành quan trọng: chi phí gây ra cho benign traffic.

Nói ngắn:

```text
Fair benchmark = show both wins and tradeoffs.
```

### 23. Vì sao không chỉnh reward để PPO thắng luôn?

Trả lời:

> Không nên chỉnh reward sau khi thấy kết quả vì sẽ tạo bias. Cách đúng là giữ reward/eval protocol, sau đó phân tích thêm các operational metrics. Nếu future work muốn tối ưu availability mạnh hơn, có thể thiết kế reward mới hoặc multi-objective optimization, nhưng kết quả hiện tại phải trình bày theo reward hiện hành.

### 24. Nếu hội đồng nói PPO chỉ hơn ở metric phụ thì trả lời sao?

Trả lời:

> Đúng, PPO hơn ở nhóm metric vận hành phụ nhưng quan trọng: benign-safety và availability. Trong hệ thống IDS/WAF thực tế, metric phụ này không nhỏ, vì false positive và intervention nhầm có thể gây downtime, giảm trải nghiệm hoặc ảnh hưởng người dùng hợp lệ. Vì vậy nhóm trình bày PPO như một lựa chọn cân bằng, không phải model thắng tuyệt đối.

### 25. Một câu kết luận cuối cùng nên nói trước hội đồng là gì?

Trả lời:

> Kết quả không cho thấy một thuật toán thắng tuyệt đối. DQN là lựa chọn tốt hơn cho mục tiêu phòng thủ mạnh nhất, còn PPO là lựa chọn tốt hơn khi cần cân bằng giữa mitigation và availability. Điểm đóng góp của benchmark là làm rõ tradeoff này thay vì chỉ nhìn reward hoặc mitigation rate.
