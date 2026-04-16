# Benchmark Problems & Roadmap

---

## 1. Trạng thái hiện tại (2026-04-15)

### Đã xác nhận

| Hạng mục | Trạng thái |
|---|---|
| Thursday-22-02-2018 (Brute Force + SQLi/XSS) | ✓ Chạy lại và verify được |
| stateless mode | ✓ Khớp tài liệu |
| window-reset mode | ✓ Khớp tài liệu |
| Tách stateless vs stateful trong báo cáo | ✓ Đã làm rõ |
| stateful ảnh hưởng bởi hold/escalate/auto-unblock | ✓ Đã note rõ trong methodology |

### Chưa xác nhận

| Hạng mục | Trạng thái |
|---|---|
| DDoS benchmark (Tuesday/Wednesday CIC-IDS2018) | ✗ Đã xóa pcap (disk), chưa có JSONL |
| Port Scan benchmark | ✗ Chưa có dataset |
| SQLi riêng (tách khỏi sqli_xss) | ✗ Chưa làm |
| XSS riêng (tách khỏi sqli_xss) | ✗ Chưa làm |

---

## 2. Các vấn đề còn tồn đọng

### 2.1 Benchmark DDoS chưa đủ

**Vấn đề:** Tuesday/Wednesday CIC-IDS2018 dùng LOIC-HTTP/LOIC-UDP/HOIC — pattern khác với hping3 mà model được train để detect.

- LOIC-HTTP: TCP handshake hoàn chỉnh → F2 ≈ 1.0, F6 cao → model có thể nhận nhầm thành brute_force → Redirect thay vì Block
- LOIC-UDP: không có SYN/ACK → F2 = 0 → model detect qua F1 cao (gần hping3 hơn)
- Distribution shift: training dùng MockIPBehavior (hping3-like), test dùng LOIC → recall DDoS có thể thấp hơn thực tế năng lực model

**Hướng fix:** Tải CIC-DDoS2019 (subset SYN flood) hoặc capture trực tiếp từ Mininet với hping3.

### 2.2 SQLi và XSS bị gộp

**Vấn đề:** Label `sqli_xss` gộp cả SQL Injection và XSS thành 1 class. Số liệu `88.9%` là recall gộp, không tách riêng từng loại.

**✓ ĐÃ SỬA (2026-04-15):** Label đã tách thành `xss` và `sqli` riêng trong `pcap_benchmark.py`. Kết quả mới:
- `brute_force`: 99.9% recall (stateless)
- `xss`: 89.3% recall (stateless) — 2202 rows
- `sqli`: 69.4% recall (stateless) — 49 rows

### 2.3 Số liệu benchmark nhìn "ảo" do metric và pipeline chưa thật sạch

#### a. `stateless` chưa phải "model-only" hoàn toàn

**Vấn đề:** `stateless` được mô tả là đánh giá thuần túy của model, nhưng pipeline `IDSDefenseAgent.predict()` vẫn có policy override: nếu PPO ra `Block` nhưng có tín hiệu SQLi/XSS → đổi thành `Redirect`. Số `99.9%`, `89.3%`, `69.4%` là **AI agent (PPO + policy guard)**, không phải raw PPO.

**✓ ĐÃ SỬA trong METHODOLOGY (2026-04-15):** Đã ghi rõ "AI agent accuracy" thay vì "model accuracy". Đã note policy override vẫn active trong stateless mode.

**Phản biện:** Với Thursday data (F1=6-7 pps, không có DDoS), PPO hiếm khi ra Block nên override hầu như không kích hoạt — ảnh hưởng thực tế đến số liệu là nhỏ. Tuy nhiên về mặt học thuật vẫn cần ghi đúng.

#### b. `mitigate_rate` được định nghĩa quá rộng

**Vấn đề:** `mitigate_rate = pred != Allow`, bao gồm cả RateLimit/Redirect/Block. Số `100% mitigate` không có nghĩa là action đúng loại, chỉ có nghĩa là "có chặn gì đó".

**✓ ĐÃ SỬA trong METHODOLOGY (2026-04-15):** Đã thêm cảnh báo định nghĩa rộng vào phần nhận xét và bảng giới hạn.

**Phản biện:** `mitigate_rate` vẫn là metric hữu ích cho câu hỏi vận hành: "hệ thống có bỏ sót attacker nào không?". Cần đọc cùng với `recall` (đúng action) để có bức tranh đầy đủ. Không nên bỏ metric này, chỉ cần diễn giải đúng.

#### c. SQLi có quá ít mẫu

**Vấn đề:** `sqli` chỉ 49 rows (window 14 phút). Số `69.4%` dễ dao động, không đủ để kết luận mạnh.

**Trạng thái:** Chưa fix — đây là giới hạn của dataset (window SQLi ngắn nhất trong Thursday). Không có cách tăng số rows mà không tải thêm dataset khác.

**Phản biện:** 49 rows vẫn đủ để quan sát xu hướng. Trong báo cáo nên trình bày kèm disclaimer: "SQLi window chỉ 14 phút, 49 samples — kết quả mang tính tham khảo".

#### d. Benign được sample giới hạn 500 rows

**Vấn đề:** Chỉ lấy 500 benign rows, false positive có thể đẹp hơn thực tế.

**Trạng thái:** Chưa fix. Có thể tăng `benign_cap` lên 2000-5000 nếu muốn.

**Phản biện:** 500 rows vẫn là sample đủ lớn để ước tính false positive rate. Việc cap là cần thiết để tránh class imbalance nghiêm trọng (benign >> attacker).

#### e. Chỉ benchmark trên 1 attacker IP

**Vấn đề:** Thursday chỉ có 1 attacker IP `18.218.115.60`. Chưa test variability giữa nhiều host.

**Trạng thái:** Giới hạn của dataset, không sửa được với Thursday data.

**Phản biện:** Đây là đặc điểm của CIC-IDS2018 (controlled lab environment). Model detect dựa trên feature pattern (F1-F20), không phải IP address — nên không bị ảnh hưởng bởi việc chỉ có 1 IP.

#### f. Không nhất quán HTTP vs HTTPS

**Vấn đề:** Methodology cũ giải thích XSS/SQLi miss là do "tshark không decrypt kịp HTTPS" — sai. CIC-IDS2018 Thursday dùng **HTTP (port 80)**, không phải HTTPS.

**✓ ĐÃ SỬA trong METHODOLOGY (2026-04-15):** Đã sửa explanation: nguyên nhân miss là do một số 1s windows có payload XSS/SQLi thưa/yếu → F18/F13 thấp → AI agent phân loại Allow. Không liên quan đến HTTPS decryption.

#### g. `100% mitigate` ở window-reset dễ gây hiểu nhầm

**Vấn đề:** `window-reset mitigate=100%` không phạt action đổi từ Redirect→Block, không phản ánh cost false positive.

**✓ ĐÃ SỬA trong METHODOLOGY (2026-04-15):** Đã thêm note vào bảng giới hạn.

**Phản biện:** `100% mitigate` trong window-reset là kết quả thực — mọi attacker đều bị chặn, chỉ khác nhau về loại chặn. Đây là chỉ số vận hành hệ thống (operational metric), không phải chỉ số chất lượng model. Nên trình bày cùng với recall để rõ ràng hơn.

### 2.4 Đánh giá tổng thể kết quả Thursday (đã cập nhật 3-layer)

| Class | L1 Raw PPO | L2 AI Agent | L3 Mitigate | Đáng tin không | Ghi chú |
|---|---|---|---|---|---|
| brute_force | 3.0% | **99.9%** | **100%** | ✓ Khá đáng tin | 3940 rows |
| xss | 3.5% | **89.3%** | **100%** | ~ Tạm đáng tin | 2202 rows, 10.7% miss do browse_guard |
| sqli | 40.8% | **69.4%** | **100%** | ✗ Yếu | 49 rows, cỡ mẫu nhỏ |
| benign FP | 1.4% | 1.4% | 1.2% | ~ Tạm đáng tin | 500 rows sample |
| mitigate 100% | — | — | L3: 100% | Chỉ số vận hành | Bao gồm cả Block (≠ Redirect) |

**Cách trình bày an toàn trong báo cáo:**
> "Hệ thống phòng thủ được đánh giá theo 3 tầng. PPO model thuần (L1) đạt recall 3-41% do cần tích lũy temporal context trước khi ra quyết định. AI agent hoàn chỉnh (L2, PPO + safety_net override) đạt 99.9% Brute Force, 89.3% XSS, 69.4% SQLi (n=49, mang tính tham khảo). Ở chế độ vận hành (L3, window-reset), 100% attacker bị mitigate thông qua cơ chế Redirect→Block escalation trong 15 giây đầu tiên."
### 2.5 stateful bị drift so với tài liệu cũ

**Vấn đề:** `stateful` hiện chạy lại cho `sqli_xss` ≈ 1.42% (false mitigation rất thấp) thay vì số cũ cao hơn trong cache. Logic hold/escalate/auto-unblock đã thay đổi qua nhiều session.

**Hướng fix:** Không cần sửa số — chỉ cần ghi rõ trong báo cáo rằng stateful result phụ thuộc vào version code, và kết quả báo cáo là từ code version hiện tại.

### 2.6 Output file bị ghi đè

**Vấn đề:** Nhiều mode (stateful/stateless/window-reset) ghi vào cùng 1 file JSON → khó audit, dễ nhầm số.

**Hướng fix:** Đã có file riêng per mode (`benchmark_results_stateful.json`, `benchmark_results_stateless.json`, `benchmark_results_window-reset.json`) — đã giải quyết.

### 2.7 Reproducibility chưa mạnh

**Vấn đề:** Cache JSONL có thể bị ghi đè nếu chạy lại pipeline từ đầu. Không có hash/checksum để verify.

**Hướng fix:** Ghi rõ trong báo cáo rằng kết quả benchmark được chạy từ cache cố định `Thursday_22_02_2018_nids.jsonl` (5.4MB, không thay đổi).

### 2.8 3-layer benchmark — ĐÃ THỰC HIỆN (2026-04-14)

**✓ ĐÃ CHẠY — kết quả thực tế dưới đây**

Trả lời câu hỏi: "Liệu benchmark có đang cho ra con số đẹp hơn thực lực thật không?"

**Kết quả 3-LAYER SUMMARY (CIC-IDS2018 Thursday-22-02-2018, n=6691):**

| Layer | Benign FP | BruteForce | XSS | SQLi | Avg Mitigate% |
|-------|-----------|------------|-----|------|---------------|
| **L1 Raw PPO** (model only, no guard) | 1.4% | 3.0% | 3.5% | 40.8% | 15.8% |
| **L2 AI Agent** (PPO + safety_net, stateless) | 1.4% | **99.9%** | **89.3%** | **69.4%** | 86.2% |
| **L3 Window-Reset** (full system + escalation) | 1.2% | 0.3% | 0.7% | 8.2% | **100.0%** |

**Giải thích kết quả:**

- **L1 → L2 delta**: BruteForce 3.0%→99.9%, XSS 3.5%→89.3% — safety_net override (Allow→Redirect khi F6>0.85 hoặc F13/F18>threshold) là lý do chính. PPO model không detect tốt attacker fresh IP (temporal=default/Allow → model cho benefit of doubt). Đây là thiết kế có chủ ý: PPO học rằng "IP lần đầu thấy, chưa có signal damage → không block sớm".
- **L2 → L3 delta**: Recall drop về 0.3-8.2% vì sau 15s, Redirect escalate thành Block (cơ chế `REDIRECT_TTL_SECONDS`). 99% traffic sau giây 15 bị Block (không phải Redirect) → recall Redirect thấp nhưng mitigate_rate=100%.
- **Raw PPO SQLi=40.8%**: Model có học được SQLi từ F13/F12, nhưng threshold trên F13 làm L2 bắt thêm được từ 40.8% lên 69.4%.
- **XSS miss 10.7% ở L2**: Browse_guard `_apply_benign_browse_guard()` fire cho rows có F6≥0.95 nhưng F18≈0 (window không capture đủ XSS payload) → gọi nhầm là benign page fetch → Allow.

**Override audit (stateless mode):**
- `raw_ppo_diff=0` — raw PPO và `info['rl_action']` luôn giống nhau (PCAP HTTP, không có HTTPS decrypt miss, browse_guard chỉ fire sau khi PPO đã quyết định)
- `safety_net_overrides=5721/6691 (85.5%)` — safety_net.apply_safety_overrides() chuyển Allow→Redirect cho 85.5% rows (chủ yếu attack rows với F13/F6 cao)

**Kết luận trả lời nghi ngờ "AI hay do rule cứu":**
> PPO một mình (L1) chỉ detect 3-41% attack traffic. Safety_net rule-based override kéo L2 lên 89-99%. Đây là **thiết kế 2-layer deliberate** (không phải che giấu điểm yếu): PPO học temporal behavior (hold/escalate/recover), safety_net cung cấp first-window detection cho IP mới. Cả 2 lớp đều cần thiết và được báo cáo riêng biệt.

#### Phương pháp đề xuất: 3-layer benchmark (tham khảo)

Thay vì chỉ báo `stateless`, `window-reset`, `stateful`, nên tách benchmark thành 3 lớp rõ ràng:

##### Layer 1 — Raw PPO benchmark

Mục tiêu:

- đo đúng khả năng của **PPO model thuần**
- không cho policy override, safety net, guard tracker can thiệp vào quyết định cuối

Cách chạy:

- dùng cùng file labeled JSONL hiện tại
- tắt toàn bộ rule-based override
- output chỉ lấy `rl_action` trực tiếp từ model

Metric nên báo:

- per-class recall
- confusion matrix
- macro recall
- balanced accuracy

Ý nghĩa:

- trả lời câu hỏi "model học được gì nếu đứng một mình?"
- đây là lớp benchmark quan trọng nhất để dập nghi ngờ "AI hay do rule cứu"

##### Layer 2 — AI Agent benchmark

Mục tiêu:

- đo hệ thống quyết định của agent hoàn chỉnh: `PPO + policy guard + state logic`

Cách chạy:

- giữ pipeline như hiện tại
- báo rõ đây là `AI agent benchmark`, không gọi là `model benchmark`

Metric nên báo:

- recall theo expected action
- mitigate rate
- false positive rate
- số lần override được kích hoạt

Ý nghĩa:

- trả lời câu hỏi "agent hoàn chỉnh hoạt động ra sao trong thực tế?"
- cho phép so sánh trực tiếp với Layer 1 để biết rule-based logic đã cứu được bao nhiêu

##### Layer 3 — Operational benchmark

Mục tiêu:

- đo hiệu quả vận hành của cả hệ thống phòng thủ

Cách chạy:

- dùng `window-reset` và `stateful`
- giữ escalation / hold / auto-unblock như production

Metric nên báo:

- time-to-first-mitigation
- time-to-block
- missed attacker rate
- benign false positive rate
- action timeline

Ý nghĩa:

- trả lời câu hỏi "khi đưa vào production logic, hệ thống có ngăn được attacker không?"
- đây là chỉ số hệ thống, không phải chỉ số năng lực model

#### Vì sao cách này hay hơn?

Vì nó tách riêng được 3 thứ thường bị trộn lẫn:

- năng lực của model
- tác động của rule/guard
- hiệu quả vận hành của hệ thống

Nếu không tách 3 lớp này, người đọc rất dễ hiểu nhầm:

- số đẹp là do model tốt

trong khi thực tế có thể là:

- model trung bình
- guard logic cứu lại
- escalation làm mitigate nhìn rất đẹp

#### Chỉ số mới nên bổ sung ngay

Ngoài các metric hiện tại, nên thêm 4 chỉ số sau:

1. `override_count`

- số row mà `final_action != rl_action`
- nếu con số này cao, chứng tỏ benchmark hiện tại phụ thuộc mạnh vào policy guard

2. `raw_vs_final_delta`

- chênh lệch recall giữa Raw PPO và AI Agent
- đây là bằng chứng định lượng tốt nhất để trả lời nghi ngờ "có phải rule đang kéo số lên không?"

3. `benign_sensitivity_check`

- chạy cùng benchmark với `benign_cap = 500`, `2000`, `5000`
- nếu FP rate thay đổi mạnh, chứng tỏ benchmark hiện tại nhạy với cách sample benign

4. `bootstrap_confidence_interval`

- đặc biệt cho `xss` và `sqli`
- báo khoảng tin cậy 95% cho recall thay vì chỉ đưa một số phần trăm duy nhất
- rất quan trọng với `sqli` vì chỉ có `49 rows`

#### Đề xuất thực hiện tối thiểu cho Thursday

Để cải thiện benchmark mà không tốn quá nhiều thời gian, nên làm tối thiểu:

1. chạy lại Thursday với **Raw PPO mode**
2. báo song song:
   - Raw PPO recall
   - AI Agent recall
   - Window-reset mitigate
3. thêm `override_count`
4. tăng benign sample từ `500` lên ít nhất `2000`
5. thêm confidence interval cho `sqli` và `xss`

#### Kết luận

Nếu muốn benchmark bớt "ảo", cách tốt nhất không phải chỉ là sửa câu chữ, mà là:

- tách rõ benchmark theo tầng
- thêm metric định lượng cho phần override
- kiểm tra độ ổn định theo benign sampling
- báo uncertainty cho các class ít mẫu

Đây là hướng nâng cấp phương pháp benchmark có giá trị học thuật hơn nhiều so với chỉ thêm disclaimer.

---

## 3. Roadmap

### Ưu tiên cao (cần cho luận văn)

1. ✅ **Raw PPO vs AI Agent benchmark** trên Thursday — **XONG (2026-04-14)** (kết quả ở 2.8)
2. ✅ **Override audit** — **XONG** (`raw_ppo_diff`, `safety_net_overrides` đã implement)
3. ✅ **Tách SQLi / XSS** trong Thursday — **XONG** (label `xss` và `sqli` riêng)
4. **DDoS benchmark** — 2 hướng:
   - Capture Mininet (hping3 + tcpdump) → ground truth chính xác nhất cho model
   - Tải CIC-DDoS2019 subset SYN flood (~nhỏ hơn CIC-IDS2018)
5. **Port Scan benchmark** — capture nmap từ Mininet

### Ưu tiên thấp (nice to have)

6. Hash/checksum cho cache JSONL
7. Benign sensitivity check với `benign_cap = 2000/5000` (dùng `--benign-cap` argument)
8. Bootstrap confidence interval cho XSS/SQLi (đặc biệt quan trọng cho SQLi n=49)

---

## 4. Phát biểu an toàn cho luận văn

> Benchmark hiện tại là **công bằng ở mức đánh giá có kiểm soát** trên subset Thursday của CIC-IDS2018, đặc biệt cho Brute Force và SQLi/XSS. Phần DDoS và Port Scan đang được bổ sung bằng cách capture traffic thực từ môi trường Mininet với hping3 và nmap để đảm bảo tính nhất quán với distribution mà model được huấn luyện.

**Không nên phát biểu:**
> Model đã benchmark hoàn chỉnh và xác nhận đầy đủ trên DDoS, Brute Force, SQLi, XSS

nếu chưa có JSONL cho DDoS.

---

## 5. Về việc tải dataset từng loại tấn công

Tải thêm dataset thật (CIC-DDoS2019, CIC-IDS2017 port scan) **giải quyết vấn đề coverage** nhưng **không giải quyết hoàn toàn vấn đề fairness** vì:

- Model train từ MockIPBehavior (synthetic, hping3-like) → distribution shift với bất kỳ real-world dataset nào
- Kết quả thấp trên real dataset = distribution shift, không nhất thiết là model kém
- **Ground truth từ Mininet** (capture hping3/nmap thật) là phương án đại diện nhất cho model, vì đúng topology + đúng feature pipeline

Capture từ Mininet không phải là "kém hơn" dataset CIC — nó là **in-distribution evaluation**, đánh giá đúng năng lực model trong môi trường nó được thiết kế để chạy.
