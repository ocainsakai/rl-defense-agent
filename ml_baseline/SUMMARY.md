# ML Baseline Benchmark — Tóm Tắt

**Mục tiêu:** Xây dựng ML baseline (Random Forest) để so sánh với RL Agent (PPO) trong hệ thống phòng thủ mạng.

---

## 1. Kiến Trúc Hệ Thống

```
IDSDefenseEnv (env_ids.py)
        ↓  sinh eval_data.jsonl (obs 20D + label + expected_action)
        ↓
  ┌─────────────┐     ┌──────────────────┐
  │  RL Agent   │     │  ML Baseline     │
  │  PPO model  │     │  Random Forest   │
  └─────────────┘     └──────────────────┘
        ↓                      ↓
   action trực tiếp    feature → label → action
        ↓                      ↓
        └──────── metrics.py ──────────┘
                       ↓
               benchmark_results.png
```

**Lý do dùng cùng 20D obs vector:**  
RL dùng features F1–F20 từ NIDS sniffer. Để so sánh công bằng, ML cũng dùng cùng feature space — không dùng CICIDS2017 riêng vì feature space khác hoàn toàn.

---

## 2. Cấu Trúc File

```
ml_baseline/
├── generate_eval_data.py   # Sinh eval_data.jsonl từ IDSDefenseEnv
├── train_model.py          # Train Random Forest trên eval_data.jsonl
├── ml_baseline_agent.py    # Decision engine: obs → label → action
├── metrics.py              # Công thức 3 nhóm metrics
├── run_benchmark.py        # Chạy cả RL + ML, xuất JSON + CSV
├── visualize.py            # Sinh biểu đồ matplotlib
├── experiment_config.py    # Config chung (seed, scenarios)
└── data/
    └── eval_data.jsonl     # 6,000 records (500 episodes × 12 IPs)
```

---

## 3. Mapping Label → Action (ML)

| Predicted Label | Confidence | Action |
|----------------|-----------|--------|
| benign | any | allow |
| attack | any | block |
| suspicious | ≥ 0.75 | rate-limit |
| suspicious | < 0.75 | redirect |

**Lý do:** Confidence thấp trong class `suspicious` phản ánh vùng quyết định không chắc chắn. Thay vì block nhầm (false positive), redirect traffic đến honeypot để phân tích thêm — đây là chiến lược *soft defense*.

---

## 4. Thiết Kế Eval Data

**Phương pháp:** `env._get_obs_and_info()` trực tiếp (không qua `step()`).

**Lý do không dùng `step()`:**  
`step()` áp dụng closed-loop effect (Block → features về 0, RateLimit → F1 × 0.4...). Nếu sinh data qua multi-step với RL policy, obs sau khi mitigate trông giống benign → cả RF lẫn RL đều không nhận ra attack.

**Kết quả:**
- 6,000 records, obs dim = 20D
- Label: benign=1,500 | suspicious=3,000 | attack=1,500
- Expected action: Allow=1,500 | RateLimit=1,000 | Block=1,500 | Redirect=2,000

---

## 5. Định Nghĩa Metrics

### (A) Detection Metrics
| Metric | Công thức |
|--------|-----------|
| Accuracy | (TP+TN) / total |
| Precision | TP / (TP+FP) — weighted |
| Recall | TP / (TP+FN) — weighted |
| F1-score | 2×P×R / (P+R) — weighted |

### (B) System / Decision Metrics
| Metric | Công thức | Ý nghĩa |
|--------|-----------|---------|
| Mitigation Rate | (threats bị block/rate-limit/redirect) / tổng threats | Tỷ lệ nguy cơ được xử lý |
| FP Cost | Σ(weight × benign bị action nhầm) / tổng benign | block=2.0, rate-limit=1.0, redirect=0.5 |
| Action Efficiency | action khớp expected_action / tổng | Chất lượng quyết định |
| Response Time | avg ms/decision | Tốc độ phản ứng |

### (C) Redirect Metrics
| Metric | Công thức | Ý nghĩa |
|--------|-----------|---------|
| Redirect Usage Rate | redirected / total | Mức độ dùng redirect |
| Redirect Effectiveness | redirect đúng mục tiêu / tổng redirect | Redirect có chính xác không |
| Redirect FP Reduction | suspicious được redirect / tổng suspicious | Redirect giảm false positive thế nào |

---

## 6. Kết Quả Benchmark

### Scenario 1 — Fixed Attack (benign + attack, không có suspicious)

| Metric | ML (RF) | RL (PPO) | Winner |
|--------|---------|---------|--------|
| Accuracy | 0.9995 | 0.9995 | Tie |
| F1-score | 0.9997 | 0.9997 | Tie |
| Mitigation Rate | 1.0000 | 1.0000 | Tie |
| FP Cost | 0.0005 | 0.0000 | RL |
| Action Efficiency | 0.9995 | 0.9995 | Tie |
| **Response Time** | **18.5ms** | **0.36ms** | **RL (52×)** |
| Redirect Usage | 0.0005 | 0.0000 | — |

**Nhận xét:** Khi attack pattern đơn giản (chỉ benign vs attack), cả hai gần như bằng nhau. RL nhanh hơn 52× vì inference PPO < 1ms.

---

### Scenario 2 — Adaptive Attack (benign + suspicious + attack)

| Metric | ML (RF) | RL (PPO) | Winner |
|--------|---------|---------|--------|
| **Accuracy** | **1.0000** | **0.8410** | **ML** |
| **F1-score** | **1.0000** | **0.8451** | **ML** |
| **Mitigation Rate** | **1.0000** | **0.7880** | **ML** |
| FP Cost | 0.0000 | 0.0000 | Tie |
| **Action Efficiency** | **0.6595** | **0.8410** | **RL** |
| **Response Time** | **17.7ms** | **0.34ms** | **RL (52×)** |
| **Redirect Usage Rate** | **0.0020** | **0.3385** | **RL** |
| Redirect Effectiveness | 1.0000 | 1.0000 | Tie |
| **Redirect FP Reduction** | **0.004** | **0.680** | **RL (170×)** |

---

## 7. Phân Tích Kết Quả

### ML thắng ở: Accuracy, F1, Mitigation Rate
Random Forest là classifier thuần túy — khi obs vector rõ ràng (được sinh từ cùng env distribution), RF gần như perfect (100%). Đây là điểm mạnh tự nhiên của supervised learning trên dữ liệu ổn định.

### RL thắng ở: Action Efficiency, Response Time, Redirect Strategy

**Action Efficiency (0.84 vs 0.66):**  
ML không phân biệt được `noisy_normal` (→ rate-limit) và `brute_force/sqli_xss` (→ redirect) vì cả hai đều được gán label `suspicious`. Dùng confidence threshold để phân tách chỉ đúng 66%.

RL học được pattern sâu hơn từ obs vector: F6-URLConcentration và F12–F20 (SQLi/XSS features) phân biệt brute_force/sqli_xss với noisy_normal → action đúng 84%.

**Redirect FP Reduction (0.68 vs 0.004):**  
RL dùng redirect cho 33.8% traffic, trong đó 68% suspicious được redirect đúng thay vì bị block nhầm. ML gần như không dùng redirect (0.2%).

**Response Time (0.34ms vs 17.7ms):**  
ML cần StandardScaler transform + RF predict (100 trees) → ~18ms. RL chỉ cần forward pass qua MLP policy → <1ms.

### Trade-off tóm tắt

> ML là *bộ phát hiện chính xác* (precision classifier) — tốt khi pattern ổn định và cần label rõ ràng.  
> RL là *bộ ra quyết định thích nghi* (adaptive decision maker) — tốt khi cần phân biệt hành động tinh tế (rate-limit vs redirect) và phản ứng nhanh theo thời gian thực.

---

## 8. Hướng Dẫn Chạy Lại

```bash
cd /home/tringuyen/AIAGENT/rl-defense-agent

# Bước 1: Sinh eval data
python3 ml_baseline/generate_eval_data.py --episodes 500 --out ml_baseline/data/eval_data.jsonl

# Bước 2: Train RF model
python3 ml_baseline/train_model.py --data ml_baseline/data/eval_data.jsonl

# Bước 3: Benchmark
python3 ml_baseline/run_benchmark.py --scenario 1 --n_samples 2000
python3 ml_baseline/run_benchmark.py --scenario 2 --n_samples 2000

# Bước 4: Vẽ biểu đồ
python3 ml_baseline/visualize.py \
  --ml_json ml_baseline/ml_summary_s2.json \
  --rl_json ml_baseline/rl_summary_s2.json \
  --out ml_baseline/benchmark_s2.png
```

---

## 9. Các Vấn Đề Đã Gặp và Cách Fix

| Vấn đề | Nguyên nhân | Fix |
|--------|-------------|-----|
| RL accuracy = 1.0 (sai) | Gán `predicted_label = true_label` trong code | Dùng `_rl_action_to_label()` để suy label từ action |
| ML redirect 62% traffic | Data sinh bằng random action → obs nhiễu, RF over-predict suspicious | Chuyển sang sinh data bằng `_get_obs_and_info()` trực tiếp |
| RL mitigation thấp hơn ML | Formula chỉ tính block+rate-limit, bỏ qua redirect | Cập nhật formula: redirect cũng là mitigation |
| eval_data chỉ trả benign | `env.reset()` trả `info={}`, ip_type không có | Dùng `_get_obs_and_info()` với `current_ip_idx` thủ công |
| RL allow 89% attack | Dùng RL policy sinh data → closed-loop làm obs "bình thường" sau khi mitigate | Sinh obs từ fresh state, không qua `step()` |
