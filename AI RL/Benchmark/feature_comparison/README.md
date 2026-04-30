# Feature Comparison — Validation 20D NIDS

Folder này dùng để **chứng minh 20D feature set tự thiết kế trong `System/`
HOẠT ĐỘNG ĐÚNG**, có discriminative power, phát hiện được 4 attack class trên
dataset chuẩn CIC.

**Lưu ý:** Đây là **validation**, KHÔNG phải benchmark hiệu suất "20D vs 80D
xem ai thắng". 80D CICFlowMeter chỉ đóng vai trò **reference baseline** (industry
standard) để con số F1 của 20D có context.

---

## 1. Câu hỏi cần trả lời

> **Hội đồng:** "20D em tự làm liệu có đúng so với CICFlowMeter chuẩn?"

Cụ thể, cần chứng minh:

| Tiêu chí | Cách verify |
|---|---|
| 20D có discriminative power? | F1 macro > 0.85 trên 4 attack classes |
| 20D không mất thông tin so với 80D? | F1(20D) trong cùng range với F1(80D) |
| 20D có ý nghĩa? | Feature importance khớp design (F13, F18, F1 top) |
| 20D ổn định? | F1 std nhỏ qua 5-fold × 5-seed = 25 runs |

---

## 2. Methodology

### Dataset
- **Source:** CSE-CIC-IDS2018 — Thursday 22/02/2018
- **20D NIDS:** `datasets/CSE-CIC-IDS2018/Thursday_22_02_2018/pcap_cache/raw_data/Thursday_22_02_2018_nids.jsonl`
  (8917 rows windowed → 6691 rows sau khi label, benign cap=500)
- **80D CICFlowMeter:** `datasets/CSE-CIC-IDS2018/processed/Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv`
  (1M rows flow-based → 858 rows sau khi label, benign cap=500)
- **Labels (4 classes):** `benign`, `brute_force`, `xss`, `sqli`

### Classifiers
- **Random Forest** (n=200, max_depth=20, class_weight='balanced')
- **XGBoost** (n=200, max_depth=8, lr=0.1)
- Cùng hyperparameter cho cả 2 dataset → fairness

### Cross-validation
- StratifiedKFold(5) × 5 seeds = 25 runs per (dataset × classifier)
- Seeds: `[42, 123, 456, 789, 1337]`
- Metric: macro-F1 (insensitive với class imbalance)

### Tại sao row count khác (6691 vs 858)?
**Inherent property** của 2 feature engineering approach:
- 20D NIDS = `(src_ip × 1s window)` → sustained attack 67 phút brute = ~4000 windows
- 80D CICFlowMeter = `1 flow (5-tuple completion)` → mỗi flow = 1 row

Cùng PCAP gốc, khác cách aggregate. Đây là điều CANNOT equalize bằng resample
mà không phá tính nguyên thủy của 1 trong 2.

---

## 3. Cách chạy

```bash
cd "AI RL/Benchmark/feature_comparison"

# 1. Smoke test load
python3 load_20d.py    # check 20D dataset
python3 load_80d.py    # check 80D dataset

# 2. Run full validation (~3-5 phút)
python3 validate_20d.py
# → results/validation_results.json (50 runs × 2 datasets)

# 3. Generate plots
python3 plot_validation.py
# → results/plots/*.png
```

---

## 4. Kết quả

### Macro-F1 summary

| Dataset | Classifier | F1 macro (mean ± std) | Per-class F1 (XGB) |
|---|---|---|---|
| **20D NIDS** | Random Forest | **0.9803 ± 0.0120** | benign=0.99, brute=1.00, sqli=0.93, xss=1.00 |
| **20D NIDS** | XGBoost | **0.9858 ± 0.0132** | benign=0.99, brute=1.00, sqli=0.96, xss=1.00 |
| 80D CICFlowMeter | Random Forest | 0.8531 ± 0.0417 | benign=0.99, brute=0.93, sqli=0.54, xss=0.95 |
| 80D CICFlowMeter | XGBoost | 0.8749 ± 0.0381 | benign=0.99, brute=0.95, sqli=0.61, xss=0.95 |

### Kết luận

1. **20D có discriminative power tốt** — F1 macro = 0.98 ≫ 0.85 ngưỡng acceptable
2. **20D không mất thông tin** — F1 cao hơn 80D ở mọi class
3. **20D vượt trội ở SQLi** (F1=0.96 vs 0.61) — vì có CRS rules-based features
   (F13 CrsSqliScore, F14-F17) thiết kế riêng cho L7 SQLi detection
4. **20D ổn định** — std nhỏ (~0.012-0.013) qua 25 runs

→ **20D feature set HOẠT ĐỘNG ĐÚNG**, phát hiện được mọi attack type trong CIC.

---

## 5. Plots output

| File | Nội dung |
|---|---|
| `00_summary_table.png` | Bảng metrics tổng hợp (4 setup × 8 metrics) |
| `01_f1_macro_comparison.png` | Bar chart F1 macro 20D vs 80D với error bars |
| `02_per_class_f1.png` | Per-class F1 breakdown (benign/brute/sqli/xss) |
| `03_feature_importance_20d.png` | Top-20 feature importance từ 20D |
| `04_feature_importance_80d.png` | Top-20 feature importance từ 80D (78 total) |
| `05_confusion_matrices.png` | Side-by-side confusion matrix 20D vs 80D |

---

## 6. Trả lời các câu hội đồng có thể hỏi

**Q1: "Tại sao 20D tốt hơn 80D? Có bị overfit không?"**

A: 20D có CRS rules-based features (F13 CrsSqliScore, F18 CrsXssScore, F14-F17
binary heuristics) thiết kế riêng cho L7 attack detection. CICFlowMeter chỉ có
flow-level features (packet length, IAT, bytes/s) — không capture được signal
L7 trong payload. Không overfit vì F1 std nhỏ qua 25 fold/seed khác nhau.

**Q2: "Tại sao row count khác? Có fair không?"**

A: Inherent property — 20D windowed (1s × IP), 80D per-flow (5-tuple). Cùng
PCAP gốc nhưng cách aggregate khác. Mỗi dataset dùng StratifiedKFold riêng
trên distribution của nó → fairness within dataset. Đây là **validation**,
không phải head-to-head benchmark.

**Q3: "Sao chỉ test 1 ngày? Sao không nhiều ngày?"**

A: 80D CICFlowMeter CSV chính thức của CSE-CIC-IDS2018 chỉ available cho
Thursday-22-02-2018 ở local. Đủ để cover 4 attack types: Benign, Brute-Force-Web,
Brute-Force-XSS, SQL-Injection. Future work: extend sang Wednesday/Friday nếu
download thêm CSV.

**Q4: "Sao không dùng Deep Learning?"**

A: Không phải mục tiêu. Mục tiêu là **validate feature engineering**, không
phải tìm classifier tối ưu. RF/XGB đủ để chứng minh feature có discriminative
power. RL agent chính (`AI RL/infer.py`) mới là contribution của đề tài.

---

## 7. Files

```
feature_comparison/
├── README.md                  File này
├── load_20d.py                Load 20D NIDS labeled dataset
├── load_80d.py                Load 80D CICFlowMeter labeled dataset
├── train_classifier.py        Train + evaluate 1 (clf, fold, seed) combo
├── validate_20d.py            Orchestrator: 5-fold × 5 seed × 2 dataset × 2 clf
├── plot_validation.py         Generate 6 plots từ validation_results.json
└── results/
    ├── validation_results.json
    └── plots/
        ├── 00_summary_table.png
        ├── 01_f1_macro_comparison.png
        ├── 02_per_class_f1.png
        ├── 03_feature_importance_20d.png
        ├── 04_feature_importance_80d.png
        └── 05_confusion_matrices.png
```
