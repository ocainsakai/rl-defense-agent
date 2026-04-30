# Feature Validation Methodology — Academic-Grade Design

Tài liệu này mô tả **methodology** dùng để validate 20D NIDS feature set của
project trên dataset chuẩn CSE-CIC-IDS2018. Đây là tài liệu kèm thesis, trả
lời các câu hỏi của hội đồng về **tính đúng đắn** (correctness) và **tính
defensible** (academic rigor) của phương án validation.

---

## 1. Threat Model: Data Leakage trong NIDS Validation

NIDS feature validation rất dễ bị data leakage. Các loại leakage phổ biến:

### 1.1. Identifier leakage
Feature có chứa định danh trực tiếp/gián tiếp của label:
- `src_ip` của attacker IP cố định (ví dụ `18.218.115.60` trong CIC-IDS2018)
- `timestamp` rơi vào attack window hard-coded
- `dst_port` đặc trưng cho 1 attack type duy nhất

→ Classifier học pattern "if X = Y → label Z" thay vì học từ feature behavior.

### 1.2. Temporal leakage
Train/test split không tách biệt theo thời gian:
- StratifiedKFold shuffle ngẫu nhiên → train có rows ở t=10:17, test có rows ở t=10:18
- Các rows liền kề trong cùng attack session → behavior gần như giống nhau
- Classifier "memorize" temporal pattern ngắn

### 1.3. Group leakage
Cùng 1 entity (attacker IP) xuất hiện trong cả train và test:
- Train có 50 rows của attacker IP A, test cũng có 50 rows IP A
- Classifier học pattern của IP A specifically, không generalize sang IP khác

### 1.4. Class skew từ feature engineering
Granularity khác nhau gây class distribution khác nhau:
- Windowed (1s × IP): sustained attack → nhiều rows
- Per-flow (5-tuple): mỗi flow 1 row → ít rows hơn 80x
- Direct F1 comparison giữa 2 representation = apples vs oranges

---

## 2. Defenses Triển Khai

### 2.1. Drop identifier features (Bias 1)

Trước khi train, **bắt buộc** drop:
- `src_ip` (string, không phải feature)
- `timestamp` (numeric nhưng leak label)
- Bất kỳ metadata nào không phải traffic feature thuần túy

Implementation: `load_20d.get_features_only()` chỉ trả về 20 numeric features
F1-F20, không có metadata.

### 2.2. Label-shuffle sanity check (Bias 1 verification)

Đây là **gold standard** test cho data leakage:

```
1. Train classifier với label đã shuffle ngẫu nhiên
2. Eval: F1 macro phải gần baseline (1/n_classes)
3. Nếu F1_shuffled > 0.5 → có leak
4. Nếu F1_shuffled ≈ 0.25 (1/4 classes) → không leak
```

Test này không thể "cheat": nếu feature có information leak với label, thì
shuffle label sẽ phá information đó → F1 sẽ rớt về random.

Tham khảo: Kaufman et al. 2012, "Leakage in Data Mining" (KDD).

### 2.3. Class distribution matching (Bias 2)

Khi 2 dataset có class skew khác nhau (do granularity), direct F1 comparison
có 2 confound:

1. **Sample size effect**: dataset lớn hơn → F1 std nhỏ hơn (statistical power)
2. **Prior shift**: classifier học prior khác nhau → behavior khác

Defense: Subsample dataset có class skew cao về match dataset có class skew thấp:

```python
def subsample_20d_to_match_80d(df_20d, df_80d):
    target_dist = df_80d.value_counts()  # benign=496, brute=249, ...
    sampled = []
    for label, n in target_dist.items():
        sampled.append(df_20d[label].sample(n=n))
    return concat(sampled)
```

### 2.4. GroupKFold theo session (Bias 3)

Thay StratifiedKFold (random shuffle) bằng GroupKFold theo grouping:

```
group_id = f"{src_ip}_attack{window_id}_minute{int(ts/60)}"
```

Tại sao "minute"?
- 1-minute granularity coarse enough: 2 rows train/test ≥ 1 phút apart → no
  short-term correlation leak
- Fine enough: mỗi attack window (14-67 min) yields ≥ 8 groups → đủ cho 5-fold
- Benign rows: group theo (src_ip, minute) → 370 groups cho n=500

GroupKFold đảm bảo: 1 group không bao giờ bị split giữa train/test fold.
1 attack minute = 1 group → train không thấy minute đó, test có minute đó →
classifier phải generalize, không memorize.

Tham khảo: Engelen et al. 2021, "Towards a Standard Feature Set for NIDS".

### 2.5. Bootstrap percentile CI (Bias 4)

Parametric CI: `mean ± 1.96 · std / √n` giả định:
- F1 normal distribution
- Sample là i.i.d.
- n đủ lớn (CLT)

Vấn đề khi n=25:
- F1 ∈ [0, 1] → distribution skew left khi mean cao (≥0.9)
- Folds correlated do data overlap nội bộ
- CLT approximation thiếu chính xác

Bootstrap percentile CI:
```python
from scipy.stats import bootstrap
bootstrap((f1_scores,), np.mean, n_resamples=2000,
          confidence_level=0.95, method="percentile")
```
- Không giả định normal
- Resample 2000 lần → empirical distribution của mean
- Lấy percentile 2.5th, 97.5th → CI95 honest

Tham khảo: Raschka 2022, "Confidence Intervals for ML Classifiers".

### 2.6. Honest framing (Bias 5)

Phân biệt rõ:
- **Validation**: chứng minh feature set hoạt động đúng (tính chất nội bộ)
- **Benchmark**: so sánh hiệu suất 2 phương án (head-to-head)

Project này: **Validation only**. 80D CICFlowMeter làm reference baseline để
đặt con số F1 vào perspective, KHÔNG phải competitor.

Cách phát biểu đúng:
- ✓ "20D đạt F1 = 0.96 trên dataset chuẩn → có discriminative power"
- ✗ "20D tốt hơn 80D vì F1 = 0.98 vs 0.87"

Cách phát biểu thứ 2 sai vì:
1. Granularity khác nhau (windowed vs per-flow) — không cùng object
2. 20D có features chuyên dụng L7 (CRS rules) — design difference, không phải superiority

---

## 3. 3-Protocol Design Rationale

| Protocol | CV | Purpose | Sensitivity to |
|---|---|---|---|
| A — Native | StratifiedKFold | Reference với commit cũ | Class skew, temporal leak |
| B — Matched | StratifiedKFold | Apples-to-apples | Temporal leak |
| C — Group | GroupKFold | Robust validation | Statistical power (less data per fold) |

**Logic**: Nếu kết luận giống nhau qua 3 protocols → robust. Nếu khác nhau →
discuss caveats minh bạch.

Trong validation 20D này:
- Protocol A: F1 = 0.987 (XGB)
- Protocol B: F1 = 0.987 (XGB)
- Protocol C: F1 = 0.960 (XGB)

→ Cả 3 protocols đều > 0.85 threshold → robust conclusion: 20D works.

---

## 4. Ablation Study Design

Để chứng minh **mỗi nhóm feature đóng góp**:

```
Setups:
  - Full 20D (baseline)
  - Full 20D MINUS Network features (F1-F5, F9-F11)
  - Full 20D MINUS Application features (F6-F8)
  - Full 20D MINUS SQLi rules (F12-F17)
  - Full 20D MINUS XSS rules (F18-F20)

Metric: per-class F1 drop vs full
  - Drop > 0.05 → group critical cho class đó
  - Drop ≤ 0.01 → group redundant
```

Kết quả expected (và đã verify):
- Remove Network → SQLi class drop 0.12 (Network features quan trọng cho mọi attack)
- Remove SQLi rules → SQLi class drop 0.05
- Remove XSS rules → cũng drop sqli 0.05 (cross-feature interaction)

---

## 5. Threshold cho "Acceptable"

Theo literature:
- **Macro F1 ≥ 0.85**: feature set good (threshold của project)
- **Macro F1 ≥ 0.90**: very good
- **Macro F1 ≥ 0.95**: excellent (suspect overfit nếu n nhỏ)
- **F1 std < 0.05**: stable
- **CI95 width < 0.10**: precise estimate
- **F1_shuffled ≈ 1/n_classes**: no leak

Project hiện tại đáp ứng tất cả tiêu chí.

---

## 6. References

### Methodology

1. **Kaufman et al. 2012** — "Leakage in Data Mining: Formulation, Detection,
   and Avoidance" (KDD). Định nghĩa formal về data leakage.

2. **Engelen et al. 2021** — "Towards a Standard Feature Set for Network
   Intrusion Detection System Datasets" (arXiv 2101.11315).
   → Validate 12 + 43 NetFlow features trên CIC-IDS2017, 5-fold CV + std.

3. **Layeghy et al. 2022** — "Evaluating Standard Feature Sets Towards
   Increased Generalisability and Explainability of ML-Based NIDS"
   (Computers & Security).
   → So sánh NetFlow vs CICFlowMeter; cảnh báo cross-dataset generalization yếu.

4. **Ferrag et al. 2024** — "Machine Learning-Based Intrusion Detection for
   Big and Imbalanced Data" (Journal of Big Data).
   → SMOTE trên train only, 10-fold stratified CV với CI95.

5. **Raschka 2022** — "Creating Confidence Intervals for ML Classifiers"
   (https://sebastianraschka.com/blog/2022/confidence-intervals-for-ml.html).
   → Khuyến nghị bootstrap CI khi n < 100.

### Datasets

6. **Sharafaldin et al. 2018** — CSE-CIC-IDS2018 dataset documentation
   (UNB CIC). https://www.unb.ca/cic/datasets/ids-2018.html

### Attack Detection References

7. **OWASP ModSecurity CRS-3** — REQUEST-942-APPLICATION-ATTACK-SQLI.conf
   + REQUEST-941-APPLICATION-ATTACK-XSS.conf. Used cho F13, F18.

8. **Kruegel & Vigna 2003** — "Anomaly Detection of Web-based Attacks" (CCS).
   Foundation for application-level features F6-F8.
