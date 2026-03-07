# Model Evaluation Report - Classification Metrics

**Model**: `runs/run_20260115_050748_seed68/best_model.zip`

**Test Date**: 2026-01-14T22:29:35

**Configuration**:
- Episodes: 50
- Seed: 42
- Total predictions: 6000

---

## Overall Performance

**Accuracy**: 0.8518

### Macro Averages (unweighted)

- **Precision**: 0.6366
- **Recall**: 0.8413
- **F1-Score**: 0.6341

### Weighted Averages (by support)

- **Precision**: 0.9525
- **Recall**: 0.8518
- **F1-Score**: 0.8943

---

## Per-Action Metrics

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 0.9966 | 0.9310 | 0.9627 | 3132 |
| RateLimit | 0.9433 | 0.7667 | 0.8459 | 2645 |
| Redirect | 0.0644 | 0.9783 | 0.1208 | 46 |
| Block | 0.5422 | 0.6893 | 0.6070 | 177 |

## Confusion Matrix

Rows = Expected (Ground Truth), Columns = Predicted

|  | Allow | RateLimit | Redirect | Block |
|--|-------|-----------|----------|-------|
| Allow | 2916 | 117 | 2 | 97 |
| RateLimit | 10 | 2028 | 602 | 5 |
| Redirect | 0 | 0 | 45 | 1 |
| Block | 0 | 5 | 50 | 122 |

## Per-IP-Type Performance

### IP Type: `benign`

- **Total predictions**: 1050
- **Accuracy**: 1.0000
- **F1-Score (macro)**: 1.0000

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 1.0000 | 1.0000 | 1050 |
| RateLimit | 0.0000 | 0.0000 | 0.0000 | 0 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

### IP Type: `benign_upload`

- **Total predictions**: 350
- **Accuracy**: 1.0000
- **F1-Score (macro)**: 1.0000

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 1.0000 | 1.0000 | 350 |
| RateLimit | 0.0000 | 0.0000 | 0.0000 | 0 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

### IP Type: `brute_force`

- **Total predictions**: 300
- **Accuracy**: 1.0000
- **F1-Score (macro)**: 1.0000

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 1.0000 | 1.0000 | 300 |
| RateLimit | 0.0000 | 0.0000 | 0.0000 | 0 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

### IP Type: `grayzone`

- **Total predictions**: 900
- **Accuracy**: 0.9178
- **F1-Score (macro)**: 0.3883

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 0.9464 | 0.4380 | 0.5989 | 121 |
| RateLimit | 0.9191 | 0.9923 | 0.9543 | 779 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

### IP Type: `layer7_stealth`

- **Total predictions**: 900
- **Accuracy**: 0.3044
- **F1-Score (macro)**: 0.4647

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 0.9500 | 0.9500 | 0.9500 | 60 |
| RateLimit | 0.9938 | 0.2183 | 0.3579 | 733 |
| Redirect | 0.0536 | 1.0000 | 0.1017 | 35 |
| Block | 0.8462 | 0.3056 | 0.4490 | 72 |

### IP Type: `mimicry_attackers`

- **Total predictions**: 600
- **Accuracy**: 0.9400
- **F1-Score (macro)**: 0.5332

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 0.6667 | 0.8000 | 3 |
| RateLimit | 0.9982 | 0.9420 | 0.9693 | 586 |
| Redirect | 0.2273 | 0.9091 | 0.3636 | 11 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

### IP Type: `noisy_normal`

- **Total predictions**: 700
- **Accuracy**: 0.9200
- **F1-Score (macro)**: 0.5831

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 0.9619 | 0.6824 | 0.7984 | 148 |
| RateLimit | 0.9126 | 0.9927 | 0.9510 | 547 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 5 |

### IP Type: `scan`

- **Total predictions**: 300
- **Accuracy**: 0.8433
- **F1-Score (macro)**: 0.4575

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 0.8433 | 0.9150 | 300 |
| RateLimit | 0.0000 | 0.0000 | 0.0000 | 0 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

### IP Type: `sqli_xss`

- **Total predictions**: 600
- **Accuracy**: 1.0000
- **F1-Score (macro)**: 1.0000

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 1.0000 | 1.0000 | 500 |
| RateLimit | 0.0000 | 0.0000 | 0.0000 | 0 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 1.0000 | 1.0000 | 1.0000 | 100 |

### IP Type: `syn_flood`

- **Total predictions**: 300
- **Accuracy**: 0.8333
- **F1-Score (macro)**: 0.4545

| Action | Precision | Recall | F1-Score | Support |
|--------|-----------|--------|----------|----------|
| Allow | 1.0000 | 0.8333 | 0.9091 | 300 |
| RateLimit | 0.0000 | 0.0000 | 0.0000 | 0 |
| Redirect | 0.0000 | 0.0000 | 0.0000 | 0 |
| Block | 0.0000 | 0.0000 | 0.0000 | 0 |

---

## Metric Interpretation

### Precision
- **Definition**: Of all times the model predicted this action, how many were correct?
- **Formula**: TP / (TP + FP)
- **High precision**: Few false positives (model doesn't over-use this action)

### Recall
- **Definition**: Of all times this action was expected, how many did the model catch?
- **Formula**: TP / (TP + FN)
- **High recall**: Few false negatives (model doesn't miss expected cases)

### F1-Score
- **Definition**: Harmonic mean of precision and recall
- **Formula**: 2 * (Precision * Recall) / (Precision + Recall)
- **High F1**: Good balance between precision and recall

### Accuracy
- **Definition**: Overall percentage of correct predictions
- **Formula**: (TP + TN) / Total
- **Note**: Can be misleading with imbalanced classes

