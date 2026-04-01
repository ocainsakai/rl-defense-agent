# ML Baseline — Random Forest for RL Defense Agent

Đây là **baseline tham chiếu** để so sánh với RL Agent (PPO).  
ML không thay thế RL — chỉ làm điểm so sánh học thuật.

---

## Cấu trúc

```
ml_baseline/
├── train_model.py        # Ngày 1-2: train RF trên CICIDS2017
├── ml_baseline_agent.py  # Ngày 3: decision engine (feature → action)
├── metrics.py            # Công thức Detection / System / Redirect
├── run_benchmark.py      # Ngày 4-5: chạy benchmark, xuất CSV + JSON
├── visualize.py          # Sinh biểu đồ matplotlib
├── experiment_config.py  # Config chung (seed, n_samples, scenarios)
└── data/                 # Đặt CICIDS2017 CSV vào đây
```

---

## Nhanh bắt đầu

### 1. Cài dependencies
```bash
pip install scikit-learn xgboost pandas numpy matplotlib joblib
```

### 2. Đặt dữ liệu
```
ml_baseline/data/CICIDS2017_sample.csv
```
Download: https://www.unb.ca/cic/datasets/ids-2017.html

### 3. Train model
```bash
cd ml_baseline
python train_model.py
```

### 4. Chạy benchmark
```bash
# Scenario 1: attack cố định
python run_benchmark.py --data data/CICIDS2017_sample.csv --scenario 1

# Scenario 2: adaptive attack
python run_benchmark.py --data data/CICIDS2017_sample.csv --scenario 2
```

### 5. Sinh biểu đồ
```bash
# Dùng dữ liệu mẫu (chưa có JSON thực)
python visualize.py

# Dùng kết quả thực
python visualize.py --ml_json benchmark_results_summary.json --rl_json ../rl_results_summary.json
```

---

## Mapping Label → Action

| Label | Confidence | Action |
|-------|-----------|--------|
| benign | any | allow |
| attack | any | block |
| suspicious | ≥ 0.75 | rate-limit |
| suspicious | < 0.75 | redirect |

---

## Metrics

| Nhóm | Metrics |
|------|---------|
| Detection | Accuracy, Precision, Recall, F1 |
| System | Mitigation Rate, FP Cost, Action Efficiency, Response Time |
| Redirect | Usage Rate, Effectiveness, FP Reduction |
