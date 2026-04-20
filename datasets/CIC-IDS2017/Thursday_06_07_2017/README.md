# Thursday-06-07-2017 Benchmark Results

## Overview
CIC-IDS2017 PCAP benchmark for RL defense agent model on **Thursday, July 6, 2017**.

## Directory Structure
```
Thursday_06_07_2017/
├── pcap_cache/
│   ├── raw_data/
│   │   └── Thursday_06_07_2017_nids.jsonl        # 10,821 NIDS feature windows (20D)
│   ├── results/
│   │   ├── benchmark_results_all_modes.json
│   │   ├── benchmark_results_raw_ppo.json        # Layer 1: Raw PPO (baseline)
│   │   ├── benchmark_results_stateless.json      # Layer 2: AI agent
│   │   └── benchmark_results_window_reset.json   # Layer 3: System response
│   └── plots/
│       ├── chart1_recall_L1_L2.png
│       ├── chart2_confusion_matrix_L1.png
│       ├── chart3_timeline_L3.png
│       ├── chart4_pred_distribution_L1.png
│       └── chart5_mitigate_rate_3layers.png
└── README.md
```

## Benchmark Data

### PCAP Processing
- **Total packets**: Extracted via tshark with IP/port filtering
- **Extracted NIDS rows**: 10,821 (20D features)
- **Labeled rows**: 4,184

### Traffic Breakdown
| Label | Count | Expected Action | L1 Acc% | L2 Acc% | L3 Acc% |
|-------|-------|-----------------|---------|---------|---------|
| benign | 500 | Allow | 97.6% | 99.6% | 99.6% |
| brute_force | 2,306 | Redirect | 94.7% | 98.0% | 87.5% |
| xss | 1,136 | Redirect | 99.1% | 99.4% | 92.7% |
| sqli | 22 | Redirect | 81.8% | 81.8% | 81.8% |

### 3-Layer Evaluation

#### Layer 1: Raw PPO (Baseline)
- **Overall Accuracy**: 96.3% (4035/4184 rows)
- **Model**: 34D v13 (run_34d_v13/best_model)
- **Mode**: Pure PPO output, no override/safety guards
- **Mitigation Rate**: 93.4%

#### Layer 2: Stateless AI Agent (Per-Window)
- **Overall Accuracy**: 98.5% (4120/4184 rows)
- **Model improvement over L1**: +2.2%
- **Safety net overrides**: 0 (0.0%)
- **Mitigation Rate**: 93.4%

#### Layer 3: Window-Reset (System Response Timeline)
- **Overall Accuracy**: 90.5% (3787/4184 rows)
- **Model improvement over L1**: -5.8% (escalation trade-off)
- **Timeline analysis**: Shows Redirect→Block progression for sustained attacks
- **Mitigation Rate**: 94.3%

## Attack Characteristics
1. **Brute Force (22:36-23:36 UTC, 1h)** - HTTP auth dictionary attacks
2. **XSS (14:08-15:34 UTC, 1.43h)** - JavaScript injection patterns
3. **SQLi (11:04-11:41 UTC, 37 min)** - SQL query injection attempts

## Feature Quality
L7 HTTP enrichment via tshark:
- **F1 (PacketRate)**: 5-14 packets/sec
- **F6 (URLConcentration)**: 0.0 (benign) → 1.0 (brute_force)
- **F12/F13 (SQLi indicators)**: Elevated for sqli class
- **F18 (XSS score)**: 1.5-2.5 for xss patterns

## Model Performance
- **Model version**: 34D (observation space with 4D effect vector)
- **Effect collector**: ON (OfflineEffectCollector for nginx feedback simulation)
- **Action space**: [Allow, RateLimit, Redirect, Block]
- **Soft-guard mode**: OFF (model decides independently)

## Files
- `raw_data/Thursday_06_07_2017_nids.jsonl`: Full labeled dataset (10,821 windows)
- `results/benchmark_results_*_modes.json`: Metrics for each evaluation layer
- `plots/chart*.png`: 5 visualization charts with .2f precision

## Timezone & Dataset Info
- **Timezone**: CIC-IDS2017 in Halifax, Nova Scotia (ADT = UTC-3)
- **Dataset**: CIC-IDS2017 full PCAP capture from ISCX
- **Running mode**: Dry-run (no iptables action enforcement)

## Notes
- Thursday is a normal business day with background HTTP traffic (benign baseline)
- Attack variants appear in isolated time windows
- Layer 3 (window-reset) shows realistic escalation decisions for sustained threats

Generated: 2026-04-20 18:04 UTC
