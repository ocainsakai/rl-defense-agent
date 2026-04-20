# Friday-23-02-2018 Benchmark Results

## Overview
CIC-IDS2018 PCAP benchmark for RL defense agent model on **Friday, February 23, 2018**.

## Directory Structure
```
Friday_23_02_2018/
├── pcap_cache/
│   ├── raw_data/
│   │   └── Friday_23_02_2018_nids.jsonl     # 10,141 NIDS feature windows (20D)
│   ├── results/
│   │   └── benchmark_results_stateless.json # AI agent evaluation (Layer 2)
│   └── plots/
│       └── (generated charts from plot_benchmark.py)
└── README.md
```

## Benchmark Data

### PCAP Processing
- **Source PCAP**: `/mnt/hgfs/pcap data/CICIDS2018/pcap/pcap/UCAP172.31.69.28` (33 MB)
- **Total packets**: 44,220
- **Extracted NIDS rows**: 10,141 (20D features)
- **Labeled rows**: 9,429

### Traffic Breakdown
| Label | Count | Expected Action | Accuracy | Recall |
|-------|-------|-----------------|----------|--------|
| benign | 1,702 | Allow | 98.0% | 98.0% |
| brute_force | 3,510 | Redirect | 100.0% | 100.0% |
| xss | 4,136 | Redirect | 100.0% | 100.0% |
| sqli | 81 | Redirect | 71.6% | 71.6% |

### Eval Mode: Stateless (Layer 2 - AI Agent Capability)
- **Overall Accuracy**: 99.4% (9372/9429 rows)
- **Model**: 34D v13 (run_34d_v13/best_model)
- **Mode**: Per-window AI agent accuracy (fresh state each window)
- **Raw PPO accuracy**: 99.3%
- **Override audit**:
  - raw_ppo vs rl_action diff: 0 (0.0%)
  - safety_net + tracker overrides: 5 (0.1%)

### Attack Windows
1. **Brute Force (Redirect)** - 10:03-11:03 UTC (1h)
2. **XSS (Redirect)** - 13:00-14:10 UTC (1.17h)
3. **SQLi (Redirect)** - 15:05-15:18 UTC (13 min)

### Mitigation Rates (attack detection + correct action)
- brute_force: 100.0% ✓
- xss: 100.0% ✓
- sqli: 71.6% (23 false Allow)

## Feature Quality
L7 enrichment via tshark HTTP extraction:
- F1 (PacketRate): 5.9 (benign) → 7.3 (xss)
- F6 (URLConcentration): 0.0 (benign) → 0.99 (brute_force)
- F12/F13 (SQLi indicators): Present for sqli class
- F18 (XSS score): 2.1 for xss class

## Files
- `raw_data/Friday_23_02_2018_nids.jsonl`: Full labeled dataset with 20D features
- `results/benchmark_results_stateless.json`: Layer 2 evaluation metrics (per-class, timeline, confusion matrix)

## Notes
- **Timezone**: CIC-IDS2018 in Halifax, Nova Scotia (AST = UTC-4)
- **Model version**: 34D (includes 4D effect vector from nginx side-channel)
- **Running mode**: Stateless (fresh state per window for pure AI agent accuracy)
- **Demo safe**: OFF (dry-run, no iptables enforcement)

Generated: 2026-04-20 17:07 UTC
