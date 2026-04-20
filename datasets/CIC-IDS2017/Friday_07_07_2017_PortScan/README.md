# Friday-07-07-2017 PortScan Benchmark Results

## Overview
CIC-IDS2017 PCAP benchmark for RL defense agent model on **Friday, July 7, 2017** (Port Scanning attack).

## Directory Structure
```
Friday_07_07_2017_PortScan/
├── pcap_cache/
│   ├── raw_data/
│   │   └── Friday_07_07_2017_PortScan_nids.jsonl    # 1,089 NIDS feature windows (20D)
│   ├── results/
│   │   ├── benchmark_results_all_modes.json
│   │   ├── benchmark_results_raw_ppo.json           # Layer 1: Raw PPO (baseline)
│   │   ├── benchmark_results_stateless.json         # Layer 2: AI agent
│   │   └── benchmark_results_window_reset.json      # Layer 3: System response
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
- **Extracted NIDS rows**: 1,089 (20D features)
- **Labeled rows**: 1,089

### Traffic Breakdown
| Label | Count | Expected Action | L1 Acc% | L2 Acc% | L3 Acc% |
|-------|-------|-----------------|---------|---------|---------|
| benign | 500 | Allow | 75.0% | 97.0% | 97.4% |
| scan_fw_off | 332 | Block | 69.9% | 69.9% | 89.2% |
| scan_fw_on | 257 | Block | 0.0% | 0.0% | 7.4% |

### 3-Layer Evaluation

#### Layer 1: Raw PPO (Baseline)
- **Overall Accuracy**: 55.7% (607/1089 rows)
- **Model**: 34D v13 (run_34d_v13/best_model)
- **Mode**: Pure PPO output, no override/safety guards
- **Mitigation Rate**: 48.5% (scan detection)

#### Layer 2: Stateless AI Agent (Per-Window)
- **Overall Accuracy**: 65.8% (717/1089 rows)
- **Model improvement over L1**: +10.1%
- **Benign accuracy improvement**: 75.0% → 97.0% (browse-guard active)
- **Mitigation Rate**: 47.1%

#### Layer 3: Window-Reset (System Response Timeline)
- **Overall Accuracy**: 73.7% (802/1089 rows)
- **Model improvement over L1**: +18.0%
- **Improved scan detection**: scan_fw_off 69.9% → 89.2%
- **Mitigation Rate**: 57.4% (escalation Redirect→Block for sustained scans)

## Attack Characteristics
1. **Scan with Firewall Off** (172.16.0.0/24 → attacker port scans)
   - 332 flows, mixed TCP/UDP ports
   - Detection more robust in L3 (escalation across time)

2. **Scan with Firewall On** (filtered by firewall, some flows pass)
   - 257 flows, primarily ICMP/UDP
   - Challenging to distinguish from benign traffic
   - L3 achieves 7.4% detection (hard negative)

3. **Benign Traffic** (background HTTP/HTTPS)
   - 500 flows, normal web browsing patterns
   - Browse-guard protects against false positives in L2/L3

## Feature Quality
L7 HTTP enrichment via tshark:
- **F1 (PacketRate)**: 11-127 packets/sec (higher for scanning)
- **F6 (URLConcentration)**: 0.0 (benign) → 1.0 (port scans)
- **F18 (XSS score)**: 0.0 (no L7 attack payload)

## Model Performance
- **Model version**: 34D (observation space with 4D effect vector)
- **Effect collector**: ON (OfflineEffectCollector for nginx feedback simulation)
- **Action space**: [Allow, RateLimit, Redirect, Block]
- **Special mode**: Browse-guard active (detects HTTP patterns)

## Files
- `raw_data/Friday_07_07_2017_PortScan_nids.jsonl`: Full labeled dataset (1,089 windows)
- `results/benchmark_results_*_modes.json`: Metrics for each evaluation layer
- `plots/chart*.png`: 5 visualization charts with .2f precision

## Key Findings
1. **Benign vs Scan Distinction**: L2 achieves 97% benign accuracy via browse-guard
2. **Firewall-bypass Challenge**: FW-On scans (scan_fw_on) difficult to detect (0-7.4%)
3. **Temporal Context Helps**: L3 escalation improves FW-Off scan detection (69.9% → 89.2%)
4. **L7 Indicators Weak**: HTTP features less useful for port scan detection (vs web attacks)

## Timezone & Dataset Info
- **Timezone**: CIC-IDS2017 in Halifax, Nova Scotia (ADT = UTC-3)
- **Dataset**: CIC-IDS2017 full PCAP capture from ISCX
- **Running mode**: Dry-run (no iptables action enforcement)

## Notes
- Port scanning is a network-layer attack, requires different feature set than web attacks
- Browse-guard is an effective heuristic for false positive reduction in L2
- Model struggles with firewall-mediated attacks (FW-On), suggesting need for timeout-based features

Generated: 2026-04-20 18:05 UTC
