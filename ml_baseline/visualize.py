"""
visualize.py
Sinh biểu đồ so sánh RL vs ML Baseline.

Usage:
    python visualize.py
    python visualize.py --ml_json ml_results_summary.json --rl_json rl_results_summary.json
"""

import argparse
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import os

# -------------------------------------------------------
# Dữ liệu mẫu (dùng khi chưa có file JSON thực)
# -------------------------------------------------------
SAMPLE_DATA = {
    'ml': {
        'accuracy'              : 0.94,
        'precision'             : 0.92,
        'recall'                : 0.91,
        'f1_score'              : 0.91,
        'mitigation_rate'       : 0.78,
        'fp_cost'               : 0.45,
        'action_efficiency'     : 0.82,
        'avg_response_ms'       : 2.1,
        'redirect_usage_rate'   : 0.11,
        'redirect_effectiveness': 0.71,
        'redirect_fp_reduction' : 0.34,
    },
    'rl': {
        'accuracy'              : 0.89,
        'precision'             : 0.87,
        'recall'                : 0.88,
        'f1_score'              : 0.87,
        'mitigation_rate'       : 0.91,
        'fp_cost'               : 0.28,
        'action_efficiency'     : 0.88,
        'avg_response_ms'       : 8.3,
        'redirect_usage_rate'   : 0.19,
        'redirect_effectiveness': 0.84,
        'redirect_fp_reduction' : 0.52,
    },
}

# Scenario 2: adaptive — RL cải thiện, ML giảm
SCENARIO2_OVER_TIME = {
    'steps'    : list(range(1, 11)),
    'ml_mrate' : [0.88, 0.87, 0.86, 0.85, 0.85, 0.84, 0.84, 0.83, 0.83, 0.82],
    'rl_mrate' : [0.82, 0.84, 0.86, 0.87, 0.88, 0.89, 0.89, 0.90, 0.91, 0.91],
}

COLORS = {'ml': '#4C72B0', 'rl': '#DD8452'}


# -------------------------------------------------------
def load_data(ml_json=None, rl_json=None):
    data = SAMPLE_DATA.copy()
    if ml_json and os.path.exists(ml_json):
        with open(ml_json) as f:
            data['ml'] = json.load(f)
        print(f"Loaded ML data from {ml_json}")
    else:
        print("Using sample ML data")

    if rl_json and os.path.exists(rl_json):
        with open(rl_json) as f:
            data['rl'] = json.load(f)
        print(f"Loaded RL data from {rl_json}")
    else:
        print("Using sample RL data")

    return data


def _bar(ax, labels, ml_vals, rl_vals, title, ylabel='Score',
         ylim=(0, 1.05), lower_is_better=False):
    x = np.arange(len(labels))
    b1 = ax.bar(x - 0.2, ml_vals, 0.35, label='ML Baseline', color=COLORS['ml'])
    b2 = ax.bar(x + 0.2, rl_vals, 0.35, label='RL Agent (PPO)', color=COLORS['rl'])
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha='right', fontsize=9)
    ax.set_ylim(*ylim)
    ax.set_title(title, fontsize=11, fontweight='bold')
    ax.set_ylabel(ylabel)
    ax.legend(fontsize=8)

    # Annotate bars
    for bar in [*b1, *b2]:
        h = bar.get_height()
        ax.annotate(f'{h:.2f}',
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords='offset points',
                    ha='center', va='bottom', fontsize=7)

    if lower_is_better:
        ax.set_title(title + '  (↓ lower is better)', fontsize=11, fontweight='bold')


# -------------------------------------------------------
def plot(data: dict, out='benchmark_results.png'):
    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    fig.suptitle('RL Agent (PPO) vs ML Baseline — Benchmark Results',
                 fontsize=14, fontweight='bold', y=1.01)

    ml, rl = data['ml'], data['rl']

    # --- (1) Detection metrics ---
    keys = ['accuracy', 'precision', 'recall', 'f1_score']
    _bar(axes[0, 0],
         labels=['Accuracy', 'Precision', 'Recall', 'F1'],
         ml_vals=[ml[k] for k in keys],
         rl_vals=[rl[k] for k in keys],
         title='(A) Detection Metrics')

    # --- (2) Mitigation Rate ---
    _bar(axes[0, 1],
         labels=['Mitigation Rate'],
         ml_vals=[ml['mitigation_rate']],
         rl_vals=[rl['mitigation_rate']],
         title='(B) Attack Mitigation Rate',
         ylim=(0, 1.1))

    # --- (3) False Positive Cost ---
    _bar(axes[0, 2],
         labels=['FP Cost (weighted)'],
         ml_vals=[ml['fp_cost']],
         rl_vals=[rl['fp_cost']],
         title='(B) False Positive Cost',
         ylim=(0, 0.7),
         lower_is_better=True)

    # --- (4) Redirect metrics ---
    rkeys = ['redirect_usage_rate', 'redirect_effectiveness', 'redirect_fp_reduction']
    _bar(axes[1, 0],
         labels=['Usage Rate', 'Effectiveness', 'FP Reduction'],
         ml_vals=[ml[k] for k in rkeys],
         rl_vals=[rl[k] for k in rkeys],
         title='(C) Redirect Metrics')

    # --- (5) Response Time ---
    ax = axes[1, 1]
    rt_data = {'ML Baseline': ml['avg_response_ms'], 'RL Agent (PPO)': rl['avg_response_ms']}
    bars = ax.bar(rt_data.keys(), rt_data.values(),
                  color=[COLORS['ml'], COLORS['rl']], width=0.4)
    ax.set_title('(B) Response Time  (↓ lower is better)',
                 fontsize=11, fontweight='bold')
    ax.set_ylabel('Avg Response Time (ms)')
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f'{h:.1f} ms',
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords='offset points',
                    ha='center', va='bottom', fontsize=9, fontweight='bold')

    # --- (6) Performance over time (Scenario 2) ---
    ax = axes[1, 2]
    s2 = SCENARIO2_OVER_TIME
    ax.plot(s2['steps'], s2['ml_mrate'], 'o-', label='ML Baseline', color=COLORS['ml'], linewidth=2)
    ax.plot(s2['steps'], s2['rl_mrate'], 's-', label='RL Agent',    color=COLORS['rl'], linewidth=2)
    ax.axvline(x=5, color='gray', linestyle='--', alpha=0.6, label='Attack changes')
    ax.set_title('(Scenario 2) Mitigation Rate Over Time', fontsize=11, fontweight='bold')
    ax.set_xlabel('Time Window')
    ax.set_ylabel('Mitigation Rate')
    ax.set_ylim(0.75, 0.96)
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))

    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches='tight')
    print(f"Saved chart: {out}")
    plt.show()


# -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ml_json', default=None,
                        help='Path to ML benchmark_results_summary.json')
    parser.add_argument('--rl_json', default=None,
                        help='Path to RL benchmark_results_summary.json')
    parser.add_argument('--out', default='benchmark_results.png')
    args = parser.parse_args()

    data = load_data(args.ml_json, args.rl_json)
    plot(data, out=args.out)


if __name__ == '__main__':
    main()
