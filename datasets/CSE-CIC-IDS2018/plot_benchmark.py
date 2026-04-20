"""
plot_benchmark.py — Sinh biểu đồ từ benchmark_results_all_modes.json

Sinh ra 4 biểu đồ:
  1. Per-class recall so sánh L1 / L2 (bar chart)
  2. Confusion matrix L1 raw-PPO (heatmap)
  3. Attack response timeline L3 window-reset (stacked bar)
  4. Pred distribution L1 theo từng traffic type (stacked bar)

Usage:
  cd datasets/CSE-CIC-IDS2018
  python3 plot_benchmark.py
  python3 plot_benchmark.py --results pcap_cache/benchmark_results_all_modes.json --out plots/
"""

import argparse
import json
import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

# ─── Config ───────────────────────────────────────────────────────────────────
ACTION_COLORS = {
    'Allow':     '#4CAF50',   # green
    'RateLimit': '#FF9800',   # orange
    'Redirect':  '#2196F3',   # blue
    'Block':     '#F44336',   # red
}

LABEL_DISPLAY = {
    'benign':      'Benign',
    'brute_force': 'Brute Force',
    'xss':         'XSS',
    'sqli':        'SQLi',
}

TIMELINE_ORDER = [
    '0-15s   (initial)',
    '15-60s  (escalate)',
    '60-300s (sustained)',
    '300s+   (long-run)',
]

# ─── Load data ────────────────────────────────────────────────────────────────
def load_results(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# ─── Chart 1: Per-class recall L1 vs L2 ──────────────────────────────────────
def plot_recall_comparison(day_data: dict, out_dir: str):
    """Bar chart so sánh recall giữa L1 (raw-ppo) và L2 (stateless)."""
    labels_order = ['benign', 'brute_force', 'xss', 'sqli']
    l1 = day_data.get('raw-ppo', {}).get('per_class', {})
    l2 = day_data.get('stateless', {}).get('per_class', {})

    x      = np.arange(len(labels_order))
    width  = 0.35
    recalls_l1 = [l1.get(lbl, {}).get('recall', 0) * 100 for lbl in labels_order]
    recalls_l2 = [l2.get(lbl, {}).get('recall', 0) * 100 for lbl in labels_order]
    display    = [LABEL_DISPLAY.get(l, l) for l in labels_order]
    samples    = [l1.get(lbl, {}).get('total', 0) for lbl in labels_order]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars1 = ax.bar(x - width/2, recalls_l1, width, label='L1 — Raw PPO',
                   color='#1565C0', alpha=0.85, zorder=3)
    bars2 = ax.bar(x + width/2, recalls_l2, width, label='L2 — AI Agent (stateless)',
                   color='#43A047', alpha=0.85, zorder=3)

    # Value labels — always inside bar, white text
    for bar in list(bars1) + list(bars2):
        h = bar.get_height()
        if h < 5:
            continue  # skip near-zero bars
        ax.text(bar.get_x() + bar.get_width()/2, h - 2.5,
                f'{h:.1f}%', ha='center', va='top', fontsize=9,
                color='white', fontweight='bold')

    ax.set_xlabel('Traffic Type', fontsize=11)
    ax.set_ylabel('Recall (%)', fontsize=11)
    ax.set_title('Per-class Recall: L1 Raw PPO vs L2 AI Agent\n(CIC-IDS2018 Thursday)', fontsize=12, fontweight='bold')
    ax.set_xticks(x)
    xlabels1 = [f'{d}\n(n={n:,})' for d, n in zip(display, samples)]
    ax.set_xticklabels(xlabels1, fontsize=10)
    ax.set_ylim(0, 100)
    ax.yaxis.grid(True, linestyle='--', alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(fontsize=10)

    plt.tight_layout()
    out = os.path.join(out_dir, 'chart1_recall_L1_L2.png')
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [✓] {out}')


# ─── Chart 2: Confusion matrix heatmap (L1 raw-ppo) ─────────────────────────
def plot_confusion_matrix(day_data: dict, out_dir: str):
    """Heatmap confusion matrix cho L1 raw-ppo."""
    cm_raw = day_data.get('raw-ppo', {}).get('confusion_matrix', {})
    actions = ['Allow', 'RateLimit', 'Redirect', 'Block']

    # Build matrix: rows = GT, cols = Pred
    gt_labels = sorted(cm_raw.keys())   # ['Allow', 'Redirect']
    matrix = np.zeros((len(gt_labels), len(actions)), dtype=int)
    for i, gt in enumerate(gt_labels):
        for j, pred in enumerate(actions):
            matrix[i][j] = cm_raw.get(gt, {}).get(pred, 0)

    # Normalize per row (recall-normalized)
    row_sums = matrix.sum(axis=1, keepdims=True)
    matrix_norm = matrix / np.maximum(row_sums, 1)

    fig, ax = plt.subplots(figsize=(7, 3.5))
    im = ax.imshow(matrix_norm, cmap='Blues', vmin=0, vmax=1, aspect='auto')

    ax.set_xticks(range(len(actions)))
    ax.set_xticklabels(actions, fontsize=11)
    ax.set_yticks(range(len(gt_labels)))
    ax.set_yticklabels(gt_labels, fontsize=11)
    ax.set_xlabel('Predicted Action', fontsize=11)
    ax.set_ylabel('Ground Truth', fontsize=11)
    ax.set_title('Confusion Matrix — L1 Raw PPO\n(CIC-IDS2018 Thursday, row-normalized)', fontsize=12, fontweight='bold')

    for i in range(len(gt_labels)):
        for j in range(len(actions)):
            count = matrix[i][j]
            pct   = matrix_norm[i][j]
            if count == 0:
                continue
            color = 'white' if pct > 0.55 else 'black'
            ax.text(j, i, f'{pct*100:.1f}%\n({count})',
                    ha='center', va='center', fontsize=9.5, color=color, fontweight='bold')

    plt.colorbar(im, ax=ax, label='Recall fraction')
    plt.tight_layout()
    out = os.path.join(out_dir, 'chart2_confusion_matrix_L1.png')
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [✓] {out}')


# ─── Chart 3: Attack response timeline L3 ────────────────────────────────────
def plot_timeline(day_data: dict, out_dir: str):
    """Stacked bar cho attack response timeline trong L3 window-reset."""
    wr = day_data.get('window-reset', {}).get('per_class', {})
    attack_labels = ['brute_force', 'xss', 'sqli']
    display = [LABEL_DISPLAY.get(l, l) for l in attack_labels]

    # Buckets present in data (some attacks may skip early buckets)
    buckets = ['15-60s  (escalate)', '60-300s (sustained)', '300s+   (long-run)']
    bucket_display = ['t=15–60s\n(escalate)', 't=60–300s\n(sustained)', 't=300s+\n(long-run)']

    n_attacks = len(attack_labels)
    n_buckets = len(buckets)
    fig, axes = plt.subplots(1, n_attacks, figsize=(12, 5), sharey=False)

    for col, (lbl, disp) in enumerate(zip(attack_labels, display)):
        ax = axes[col]
        tl = wr.get(lbl, {}).get('timeline', {})

        redirect_counts = []
        block_counts    = []
        totals          = []
        for bkt in buckets:
            bdata = tl.get(bkt, {})
            r = bdata.get('Redirect', 0)
            b = bdata.get('Block', 0)
            redirect_counts.append(r)
            block_counts.append(b)
            totals.append(r + b + bdata.get('Allow', 0) + bdata.get('RateLimit', 0))

        x = np.arange(n_buckets)
        ax.bar(x, redirect_counts, label='Redirect', color=ACTION_COLORS['Redirect'], alpha=0.85, zorder=3)
        ax.bar(x, block_counts,    bottom=redirect_counts, label='Block',
               color=ACTION_COLORS['Block'], alpha=0.85, zorder=3)

        # Percentage labels — chỉ hiển thị nếu segment đủ lớn (>= 5% tổng)
        for i, (r, b, tot) in enumerate(zip(redirect_counts, block_counts, totals)):
            if tot == 0:
                continue
            if r > 0 and r / tot >= 0.05:
                ax.text(i, r/2, f'{r/tot*100:.0f}%', ha='center', va='center',
                        fontsize=8.5, color='white', fontweight='bold')
            if b > 0 and b / tot >= 0.05:
                ax.text(i, r + b/2, f'{b/tot*100:.0f}%', ha='center', va='center',
                        fontsize=8.5, color='white', fontweight='bold')

        ax.set_title(disp, fontsize=12, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(bucket_display, fontsize=8.5)
        ax.set_ylabel('Windows (1s each)' if col == 0 else '', fontsize=10)
        ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0)
        ax.set_axisbelow(True)
        if col == 0:
            ax.legend(fontsize=9, loc='upper left')

    fig.suptitle('Attack Response Timeline — L3 System (window-reset)\nRedirect → Block Escalation after ~15s',
                 fontsize=12, fontweight='bold')
    plt.tight_layout()
    out = os.path.join(out_dir, 'chart3_timeline_L3.png')
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [✓] {out}')


# ─── Chart 4: Predict distribution per traffic type (L1) ─────────────────────
def plot_pred_distribution(day_data: dict, out_dir: str):
    """Stacked bar: phân bố action predict theo từng traffic type ở L1."""
    l1 = day_data.get('raw-ppo', {}).get('per_class', {})
    labels_order = ['benign', 'brute_force', 'xss', 'sqli']
    display = [LABEL_DISPLAY.get(l, l) for l in labels_order]
    actions = ['Allow', 'RateLimit', 'Redirect', 'Block']

    fig, ax = plt.subplots(figsize=(7, 4))
    x = np.arange(len(labels_order))
    bottoms = np.zeros(len(labels_order))

    for action in actions:
        counts = []
        for lbl in labels_order:
            pd = l1.get(lbl, {}).get('pred_dist', {})
            total = l1.get(lbl, {}).get('total', 1)
            counts.append(pd.get(action, 0) / total * 100)
        bars = ax.bar(x, counts, width=0.5, bottom=bottoms, label=action,
                      color=ACTION_COLORS[action], alpha=0.88, zorder=3)
        for i, (c, b) in enumerate(zip(counts, bottoms)):
            if c >= 3.0:
                ax.text(i, b + c/2, f'{c:.1f}%', ha='center', va='center',
                        fontsize=8.5, color='white', fontweight='bold')
        bottoms = bottoms + np.array(counts)

    ax.set_xticks(x)
    # n= dưới tên traffic type, không dùng ax.text âm
    xlabels = [f'{d}\n(n={l1.get(lbl,{}).get("total",0):,})'
               for d, lbl in zip(display, labels_order)]
    ax.set_xticklabels(xlabels, fontsize=10)
    ax.set_ylabel('Proportion of predictions (%)', fontsize=10)
    ax.set_ylim(0, 100)
    ax.set_title('Prediction Distribution per Traffic Type — L1 Raw PPO\n(CIC-IDS2018 Thursday)',
                 fontsize=11, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(fontsize=9, loc='upper right',
              handles=[mpatches.Patch(color=ACTION_COLORS[a], label=a) for a in actions])

    plt.tight_layout()
    out = os.path.join(out_dir, 'chart4_pred_distribution_L1.png')
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [✓] {out}')


# ─── Chart 5: Recall so sánh 3 layers (thay thế mitigate_rate vô nghĩa) ───────
def plot_mitigate_rate(day_data: dict, out_dir: str):
    """Bar chart recall (correct action %) cho 3 layers — thể hiện đúng sự khác biệt."""
    modes = [('raw-ppo', 'L1 Raw PPO'), ('stateless', 'L2 AI Agent'), ('window-reset', 'L3 System')]
    labels_order = ['benign', 'brute_force', 'xss', 'sqli']
    display = [LABEL_DISPLAY.get(l, l) for l in labels_order]

    x = np.arange(len(labels_order))
    width = 0.25
    colors = ['#1565C0', '#43A047', '#E53935']

    fig, ax = plt.subplots(figsize=(10, 5))
    for i, (mode_key, mode_label) in enumerate(modes):
        pc = day_data.get(mode_key, {}).get('per_class', {})
        rates = [pc.get(lbl, {}).get('recall', 0) * 100 for lbl in labels_order]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, rates, width, label=mode_label,
                      color=colors[i], alpha=0.85, zorder=3)
        for bar, r in zip(bars, rates):
            if r < 5:
                continue  # skip near-zero bars
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() - 2.5,
                    f'{r:.1f}%', ha='center', va='top', fontsize=8.5,
                    color='white', fontweight='bold')

    ax.set_xticks(x)
    ax.set_xticklabels(display, fontsize=11)
    ax.set_ylabel('Recall — Correct Action (%)', fontsize=11)
    ax.set_ylim(0, 100)
    ax.set_title('Per-class Recall Across 3 Evaluation Layers\n(CIC-IDS2018 Thursday)', fontsize=12, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(fontsize=10)

    plt.tight_layout()
    out = os.path.join(out_dir, 'chart5_mitigate_rate_3layers.png')
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [✓] {out}')


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Plot benchmark results')
    parser.add_argument('--results', default='pcap_cache/benchmark_results_all_modes.json')
    parser.add_argument('--out',     default='pcap_cache/plots')
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    results = load_results(args.results)

    day = 'Thursday-22-02-2018'
    if day not in results:
        day = next(iter(results))
    day_data = results[day]

    print(f'\n[*] Generating charts for: {day}')
    print(f'[*] Output dir: {args.out}\n')

    plot_recall_comparison(day_data, args.out)
    plot_confusion_matrix(day_data, args.out)
    plot_timeline(day_data, args.out)
    plot_pred_distribution(day_data, args.out)
    plot_mitigate_rate(day_data, args.out)

    print(f'\n[+] Done — {args.out}/')


if __name__ == '__main__':
    main()
