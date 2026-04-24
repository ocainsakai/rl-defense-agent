"""
plot_benchmark_combined.py — Biểu đồ tổng hợp CIC-IDS2017 + CIC-IDS2018

Charts:
  1. Per-class recall L1/L2/L3 — IDS2018
  2. Per-class recall L1/L2/L3 — IDS2017 Thursday (BruteForce/XSS/SQLi)
  3. Cross-dataset comparison: 5 attack types L1 vs L3
  4. SYN Flood + PortScan FW-Off timeline (IDS2017 Friday)
  5. Confusion matrix L2 — IDS2018
  6. False Positive rate across 7 hosts (IDS2018)

Usage:
  python3 datasets/plot_benchmark_combined.py
  python3 datasets/plot_benchmark_combined.py --out datasets/plots/
"""

import argparse, json, os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE = Path(__file__).parent.parent
IDS2017_JSON  = BASE / "CIC-IDS2017/scripts/pcap_cache/benchmark_results_all_modes.json"
IDS2018_FRI   = BASE / "CSE-CIC-IDS2018/Friday_23_02_2018/pcap_cache/results_friday_2018/benchmark_results_all_modes.json"
IDS2018_THU   = BASE / "CSE-CIC-IDS2018/Thursday_22_02_2018/pcap_cache/results_thursday_2018/benchmark_results_all_modes.json"
IDS2018_FP    = BASE / "CSE-CIC-IDS2018/pcap_cache/benchmark_results_fp_all.json"

ACTION_COLORS = {
    'Allow':     '#4CAF50',
    'RateLimit': '#FF9800',
    'Redirect':  '#2196F3',
    'Block':     '#F44336',
}
LAYER_COLORS = ['#1565C0', '#43A047', '#E53935']
LAYER_LABELS = ['L1 — Raw PPO', 'L2 — AI Agent', 'L3 — Window-Reset']

LABEL_DISPLAY = {
    'benign':       'Benign',
    'brute_force':  'Brute Force',
    'xss':          'XSS',
    'sqli':         'SQLi',
    'syn_flood':    'SYN Flood',
    'scan_fw_on':   'PortScan\n(FW-On)',
    'scan_fw_off':  'PortScan\n(FW-Off)',
}

MODES = [('raw-ppo', 'L1'), ('stateless', 'L2'), ('window-reset', 'L3')]


def _acc(pc, lbl):
    return pc.get(lbl, {}).get('accuracy', 0) * 100


def _n(pc, lbl):
    return pc.get(lbl, {}).get('total', 0)


# ─── Chart 1: IDS2018 recall 3 layers ────────────────────────────────────────
def chart1_ids2018_3layers(data2018, out_dir):
    day_data = data2018.get('Friday-23-02-2018', next(iter(data2018.values())))
    labels   = ['benign', 'brute_force', 'xss', 'sqli']
    display  = [LABEL_DISPLAY[l] for l in labels]
    x = np.arange(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(11, 6))
    for i, (mode_key, mode_short) in enumerate(MODES):
        pc = day_data.get(mode_key, {}).get('per_class', {})
        vals = [_acc(pc, l) for l in labels]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, vals, width, label=LAYER_LABELS[i],
                      color=LAYER_COLORS[i], alpha=0.85, zorder=3)
        for bar, v in zip(bars, vals):
            if v >= 5:
                ax.text(bar.get_x() + bar.get_width()/2, v / 2,
                        f'{v:.2f}%', ha='center', va='center', fontsize=8,
                        color='white', fontweight='bold')

    l1_pc = day_data.get('raw-ppo', {}).get('per_class', {})
    for i, lbl in enumerate(labels):
        ax.text(i, 2, f'n={_n(l1_pc, lbl):,}', ha='center', fontsize=8, color='gray')

    ax.set_xticks(x); ax.set_xticklabels(display, fontsize=11)
    ax.set_ylim(0, 120)
    ax.set_ylabel('Accuracy (%)', fontsize=11)
    ax.set_title('CIC-IDS2018 — Per-class Accuracy Across 3 Layers\n(Friday 23-02-2018)', fontsize=12, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0); ax.set_axisbelow(True)
    ax.legend(fontsize=10, loc='lower right')
    plt.tight_layout()
    _save(fig, out_dir, 'chart1_ids2018_3layers.png')


# ─── Chart 2: IDS2017 Thursday recall 3 layers ───────────────────────────────
def chart2_ids2017_thursday(data2017, out_dir):
    day_data = data2017.get('Thursday-06-07-2017', {})
    labels   = ['benign', 'brute_force', 'xss', 'sqli']
    display  = [LABEL_DISPLAY[l] for l in labels]
    x = np.arange(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(11, 6))
    for i, (mode_key, _) in enumerate(MODES):
        pc = day_data.get(mode_key, {}).get('per_class', {})
        vals = [_acc(pc, l) for l in labels]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, vals, width, label=LAYER_LABELS[i],
                      color=LAYER_COLORS[i], alpha=0.85, zorder=3)
        for bar, v in zip(bars, vals):
            if v >= 5:
                ax.text(bar.get_x() + bar.get_width()/2, v / 2,
                        f'{v:.2f}%', ha='center', va='center', fontsize=8,
                        color='white', fontweight='bold')

    l1_pc = day_data.get('raw-ppo', {}).get('per_class', {})
    for i, lbl in enumerate(labels):
        ax.text(i, 2, f'n={_n(l1_pc, lbl):,}', ha='center', fontsize=8, color='gray')

    ax.set_xticks(x); ax.set_xticklabels(display, fontsize=11)
    ax.set_ylim(0, 120)
    ax.set_ylabel('Accuracy (%)', fontsize=11)
    ax.set_title('CIC-IDS2017 — Per-class Accuracy Across 3 Layers\n(Thursday 06-07-2017: BruteForce / XSS / SQLi)', fontsize=12, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0); ax.set_axisbelow(True)
    ax.legend(fontsize=10, loc='lower right')
    plt.tight_layout()
    _save(fig, out_dir, 'chart2_ids2017_thursday_3layers.png')


# ─── Chart 3: Cross-dataset 5 attack types L1 vs L3 ─────────────────────────
def chart3_cross_dataset(data2017, data2018, out_dir):
    # Gather: attack → {dataset → {L1, L3}}
    entries = [
        # (label_display, ids2018_day, ids2018_lbl, ids2017_day, ids2017_lbl)
        ('BruteForce', 'Friday-23-02-2018', 'brute_force', 'Thursday-06-07-2017', 'brute_force'),
        ('XSS',        'Friday-23-02-2018', 'xss',         'Thursday-06-07-2017', 'xss'),
        ('SQLi',       'Friday-23-02-2018', 'sqli',        'Thursday-06-07-2017', 'sqli'),
    ]

    attack_labels = [e[0] for e in entries]
    # Add SYN Flood (IDS2017 only) and PortScan FW-Off (IDS2017 only)
    attack_labels += ['SYN Flood', 'PortScan\n(FW-Off)']

    def get_acc(data, day, lbl, mode):
        pc = data.get(day, {}).get(mode, {}).get('per_class', {})
        return _acc(pc, lbl)

    # Build values: IDS2018 L1, IDS2018 L3, IDS2017 L1, IDS2017 L3
    v18_l1, v18_l3, v17_l1, v17_l3 = [], [], [], []
    for _, d18, l18, d17, l17 in entries:
        v18_l1.append(get_acc(data2018, d18, l18, 'raw-ppo'))
        v18_l3.append(get_acc(data2018, d18, l18, 'window-reset'))
        v17_l1.append(get_acc(data2017, d17, l17, 'raw-ppo'))
        v17_l3.append(get_acc(data2017, d17, l17, 'window-reset'))

    # SYN Flood — IDS2017 only
    v18_l1.append(0); v18_l3.append(0)
    v17_l1.append(get_acc(data2017, 'Friday-07-07-2017-DDoS', 'syn_flood', 'raw-ppo'))
    v17_l3.append(get_acc(data2017, 'Friday-07-07-2017-DDoS', 'syn_flood', 'window-reset'))

    # PortScan FW-Off — IDS2017 only
    v18_l1.append(0); v18_l3.append(0)
    v17_l1.append(get_acc(data2017, 'Friday-07-07-2017-PortScan', 'scan_fw_off', 'raw-ppo'))
    v17_l3.append(get_acc(data2017, 'Friday-07-07-2017-PortScan', 'scan_fw_off', 'window-reset'))

    x = np.arange(len(attack_labels))
    width = 0.2
    fig, ax = plt.subplots(figsize=(13, 6))

    colors = ['#1565C0', '#90CAF9', '#E53935', '#FFCDD2']
    bar_defs = [
        (v18_l1, 'IDS2018 L1', colors[0], -1.5),
        (v18_l3, 'IDS2018 L3', colors[1], -0.5),
        (v17_l1, 'IDS2017 L1', colors[2],  0.5),
        (v17_l3, 'IDS2017 L3', colors[3],  1.5),
    ]
    for i, (vals, label, color, offset) in enumerate(bar_defs):
        bars = ax.bar(x + offset*width, vals, width, label=label,
                      color=color, alpha=0.88, zorder=3)
        for bar, v in zip(bars, vals):
            if v >= 1:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                        f'{v:.2f}%', ha='center', va='bottom', fontsize=7.5,
                        color=color, fontweight='bold')

    ax.set_xticks(x); ax.set_xticklabels(attack_labels, fontsize=11)
    ax.set_ylim(0, 118)
    ax.set_ylabel('Accuracy (%)', fontsize=11)
    ax.set_title('Cross-Dataset Comparison — 5 Attack Types\nCIC-IDS2017 vs CIC-IDS2018 | L1 Raw PPO vs L3 Window-Reset', fontsize=12, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0); ax.set_axisbelow(True)
    ax.legend(fontsize=10, ncol=2)
    # Annotate IDS2017-only attacks
    for xi in [3, 4]:
        ax.annotate('IDS2017 only', xy=(xi, 5), ha='center', fontsize=8, color='gray', style='italic')
    plt.tight_layout()
    _save(fig, out_dir, 'chart3_cross_dataset_5attacks.png')


# ─── Chart 4: IDS2017 Friday — SYN Flood + PortScan timeline L3 ──────────────
def chart4_friday_timeline(data2017, out_dir):
    ddos_data = data2017.get('Friday-07-07-2017-DDoS', {}).get('window-reset', {}).get('per_class', {})
    scan_data = data2017.get('Friday-07-07-2017-PortScan', {}).get('window-reset', {}).get('per_class', {})

    buckets_display = ['0–15s\n(initial)', '15–60s\n(escalate)', '60–300s\n(sustained)', '300s+\n(long-run)']
    buckets_key     = ['0-15s   (initial)', '15-60s  (escalate)', '60-300s (sustained)', '300s+   (long-run)']

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))
    configs = [
        ('SYN Flood', ddos_data.get('syn_flood', {})),
        ('PortScan (FW-On)',  scan_data.get('scan_fw_on', {})),
        ('PortScan (FW-Off)', scan_data.get('scan_fw_off', {})),
    ]

    actions = ['Allow', 'RateLimit', 'Redirect', 'Block']
    for ax, (title, pc) in zip(axes, configs):
        tl = pc.get('timeline', {})
        bottoms = np.zeros(len(buckets_key))
        for action in actions:
            vals = [tl.get(bk, {}).get(action, 0) for bk in buckets_key]
            ax.bar(np.arange(len(buckets_key)), vals, bottom=bottoms,
                   color=ACTION_COLORS[action], alpha=0.88, zorder=3)
            for i, (v, b) in enumerate(zip(vals, bottoms)):
                tot = sum(tl.get(bk, {}).get(a, 0) for bk in [buckets_key[i]] for a in actions)
                if v > 0 and tot > 0 and v/tot >= 0.08:
                    ax.text(i, b + v/2, f'{v/tot*100:.0f}%', ha='center', va='center',
                            fontsize=8.5, color='white', fontweight='bold')
            bottoms = bottoms + np.array(vals)

        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.set_xticks(np.arange(len(buckets_key)))
        ax.set_xticklabels(buckets_display, fontsize=8.5)
        ax.set_ylabel('Packets (1s windows)' if ax == axes[0] else '', fontsize=9)
        ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0); ax.set_axisbelow(True)

    legend_handles = [mpatches.Patch(color=ACTION_COLORS[a], label=a) for a in actions]
    fig.legend(handles=legend_handles, fontsize=9, loc='lower center',
               ncol=4, bbox_to_anchor=(0.5, -0.02), frameon=True)
    fig.suptitle('CIC-IDS2017 Friday — Attack Response Timeline (L3 Window-Reset)', fontsize=12, fontweight='bold')
    plt.tight_layout(rect=[0, 0.06, 1, 1])
    _save(fig, out_dir, 'chart4_ids2017_friday_timeline.png')


# ─── Chart 5: Confusion matrix IDS2018 L2 ────────────────────────────────────
def chart5_confusion_matrix(data2018, out_dir):
    day_data = data2018.get('Friday-23-02-2018', next(iter(data2018.values())))
    cm_raw   = day_data.get('stateless', {}).get('confusion_matrix', {})
    actions  = ['Allow', 'RateLimit', 'Redirect', 'Block']
    gt_labels = sorted(cm_raw.keys())

    matrix = np.zeros((len(gt_labels), len(actions)), dtype=int)
    for i, gt in enumerate(gt_labels):
        for j, pred in enumerate(actions):
            matrix[i][j] = cm_raw.get(gt, {}).get(pred, 0)

    row_sums = matrix.sum(axis=1, keepdims=True)
    matrix_norm = matrix / np.maximum(row_sums, 1)

    fig, ax = plt.subplots(figsize=(7, 3.5))
    im = ax.imshow(matrix_norm, cmap='Blues', vmin=0, vmax=1, aspect='auto')
    ax.set_xticks(range(len(actions)));    ax.set_xticklabels(actions, fontsize=11)
    ax.set_yticks(range(len(gt_labels))); ax.set_yticklabels(gt_labels, fontsize=11)
    ax.set_xlabel('Predicted Action', fontsize=11)
    ax.set_ylabel('Ground Truth', fontsize=11)
    ax.set_title('Confusion Matrix — L2 AI Agent\n(CIC-IDS2018 Friday 23-02-2018, row-normalized)', fontsize=12, fontweight='bold')

    for i in range(len(gt_labels)):
        for j in range(len(actions)):
            count = matrix[i][j]
            pct   = matrix_norm[i][j]
            if count == 0: continue
            color = 'white' if pct > 0.55 else 'black'
            ax.text(j, i, f'{pct*100:.2f}%\n({count:,})',
                    ha='center', va='center', fontsize=9, color=color, fontweight='bold')

    plt.colorbar(im, ax=ax, label='Recall fraction')
    plt.tight_layout()
    _save(fig, out_dir, 'chart5_ids2018_confusion_L2.png')


# ─── Chart 6: False Positive rate 7 hosts ────────────────────────────────────
def chart6_false_positive(fp_data, out_dir):
    hosts, accs = [], []
    for day, modes in fp_data.items():
        pc = modes.get('stateless', {}).get('per_class', {})
        b  = pc.get('benign', {})
        hosts.append(day.replace('FP-Test-UCAP', '').replace('FP-Test-', ''))
        accs.append(b.get('accuracy', 0) * 100)

    avg = sum(accs) / len(accs)
    x   = np.arange(len(hosts))

    fig, ax = plt.subplots(figsize=(11, 5))
    colors = ['#43A047' if a >= 97 else '#FF9800' for a in accs]
    bars = ax.bar(x, accs, color=colors, alpha=0.88, zorder=3, width=0.6)
    for bar, v in zip(bars, accs):
        ax.text(bar.get_x() + bar.get_width()/2, (v - 90) / 2 + 90,
                f'{v:.2f}%', ha='center', va='center', fontsize=10,
                fontweight='bold', color='white')

    ax.axhline(avg, color='#E53935', linestyle='--', linewidth=1.5,
               label=f'Average: {avg:.1f}%', zorder=4)
    ax.axhline(100, color='gray', linestyle=':', linewidth=1, alpha=0.5)

    ax.set_xticks(x); ax.set_xticklabels(hosts, fontsize=10, rotation=15, ha='right')
    ax.set_ylim(90, 104)
    ax.set_ylabel('Benign Accuracy — True Negative Rate (%)', fontsize=11)
    ax.set_title('False Positive Test — Benign Traffic Classification\n(CIC-IDS2018, 7 Independent Hosts, L2 AI Agent)', fontsize=12, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0); ax.set_axisbelow(True)
    ax.legend(fontsize=10)
    plt.tight_layout()
    _save(fig, out_dir, 'chart6_false_positive_7hosts.png')


# ─── Chart 7: IDS2018 Thursday recall 3 layers (Benchmark) ───────────────────
def chart7_ids2018_thursday_3layers(data2018, out_dir):
    day_data = data2018.get('Thursday-22-02-2018', {})
    labels   = ['benign', 'brute_force', 'xss', 'sqli']
    display  = [LABEL_DISPLAY[l] for l in labels]
    x = np.arange(len(labels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(11, 6))
    for i, (mode_key, _) in enumerate(MODES):
        pc = day_data.get(mode_key, {}).get('per_class', {})
        vals = [_acc(pc, l) for l in labels]
        offset = (i - 1) * width
        bars = ax.bar(x + offset, vals, width, label=LAYER_LABELS[i],
                      color=LAYER_COLORS[i], alpha=0.85, zorder=3)
        for bar, v in zip(bars, vals):
            if v >= 5:
                ax.text(bar.get_x() + bar.get_width()/2, v / 2,
                        f'{v:.2f}%', ha='center', va='center', fontsize=8,
                        color='white', fontweight='bold')

    l1_pc = day_data.get('raw-ppo', {}).get('per_class', {})
    for i, lbl in enumerate(labels):
        ax.text(i, 2, f'n={_n(l1_pc, lbl):,}', ha='center', fontsize=8, color='gray')

    ax.set_xticks(x); ax.set_xticklabels(display, fontsize=11)
    ax.set_ylim(0, 120)
    ax.set_ylabel('Accuracy (%)', fontsize=11)
    ax.set_title('CIC-IDS2018 — Per-class Accuracy Across 3 Layers\n(Thursday 22-02-2018: Benign + Synthetic Benchmark)', fontsize=12, fontweight='bold')
    ax.yaxis.grid(True, linestyle='--', alpha=0.4, zorder=0); ax.set_axisbelow(True)
    ax.legend(fontsize=10, loc='lower right')
    plt.tight_layout()
    _save(fig, out_dir, 'chart7_ids2018_thursday_3layers.png')


# ─── Helper ───────────────────────────────────────────────────────────────────
def _save(fig, out_dir, name):
    out = os.path.join(out_dir, name)
    fig.savefig(out, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [OK] {out}')


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default=str(BASE / 'plots'))
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    data2017 = json.loads(IDS2017_JSON.read_text())
    
    data2018 = {}
    if IDS2018_FRI.exists():
        data2018.update(json.loads(IDS2018_FRI.read_text()))
    if IDS2018_THU.exists():
        data2018.update(json.loads(IDS2018_THU.read_text()))
        
    fp_data  = json.loads(IDS2018_FP.read_text()) if IDS2018_FP.exists() else {}

    print(f'\n[*] Output: {args.out}\n')
    chart1_ids2018_3layers(data2018, args.out)
    chart2_ids2017_thursday(data2017, args.out)
    chart7_ids2018_thursday_3layers(data2018, args.out)
    chart3_cross_dataset(data2017, data2018, args.out)
    chart4_friday_timeline(data2017, args.out)
    chart5_confusion_matrix(data2018, args.out)
    if fp_data:
        chart6_false_positive(fp_data, args.out)
    print(f'\n[+] Done — {args.out}/')


if __name__ == '__main__':
    main()
