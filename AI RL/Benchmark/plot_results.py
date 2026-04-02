"""
Benchmark Results Visualization

Generates 5 publication-quality charts (300 DPI) from benchmark_results.json.

Charts:
  01_mean_reward_ci.png      — Bar + 95% CI
  02_action_distribution.png — Stacked bar
  03_learning_curves.png     — Line + shaded std (placeholder; real curves need TB logs)
  04_confusion_matrix_*.png  — 5 heatmaps (one per algorithm)
  05_radar_chart.png         — Multi-metric radar

Usage:
  cd "AI RL/Benchmark"
  python3 plot_results.py
"""

import os
import json
import math
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

# ============================================================================
# CONFIG
# ============================================================================

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "results", "benchmark_results.json")
CHARTS_DIR   = os.path.join(os.path.dirname(__file__), "charts")
os.makedirs(CHARTS_DIR, exist_ok=True)

DPI = 300

ALGO_LABELS = {
    "ppo_tuned":   "PPO-Tuned",
    "ppo_default": "PPO-Default",
    "a2c":         "A2C",
    "dqn":         "DQN",
    "rule_based":  "Rule-Based",
}
ALGO_ORDER = ["ppo_tuned", "ppo_default", "a2c", "dqn", "rule_based"]

COLORS = {
    "ppo_tuned":   "#1f77b4",
    "ppo_default": "#ff7f0e",
    "a2c":         "#2ca02c",
    "dqn":         "#d62728",
    "rule_based":  "#9467bd",
}

ACTION_COLORS = ["#2ca02c", "#ffdd57", "#ff8c00", "#d62728"]  # Allow, RL, Redirect, Block
ACTION_NAMES  = ["Allow", "RateLimit", "Redirect", "Block"]

# IEEE-compatible font
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.labelsize": 11,
    "axes.titlesize": 12,
    "legend.fontsize": 9,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
})

# ============================================================================
# LOAD DATA
# ============================================================================

def load_results():
    with open(RESULTS_PATH) as f:
        return json.load(f)

def get_agg(results, algo):
    return results.get(algo, {}).get("_aggregate", None)

# ============================================================================
# CHART 1 — Mean Episode Reward + 95% CI
# ============================================================================

def plot_mean_reward_ci(results):
    fig, ax = plt.subplots(figsize=(7, 4.5))

    labels, means, ci95s, colors_list = [], [], [], []
    for algo in ALGO_ORDER:
        agg = get_agg(results, algo)
        if agg is None:
            continue
        labels.append(ALGO_LABELS[algo])
        means.append(agg["mean_reward"])
        ci95s.append(agg["ci95"])
        colors_list.append(COLORS[algo])

    x = np.arange(len(labels))
    bars = ax.bar(x, means, color=colors_list, alpha=0.85, edgecolor="black", linewidth=0.7)
    ax.errorbar(x, means, yerr=ci95s, fmt="none", ecolor="black", elinewidth=1.5,
                capsize=5, capthick=1.5)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Mean Episode Reward")
    ax.set_title("Mean Episode Reward ± 95% CI\n"
                 "(5 random seeds × 30 eval episodes each)")
    ax.axhline(0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)

    # Value labels on bars
    for bar, val, ci in zip(bars, means, ci95s):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + ci + 0.01,
                f"{val:.3f}", ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, "01_mean_reward_ci.png")
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved: {path}")

# ============================================================================
# CHART 2 — Stacked Bar: Action Distribution
# ============================================================================

def plot_action_distribution(results):
    fig, ax = plt.subplots(figsize=(7, 4.5))

    algos_present = [a for a in ALGO_ORDER if get_agg(results, a) is not None]
    labels = [ALGO_LABELS[a] for a in algos_present]
    dists  = np.array([get_agg(results, a)["action_dist_mean"] for a in algos_present])

    x = np.arange(len(labels))
    bar_w = 0.55
    bottoms = np.zeros(len(labels))

    patches = []
    for i, (aname, acolor) in enumerate(zip(ACTION_NAMES, ACTION_COLORS)):
        bars = ax.bar(x, dists[:, i], bar_w, bottom=bottoms,
                      color=acolor, label=aname, edgecolor="white", linewidth=0.5)
        bottoms += dists[:, i]
        patches.append(mpatches.Patch(color=acolor, label=aname))

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Action Proportion (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Action Distribution by Algorithm")
    ax.legend(handles=patches, loc="upper right", ncol=2)
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)

    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, "02_action_distribution.png")
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved: {path}")

# ============================================================================
# CHART 3 — Learning Curves (from per-seed episode rewards as proxy)
# ============================================================================

def plot_learning_curves(results):
    """
    Plots mean ± std of episode rewards across seeds as a proxy learning curve.
    X axis = episode index (not timesteps, since we don't have TB log data here).
    For actual timestep-based curves, use TensorBoard.
    """
    fig, ax = plt.subplots(figsize=(8, 5))

    for algo in ALGO_ORDER:
        if algo == "rule_based":
            continue
        algo_data = results.get(algo, {})
        seed_rewards = []
        for seed in [42, 123, 456, 789, 1337]:
            key = str(seed)
            if key in algo_data:
                seed_rewards.append(algo_data[key]["episode_rewards"])

        if not seed_rewards:
            continue

        max_len = max(len(r) for r in seed_rewards)
        padded  = np.array([r + [r[-1]] * (max_len - len(r)) for r in seed_rewards])
        mean    = padded.mean(axis=0)
        std     = padded.std(axis=0)
        x       = np.arange(1, max_len + 1)

        ax.plot(x, mean, label=ALGO_LABELS[algo], color=COLORS[algo], linewidth=1.8)
        ax.fill_between(x, mean - std, mean + std, color=COLORS[algo], alpha=0.15)

    # Rule-based horizontal line
    rb_agg = get_agg(results, "rule_based")
    if rb_agg:
        rb_val = rb_agg["mean_reward"]
        ax.axhline(rb_val, color=COLORS["rule_based"], linewidth=1.5,
                   linestyle="--", label=f"Rule-Based ({rb_val:.3f})")

    ax.set_xlabel("Evaluation Episode Index")
    ax.set_ylabel("Episode Reward")
    ax.set_title("Reward per Evaluation Episode\n(mean ± std across 5 seeds)")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    sns.despine(ax=ax)

    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, "03_learning_curves.png")
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved: {path}")

# ============================================================================
# CHART 4 — Confusion Matrix Heatmaps (one per algo)
# ============================================================================

def plot_confusion_matrices(results):
    ACTION_TICK = ["Allow", "RateLimit", "Redirect", "Block"]

    for algo in ALGO_ORDER:
        agg = get_agg(results, algo)
        if agg is None:
            continue

        cm = np.array(agg["confusion_matrix_mean"])

        # Row-normalize to %
        row_sums = cm.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1   # avoid div-by-zero
        cm_norm = cm / row_sums * 100

        fig, ax = plt.subplots(figsize=(5, 4))
        sns.heatmap(
            cm_norm,
            annot=True,
            fmt=".1f",
            cmap="Blues",
            xticklabels=ACTION_TICK,
            yticklabels=ACTION_TICK,
            ax=ax,
            linewidths=0.5,
            cbar_kws={"label": "Row %"},
        )
        ax.set_xlabel("Predicted Action")
        ax.set_ylabel("Ground-Truth Optimal Action")
        ax.set_title(f"Confusion Matrix — {ALGO_LABELS[algo]}\n"
                     "(row-normalized %, avg across 5 seeds)")
        fig.tight_layout()
        fname = f"04_confusion_matrix_{algo}.png"
        path  = os.path.join(CHARTS_DIR, fname)
        fig.savefig(path, dpi=DPI, bbox_inches="tight")
        plt.close(fig)
        print(f"[+] Saved: {path}")

# ============================================================================
# CHART 5 — Radar Chart
# ============================================================================

def _radar_axis_data(results):
    """
    5 axes: MeanReward | DetectionRate | Precision(1-FPR) | ActionDiversity | AvoidBlock(1-Block%)
    All normalized to [0,1] range for radar display.
    """
    data = {}
    raw = {}
    for algo in ALGO_ORDER:
        agg = get_agg(results, algo)
        if agg is None:
            continue
        ad = agg["action_dist_mean"]
        action_entropy = sum(
            -p/100 * math.log2(p/100 + 1e-9) for p in ad
        ) / math.log2(4)    # normalized Shannon entropy [0,1]

        raw[algo] = {
            "mean_reward":   agg["mean_reward"],
            "detection":     agg["detection_rate"] / 100,
            "precision":     1.0 - agg["fp_rate"] / 100,
            "diversity":     action_entropy,
            "avoid_block":   1.0 - ad[3] / 100,  # 1 - Block%
        }

    # Min-max normalize each axis across present algos
    if not raw:
        return {}, []
    keys = ["mean_reward", "detection", "precision", "diversity", "avoid_block"]
    for key in keys:
        vals = [raw[a][key] for a in raw]
        vmin, vmax = min(vals), max(vals)
        rng = vmax - vmin if vmax != vmin else 1.0
        for algo in raw:
            raw[algo][key + "_norm"] = (raw[algo][key] - vmin) / rng

    axis_labels = ["Mean\nReward", "Detection\nRate", "Precision\n(1-FPR)",
                   "Action\nDiversity", "Avoid\nOverblock"]

    for algo in raw:
        data[algo] = [raw[algo][k + "_norm"] for k in keys]

    return data, axis_labels

def plot_radar_chart(results):
    data, axis_labels = _radar_axis_data(results)
    if not data:
        print("[!] No data for radar chart")
        return

    N = len(axis_labels)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]  # close polygon

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw=dict(polar=True))

    for algo, values in data.items():
        vals = values + values[:1]
        ax.plot(angles, vals, linewidth=2, label=ALGO_LABELS[algo], color=COLORS[algo])
        ax.fill(angles, vals, alpha=0.08, color=COLORS[algo])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(axis_labels, size=9)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0.25", "0.5", "0.75", "1.0"], size=7)
    ax.set_title("Algorithm Comparison — Multi-Metric Radar\n"
                 "(axes min-max normalized)", pad=20)
    ax.legend(loc="lower right", bbox_to_anchor=(1.35, -0.05), framealpha=0.9)

    fig.tight_layout()
    path = os.path.join(CHARTS_DIR, "05_radar_chart.png")
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] Saved: {path}")

# ============================================================================
# MAIN
# ============================================================================

def main():
    if not os.path.exists(RESULTS_PATH):
        print(f"[ERROR] Results file not found: {RESULTS_PATH}")
        print("Run evaluate_all.py first.")
        return

    print(f"[*] Loading results from: {RESULTS_PATH}")
    results = load_results()

    print("[*] Generating charts...")
    plot_mean_reward_ci(results)
    plot_action_distribution(results)
    plot_learning_curves(results)
    plot_confusion_matrices(results)
    plot_radar_chart(results)

    print(f"\n[+] All charts saved to: {CHARTS_DIR}/")

if __name__ == "__main__":
    main()
