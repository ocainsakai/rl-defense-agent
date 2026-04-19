"""
Benchmark Results Visualization — Main + Appendix Charts

Reads results/benchmark_results.json and outputs:

  charts/main/
    01_reward_ci_by_eval_mode.png
    02_response_quality_metrics.png
    03_operational_safety_costs.png
    04_service_damage_auc.png
    05_operational_profile_radar.png
    06_per_ip_type_exact_heatmap.png
    07_closed_loop_robustness_delta.png
    08_dynamic_response_rate.png        (thesis: static vs phase-aware exact response)
    09_l7_escalation_quality.png        (thesis: redirect hold + on-time block rates)
    10_premature_vs_ontime_block.png    (thesis: escalation precision scatter)

  charts/appendix/
    appendix_action_distribution.png
    appendix_confusion_matrix_grid.png
    appendix_eval_reward_trace.png
    appendix_honeypot_overblock_tradeoff.png
    appendix_benign_safety_tradeoff.png
    appendix_seed_variability_boxplot.png
    appendix_effect_size_forest.png
    appendix_efficiency_scatter.png     (security-usability tradeoff: PPO Pareto-optimal)

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
MAIN_DIR     = os.path.join(CHARTS_DIR, "main")
APND_DIR     = os.path.join(CHARTS_DIR, "appendix")
for d in (CHARTS_DIR, MAIN_DIR, APND_DIR):
    os.makedirs(d, exist_ok=True)

DPI = 300

ALGO_ORDER  = ["ppo", "a2c", "dqn", "rule_based"]
RL_ALGOS    = ["ppo", "a2c", "dqn"]
ALGO_LABELS = {"ppo": "PPO", "a2c": "A2C", "dqn": "DQN", "rule_based": "Rule-Based"}
COLORS      = {"ppo": "#1f77b4", "a2c": "#2ca02c", "dqn": "#d62728", "rule_based": "#9467bd"}

EVAL_MODES  = ["round_robin", "round_robin_stress", "session_20", "session_20_stress"]
MODE_LABELS = {
    "round_robin":        "Round-Robin",
    "round_robin_stress": "Round-Robin Stress",
    "session_20":         "Session-20",
    "session_20_stress":  "Session-20 Stress",
}
# Stress pairs for robustness delta charts (same session, different noise level)
STRESS_PAIRS = [
    ("round_robin",  "round_robin_stress"),
    ("session_20",   "session_20_stress"),
]

ACTION_COLORS = ["#2ca02c", "#ffdd57", "#ff8c00", "#d62728"]
ACTION_NAMES  = ["Allow", "RateLimit", "Redirect", "Block"]

IP_TYPE_ORDER = ["benign", "noisy_normal", "brute_force", "brute_force_ka",
                 "sqli", "xss", "scan", "syn_flood"]
IP_TYPE_LABELS = {
    "benign": "Benign", "noisy_normal": "Noisy",
    "brute_force": "Brute Force", "brute_force_ka": "BF Keep-Alive",
    "sqli": "SQLi", "xss": "XSS",
    "scan": "Port Scan", "syn_flood": "SYN Flood",
}

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
# HELPERS
# ============================================================================

def load_results():
    with open(RESULTS_PATH) as f:
        return json.load(f)

def get_agg(results, algo, mode="round_robin"):
    return results.get(algo, {}).get(mode, {}).get("_aggregate", None)

def savefig(fig, path):
    fig.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[+] {path}")

# ============================================================================
# MAIN 01 — Mean Reward ± 95% CI grouped by eval mode
# ============================================================================

def plot_reward_ci_by_mode(results):
    # Show only the two primary (non-stress) modes to keep the chart readable.
    primary_modes = ["round_robin", "session_20"]
    algos = [a for a in ALGO_ORDER if any(get_agg(results, a, m) for m in primary_modes)]
    n_algos = len(algos)
    n_modes = len(primary_modes)
    x = np.arange(n_algos)
    bar_w = 0.35
    offsets = np.linspace(-(n_modes-1)/2, (n_modes-1)/2, n_modes) * bar_w

    fig, ax = plt.subplots(figsize=(8, 5))
    mode_hatches = ["", "//"]
    for mi, mode in enumerate(primary_modes):
        means, cis, cols = [], [], []
        for algo in algos:
            agg = get_agg(results, algo, mode)
            means.append(agg["mean_reward"] if agg else 0)
            cis.append(agg["ci95"] if agg else 0)
            cols.append(COLORS[algo])
        bars = ax.bar(x + offsets[mi], means, bar_w, color=cols, alpha=0.8,
                      edgecolor="black", linewidth=0.6, hatch=mode_hatches[mi],
                      label=MODE_LABELS[mode])
        ax.errorbar(x + offsets[mi], means, yerr=cis, fmt="none",
                    ecolor="black", elinewidth=1.2, capsize=4, capthick=1.2)
        for bar, v, ci in zip(bars, means, cis):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + ci + 0.005,
                    f"{v:.3f}", ha="center", va="bottom", fontsize=7, fontweight="bold",
                    )

    ax.set_xticks(x)
    ax.set_xticklabels([ALGO_LABELS[a] for a in algos])
    ax.set_ylabel("Mean Episode Reward")
    ax.set_title("Mean Episode Reward ± 95% CI\n(5 seeds × 30 eval episodes each, higher is better)")
    ax.axhline(0, color="gray", linewidth=0.8, linestyle="--", alpha=0.5)
    ax.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "01_reward_ci_by_eval_mode.png"))

# ============================================================================
# MAIN 02 — Response Quality Metrics (grouped bar)
# ============================================================================

def plot_response_quality(results):
    metrics = [
        ("exact_response_rate", "Exact Response %", "↑"),
        ("mitigation_rate",     "Mitigation %",     "↑"),
        ("macro_f1",            "Macro F1 × 100",   "↑"),
    ]
    algos = [a for a in ALGO_ORDER if get_agg(results, a)]
    mode = "round_robin"

    fig, axes = plt.subplots(1, 3, figsize=(12, 4.5), sharey=False)
    for ax, (mkey, mlabel, direction) in zip(axes, metrics):
        vals, cis, cols = [], [], []
        for algo in algos:
            agg = get_agg(results, algo, mode)
            v = agg.get(mkey, 0) if agg else 0
            if mkey == "macro_f1":
                v = v * 100
            ci_key = mkey + "_ci95"
            ci = agg.get(ci_key, 0) if agg else 0
            if mkey == "macro_f1":
                ci = ci * 100
            vals.append(v); cis.append(ci); cols.append(COLORS[algo])

        x = np.arange(len(algos))
        bars = ax.bar(x, vals, color=cols, alpha=0.85, edgecolor="black", linewidth=0.6)
        ax.errorbar(x, vals, yerr=cis, fmt="none", ecolor="black",
                    elinewidth=1.2, capsize=4, capthick=1.2)
        ax.set_xticks(x)
        ax.set_xticklabels([ALGO_LABELS[a] for a in algos])
        ax.set_title(f"{mlabel}\n({direction} better)")
        ax.grid(axis="y", alpha=0.3)
        sns.despine(ax=ax)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                    f"{v:.1f}", ha="center", va="bottom", fontsize=8, fontweight="bold",
                    )

    fig.suptitle("Response Quality Metrics — Round-Robin Eval", fontsize=13, y=1.02)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "02_response_quality_metrics.png"))

# ============================================================================
# MAIN 03 — Operational Safety Costs (lower is better)
# ============================================================================

def plot_operational_safety(results):
    metrics = [
        ("benign_intervention_rate", "Benign Intervention %"),
        ("benign_block_rate",        "Benign Block %"),
        ("over_mitigation_rate",     "Over-Mitigation %"),
        ("action_oscillation_rate",  "Action Oscillation %"),
    ]
    algos = [a for a in ALGO_ORDER if get_agg(results, a)]
    mode = "round_robin"
    n_metrics = len(metrics)
    n_algos = len(algos)
    bar_w = 0.18
    x = np.arange(n_metrics)
    offsets = np.linspace(-(n_algos-1)/2, (n_algos-1)/2, n_algos) * bar_w

    fig, ax = plt.subplots(figsize=(10, 5))
    for ai, algo in enumerate(algos):
        agg = get_agg(results, algo, mode)
        vals = [agg.get(mkey, 0) if agg else 0 for mkey, _ in metrics]
        bars = ax.bar(x + offsets[ai], vals, bar_w,
                      color=COLORS[algo], alpha=0.85, edgecolor="black",
                      linewidth=0.5, label=ALGO_LABELS[algo])
        for bar, v in zip(bars, vals):
            if v > 0.5:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                        f"{v:.1f}", ha="center", va="bottom", fontsize=7, fontweight="bold",
                        )

    ax.set_xticks(x)
    ax.set_xticklabels([ml for _, ml in metrics], rotation=12, ha="right")
    ax.set_ylabel("Rate (%)")
    ax.set_title("Operational Safety Costs — Round-Robin Eval\n(↓ lower is better)")
    ax.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "03_operational_safety_costs.png"))

# ============================================================================
# MAIN 04 — Service Damage AUC (lower is better)
# ============================================================================

def plot_service_damage(results):
    primary_modes = ["round_robin", "session_20"]
    algos = [a for a in ALGO_ORDER if any(get_agg(results, a, m) for m in primary_modes)]
    n_modes = len(primary_modes)
    x = np.arange(len(algos))
    bar_w = 0.35
    offsets = np.linspace(-(n_modes-1)/2, (n_modes-1)/2, n_modes) * bar_w

    fig, ax = plt.subplots(figsize=(8, 4.5))
    mode_hatches = ["", "//"]
    for mi, mode in enumerate(primary_modes):
        vals, cis, cols = [], [], []
        for algo in algos:
            agg = get_agg(results, algo, mode)
            vals.append(agg.get("service_damage_auc", 0) if agg else 0)
            cis.append(agg.get("service_damage_auc_ci95", 0) if agg else 0)
            cols.append(COLORS[algo])
        bars = ax.bar(x + offsets[mi], vals, bar_w, color=cols, alpha=0.8,
                      edgecolor="black", linewidth=0.6, hatch=mode_hatches[mi],
                      label=MODE_LABELS[mode])
        ax.errorbar(x + offsets[mi], vals, yerr=cis, fmt="none",
                    ecolor="black", elinewidth=1.2, capsize=4, capthick=1.2)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
                    f"{v:.4f}", ha="center", va="bottom", fontsize=8, fontweight="bold",
                    )

    ax.set_xticks(x)
    ax.set_xticklabels([ALGO_LABELS[a] for a in algos])
    ax.set_ylabel("Mean Step Damage (normalized)")
    ax.set_title("Service Damage AUC by Eval Mode\n(↓ lower is better)")
    ax.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "04_service_damage_auc.png"))

# ============================================================================
# MAIN 05 — Operational Profile Radar
# ============================================================================

def plot_radar(results):
    mode = "round_robin"
    axes_def = [
        ("mean_reward",            "Reward",       True,  None,  None),
        ("exact_response_rate",    "Exact\nResp.", True,  0.0,   100.0),
        ("honeypot_capture_rate",  "Honeypot\nCapture", True, 0.0, 100.0),
        ("benign_intervention_rate","Benign\nSafety", False, 0.0, 100.0),
        ("service_damage_auc",     "Svc\nDamage",  False, None,  None),
        ("action_oscillation_rate","Stability",    False, 0.0,   100.0),
    ]

    # Collect raw values
    raw = {}
    for algo in ALGO_ORDER:
        agg = get_agg(results, algo, mode)
        if agg is None:
            continue
        raw[algo] = {k: agg.get(k, 0) for k, *_ in axes_def}

    if not raw:
        print("[!] No data for radar chart")
        return

    # Normalize each axis to [0,1] where 1=best
    norm = {algo: [] for algo in raw}
    axis_labels = []
    for key, label, higher_better, lo, hi in axes_def:
        vals = {a: raw[a][key] for a in raw}
        v_min = lo if lo is not None else min(vals.values())
        v_max = hi if hi is not None else max(vals.values())
        rng = v_max - v_min if v_max != v_min else 1.0
        for algo in raw:
            n = (vals[algo] - v_min) / rng
            norm[algo].append(n if higher_better else 1.0 - n)
        axis_labels.append(label)

    N = len(axis_labels)
    angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(6.5, 6.5), subplot_kw=dict(polar=True))
    for algo, vals in norm.items():
        v = vals + vals[:1]
        ax.plot(angles, v, linewidth=2, label=ALGO_LABELS[algo], color=COLORS[algo])
        ax.fill(angles, v, alpha=0.07, color=COLORS[algo])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(axis_labels, size=9)
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], size=7)
    ax.set_title("Operational Profile Radar\n"
                 "(normalized; all axes: outer edge = best performance)", pad=20)
    ax.legend(loc="lower right", bbox_to_anchor=(1.35, -0.05), framealpha=0.9)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "05_operational_profile_radar.png"))

# ============================================================================
# MAIN 06 — Per-IP-Type Exact Response Heatmap
# ============================================================================

def plot_ip_type_heatmap(results):
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    ipt_present = []
    for ipt in IP_TYPE_ORDER:
        for algo in algos:
            agg = get_agg(results, algo, mode)
            if agg and ipt in agg.get("per_ip_type_exact_rate_mean", {}):
                ipt_present.append(ipt)
                break

    matrix = np.full((len(ipt_present), len(algos)), np.nan)
    for j, algo in enumerate(algos):
        agg = get_agg(results, algo, mode)
        if agg is None:
            continue
        ipt_rates = agg.get("per_ip_type_exact_rate_mean", {})
        for i, ipt in enumerate(ipt_present):
            if ipt in ipt_rates:
                matrix[i, j] = ipt_rates[ipt]

    fig, ax = plt.subplots(figsize=(7, 5))
    mask = np.isnan(matrix)
    im = ax.imshow(np.where(mask, 0, matrix), cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
    plt.colorbar(im, ax=ax, label="Exact Response Rate (%)")

    for i in range(len(ipt_present)):
        for j in range(len(algos)):
            if not mask[i, j]:
                ax.text(j, i, f"{matrix[i,j]:.0f}",
                        ha="center", va="center", fontsize=9,
                        color="black" if 20 < matrix[i,j] < 80 else "white")

    ax.set_xticks(range(len(algos)))
    ax.set_xticklabels([ALGO_LABELS[a] for a in algos])
    ax.set_yticks(range(len(ipt_present)))
    ax.set_yticklabels([IP_TYPE_LABELS.get(t, t) for t in ipt_present])
    ax.set_title("Per-IP-Type Exact Response Rate (%)\n"
                 "(Round-Robin eval, mean across 5 seeds; green=100%, red=0%)")
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "06_per_ip_type_exact_heatmap.png"))

# ============================================================================
# MAIN 07 — Closed-Loop Robustness Delta (session_20 − round_robin)
# ============================================================================

def _delta_panel(ax, results, base_mode, stress_mode, mkey, mlabel, higher_delta_better):
    algos = [a for a in ALGO_ORDER if
             get_agg(results, a, base_mode) and get_agg(results, a, stress_mode)]
    deltas = []
    for a in algos:
        base = (get_agg(results, a, base_mode) or {}).get(mkey, 0)
        stress = (get_agg(results, a, stress_mode) or {}).get(mkey, 0)
        deltas.append(stress - base)
    bar_colors = []
    for d in deltas:
        if higher_delta_better:
            bar_colors.append("#2ca02c" if d >= 0 else "#d62728")
        else:
            bar_colors.append("#2ca02c" if d <= 0 else "#d62728")
    x = np.arange(len(algos))
    bars = ax.bar(x, deltas, color=bar_colors, alpha=0.85, edgecolor="black", linewidth=0.6)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels([ALGO_LABELS[a] for a in algos], rotation=10)
    good = "↑" if higher_delta_better else "↓"
    ax.set_title(f"{mlabel}\n(green={good} better under stress)")
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)
    for bar, v in zip(bars, deltas):
        if v >= 0:
            ypos = v + abs(v)*0.05 + 0.001
            va = "bottom"
        else:
            ypos = v - abs(v)*0.05 - 0.001
            va = "top"
        ax.text(bar.get_x() + bar.get_width()/2, ypos,
                f"{v:+.3f}", ha="center", va=va, fontsize=7.5, fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.7))


def plot_robustness_delta(results):
    """
    Two rows of delta charts: noise-stress impact on key metrics.
    Row 0: round_robin_stress − round_robin
    Row 1: session_20_stress  − session_20
    Only compares same-session pairs to isolate noise/drift effect.
    """
    metrics = [
        ("mean_reward",            "Reward Δ",              True),
        ("exact_response_rate",    "Exact Response Δ (%)",  True),
        ("mitigation_efficiency",  "Mitig Efficiency Δ",    True),
        ("benign_intervention_rate","Benign Interv. Δ (%)", False),
    ]
    pairs = [
        ("round_robin",  "round_robin_stress",  "RR: stress − normal"),
        ("session_20",   "session_20_stress",   "S20: stress − normal"),
    ]

    fig, axes = plt.subplots(len(pairs), len(metrics),
                             figsize=(14, 7), sharey=False)
    for ri, (base, stress, row_title) in enumerate(pairs):
        for ci, (mkey, mlabel, hib) in enumerate(metrics):
            _delta_panel(axes[ri, ci], results, base, stress, mkey, mlabel, hib)
        axes[ri, 0].set_ylabel(row_title, fontsize=9)

    fig.suptitle("Noise/Drift Stress Impact (stress − normal, same session type)\n"
                 "Green = change is favourable; red = change is unfavourable",
                 fontsize=11)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "07_closed_loop_robustness_delta.png"))

# ============================================================================
# APPENDIX — Action Distribution (stacked bar)
# ============================================================================

def plot_action_distribution(results):
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    labels = [ALGO_LABELS[a] for a in algos]
    dists  = np.array([get_agg(results, a, mode)["action_dist_mean"] for a in algos])

    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = np.arange(len(labels))
    bottoms = np.zeros(len(labels))
    patches = []
    for i, (aname, acolor) in enumerate(zip(ACTION_NAMES, ACTION_COLORS)):
        ax.bar(x, dists[:, i], 0.55, bottom=bottoms,
               color=acolor, label=aname, edgecolor="white", linewidth=0.5)
        bottoms += dists[:, i]
        patches.append(mpatches.Patch(color=acolor, label=aname))
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("Action Proportion (%)"); ax.set_ylim(0, 100)
    ax.set_title("Action Distribution by Algorithm (Round-Robin)")
    ax.legend(handles=patches, loc="upper right", ncol=2)
    ax.grid(axis="y", alpha=0.3); sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_action_distribution.png"))

# ============================================================================
# APPENDIX — Confusion Matrix Grid (2×2)
# ============================================================================

def plot_confusion_matrix_grid(results):
    mode = "round_robin"
    ACTION_TICK = ["Allow", "RL", "Redir", "Block"]
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    n = len(algos)
    ncols = 2; nrows = math.ceil(n / ncols)

    fig, axes = plt.subplots(nrows, ncols, figsize=(ncols*4.5, nrows*4))
    axes_flat = axes.flatten() if n > 1 else [axes]
    for ax, algo in zip(axes_flat, algos):
        agg = get_agg(results, algo, mode)
        cm = np.array(agg["confusion_matrix_mean"])
        row_sums = cm.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        cm_norm = cm / row_sums * 100
        sns.heatmap(cm_norm, annot=True, fmt=".1f", cmap="Blues",
                    xticklabels=ACTION_TICK, yticklabels=ACTION_TICK,
                    ax=ax, linewidths=0.5, cbar_kws={"label": "Row %"},
                    vmin=0, vmax=100)
        ax.set_xlabel("Predicted Action")
        ax.set_ylabel("Optimal Action")
        ax.set_title(f"{ALGO_LABELS[algo]}")

    for ax in axes_flat[n:]:
        ax.set_visible(False)
    fig.suptitle("Confusion Matrix — Row-Normalized % (avg 5 seeds, Round-Robin)", y=1.02)
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_confusion_matrix_grid.png"))

# ============================================================================
# APPENDIX — Eval Reward Trace (post-training episodes)
# ============================================================================

def plot_eval_reward_trace(results):
    mode = "round_robin"
    fig, ax = plt.subplots(figsize=(9, 5))
    for algo in ALGO_ORDER:
        if algo == "rule_based":
            continue
        mode_data = results.get(algo, {}).get(mode, {})
        seed_rewards = [mode_data[str(s)]["episode_rewards"]
                        for s in [42, 123, 456, 789, 1337]
                        if str(s) in mode_data]
        if not seed_rewards:
            continue
        max_len = max(len(r) for r in seed_rewards)
        padded  = np.array([r + [r[-1]]*(max_len - len(r)) for r in seed_rewards])
        mean = padded.mean(axis=0); std = padded.std(axis=0)
        x = np.arange(1, max_len+1)
        ax.plot(x, mean, label=ALGO_LABELS[algo], color=COLORS[algo], linewidth=1.8)
        ax.fill_between(x, mean-std, mean+std, color=COLORS[algo], alpha=0.15)

    rb_agg = get_agg(results, "rule_based", mode)
    if rb_agg:
        rb_val = rb_agg["mean_reward"]
        ax.axhline(rb_val, color=COLORS["rule_based"], linewidth=1.5,
                   linestyle="--", label=f"Rule-Based ({rb_val:.3f})")

    ax.set_xlabel("Evaluation Episode Index")
    ax.set_ylabel("Episode Reward")
    ax.set_title("Post-Training Evaluation Reward Trace\n"
                 "(mean ± std across 5 seeds, 30 episodes each — NOT training curve)")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3); sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_eval_reward_trace.png"))

# ============================================================================
# APPENDIX — Honeypot vs L7 Over-Block Tradeoff (scatter)
# ============================================================================

def plot_honeypot_overblock_tradeoff(results):
    mode = "round_robin"
    fig, ax = plt.subplots(figsize=(6, 5))
    for algo in ALGO_ORDER:
        agg = get_agg(results, algo, mode)
        if agg is None:
            continue
        x_val = agg.get("l7_over_block_rate", 0)
        y_val = agg.get("honeypot_capture_rate", 0)
        ax.scatter(x_val, y_val, s=120, color=COLORS[algo],
                   label=ALGO_LABELS[algo], zorder=3)
        ax.annotate(ALGO_LABELS[algo], (x_val, y_val),
                    textcoords="offset points", xytext=(6, 4), fontsize=9)

    ax.set_xlabel("L7 Over-Block Rate (%) ← lower is better")
    ax.set_ylabel("Honeypot Capture Rate (%) ↑ higher is better")
    ax.set_title("Honeypot Capture vs L7 Over-Block Tradeoff\n"
                 "(ideal = top-left corner)")
    ax.grid(alpha=0.3); sns.despine(ax=ax)
    # Draw ideal corner marker
    ax.axvline(0, color="green", linewidth=0.7, linestyle=":", alpha=0.5)
    ax.axhline(100, color="green", linewidth=0.7, linestyle=":", alpha=0.5)
    ax.legend(loc="upper right")
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_honeypot_overblock_tradeoff.png"))

# ============================================================================
# APPENDIX — Benign Safety Tradeoff (scatter)
# ============================================================================

def plot_benign_safety_tradeoff(results):
    mode = "round_robin"
    fig, ax = plt.subplots(figsize=(6, 5))
    for algo in ALGO_ORDER:
        agg = get_agg(results, algo, mode)
        if agg is None:
            continue
        x_val = agg.get("benign_intervention_rate", 0)
        y_val = agg.get("mean_reward", 0)
        ax.scatter(x_val, y_val, s=120, color=COLORS[algo],
                   label=ALGO_LABELS[algo], zorder=3)
        ax.annotate(ALGO_LABELS[algo], (x_val, y_val),
                    textcoords="offset points", xytext=(6, 4), fontsize=9)

    ax.set_xlabel("Benign Intervention Rate (%) ← lower is better")
    ax.set_ylabel("Mean Reward ↑ higher is better")
    ax.set_title("Benign Safety vs Reward Tradeoff\n"
                 "(ideal = top-left: low intervention + high reward)")
    ax.legend(loc="upper right")
    ax.grid(alpha=0.3); sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_benign_safety_tradeoff.png"))

# ============================================================================
# APPENDIX — Seed Variability Boxplot
# ============================================================================

def plot_seed_variability(results):
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if results.get(a, {}).get(mode)]
    data_per_algo = []
    labels = []
    for algo in algos:
        mode_data = results[algo][mode]
        vals = [mode_data[k]["mean_reward"] for k in mode_data
                if not k.startswith("_") and "mean_reward" in mode_data[k]]
        if vals:
            data_per_algo.append(vals)
            labels.append(ALGO_LABELS[algo])

    fig, ax = plt.subplots(figsize=(7, 5))
    bp = ax.boxplot(data_per_algo, labels=labels, patch_artist=True,
                    medianprops=dict(color="black", linewidth=2))
    for patch, algo in zip(bp["boxes"], algos):
        patch.set_facecolor(COLORS[algo])
        patch.set_alpha(0.5)

    rng = np.random.default_rng(0)
    for i, (vals, algo) in enumerate(zip(data_per_algo, algos), start=1):
        jitter = rng.normal(0, 0.035, size=len(vals))
        ax.scatter(np.full(len(vals), i) + jitter, vals,
                   color=COLORS[algo], s=60, zorder=3,
                   edgecolors="black", linewidths=0.6, alpha=0.9)

    ax.set_ylabel("Mean Episode Reward")
    ax.set_title("Seed Variability — Mean Reward Distribution\n"
                 "(points = individual train seeds, box = seed distribution)")
    ax.grid(axis="y", alpha=0.3); sns.despine(ax=ax)
    legend_patches = [mpatches.Patch(color=COLORS[a], alpha=0.7, label=ALGO_LABELS[a])
                      for a in algos]
    ax.legend(handles=legend_patches, loc="upper right")
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_seed_variability_boxplot.png"))

# ============================================================================
# APPENDIX — Statistical Effect Size Forest Plot
# ============================================================================

def plot_effect_size_forest(results):
    stats = results.get("_statistics", {})
    mode = "round_robin"
    mode_stats = stats.get(mode, {})
    if not mode_stats:
        print("[!] No statistics data for effect size plot")
        return

    metrics_to_plot = [
        ("mean_reward",              "Mean Reward",         True),
        ("exact_response_rate",      "Exact Response Rate", True),
        ("honeypot_capture_rate",    "Honeypot Capture",    True),
        ("benign_intervention_rate", "Benign Safety",       False),
        ("service_damage_auc",       "Low Service Damage",  False),
    ]

    pairs = list(mode_stats.keys())
    n_pairs = len(pairs)
    n_metrics = len(metrics_to_plot)

    fig, axes = plt.subplots(1, n_pairs, figsize=(5*n_pairs, 5), sharey=True)
    if n_pairs == 1:
        axes = [axes]

    for ax, pair in zip(axes, pairs):
        pair_stats = mode_stats[pair]
        a1, a2 = pair.split("_vs_")
        ys, ds, colors_dot, labels_m = [], [], [], []
        for i, (mkey, mlabel, higher_is_better) in enumerate(metrics_to_plot):
            ms = pair_stats.get(mkey)
            if ms is None:
                continue
            d = ms["cohen_d"]
            p = ms["p_value"]
            # Flip sign for lower-is-better metrics so positive always means first algo better
            d_plot = d if higher_is_better else -d
            ys.append(i)
            ds.append(d_plot)
            color = "#2ca02c" if p < 0.05 else "#aaaaaa"
            colors_dot.append(color)
            labels_m.append(mlabel)

        ax.barh(ys, ds, color=colors_dot, alpha=0.75, edgecolor="black", linewidth=0.5)
        # Auto-expand xlim to fit all bars
        max_pos = max((d for d in ds if d >= 0), default=0)
        max_neg = min((d for d in ds if d < 0), default=0)
        cur_l, cur_r = ax.get_xlim()
        ax.set_xlim(min(cur_l, max_neg * 1.2 if max_neg < 0 else cur_l),
                    max(cur_r, max_pos * 1.2 if max_pos > 0 else cur_r))
        for y, d_val in zip(ys, ds):
            xlim = ax.get_xlim()
            pad = 0.05
            if d_val >= 0:
                x_pos, ha = d_val + pad, "left"
                if x_pos > xlim[1] - pad:   # tràn phải → lật vào trong
                    x_pos, ha = d_val - pad, "right"
            else:
                x_pos, ha = d_val - pad, "right"
                if x_pos < xlim[0] + pad:   # tràn trái → lật vào phải
                    x_pos, ha = d_val + pad, "left"
            ax.text(x_pos, y, f"{d_val:+.2f}", va="center", ha=ha,
                    fontsize=7.5, clip_on=False)
        ax.axvline(0, color="black", linewidth=0.8)
        ax.axvline( 0.8, color="gray", linewidth=0.6, linestyle="--", alpha=0.5)
        ax.axvline(-0.8, color="gray", linewidth=0.6, linestyle="--", alpha=0.5)
        ax.set_yticks(ys)
        ax.set_yticklabels(labels_m)
        ax.set_xlabel("Cohen's d")
        ax.set_title(f"{ALGO_LABELS.get(a1, a1)} vs {ALGO_LABELS.get(a2, a2)}\n"
                     f"(green p<0.05, dashed=|d|=0.8 large)")
        ax.grid(axis="x", alpha=0.3); sns.despine(ax=ax)

    fig.suptitle("Statistical Effect Size (Cohen's d) — Round-Robin Eval\n"
                 "Positive = first algo better; |d|≥0.8 = large effect", y=1.02)
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_effect_size_forest.png"))

# ============================================================================
# THESIS 01 — Dynamic / Phase-Aware Response Rate
# ============================================================================

def plot_dynamic_response(results):
    """
    Grouped bar: dynamic_exact_response_rate vs exact_response_rate per algo.
    Shows how much the phase-aware metric differs from static exact response.
    """
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    if not algos:
        return

    has_dynamic = any(
        get_agg(results, a, mode) and
        get_agg(results, a, mode).get("dynamic_exact_response_rate") is not None
        for a in algos
    )
    if not has_dynamic:
        print("  [SKIP] dynamic metrics not found in results — run evaluate_all.py first")
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(algos))
    bw = 0.35

    metrics = [
        ("exact_response_rate",        "Static Exact Response %", ""),
        ("dynamic_exact_response_rate", "Dynamic Exact Response %", "//"),
    ]
    colors_pair = ["#4c78a8", "#f28e2b"]

    for i, (mkey, label, hatch) in enumerate(metrics):
        vals, cis = [], []
        for a in algos:
            agg = get_agg(results, a, mode)
            v = agg.get(mkey) if agg else None
            ci_v = agg.get(mkey + "_ci95") if agg else 0
            vals.append(v if v is not None else 0)
            cis.append(ci_v if ci_v is not None else 0)
        offs = x + (i - 0.5) * bw
        bars = ax.bar(offs, vals, bw, color=colors_pair[i], alpha=0.85,
                      edgecolor="black", linewidth=0.5, hatch=hatch, label=label)
        ax.errorbar(offs, vals, yerr=cis, fmt="none", ecolor="black",
                    elinewidth=1.2, capsize=3)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f"{v:.1f}", ha="center", va="bottom", fontsize=7.5, fontweight="bold",
                    )

    ax.set_xticks(x)
    ax.set_xticklabels([ALGO_LABELS[a] for a in algos])
    ax.set_ylabel("% of Active Steps")
    ax.set_ylim(0, 105)
    ax.set_title("Static vs Phase-Aware (Dynamic) Exact Response Rate\n"
                 "Dynamic: Redirect=optimal when not block_ready, Block=optimal when block_ready")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "08_dynamic_response_rate.png"))


# ============================================================================
# THESIS 02 — L7 Escalation Quality Breakdown
# ============================================================================

def plot_l7_escalation_quality(results):
    """
    Stacked bar showing L7 phase breakdown:
      Redirect hold (correct) / On-time Block (correct) /
      Premature Block (error) / Late Redirect (error)
    """
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    if not algos:
        return

    metrics_info = [
        ("l7_redirect_hold_rate",         "Redirect (Hold Phase)",   "#2ca02c"),
        ("l7_ontime_block_rate",           "Block (On-Time)",         "#1f77b4"),
        ("l7_premature_block_rate",        "Block (Premature)",       "#d62728"),
        ("l7_late_under_escalation_rate",  "Redirect (Late/Under)",   "#ff7f0e"),
    ]

    has_any = any(
        get_agg(results, a, mode) and
        get_agg(results, a, mode).get("l7_redirect_hold_rate") is not None
        for a in algos
    )
    if not has_any:
        print("  [SKIP] l7_redirect_hold_rate not found — run evaluate_all.py first")
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    for ax_i, (ax, (mkey, mlabel, col)) in enumerate(
            zip(axes, metrics_info[:2])):
        vals, cis = [], []
        for a in algos:
            agg = get_agg(results, a, mode)
            v = agg.get(mkey) if agg else None
            ci_v = agg.get(mkey + "_ci95") if agg else 0
            vals.append(v if v is not None else 0)
            cis.append(ci_v if ci_v is not None else 0)
        x = np.arange(len(algos))
        bars = ax.bar(x, vals, color=[COLORS[a] for a in algos], alpha=0.85,
                      edgecolor="black", linewidth=0.5)
        ax.errorbar(x, vals, yerr=cis, fmt="none", ecolor="black",
                    elinewidth=1.2, capsize=3)
        ax.set_xticks(x)
        ax.set_xticklabels([ALGO_LABELS[a] for a in algos])
        ax.set_ylabel("% of L7 Steps")
        ax.set_ylim(0, 105)
        ax.set_title(f"{mlabel}\n(↑ better)")
        ax.grid(axis="y", alpha=0.3)
        sns.despine(ax=ax)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f"{v:.1f}", ha="center", va="bottom", fontsize=8, fontweight="bold",
                    )

    fig.suptitle("L7 Escalation Quality — Phase-Aware Metrics\n"
                 "Round-Robin Eval (5 seeds × 30 episodes)", y=1.02)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "09_l7_escalation_quality.png"))


# ============================================================================
# THESIS 03 — Premature vs On-Time Block Rate
# ============================================================================

def plot_premature_vs_ontime_block(results):
    """Scatter: x=premature_block_rate, y=ontime_block_rate, one point per algo."""
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    if not algos:
        return

    has_any = any(
        get_agg(results, a, mode) and
        get_agg(results, a, mode).get("l7_premature_block_rate") is not None
        for a in algos
    )
    if not has_any:
        print("  [SKIP] premature block rate not found — run evaluate_all.py first")
        return

    fig, ax = plt.subplots(figsize=(6, 5))
    for a in algos:
        agg = get_agg(results, a, mode)
        if not agg:
            continue
        x_val = agg.get("l7_premature_block_rate") or 0
        y_val = agg.get("l7_ontime_block_rate") or 0
        ci_x  = agg.get("l7_premature_block_rate_ci95") or 0
        ci_y  = agg.get("l7_ontime_block_rate_ci95") or 0
        ax.errorbar(x_val, y_val, xerr=ci_x, yerr=ci_y,
                    fmt="o", color=COLORS[a], markersize=9,
                    label=ALGO_LABELS[a], linewidth=1.5)
        ax.annotate(ALGO_LABELS[a], (x_val, y_val),
                    textcoords="offset points", xytext=(6, 4), fontsize=9)

    ax.set_xlabel("Premature Block Rate % (↓ better)")
    ax.set_ylabel("On-Time Block Rate % (↑ better)")
    ax.set_title("L7 Escalation Precision\nPremature vs On-Time Block\n"
                 "(ideal: bottom-right → high on-time, low premature)")
    ax.grid(alpha=0.3)
    ax.legend()
    sns.despine(ax=ax)
    fig.tight_layout()
    savefig(fig, os.path.join(MAIN_DIR, "10_premature_vs_ontime_block.png"))


# ============================================================================
# APPENDIX — Security-Usability Tradeoff Scatter
# ============================================================================

def _efficiency_scatter_ax(ax, results, mode, x_key, y_key, size_key, x_label, size_label):
    """Shared helper for security-usability tradeoff scatter plots."""
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    if not algos:
        return

    finite_effs = [
        (get_agg(results, a, mode) or {}).get(size_key, 0)
        for a in algos
        if (get_agg(results, a, mode) or {}).get(size_key) not in (None, float("inf"))
    ]
    max_eff = max(finite_effs) if finite_effs else 1

    for a in algos:
        agg = get_agg(results, a, mode)
        if not agg:
            continue
        x_val = agg.get(x_key) or 0
        y_val = agg.get(y_key) or 0
        ci_x  = agg.get(x_key + "_ci95") or 0
        ci_y  = agg.get(y_key + "_ci95") or 0
        eff   = agg.get(size_key)
        eff   = eff if (eff and eff != float("inf")) else max_eff
        size  = max(80, min(1200, (eff / max(max_eff, 1)) * 1000))

        ax.errorbar(x_val, y_val, xerr=ci_x, yerr=ci_y,
                    fmt="o", color=COLORS[a], markersize=0,
                    linewidth=1.5, capsize=3, alpha=0.6)
        ax.scatter(x_val, y_val, s=size, color=COLORS[a], alpha=0.85,
                   edgecolors="black", linewidths=0.8,
                   label=f"{ALGO_LABELS[a]} ({size_label}={eff:.0f})", zorder=5)
        ax.annotate(ALGO_LABELS[a], (x_val, y_val),
                    textcoords="offset points", xytext=(8, 4), fontsize=9,
                    color=COLORS[a], fontweight="bold")

    ax.annotate("← Ideal region\n(high mitigation, low benign disruption)",
                xy=(0, ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 100),
                xytext=(0.05, 99.2), fontsize=7.5, color="gray", style="italic")
    ax.set_xlabel(x_label)
    ax.set_ylabel("Mitigation Rate % (↑ better)")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(alpha=0.25)
    sns.despine(ax=ax)


def plot_efficiency_scatter(results):
    """
    Two-panel scatter: x=benign_intervention_rate and x=benign_harm_score vs mitigation_rate.
    Bubble size = respective efficiency ratio.
    Neutral framing: shows security-usability tradeoff, not "PPO wins overall".
    """
    mode = "round_robin"
    algos = [a for a in ALGO_ORDER if get_agg(results, a, mode)]
    if not algos:
        return

    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))

    _efficiency_scatter_ax(
        axes[0], results, mode,
        x_key="benign_intervention_rate",
        y_key="mitigation_rate",
        size_key="mitigation_efficiency",
        x_label="Benign Intervention Rate % (↓ better)\n"
                 "[any non-Allow action on benign traffic]",
        size_label="eff",
    )
    axes[0].set_title("Mitigation per Benign Intervention\n"
                      "Bubble ∝ mitigation_rate / benign_intervention_rate")

    _efficiency_scatter_ax(
        axes[1], results, mode,
        x_key="benign_harm_score",
        y_key="mitigation_rate",
        size_key="weighted_mitigation_efficiency",
        x_label="Benign Harm Score (↓ better)\n"
                 "[1×RateLimit + 2×Redirect + 3×Block on benign steps]",
        size_label="w-eff",
    )
    axes[1].set_title("Mitigation per Weighted Benign Harm\n"
                      "Bubble ∝ mitigation_rate / benign_harm_score")

    fig.suptitle("Security-Usability Tradeoff — Round-Robin Eval (5 seeds × 30 ep)\n"
                 "DQN leads on raw mitigation; PPO achieves higher efficiency ratios.",
                 y=1.02)
    fig.tight_layout()
    savefig(fig, os.path.join(APND_DIR, "appendix_efficiency_scatter.png"))


# ============================================================================
# MAIN
# ============================================================================

def main():
    if not os.path.exists(RESULTS_PATH):
        print(f"[ERROR] Results file not found: {RESULTS_PATH}")
        print("Run evaluate_all.py first.")
        return

    print(f"[*] Loading: {RESULTS_PATH}")
    results = load_results()

    print("\n[*] Main charts →", MAIN_DIR)
    plot_reward_ci_by_mode(results)
    plot_response_quality(results)
    plot_operational_safety(results)
    plot_service_damage(results)
    plot_radar(results)
    plot_ip_type_heatmap(results)
    plot_robustness_delta(results)

    print("\n[*] Thesis-control charts →", MAIN_DIR)
    plot_dynamic_response(results)
    plot_l7_escalation_quality(results)
    plot_premature_vs_ontime_block(results)

    print("\n[*] Appendix charts →", APND_DIR)
    plot_action_distribution(results)
    plot_confusion_matrix_grid(results)
    plot_eval_reward_trace(results)
    plot_honeypot_overblock_tradeoff(results)
    plot_benign_safety_tradeoff(results)
    plot_seed_variability(results)
    plot_effect_size_forest(results)
    plot_efficiency_scatter(results)

    print(f"\n[+] Done. charts/main/ ({10} files) + charts/appendix/ ({8} files)")


if __name__ == "__main__":
    main()
