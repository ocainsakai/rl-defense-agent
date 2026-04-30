"""
plot_validation.py — Generate 8 academic-grade plots from validation results.

Plots:
  00_summary_table.png        Bảng metrics 4 protocols × 2 datasets × 2 classifiers
  01_protocol_comparison.png  F1 macro across A_native / B_matched / C_group
  02_per_class_f1_matched.png Per-class F1 trong Protocol B (apples-to-apples)
  03_feature_importance.png   20D feature importance ranking (top all 20)
  04_label_leak_check.png     SHUFFLE F1 vs real F1 (sanity check)
  05_bootstrap_ci.png         Forest plot với bootstrap 95% CI
  06_ablation.png             Per-class F1 drop khi remove từng feature group
  07_confusion_matrix.png     Side-by-side 20D RF vs 80D RF (Protocol B)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

RESULTS_DIR = Path(__file__).parent / "results"
VAL_FILE = RESULTS_DIR / "validation_results.json"
ABL_FILE = RESULTS_DIR / "ablation_results.json"
PLOTS_DIR = RESULTS_DIR / "plots"

CLASS_ORDER = ["benign", "brute_force", "sqli", "xss"]
COLOR_20D = "#2E86AB"        # Blue (project)
COLOR_80D = "#A23B72"        # Magenta (reference)
COLOR_SHUFFLE = "#888888"    # Gray (sanity baseline)
COLOR_BASELINE = "#7CB342"   # Green (ablation baseline)
COLOR_ABLATED = "#F57C00"    # Orange (ablation diff)


def plot_summary_table(metadata: dict, summary: dict, out_path: Path) -> None:
    """Bảng metrics 14 cells (3 protocols × varied count)."""
    rows = []
    for key in sorted(summary.keys()):
        s = summary[key]
        if s["protocol"] == "SHUFFLE":
            continue  # skip shuffle in main table
        rows.append([
            s["protocol"],
            s["dataset"],
            s["classifier"].upper(),
            f"{s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f}",
            f"[{s['f1_macro_ci95_bootstrap_lo']:.3f}, {s['f1_macro_ci95_bootstrap_hi']:.3f}]",
            f"{s['precision_macro_mean']:.4f}",
            f"{s['recall_macro_mean']:.4f}",
            f"{s['accuracy_mean']:.4f}",
            f"{s['train_time_mean_sec']:.2f}s",
        ])

    columns = ["Protocol", "Dataset", "Clf", "F1 macro (mean ± std)",
               "Bootstrap CI95", "Precision", "Recall", "Accuracy", "Train"]

    fig, ax = plt.subplots(figsize=(15, 1 + 0.45 * len(rows)))
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=columns,
                      loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.8)

    for i, row in enumerate(rows, start=1):
        if "20D" in row[1]:
            color = "#E8F1FA"
        else:
            color = "#F8E6EE"
        for j in range(len(columns)):
            table[(i, j)].set_facecolor(color)

    for j in range(len(columns)):
        table[(0, j)].set_facecolor("#2E2E2E")
        table[(0, j)].set_text_props(color="white", weight="bold")

    plt.title(
        f"Validation Summary — CSE-CIC-IDS2018 Thursday-22-02-2018\n"
        f"3 Protocols × 5-fold × 5 seeds = 25 runs/cell  |  "
        f"20D: {metadata['rows_20d_full']} rows  |  80D: {metadata['rows_80d']} rows  |  "
        f"Bootstrap CI95 (n=2000)",
        fontsize=10, pad=15,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_protocol_comparison(summary: dict, out_path: Path) -> None:
    """Bar chart F1 macro 3 protocols × 2 datasets × 2 classifiers (skip SHUFFLE)."""
    protocols = ["A_native", "B_matched", "C_group"]
    datasets_clfs = [
        ("20D_NIDS", "rf", COLOR_20D, "20D RF"),
        ("20D_NIDS", "xgb", COLOR_20D, "20D XGB"),
        ("80D_CICFlowMeter", "rf", COLOR_80D, "80D RF"),
        ("80D_CICFlowMeter", "xgb", COLOR_80D, "80D XGB"),
    ]

    fig, ax = plt.subplots(figsize=(12, 6))
    width = 0.18
    x = np.arange(len(protocols))

    for i, (ds, clf, color, label) in enumerate(datasets_clfs):
        means, lows, highs = [], [], []
        for proto in protocols:
            key = f"{proto}__{ds}__{clf}"
            if key in summary:
                s = summary[key]
                means.append(s["f1_macro_mean"])
                lows.append(s["f1_macro_mean"] - s["f1_macro_ci95_bootstrap_lo"])
                highs.append(s["f1_macro_ci95_bootstrap_hi"] - s["f1_macro_mean"])
            else:
                means.append(0)
                lows.append(0)
                highs.append(0)
        offset = (i - 1.5) * width
        hatch = None if "20D" in ds else "//"
        bars = ax.bar(
            x + offset, means, width,
            yerr=[lows, highs], capsize=4,
            color=color, alpha=0.85 if clf == "rf" else 0.55,
            label=label, edgecolor="black", linewidth=1, hatch=hatch,
        )
        for bar, m in zip(bars, means):
            if m > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        f"{m:.3f}", ha="center", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels([
        "Protocol A\n(Native, StratifiedKFold)\nFull data",
        "Protocol B\n(Matched, StratifiedKFold)\n20D subsampled",
        "Protocol C\n(Group, GroupKFold)\nNo temporal leak",
    ], fontsize=9)
    ax.set_ylabel("Macro F1-score (Bootstrap 95% CI)", fontsize=11)
    ax.set_title(
        "Validation Results — 3 Protocols × Bootstrap CI95\n"
        "Protocol C only for 20D (80D lacks IP/timestamp metadata for grouping)",
        fontsize=11,
    )
    ax.set_ylim(0, 1.05)
    ax.axhline(0.85, color="green", linestyle=":", alpha=0.5,
               label="Acceptable threshold (0.85)")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(loc="lower right", fontsize=9, ncol=2)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_per_class_f1_matched(summary: dict, out_path: Path) -> None:
    """Per-class F1 cho Protocol B (matched) — apples-to-apples direct comparison."""
    fig, ax = plt.subplots(figsize=(11, 5.5))

    s_20d = summary["B_matched__20D_NIDS__xgb"]
    s_80d = summary["B_matched__80D_CICFlowMeter__xgb"]

    width = 0.35
    x = np.arange(len(CLASS_ORDER))
    means_20 = [s_20d["per_class_f1_mean"].get(c, 0) for c in CLASS_ORDER]
    means_80 = [s_80d["per_class_f1_mean"].get(c, 0) for c in CLASS_ORDER]
    ci_20 = [s_20d["per_class_ci95"].get(c, [0, 0]) for c in CLASS_ORDER]
    ci_80 = [s_80d["per_class_ci95"].get(c, [0, 0]) for c in CLASS_ORDER]
    err_20 = [[m - lo for m, (lo, hi) in zip(means_20, ci_20)],
              [hi - m for m, (lo, hi) in zip(means_20, ci_20)]]
    err_80 = [[m - lo for m, (lo, hi) in zip(means_80, ci_80)],
              [hi - m for m, (lo, hi) in zip(means_80, ci_80)]]

    bars1 = ax.bar(x - width/2, means_20, width, yerr=err_20, capsize=5,
                   label="20D NIDS (matched subsample)", color=COLOR_20D,
                   edgecolor="black", linewidth=1, alpha=0.85)
    bars2 = ax.bar(x + width/2, means_80, width, yerr=err_80, capsize=5,
                   label="80D CICFlowMeter", color=COLOR_80D,
                   edgecolor="black", linewidth=1, alpha=0.85, hatch="//")

    for bars, means in [(bars1, means_20), (bars2, means_80)]:
        for bar, m in zip(bars, means):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.04,
                    f"{m:.3f}", ha="center", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([c.upper() for c in CLASS_ORDER], fontsize=11)
    ax.set_ylabel("Per-class F1 (XGBoost, Bootstrap CI95)", fontsize=11)
    ax.set_title(
        "Per-class F1 — Protocol B (Matched) — Apples-to-Apples Comparison\n"
        "Both datasets: same N rows, same class distribution",
        fontsize=11,
    )
    ax.set_ylim(0, 1.15)
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_feature_importance(summary: dict, out_path: Path) -> None:
    """20D feature importance — sorted descending."""
    importance = summary["A_native__20D_NIDS__rf"].get("feature_importance_mean", {})
    if not importance:
        print(f"  WARN: no feature importance for 20D RF")
        return

    sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)
    features = [f[0] for f in sorted_features]
    values = [f[1] for f in sorted_features]

    fig, ax = plt.subplots(figsize=(11, 7))
    y_pos = np.arange(len(features))
    bars = ax.barh(y_pos, values, color=COLOR_20D, alpha=0.85,
                   edgecolor="black", linewidth=1)
    for bar, v in zip(bars, values):
        ax.text(v + max(values) * 0.005, bar.get_y() + bar.get_height() / 2,
                f"{v:.3f}", va="center", fontsize=9)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(features, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Feature Importance (Random Forest, averaged 25 runs)", fontsize=11)
    ax.set_title(
        "20D NIDS — Feature Importance Ranking (all 20)\n"
        "F9/F12/F13/F18 expected at top (designed for L7 attack detection)",
        fontsize=11,
    )
    ax.grid(axis="x", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_label_leak_check(summary: dict, out_path: Path) -> None:
    """Real label F1 vs Shuffled label F1 — sanity check."""
    setups = [
        ("A_native__20D_NIDS__rf",      "20D NIDS\n(real labels, RF)",    COLOR_20D),
        ("SHUFFLE__20D_NIDS__rf",        "20D NIDS\n(shuffled, RF)",       COLOR_SHUFFLE),
        ("A_native__80D_CICFlowMeter__rf", "80D CICFlow\n(real labels, RF)", COLOR_80D),
        ("SHUFFLE__80D_CICFlowMeter__rf",  "80D CICFlow\n(shuffled, RF)",   COLOR_SHUFFLE),
    ]

    fig, ax = plt.subplots(figsize=(10, 5.5))
    x = np.arange(len(setups))
    means = []
    cis = []
    colors = []
    labels = []
    for key, lab, col in setups:
        s = summary.get(key, {})
        means.append(s.get("f1_macro_mean", 0))
        cis.append([s.get("f1_macro_mean", 0) - s.get("f1_macro_ci95_bootstrap_lo", 0),
                    s.get("f1_macro_ci95_bootstrap_hi", 0) - s.get("f1_macro_mean", 0)])
        colors.append(col)
        labels.append(lab)

    bars = ax.bar(x, means, yerr=np.array(cis).T, color=colors, alpha=0.85,
                   capsize=8, edgecolor="black", linewidth=1)
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{m:.3f}", ha="center", fontsize=10, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Macro F1-score", fontsize=11)
    ax.set_title(
        "Label-Shuffle Sanity Check — Verify NO Feature Leakage\n"
        "Real labels: F1 should be HIGH. Shuffled labels: F1 should be ~0.25 (random).",
        fontsize=11,
    )
    ax.set_ylim(0, 1.1)
    ax.axhline(0.25, color="red", linestyle="--", alpha=0.6,
               label="Random baseline (1/4 = 0.25)")
    ax.axhline(0.5, color="orange", linestyle=":", alpha=0.4,
               label="Leak threshold (>0.5 = SUSPICIOUS)")
    ax.legend(loc="center right", fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_bootstrap_forest(summary: dict, out_path: Path) -> None:
    """Forest plot — F1 macro với bootstrap CI95, all (protocol, dataset, classifier)."""
    rows = []
    for key in sorted(summary.keys()):
        s = summary[key]
        if s["protocol"] == "SHUFFLE":
            continue
        rows.append({
            "label": f"{s['protocol']} | {s['dataset']} | {s['classifier'].upper()}",
            "mean": s["f1_macro_mean"],
            "lo": s["f1_macro_ci95_bootstrap_lo"],
            "hi": s["f1_macro_ci95_bootstrap_hi"],
            "color": COLOR_20D if "20D" in s["dataset"] else COLOR_80D,
        })

    fig, ax = plt.subplots(figsize=(11, max(6, 0.4 * len(rows) + 2)))
    y_pos = np.arange(len(rows))

    for i, r in enumerate(rows):
        ax.errorbar(r["mean"], i,
                    xerr=[[r["mean"] - r["lo"]], [r["hi"] - r["mean"]]],
                    fmt="o", color=r["color"], capsize=6, markersize=8,
                    elinewidth=2)
        ax.text(r["hi"] + 0.005, i, f"  {r['mean']:.3f} [{r['lo']:.3f}, {r['hi']:.3f}]",
                va="center", fontsize=9)

    ax.set_yticks(y_pos)
    ax.set_yticklabels([r["label"] for r in rows], fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Macro F1-score (Bootstrap 95% CI)", fontsize=11)
    ax.set_title(
        "Forest Plot — F1 Macro với Bootstrap 95% CI (n_resamples=2000)\n"
        "Honest CI without normality assumption",
        fontsize=11,
    )
    ax.set_xlim(0.5, 1.05)
    ax.axvline(0.85, color="green", linestyle=":", alpha=0.5, label="Acceptable (0.85)")
    ax.grid(axis="x", linestyle="--", alpha=0.4)
    ax.legend(loc="lower right", fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_ablation(out_path: Path) -> None:
    """Per-class F1 với ablation — show contribution of each feature group."""
    if not ABL_FILE.exists():
        print(f"  SKIP: {ABL_FILE.name} not found")
        return

    with open(ABL_FILE) as f:
        abl = json.load(f)

    summary = abl["summary"]
    setups = ["full_20d", "minus_Network_F1_F5_F9_F11", "minus_Application_F6_F8",
              "minus_SQLi_F12_F17", "minus_XSS_F18_F20"]
    setup_labels = ["Full 20D\n(baseline)", "− Network\n(F1-5,9-11)",
                    "− Application\n(F6-8)", "− SQLi rules\n(F12-17)",
                    "− XSS rules\n(F18-20)"]

    fig, ax = plt.subplots(figsize=(13, 6))
    x = np.arange(len(setups))
    width = 0.18

    for i, cls in enumerate(CLASS_ORDER):
        means = [summary[s]["per_class_f1_mean"].get(cls, 0) for s in setups]
        offset = (i - 1.5) * width
        bars = ax.bar(x + offset, means, width, label=cls.upper(),
                      edgecolor="black", linewidth=1)
        for bar, m in zip(bars, means):
            if m > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                        f"{m:.2f}", ha="center", fontsize=8)

    ax.set_xticks(x)
    ax.set_xticklabels(setup_labels, fontsize=10)
    ax.set_ylabel("Per-class F1 (Random Forest, GroupKFold)", fontsize=11)
    ax.set_title(
        "Feature Ablation — Contribution of Each Feature Group\n"
        "F1 drop khi remove → group critical cho class đó",
        fontsize=11,
    )
    ax.set_ylim(0, 1.15)
    ax.legend(loc="lower left", fontsize=9, ncol=4)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_confusion_matrices(all_runs: list, out_path: Path) -> None:
    """Side-by-side normalized confusion matrix 20D RF vs 80D RF (Protocol B)."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5.5))

    for ax, dataset, title in [
        (axes[0], "20D_NIDS", "20D NIDS"),
        (axes[1], "80D_CICFlowMeter", "80D CICFlowMeter"),
    ]:
        runs = [r for r in all_runs
                if r["dataset"] == dataset
                and r["classifier"] == "rf"
                and r["protocol"] == "B_matched"]
        if not runs:
            print(f"  WARN: no runs for {dataset} B_matched")
            continue

        class_names = runs[0]["class_names"]
        cm_total = np.zeros((len(class_names), len(class_names)))
        for r in runs:
            cm_total += np.array(r["confusion_matrix"])
        cm_norm = cm_total / cm_total.sum(axis=1, keepdims=True)

        sns.heatmap(cm_norm, annot=True, fmt=".3f", cmap="Blues",
                    xticklabels=class_names, yticklabels=class_names,
                    cbar=True, ax=ax, vmin=0, vmax=1, square=True,
                    annot_kws={"size": 11})
        ax.set_xlabel("Predicted", fontsize=11)
        ax.set_ylabel("True", fontsize=11)
        ax.set_title(f"{title}\n(RF, Protocol B Matched, normalized)", fontsize=11)

    plt.suptitle(
        "Confusion Matrices — Protocol B (Matched, apples-to-apples)\n"
        "Sum of 25 runs (5 folds × 5 seeds), normalized by row",
        fontsize=12, y=1.02,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(VAL_FILE) as f:
        data = json.load(f)
    summary = data["summary"]
    metadata = data["metadata"]
    all_runs = data["all_runs"]

    sns.set_style("whitegrid")
    plt.rcParams["font.family"] = "DejaVu Sans"

    print("Generating plots ...\n")
    plot_summary_table(metadata, summary, PLOTS_DIR / "00_summary_table.png")
    plot_protocol_comparison(summary, PLOTS_DIR / "01_protocol_comparison.png")
    plot_per_class_f1_matched(summary, PLOTS_DIR / "02_per_class_f1_matched.png")
    plot_feature_importance(summary, PLOTS_DIR / "03_feature_importance.png")
    plot_label_leak_check(summary, PLOTS_DIR / "04_label_leak_check.png")
    plot_bootstrap_forest(summary, PLOTS_DIR / "05_bootstrap_forest.png")
    plot_ablation(PLOTS_DIR / "06_ablation.png")
    plot_confusion_matrices(all_runs, PLOTS_DIR / "07_confusion_matrix.png")

    print(f"\nAll plots saved in: {PLOTS_DIR}")


if __name__ == "__main__":
    main()
