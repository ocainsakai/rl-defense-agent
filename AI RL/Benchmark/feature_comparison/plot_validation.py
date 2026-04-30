"""
plot_validation.py — Generate validation plots from validation_results.json.

Plots:
  1. f1_macro_comparison.png — Bar chart F1 macro 20D vs 80D, with error bars
  2. per_class_f1.png — Grouped bar chart per-class F1
  3. feature_importance_20d.png — Top-20 feature importance (cả 20 features)
  4. feature_importance_80d.png — Top-20 feature importance từ 78
  5. confusion_matrix.png — Side-by-side 20D RF vs 80D RF
  6. summary_table.png — Bảng metrics tổng hợp
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

RESULTS_FILE = Path(__file__).parent / "results" / "validation_results.json"
PLOTS_DIR = Path(__file__).parent / "results" / "plots"

CLASS_ORDER = ["benign", "brute_force", "sqli", "xss"]
DATASET_COLORS = {
    "20D_NIDS": "#2E86AB",       # Blue (project)
    "80D_CICFlowMeter": "#A23B72", # Magenta (reference)
}


def plot_f1_macro_comparison(summary: dict, out_path: Path) -> None:
    """Bar chart F1 macro với 95% CI error bars."""
    fig, ax = plt.subplots(figsize=(8, 5))

    keys = ["20D_NIDS_rf", "20D_NIDS_xgb", "80D_CICFlowMeter_rf", "80D_CICFlowMeter_xgb"]
    labels = ["20D NIDS\n(RF)", "20D NIDS\n(XGB)", "80D CICFlow\n(RF)", "80D CICFlow\n(XGB)"]
    colors = [DATASET_COLORS["20D_NIDS"], DATASET_COLORS["20D_NIDS"],
              DATASET_COLORS["80D_CICFlowMeter"], DATASET_COLORS["80D_CICFlowMeter"]]
    means = [summary[k]["f1_macro_mean"] for k in keys]
    stds = [summary[k]["f1_macro_std"] for k in keys]

    x = np.arange(len(keys))
    bars = ax.bar(x, means, yerr=stds, color=colors, capsize=8, alpha=0.85,
                  edgecolor="black", linewidth=1.2)
    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + std + 0.01,
                f"{mean:.3f}", ha="center", fontsize=11, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Macro F1-score", fontsize=12)
    ax.set_title("Validation: 20D NIDS vs 80D CICFlowMeter (Reference Baseline)\n"
                 "5-fold CV × 5 seeds = 25 runs each",
                 fontsize=12)
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.axhline(0.85, color="green", linestyle=":", alpha=0.5,
               label="Acceptable threshold (0.85)")
    ax.legend(loc="lower right")

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_per_class_f1(summary: dict, out_path: Path) -> None:
    """Grouped bar chart per-class F1 cho 20D vs 80D (lấy XGB results)."""
    fig, ax = plt.subplots(figsize=(10, 5))

    s_20d = summary["20D_NIDS_xgb"]["per_class_f1_mean"]
    s_80d = summary["80D_CICFlowMeter_xgb"]["per_class_f1_mean"]
    s_20d_std = summary["20D_NIDS_xgb"]["per_class_f1_std"]
    s_80d_std = summary["80D_CICFlowMeter_xgb"]["per_class_f1_std"]

    width = 0.35
    x = np.arange(len(CLASS_ORDER))
    means_20 = [s_20d.get(c, 0) for c in CLASS_ORDER]
    means_80 = [s_80d.get(c, 0) for c in CLASS_ORDER]
    stds_20 = [s_20d_std.get(c, 0) for c in CLASS_ORDER]
    stds_80 = [s_80d_std.get(c, 0) for c in CLASS_ORDER]

    bars1 = ax.bar(x - width/2, means_20, width, yerr=stds_20,
                   label="20D NIDS", color=DATASET_COLORS["20D_NIDS"],
                   capsize=5, edgecolor="black", linewidth=1)
    bars2 = ax.bar(x + width/2, means_80, width, yerr=stds_80,
                   label="80D CICFlowMeter", color=DATASET_COLORS["80D_CICFlowMeter"],
                   capsize=5, edgecolor="black", linewidth=1)

    for bars, means in [(bars1, means_20), (bars2, means_80)]:
        for bar, m in zip(bars, means):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                    f"{m:.2f}", ha="center", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([c.upper() for c in CLASS_ORDER], fontsize=11)
    ax.set_ylabel("F1-score (XGBoost)", fontsize=12)
    ax.set_title("Per-class F1-score: 20D NIDS vs 80D CICFlowMeter\n"
                 "(Per-class breakdown — XGBoost classifier, 25 runs each)",
                 fontsize=12)
    ax.set_ylim(0, 1.1)
    ax.legend(loc="lower right")
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_feature_importance(summary: dict, dataset_key: str, out_path: Path,
                              top_n: int = 20) -> None:
    """Bar chart top-N feature importance từ Random Forest."""
    importance = summary[dataset_key].get("feature_importance_mean", {})
    if not importance:
        print(f"  WARN: No feature_importance for {dataset_key}")
        return

    sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:top_n]
    features = [f[0] for f in sorted_features]
    values = [f[1] for f in sorted_features]

    fig, ax = plt.subplots(figsize=(10, max(6, len(features) * 0.35)))
    color = DATASET_COLORS["20D_NIDS"] if "20D" in dataset_key else DATASET_COLORS["80D_CICFlowMeter"]

    y_pos = np.arange(len(features))
    bars = ax.barh(y_pos, values, color=color, alpha=0.85,
                   edgecolor="black", linewidth=1)
    for bar, v in zip(bars, values):
        ax.text(v + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{v:.3f}", va="center", fontsize=9)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(features, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("Feature Importance (Random Forest)", fontsize=12)
    title = "20D NIDS — Feature Importance" if "20D" in dataset_key else "80D CICFlowMeter — Top-20 Feature Importance"
    ax.set_title(title + "\n(Averaged over 25 RF runs)", fontsize=12)
    ax.grid(axis="x", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_confusion_matrices(all_runs: list, out_path: Path) -> None:
    """Side-by-side confusion matrix 20D RF vs 80D RF (averaged over runs)."""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    for ax, dataset, title in [
        (axes[0], "20D_NIDS", "20D NIDS"),
        (axes[1], "80D_CICFlowMeter", "80D CICFlowMeter"),
    ]:
        runs = [r for r in all_runs if r["dataset"] == dataset and r["classifier"] == "rf"]
        if not runs:
            continue

        # Sum confusion matrices then normalize by row
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
        ax.set_title(f"{title}\n(Random Forest, normalized, sum of 25 runs)",
                     fontsize=11)

    plt.suptitle("Confusion Matrices: 20D NIDS vs 80D CICFlowMeter",
                 fontsize=13, y=1.02)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_summary_table(metadata: dict, summary: dict, out_path: Path) -> None:
    """Render summary metrics as a clean table image."""
    rows = []
    for key in ["20D_NIDS_rf", "20D_NIDS_xgb", "80D_CICFlowMeter_rf", "80D_CICFlowMeter_xgb"]:
        s = summary[key]
        rows.append([
            f"{s['dataset']}",
            f"{s['classifier'].upper()}",
            f"{s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f}",
            f"{s['precision_macro_mean']:.4f}",
            f"{s['recall_macro_mean']:.4f}",
            f"{s['accuracy_mean']:.4f}",
            f"{s['train_time_mean_sec']:.2f}s",
            f"{s['predict_time_mean_ms']:.4f}",
        ])

    columns = ["Dataset", "Classifier", "F1 macro (±std)", "Precision",
               "Recall", "Accuracy", "Train", "Predict (ms/sample)"]

    fig, ax = plt.subplots(figsize=(14, 3.5))
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=columns,
                      loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2.0)

    # Color rows
    for i, row in enumerate(rows, start=1):
        if "20D" in row[0]:
            color = "#E8F1FA"  # light blue
        else:
            color = "#F8E6EE"  # light magenta
        for j in range(len(columns)):
            table[(i, j)].set_facecolor(color)

    # Header
    for j in range(len(columns)):
        table[(0, j)].set_facecolor("#2E2E2E")
        table[(0, j)].set_text_props(color="white", weight="bold")

    plt.title(
        f"Validation Summary — Dataset: CSE-CIC-IDS2018 Thursday-22-02-2018\n"
        f"5-fold CV × 5 seeds = 25 runs/cell  |  "
        f"20D rows: {metadata['rows_20d']}  |  80D rows: {metadata['rows_80d']}",
        fontsize=11,
        pad=20,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    with open(RESULTS_FILE) as f:
        data = json.load(f)

    summary = data["summary"]
    metadata = data["metadata"]
    all_runs = data["all_runs"]

    sns.set_style("whitegrid")
    plt.rcParams["font.family"] = "DejaVu Sans"

    print("Generating plots ...\n")
    plot_summary_table(metadata, summary, PLOTS_DIR / "00_summary_table.png")
    plot_f1_macro_comparison(summary, PLOTS_DIR / "01_f1_macro_comparison.png")
    plot_per_class_f1(summary, PLOTS_DIR / "02_per_class_f1.png")
    plot_feature_importance(summary, "20D_NIDS_rf",
                            PLOTS_DIR / "03_feature_importance_20d.png", top_n=20)
    plot_feature_importance(summary, "80D_CICFlowMeter_rf",
                            PLOTS_DIR / "04_feature_importance_80d.png", top_n=20)
    plot_confusion_matrices(all_runs, PLOTS_DIR / "05_confusion_matrices.png")

    print(f"\nAll plots saved in: {PLOTS_DIR}")


if __name__ == "__main__":
    main()
