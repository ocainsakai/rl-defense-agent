"""
plot_cross_dataset.py — Combined plots showing 2018 + 2017 validation.

Đặc biệt cho thesis defense: chứng minh 20D feature set generalize được sang
2 dataset khác nhau với attack types khác nhau (cộng thêm scan + syn_flood).

Plots:
  10_cross_dataset_summary.png      Bảng metrics 2018 + 2017
  11_cross_dataset_f1.png           Bar chart F1 macro 2 datasets, 2 protocols
  12_per_class_2017.png             Per-class F1 2017 (7 classes)
  13_label_leak_both.png            Sanity check qua cả 2 dataset
  14_attack_coverage.png            Diagram 11 attack types covered (4 + 3 new)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

RESULTS_DIR = Path(__file__).parent / "results"
VAL_2018_FILE = RESULTS_DIR / "validation_results.json"
VAL_2017_FILE = RESULTS_DIR / "validation_2017_results.json"
PLOTS_DIR = RESULTS_DIR / "plots"

CLASS_ORDER_2018 = ["benign", "brute_force", "sqli", "xss"]
CLASS_ORDER_2017 = ["benign", "brute_force", "sqli", "xss",
                    "scan_fw_on", "scan_fw_off", "syn_flood"]
COLOR_2018 = "#2E86AB"
COLOR_2017 = "#5D9B6A"
COLOR_SHUFFLE = "#888888"


def plot_summary_table(s2018: dict, s2017: dict, out_path: Path) -> None:
    """Bảng metrics 2018 + 2017 (skip SHUFFLE)."""
    rows = []
    for tag, summary, ds in [("2018", s2018, "20D_NIDS"), ("2017", s2017, "20D_2017")]:
        for key in sorted(summary.keys()):
            s = summary[key]
            if s["protocol"] == "SHUFFLE" or s["dataset"] != ds:
                continue
            n_classes = len(s.get("per_class_f1_mean", {}))
            rows.append([
                tag,
                s["protocol"],
                s["classifier"].upper(),
                str(n_classes),
                f"{s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f}",
                f"[{s['f1_macro_ci95_bootstrap_lo']:.3f}, {s['f1_macro_ci95_bootstrap_hi']:.3f}]",
                f"{s['precision_macro_mean']:.4f}",
                f"{s['recall_macro_mean']:.4f}",
                f"{s['accuracy_mean']:.4f}",
            ])

    columns = ["Dataset", "Protocol", "Clf", "Classes", "F1 macro (mean ± std)",
               "Bootstrap CI95", "Precision", "Recall", "Accuracy"]

    fig, ax = plt.subplots(figsize=(15, 1 + 0.45 * len(rows)))
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=columns,
                      loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.8)

    for i, row in enumerate(rows, start=1):
        color = "#E8F1FA" if row[0] == "2018" else "#E8F5E9"
        for j in range(len(columns)):
            table[(i, j)].set_facecolor(color)

    for j in range(len(columns)):
        table[(0, j)].set_facecolor("#2E2E2E")
        table[(0, j)].set_text_props(color="white", weight="bold")

    plt.title(
        "Cross-Dataset Validation Summary — 20D NIDS Feature Set\n"
        "CSE-CIC-IDS2018 (4 classes) + CIC-IDS2017 (7 classes)\n"
        "5-fold × 5 seeds = 25 runs/cell  |  Bootstrap CI95 (n=2000)",
        fontsize=10, pad=15,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_cross_dataset_f1(s2018: dict, s2017: dict, out_path: Path) -> None:
    """Bar chart F1 macro 2 datasets × 2 protocols × 2 classifiers."""
    fig, ax = plt.subplots(figsize=(12, 6))

    setups = [
        ("A_native", "20D_NIDS", "rf", COLOR_2018, "2018 RF"),
        ("A_native", "20D_NIDS", "xgb", COLOR_2018, "2018 XGB"),
        ("C_group", "20D_NIDS", "rf", COLOR_2018, "2018 RF (Group)"),
        ("C_group", "20D_NIDS", "xgb", COLOR_2018, "2018 XGB (Group)"),
        ("A_native", "20D_2017", "rf", COLOR_2017, "2017 RF"),
        ("A_native", "20D_2017", "xgb", COLOR_2017, "2017 XGB"),
        ("C_group", "20D_2017", "rf", COLOR_2017, "2017 RF (Group)"),
        ("C_group", "20D_2017", "xgb", COLOR_2017, "2017 XGB (Group)"),
    ]

    x = np.arange(len(setups))
    means, errs_lo, errs_hi, colors, labels = [], [], [], [], []
    hatches = []
    for proto, ds, clf, color, label in setups:
        key = f"{proto}__{ds}__{clf}"
        summary = s2018 if "2018" in label or "20D_NIDS" in ds else s2017
        s = summary.get(key)
        if s is None:
            means.append(0); errs_lo.append(0); errs_hi.append(0)
        else:
            means.append(s["f1_macro_mean"])
            errs_lo.append(s["f1_macro_mean"] - s["f1_macro_ci95_bootstrap_lo"])
            errs_hi.append(s["f1_macro_ci95_bootstrap_hi"] - s["f1_macro_mean"])
        colors.append(color)
        labels.append(label)
        hatches.append("//" if "Group" in label else None)

    bars = ax.bar(x, means, yerr=[errs_lo, errs_hi], color=colors,
                  capsize=6, edgecolor="black", linewidth=1, alpha=0.85)
    for bar, m, hatch in zip(bars, means, hatches):
        if hatch:
            bar.set_hatch(hatch)
        if m > 0:
            ax.text(bar.get_x() + bar.get_width() / 2, m + 0.015,
                    f"{m:.3f}", ha="center", fontsize=9, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right", fontsize=9)
    ax.set_ylabel("Macro F1-score (Bootstrap 95% CI)", fontsize=11)
    ax.set_title(
        "Cross-Dataset Validation — F1 Macro across 2018 (4 classes) & 2017 (7 classes)\n"
        "Hatched bars = GroupKFold (chống temporal leak)",
        fontsize=11,
    )
    ax.set_ylim(0, 1.1)
    ax.axhline(0.85, color="green", linestyle=":", alpha=0.5,
               label="Acceptable threshold (0.85)")
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(loc="lower right", fontsize=9)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_per_class_2017(summary: dict, out_path: Path) -> None:
    """Per-class F1 cho 2017 (7 classes — gồm 3 attack types mới)."""
    fig, ax = plt.subplots(figsize=(13, 6))

    s_a = summary.get("A_native__20D_2017__xgb", {})
    s_c = summary.get("C_group__20D_2017__xgb", {})

    classes = ["benign", "brute_force", "xss", "sqli", "scan_fw_on",
               "scan_fw_off", "syn_flood"]
    width = 0.35
    x = np.arange(len(classes))

    means_a = [s_a.get("per_class_f1_mean", {}).get(c, 0) for c in classes]
    means_c = [s_c.get("per_class_f1_mean", {}).get(c, 0) for c in classes]

    bars1 = ax.bar(x - width/2, means_a, width, color=COLOR_2017,
                   alpha=0.85, edgecolor="black", linewidth=1,
                   label="Protocol A — Native StratifiedKFold")
    bars2 = ax.bar(x + width/2, means_c, width, color=COLOR_2017,
                   alpha=0.55, edgecolor="black", linewidth=1, hatch="//",
                   label="Protocol C — Group StratifiedGroupKFold (chống temporal leak)")

    for bars, means in [(bars1, means_a), (bars2, means_c)]:
        for bar, m in zip(bars, means):
            if m > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, m + 0.02,
                        f"{m:.2f}", ha="center", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels([c.upper() for c in classes], fontsize=10, rotation=10)
    ax.set_ylabel("Per-class F1 (XGBoost)", fontsize=11)
    ax.set_title(
        "Per-class F1 — CIC-IDS2017 (7 classes incl. SCAN + SYN_FLOOD)\n"
        "Note: SQLi class dropped in Protocol C (only 2 groups < 5 folds)",
        fontsize=11,
    )
    ax.set_ylim(0, 1.15)
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_label_leak_both(s2018: dict, s2017: dict, out_path: Path) -> None:
    """Sanity check label-shuffle qua cả 2 datasets."""
    setups = [
        ("A_native__20D_NIDS__rf",       s2018, "2018\n(real, RF)",      COLOR_2018, 4),
        ("SHUFFLE__20D_NIDS__rf",         s2018, "2018\n(shuffled)",     COLOR_SHUFFLE, 4),
        ("A_native__20D_2017__rf",        s2017, "2017\n(real, RF)",     COLOR_2017, 7),
        ("SHUFFLE__20D_2017__rf",         s2017, "2017\n(shuffled)",     COLOR_SHUFFLE, 7),
    ]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    x = np.arange(len(setups))
    means, errs, colors, labels = [], [], [], []
    for key, summary, label, col, n_class in setups:
        s = summary.get(key, {})
        means.append(s.get("f1_macro_mean", 0))
        std = s.get("f1_macro_std", 0)
        errs.append(std)
        colors.append(col)
        labels.append(label)

    bars = ax.bar(x, means, yerr=errs, color=colors, alpha=0.85,
                   capsize=8, edgecolor="black", linewidth=1)
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, m + 0.025,
                f"{m:.3f}", ha="center", fontsize=10, fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Macro F1-score", fontsize=11)
    ax.set_title(
        "Label-Shuffle Sanity Check — Both Datasets\n"
        "Real labels: F1 HIGH. Shuffled labels: F1 ~ 1/n_classes (random baseline)",
        fontsize=11,
    )
    ax.set_ylim(0, 1.1)
    ax.axhline(0.25, color="red", linestyle="--", alpha=0.6,
               label="2018 random (1/4 = 0.25)")
    ax.axhline(0.143, color="orange", linestyle="--", alpha=0.6,
               label="2017 random (1/7 = 0.143)")
    ax.legend(loc="center right", fontsize=9)
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_attack_coverage(out_path: Path) -> None:
    """Diagram showing attack types covered across 2 datasets."""
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.axis("off")

    attack_types = [
        ("benign", True, True, "Both"),
        ("brute_force", True, True, "Both"),
        ("xss", True, True, "Both"),
        ("sqli", True, True, "Both"),
        ("scan_fw_on", False, True, "2017 only"),
        ("scan_fw_off", False, True, "2017 only"),
        ("syn_flood", False, True, "2017 only"),
    ]

    cell_h = 0.8
    cell_w = 1.4
    x_2018 = 1
    x_2017 = 4
    y_start = 7

    # Headers
    ax.text(x_2018 + cell_w/2, y_start + 0.5, "CSE-CIC-IDS2018\n(Thursday-22-02)",
            ha="center", va="center", fontsize=11, fontweight="bold",
            bbox=dict(facecolor=COLOR_2018, alpha=0.3, edgecolor="black", boxstyle="round"))
    ax.text(x_2017 + cell_w/2, y_start + 0.5, "CIC-IDS2017\n(Thursday + Friday × 2)",
            ha="center", va="center", fontsize=11, fontweight="bold",
            bbox=dict(facecolor=COLOR_2017, alpha=0.3, edgecolor="black", boxstyle="round"))

    for i, (atk, in_2018, in_2017, _) in enumerate(attack_types):
        y = y_start - 1 - i * cell_h

        # 2018
        if in_2018:
            ax.add_patch(plt.Rectangle((x_2018, y - cell_h/2), cell_w, cell_h * 0.9,
                                        facecolor=COLOR_2018, alpha=0.7, edgecolor="black"))
            ax.text(x_2018 + cell_w/2, y, "✓", ha="center", va="center",
                     fontsize=14, color="white", fontweight="bold")
        else:
            ax.add_patch(plt.Rectangle((x_2018, y - cell_h/2), cell_w, cell_h * 0.9,
                                        facecolor="#EEE", alpha=0.5, edgecolor="black"))
            ax.text(x_2018 + cell_w/2, y, "—", ha="center", va="center",
                     fontsize=14, color="gray")

        # 2017
        if in_2017:
            ax.add_patch(plt.Rectangle((x_2017, y - cell_h/2), cell_w, cell_h * 0.9,
                                        facecolor=COLOR_2017, alpha=0.7, edgecolor="black"))
            ax.text(x_2017 + cell_w/2, y, "✓", ha="center", va="center",
                     fontsize=14, color="white", fontweight="bold")

        # Class label
        ax.text(x_2018 - 0.3, y, atk.upper(), ha="right", va="center", fontsize=11)

    ax.set_xlim(-3, 7)
    ax.set_ylim(0, 9)
    ax.set_title(
        "Attack Type Coverage — 11 Total Detection Tasks Tested\n"
        "20D feature set validated trên 7 attack classes + benign  |  "
        "4 chung 2 datasets + 3 mới chỉ trong 2017",
        fontsize=12,
    )

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    if not VAL_2017_FILE.exists():
        print(f"ERROR: {VAL_2017_FILE} not found. Run validate_2017.py first.")
        return

    with open(VAL_2018_FILE) as f:
        s2018 = json.load(f)["summary"]
    with open(VAL_2017_FILE) as f:
        s2017 = json.load(f)["summary"]

    sns.set_style("whitegrid")
    plt.rcParams["font.family"] = "DejaVu Sans"

    print("Generating cross-dataset plots ...\n")
    plot_summary_table(s2018, s2017, PLOTS_DIR / "10_cross_dataset_summary.png")
    plot_cross_dataset_f1(s2018, s2017, PLOTS_DIR / "11_cross_dataset_f1.png")
    plot_per_class_2017(s2017, PLOTS_DIR / "12_per_class_2017.png")
    plot_label_leak_both(s2018, s2017, PLOTS_DIR / "13_label_leak_both.png")
    plot_attack_coverage(PLOTS_DIR / "14_attack_coverage.png")

    print(f"\nDone. Plots in: {PLOTS_DIR}")


if __name__ == "__main__":
    main()
