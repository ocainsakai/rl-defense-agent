"""
feature_distribution.py — Direct feature correctness validation.

Mục tiêu: chứng minh mỗi feature F1-F20 có distribution KHÁC NHAU giữa các class
theo design intent — không phải spurious classifier-only artifact.

Output:
  - results/plots/20_feature_distribution_2018.png — boxplot 20×4 (feature × class 2018)
  - results/plots/21_feature_distribution_2017.png — boxplot 20×7 (feature × class 2017)
  - results/correctness_distribution.json — mean/median/std per (feature, class)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from load_20d import FEATURE_COLS_20D, load_20d_labeled
from load_2017 import load_2017_labeled

RESULTS_DIR = Path(__file__).parent / "results"
PLOTS_DIR = RESULTS_DIR / "plots"
OUTPUT_FILE = RESULTS_DIR / "correctness_distribution.json"


def compute_distribution(df: pd.DataFrame, feature_cols: list[str]) -> dict:
    """Compute mean/median/std/p25/p75 per (feature, class)."""
    out = {}
    for feat in feature_cols:
        out[feat] = {}
        for label, group in df.groupby("label"):
            vals = group[feat].values
            out[feat][label] = {
                "mean": float(np.mean(vals)),
                "median": float(np.median(vals)),
                "std": float(np.std(vals)),
                "p25": float(np.percentile(vals, 25)),
                "p75": float(np.percentile(vals, 75)),
                "min": float(np.min(vals)),
                "max": float(np.max(vals)),
                "n": int(len(vals)),
            }
    return out


def plot_distribution_grid(
    df: pd.DataFrame, feature_cols: list[str], title: str, out_path: Path,
    class_order: list[str] | None = None,
) -> None:
    """5×4 grid of boxplots — one per feature."""
    if class_order is None:
        class_order = sorted(df["label"].unique())

    n_features = len(feature_cols)
    cols = 4
    rows = (n_features + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(cols * 4.5, rows * 3.2))
    axes = axes.flatten()

    palette = sns.color_palette("Set2", len(class_order))

    for i, feat in enumerate(feature_cols):
        ax = axes[i]
        data = [df[df["label"] == c][feat].values for c in class_order]
        bp = ax.boxplot(
            data, labels=class_order, patch_artist=True,
            showfliers=False, widths=0.6,
        )
        for patch, color in zip(bp["boxes"], palette):
            patch.set_facecolor(color)
            patch.set_alpha(0.75)
        # Annotate mean values above each box
        for j, c in enumerate(class_order, start=1):
            vals = df[df["label"] == c][feat].values
            mean_val = np.mean(vals)
            ax.text(j, ax.get_ylim()[1] * 0.95, f"{mean_val:.2f}",
                    ha="center", fontsize=7, fontweight="bold")

        short_name = feat.split(" - ")[1] if " - " in feat else feat
        ax.set_title(f"{feat.split(' - ')[0]}: {short_name}", fontsize=10)
        ax.tick_params(axis="x", labelsize=7, rotation=30)
        ax.tick_params(axis="y", labelsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.4)

    for j in range(n_features, len(axes)):
        axes[j].axis("off")

    plt.suptitle(title, fontsize=13, y=1.001)
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading 2018 ...")
    df_2018 = load_20d_labeled(benign_cap=500)
    print(f"  {len(df_2018)} rows, classes: {sorted(df_2018['label'].unique())}")

    print("Loading 2017 ...")
    df_2017 = load_2017_labeled()
    print(f"  {len(df_2017)} rows, classes: {sorted(df_2017['label'].unique())}")

    sns.set_style("whitegrid")
    plt.rcParams["font.family"] = "DejaVu Sans"

    print("\nComputing distributions ...")
    dist_2018 = compute_distribution(df_2018, FEATURE_COLS_20D)
    dist_2017 = compute_distribution(df_2017, FEATURE_COLS_20D)

    output = {
        "2018": {"n": len(df_2018), "distributions": dist_2018},
        "2017": {"n": len(df_2017), "distributions": dist_2017},
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"  Saved: {OUTPUT_FILE.name}")

    print("\nGenerating boxplot grids ...")
    plot_distribution_grid(
        df_2018, FEATURE_COLS_20D,
        "Feature Distribution per Class — CSE-CIC-IDS2018 (4 classes)\n"
        "Mỗi panel = 1 feature; box = IQR; số trên = mean per class",
        PLOTS_DIR / "20_feature_distribution_2018.png",
        class_order=["benign", "brute_force", "sqli", "xss"],
    )
    plot_distribution_grid(
        df_2017, FEATURE_COLS_20D,
        "Feature Distribution per Class — CIC-IDS2017 (7 classes incl. SCAN + SYN_FLOOD)",
        PLOTS_DIR / "21_feature_distribution_2017.png",
        class_order=["benign", "brute_force", "xss", "sqli",
                     "scan_fw_on", "scan_fw_off", "syn_flood"],
    )

    print("\nDone.")


if __name__ == "__main__":
    main()
