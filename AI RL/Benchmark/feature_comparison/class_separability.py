"""
class_separability.py — Test class separability của 20D feature space.

Tests:
  1. ANOVA F-statistic mỗi feature qua các class — feature có discriminate không?
  2. PCA 2D projection — visual separability
  3. t-SNE 2D projection — non-linear separability
  4. KNN purity score — quantitative measure of class clustering trong 20D

Output:
  - results/correctness_separability.json
  - results/plots/22_anova_heatmap.png
  - results/plots/23_pca_projection.png
  - results/plots/24_tsne_projection.png
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.stats import f_oneway, kruskal
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

from load_20d import FEATURE_COLS_20D, load_20d_labeled
from load_2017 import load_2017_labeled

RESULTS_DIR = Path(__file__).parent / "results"
PLOTS_DIR = RESULTS_DIR / "plots"
OUTPUT_FILE = RESULTS_DIR / "correctness_separability.json"


def anova_per_feature(df: pd.DataFrame, feature_cols: list, dataset: str) -> dict:
    """For each feature, run ANOVA + Kruskal-Wallis across all classes."""
    classes = sorted(df["label"].unique())
    out = {}
    for feat in feature_cols:
        groups = [df[df["label"] == c][feat].values for c in classes]
        groups = [g for g in groups if len(g) > 0]
        if len(groups) < 2:
            continue
        try:
            f_stat, f_p = f_oneway(*groups)
            h_stat, h_p = kruskal(*groups)
        except Exception:
            f_stat = f_p = h_stat = h_p = float("nan")
        out[feat] = {
            "anova_f_stat": float(f_stat),
            "anova_p_value": float(f_p),
            "kruskal_h_stat": float(h_stat),
            "kruskal_p_value": float(h_p),
            "discriminative": bool(h_p < 0.05),
        }
    return out


def plot_anova_heatmap(stats_2018: dict, stats_2017: dict, out_path: Path) -> None:
    """Heatmap: feature × dataset → -log10(p_value) (clip 0-50)."""
    feats = FEATURE_COLS_20D
    rows = []
    for f in feats:
        row = []
        for stats in [stats_2018, stats_2017]:
            if f in stats:
                p = stats[f]["kruskal_p_value"]
                neg_log = -np.log10(max(p, 1e-50))
                row.append(min(neg_log, 50))  # clip
            else:
                row.append(0)
        rows.append(row)

    arr = np.array(rows)
    fig, ax = plt.subplots(figsize=(7, 9))
    sns.heatmap(arr, annot=True, fmt=".1f", cmap="viridis",
                xticklabels=["2018 (4 classes)", "2017 (7 classes)"],
                yticklabels=[f.split(" - ")[0] + " " + f.split(" - ")[1] for f in feats],
                cbar_kws={"label": "-log10(p_value), clipped at 50"},
                ax=ax, linewidths=0.5)
    ax.set_title(
        "Class Separability per Feature — Kruskal-Wallis -log10(p)\n"
        "Higher = feature discriminate stronger across classes\n"
        "p < 0.05 → -log10(p) > 1.3 → significant",
        fontsize=11,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def plot_pca(df: pd.DataFrame, feature_cols: list, title: str, out_path: Path) -> None:
    """PCA 2D projection of 20D features, colored by class."""
    X = df[feature_cols].values
    y = df["label"].values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)

    classes = sorted(df["label"].unique())
    palette = sns.color_palette("tab10", len(classes))

    fig, ax = plt.subplots(figsize=(11, 7))
    for cls, color in zip(classes, palette):
        mask = y == cls
        ax.scatter(X_pca[mask, 0], X_pca[mask, 1], c=[color],
                   label=f"{cls} (n={mask.sum()})", s=15, alpha=0.6,
                   edgecolors="white", linewidths=0.3)

    var_explained = pca.explained_variance_ratio_
    ax.set_xlabel(f"PC1 ({var_explained[0]*100:.1f}% variance)", fontsize=11)
    ax.set_ylabel(f"PC2 ({var_explained[1]*100:.1f}% variance)", fontsize=11)
    ax.set_title(
        f"PCA 2D projection — {title}\n"
        f"Total variance explained: {sum(var_explained)*100:.1f}%",
        fontsize=11,
    )
    ax.legend(loc="best", fontsize=9, markerscale=2)
    ax.grid(linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")
    return float(sum(var_explained))


def plot_tsne(df: pd.DataFrame, feature_cols: list, title: str, out_path: Path,
              perplexity: int = 30, max_samples: int = 3000) -> float:
    """t-SNE 2D non-linear projection."""
    X = df[feature_cols].values
    y = df["label"].values

    if len(X) > max_samples:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X), size=max_samples, replace=False)
        X = X[idx]
        y = y[idx]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    tsne = TSNE(n_components=2, perplexity=perplexity, random_state=42,
                init="pca", max_iter=1000, learning_rate="auto")
    X_tsne = tsne.fit_transform(X_scaled)

    classes = sorted(np.unique(y))
    palette = sns.color_palette("tab10", len(classes))

    fig, ax = plt.subplots(figsize=(11, 7))
    for cls, color in zip(classes, palette):
        mask = y == cls
        ax.scatter(X_tsne[mask, 0], X_tsne[mask, 1], c=[color],
                   label=f"{cls} (n={mask.sum()})", s=15, alpha=0.6,
                   edgecolors="white", linewidths=0.3)

    ax.set_xlabel("t-SNE component 1", fontsize=11)
    ax.set_ylabel("t-SNE component 2", fontsize=11)
    ax.set_title(f"t-SNE 2D projection — {title}\nperplexity={perplexity}", fontsize=11)
    ax.legend(loc="best", fontsize=9, markerscale=2)
    ax.grid(linestyle="--", alpha=0.4)

    # KNN purity: for each point, fraction of K nearest neighbors that share label
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(X_tsne, y)
    purity = float(np.mean(knn.predict(X_tsne) == y))

    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}  (KNN-5 purity in t-SNE space: {purity:.3f})")
    return purity


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading datasets ...")
    df_2018 = load_20d_labeled(benign_cap=500)
    df_2017 = load_2017_labeled()

    sns.set_style("whitegrid")
    plt.rcParams["font.family"] = "DejaVu Sans"

    print("\n[1] ANOVA + Kruskal-Wallis per feature ...")
    stats_2018 = anova_per_feature(df_2018, FEATURE_COLS_20D, "2018")
    stats_2017 = anova_per_feature(df_2017, FEATURE_COLS_20D, "2017")

    plot_anova_heatmap(stats_2018, stats_2017, PLOTS_DIR / "22_anova_heatmap.png")

    print("\n[2] PCA projection ...")
    var_2018 = plot_pca(df_2018, FEATURE_COLS_20D,
                        "CSE-CIC-IDS2018 (4 classes)",
                        PLOTS_DIR / "23_pca_projection_2018.png")
    var_2017 = plot_pca(df_2017, FEATURE_COLS_20D,
                        "CIC-IDS2017 (7 classes)",
                        PLOTS_DIR / "23_pca_projection_2017.png")

    print("\n[3] t-SNE projection ...")
    purity_2018 = plot_tsne(df_2018, FEATURE_COLS_20D,
                            "CSE-CIC-IDS2018 (4 classes)",
                            PLOTS_DIR / "24_tsne_projection_2018.png")
    purity_2017 = plot_tsne(df_2017, FEATURE_COLS_20D,
                            "CIC-IDS2017 (7 classes)",
                            PLOTS_DIR / "24_tsne_projection_2017.png")

    # Summary
    n_disc_2018 = sum(1 for s in stats_2018.values() if s["discriminative"])
    n_disc_2017 = sum(1 for s in stats_2017.values() if s["discriminative"])

    output = {
        "anova_2018": stats_2018,
        "anova_2017": stats_2017,
        "summary": {
            "n_discriminative_features_2018": n_disc_2018,
            "n_discriminative_features_2017": n_disc_2017,
            "pca_variance_explained_2018": var_2018,
            "pca_variance_explained_2017": var_2017,
            "tsne_knn5_purity_2018": purity_2018,
            "tsne_knn5_purity_2017": purity_2017,
        },
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print("\n=== SUMMARY ===")
    print(f"Discriminative features (Kruskal-Wallis p<0.05):")
    print(f"  2018: {n_disc_2018}/20")
    print(f"  2017: {n_disc_2017}/20")
    print(f"PCA 2D variance explained:")
    print(f"  2018: {var_2018*100:.1f}%")
    print(f"  2017: {var_2017*100:.1f}%")
    print(f"t-SNE KNN-5 purity (class clustering quality):")
    print(f"  2018: {purity_2018:.3f}")
    print(f"  2017: {purity_2017:.3f}")
    print("Higher purity → classes well-clustered → 20D có inherent separability")


if __name__ == "__main__":
    main()
