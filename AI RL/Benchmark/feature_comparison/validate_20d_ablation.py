"""
validate_20d_ablation.py — Feature ablation study cho 20D NIDS.

Mục tiêu: chứng minh từng nhóm feature có ý nghĩa
  - Nhóm Network (F1-F5, F9-F11):      detect Brute Force (high packet rate)
  - Nhóm Application (F6-F8):           detect HTTP-level patterns (URL concentration)
  - Nhóm SQLi rules (F12-F17):          detect SQL Injection (CRS 942)
  - Nhóm XSS rules  (F18-F20):          detect XSS (CRS 941)

Methodology:
  - Baseline: train RF trên 20D đầy đủ
  - Ablation: train RF trên 20D MINUS từng nhóm features
  - Metric: per-class F1 drop (if drop large for class X → group critical for X)
  - 5 seeds × 3 folds (= 15 runs) per (ablation_setup × class)

Output: results/ablation_results.json
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import LabelEncoder

from load_20d import FEATURE_COLS_20D, get_features_only, load_20d_labeled
from train_classifier import evaluate_classifier

OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_FILE = OUTPUT_DIR / "ablation_results.json"

SEEDS = [42, 123, 456]
N_FOLDS = 3
CLASSIFIER = "rf"  # ablation chỉ dùng RF (faster + interpretable)

# Define feature groups
FEATURE_GROUPS: Dict[str, List[str]] = {
    "Network_F1_F5_F9_F11": [
        "F1 - PacketRate", "F2 - SynAckRatio", "F3 - InterArrivalTime",
        "F4 - RstRatio", "F5 - DistinctPorts",
        "F9 - AvgPayloadSize", "F10 - FwdBwdRatio", "F11 - PacketsPerPort",
    ],
    "Application_F6_F8": [
        "F6 - URLConcentration", "F7 - HttpIatUniformity",
        "F8 - RequestSizeUniformity",
    ],
    "SQLi_F12_F17": [
        "F12 - SqlSpecialChar", "F13 - CrsSqliScore",
        "F14 - SqlUnionSelect", "F15 - SqlComment",
        "F16 - SqlStackedQuery", "F17 - SqlSelectCount",
    ],
    "XSS_F18_F20": [
        "F18 - CrsXssScore", "F19 - JsFunctionCall",
        "F20 - HtmlEventHandler",
    ],
}


def run_ablation(df: pd.DataFrame) -> List[Dict]:
    """Train RF với various feature subsets, return all metrics."""
    X_full = get_features_only(df)
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    groups = df["group_id"].values

    # Setups: full + 4 ablations
    setups: Dict[str, List[str]] = {"full_20d": FEATURE_COLS_20D}
    for group_name, group_feats in FEATURE_GROUPS.items():
        kept = [f for f in FEATURE_COLS_20D if f not in group_feats]
        setups[f"minus_{group_name}"] = kept

    results: List[Dict] = []
    total = len(setups) * len(SEEDS) * N_FOLDS
    run_idx = 0

    for setup_name, feature_cols in setups.items():
        X = X_full[feature_cols]

        for seed in SEEDS:
            unique_groups = np.unique(groups)
            rng = np.random.default_rng(seed)
            shuffled = rng.permutation(unique_groups)
            group_to_idx = {g: i for i, g in enumerate(shuffled)}
            shuffled_groups = np.array([group_to_idx[g] for g in groups])
            cv = GroupKFold(n_splits=N_FOLDS)

            for fold_idx, (tr_idx, te_idx) in enumerate(cv.split(X, y, groups=shuffled_groups)):
                run_idx += 1
                t0 = time.time()
                X_tr = X.iloc[tr_idx].reset_index(drop=True)
                X_te = X.iloc[te_idx].reset_index(drop=True)
                metrics = evaluate_classifier(
                    X_tr, y[tr_idx], X_te, y[te_idx],
                    classifier_name=CLASSIFIER, seed=seed, label_encoder=le,
                )
                metrics["setup"] = setup_name
                metrics["fold"] = fold_idx
                metrics["seed"] = seed
                metrics["n_features"] = len(feature_cols)
                results.append(metrics)
                elapsed = time.time() - t0
                print(
                    f"  [{run_idx:3d}/{total}] {setup_name:35s} s={seed} f={fold_idx} "
                    f"f1={metrics['f1_macro']:.4f} ({elapsed:.1f}s)"
                )

    return results


def summarize_ablation(results: List[Dict]) -> Dict:
    """Compute per-class F1 mean for each setup, then drop vs full_20d."""
    df = pd.DataFrame(results)

    summary: Dict = {}
    for setup, group in df.groupby("setup"):
        per_class_f1: Dict[str, List[float]] = {}
        for _, row in group.iterrows():
            for cls, stats in row["per_class"].items():
                per_class_f1.setdefault(cls, []).append(stats["f1-score"])

        summary[setup] = {
            "n_features": int(group["n_features"].iloc[0]),
            "f1_macro_mean": float(group["f1_macro"].mean()),
            "f1_macro_std": float(group["f1_macro"].std()),
            "per_class_f1_mean": {c: float(np.mean(v)) for c, v in per_class_f1.items()},
            "per_class_f1_std": {c: float(np.std(v)) for c, v in per_class_f1.items()},
        }

    # Compute drop vs full
    if "full_20d" in summary:
        baseline = summary["full_20d"]
        for setup in summary:
            if setup == "full_20d":
                continue
            summary[setup]["drop_macro_f1"] = (
                baseline["f1_macro_mean"] - summary[setup]["f1_macro_mean"]
            )
            summary[setup]["per_class_drop"] = {
                c: baseline["per_class_f1_mean"].get(c, 0) - summary[setup]["per_class_f1_mean"].get(c, 0)
                for c in baseline["per_class_f1_mean"]
            }

    return summary


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading 20D NIDS dataset (with grouping metadata) ...")
    df = load_20d_labeled(benign_cap=500)
    print(f"  Rows: {len(df)}, groups: {df['group_id'].nunique()}\n")

    print("=" * 70)
    print("  FEATURE ABLATION STUDY (GroupKFold, RF, 3 folds × 3 seeds)")
    print("=" * 70 + "\n")

    results = run_ablation(df)
    summary = summarize_ablation(results)

    output = {
        "metadata": {
            "purpose": "Validate that each feature group có vai trò trong 20D feature set",
            "classifier": CLASSIFIER,
            "n_seeds": len(SEEDS),
            "n_folds": N_FOLDS,
            "feature_groups": FEATURE_GROUPS,
        },
        "summary": summary,
        "all_runs": results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print("\n" + "=" * 70)
    print(f"  RESULTS: {OUTPUT_FILE}")
    print("=" * 70 + "\n")

    print("ABLATION SUMMARY (drop vs full_20d):\n")
    for setup, s in summary.items():
        print(f"  {setup:35s} (n_feat={s['n_features']:2d})")
        print(f"    F1 macro: {s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f}", end="")
        if "drop_macro_f1" in s:
            print(f"   (drop: {s['drop_macro_f1']:+.4f})")
        else:
            print(" (baseline)")
        print(f"    Per-class: ", end="")
        for cls, f1 in s["per_class_f1_mean"].items():
            drop = s.get("per_class_drop", {}).get(cls, 0)
            arrow = f" (↓{drop:.2f})" if drop > 0.05 else ""
            print(f"{cls}={f1:.3f}{arrow}  ", end="")
        print("\n")


if __name__ == "__main__":
    main()
