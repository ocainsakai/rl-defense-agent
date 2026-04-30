"""
validate_20d.py — Validate 20D NIDS feature set HOẠT ĐỘNG ĐÚNG.

Mục tiêu (KHÔNG phải benchmark hiệu suất):
  Trả lời câu hỏi của hội đồng: "20D em tự làm liệu có đúng so với CICFlowMeter chuẩn?"

Bằng chứng cần show:
  1. 20D có discriminative power: F1 cao trên 4 attack classes
  2. 20D không mất thông tin: F1(20D) trong cùng range với F1(80D CICFlowMeter)
  3. 20D có ý nghĩa: feature importance khớp design (F13=CRS-SQLi top cho sqli class, ...)
  4. 20D ổn định: F1 std nhỏ qua 5-fold × 5-seed

Methodology:
  - Train RandomForest + XGBoost trên CẢ 2 dataset (20D + 80D)
  - StratifiedKFold(5) × 5 seeds = 25 runs per (dataset × classifier)
  - Output: validation_results.json
  - Plot ở file plot_validation.py riêng

Output: AI RL/Benchmark/feature_comparison/results/validation_results.json
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder

from load_20d import FEATURE_COLS_20D, load_20d_labeled
from load_80d import load_80d_labeled
from train_classifier import evaluate_classifier

OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_FILE = OUTPUT_DIR / "validation_results.json"

SEEDS = [42, 123, 456, 789, 1337]
N_FOLDS = 5
CLASSIFIERS = ["rf", "xgb"]


def run_validation_for_dataset(
    df: pd.DataFrame,
    feature_cols: List[str],
    dataset_name: str,
) -> List[Dict]:
    """Run StratifiedKFold × seeds × classifiers on one dataset."""
    X = df[feature_cols].values
    le = LabelEncoder()
    y = le.fit_transform(df["label"])

    print(f"\n{'='*70}")
    print(f"  Dataset: {dataset_name}")
    print(f"  Rows: {len(df)}, Features: {len(feature_cols)}, Classes: {list(le.classes_)}")
    print(f"  Class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
    print(f"{'='*70}")

    results: List[Dict] = []
    total_runs = len(SEEDS) * N_FOLDS * len(CLASSIFIERS)
    run_idx = 0

    for seed in SEEDS:
        skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)

        for fold_idx, (train_idx, test_idx) in enumerate(skf.split(X, y)):
            X_train_df = pd.DataFrame(X[train_idx], columns=feature_cols)
            X_test_df = pd.DataFrame(X[test_idx], columns=feature_cols)
            y_train, y_test = y[train_idx], y[test_idx]

            for clf_name in CLASSIFIERS:
                run_idx += 1
                t0 = time.time()
                metrics = evaluate_classifier(
                    X_train_df, y_train, X_test_df, y_test,
                    classifier_name=clf_name, seed=seed, label_encoder=le,
                )
                metrics["dataset"] = dataset_name
                metrics["fold"] = fold_idx
                metrics["seed"] = seed
                results.append(metrics)
                elapsed = time.time() - t0
                print(
                    f"  [{run_idx:3d}/{total_runs}] "
                    f"{clf_name.upper()} seed={seed} fold={fold_idx} "
                    f"f1_macro={metrics['f1_macro']:.4f} "
                    f"acc={metrics['accuracy']:.4f} "
                    f"({elapsed:.1f}s)"
                )

    return results


def summarize_results(results: List[Dict]) -> Dict:
    """Aggregate per-(dataset, classifier) statistics."""
    df = pd.DataFrame(results)
    summary: Dict = {}

    for (dataset, clf), group in df.groupby(["dataset", "classifier"]):
        key = f"{dataset}_{clf}"
        summary[key] = {
            "dataset": dataset,
            "classifier": clf,
            "n_runs": len(group),
            "f1_macro_mean": float(group["f1_macro"].mean()),
            "f1_macro_std": float(group["f1_macro"].std()),
            "f1_macro_ci95_lo": float(group["f1_macro"].mean() - 1.96 * group["f1_macro"].std() / np.sqrt(len(group))),
            "f1_macro_ci95_hi": float(group["f1_macro"].mean() + 1.96 * group["f1_macro"].std() / np.sqrt(len(group))),
            "f1_weighted_mean": float(group["f1_weighted"].mean()),
            "precision_macro_mean": float(group["precision_macro"].mean()),
            "recall_macro_mean": float(group["recall_macro"].mean()),
            "accuracy_mean": float(group["accuracy"].mean()),
            "train_time_mean_sec": float(group["train_time_sec"].mean()),
            "predict_time_mean_ms": float(group["predict_time_ms_per_sample"].mean()),
        }

        # Per-class F1 average
        per_class_f1: Dict[str, List[float]] = {}
        for _, row in group.iterrows():
            for cls, stats in row["per_class"].items():
                per_class_f1.setdefault(cls, []).append(stats["f1-score"])
        summary[key]["per_class_f1_mean"] = {
            cls: float(np.mean(v)) for cls, v in per_class_f1.items()
        }
        summary[key]["per_class_f1_std"] = {
            cls: float(np.std(v)) for cls, v in per_class_f1.items()
        }

        # Average feature importance (RF only — XGB stores differently but works)
        importances: Dict[str, List[float]] = {}
        for _, row in group.iterrows():
            fi = row.get("feature_importance", {})
            for feat, imp in fi.items():
                importances.setdefault(feat, []).append(imp)
        if importances:
            summary[key]["feature_importance_mean"] = {
                feat: float(np.mean(v)) for feat, v in importances.items()
            }

    return summary


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading 20D NIDS dataset ...")
    df_20d = load_20d_labeled(benign_cap=500)

    print("\nLoading 80D CICFlowMeter dataset (reference baseline) ...")
    df_80d = load_80d_labeled(benign_cap=500)
    feature_cols_80d = [c for c in df_80d.columns if c != "label"]

    all_results: List[Dict] = []

    # 1. Validate 20D (PRIMARY — câu trả lời chính)
    results_20d = run_validation_for_dataset(df_20d, FEATURE_COLS_20D, "20D_NIDS")
    all_results.extend(results_20d)

    # 2. Run 80D as reference baseline (cho perspective)
    results_80d = run_validation_for_dataset(df_80d, feature_cols_80d, "80D_CICFlowMeter")
    all_results.extend(results_80d)

    # 3. Summarize
    summary = summarize_results(all_results)

    output = {
        "metadata": {
            "purpose": "Validation that 20D NIDS feature set works correctly (NOT benchmark vs 80D)",
            "dataset_source": "CSE-CIC-IDS2018 Thursday-22-02-2018",
            "n_seeds": len(SEEDS),
            "n_folds": N_FOLDS,
            "classifiers": CLASSIFIERS,
            "rows_20d": len(df_20d),
            "rows_80d": len(df_80d),
            "n_features_20d": len(FEATURE_COLS_20D),
            "n_features_80d": len(feature_cols_80d),
            "label_distribution_20d": df_20d["label"].value_counts().to_dict(),
            "label_distribution_80d": df_80d["label"].value_counts().to_dict(),
        },
        "summary": summary,
        "all_runs": all_results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n{'='*70}")
    print(f"  RESULTS SAVED: {OUTPUT_FILE}")
    print(f"{'='*70}\n")

    # Pretty print key findings
    print("KEY FINDINGS:\n")
    for key, s in summary.items():
        print(f"  {key}:")
        print(f"    F1 (macro):  {s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f} "
              f"[95% CI: {s['f1_macro_ci95_lo']:.4f}, {s['f1_macro_ci95_hi']:.4f}]")
        print(f"    Per-class:   ", end="")
        for cls, f1 in s["per_class_f1_mean"].items():
            print(f"{cls}={f1:.3f}  ", end="")
        print()
        print(f"    Train: {s['train_time_mean_sec']:.2f}s  "
              f"Predict: {s['predict_time_mean_ms']:.4f} ms/sample\n")


if __name__ == "__main__":
    main()
