"""
validate_2017.py — Cross-dataset validation 20D NIDS trên CIC-IDS2017.

Bổ sung cho validate_20d.py (chạy trên CSE-CIC-IDS2018 Thursday-22-02-2018).
Chứng minh 20D feature set generalize được sang dataset thứ 2 với 7 attack classes
(thêm scan_fw_on, scan_fw_off, syn_flood — chưa có trong 2018).

Methodology:
  - Same as validate_20d.py: 5-fold × 5 seeds = 25 runs per classifier
  - StratifiedKFold (Protocol A) + GroupKFold (Protocol C) — chống temporal leak
  - Bootstrap CI95 (n=2000)
  - Label-shuffle sanity check

Note: SQLi class trong 2017 quá ít (n=22, 2 groups) → không stable cho 5-fold.
      Solution: dùng StratifiedGroupKFold(5) từ sklearn để balance folds.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from scipy.stats import bootstrap
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.preprocessing import LabelEncoder

from load_2017 import FEATURE_COLS_20D, get_features_only, load_2017_labeled
from train_classifier import evaluate_classifier

OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_FILE = OUTPUT_DIR / "validation_2017_results.json"

SEEDS = [42, 123, 456, 789, 1337]
N_FOLDS = 5
CLASSIFIERS = ["rf", "xgb"]


def _bootstrap_ci(scores: List[float], confidence: float = 0.95, n_resamples: int = 2000):
    if len(scores) < 2:
        return (float(np.mean(scores)), float(np.mean(scores)))
    arr = np.array(scores, dtype=float)
    res = bootstrap((arr,), np.mean, n_resamples=n_resamples,
                    confidence_level=confidence, method="percentile")
    return float(res.confidence_interval.low), float(res.confidence_interval.high)


def _run_cv(
    X: pd.DataFrame, y: np.ndarray, groups: np.ndarray | None,
    cv_strategy: str, dataset_name: str, protocol: str,
    label_encoder: LabelEncoder,
) -> List[Dict]:
    results: List[Dict] = []
    total_runs = len(SEEDS) * N_FOLDS * len(CLASSIFIERS)
    run_idx = 0

    for seed in SEEDS:
        if cv_strategy == "stratified":
            cv = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)
            split_iter = cv.split(X, y)
        elif cv_strategy == "stratified_group":
            cv = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)
            split_iter = cv.split(X, y, groups=groups)
        else:
            raise ValueError(f"Unknown cv_strategy: {cv_strategy}")

        for fold_idx, (train_idx, test_idx) in enumerate(split_iter):
            X_train_df = X.iloc[train_idx].reset_index(drop=True)
            X_test_df = X.iloc[test_idx].reset_index(drop=True)
            y_train, y_test = y[train_idx], y[test_idx]

            # Skip fold nếu test set thiếu class (do StratifiedGroupKFold)
            if len(np.unique(y_test)) < len(np.unique(y)):
                # OK — classifier vẫn train được, chỉ là 1 class không xuất hiện trong test
                pass

            for clf_name in CLASSIFIERS:
                run_idx += 1
                t0 = time.time()
                metrics = evaluate_classifier(
                    X_train_df, y_train, X_test_df, y_test,
                    classifier_name=clf_name, seed=seed, label_encoder=label_encoder,
                )
                metrics["dataset"] = dataset_name
                metrics["protocol"] = protocol
                metrics["fold"] = fold_idx
                metrics["seed"] = seed
                metrics["cv_strategy"] = cv_strategy
                results.append(metrics)
                elapsed = time.time() - t0
                print(
                    f"  [{run_idx:3d}/{total_runs}] {protocol} {dataset_name:18s} "
                    f"{clf_name.upper()} s={seed} f={fold_idx} "
                    f"f1={metrics['f1_macro']:.4f} ({elapsed:.1f}s)"
                )

    return results


def run_protocol_a_2017(df: pd.DataFrame) -> List[Dict]:
    """Protocol A — Native StratifiedKFold trên 2017."""
    print("\n" + "=" * 70)
    print("  PROTOCOL A — Native (CIC-IDS2017, StratifiedKFold)")
    print("=" * 70)

    X = get_features_only(df)
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    print(f"\n  Rows: {len(df)}, Features: {X.shape[1]}, Classes: {list(le.classes_)}")
    print(f"  Class distribution: {dict(df['label'].value_counts())}")

    return _run_cv(X, y, None, "stratified", "20D_2017", "A_native", le)


def run_protocol_c_2017(df: pd.DataFrame) -> List[Dict]:
    """Protocol C — StratifiedGroupKFold trên 2017 — chống temporal leak.

    Use StratifiedGroupKFold (sklearn 1.0+) để vừa balance class vừa respect group.
    """
    print("\n" + "=" * 70)
    print("  PROTOCOL C — Group (CIC-IDS2017, StratifiedGroupKFold) — chống temporal leak")
    print("=" * 70)

    X = get_features_only(df)
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    groups = df["group_id"].values
    n_groups = len(np.unique(groups))
    print(f"\n  Rows: {len(df)}, groups: {n_groups}")

    # Drop sqli class nếu quá ít group (StratifiedGroupKFold cần n_groups_per_class >= n_splits)
    drop_classes = []
    for lab in df["label"].unique():
        n_g = df[df["label"] == lab]["group_id"].nunique()
        if n_g < N_FOLDS:
            print(f"  WARN: class '{lab}' has only {n_g} groups (< {N_FOLDS} folds)")
            drop_classes.append(lab)

    if drop_classes:
        print(f"  → Filtering out classes with < {N_FOLDS} groups: {drop_classes}")
        mask = ~df["label"].isin(drop_classes)
        df_filt = df[mask].reset_index(drop=True)
        X = get_features_only(df_filt)
        le = LabelEncoder()
        y = le.fit_transform(df_filt["label"])
        groups = df_filt["group_id"].values
        print(f"  → Filtered: {len(df_filt)} rows, classes: {list(le.classes_)}")

    return _run_cv(X, y, groups, "stratified_group", "20D_2017", "C_group", le)


def run_label_leak_check_2017(df: pd.DataFrame) -> List[Dict]:
    """Sanity check — shuffle labels → F1 phải ≈ random baseline."""
    print("\n" + "=" * 70)
    print("  LABEL-SHUFFLE SANITY CHECK (CIC-IDS2017)")
    print("=" * 70)
    rng = np.random.default_rng(0)

    X = get_features_only(df)
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    y_shuffled = rng.permutation(y)

    n_classes = len(le.classes_)
    print(f"\n  Random baseline (1/{n_classes}) = {1/n_classes:.4f}")
    print(f"  Expected F1_shuffled ~ {1/n_classes:.2f}")

    return _run_cv(X, y_shuffled, None, "stratified", "20D_2017", "SHUFFLE", le)


def summarize(results: List[Dict]) -> Dict:
    df = pd.DataFrame(results)
    summary: Dict = {}

    for (protocol, dataset, clf), group in df.groupby(["protocol", "dataset", "classifier"]):
        key = f"{protocol}__{dataset}__{clf}"
        f1_scores = group["f1_macro"].tolist()
        ci_lo, ci_hi = _bootstrap_ci(f1_scores)

        summary[key] = {
            "protocol": protocol,
            "dataset": dataset,
            "classifier": clf,
            "n_runs": len(group),
            "f1_macro_mean": float(group["f1_macro"].mean()),
            "f1_macro_std": float(group["f1_macro"].std()),
            "f1_macro_ci95_bootstrap_lo": ci_lo,
            "f1_macro_ci95_bootstrap_hi": ci_hi,
            "f1_weighted_mean": float(group["f1_weighted"].mean()),
            "precision_macro_mean": float(group["precision_macro"].mean()),
            "recall_macro_mean": float(group["recall_macro"].mean()),
            "accuracy_mean": float(group["accuracy"].mean()),
            "train_time_mean_sec": float(group["train_time_sec"].mean()),
            "predict_time_mean_ms": float(group["predict_time_ms_per_sample"].mean()),
        }

        per_class_f1: Dict[str, List[float]] = {}
        for _, row in group.iterrows():
            for cls, stats in row["per_class"].items():
                per_class_f1.setdefault(cls, []).append(stats["f1-score"])
        summary[key]["per_class_f1_mean"] = {c: float(np.mean(v)) for c, v in per_class_f1.items()}
        summary[key]["per_class_f1_std"] = {c: float(np.std(v)) for c, v in per_class_f1.items()}
        summary[key]["per_class_ci95"] = {
            c: list(_bootstrap_ci(v)) for c, v in per_class_f1.items()
        }

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

    print("Loading CIC-IDS2017 (3 days, 7 classes) ...\n")
    df = load_2017_labeled()
    print(f"  Total: {len(df)} rows, classes: {sorted(df['label'].unique())}")

    all_results: List[Dict] = []
    all_results.extend(run_protocol_a_2017(df))
    all_results.extend(run_protocol_c_2017(df))
    all_results.extend(run_label_leak_check_2017(df))

    summary = summarize(all_results)

    output = {
        "metadata": {
            "purpose": (
                "Cross-dataset validation 20D NIDS feature set trên CIC-IDS2017. "
                "7 classes: benign + brute_force + xss + sqli + scan_fw_on + "
                "scan_fw_off + syn_flood. "
                "Bổ sung 3 attack types mới (scan, syn_flood) chưa có trong 2018."
            ),
            "dataset_source": "CIC-IDS2017 (Thursday + Friday-PortScan + Friday-DDoS)",
            "n_seeds": len(SEEDS),
            "n_folds": N_FOLDS,
            "classifiers": CLASSIFIERS,
            "rows": len(df),
            "n_features": len(FEATURE_COLS_20D),
            "label_distribution": dict(df["label"].value_counts()),
        },
        "summary": summary,
        "all_runs": all_results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print("\n" + "=" * 70)
    print(f"  RESULTS: {OUTPUT_FILE}")
    print("=" * 70 + "\n")

    print("KEY FINDINGS:\n")
    for key in sorted(summary.keys()):
        s = summary[key]
        print(f"  {key}:")
        print(f"    F1 (macro):  {s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f}")
        print(f"      CI95:  [{s['f1_macro_ci95_bootstrap_lo']:.4f}, "
              f"{s['f1_macro_ci95_bootstrap_hi']:.4f}]")
        print(f"    Per-class:   ", end="")
        for cls, f1 in s["per_class_f1_mean"].items():
            print(f"{cls}={f1:.3f}  ", end="")
        print()
        if s["protocol"] == "SHUFFLE":
            n_classes = len(s["per_class_f1_mean"])
            baseline = 1.0 / n_classes
            interp = ("CRITICAL: leak suspect" if s['f1_macro_mean'] > baseline + 0.2
                      else "PASS: ~baseline")
            print(f"    [{interp}]")
        print()


if __name__ == "__main__":
    main()
