"""
validate_20d.py — Academic-grade validation of 20D NIDS feature set.

Mục tiêu: Chứng minh 20D feature set HOẠT ĐỘNG ĐÚNG, KHÔNG phải benchmark
hiệu suất "20D vs 80D xem ai thắng".

5 BIAS đã được fix so với version trước:

  Bias 1 (Label leakage qua src_ip + timestamp)
    → DROP src_ip + timestamp khỏi feature matrix X (chỉ giữ trong metadata)
    → Add label-shuffle sanity check: F1 với random label phải ~baseline (1/4 = 0.25)

  Bias 2 (Class skew giả: 6691 vs 858 rows do granularity khác)
    → Protocol B: subsample 20D về match 80D class distribution → fair comparison
    → Report cả native (Protocol A) lẫn matched (Protocol B)

  Bias 3 (CV temporal leak — StratifiedKFold shuffle ngẫu nhiên)
    → Protocol C: GroupKFold theo (src_ip, attack_window, minute_bucket)
    → Đảm bảo train/test rows không cùng minute → no temporal leak

  Bias 4 (Sample size bias trong CI calc — parametric assumption)
    → Bootstrap percentile CI (n_resamples=2000, 95%)
    → Honest hơn parametric mean ± 1.96·std/√n khi n small

  Bias 5 (Conclusion overstate)
    → Framing rõ ràng: "validation 20D works" KHÔNG phải "20D > 80D"
    → Honest report limitations: 1 day, 1 dataset, sqli n=34

3 Protocols:
  A — Native:  StratifiedKFold(5) trên full data của mỗi dataset
                (replicate behavior commit cũ — reference)
  B — Matched: Subsample 20D match 80D, StratifiedKFold(5)
                (apples-to-apples direct comparison)
  C — Group:   GroupKFold(5) trên 20D theo group_id
                (chống temporal leak — chỉ cho 20D vì 80D không có group metadata)

Sanity check: Label-shuffle baseline → F1 phải ~0.25 (random)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from scipy.stats import bootstrap
from sklearn.model_selection import GroupKFold, StratifiedKFold
from sklearn.preprocessing import LabelEncoder

from load_20d import FEATURE_COLS_20D, get_features_only, load_20d_labeled
from load_80d import (
    get_class_distribution,
    load_80d_labeled,
    subsample_20d_to_match_80d,
)
from train_classifier import evaluate_classifier

OUTPUT_DIR = Path(__file__).parent / "results"
OUTPUT_FILE = OUTPUT_DIR / "validation_results.json"

SEEDS = [42, 123, 456, 789, 1337]
N_FOLDS = 5
CLASSIFIERS = ["rf", "xgb"]


def _bootstrap_ci(scores: List[float], confidence: float = 0.95, n_resamples: int = 2000) -> Tuple[float, float]:
    """Compute bootstrap percentile CI for mean of scores.

    Honest CI when n is small or distribution is skewed; doesn't assume normal.
    """
    if len(scores) < 2:
        return (float(np.mean(scores)), float(np.mean(scores)))
    arr = np.array(scores, dtype=float)
    res = bootstrap(
        (arr,), np.mean, n_resamples=n_resamples,
        confidence_level=confidence, method="percentile",
    )
    return float(res.confidence_interval.low), float(res.confidence_interval.high)


def _run_cv(
    X: pd.DataFrame, y: np.ndarray, groups: np.ndarray | None,
    cv_strategy: str, dataset_name: str, protocol: str,
    label_encoder: LabelEncoder,
) -> List[Dict]:
    """Run k-fold × seeds × classifiers on (X, y).

    Args:
        cv_strategy: 'stratified' or 'group'.
        groups: group ids (required if cv_strategy='group').
    """
    results: List[Dict] = []
    total_runs = len(SEEDS) * N_FOLDS * len(CLASSIFIERS)
    run_idx = 0

    for seed in SEEDS:
        if cv_strategy == "stratified":
            cv = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)
            split_iter = cv.split(X, y)
        elif cv_strategy == "group":
            # GroupKFold không có random_state → fake bằng cách shuffle groups
            unique_groups = np.unique(groups)
            rng = np.random.default_rng(seed)
            shuffled = rng.permutation(unique_groups)
            group_to_idx = {g: i for i, g in enumerate(shuffled)}
            shuffled_groups = np.array([group_to_idx[g] for g in groups])
            cv = GroupKFold(n_splits=N_FOLDS)
            split_iter = cv.split(X, y, groups=shuffled_groups)
        else:
            raise ValueError(f"Unknown cv_strategy: {cv_strategy}")

        for fold_idx, (train_idx, test_idx) in enumerate(split_iter):
            X_train_df = X.iloc[train_idx].reset_index(drop=True)
            X_test_df = X.iloc[test_idx].reset_index(drop=True)
            y_train, y_test = y[train_idx], y[test_idx]

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


def run_protocol_a(df_20d: pd.DataFrame, df_80d: pd.DataFrame) -> List[Dict]:
    """Protocol A — Native: each dataset uses full data, StratifiedKFold."""
    print("\n" + "=" * 70)
    print(f"  PROTOCOL A — Native (full data, StratifiedKFold)")
    print("=" * 70)
    out: List[Dict] = []

    # 20D
    X_20 = get_features_only(df_20d)
    le_20 = LabelEncoder()
    y_20 = le_20.fit_transform(df_20d["label"])
    print(f"\n  Dataset: 20D_NIDS  rows={len(df_20d)}  features={X_20.shape[1]}")
    print(f"  Class distribution: {get_class_distribution(df_20d)}")
    out.extend(_run_cv(X_20, y_20, None, "stratified", "20D_NIDS", "A_native", le_20))

    # 80D
    feature_cols_80 = [c for c in df_80d.columns if c != "label"]
    X_80 = df_80d[feature_cols_80]
    le_80 = LabelEncoder()
    y_80 = le_80.fit_transform(df_80d["label"])
    print(f"\n  Dataset: 80D_CICFlowMeter  rows={len(df_80d)}  features={X_80.shape[1]}")
    print(f"  Class distribution: {get_class_distribution(df_80d)}")
    out.extend(_run_cv(X_80, y_80, None, "stratified", "80D_CICFlowMeter", "A_native", le_80))

    return out


def run_protocol_b(df_20d: pd.DataFrame, df_80d: pd.DataFrame) -> List[Dict]:
    """Protocol B — Matched: subsample 20D to 80D class distribution."""
    print("\n" + "=" * 70)
    print(f"  PROTOCOL B — Matched (subsample 20D, StratifiedKFold)")
    print("=" * 70)
    out: List[Dict] = []

    df_20_matched = subsample_20d_to_match_80d(df_20d, df_80d, seed=42)
    print(f"\n  Subsampled 20D: {get_class_distribution(df_20_matched)} = {len(df_20_matched)} rows")

    # 20D matched
    X_20m = get_features_only(df_20_matched)
    le = LabelEncoder()
    y_20m = le.fit_transform(df_20_matched["label"])
    out.extend(_run_cv(X_20m, y_20m, None, "stratified", "20D_NIDS", "B_matched", le))

    # 80D (same as Protocol A — re-run for fair comparison within same protocol section)
    feature_cols_80 = [c for c in df_80d.columns if c != "label"]
    X_80 = df_80d[feature_cols_80]
    le_80 = LabelEncoder()
    y_80 = le_80.fit_transform(df_80d["label"])
    out.extend(_run_cv(X_80, y_80, None, "stratified", "80D_CICFlowMeter", "B_matched", le_80))

    return out


def run_protocol_c(df_20d: pd.DataFrame) -> List[Dict]:
    """Protocol C — Group: GroupKFold by (src_ip × attack_window × minute_bucket).

    Only applies to 20D (80D has no IP/timestamp metadata to group by).
    """
    print("\n" + "=" * 70)
    print(f"  PROTOCOL C — Group (GroupKFold on 20D — chống temporal leak)")
    print("=" * 70)
    out: List[Dict] = []

    X = get_features_only(df_20d)
    le = LabelEncoder()
    y = le.fit_transform(df_20d["label"])
    groups = df_20d["group_id"].values

    n_groups = len(np.unique(groups))
    print(f"\n  Dataset: 20D_NIDS  rows={len(df_20d)}  groups={n_groups}")
    print(f"  Class distribution: {get_class_distribution(df_20d)}")

    # GroupKFold should have enough groups per class
    for lab, idx in df_20d.groupby("label"):
        n_g = idx["group_id"].nunique()
        if n_g < N_FOLDS:
            print(f"  WARN: class '{lab}' has only {n_g} groups < N_FOLDS={N_FOLDS}")

    out.extend(_run_cv(X, y, groups, "group", "20D_NIDS", "C_group", le))
    return out


def run_label_leak_sanity_check(df_20d: pd.DataFrame, df_80d: pd.DataFrame) -> List[Dict]:
    """SANITY CHECK: shuffle y → train classifier → F1 phải ~baseline (random).

    Nếu F1_shuffled > 0.5 → có label leak từ feature/metadata → FAIL.
    Expected: F1_shuffled ≈ 0.25 (1/n_classes for 4-class problem).
    """
    print("\n" + "=" * 70)
    print(f"  LABEL-SHUFFLE SANITY CHECK (gold standard for no-leak)")
    print("=" * 70)
    out: List[Dict] = []
    rng = np.random.default_rng(0)

    # Shuffle labels for each dataset, run 1 seed × 5 folds × 2 classifiers
    for df, name, get_X in [
        (df_20d, "20D_NIDS", get_features_only),
        (df_80d, "80D_CICFlowMeter",
         lambda d: d[[c for c in d.columns if c != "label"]]),
    ]:
        X = get_X(df)
        le = LabelEncoder()
        y = le.fit_transform(df["label"])
        y_shuffled = rng.permutation(y)
        print(f"\n  Dataset: {name}  (labels shuffled)")
        out.extend(_run_cv(X, y_shuffled, None, "stratified", name, "SHUFFLE", le))

    return out


def summarize(results: List[Dict]) -> Dict:
    """Aggregate per-(protocol, dataset, classifier) statistics with bootstrap CI."""
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
            "f1_macro_p25": float(np.percentile(f1_scores, 2.5)),
            "f1_macro_p975": float(np.percentile(f1_scores, 97.5)),
            "f1_weighted_mean": float(group["f1_weighted"].mean()),
            "precision_macro_mean": float(group["precision_macro"].mean()),
            "recall_macro_mean": float(group["recall_macro"].mean()),
            "accuracy_mean": float(group["accuracy"].mean()),
            "train_time_mean_sec": float(group["train_time_sec"].mean()),
            "predict_time_mean_ms": float(group["predict_time_ms_per_sample"].mean()),
        }

        # Per-class F1
        per_class_f1: Dict[str, List[float]] = {}
        for _, row in group.iterrows():
            for cls, stats in row["per_class"].items():
                per_class_f1.setdefault(cls, []).append(stats["f1-score"])
        summary[key]["per_class_f1_mean"] = {c: float(np.mean(v)) for c, v in per_class_f1.items()}
        summary[key]["per_class_f1_std"] = {c: float(np.std(v)) for c, v in per_class_f1.items()}
        summary[key]["per_class_ci95"] = {
            c: list(_bootstrap_ci(v)) for c, v in per_class_f1.items()
        }

        # Feature importance (RF only)
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

    print("Loading 80D CICFlowMeter dataset ...")
    df_80d = load_80d_labeled(benign_cap=500)

    all_results: List[Dict] = []

    all_results.extend(run_protocol_a(df_20d, df_80d))
    all_results.extend(run_protocol_b(df_20d, df_80d))
    all_results.extend(run_protocol_c(df_20d))
    all_results.extend(run_label_leak_sanity_check(df_20d, df_80d))

    summary = summarize(all_results)

    output = {
        "metadata": {
            "purpose": (
                "VALIDATION (not benchmark): chứng minh 20D NIDS feature set hoạt động đúng. "
                "80D CICFlowMeter làm reference baseline cho context, KHÔNG phải head-to-head benchmark."
            ),
            "dataset_source": "CSE-CIC-IDS2018 Thursday-22-02-2018",
            "n_seeds": len(SEEDS),
            "n_folds": N_FOLDS,
            "classifiers": CLASSIFIERS,
            "rows_20d_full": len(df_20d),
            "rows_80d": len(df_80d),
            "n_features_20d": len(FEATURE_COLS_20D),
            "n_features_80d": len([c for c in df_80d.columns if c != "label"]),
            "label_distribution_20d_full": get_class_distribution(df_20d),
            "label_distribution_80d": get_class_distribution(df_80d),
            "bias_fixes": [
                "Bias1: drop src_ip+timestamp from X (label-leak verification: F1_shuffled ~0.25)",
                "Bias2: Protocol B subsamples 20D to match 80D class distribution",
                "Bias3: Protocol C uses GroupKFold to prevent temporal leak",
                "Bias4: bootstrap percentile CI (n=2000) instead of parametric",
                "Bias5: framed as 'validation' not 'benchmark', honest limitations",
            ],
        },
        "summary": summary,
        "all_runs": all_results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print("\n" + "=" * 70)
    print(f"  RESULTS SAVED: {OUTPUT_FILE}")
    print("=" * 70 + "\n")

    print("KEY FINDINGS (sorted by protocol → dataset → classifier):\n")
    for key in sorted(summary.keys()):
        s = summary[key]
        print(f"  {key}:")
        print(f"    F1 (macro):  {s['f1_macro_mean']:.4f} ± {s['f1_macro_std']:.4f}")
        print(f"      bootstrap CI95:  [{s['f1_macro_ci95_bootstrap_lo']:.4f}, "
              f"{s['f1_macro_ci95_bootstrap_hi']:.4f}]")
        print(f"    Per-class:   ", end="")
        for cls, f1 in s["per_class_f1_mean"].items():
            print(f"{cls}={f1:.3f}  ", end="")
        print()
        if s["protocol"] == "SHUFFLE":
            interp = "CRITICAL: should be ~0.25 (random)" if s["f1_macro_mean"] > 0.5 else "PASS: ~baseline"
            print(f"    ⚠ {interp}")
        print()


if __name__ == "__main__":
    main()
