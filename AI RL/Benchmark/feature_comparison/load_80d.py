"""
load_80d.py — Load 80D CICFlowMeter labeled dataset for Thursday-22-02-2018.

The CSV is the official "TrafficForML" CICFlowMeter export — IP fields stripped,
but Label column retained. We map official labels to the same 4-class taxonomy
used by the 20D NIDS dataset:

  CICFlowMeter Label    →  unified label
  --------------------     --------------
  Benign                →  benign
  Brute Force -Web      →  brute_force
  Brute Force -XSS      →  xss
  SQL Injection         →  sqli

Functions:
  - load_80d_labeled():       full load with benign cap
  - get_class_distribution(): inspect class counts
  - subsample_20d_to_match_80d(): downsample 20D class-by-class to match 80D
                                  (Protocol B in validate_20d.py — fair apples-to-apples)
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[3]
CSV_PATH = (
    REPO_ROOT / "datasets" / "CSE-CIC-IDS2018" / "processed"
    / "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"
)

LABEL_MAP = {
    "Benign": "benign",
    "Brute Force -Web": "brute_force",
    "Brute Force -XSS": "xss",
    "SQL Injection": "sqli",
}

DROP_COLS = ["Timestamp"]


def load_80d_labeled(
    benign_cap: int = 500,
    csv_path: Path = CSV_PATH,
    seed: int = 42,
) -> pd.DataFrame:
    """Load 80D CICFlowMeter dataset with labels.

    Args:
        benign_cap: max benign rows (random sample). Default 500 matches 20D.
        csv_path: override path for testing.
        seed: random seed for benign sampling.

    Returns:
        DataFrame with 78 numeric features + label column.
    """
    print(f"Reading {csv_path.name} ({csv_path.stat().st_size / 1e6:.1f} MB) ...")

    chunks = pd.read_csv(csv_path, chunksize=100_000, low_memory=False)
    attack_dfs: List[pd.DataFrame] = []
    benign_dfs: List[pd.DataFrame] = []
    benign_collected = 0

    for chunk in chunks:
        chunk["label"] = chunk["Label"].map(LABEL_MAP)

        attack = chunk[chunk["label"].isin(["brute_force", "xss", "sqli"])]
        if len(attack) > 0:
            attack_dfs.append(attack)

        if benign_collected < benign_cap:
            benign = chunk[chunk["label"] == "benign"]
            need = benign_cap - benign_collected
            if len(benign) > need:
                benign = benign.sample(n=need, random_state=seed)
            benign_collected += len(benign)
            if len(benign) > 0:
                benign_dfs.append(benign)

    df = pd.concat(attack_dfs + benign_dfs, ignore_index=True)

    feature_cols = [c for c in df.columns
                    if c not in DROP_COLS + ["Label", "label"]]

    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    n_before = len(df)
    df = df.dropna(subset=feature_cols).reset_index(drop=True)
    n_dropped = n_before - len(df)
    if n_dropped > 0:
        print(f"  Dropped {n_dropped} rows with inf/NaN values ({n_dropped/n_before*100:.2f}%)")

    df = df[feature_cols + ["label"]]
    return df


def get_class_distribution(df: pd.DataFrame) -> Dict[str, int]:
    """Return dict {label: count} sorted alphabetically."""
    return dict(sorted(df["label"].value_counts().to_dict().items()))


def subsample_20d_to_match_80d(
    df_20d: pd.DataFrame,
    df_80d: pd.DataFrame,
    seed: int = 42,
) -> pd.DataFrame:
    """Downsample 20D dataset class-by-class so it matches 80D distribution.

    This implements **Protocol B** from validate_20d.py:
    - 20D rows are bigger (windowed, sustained attack) than 80D (per-flow)
    - Direct F1 comparison is unfair due to sample size + class skew
    - Sampling 20D to match 80D class counts → apples-to-apples comparison

    Note: rows are random-sampled WITHIN each class (preserves group_id, metadata).

    Args:
        df_20d: full 20D DataFrame from load_20d_labeled()
        df_80d: 80D DataFrame from load_80d_labeled()
        seed: random seed for reproducibility

    Returns:
        Subsampled 20D DataFrame with len() ≈ len(df_80d).
    """
    rng = np.random.default_rng(seed)
    target_dist = get_class_distribution(df_80d)

    sampled_chunks = []
    for label, target_n in target_dist.items():
        class_df = df_20d[df_20d["label"] == label]
        if len(class_df) == 0:
            print(f"  WARN: class '{label}' missing in 20D — skipping")
            continue
        if len(class_df) <= target_n:
            sampled_chunks.append(class_df)
        else:
            idx = rng.choice(len(class_df), size=target_n, replace=False)
            sampled_chunks.append(class_df.iloc[idx])

    out = pd.concat(sampled_chunks, ignore_index=True)
    return out


def main() -> None:
    df = load_80d_labeled()
    print(f"\nLoaded {len(df)} rows")
    print(f"\nLabel distribution:")
    print(df["label"].value_counts())
    print(f"\nNumber of features: {len(df.columns) - 1}")

    # Demo subsample
    from load_20d import load_20d_labeled
    df_20 = load_20d_labeled()
    df_20_matched = subsample_20d_to_match_80d(df_20, df)

    print(f"\n--- Subsample demo ---")
    print(f"20D full:    {get_class_distribution(df_20)}")
    print(f"80D:         {get_class_distribution(df)}")
    print(f"20D matched: {get_class_distribution(df_20_matched)}")


if __name__ == "__main__":
    main()
