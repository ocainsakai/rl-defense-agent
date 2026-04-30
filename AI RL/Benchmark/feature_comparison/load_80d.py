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

Output columns:
  - 76 numeric CICFlowMeter features (Dst Port, Protocol numeric; Timestamp dropped)
  - label
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[3]
CSV_PATH = (
    REPO_ROOT / "datasets" / "CSE-CIC-IDS2018" / "processed"
    / "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv"
)

# Map official CICFlowMeter Label values to unified 4-class scheme
LABEL_MAP = {
    "Benign": "benign",
    "Brute Force -Web": "brute_force",
    "Brute Force -XSS": "xss",
    "SQL Injection": "sqli",
}

# Drop Timestamp — string format, not numeric. Keep all other 79 columns + label.
DROP_COLS = ["Timestamp"]


def load_80d_labeled(
    benign_cap: int = 500,
    csv_path: Path = CSV_PATH,
    seed: int = 42,
) -> pd.DataFrame:
    """Load 80D CICFlowMeter dataset with labels.

    Args:
        benign_cap: max benign rows (random sample). Default 500 matches load_20d.py.
        csv_path: override path for testing.
        seed: random seed for benign sampling reproducibility.

    Returns:
        DataFrame with 76 numeric features + label column.
    """
    print(f"Reading {csv_path.name} ({csv_path.stat().st_size / 1e6:.1f} MB) ...")

    # Read in chunks to manage memory; only keep relevant rows
    chunks = pd.read_csv(csv_path, chunksize=100_000, low_memory=False)
    attack_dfs: List[pd.DataFrame] = []
    benign_dfs: List[pd.DataFrame] = []
    benign_collected = 0

    for chunk in chunks:
        # Map Label
        chunk["label"] = chunk["Label"].map(LABEL_MAP)

        # Keep all attack rows
        attack = chunk[chunk["label"].isin(["brute_force", "xss", "sqli"])]
        if len(attack) > 0:
            attack_dfs.append(attack)

        # Sample benign with cap
        if benign_collected < benign_cap:
            benign = chunk[chunk["label"] == "benign"]
            need = benign_cap - benign_collected
            if len(benign) > need:
                benign = benign.sample(n=need, random_state=seed)
            benign_collected += len(benign)
            if len(benign) > 0:
                benign_dfs.append(benign)

    df = pd.concat(attack_dfs + benign_dfs, ignore_index=True)

    # Drop non-feature columns
    feature_cols = [c for c in df.columns
                    if c not in DROP_COLS + ["Label", "label"]]

    # Coerce all features to numeric (CICFlowMeter sometimes has non-numeric placeholders)
    for c in feature_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    # Replace inf with NaN (CICFlowMeter has +/-inf in rate columns when duration=0)
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    # Drop rows with any NaN in features (CICFlowMeter quirk: small fraction of bad rows)
    n_before = len(df)
    df = df.dropna(subset=feature_cols).reset_index(drop=True)
    n_dropped = n_before - len(df)
    if n_dropped > 0:
        print(f"  Dropped {n_dropped} rows with inf/NaN values ({n_dropped/n_before*100:.2f}%)")

    df = df[feature_cols + ["label"]]
    return df


def main() -> None:
    df = load_80d_labeled()
    print(f"\nLoaded {len(df)} rows")
    print(f"\nLabel distribution:")
    print(df["label"].value_counts())
    print(f"\nNumber of features: {len(df.columns) - 1}")
    print(f"\nFirst 5 feature columns: {list(df.columns[:5])}")
    print(f"Last 5 feature columns: {list(df.columns[-6:-1])}")


if __name__ == "__main__":
    main()
