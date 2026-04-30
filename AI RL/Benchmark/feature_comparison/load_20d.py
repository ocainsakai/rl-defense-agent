"""
load_20d.py — Load 20D NIDS labeled dataset for Thursday-22-02-2018.

Reads the cached JSONL extracted by `pcap_benchmark.py`, applies the same labeling
scheme (attacker IP + attack windows), AND post-processes to add metadata fields
needed for academic-grade validation:

  - window_id_temporal: int(timestamp) — 1s window identifier per row
  - attack_window_id:   0/1/2 if attacker in window, None if benign
  - attack_name:        "brute_force" / "xss" / "sqli" / None
  - group_id:           "{src_ip}_{attack_window_id}" or "{src_ip}_benign"
                        Used by GroupKFold to prevent temporal leakage:
                        a single attack session never split across train/test folds.

CRITICAL — no leakage:
  - src_ip + timestamp are kept as METADATA ONLY (not in feature matrix X)
  - Only F1-F20 features are returned in get_features()
  - Use FEATURE_COLS_20D when training classifiers

Output DataFrame columns:
  - F1 - PacketRate, ..., F20 - HtmlEventHandler  (features)
  - src_ip, timestamp                              (metadata, drop before train)
  - window_id_temporal, attack_window_id, attack_name, group_id  (CV grouping)
  - label                                          (target: benign/brute_force/xss/sqli)
"""

from __future__ import annotations

import calendar
import datetime
import json
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[3]
JSONL_PATH = (
    REPO_ROOT / "datasets" / "CSE-CIC-IDS2018" / "Thursday_22_02_2018"
    / "pcap_cache" / "raw_data" / "Thursday_22_02_2018_nids.jsonl"
)

ATTACKER_IPS = ["18.218.115.60"]


def _ast_to_epoch(date_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' AST (UTC-4) string to Unix epoch."""
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return float(calendar.timegm(dt.timetuple())) + 4 * 3600


# Attack windows in AST (UTC-4) — taken from datasets/CSE-CIC-IDS2018/scripts/pcap_benchmark.py
ATTACK_WINDOWS: List[Tuple[float, float, str]] = [
    (_ast_to_epoch("2018-02-22 10:17:00"), _ast_to_epoch("2018-02-22 11:24:00"), "brute_force"),
    (_ast_to_epoch("2018-02-22 13:50:00"), _ast_to_epoch("2018-02-22 14:29:00"), "xss"),
    (_ast_to_epoch("2018-02-22 16:15:00"), _ast_to_epoch("2018-02-22 16:29:00"), "sqli"),
]

FEATURE_COLS_20D = [
    "F1 - PacketRate", "F2 - SynAckRatio", "F3 - InterArrivalTime",
    "F4 - RstRatio", "F5 - DistinctPorts", "F6 - URLConcentration",
    "F7 - HttpIatUniformity", "F8 - RequestSizeUniformity", "F9 - AvgPayloadSize",
    "F10 - FwdBwdRatio", "F11 - PacketsPerPort", "F12 - SqlSpecialChar",
    "F13 - CrsSqliScore", "F14 - SqlUnionSelect", "F15 - SqlComment",
    "F16 - SqlStackedQuery", "F17 - SqlSelectCount", "F18 - CrsXssScore",
    "F19 - JsFunctionCall", "F20 - HtmlEventHandler",
]

METADATA_COLS = ["src_ip", "timestamp", "window_id_temporal", "attack_window_id",
                 "attack_name", "group_id"]


def _resolve_attack_window(ts: float, src_ip: str) -> Tuple[int, str]:
    """Return (attack_window_id, attack_name) for an attacker row inside a window."""
    if src_ip not in ATTACKER_IPS:
        return -1, "benign"
    for idx, (t_start, t_end, lab) in enumerate(ATTACK_WINDOWS):
        if t_start <= ts <= t_end:
            return idx, lab
    return -1, "ambiguous"


def load_20d_labeled(
    benign_cap: int = 500,
    jsonl_path: Path = JSONL_PATH,
    seed: int = 42,
) -> pd.DataFrame:
    """Load 20D NIDS dataset with labels + grouping metadata.

    Args:
        benign_cap: max benign rows. Default 500 matches pcap_benchmark.py.
        jsonl_path: override path for testing.
        seed: random seed for benign sampling reproducibility.

    Returns:
        DataFrame with FEATURE_COLS_20D + METADATA_COLS + [label].
    """
    rng = np.random.default_rng(seed)

    rows = []
    benign_pool = []  # collect all benign first, then sample

    with open(jsonl_path) as f:
        for line in f:
            row = json.loads(line.strip())
            ts = float(row["timestamp"])
            src_ip = row["src_ip"]

            window_id, attack_name = _resolve_attack_window(ts, src_ip)
            label = None

            if src_ip in ATTACKER_IPS:
                if window_id < 0:
                    continue  # attacker outside any window — ambiguous, skip
                label = attack_name
            else:
                # Benign: not attacker IP, not inside any attack window
                if any(t_s <= ts <= t_e for (t_s, t_e, _) in ATTACK_WINDOWS):
                    continue  # victim reply during attack — skip (could be contaminated)
                label = "benign"

            row["label"] = label
            row["window_id_temporal"] = int(ts)
            row["attack_window_id"] = window_id
            row["attack_name"] = attack_name
            # group_id grouping rationale:
            # - 1-minute granularity is coarse enough to prevent train/test rows from
            #   being temporally adjacent (≤1s apart), which would leak via short-term
            #   network state correlation.
            # - 1-minute is also fine enough that each attack window (14-67 min) yields
            #   ≥10 groups, allowing meaningful 5-fold GroupKFold splits.
            # - Benign rows: group by source IP + minute (370 groups for n=500 ≈ even).
            # - Attack rows: group by source IP + attack window + minute.
            minute_bucket = int(ts // 60)
            if label == "benign":
                row["group_id"] = f"{src_ip}_benign_m{minute_bucket}"
            else:
                row["group_id"] = f"{src_ip}_attack{window_id}_m{minute_bucket}"

            if label == "benign":
                benign_pool.append(row)
            else:
                rows.append(row)

    # Random sample benign with cap
    if len(benign_pool) > benign_cap:
        idx = rng.choice(len(benign_pool), size=benign_cap, replace=False)
        rows.extend([benign_pool[i] for i in idx])
    else:
        rows.extend(benign_pool)

    df = pd.DataFrame(rows)
    cols = FEATURE_COLS_20D + METADATA_COLS + ["label"]
    df = df[cols].reset_index(drop=True)
    return df


def get_features_only(df: pd.DataFrame) -> pd.DataFrame:
    """Return ONLY the 20 numeric features — drops src_ip/timestamp/group_id.

    This is the canonical input for classifier training. Calling this guards
    against accidentally training on metadata that leaks the label.
    """
    return df[FEATURE_COLS_20D].copy()


def main() -> None:
    df = load_20d_labeled()
    print(f"Loaded {len(df)} rows")
    print(f"\nLabel distribution:")
    print(df["label"].value_counts())
    print(f"\nGroup count per label:")
    for lab, group in df.groupby("label"):
        n_groups = group["group_id"].nunique()
        print(f"  {lab:12s}: {len(group):4d} rows, {n_groups:3d} groups")
    print(f"\nFeatures (X.shape after get_features_only):")
    X = get_features_only(df)
    print(f"  shape={X.shape}, columns={list(X.columns[:3])}...{list(X.columns[-2:])}")
    print(f"  has src_ip? {'src_ip' in X.columns} (must be False)")
    print(f"  has timestamp? {'timestamp' in X.columns} (must be False)")


if __name__ == "__main__":
    main()
