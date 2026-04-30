"""
load_20d.py — Load 20D NIDS labeled dataset for Thursday-22-02-2018.

Reads the cached JSONL extracted by `pcap_benchmark.py`, applies the same labeling
scheme (attacker IP + attack windows), and returns a pandas DataFrame ready for
classifier training.

Output columns:
  - F1 - PacketRate, F2 - SynAckRatio, ..., F20 - HtmlEventHandler   (20 features)
  - src_ip, timestamp                                                 (metadata)
  - label                                                             (target: benign/brute_force/xss/sqli)
"""

from __future__ import annotations

import calendar
import datetime
import json
from pathlib import Path
from typing import List, Tuple

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


def load_20d_labeled(benign_cap: int = 500, jsonl_path: Path = JSONL_PATH) -> pd.DataFrame:
    """Load 20D NIDS dataset with labels.

    Args:
        benign_cap: maximum number of benign rows to keep (class balancing).
                    Default 500 matches pcap_benchmark.py.
        jsonl_path: override path for testing.

    Returns:
        DataFrame with FEATURE_COLS_20D + [src_ip, timestamp, label].
    """
    rows = []
    benign_count = 0

    with open(jsonl_path) as f:
        for line in f:
            row = json.loads(line.strip())
            ts = float(row["timestamp"])
            src_ip = row["src_ip"]
            label = None

            if src_ip in ATTACKER_IPS:
                for t_start, t_end, lab in ATTACK_WINDOWS:
                    if t_start <= ts <= t_end:
                        label = lab
                        break
                if label is None:
                    continue  # attacker outside window — ambiguous, skip
            else:
                in_window = any(t_s <= ts <= t_e for (t_s, t_e, _) in ATTACK_WINDOWS)
                if in_window:
                    continue  # victim reply during attack — skip
                if benign_count >= benign_cap:
                    continue
                label = "benign"
                benign_count += 1

            row["label"] = label
            rows.append(row)

    df = pd.DataFrame(rows)
    # Ensure column order
    cols = FEATURE_COLS_20D + ["src_ip", "timestamp", "label"]
    df = df[cols]
    return df


def main() -> None:
    df = load_20d_labeled()
    print(f"Loaded {len(df)} rows")
    print(f"\nLabel distribution:")
    print(df["label"].value_counts())
    print(f"\nFeature stats:")
    print(df[FEATURE_COLS_20D].describe().T[["mean", "std", "min", "max"]])


if __name__ == "__main__":
    main()
