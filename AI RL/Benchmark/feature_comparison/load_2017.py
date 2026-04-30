"""
load_2017.py — Load 20D NIDS labeled dataset for CIC-IDS2017 (3 days merged).

CIC-IDS2017 cung cấp **DIFFERENT attack types** so với 2018:
  - Thursday-06-07-2017: brute_force, xss, sqli, benign     (cùng 2018)
  - Friday-07-07-2017-PortScan: scan_fw_on, scan_fw_off, benign  (NEW)
  - Friday-07-07-2017-DDoS: syn_flood                       (NEW)

→ Tổng 7 attack classes (vs 4 ở 2018) — chứng minh 20D generalize được.

Mục đích trong validation:
  - Cross-dataset evidence — 20D works trên cả 2017 và 2018
  - Cover thêm 3 attack types: scan_fw_on, scan_fw_off, syn_flood
  - Test diverse attacker behaviors

Output: pandas DataFrame với 20 features + metadata + label.
"""

from __future__ import annotations

import calendar
import datetime
import json
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_2017_DIR = REPO_ROOT / "datasets" / "CIC-IDS2017"

# Attacker IP (NAT internal FW interface) — same across all 3 days
ATTACKER_IP_2017 = "172.16.0.1"


def _adt_to_epoch(date_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' ADT (UTC-3 Halifax summer) string to Unix epoch."""
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return float(calendar.timegm(dt.timetuple())) + 3 * 3600


# Attack metadata — taken from datasets/CIC-IDS2017/scripts/pcap_benchmark_ids2017.py
DAYS_2017: List[Dict] = [
    {
        "day": "Thursday-06-07-2017",
        "jsonl": (DATA_2017_DIR / "Thursday_06_07_2017"
                  / "pcap_cache" / "raw_data" / "Thursday_06_07_2017_nids.jsonl"),
        "windows": [
            (_adt_to_epoch("2017-07-06 09:20:00"), _adt_to_epoch("2017-07-06 10:00:00"), "brute_force"),
            (_adt_to_epoch("2017-07-06 10:15:00"), _adt_to_epoch("2017-07-06 10:35:00"), "xss"),
            (_adt_to_epoch("2017-07-06 10:40:00"), _adt_to_epoch("2017-07-06 10:42:00"), "sqli"),
        ],
        "benign_window": (_adt_to_epoch("2017-07-06 10:50:00"),
                          _adt_to_epoch("2017-07-06 11:15:00")),
    },
    {
        "day": "Friday-07-07-2017-PortScan",
        "jsonl": (DATA_2017_DIR / "Friday_07_07_2017_PortScan"
                  / "pcap_cache" / "raw_data" / "Friday_07_07_2017_PortScan_nids.jsonl"),
        "windows": [
            (_adt_to_epoch("2017-07-07 13:55:00"), _adt_to_epoch("2017-07-07 14:35:00"), "scan_fw_on"),
            (_adt_to_epoch("2017-07-07 14:51:00"), _adt_to_epoch("2017-07-07 15:29:00"), "scan_fw_off"),
        ],
        "benign_window": (_adt_to_epoch("2017-07-07 09:00:00"),
                          _adt_to_epoch("2017-07-07 09:15:00")),
    },
    {
        "day": "Friday-07-07-2017-DDoS",
        "jsonl": (DATA_2017_DIR / "Friday_07_07_2017_DDoS"
                  / "pcap_cache" / "raw_data" / "Friday_07_07_2017_DDoS_nids.jsonl"),
        "windows": [
            (_adt_to_epoch("2017-07-07 15:56:00"), _adt_to_epoch("2017-07-07 16:16:00"), "syn_flood"),
        ],
        "benign_window": None,  # No benign window for DDoS day (per pcap_benchmark_ids2017.py)
    },
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

METADATA_COLS = ["src_ip", "timestamp", "day", "window_id_temporal",
                 "attack_window_id", "attack_name", "group_id"]


def _label_row_2017(row: dict, day_cfg: dict, attacker_ip: str) -> Tuple[str | None, int, str]:
    """Determine label for one row given day config.

    Returns: (label, attack_window_id, attack_name)
        - (None, _, _) if row should be skipped (e.g., attacker outside window)
    """
    ts = float(row["timestamp"])
    src_ip = row["src_ip"]

    # Attacker rows: must be inside an attack window
    if src_ip == attacker_ip:
        for idx, (t_start, t_end, lab) in enumerate(day_cfg["windows"]):
            if t_start <= ts <= t_end:
                return lab, idx, lab
        return None, -1, "ambiguous"

    # Benign rows: not attacker IP, within explicit benign_window (if specified)
    bw = day_cfg.get("benign_window")
    if bw is not None:
        t_s, t_e = bw
        if t_s <= ts <= t_e:
            return "benign", -1, "benign"

    # Otherwise skip (could be victim reply during attack or outside benign window)
    return None, -1, "skip"


def load_2017_labeled(
    benign_cap_per_day: int = 300,
    seed: int = 42,
) -> pd.DataFrame:
    """Load all 3 days of CIC-IDS2017 labeled.

    Args:
        benign_cap_per_day: max benign rows per day (random sample).
                            Default 300 → tổng ~600 benign across days.
        seed: random seed.

    Returns:
        DataFrame with 20 features + metadata + label.
        Total: 7 classes — benign + brute_force + xss + sqli +
                            scan_fw_on + scan_fw_off + syn_flood
    """
    rng = np.random.default_rng(seed)
    all_rows: List[dict] = []

    for day_cfg in DAYS_2017:
        if not day_cfg["jsonl"].exists():
            print(f"  WARN: {day_cfg['jsonl']} not found, skipping day '{day_cfg['day']}'")
            continue

        rows = []
        benign_pool = []

        with open(day_cfg["jsonl"]) as f:
            for line in f:
                row = json.loads(line.strip())
                label, window_id, attack_name = _label_row_2017(row, day_cfg, ATTACKER_IP_2017)
                if label is None:
                    continue

                row["label"] = label
                row["day"] = day_cfg["day"]
                ts = float(row["timestamp"])
                row["window_id_temporal"] = int(ts)
                row["attack_window_id"] = window_id
                row["attack_name"] = attack_name

                # Group by (src_ip × attack_window × minute) for GroupKFold
                minute_bucket = int(ts // 60)
                src_ip = row["src_ip"]
                if label == "benign":
                    row["group_id"] = f"{src_ip}_benign_{day_cfg['day']}_m{minute_bucket}"
                else:
                    row["group_id"] = f"{src_ip}_{day_cfg['day']}_w{window_id}_m{minute_bucket}"

                if label == "benign":
                    benign_pool.append(row)
                else:
                    rows.append(row)

        # Cap benign per day
        if len(benign_pool) > benign_cap_per_day:
            idx = rng.choice(len(benign_pool), size=benign_cap_per_day, replace=False)
            rows.extend([benign_pool[i] for i in idx])
        else:
            rows.extend(benign_pool)

        print(f"  {day_cfg['day']:35s} → {len(rows):4d} rows ({len(benign_pool)} benign avail)")
        all_rows.extend(rows)

    df = pd.DataFrame(all_rows)
    cols = FEATURE_COLS_20D + METADATA_COLS + ["label"]
    df = df[cols].reset_index(drop=True)
    return df


def get_features_only(df: pd.DataFrame) -> pd.DataFrame:
    """Return only 20 numeric features (drops metadata)."""
    return df[FEATURE_COLS_20D].copy()


def main() -> None:
    print("Loading CIC-IDS2017 (3 days) ...\n")
    df = load_2017_labeled()
    print(f"\nTotal rows: {len(df)}")
    print(f"\nLabel distribution:")
    print(df["label"].value_counts())
    print(f"\nGroup count per label:")
    for lab, group in df.groupby("label"):
        n_groups = group["group_id"].nunique()
        n_ips = group["src_ip"].nunique()
        print(f"  {lab:14s}: {len(group):5d} rows, {n_ips:4d} unique IPs, {n_groups:4d} groups")
    print(f"\nFeature matrix shape: {get_features_only(df).shape}")


if __name__ == "__main__":
    main()
