"""
cicids_to_eval.py
Chuyển CICIDS2017 CSV → eval_data.jsonl (20D format) cho cả RL lẫn ML.

Đọc thẳng từ dataset/archive.zip — không cần unzip trước.

Mapping CICIDS2017 → F1-F20:
  F1  PacketRate       ← Flow Packets/s
  F2  SynAckRatio      ← SYN Flag Count / ACK Flag Count
  F3  InterArrivalTime ← Flow IAT Mean (μs → seconds)
  F4  RstRatio         ← RST Flag Count / total packets
  F5  DistinctPorts    ← 0  (không có trong CICIDS2017)
  F6  URLConcentration ← 0  (không có trong CICIDS2017)
  F7  HttpIatUniformity       ← 1 / (1 + Flow_IAT_Std / Flow_IAT_Mean)
  F8  RequestSizeUniformity   ← 1 / (1 + Pkt_Len_Std / Pkt_Len_Mean)
  F9  AvgPayloadSize   ← Average Packet Size
  F10 FwdBwdRatio      ← Total Fwd Packets / Total Bwd Packets
  F11 PacketsPerPort   ← Total Packets (proxy — 1 port per CICIDS2017 flow)
  F12-F20              ← 0  (SQLi/XSS payload — không có trong CICIDS2017)

Limitation (cần nêu khi bảo vệ):
  CICIDS2017 là flow-level dataset, không có application-layer payload.
  F5, F6, F12-F20 = 0 → RL/RF không phát hiện SQLi/XSS từ CICIDS2017.
  Phù hợp để so sánh trên network-level attacks (DDoS, PortScan, BruteForce).

Usage:
    cd /home/tringuyen/AIAGENT/rl-defense-agent
    python3 ml_baseline/cicids_to_eval.py
    python3 ml_baseline/cicids_to_eval.py --n_per_class 2000 --out ml_baseline/data/eval_data.jsonl
"""

import argparse
import io
import json
import math
import os
import sys
import zipfile

import numpy as np
import pandas as pd

# Thêm path để dùng normalize từ data_params.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'System'))
from config.data_params import (
    FEATURE_CLIP_BOUNDS, FEATURE_LOG_SCALE, FEATURE_ORDER, normalize_feature_vector
)

# -------------------------------------------------------
# CONFIG
# -------------------------------------------------------
ZIP_PATH = "dataset/archive.zip"
RANDOM_SEED = 42

# Files trong zip và label mapping
# Chọn 3 file đại diện đủ 3 class
FILES_TO_USE = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",           # BENIGN + DDoS
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",       # BENIGN + PortScan
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",     # BENIGN + Web Attacks
]

# CICIDS2017 Label → 3-class
CICIDS_LABEL_MAP = {
    'BENIGN'      : 'benign',
    'DDoS'        : 'attack',
    'DoS Hulk'    : 'attack',
    'DoS GoldenEye' : 'attack',
    'DoS Slowloris' : 'attack',
    'DoS Slowhttptest' : 'attack',
    'PortScan'    : 'attack',
    'FTP-Patator' : 'suspicious',
    'SSH-Patator' : 'suspicious',
    'Bot'         : 'suspicious',
    'Infiltration': 'suspicious',
    'Heartbleed'  : 'suspicious',
}

def normalize_cicids_label(raw: str) -> str:
    """Robust label matching — xử lý encoding variants (–, \x96, \ufffd)."""
    s = raw.strip().upper()
    if s == 'BENIGN':
        return 'benign'
    if 'DDOS' in s or s.startswith('DOS '):
        return 'attack'
    if 'PORTSCAN' in s:
        return 'attack'
    if 'PATATOR' in s or 'BRUTE' in s:
        return 'suspicious'
    if 'XSS' in s or 'SQL' in s or 'WEB ATTACK' in s:
        return 'suspicious'
    if s in ('BOT', 'INFILTRATION', 'HEARTBLEED'):
        return 'suspicious'
    return CICIDS_LABEL_MAP.get(raw.strip())

# 3-class → expected_action (theo thiết kế RL)
LABEL_TO_ACTION = {
    'benign'    : 'Allow',
    'attack'    : 'Block',
    'suspicious': 'Redirect',
}


# -------------------------------------------------------
# FEATURE MAPPING
# -------------------------------------------------------
def safe_float(val, default=0.0):
    try:
        v = float(val)
        return v if math.isfinite(v) else default
    except Exception:
        return default


def cicids_row_to_raw_20d(row) -> list:
    """
    Chuyển 1 row CICIDS2017 → vector 20D raw (chưa normalize).

    Chỉ map các features có semantic tương đồng tốt với RL env:
      F2  SynAckRatio      ← SYN / ACK  (log scale, cap=100)
      F4  RstRatio         ← RST / total packets  (pass-through [0,1])
      F7  HttpIatUniformity       ← 1/(1+CV_IAT)  (pass-through [0,1])
      F8  RequestSizeUniformity   ← 1/(1+CV_pkt_len)  (pass-through [0,1])
      F9  AvgPayloadSize   ← Average Packet Size  (linear, cap=1500)
      F10 FwdBwdRatio      ← Fwd/Bwd packets  (log scale, cap=100)

    Set = 0 (không dùng):
      F1  PacketRate       ← Flow Packets/s incompatible (flow-level vs window-level)
      F3  InterArrivalTime ← semantic khác nhau
      F5  DistinctPorts    ← không có trong CICIDS2017
      F6  URLConcentration ← không có trong CICIDS2017
      F11 PacketsPerPort   ← không có trong CICIDS2017
      F12-F20 SQLi/XSS    ← không có trong CICIDS2017
    """
    total_pkts = max(1.0,
        safe_float(row.get('Total Fwd Packets', 0)) +
        safe_float(row.get('Total Backward Packets', 0))
    )

    # F1: 0 — Flow Packets/s incompatible (flow-level vs 1s window)
    f1 = 0.0

    # F2: SynAckRatio = SYN / max(1, ACK)
    syn = safe_float(row.get('SYN Flag Count', 0))
    ack = max(1.0, safe_float(row.get('ACK Flag Count', 1)))
    f2  = syn / ack

    # F3: 0 — IAT semantic khác (flow duration vs window)
    f3 = 0.0

    # F4: RstRatio = RST / total_pkts ∈ [0,1]
    rst = safe_float(row.get('RST Flag Count', 0))
    f4  = min(1.0, rst / total_pkts)

    # F5: 0 — DistinctPorts không có
    f5 = 0.0

    # F6: 0 — URLConcentration không có
    f6 = 0.0

    # F7: HttpIatUniformity = 1/(1+CV_IAT)
    iat_mean = max(1e-6, abs(safe_float(row.get('Flow IAT Mean', 1))))
    iat_std  = safe_float(row.get('Flow IAT Std', 0))
    f7 = 1.0 / (1.0 + iat_std / iat_mean)

    # F8: RequestSizeUniformity = 1/(1+CV_pkt_len)
    pkt_mean = max(1e-6, safe_float(row.get('Packet Length Mean', 1)))
    pkt_std  = safe_float(row.get('Packet Length Std', 0))
    f8 = 1.0 / (1.0 + pkt_std / pkt_mean)

    # F9: AvgPayloadSize (bytes)
    f9 = safe_float(row.get('Average Packet Size', 0))

    # F10: FwdBwdRatio = Fwd / max(1, Bwd)
    fwd = safe_float(row.get('Total Fwd Packets', 0))
    bwd = max(1.0, safe_float(row.get('Total Backward Packets', 1)))
    f10 = fwd / bwd

    # F11: 0 — PacketsPerPort không có
    f11 = 0.0

    # F12-F20: 0 — SQLi/XSS không có trong CICIDS2017
    f12_f20 = [0.0] * 9

    return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11] + f12_f20


# -------------------------------------------------------
# LOAD & PROCESS
# -------------------------------------------------------
def load_csv_from_zip(zip_path: str, filename: str) -> pd.DataFrame:
    """Đọc CSV từ trong file zip mà không cần unzip."""
    print(f"  Reading {filename} ...", end=' ', flush=True)
    with zipfile.ZipFile(zip_path) as zf:
        with zf.open(filename) as f:
            df = pd.read_csv(io.TextIOWrapper(f, encoding='utf-8', errors='replace'))
    df.columns = df.columns.str.strip()
    print(f"{len(df):,} rows")
    return df


def process_dataframe(df: pd.DataFrame) -> list:
    """Chuyển DataFrame → list of records."""
    records = []
    skipped = 0

    for _, row in df.iterrows():
        raw_label = str(row.get('Label', '')).strip()
        label_3class = normalize_cicids_label(raw_label)
        if label_3class is None:
            skipped += 1
            continue

        try:
            raw_20d = cicids_row_to_raw_20d(row)
            # Thay inf/nan bằng 0 trước khi normalize
            raw_20d = [0.0 if (not math.isfinite(v) or v < 0) else v
                       for v in raw_20d]
            obs = normalize_feature_vector(raw_20d)
        except Exception:
            skipped += 1
            continue

        # Sanity check
        if any(not math.isfinite(v) for v in obs):
            skipped += 1
            continue

        records.append({
            'obs'            : [round(v, 6) for v in obs],
            'label_3class'   : label_3class,
            'expected_action': LABEL_TO_ACTION[label_3class],
            'cicids_label'   : raw_label,
        })

    if skipped:
        print(f"    Skipped {skipped:,} invalid rows")

    return records


# -------------------------------------------------------
# MAIN
# -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zip',         default=ZIP_PATH)
    parser.add_argument('--n_per_class', type=int, default=2000,
                        help='Số samples mỗi class (balanced dataset)')
    parser.add_argument('--out',         default='ml_baseline/data/eval_data_cicids.jsonl')
    args = parser.parse_args()

    if not os.path.exists(args.zip):
        print(f"[ERROR] Không tìm thấy: {args.zip}")
        sys.exit(1)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rng = np.random.default_rng(RANDOM_SEED)

    # --- Load và process từng file ---
    all_records = {'benign': [], 'attack': [], 'suspicious': []}

    print(f"[*] Loading CICIDS2017 from {args.zip}")
    for fname in FILES_TO_USE:
        try:
            df = load_csv_from_zip(args.zip, fname)
            records = process_dataframe(df)
            for r in records:
                all_records[r['label_3class']].append(r)
            from collections import Counter
            dist = Counter(r['label_3class'] for r in records)
            print(f"    → {dict(dist)}")
        except Exception as e:
            print(f"    [WARN] Lỗi khi đọc {fname}: {e}")
            continue

    # --- Balanced sampling ---
    print(f"\n[*] Balancing dataset ({args.n_per_class} samples/class)...")
    final_records = []
    for cls, recs in all_records.items():
        n = min(args.n_per_class, len(recs))
        if n == 0:
            print(f"  [WARN] Không có records cho class: {cls}")
            continue
        idx = rng.choice(len(recs), size=n, replace=False)
        sampled = [recs[i] for i in idx]
        # Thêm episode/ip_idx để tương thích với train_model.py split
        for i, r in enumerate(sampled):
            r['episode'] = i  # dùng để split train/test
        final_records.extend(sampled)
        print(f"  {cls:<12}: {n:,} samples")

    # Shuffle
    idx_all = rng.permutation(len(final_records))
    final_records = [final_records[i] for i in idx_all]
    # Re-assign episode sau shuffle để split đúng
    for i, r in enumerate(final_records):
        r['episode'] = i

    # --- Stats ---
    from collections import Counter
    print(f"\n[*] Final dataset: {len(final_records):,} records")
    print(f"    Label dist  : {dict(Counter(r['label_3class'] for r in final_records))}")
    print(f"    Action dist : {dict(Counter(r['expected_action'] for r in final_records))}")
    print(f"    Obs dim     : {len(final_records[0]['obs'])}D")

    # --- Sample obs để verify ---
    print(f"\n[*] Sample obs per class:")
    shown = set()
    for r in final_records:
        cls = r['label_3class']
        if cls not in shown:
            obs_preview = [round(v, 3) for v in r['obs'][:11]]
            sqli_preview = [round(v, 3) for v in r['obs'][11:]]
            print(f"  {cls:<12} ({r['cicids_label']:<35})")
            print(f"    F1-F11 : {obs_preview}")
            print(f"    F12-F20: {sqli_preview}")
            shown.add(cls)

    # --- Save ---
    with open(args.out, 'w') as f:
        for r in final_records:
            f.write(json.dumps(r) + '\n')

    print(f"\n[OK] Saved: {args.out}")
    print(f"\nBước tiếp theo:")
    print(f"  python3 ml_baseline/train_model.py --data {args.out}")


if __name__ == '__main__':
    main()
