"""
spot_verification.py — Print 5 raw rows per class với F-values để hội đồng inspect.

Mục tiêu: cho hội đồng đọc trực tiếp giá trị F1-F20 trên các sample rows,
verify tính hợp lý theo design.

Output:
  - results/spot_verification.txt — formatted text report
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from load_20d import FEATURE_COLS_20D, load_20d_labeled
from load_2017 import load_2017_labeled

RESULTS_DIR = Path(__file__).parent / "results"
OUTPUT_FILE = RESULTS_DIR / "spot_verification.txt"

FEATURE_INTERPRETATIONS = {
    "F1 - PacketRate": ("pkts/s", "high → DDoS/scan; low → normal"),
    "F2 - SynAckRatio": ("ratio", "high → SYN flood; ~0 → normal"),
    "F3 - InterArrivalTime": ("s", "low → bot/automated; high → human"),
    "F4 - RstRatio": ("[0,1]", ">0.3 → port scan; ~0 → L7 attack/normal"),
    "F5 - DistinctPorts": ("count", ">50 → port scan"),
    "F6 - URLConcentration": ("[0,1]", ">0.9 → brute force on 1 URL"),
    "F7 - HttpIatUniformity": ("(0,1]", "~1 → bot timing"),
    "F8 - RequestSizeUniformity": ("(0,1]", "~1 → bot payload"),
    "F9 - AvgPayloadSize": ("bytes", "varies"),
    "F10 - FwdBwdRatio": ("ratio", "high → unidirectional flood"),
    "F11 - PacketsPerPort": ("ratio", ""),
    "F12 - SqlSpecialChar": ("[0,1]", ">0.15 → SQLi"),
    "F13 - CrsSqliScore": ("count", ">3 → SQLi (CRS-942 PL2)"),
    "F14 - SqlUnionSelect": ("{0,1}", "1 → UNION SELECT detected"),
    "F15 - SqlComment": ("{0,1}", "1 → SQL comment detected"),
    "F16 - SqlStackedQuery": ("{0,1}", "1 → ; DROP/DELETE detected"),
    "F17 - SqlSelectCount": ("count", ">1 → multiple SELECTs"),
    "F18 - CrsXssScore": ("count", ">3 → XSS (CRS-941 PL2)"),
    "F19 - JsFunctionCall": ("{0,1}", "1 → alert()/eval() detected"),
    "F20 - HtmlEventHandler": ("{0,1}", "1 → onerror=/onload= detected"),
}


def format_row(row: pd.Series, idx: int) -> str:
    """Format 1 row với raw F values + interpretation."""
    lines = []
    lines.append(f"  Row #{idx}: src_ip={row['src_ip']}  ts={row.get('timestamp', '?'):.2f}  "
                  f"day={row.get('day', '2018')}")
    for feat in FEATURE_COLS_20D:
        unit, hint = FEATURE_INTERPRETATIONS.get(feat, ("", ""))
        val = row[feat]
        flag = ""
        # Highlight notable values
        if "F13" in feat and val > 1:
            flag = " ★ SQLi signal"
        elif "F18" in feat and val > 1:
            flag = " ★ XSS signal"
        elif "F4" in feat and val > 0.3:
            flag = " ★ port scan signal"
        elif "F5" in feat and val > 50:
            flag = " ★ port scan signal"
        elif "F19" in feat and val > 0:
            flag = " ★ JS function call"
        elif "F20" in feat and val > 0:
            flag = " ★ event handler"
        lines.append(f"    {feat:<28} = {val:>10.4f} {unit:<8} {hint}{flag}")
    return "\n".join(lines)


def sample_rows_per_class(df: pd.DataFrame, n_per_class: int = 5,
                           seed: int = 42) -> pd.DataFrame:
    """Sample n rows per class."""
    rng = np.random.default_rng(seed)
    sampled = []
    for label, group in df.groupby("label"):
        n = min(n_per_class, len(group))
        idx = rng.choice(len(group), size=n, replace=False)
        sampled.append(group.iloc[idx])
    return pd.concat(sampled).reset_index(drop=True)


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading datasets ...")
    df_2018 = load_20d_labeled(benign_cap=500)
    df_2017 = load_2017_labeled()

    out_lines = []
    out_lines.append("=" * 80)
    out_lines.append("SPOT VERIFICATION — Raw F1-F20 values per class")
    out_lines.append("=" * 80)
    out_lines.append("")
    out_lines.append("Mục đích: hội đồng đọc trực tiếp giá trị features trên sample rows,")
    out_lines.append("verify rằng F-values khớp với design intent.")
    out_lines.append("")

    for tag, df in [("CSE-CIC-IDS2018 (Thursday-22-02-2018)", df_2018),
                     ("CIC-IDS2017 (3 days)", df_2017)]:
        out_lines.append("=" * 80)
        out_lines.append(f"DATASET: {tag}")
        out_lines.append("=" * 80)

        sampled = sample_rows_per_class(df, n_per_class=5, seed=42)
        for label, group in sampled.groupby("label"):
            out_lines.append("")
            out_lines.append(f"--- Class: {label.upper()}  (sampled 5 rows from {len(df[df['label']==label])} total) ---")
            for i, (_, row) in enumerate(group.iterrows(), start=1):
                out_lines.append("")
                out_lines.append(format_row(row, i))
            out_lines.append("")

    text = "\n".join(out_lines)
    with open(OUTPUT_FILE, "w") as f:
        f.write(text)
    print(f"\nSaved: {OUTPUT_FILE.name}")
    print(f"Total lines: {len(out_lines)}")
    print("\nFirst 100 lines preview:")
    print("\n".join(out_lines[:100]))


if __name__ == "__main__":
    main()
