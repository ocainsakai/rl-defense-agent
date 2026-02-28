#!/usr/bin/env python3
"""Extract NIDS features from dissected CSV and output JSON.

Reads Wireshark-dissected CSV, computes 20 features per (src_ip, time_window),
outputs a JSON array with: time, srcip, and 20 feature values.

Usage:
    python tools/test_features_to_json.py -i dataset/SYN-Flood.csv -o output.json
    python tools/test_features_to_json.py -i dataset/normal.csv -o output.json -w 2.0
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
_SYSTEM_DIR = _SCRIPT_DIR.parent
if str(_SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(_SYSTEM_DIR))
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from test_features_from_csv import _row_to_layer_info
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator


def _compute_time_base(row: dict) -> Optional[float]:
    """Tính epoch offset từ row CSV có Frame Time (Epoch) là integer và Time là relative.

    Returns:
        float: epoch_of_capture_start = Frame_Time_Epoch - Time
        None: nếu không đủ dữ liệu hoặc Frame Time (Epoch) đã là float (có dấu .)
    """
    epoch_raw = (row.get("Frame Time (Epoch)") or "").strip()
    time_raw = (row.get("Time") or "").strip()
    if not epoch_raw or not time_raw:
        return None
    if "." in epoch_raw:
        # Epoch đã là float — dùng trực tiếp, không cần offset
        return None
    try:
        return float(int(epoch_raw)) - float(time_raw)
    except (ValueError, TypeError):
        return None


def _format_timestamp(absolute_epoch: float) -> str:
    """Format epoch → ISO 8601 string: 'YYYY-MM-DDTHH:MM:SS.ffffff'"""
    return datetime.fromtimestamp(absolute_epoch).strftime("%Y-%m-%dT%H:%M:%S.%f")


def extract_features_to_json(
    csv_path: Path,
    output_path: Path,
    window_size: float,
    precision: int = 4,
) -> List[dict]:
    """Read CSV, compute features per (src_ip, window), write JSON.

    Args:
        csv_path: Input Wireshark-dissected CSV.
        output_path: Output JSON file path.
        window_size: Sliding window duration in seconds.
        precision: Decimal places for feature values.

    Returns:
        List of dicts (the JSON records).
    """
    time_base: Optional[float] = None  # epoch_of_capture_start = Frame_Epoch - Time

    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        packets = []
        for row in reader:
            if time_base is None:
                time_base = _compute_time_base(row)
            li = _row_to_layer_info(row)
            if li is not None:
                packets.append(li)

    if not packets:
        raise ValueError("No valid packet rows parsed from CSV.")

    packets.sort(key=lambda x: x.timestamp)

    calc = FlowFeatureCalculator()
    feature_names = calc.get_feature_names()
    records = []

    idx = 0
    n = len(packets)
    window_start = packets[0].timestamp
    window_end = window_start + window_size

    while idx < n:
        fm = FlowManager(
            window_size=window_size,
            flow_timeout=max(window_size * 2, 1.0),
            cleanup_interval=100000,
        )
        while idx < n and packets[idx].timestamp < window_end:
            fm.process_packet(packets[idx])
            idx += 1

        for src_ip in fm.get_all_src_ips():
            flows = fm.get_flows_by_src(src_ip)
            if not flows:
                continue
            for flow in flows:
                flow.analysis_window_size = window_size
            values = calc.calculate_all_optimized(flows)

            if time_base is not None:
                time_val = _format_timestamp(time_base + window_start)
            else:
                time_val = round(window_start, precision)
            record = {
                "time": time_val,
                "srcip": src_ip,
            }
            for i, name in enumerate(feature_names):
                record[name] = round(float(values[i]), precision)
            records.append(record)

        window_start = window_end
        window_end = window_start + window_size

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    return records


def main():
    parser = argparse.ArgumentParser(
        description="Extract NIDS features from dissected CSV → JSON"
    )
    parser.add_argument("-i", "--input", required=True,
                        help="Input dissected CSV path")
    parser.add_argument("-o", "--output", default="dataset/output/features.json",
                        help="Output JSON path (default: dataset/output/features.json)")
    parser.add_argument("-w", "--window", type=float, default=1.0,
                        help="Window size in seconds (default: 1.0)")
    parser.add_argument("--precision", type=int, default=4,
                        help="Decimal places for numeric output (default: 4)")
    args = parser.parse_args()

    if args.window <= 0:
        raise ValueError("window must be > 0")
    if args.precision < 0:
        raise ValueError("precision must be >= 0")

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    output_path = Path(args.output)
    records = extract_features_to_json(
        csv_path=input_path,
        output_path=output_path,
        window_size=args.window,
        precision=args.precision,
    )
    print(f"[OK] {len(records)} records exported: {output_path}")


if __name__ == "__main__":
    main()
