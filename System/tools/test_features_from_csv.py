#!/usr/bin/env python3
"""Extract NIDS features from dissected CSV (Wireshark-style) for RL/PPO training.

Use this when you have packet-level CSV (not PCAP) and want feature vectors by
source IP and time window.
"""

import argparse
import csv
import sys
from pathlib import Path
from typing import Dict, List, Optional

_SCRIPT_DIR = Path(__file__).resolve().parent
_SYSTEM_DIR = _SCRIPT_DIR.parent
if str(_SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(_SYSTEM_DIR))

from core.layer_info import LayerInfo
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator


PROTO_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
}


def _clean_ip(value: Optional[str]) -> str:
    if value is None:
        return ""
    text = str(value).strip().strip('"').strip("'")
    if not text:
        return ""
    if "," in text:
        text = text.split(",", 1)[0].strip()
    return text


def _to_int(value: Optional[str], default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except Exception:
        return default


def _to_float(value: Optional[str], default: Optional[float] = None) -> Optional[float]:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    try:
        return float(text)
    except Exception:
        return default


def _is_set_flag(value: Optional[str]) -> bool:
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in {"set", "1", "true", "yes"}


def _tcp_flags_from_row(row: Dict[str, str]) -> str:
    flags = []
    if _is_set_flag(row.get("TCP SYN Flag")):
        flags.append("S")
    if _is_set_flag(row.get("TCP ACK Flag")):
        flags.append("A")
    if _is_set_flag(row.get("TCP FIN Flag")):
        flags.append("F")
    if _is_set_flag(row.get("TCP RST Flag")):
        flags.append("R")

    if flags:
        return "".join(flags)

    raw = (row.get("TCP Flags") or "").strip().lower()
    if raw.startswith("0x"):
        v = _to_int(raw, 0) or 0
        if v & 0x02:
            flags.append("S")
        if v & 0x10:
            flags.append("A")
        if v & 0x01:
            flags.append("F")
        if v & 0x04:
            flags.append("R")
        if v & 0x08:
            flags.append("P")
        if v & 0x20:
            flags.append("U")
    return "".join(flags)


def _row_to_layer_info(row: Dict[str, str]) -> Optional[LayerInfo]:
    ts = _to_float(row.get("Frame Time (Epoch)"))
    if ts is None:
        ts = _to_float(row.get("Time"))
    if ts is None:
        return None

    packet_number = _to_int(row.get("No."), 0) or 0

    src_ip = _clean_ip(row.get("IP Source") or row.get("Source"))
    dst_ip = _clean_ip(row.get("IP Destination") or row.get("Destination"))
    has_ip = bool(src_ip and dst_ip)

    protocol_name = (row.get("Protocol") or "").strip().upper()
    protocol = PROTO_MAP.get(protocol_name)

    tcp_sport = _to_int(row.get("TCP Source Port"))
    tcp_dport = _to_int(row.get("TCP Destination Port"))
    has_tcp = protocol_name == "TCP" or (tcp_sport is not None and tcp_dport is not None)

    http_method = (row.get("HTTP Request Method") or "").strip() or None
    http_uri = (row.get("HTTP Request URI") or "").strip() or None
    http_host = (row.get("HTTP Host") or "").strip() or None
    http_user_agent = (row.get("HTTP User-Agent") or "").strip() or None
    http_status = _to_int(row.get("HTTP Response Code"))
    has_http = any([http_method, http_uri, http_host, http_user_agent, http_status is not None])

    # Filter theo yêu cầu: chỉ giữ packet có đủ L3(IP) + L4(TCP)
    if not (has_ip and has_tcp):
        return None

    tcp_len = _to_int(row.get("TCP Length"), 0) or 0
    payload_text_parts = [p for p in [http_uri, http_user_agent] if p]
    payload_text = " ".join(payload_text_parts)
    payload_bytes = payload_text.encode("utf-8", errors="ignore") if payload_text else None
    payload_len = len(payload_bytes) if payload_bytes else tcp_len
    has_payload = payload_len > 0

    li = LayerInfo(
        timestamp=ts,
        packet_number=packet_number,
        has_ip=has_ip,
        ip_version=_to_int(row.get("IP Version")),
        src_ip=src_ip or None,
        dst_ip=dst_ip or None,
        ttl=_to_int(row.get("IP TTL")),
        ip_len=_to_int(row.get("IP Length")),
        protocol=protocol,
        has_tcp=has_tcp,
        tcp_sport=tcp_sport,
        tcp_dport=tcp_dport,
        tcp_flags=_tcp_flags_from_row(row),
        tcp_seq=_to_int(row.get("TCP Sequence Number")),
        tcp_ack=_to_int(row.get("TCP Acknowledgment Number")),
        tcp_window=_to_int(row.get("TCP Window Size")),
        has_payload=has_payload,
        payload_bytes=payload_bytes,
        payload_length=payload_len,
        has_http=has_http,
        http_method=http_method,
        http_uri=http_uri,
        http_host=http_host,
        http_user_agent=http_user_agent,
        http_status=http_status,
    )
    return li if li.has_ip else None


def _group_flows_by_src(flows):
    grouped = {}
    for f in flows:
        src = f.src_ip
        grouped.setdefault(src, []).append(f)
    return grouped


def extract_features_from_csv(
    csv_path: Path,
    output_path: Path,
    window_size: float,
    label: Optional[str] = None,
    max_rows: int = 0,
    precision: int = 2,
):
    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        packets: List[LayerInfo] = []
        for row in reader:
            li = _row_to_layer_info(row)
            if li is not None:
                packets.append(li)
            if max_rows > 0 and len(packets) >= max_rows:
                break

    if not packets:
        raise ValueError("No valid packet rows parsed from CSV.")

    packets.sort(key=lambda x: x.timestamp)
    calc = FlowFeatureCalculator()
    feature_names = calc.get_feature_names()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as out:
        fieldnames = [
            "window_index",
            "window_start",
            "window_end",
            "src_ip",
            "packets_in_window",
            "total_flows_in_window",
            "flows_for_src",
            "fwd_packets_for_src",
            "bwd_packets_for_src",
        ] + feature_names
        if label is not None:
            fieldnames.append("label")
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        idx = 0
        n = len(packets)
        window_start = packets[0].timestamp
        window_end = window_start + window_size
        window_index = 0

        while idx < n:
            fm = FlowManager(window_size=window_size, flow_timeout=max(window_size * 2, 1.0), cleanup_interval=100000)
            start_idx = idx

            while idx < n and packets[idx].timestamp < window_end:
                fm.process_packet(packets[idx])
                idx += 1

            all_flows = fm.get_all_flows()
            packets_in_window = idx - start_idx
            total_flows_in_window = len(all_flows)
            if all_flows:
                grouped = _group_flows_by_src(all_flows)
                for src_ip, flows in grouped.items():
                    for flow in flows:
                        flow.analysis_window_size = window_size
                    values = calc.calculate_all_optimized(flows)

                    fwd_packets_for_src = sum(f.get_fwd_packet_count() for f in flows)
                    bwd_packets_for_src = sum(f.get_bwd_packet_count() for f in flows)

                    row_out = {
                        "window_index": window_index,
                        "window_start": f"{window_start:.{precision}f}",
                        "window_end": f"{window_end:.{precision}f}",
                        "src_ip": src_ip,
                        "packets_in_window": packets_in_window,
                        "total_flows_in_window": total_flows_in_window,
                        "flows_for_src": len(flows),
                        "fwd_packets_for_src": fwd_packets_for_src,
                        "bwd_packets_for_src": bwd_packets_for_src,
                    }
                    for i, name in enumerate(feature_names):
                        row_out[name] = f"{float(values[i]):.{precision}f}"
                    if label is not None:
                        row_out["label"] = label
                    writer.writerow(row_out)

            window_start = window_end
            window_end = window_start + window_size
            window_index += 1


def main():
    parser = argparse.ArgumentParser(description="Extract NIDS features from dissected CSV for RL/PPO training")
    parser.add_argument("-i", "--input", required=True, help="Input dissected CSV path")
    parser.add_argument("-o", "--output", default="dataset/features_from_csv.csv", help="Output feature CSV path")
    parser.add_argument("-w", "--window", type=float, default=1.0, help="Window size in seconds (default: 1.0)")
    parser.add_argument("-l", "--label", default=None, help="Optional label column value (e.g., port_scanning)")
    parser.add_argument("--max-rows", type=int, default=0, help="Optional row cap for quick test (0 = all rows)")
    parser.add_argument("--precision", type=int, default=4, help="Decimal places for numeric output (default: 4)")
    args = parser.parse_args()

    if args.window <= 0:
        raise ValueError("window must be > 0")
    if args.precision < 0:
        raise ValueError("precision must be >= 0")

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    output_path = Path(args.output)
    extract_features_from_csv(
        csv_path=input_path,
        output_path=output_path,
        window_size=args.window,
        label=args.label,
        max_rows=args.max_rows,
        precision=args.precision,
    )
    print(f"[OK] Features exported: {output_path}")


if __name__ == "__main__":
    main()
