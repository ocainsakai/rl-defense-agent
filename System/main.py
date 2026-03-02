#!/usr/bin/env python3
"""
=============================================================================
NIDS - Network Intrusion Detection System
=============================================================================
Interactive entry point: chọn chế độ chạy từ menu.

Modes:
  1) Realtime  - Capture live từ network interface  -> JSONL
  2) PCAP      - Phân tích offline PCAP file        -> CSV
  3) CSV       - Extract features từ Wireshark CSV  -> CSV

Import trực tiếp từ core/feature library modules.
=============================================================================
"""

import csv
import json
import logging
import os
import sys
import threading
import time
import traceback

logger = logging.getLogger(__name__)

from datetime import datetime
from pathlib import Path
from typing import Optional

from scapy.all import PcapReader, get_if_list, conf as scapy_conf

# Đảm bảo System/ luôn trong sys.path khi chạy từ thư mục khác
_SYSTEM_DIR = Path(__file__).resolve().parent
if str(_SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(_SYSTEM_DIR))

from config.data_params import normalize_feature_vector, WINDOW_SIZE_SECONDS
from config.nids_config import DEFAULT_CONFIG
from core.flow_manager import FlowManager
from core.layer_info import LayerInfo
from core.packet_parser import PacketLayerExtractor
from core.packet_queue import PacketQueue
from core.sniffer import NetworkSniffer
from feature.calculator import FlowFeatureCalculator
from feature.wamm_classifier import WammClassifier

scapy_conf.checkIPaddr = False

# Thư mục output mặc định (có thể thay đổi qua menu [4])
_output_dir: str = str(Path.cwd())


def _resolve_output(filename: str) -> str:
    """Ghép _output_dir với filename nếu filename không phải absolute path."""
    p = Path(filename)
    if p.is_absolute():
        return filename
    return str(Path(_output_dir) / p)


# ============================================================================
# UI HELPERS
# ============================================================================

def _banner():
    print("\n" + "=" * 60)
    print("   NIDS - Network Intrusion Detection System")
    print("=" * 60)
    print("  [1] Realtime  - Capture từ network interface")
    print("  [2] PCAP      - Phân tích offline PCAP file")
    print("  [3] CSV       - Extract features từ Wireshark CSV")
    print("  [4] Output    - Cài đặt thư mục lưu output")
    print("  [0] Exit")
    print("=" * 60)
    print(f"  Output dir: {_output_dir}")


def _prompt(msg: str, default=None) -> str:
    hint = f" [{default}]" if default is not None else ""
    val = input(f"  {msg}{hint}: ").strip()
    return val if val else (str(default) if default is not None else "")


def _prompt_float(msg: str, default: float) -> float:
    while True:
        raw = _prompt(msg, default)
        try:
            v = float(raw)
            if v > 0:
                return v
            print("  [!] Phải > 0")
        except ValueError:
            print("  [!] Nhập số thực hợp lệ")


def _prompt_window_size() -> float:
    """Nhập window size với cảnh báo nếu khác WINDOW_SIZE_SECONDS (1.0s)."""
    v = _prompt_float("Window size (seconds)", WINDOW_SIZE_SECONDS)
    if v != WINDOW_SIZE_SECONDS:
        print(f"  [!] CẢNH BÁO: hệ thống được thiết kế cho WINDOW_SIZE={WINDOW_SIZE_SECONDS}s.")
        print(f"      FEATURE_CLIP_BOUNDS trong data_params.py được calibrate cho {WINDOW_SIZE_SECONDS}s.")
        print(f"      Dùng {v}s sẽ làm lệch F1/F3 (rate-based) và F7/F8 (IAT-based) → normalize sai → RL model kém chính xác.")
        confirm = _prompt_bool(f"  Vẫn tiếp tục với window={v}s? (y/n)", False)
        if not confirm:
            print(f"  [→] Dùng mặc định {WINDOW_SIZE_SECONDS}s.")
            return WINDOW_SIZE_SECONDS
    return v


def _prompt_output_path(default_name: str) -> str:
    """Nhập đường dẫn output file.

    - Chỉ nhập tên file  → lưu vào _output_dir/<tên file>
    - Nhập full/absolute path → lưu chính xác tại path đó
    """
    print(f"  Output dir hiện tại : {_output_dir}")
    print(f"  (Nhập tên file hoặc đường dẫn đầy đủ)")
    raw = _prompt("Output path", default_name)
    resolved = _resolve_output(raw)
    print(f"  → Sẽ lưu tại: {resolved}")
    return resolved


def _prompt_bool(msg: str, default: bool = False) -> bool:
    raw = _prompt(msg, "y" if default else "n").lower()
    return raw in ("y", "yes", "1", "true")


def _prompt_file(msg: str, must_exist: bool = True) -> str:
    while True:
        path = _prompt(msg)
        if not path:
            print("  [!] Vui lòng nhập đường dẫn file.")
            continue
        if must_exist and not os.path.exists(path):
            print(f"  [!] File không tồn tại: {path}")
            continue
        return path


# ============================================================================
# MODE 1: REALTIME
# ============================================================================

def _run_realtime(interface: str, window_size: float, output_file: str):
    if not (output_file.endswith(".json") or output_file.endswith(".jsonl")):
        output_file += ".jsonl"

    packet_queue = PacketQueue(max_size=DEFAULT_CONFIG.MAX_QUEUE_SIZE)
    parser       = PacketLayerExtractor()
    flow_manager = FlowManager(window_size=window_size)
    wamm         = WammClassifier()
    calc         = FlowFeatureCalculator(wamm_classifier=wamm)
    sniffer      = NetworkSniffer()
    lock         = threading.Lock()
    stats        = {"cap": 0, "proc": 0, "drop": 0, "rows": 0, "err": 0}
    running      = [True]

    def _capture():
        def cb(pkt):
            if not running[0]:
                return
            if packet_queue.put(pkt, block=False):
                stats["cap"] += 1
            else:
                stats["drop"] += 1
        sniffer.start_live(interface=interface, callback=cb, bpf_filter="tcp")

    def _analyze():
        while running[0] or not packet_queue.empty():
            pkt = packet_queue.get(block=True, timeout=0.5)
            if pkt is None:
                continue
            try:
                info = parser.extract(pkt)
                if info and info.has_ip and info.has_tcp:
                    with lock:
                        flow_manager.process_packet(info)
                    stats["proc"] += 1
            except Exception as e:
                stats["err"] += 1
                logger.debug("Packet parse/ingest error: %s", e)

    feature_labels = FlowFeatureCalculator.get_feature_labels()
    out_fd = open(output_file, "w", encoding="utf-8")

    def _process_window(win_end: float):
        with lock:
            all_flows = flow_manager.get_all_flows()
            flow_manager.slide_window_packets(win_end)

        by_src: dict = {}
        for fl in all_flows:
            src = fl.effective_src_ip if hasattr(fl, "effective_src_ip") else fl.src_ip
            by_src.setdefault(src, []).append(fl)

        for src_ip, flows_list in by_src.items():
            for fl in flows_list:
                fl.analysis_window_size = window_size
            features = calc.calculate_all(flows_list)
            if not features or float(features[0]) <= 0:
                continue
            row = {"timestamp": round(win_end, 6), "src_ip": src_ip}
            for i, label in enumerate(feature_labels):
                row[label] = round(float(features[i]), 4)
            out_fd.write(json.dumps(row) + "\n")
            out_fd.flush()
            stats["rows"] += 1

    cap_t = threading.Thread(target=_capture, daemon=True)
    ana_t = threading.Thread(target=_analyze, daemon=True)
    cap_t.start()
    ana_t.start()

    win_start = time.time()
    win_end   = win_start + window_size
    print(f"\n[✓] Đang chạy | Interface={interface} | Window={window_size}s | Output={output_file}")
    print("    Ctrl+C để dừng.\n")

    try:
        while True:
            time.sleep(0.1)
            now = time.time()
            while now >= win_end:
                _process_window(win_end)
                win_start += window_size
                win_end    = win_start + window_size
                print(f"    Cap={stats['cap']} Proc={stats['proc']} Drop={stats['drop']} Err={stats['err']} Rows={stats['rows']}")
    except KeyboardInterrupt:
        print("\n[!] Dừng hệ thống...")
    finally:
        running[0] = False
        sniffer.stop()
        time.sleep(0.5)
        out_fd.close()
        print(f"[✓] Done. Rows={stats['rows']} | Output={output_file}")


def _menu_realtime():
    print("\n--- REALTIME MODE ---")
    try:
        ifaces = get_if_list()
        print(f"  Available interfaces: {', '.join(ifaces)}")
    except Exception as e:
        print(f"  [!] Không thể liệt kê interfaces (cần quyền root/admin hoặc kiểm tra cài đặt Scapy): {e}")
    default_iface = "Ethernet" if sys.platform == "win32" else "eth0"
    interface   = _prompt("Network interface", default_iface) or default_iface
    window_size = _prompt_window_size()
    output_file = _prompt_output_path("live_output.jsonl")
    _run_realtime(interface, window_size, output_file)


# ============================================================================
# MODE 2: PCAP
# ============================================================================

def _run_pcap(pcap_file: str, output_csv: str, window_size: float, verbose: bool):
    parser        = PacketLayerExtractor(use_packet_time=True)
    calc          = FlowFeatureCalculator()
    feature_labels = FlowFeatureCalculator.get_feature_labels()
    headers       = [
        "Window_Start", "Window_End", "DateTime",
        "Src_IP", "Total_Flows", "Total_Pkts",
    ] + [f"{n}_RAW" for n in feature_labels] \
      + [f"{n}_NORM" for n in feature_labels]

    total_pkts = total_wins = rows = 0
    win_start = win_end = None
    fm: Optional[FlowManager] = None

    def _export_window():
        nonlocal total_wins, rows
        if fm is None:
            return
        all_flows = fm.get_all_flows()
        if not all_flows:
            return
        total_wins += 1
        by_src: dict = {}
        for fl in all_flows:
            by_src.setdefault(fl.src_ip, []).append(fl)

        for src_ip, flows_list in by_src.items():
            n_pkts = sum(f.get_packet_count() for f in flows_list)
            for fl in flows_list:
                fl.analysis_window_size = window_size
            features = calc.calculate_all(flows_list)
            if features is None:
                continue
            # F1 (PacketRate) được tính đúng bởi F1_PacketRate.calculate() thông qua
            # analysis_window_size đã set ở trên — không cần override thủ công.
            norm_features = normalize_feature_vector(features)
            dt  = datetime.fromtimestamp(win_start).strftime("%Y-%m-%d %H:%M:%S")
            row = {
                "Window_Start": f"{win_start:.6f}",
                "Window_End":   f"{win_end:.6f}",
                "DateTime":     dt,
                "Src_IP":       src_ip,
                "Total_Flows":  len(flows_list),
                "Total_Pkts":   n_pkts,
            }
            for i, label in enumerate(feature_labels):
                row[f"{label}_RAW"]  = f"{features[i]:.4f}"
                row[f"{label}_NORM"] = f"{norm_features[i]:.4f}"
            writer.writerow(row)
            rows += 1
            if verbose:
                print(f"    {src_ip}: Flows={len(flows_list)} F1={features[0]:.1f}")

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        print(f"\n[*] Đọc PCAP: {pcap_file}")
        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    info = parser.extract(pkt, total_pkts)
                    if info is None or not info.has_ip or not info.has_tcp:
                        continue
                    pkt_time = info.timestamp

                    if win_start is None:
                        win_start = pkt_time
                        win_end   = win_start + window_size
                        fm = FlowManager(window_size=window_size)

                    while pkt_time >= win_end:
                        _export_window()
                        fm.slide_window_packets(win_end)
                        win_start = win_end
                        win_end   = win_start + window_size

                    fm.process_packet(info)
                    total_pkts += 1
                    if total_pkts % 1000 == 0:
                        print(f"\r    Packets={total_pkts} Windows={total_wins}...", end="", flush=True)
            _export_window()
        except Exception as e:
            print(f"\n[!] Lỗi đọc PCAP: {e}")
            return

    print(f"\n[✓] Done. Packets={total_pkts} | Windows={total_wins} | Rows={rows}")
    print(f"    Output: {output_csv}")


def _menu_pcap():
    print("\n--- PCAP MODE ---")
    pcap_file   = _prompt_file("PCAP file path")
    window_size = _prompt_window_size()
    output_csv  = _prompt_output_path("pcap_output.csv")
    verbose     = _prompt_bool("Verbose (y/n)", False)
    _run_pcap(pcap_file, output_csv, window_size, verbose)


# ============================================================================
# MODE 3: CSV — Wireshark packet-level export
# ============================================================================

_PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1}


def _to_int(v, default=None):
    if v is None:
        return default
    s = str(v).strip()
    if not s:
        return default
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    except Exception:
        return default


def _to_float_val(v, default=None):
    if v is None:
        return default
    s = str(v).strip()
    if not s:
        return default
    try:
        return float(s)
    except Exception:
        return default


def _is_set(v) -> bool:
    return str(v or "").strip().lower() in {"set", "1", "true", "yes"}


def _csv_row_to_layer_info(row: dict, pkt_num: int) -> Optional[LayerInfo]:
    # Timestamp — ưu tiên epoch float, fallback về relative time
    epoch_raw = (row.get("Frame Time (Epoch)") or "").strip()
    ts = _to_float_val(epoch_raw) if "." in epoch_raw else _to_float_val(row.get("Time"))
    if ts is None:
        ts = _to_float_val(epoch_raw)
    if ts is None:
        return None

    # IP
    src_ip = (row.get("IP Source") or row.get("Source") or "").strip().strip('"')
    dst_ip = (row.get("IP Destination") or row.get("Destination") or "").strip().strip('"')
    if "," in src_ip:
        src_ip = src_ip.split(",")[0].strip()
    if "," in dst_ip:
        dst_ip = dst_ip.split(",")[0].strip()
    has_ip = bool(src_ip and dst_ip)

    # Protocol
    proto_name    = (row.get("Protocol") or "").strip().upper()
    ip_proto_name = (row.get("IP Protocol") or "").strip().upper()
    protocol      = _PROTO_MAP.get(ip_proto_name) or _PROTO_MAP.get(proto_name)

    # TCP ports
    tcp_sport = _to_int(row.get("TCP Source Port"))
    tcp_dport = _to_int(row.get("TCP Destination Port"))
    has_tcp   = proto_name == "TCP" or (tcp_sport is not None and tcp_dport is not None)

    if not (has_ip and has_tcp):
        return None

    # TCP Flags — thử cột riêng trước, fallback về hex
    flags = []
    for col, letter in [("TCP SYN Flag", "S"), ("TCP ACK Flag", "A"),
                         ("TCP FIN Flag", "F"), ("TCP RST Flag", "R")]:
        if _is_set(row.get(col)):
            flags.append(letter)
    if not flags:
        raw_flags = (row.get("TCP Flags") or "").strip().lower()
        if raw_flags.startswith("0x"):
            v = _to_int(raw_flags, 0) or 0
            if v & 0x02: flags.append("S")
            if v & 0x10: flags.append("A")
            if v & 0x01: flags.append("F")
            if v & 0x04: flags.append("R")
            if v & 0x08: flags.append("P")

    # HTTP
    http_method = (row.get("HTTP Request Method") or "").strip() or None
    http_uri    = (row.get("HTTP Request URI") or "").strip() or None
    http_host   = (row.get("HTTP Host") or "").strip() or None
    http_ua     = (row.get("HTTP User-Agent") or "").strip() or None
    http_status = _to_int(row.get("HTTP Response Code"))
    has_http    = any([http_method, http_uri, http_host, http_ua, http_status is not None])
    tcp_len     = _to_int(row.get("TCP Length"), 0) or 0

    return LayerInfo(
        timestamp=ts,
        packet_number=pkt_num,
        has_ip=has_ip,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        has_tcp=has_tcp,
        tcp_sport=tcp_sport,
        tcp_dport=tcp_dport,
        tcp_flags="".join(flags),
        tcp_seq=_to_int(row.get("TCP Sequence Number")),
        tcp_ack=_to_int(row.get("TCP Acknowledgment Number")),
        tcp_window=_to_int(row.get("TCP Window Size")),
        has_payload=has_http or tcp_len > 0,
        payload_length=tcp_len,
        has_http=has_http,
        http_method=http_method,
        http_uri=http_uri,
        http_host=http_host,
        http_user_agent=http_ua,
        http_status=http_status,
    )


def _run_csv(csv_file: str, output_csv: str, window_size: float,
             label: Optional[str], normalize: bool):
    # Parse toàn bộ CSV thành danh sách LayerInfo
    packets = []
    with open(csv_file, "r", encoding="utf-8", errors="ignore", newline="") as f:
        for i, row in enumerate(csv.DictReader(f)):
            li = _csv_row_to_layer_info(row, i)
            if li is not None:
                packets.append(li)

    if not packets:
        print("[!] Không parse được packet nào từ CSV.")
        return

    packets.sort(key=lambda x: x.timestamp)
    print(f"    Parsed {len(packets)} packets.")

    calc           = FlowFeatureCalculator()
    feature_labels = calc.get_feature_labels()
    fieldnames     = [
        "window_index", "window_start", "window_end",
        "src_ip", "packets_in_window", "flows_for_src",
    ] + feature_labels
    if label:
        fieldnames.append("label")

    n         = len(packets)
    idx       = 0
    win_start = packets[0].timestamp
    win_end   = win_start + window_size
    win_idx   = rows = 0
    fm        = FlowManager(window_size=window_size)

    with open(output_csv, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        while idx < n:
            start_idx = idx
            while idx < n and packets[idx].timestamp < win_end:
                fm.process_packet(packets[idx])
                idx += 1
            pkts_in_win = idx - start_idx

            by_src: dict = {}
            for fl in fm.get_all_flows():
                by_src.setdefault(fl.src_ip, []).append(fl)

            for src_ip, flows_list in by_src.items():
                for fl in flows_list:
                    fl.analysis_window_size = window_size
                values = calc.calculate_all_optimized(flows_list)
                if normalize:
                    values = normalize_feature_vector(values)
                row_out = {
                    "window_index":    win_idx,
                    "window_start":    f"{win_start:.4f}",
                    "window_end":      f"{win_end:.4f}",
                    "src_ip":          src_ip,
                    "packets_in_window": pkts_in_win,
                    "flows_for_src":   len(flows_list),
                }
                for i, feat_label in enumerate(feature_labels):
                    row_out[feat_label] = f"{float(values[i]):.4f}"
                if label:
                    row_out["label"] = label
                writer.writerow(row_out)
                rows += 1

            fm.slide_window_packets(win_end)
            win_start = win_end
            win_end   = win_start + window_size
            win_idx  += 1

    print(f"[✓] Done. Windows={win_idx} | Rows={rows} | Output={output_csv}")


def _menu_csv():
    print("\n--- CSV MODE (Wireshark export) ---")
    csv_file    = _prompt_file("Input CSV path")
    window_size = _prompt_window_size()
    output_csv  = _prompt_output_path("features.csv")
    label_raw   = _prompt("Label (Enter để bỏ qua)")
    label       = label_raw if label_raw else None
    normalize   = _prompt_bool("Normalize features (y/n)", False)
    _run_csv(csv_file, output_csv, window_size, label, normalize)


# ============================================================================
# MODE 4: OUTPUT DIRECTORY SETTINGS
# ============================================================================

def _menu_output():
    global _output_dir
    print("\n--- CÀI ĐẶT OUTPUT PATH ---")
    print(f"  Thư mục hiện tại: {_output_dir}")
    print("  [1] Nhập đường dẫn thủ công")
    print("  [2] Dùng thư mục hiện tại (cwd)")
    print("  [3] Dùng thư mục chứa script này")
    print("  [0] Hủy")
    sub = input("  Chọn: ").strip()

    if sub == "0":
        return
    elif sub == "2":
        new_dir = str(Path.cwd())
    elif sub == "3":
        new_dir = str(_SYSTEM_DIR)
    elif sub == "1":
        raw = _prompt("Nhập đường dẫn thư mục").strip()
        if not raw:
            print("  [!] Không có gì được nhập. Giữ nguyên.")
            return
        new_dir = raw
    else:
        print("  [!] Lựa chọn không hợp lệ.")
        return

    p = Path(new_dir)
    if not p.exists():
        create = _prompt_bool(f"Thư mục '{new_dir}' chưa tồn tại. Tạo mới? (y/n)", True)
        if create:
            try:
                p.mkdir(parents=True, exist_ok=True)
                print(f"  [✓] Đã tạo thư mục: {new_dir}")
            except Exception as e:
                print(f"  [!] Không thể tạo thư mục: {e}")
                return
        else:
            return
    elif not p.is_dir():
        print(f"  [!] '{new_dir}' không phải thư mục.")
        return

    _output_dir = str(p.resolve())
    print(f"  [✓] Output path đã được đặt thành: {_output_dir}")


# ============================================================================
# MAIN MENU
# ============================================================================

def main():
    _MENU = {
        "1": ("Realtime", _menu_realtime),
        "2": ("PCAP",     _menu_pcap),
        "3": ("CSV",      _menu_csv),
        "4": ("Output",   _menu_output),
    }

    while True:
        _banner()
        choice = input("Chọn chế độ (0-3): ").strip()

        if choice == "0":
            print("Bye!")
            break

        entry = _MENU.get(choice)
        if entry is None:
            print("[!] Lựa chọn không hợp lệ. Vui lòng nhập 0-4.\n")
            continue

        name, fn = entry
        print(f"\n>>> {name} MODE <<<")
        try:
            fn()
        except Exception as e:
            print(f"\n[!] Lỗi: {e}")
            traceback.print_exc()

        input("\nNhấn Enter để quay về menu...")


if __name__ == "__main__":
    main()
