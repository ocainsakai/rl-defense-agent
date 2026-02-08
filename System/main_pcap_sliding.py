#!/usr/bin/env python3
# main_pcap_sliding.py
"""
=============================================================================
PCAP SLIDING WINDOW ANALYZER - TIME-SERIES FEATURE EXTRACTION
=============================================================================

Phân tích PCAP với SLIDING TIME WINDOWS để tạo dữ liệu features theo thời gian.

KHÁC BIỆT VỚI main_pcap.py:
- main_pcap.py: Toàn bộ PCAP → 1 row/src_ip (phân tích tĩnh)
- main_pcap_sliding.py: Time windows → nhiều rows/src_ip (theo thời gian)

ỨNG DỤNG:
- Phát hiện chính xác thời điểm attack bắt đầu/kết thúc
- Huấn luyện mô hình AI với time-series data
- Mô phỏng realtime monitoring

CÁCH SỬ DỤNG:
    python main_pcap_sliding.py -p attack.pcap -o output.csv -w 1.0
    python main_pcap_sliding.py --pcap dos.pcap --output dos_sliding.csv --window 0.5 --verbose

OUTPUT FORMAT:
    Mỗi row = 1 src_ip trong 1 time window:
    - Window_Start, Window_End (timestamps)
    - Src_IP
    - Aggregated statistics (flows, packets, duration)
    - 6 RAW Features (F1-F6)
    
FEATURE F1 IN SLIDING MODE:
    F1 = Total_Packets / window_size (cố định)
    VÍ DỤ: window_size=1.0s, có 2500 packets → F1=2500.0 pkts/s
=============================================================================
"""

import argparse
import csv
import sys
import os
from datetime import datetime
from scapy.all import PcapReader
from typing import Dict, List
from collections import defaultdict

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from feature.feature_flow import FlowFeatureCalculator


def group_flows_by_src_ip(flows: list) -> dict:
    """
    Gom các flows theo source IP address.
    
    Returns:
        dict: {src_ip: [flow1, flow2, ...]}
    """
    flows_by_src = {}
    
    for flow in flows:
        src_ip = flow.src_ip
        
        if src_ip not in flows_by_src:
            flows_by_src[src_ip] = []
        
        flows_by_src[src_ip].append(flow)
    
    return flows_by_src


def calculate_features_with_window_size(flows: List[FlowState], window_size: float) -> list:
    """
    Tính features với điều chỉnh cho sliding window mode.
    
    ĐIỀU CHỈNH QUAN TRỌNG:
    - F1_PacketRate = Total_Packets / window_size (thay vì / actual_duration)
    - Các features khác giữ nguyên logic
    
    Args:
        flows: List of FlowState objects trong window
        window_size: Kích thước window (seconds)
    
    Returns:
        list: [f1_adjusted, f2, f3, f4, f5, f6]
    """
    if not flows:
        return None
    
    # Tính F2-F6 bình thường
    calc = FlowFeatureCalculator()
    features = calc.calculate_all(flows)
    
    if features is None:
        return None
    
    # ĐIỀU CHỈNH F1: Dùng window_size thay vì actual duration
    total_packets = sum(f.get_packet_count() for f in flows)
    
    if window_size <= 0:
        f1_adjusted = float(total_packets)
    else:
        f1_adjusted = float(total_packets) / window_size
    
    # Thay thế F1 trong features
    features[0] = f1_adjusted
    
    return features


def analyze_pcap_sliding(pcap_file: str, output_csv: str, window_size: float = 1.0, verbose: bool = False):
    """
    Phân tích PCAP với sliding time windows.
    
    Args:
        pcap_file: Đường dẫn file PCAP
        output_csv: File CSV output
        window_size: Kích thước window (seconds)
        verbose: In chi tiết mỗi window
    
    LOGIC:
    1. Đọc packets từ PCAP theo thứ tự
    2. Tạo window mới mỗi khi timestamp > window_end
    3. Xuất features cho window trước đó
    4. Gom flows theo src_ip trong mỗi window
    5. Tính features với F1 = packets/window_size
    """
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: File không tồn tại: {pcap_file}")
        sys.exit(1)
    
    print(f"\n{'='*70}")
    print(f"PCAP SLIDING WINDOW ANALYZER")
    print(f"{'='*70}")
    print(f"[+] Input PCAP:   {pcap_file}")
    print(f"[+] Output CSV:   {output_csv}")
    print(f"[+] Window Size:  {window_size}s")
    print(f"[+] Verbose:      {verbose}")
    print(f"{'='*70}\n")
    
    # ========================================================================
    # KHỞI TẠO COMPONENTS
    # ========================================================================
    
    parser = PacketLayerExtractor(
        enable_http_parsing=True,
        use_packet_time=True  # QUAN TRỌNG: Dùng timestamp từ PCAP, KHÔNG dùng thời gian máy
    )
    
    print("[✓] PacketLayerExtractor configured:")
    print("    - use_packet_time=True → Timestamps từ PCAP file")
    print("    - Timestamps phản ánh thời gian ghi trong PCAP, KHÔNG phải thời gian hiện tại\n")
    
    # CSV Headers
    headers = [
        # Time Window
        "Window_Start",          # PCAP timestamp (epoch seconds)
        "Window_End",            # PCAP timestamp (epoch seconds)
        "DateTime",              # Human-readable: YYYY-MM-DD HH:MM:SS
        
        # Source IP Identification
        "Src_IP",
        "Total_Flows",
        "Total_Unique_Dst_IPs",
        
        # Aggregated Statistics
        "Total_Fwd_Pkts",
        "Total_Bwd_Pkts",
        "Total_Pkts",
        "Total_Duration",
        
        # TCP Flags Summary (from forward packets)
        "TCP_Flags",             # Format: "SYN:10,ACK:20,RST:5,FIN:2"
        
        # RAW Features (F1 adjusted for sliding window)
        "F1_PacketRate_RAW",
        "F2_SynRatio_RAW",
        "F3_DistinctPorts_RAW",
        "F4_PayloadLen_RAW",
        "F5_FailRate_RAW",
        "F6_ContextScore_RAW",
    ]
    
    # Open CSV file for writing
    csv_file = open(output_csv, 'w', newline='', encoding='utf-8')
    writer = csv.DictWriter(csv_file, fieldnames=headers)
    writer.writeheader()
    
    # ========================================================================
    # SLIDING WINDOW LOGIC
    # ========================================================================
    
    current_window_start = None
    current_window_end = None
    current_flow_manager = None
    
    total_packets = 0
    total_windows = 0
    total_rows_written = 0
    
    def process_and_export_window():
        """Xử lý và xuất features cho window hiện tại."""
        nonlocal total_windows, total_rows_written
        
        if current_flow_manager is None:
            return
        
        all_flows = current_flow_manager.get_all_flows()
        if not all_flows:
            return
        
        total_windows += 1
        
        # Group flows by src_ip
        flows_by_src = group_flows_by_src_ip(all_flows)
        
        if verbose:
            print(f"\n[*] Window {total_windows}: [{current_window_start:.3f} - {current_window_end:.3f}]")
            print(f"    Flows: {len(all_flows)}, Unique Src IPs: {len(flows_by_src)}")
        
        # Tính features cho mỗi src_ip
        for src_ip, flows_list in flows_by_src.items():
            # Aggregate statistics
            total_fwd = sum(f.get_fwd_packet_count() for f in flows_list)
            total_bwd = sum(f.get_bwd_packet_count() for f in flows_list)
            total_pkts = total_fwd + total_bwd
            unique_dst_ips = len(set(f.dst_ip for f in flows_list))
            total_duration = sum(f.duration for f in flows_list)
            
            # Aggregate TCP Flags từ forward packets
            tcp_flags_agg = {'SYN': 0, 'ACK': 0, 'RST': 0, 'FIN': 0, 'PSH': 0, 'URG': 0}
            for flow in flows_list:
                flags = flow.get_fwd_tcp_flags_count()
                for flag_name in tcp_flags_agg.keys():
                    tcp_flags_agg[flag_name] += flags.get(flag_name, 0)
            
            # Format TCP flags string (chỉ hiện flags có count > 0)
            tcp_flags_str = ','.join([f"{k}:{v}" for k, v in tcp_flags_agg.items() if v > 0])
            if not tcp_flags_str:
                tcp_flags_str = "NONE"
            
            # Convert timestamp to human-readable DateTime
            dt_str = datetime.fromtimestamp(current_window_start).strftime('%Y-%m-%d %H:%M:%S')
            
            # Calculate features với window_size adjustment
            features = calculate_features_with_window_size(flows_list, window_size)
            
            if features is None:
                continue
            
            # Unpack features
            f1, f2, f3, f4, f5, f6 = features
            
            # Write row
            row = {
                "Window_Start": f"{current_window_start:.6f}",
                "Window_End": f"{current_window_end:.6f}",
                "DateTime": dt_str,
                "Src_IP": src_ip,
                "Total_Flows": len(flows_list),
                "Total_Unique_Dst_IPs": unique_dst_ips,
                "Total_Fwd_Pkts": total_fwd,
                "Total_Bwd_Pkts": total_bwd,
                "Total_Pkts": total_pkts,
                "Total_Duration": f"{total_duration:.6f}",
                "TCP_Flags": tcp_flags_str,
                "F1_PacketRate_RAW": f"{f1:.4f}",
                "F2_SynRatio_RAW": f"{f2:.4f}",
                "F3_DistinctPorts_RAW": f"{f3:.0f}",
                "F4_PayloadLen_RAW": f"{f4:.4f}",
                "F5_FailRate_RAW": f"{f5:.4f}",
                "F6_ContextScore_RAW": f"{f6:.4f}",
            }
            writer.writerow(row)
            total_rows_written += 1
            
            if verbose:
                print(f"    └─ {src_ip}: Flows={len(flows_list)}, "
                      f"F1={f1:.1f}, F3={f3:.0f} ports, Flags={tcp_flags_str}")
    
    # ========================================================================
    # ĐỌC PCAP VÀ XỬ LÝ THEO WINDOWS
    # ========================================================================
    
    print("[*] Reading PCAP file...")
    
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                try:
                    info = parser.extract(pkt, total_packets)
                    
                    if info is None or not info.has_ip:
                        continue
                    
                    pkt_time = info.timestamp
                    
                    # Khởi tạo window đầu tiên
                    if current_window_start is None:
                        current_window_start = pkt_time
                        current_window_end = current_window_start + window_size
                        current_flow_manager = FlowManager(
                            window_size=window_size,
                            flow_timeout=window_size * 2,
                            cleanup_interval=99999
                        )
                    
                    # Check nếu packet vượt quá window hiện tại
                    while pkt_time >= current_window_end:
                        # Xuất window hiện tại
                        process_and_export_window()
                        
                        # Tạo window mới
                        current_window_start = current_window_end
                        current_window_end = current_window_start + window_size
                        current_flow_manager = FlowManager(
                            window_size=window_size,
                            flow_timeout=window_size * 2,
                            cleanup_interval=99999
                        )
                    
                    # Thêm packet vào window hiện tại
                    current_flow_manager.process_packet(info)
                    total_packets += 1
                    
                    # Progress display
                    if total_packets % 1000 == 0:
                        sys.stdout.write(f"\r[*] Processed: {total_packets} packets, {total_windows} windows...")
                        sys.stdout.flush()
                        
                except Exception as e:
                    continue
        
        # Xử lý window cuối cùng
        if current_flow_manager is not None:
            process_and_export_window()
        
        print(f"\r[+] Total packets processed: {total_packets}")
        
    except Exception as e:
        print(f"\n[!] Error reading PCAP: {e}")
        import traceback
        traceback.print_exc()
        csv_file.close()
        sys.exit(1)
    
    csv_file.close()
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    
    print(f"\n{'='*70}")
    print(f"ANALYSIS COMPLETE")
    print(f"{'='*70}")
    print(f"Total Packets:     {total_packets}")
    print(f"Total Windows:     {total_windows}")
    print(f"Total Rows:        {total_rows_written}")
    print(f"Avg Rows/Window:   {total_rows_written/max(total_windows,1):.1f}")
    print(f"Output File:       {output_csv}")
    print(f"{'='*70}\n")
    
    print("[+] CÁCH SỬ DỤNG OUTPUT:")
    print("    1. Mỗi row = 1 src_ip trong 1 time window")
    print("    2. F3_DistinctPorts cho thấy port scan theo thời gian")
    print("    3. F1_PacketRate = packets/window_size (chuẩn hóa)")
    print("    4. Có thể vẽ biểu đồ time-series từ Window_Start")
    print("")


def main():
    """Entry point cho PCAP sliding window analyzer."""
    
    parser = argparse.ArgumentParser(
        description="PCAP Sliding Window Analyzer - Time-Series Feature Extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
    # Window size mặc định (1s)
    python main_pcap_sliding.py -p attack.pcap -o output.csv
    
    # Window size custom (0.5s)
    python main_pcap_sliding.py -p dos.pcap -o dos_sliding.csv -w 0.5
    
    # Verbose mode
    python main_pcap_sliding.py -p nmap.pcap -o nmap_sliding.csv -w 1.0 --verbose

Output:
    CSV file với time-series features:
    - Mỗi row = 1 src_ip trong 1 time window
    - F1 = packets/window_size (chuẩn hóa theo window)
    - F3 cho thấy port scanning theo thời gian
        """
    )
    
    parser.add_argument(
        "-p", "--pcap",
        required=True,
        metavar="FILE",
        help="PCAP file path to analyze"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="pcap_sliding_output.csv",
        metavar="FILE",
        help="Output CSV file (default: pcap_sliding_output.csv)"
    )
    
    parser.add_argument(
        "-w", "--window",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Window size in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose: print details for each window"
    )
    
    args = parser.parse_args()
    
    # Validate window size
    if args.window <= 0:
        print("[!] Error: Window size phải > 0")
        sys.exit(1)
    
    # Run analysis
    analyze_pcap_sliding(args.pcap, args.output, args.window, args.verbose)


if __name__ == "__main__":
    main()
