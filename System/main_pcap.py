#!/usr/bin/env python3
# main_pcap.py
"""
=============================================================================
PCAP ANALYSIS TOOL - RAW VALUES OUTPUT
=============================================================================

Chuyên dụng cho PCAP analysis với output RAW VALUES để so sánh với CICFlowMeter.

FEATURES:
- Phân tích toàn bộ PCAP file theo FLOWS (không phải per-packet)
- Output 6 features ở dạng RAW VALUES (không normalize)
- Format CSV tương thích với CICFlowMeter

CÁCH SỬ DỤNG:
    python main_pcap.py -p attack_test.pcap -o output.csv
    python main_pcap.py --pcap capture.pcap --output features.csv --verbose

OUTPUT FORMAT:
    Mỗi flow = 1 row với các columns:
    - Flow identification: Flow_ID, Src_IP, Dst_IP, Src_Port, Dst_Port, Protocol
    - Flow statistics: Duration, Total_Fwd_Pkts, Total_Bwd_Pkts, Total_Pkts
    - RAW Features: F1_PacketRate, F2_SynRatio, F3_DistinctPorts, 
                    F4_PayloadLen, F5_FailRate, F6_ContextScore
=============================================================================
"""

import argparse
import csv
import sys
import os
from datetime import datetime
from scapy.all import PcapReader

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator
from feature.wamm_classifier import WammClassifier
from config.data_params import ANONYMIZE_SRC_IP_FOR_TRAINING, anonymize_src_ip


def group_flows_by_src_ip(flows: list) -> dict:
    """
    Gom các flows theo source IP address.
    
    Tại sao cần gom flows?
    ========================
    6 Features được thiết kế để phân tích behavior của MỘT src_ip,
    không phải của MỘT flow riêng lẻ:
    
    - F1_PacketRate: Tổng packets từ TẤT CẢ flows của src_ip
    - F2_SynRatio: SYN/ACK ratio từ TẤT CẢ flows của src_ip
    - F3_DistinctPorts: Số ports khác nhau mà src_ip kết nối đến
      → Phát hiện Port Scanning (nếu chỉ tính 1 flow thì luôn = 1)
    - F4_PayloadLen: Avg payload từ TẤT CẢ flows của src_ip
    - F5_FailRate: Tỷ lệ RST/errors từ TẤT CẢ flows của src_ip
    - F6_ContextScore: Malicious patterns từ TẤT CẢ flows của src_ip
    
    Args:
        flows (list): List of FlowState objects
    
    Returns:
        dict: Mapping {src_ip: [flow1, flow2, ...]}
    
    Example:
        Input: [
            Flow(192.168.1.100 -> 10.0.0.1:80),
            Flow(192.168.1.100 -> 10.0.0.1:443),
            Flow(192.168.1.200 -> 10.0.0.1:22),
        ]
        
        Output: {
            '192.168.1.100': [flow1, flow2],  # F3 = 2 ports {80, 443}
            '192.168.1.200': [flow3],         # F3 = 1 port {22}
        }
    """
    flows_by_src = {}
    
    for flow in flows:
        src_ip = flow.src_ip
        
        if src_ip not in flows_by_src:
            flows_by_src[src_ip] = []
        
        flows_by_src[src_ip].append(flow)
    
    return flows_by_src


def analyze_pcap(pcap_file: str, output_csv: str, verbose: bool = False):
    """
    Phân tích PCAP file và tính toán 6 features RAW values cho mỗi SOURCE IP.
    
    Args:
        pcap_file (str): Đường dẫn file PCAP
        output_csv (str): Đường dẫn file CSV output
        verbose (bool): In chi tiết src IPs ra màn hình
    
    LOGIC:
    1. Đọc toàn bộ PCAP
    2. Parse packets → LayerInfo
    3. Map packets vào flows (5-tuple)
    4. Group flows theo src_ip
    5. Tính 6 features RAW cho MỖI SRC_IP (aggregate từ tất cả flows)
    6. Export CSV: 1 row = 1 src_ip với aggregated features
    
    WHY GROUP BY SRC_IP?
    ====================
    6 Features được thiết kế để phân tích BEHAVIOR của mỗi src_ip:
    - F1: Packet rate từ tất cả flows của src_ip
    - F2: SYN/ACK ratio để detect SYN flood
    - F3: Distinct ports → Phát hiện Port Scanning
          (Nếu không gom theo src_ip, F3 sẽ luôn = 1 vì mỗi flow có cố định 1 port)
    - F4: Average payload length
    - F5: Fail rate (RST + HTTP errors)
    - F6: Malicious payload detection
    
    OUTPUT FORMAT:
    ==============
    Mỗi row = 1 src_ip với:
    - Src_IP
    - Total_Flows (số flows từ IP này)
    - Total_Unique_Dst_IPs
    - Total_Pkts, Total_Fwd_Pkts, Total_Bwd_Pkts
    - Total_Duration
    - 6 RAW Features (F1-F6)
    """
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: File không tồn tại: {pcap_file}")
        sys.exit(1)
    
    print(f"\n{'='*70}")
    print(f"PCAP ANALYSIS TOOL - RAW VALUES OUTPUT")
    print(f"{'='*70}")
    print(f"[+] Input PCAP: {pcap_file}")
    print(f"[+] Output CSV: {output_csv}")
    print(f"[+] Verbose: {verbose}")
    print(f"{'='*70}\n")
    
    # ========================================================================
    # KHỞI TẠO COMPONENTS
    # ========================================================================
    
    # Parser: Dùng packet timestamp từ PCAP
    parser = PacketLayerExtractor(
        use_packet_time=True  # QUAN TRỌNG: Dùng timestamp từ PCAP, KHÔNG dùng thời gian máy
    )
    
    print("[✓] PacketLayerExtractor configured:")
    print("    - use_packet_time=True → Timestamps từ PCAP file")
    print("    - Timestamps phản ánh thời gian ghi trong PCAP, KHÔNG phải thời gian hiện tại\n")
    
    # FlowManager: Vô hiệu hóa sliding window (lưu toàn bộ PCAP)
    flow_manager = FlowManager(
        window_size=999999.0,      # Window rất lớn = không cleanup
        flow_timeout=999999.0,     # Timeout rất lớn = không expire
        cleanup_interval=999999    # Không cleanup trong quá trình xử lý
    )
    
    # Feature Calculator (with WAMM if model available)
    wamm = WammClassifier()
    feature_calc = FlowFeatureCalculator(wamm_classifier=wamm)
    
    # ========================================================================
    # ĐỌC VÀ XỬ LÝ PCAP
    # ========================================================================
    
    print("[*] Reading PCAP file...")
    processed_count = 0
    first_timestamp = None
    last_timestamp = None
    
    try:
        with PcapReader(pcap_file) as pcap_reader:
            for pkt in pcap_reader:
                try:
                    # Parse packet
                    info = parser.extract(pkt, processed_count)
                    
                    if info is None or not info.has_ip:
                        continue
                    
                    # Track timestamps
                    if first_timestamp is None:
                        first_timestamp = info.timestamp
                    last_timestamp = info.timestamp
                    
                    # Process packet vào FlowManager
                    flow_manager.process_packet(info)
                    processed_count += 1
                    
                    # Progress display
                    if processed_count % 1000 == 0:
                        sys.stdout.write(f"\r[*] Processed: {processed_count} packets...")
                        sys.stdout.flush()
                        
                except Exception as e:
                    # Skip malformed packets
                    continue
        
        print(f"\r[+] Total packets processed: {processed_count}")
        
    except Exception as e:
        print(f"\n[!] Error reading PCAP: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # ========================================================================
    # TẠO OUTPUT CSV - GROUP BY SRC_IP
    # ========================================================================
    
    all_flows = flow_manager.get_all_flows()
    print(f"[+] Total flows extracted: {len(all_flows)}")
    
    if first_timestamp and last_timestamp:
        duration = last_timestamp - first_timestamp
        print(f"[+] Capture duration: {duration:.2f} seconds")
    
    # Group flows by source IP
    print("\n[*] Grouping flows by source IP...")
    flows_by_src = group_flows_by_src_ip(all_flows)
    print(f"[+] Unique source IPs: {len(flows_by_src)}")
    
    # CSV Headers — 20 features matching FEATURE_ORDER (F1-F20)
    feature_names = FlowFeatureCalculator.get_feature_names()
    feature_headers = [f"{name}_RAW" for name in feature_names]

    headers = [
        # Source IP Identification (1 row per src_ip)
        "Src_IP",
        "DateTime",              # Human-readable timestamp (first packet)
        "Total_Flows",           # Số flows từ src_ip này
        "Total_Unique_Dst_IPs",  # Số dst_ip khác nhau

        # Aggregated Statistics (tổng hợp từ tất cả flows)
        "Total_Fwd_Pkts",
        "Total_Bwd_Pkts",
        "Total_Pkts",
        "Total_Duration",

        # TCP Flags Summary (from forward packets)
        "TCP_Flags",             # Format: "SYN:10,ACK:20,RST:5,FIN:2"
    ] + feature_headers
    
    rows = []
    
    print("\n[*] Calculating features per source IP...")
    
    for i, (src_ip, flows_list) in enumerate(flows_by_src.items(), 1):
        src_ip_out = anonymize_src_ip(src_ip) if ANONYMIZE_SRC_IP_FOR_TRAINING else src_ip
        # Aggregate statistics từ tất cả flows
        total_fwd = sum(f.get_fwd_packet_count() for f in flows_list)
        total_bwd = sum(f.get_bwd_packet_count() for f in flows_list)
        total_pkts = total_fwd + total_bwd
        
        # Unique destination IPs
        unique_dst_ips = len(set(f.dst_ip for f in flows_list))
        
        # Unique destination ports
        unique_dst_ports = set()
        for f in flows_list:
            unique_dst_ports.update(f.get_distinct_ports())
        dst_ports_str = ','.join(str(p) for p in sorted(unique_dst_ports)) if unique_dst_ports else "NONE"
        
        # Total duration (sum of all flow durations)
        total_duration = sum(f.duration for f in flows_list)
        
        # Get first packet timestamp for DateTime
        first_timestamp = None
        for flow in flows_list:
            all_pkts = flow.get_all_packets()
            if all_pkts and all_pkts[0].timestamp:
                first_timestamp = all_pkts[0].timestamp
                break
        
        if first_timestamp:
            dt_str = datetime.fromtimestamp(first_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        else:
            dt_str = "N/A"
        
        # Aggregate TCP Flags từ forward packets
        tcp_flags_agg = {'SYN': 0, 'ACK': 0, 'RST': 0, 'FIN': 0, 'PSH': 0, 'URG': 0}
        for flow in flows_list:
            flags = flow.get_fwd_tcp_flags_count()
            for flag_name in tcp_flags_agg.keys():
                tcp_flags_agg[flag_name] += flags.get(flag_name, 0)
        
        tcp_flags_str = ','.join([f"{k}:{v}" for k, v in tcp_flags_agg.items() if v > 0])
        if not tcp_flags_str:
            tcp_flags_str = "NONE"
        
        # Calculate 20 features RAW VALUES
        features = feature_calc.calculate_all(flows_list)

        if features is None:
            continue

        # Build row with metadata + feature values
        row = {
            "Src_IP": src_ip_out,
            "Dst_Ports": dst_ports_str,
            "DateTime": dt_str,
            "Total_Flows": len(flows_list),
            "Total_Unique_Dst_IPs": unique_dst_ips,
            "Total_Fwd_Pkts": total_fwd,
            "Total_Bwd_Pkts": total_bwd,
            "Total_Pkts": total_pkts,
            "Total_Duration": f"{total_duration:.6f}",
            "TCP_Flags": tcp_flags_str,
        }

        # Add all 20 features dynamically
        for idx, name in enumerate(feature_names):
            row[f"{name}_RAW"] = f"{features[idx]:.4f}"

        rows.append(row)

        # Verbose output
        if verbose and i <= 20:
            print(f"\n--- Source IP {i}/{len(flows_by_src)} ---")
            print(f"IP: {src_ip_out}, Time: {dt_str}")
            print(f"Flows: {len(flows_list)}, Dst IPs: {unique_dst_ips}")
            print(f"Packets: {total_pkts} (Fwd: {total_fwd}, Bwd: {total_bwd})")
            print(f"Duration: {total_duration:.3f}s, Flags: {tcp_flags_str}")
            print(f"Features ({len(features)}):")
            for idx, name in enumerate(feature_names):
                print(f"  {name}: {features[idx]:.4f}")

    print(f"\n[*] Writing output to {output_csv}...")
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[+] Successfully exported {len(rows)} source IPs")
    
    if verbose and len(rows) > 20:
        print(f"    (Displayed first 20 source IPs, {len(rows) - 20} more in CSV)")
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    
    print(f"\n{'='*70}")
    print(f"ANALYSIS COMPLETE")
    print(f"{'='*70}")
    print(f"Total Packets:   {processed_count}")
    print(f"Total Flows:     {len(all_flows)}")
    print(f"Unique Src IPs:  {len(rows)}")
    print(f"Output File:     {output_csv}")
    print(f"{'='*70}\n")
    
    print("[+] NEXT STEPS:")
    print("    1. Open the CSV file to review RAW feature values")
    print("    2. Check F3_DistinctPorts column:")
    print("       - High values (>10) = Potential Port Scanning")
    print("       - Low values (1-5) = Normal traffic")
    print("    3. Each row represents aggregated data from ONE source IP")
    print("    4. Features are calculated across ALL flows from that IP")
    print("")


def main():
    """Entry point cho PCAP analysis tool."""
    
    parser = argparse.ArgumentParser(
        description="PCAP Analysis Tool - RAW Values Output for CICFlowMeter Comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic analysis
    python main_pcap.py -p attack_test.pcap -o output.csv
    
    # Verbose mode (show first 20 flows)
    python main_pcap.py -p capture.pcap -o features.csv --verbose
    
    # Compare with CICFlowMeter
    python main_pcap.py -p data.pcap -o my_output.csv
    # Then manually compare my_output.csv with CICFlowMeter's data_Flow.csv

Output:
    CSV file with flow-level RAW feature values (not normalized)
    Format compatible with CICFlowMeter for easy comparison
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
        default="pcap_analysis_output.csv",
        metavar="FILE",
        help="Output CSV file (default: pcap_analysis_output.csv)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose: print first 20 flows details to screen"
    )
    
    args = parser.parse_args()
    
    # Run analysis
    analyze_pcap(args.pcap, args.output, args.verbose)


if __name__ == "__main__":
    main()
