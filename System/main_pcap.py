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
from feature.feature_flow import FlowFeatureCalculator


def analyze_pcap(pcap_file: str, output_csv: str, verbose: bool = False):
    """
    Phân tích PCAP file và tính toán 6 features RAW values cho mỗi flow.
    
    Args:
        pcap_file (str): Đường dẫn file PCAP
        output_csv (str): Đường dẫn file CSV output
        verbose (bool): In chi tiết flows ra màn hình
    
    LOGIC:
    1. Đọc toàn bộ PCAP
    2. Parse packets → LayerInfo
    3. Map packets vào flows (5-tuple)
    4. Tính 6 features RAW cho MỖI FLOW
    5. Export CSV với format giống CICFlowMeter
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
        enable_http_parsing=True,  # Enable để detect HTTP status codes cho F5
        use_packet_time=True       # Dùng PCAP timestamp
    )
    
    # FlowManager: Vô hiệu hóa sliding window (lưu toàn bộ PCAP)
    flow_manager = FlowManager(
        window_size=999999.0,      # Window rất lớn = không cleanup
        flow_timeout=999999.0,     # Timeout rất lớn = không expire
        cleanup_interval=999999    # Không cleanup trong quá trình xử lý
    )
    
    # Feature Calculator
    feature_calc = FlowFeatureCalculator()
    
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
    # TẠO OUTPUT CSV
    # ========================================================================
    
    all_flows = flow_manager.get_all_flows()
    print(f"[+] Total flows extracted: {len(all_flows)}")
    
    if first_timestamp and last_timestamp:
        duration = last_timestamp - first_timestamp
        print(f"[+] Capture duration: {duration:.2f} seconds")
    
    # CSV Headers
    headers = [
        # Flow Identification
        "Flow_ID",
        "Src_IP",
        "Dst_IP", 
        "Src_Port",
        "Dst_Port",
        "Protocol",
        
        # Flow Statistics
        "Duration",
        "Total_Fwd_Pkts",
        "Total_Bwd_Pkts",
        "Total_Pkts",
        
        # RAW Features (6 features)
        "F1_PacketRate_RAW",
        "F2_SynRatio_RAW",
        "F3_DistinctPorts_RAW",
        "F4_PayloadLen_RAW",
        "F5_FailRate_RAW",
        "F6_ContextScore_RAW",
    ]
    
    rows = []
    
    print("\n[*] Calculating features for each flow...")
    
    for i, flow in enumerate(all_flows, 1):
        # Flow identification
        flow_id = f"{flow.src_ip}-{flow.dst_ip}-{flow.src_port}-{flow.dst_port}-{flow.protocol}"
        
        # Protocol name
        proto_name = "TCP" if flow.protocol == 6 else ("UDP" if flow.protocol == 17 else "OTHER")
        
        # Flow statistics
        fwd_count = flow.get_fwd_packet_count()
        bwd_count = flow.get_bwd_packet_count()
        total_pkts = fwd_count + bwd_count
        
        # Duration (from first to last packet in flow)
        all_packets = flow.get_all_packets()
        if all_packets:
            timestamps = [p.timestamp for p in all_packets if p.timestamp]
            if timestamps:
                flow_duration = max(timestamps) - min(timestamps)
            else:
                flow_duration = 0.0
        else:
            flow_duration = 0.0
        
        # Calculate 6 features RAW VALUES
        # Để tính features cho 1 flow, ta cần pass list chứa flow đó
        # (vì FlowFeatureCalculator.calculate_all() nhận List[FlowState])
        features = feature_calc.calculate_all([flow])
        
        if features is None:
            # Flow rỗng - skip
            continue
        
        # Unpack 6 features
        f1_packet_rate = features[0]
        f2_syn_ratio = features[1]
        f3_distinct_ports = features[2]
        f4_payload_len = features[3]
        f5_fail_rate = features[4]
        f6_context_score = features[5]
        
        # Tạo row
        row = {
            "Flow_ID": flow_id,
            "Src_IP": flow.src_ip,
            "Dst_IP": flow.dst_ip,
            "Src_Port": flow.src_port,
            "Dst_Port": flow.dst_port,
            "Protocol": proto_name,
            "Duration": f"{flow_duration:.6f}",
            "Total_Fwd_Pkts": fwd_count,
            "Total_Bwd_Pkts": bwd_count,
            "Total_Pkts": total_pkts,
            "F1_PacketRate_RAW": f"{f1_packet_rate:.4f}",
            "F2_SynRatio_RAW": f"{f2_syn_ratio:.4f}",
            "F3_DistinctPorts_RAW": f"{f3_distinct_ports:.4f}",
            "F4_PayloadLen_RAW": f"{f4_payload_len:.4f}",
            "F5_FailRate_RAW": f"{f5_fail_rate:.4f}",
            "F6_ContextScore_RAW": f"{f6_context_score:.4f}",
        }
        rows.append(row)
        
        # Verbose output
        if verbose and i <= 20:
            print(f"\n--- Flow {i} ---")
            print(f"ID: {flow_id}")
            print(f"Packets: {total_pkts} (Fwd: {fwd_count}, Bwd: {bwd_count})")
            print(f"Duration: {flow_duration:.3f}s")
            print(f"Features: F1={f1_packet_rate:.2f}, F2={f2_syn_ratio:.2f}, "
                  f"F3={f3_distinct_ports:.0f}, F4={f4_payload_len:.2f}, "
                  f"F5={f5_fail_rate:.2f}, F6={f6_context_score:.2f}")
    
    # Ghi ra CSV
    print(f"\n[*] Writing output to {output_csv}...")
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[+] Successfully exported {len(rows)} flows")
    
    if verbose and len(rows) > 20:
        print(f"    (Displayed first 20 flows, {len(rows) - 20} more in CSV)")
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    
    print(f"\n{'='*70}")
    print(f"ANALYSIS COMPLETE")
    print(f"{'='*70}")
    print(f"Total Packets:  {processed_count}")
    print(f"Total Flows:    {len(rows)}")
    print(f"Output File:    {output_csv}")
    print(f"{'='*70}\n")
    
    print("[+] NEXT STEPS:")
    print("    1. Open the CSV file to review RAW feature values")
    print("    2. Compare with CICFlowMeter output:")
    print(f"       - Your file: {output_csv}")
    print(f"       - CIC file:  {os.path.splitext(pcap_file)[0]}_Flow.csv")
    print("    3. Verify that logic is correct by comparing:")
    print("       - Total_Fwd_Pkts, Total_Bwd_Pkts")
    print("       - F2_SynRatio (SYN / (SYN + ACK))")
    print("       - F4_PayloadLen (average payload)")
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
