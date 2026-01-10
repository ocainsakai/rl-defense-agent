"""
Script so sánh raw values giữa hệ thống của bạn và CICFlowMeter.
SỬ DỤNG CÁC HÀM ĐÃ CÓ SẴN trong codebase.

CÁCH SỬ DỤNG:
1. Chạy CICFlowMeter trên PCAP file:
   java -jar CICFlowMeter.jar capture.pcap -c output_cic/

2. Chạy script này:
   python tools/compare_with_cic.py -p capture.pcap -o output.csv

3. So sánh output CSV với file CSV của CICFlowMeter
"""

import os
import sys
import csv
import argparse

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scapy.all import rdpcap
from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState


def analyze_pcap_with_existing_functions(pcap_path: str, output_csv: str):
    """
    Phân tích PCAP SỬ DỤNG CÁC HÀM ĐÃ CÓ SẴN và xuất ra CSV.
    """
    print(f"[+] Đang đọc file: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[+] Tổng số packets: {len(packets)}")
    
    # 1. PacketLayerExtractor - Parse Scapy packet → LayerInfo
    parser = PacketLayerExtractor(use_packet_time=True)
    
    # 2. FlowManager - Quản lý flows với bidirectional tracking
    flow_manager = FlowManager(
        window_size=9999.0,
        flow_timeout=9999.0,
        cleanup_interval=99999
    )
    
    # 3. Process từng packet qua FlowManager
    print("[+] Đang xử lý packets...")
    for i, pkt in enumerate(packets):
        layer_info = parser.extract(pkt, i)
        if layer_info.has_ip:
            flow_manager.process_packet(layer_info)
    
    all_flows = flow_manager.get_all_flows()
    print(f"[+] Tổng số flows: {len(all_flows)}")
    
    # ========================================================================
    # XUẤT RA CSV
    # ========================================================================
    
    headers = [
        "Flow_ID",
        "Src_IP",
        "Src_Port",
        "Dst_IP", 
        "Dst_Port",
        "Protocol",
        "Fwd_Pkts",
        "Bwd_Pkts",
        "Total_Pkts",
        "Fwd_Payload_Mean",
        "Bwd_Payload_Mean",
        "Fwd_SYN",
        "Fwd_ACK",
        "Fwd_RST",
        "Fwd_FIN",
        "Bwd_SYN",
        "Bwd_ACK",
        "Bwd_RST",
        "Bwd_FIN",
        "Total_SYN",
        "Total_RST",
        "Total_ACK",
        "Distinct_Ports",
    ]
    
    rows = []
    
    for flow in all_flows:
        # Packet counts
        fwd_count = flow.get_fwd_packet_count()
        bwd_count = flow.get_bwd_packet_count()
        total_pkts = fwd_count + bwd_count
        
        # Payload lengths
        fwd_lengths = flow.get_fwd_payload_lengths()
        bwd_lengths = flow.get_bwd_payload_lengths()
        fwd_mean = sum(fwd_lengths) / len(fwd_lengths) if fwd_lengths else 0
        bwd_mean = sum(bwd_lengths) / len(bwd_lengths) if bwd_lengths else 0
        
        # TCP Flags - FORWARD
        fwd_flags = flow.get_fwd_tcp_flags_count()
        
        # TCP Flags - BACKWARD
        bwd_flags = flow.get_bwd_tcp_flags_count()
        
        # Totals (để so sánh với CICFlowMeter)
        total_syn = fwd_flags['SYN'] + bwd_flags['SYN']
        total_rst = fwd_flags['RST'] + bwd_flags['RST']
        total_ack = fwd_flags['ACK'] + bwd_flags['ACK']
        
        # Distinct ports
        distinct_ports = len(flow.get_distinct_ports())
        
        # Flow ID format giống CICFlowMeter
        flow_id = f"{flow.src_ip}-{flow.dst_ip}-{flow.src_port}-{flow.dst_port}-{flow.protocol}"
        
        row = {
            "Flow_ID": flow_id,
            "Src_IP": flow.src_ip,
            "Src_Port": flow.src_port,
            "Dst_IP": flow.dst_ip,
            "Dst_Port": flow.dst_port,
            "Protocol": flow.protocol,
            "Fwd_Pkts": fwd_count,
            "Bwd_Pkts": bwd_count,
            "Total_Pkts": total_pkts,
            "Fwd_Payload_Mean": round(fwd_mean, 2),
            "Bwd_Payload_Mean": round(bwd_mean, 2),
            "Fwd_SYN": fwd_flags['SYN'],
            "Fwd_ACK": fwd_flags['ACK'],
            "Fwd_RST": fwd_flags['RST'],
            "Fwd_FIN": fwd_flags['FIN'],
            "Bwd_SYN": bwd_flags['SYN'],
            "Bwd_ACK": bwd_flags['ACK'],
            "Bwd_RST": bwd_flags['RST'],
            "Bwd_FIN": bwd_flags['FIN'],
            "Total_SYN": total_syn,
            "Total_RST": total_rst,
            "Total_ACK": total_ack,
            "Distinct_Ports": distinct_ports,
        }
        rows.append(row)
    
    # Ghi ra CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[+] Đã xuất {len(rows)} flows ra file: {output_csv}")
    print(f"""
[+] HƯỚNG DẪN SO SÁNH:
    - Mở file {output_csv} và file CICFlowMeter CSV
    - So sánh các cột:
      * Total_SYN ↔ SYN Flag Cnt (CIC)
      * Total_RST ↔ RST Flag Cnt (CIC)  
      * Fwd_Payload_Mean ↔ Fwd Pkt Len Mean (CIC)
      * Fwd_Pkts ↔ Total Fwd Packets (CIC)
""")


def main():
    parser = argparse.ArgumentParser(description="So sánh raw values với CICFlowMeter")
    parser.add_argument("-p", "--pcap", required=True, help="Đường dẫn file PCAP")
    parser.add_argument("-o", "--output", default="compare_output.csv", help="File CSV output (mặc định: compare_output.csv)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap):
        print(f"[!] Không tìm thấy file: {args.pcap}")
        sys.exit(1)
    
    analyze_pcap_with_existing_functions(args.pcap, args.output)


if __name__ == "__main__":
    main()

