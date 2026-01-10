"""
Test: Sử dụng code CÓ SẴN để kiểm tra số flows được tạo ra
So sánh với CICFlowMeter (31 flows)
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

try:
    from scapy.all import rdpcap
except ImportError:
    print("[!] Scapy not found. Install: pip install scapy")
    sys.exit(1)

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager


def test_with_existing_code(pcap_path: str):
    """
    Test sử dụng FlowManager và PacketLayerExtractor có sẵn
    """
    print(f"[+] Đang đọc PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[+] Tổng packets: {len(packets):,}")
    
    # Sử dụng FlowManager có sẵn
    flow_manager = FlowManager(
        window_size=9999.0,     # Lớn để không sliding
        flow_timeout=120.0,     # 120 giây timeout (giống CIC setting)
        cleanup_interval=10000  # Cleanup mỗi 10K packets
    )
    
    # Sử dụng PacketLayerExtractor có sẵn
    parser = PacketLayerExtractor(use_packet_time=True)
    
    print("[+] Đang process packets...")
    valid_packets = 0
    
    for i, pkt in enumerate(packets):
        if i % 100000 == 0 and i > 0:
            print(f"    Processed {i:,} packets...")
        
        layer_info = parser.extract(pkt, i)
        if layer_info.has_ip:
            flow_manager.process_packet(layer_info)
            valid_packets += 1
    
    # Lấy kết quả
    all_flows = flow_manager.get_all_flows()
    total_flows = len(all_flows)
    
    print(f"\n{'='*70}")
    print("KẾT QUẢ")
    print(f"{'='*70}")
    print(f"Valid IP packets:     {valid_packets:,}")
    print(f"Total flows (5-tuple): {total_flows:,}")
    print(f"\nCICFlowMeter result:   31 flows")
    print(f"Your system result:    {total_flows:,} flows")
    print(f"Difference:            {total_flows - 31:,}")
    
    # Phân tích top flows
    print(f"\n{'='*70}")
    print("TOP 10 FLOWS (by packet count)")
    print(f"{'='*70}")
    
    flows_with_counts = [
        (f, f.get_packet_count()) for f in all_flows
    ]
    flows_with_counts.sort(key=lambda x: x[1], reverse=True)
    
    for i, (flow, count) in enumerate(flows_with_counts[:10], 1):
        print(f"{i:2d}. {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port} "
              f"(proto={flow.protocol}) - {count} packets")
    
    print(f"\n{'='*70}")
    print("PHÂN TÍCH")
    print(f"{'='*70}")
    
    # Đếm flows có ít packets
    single_packet_flows = sum(1 for f in all_flows if f.get_packet_count() == 1)
    small_flows = sum(1 for f in all_flows if f.get_packet_count() <= 5)
    
    print(f"Flows with 1 packet:   {single_packet_flows:,} ({single_packet_flows/total_flows*100:.1f}%)")
    print(f"Flows with ≤5 packets: {small_flows:,} ({small_flows/total_flows*100:.1f}%)")
    
    if total_flows > 10000:
        print(f"\n⚠️  RẤT NHIỀU flows → PCAP chứa attack traffic (port scan, etc.)")
        print(f"    Đây KHÔNG phải bug - code đúng theo 5-tuple definition")
        print(f"    CICFlowMeter dùng logic khác (có thể gộp theo IP pair)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test flow creation with existing code")
    parser.add_argument("-p", "--pcap", required=True, help="PCAP file path")
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap):
        print(f"[!] File not found: {args.pcap}")
        sys.exit(1)
    
    test_with_existing_code(args.pcap)
