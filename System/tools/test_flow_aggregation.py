"""
Test: So sánh 2 cách tạo flow_key
1. Strict 5-tuple (code hiện tại)
2. IP-pair based (bỏ qua ports - giống CIC có thể dùng)

Run: python tools/test_flow_aggregation.py -p path/to/file.pcap
"""

import os
import sys

# Ensure project root in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Import after path setup
try:
    from scapy.all import rdpcap
except ImportError:
    print("[!] Scapy not found. Please install: pip install scapy")
    sys.exit(1)

from core.packet_parser import PacketLayerExtractor
from collections import defaultdict


def analyze_with_5tuple(pcap_path: str, limit: int = None):
    """Phân tích với 5-tuple (hiện tại)"""
    print("    Reading PCAP...")
    packets = rdpcap(pcap_path)
    if limit:
        packets = packets[:limit]
    
    parser = PacketLayerExtractor(use_packet_time=True)
    flows_5tuple = set()
    
    for i, pkt in enumerate(packets):
        layer_info = parser.extract(pkt, i)
        if not layer_info.has_ip:
            continue
        
        src_port = layer_info.tcp_sport or layer_info.udp_sport or 0
        dst_port = layer_info.tcp_dport or layer_info.udp_dport or 0
        
        # 5-tuple
        flow_key = (
            layer_info.src_ip,
            layer_info.dst_ip,
            src_port,
            dst_port,
            layer_info.protocol
        )
        flows_5tuple.add(flow_key)
        
        # Reverse key (bidirectional)
        reverse_key = (
            layer_info.dst_ip,
            layer_info.src_ip,
            dst_port,
            src_port,
            layer_info.protocol
        )
        if reverse_key in flows_5tuple:
            # Không thêm vào, dùng reverse_key đã có
            pass
        else:
            flows_5tuple.add(flow_key)
    
    return len(flows_5tuple)


def analyze_with_ip_pair(pcap_path: str, limit: int = None):
    """Phân tích với IP-pair (bỏ qua ports - giống CIC)"""
    packets = rdpcap(pcap_path)
    if limit:
        packets = packets[:limit]
    
    parser = PacketLayerExtractor(use_packet_time=True)
    flows_ip = set()
    
    for i, pkt in enumerate(packets):
        layer_info = parser.extract(pkt, i)
        if not layer_info.has_ip:
            continue
        
        # Chỉ dùng IP pair (+ protocol)
        flow_key = (
            layer_info.src_ip,
            layer_info.dst_ip,
            layer_info.protocol
        )
        
        # Check bidirectional
        reverse_key = (
            layer_info.dst_ip,
            layer_info.src_ip,
            layer_info.protocol
        )
        
        if reverse_key not in flows_ip:
            flows_ip.add(flow_key)
    
    return len(flows_ip)


def analyze_with_ip_only(pcap_path: str, limit: int = None):
    """Phân tích chỉ với IP pair (bỏ cả protocol)"""
    packets = rdpcap(pcap_path)
    if limit:
        packets = packets[:limit]
    
    parser = PacketLayerExtractor(use_packet_time=True)
    flows_ip = set()
    
    for i, pkt in enumerate(packets):
        layer_info = parser.extract(pkt, i)
        if not layer_info.has_ip:
            continue
        
        # Chỉ dùng IP pair
        flow_key = (
            min(layer_info.src_ip, layer_info.dst_ip),
            max(layer_info.src_ip, layer_info.dst_ip)
        )
        flows_ip.add(flow_key)
    
    return len(flows_ip)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", required=True, help="PCAP file")
    parser.add_argument("-l", "--limit", type=int, help="Limit packets")
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap):
        print(f"[!] File not found: {args.pcap}")
        return
    
    print("=" * 70)
    print("SO SÁNH CÁC PHƯƠNG PHÁP TẠO FLOW")
    print("=" * 70)
    print(f"PCAP: {args.pcap}")
    
    if args.limit:
        print(f"Analyzing first {args.limit} packets...\n")
    else:
        print("Analyzing all packets...\n")
    
    # Method 1: 5-tuple (hiện tại)
    print("[1] 5-Tuple (src_ip, dst_ip, src_port, dst_port, protocol)")
    count_5tuple = analyze_with_5tuple(args.pcap, args.limit)
    print(f"    → Total flows: {count_5tuple}\n")
    
    # Method 2: IP-pair + protocol
    print("[2] IP-Pair + Protocol (src_ip, dst_ip, protocol)")
    count_ip_proto = analyze_with_ip_pair(args.pcap, args.limit)
    print(f"    → Total flows: {count_ip_proto}\n")
    
    # Method 3: IP-pair only
    print("[3] IP-Pair Only (src_ip, dst_ip)")
    count_ip_only = analyze_with_ip_only(args.pcap, args.limit)
    print(f"    → Total flows: {count_ip_only}\n")
    
    print("=" * 70)
    print("KẾT LUẬN")
    print("=" * 70)
    print(f"CICFlowMeter: 31 flows")
    print(f"Method 1 (5-tuple):        {count_5tuple} flows")
    print(f"Method 2 (IP+proto):       {count_ip_proto} flows")
    print(f"Method 3 (IP only):        {count_ip_only} flows")
    
    if count_ip_proto == 31:
        print("\n✅ Method 2 (IP+proto) MATCH với CICFlowMeter!")
    elif count_ip_only == 31:
        print("\n✅ Method 3 (IP only) MATCH với CICFlowMeter!")
    else:
        print(f"\n⚠️  Không có method nào match chính xác 31 flows")
        print(f"    CICFlowMeter có thể dùng logic khác (timeout, windowing, etc.)")


if __name__ == "__main__":
    main()
