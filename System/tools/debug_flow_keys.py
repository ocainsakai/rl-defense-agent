"""
Debug script để phân tích tại sao flow_key bị sai.
"""

import os
import sys
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scapy.all import rdpcap
from core.packet_parser import PacketLayerExtractor


def debug_flow_keys(pcap_path: str, limit: int = 100):
    print(f"[+] Đang đọc file: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[+] Tổng số packets: {len(packets)}")
    
    parser = PacketLayerExtractor(use_packet_time=True)
    
    flow_keys = []
    sample_keys = []
    
    # Phân tích từng packet
    null_ports = 0
    null_ips = 0
    
    for i, pkt in enumerate(packets[:limit]):
        layer_info = parser.extract(pkt, i)
        
        if not layer_info.has_ip:
            continue
        
        src_port = layer_info.tcp_sport or layer_info.udp_sport or 0
        dst_port = layer_info.tcp_dport or layer_info.udp_dport or 0
        
        if src_port == 0 or dst_port == 0:
            null_ports += 1
        if not layer_info.src_ip or not layer_info.dst_ip:
            null_ips += 1
        
        flow_key = (
            layer_info.src_ip or '',
            layer_info.dst_ip or '',
            src_port,
            dst_port,
            layer_info.protocol or 0
        )
        
        flow_keys.append(flow_key)
        
        # Sample đầu tiên
        if i < 20:
            sample_keys.append({
                'pkt': i,
                'src_ip': layer_info.src_ip,
                'dst_ip': layer_info.dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': layer_info.protocol,
                'has_tcp': layer_info.has_tcp,
                'has_udp': layer_info.has_udp,
                'flow_key': flow_key,
            })
    
    # Thống kê
    unique_keys = len(set(flow_keys))
    
    print(f"\n===== THỐNG KÊ (đầu {limit} packets) =====")
    print(f"Packets analyzed: {len(flow_keys)}")
    print(f"Unique flow_keys: {unique_keys}")
    print(f"Packets với null ports: {null_ports}")
    print(f"Packets với null IPs: {null_ips}")
    print(f"Ratio (packets/flows): {len(flow_keys)/unique_keys:.2f}")
    
    print(f"\n===== SAMPLE FLOW KEYS (20 đầu tiên) =====")
    for s in sample_keys:
        print(f"Pkt {s['pkt']:3d}: {s['src_ip']}:{s['src_port']} → {s['dst_ip']}:{s['dst_port']} (proto={s['protocol']}, tcp={s['has_tcp']}, udp={s['has_udp']})")
    
    # Đếm flow_key phổ biến nhất
    counter = Counter(flow_keys)
    print(f"\n===== TOP 10 FLOW KEYS =====")
    for flow_key, count in counter.most_common(10):
        print(f"  Count={count:5d}: {flow_key}")
    
    # Kiểm tra xem có nhiều flow với port 0 không
    zero_port_flows = [k for k in flow_keys if k[2] == 0 or k[3] == 0]
    print(f"\n===== PACKETS VỚI PORT = 0 =====")
    print(f"Total: {len(zero_port_flows)}")
    
    # NEW: Phân tích tại sao có nhiều unique flow_keys
    print(f"\n===== PHÂN TÍCH UNIQUE FLOW_KEYS =====")
    
    # Đếm unique IP pairs (bỏ qua ports)
    ip_pairs = [(k[0], k[1]) for k in flow_keys]
    unique_ip_pairs = len(set(ip_pairs))
    print(f"Unique IP pairs (ignore ports): {unique_ip_pairs}")
    
    # Đếm unique src_ports
    src_ports = [k[2] for k in flow_keys]
    unique_src_ports = len(set(src_ports))
    print(f"Unique source ports: {unique_src_ports}")
    
    # Đếm unique dst_ports
    dst_ports = [k[3] for k in flow_keys]
    unique_dst_ports = len(set(dst_ports))
    print(f"Unique destination ports: {unique_dst_ports}")
    
    # Phân bố theo IP pair
    ip_pair_counter = Counter(ip_pairs)
    print(f"\n===== TOP 10 IP PAIRS (ignore ports) =====")
    for ip_pair, count in ip_pair_counter.most_common(10):
        print(f"  Count={count:5d}: {ip_pair[0]} → {ip_pair[1]}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", required=True, help="PCAP file path")
    parser.add_argument("-l", "--limit", type=int, default=1000, help="Số packets để analyze")
    args = parser.parse_args()
    
    debug_flow_keys(args.pcap, args.limit)
