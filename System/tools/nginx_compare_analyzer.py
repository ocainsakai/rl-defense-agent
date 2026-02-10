#!/usr/bin/env python3
"""
Nginx Compare Analyzer - Phân tích và so sánh traffic trước/sau Nginx
Hiển thị chi tiết packet info + metrics để thấy rõ sự khác biệt.

Usage:
    python nginx_compare_analyzer.py --before logs/before_nginx.log --after logs/after_nginx.log
    python nginx_compare_analyzer.py -b logs/before_nginx_web.log -a logs/after_nginx_web.log
"""

import re
import argparse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class PacketInfo:
    """Thông tin một packet được parse từ log"""
    packet_num: int = 0
    timestamp: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    ttl: int = 0
    protocol: str = ""
    length: int = 0
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: str = ""
    seq: int = 0
    ack: int = 0
    window: int = 0
    payload: str = ""
    payload_size: int = 0
    # HTTP specific (sau Nginx)
    x_request_id: str = ""
    x_real_ip: str = ""
    x_forwarded_for: str = ""
    http_method: str = ""
    http_path: str = ""
    user_agent: str = ""


@dataclass
class TrafficStats:
    """Thống kê traffic"""
    total_packets: int = 0
    total_bytes: int = 0
    
    # TCP Flags stats
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    
    # SYN Flood detection
    syn_only_count: int = 0  # SYN without ACK
    half_open_connections: int = 0
    
    # Port Scan detection
    unique_src_ips: set = field(default_factory=set)
    unique_dst_ports: set = field(default_factory=set)
    unique_src_ports: set = field(default_factory=set)
    
    # Time analysis
    first_packet_time: str = ""
    last_packet_time: str = ""
    duration_ms: float = 0
    
    # HTTP stats
    http_requests: int = 0
    with_x_real_ip: int = 0
    with_x_request_id: int = 0


def parse_timestamp(ts_str: str) -> datetime:
    """Parse timestamp từ log format"""
    try:
        return datetime.strptime(ts_str, "%H:%M:%S.%f")
    except:
        return datetime.now()


def parse_log_file(filepath: str) -> List[PacketInfo]:
    """Parse log file thành list of PacketInfo"""
    packets = []
    current_packet = None
    current_section = None
    payload_lines = []
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip()
            
            # New packet header
            if line.startswith("Packet #"):
                # Save previous packet
                if current_packet:
                    if payload_lines:
                        current_packet.payload = "\n".join(payload_lines)
                        parse_http_headers(current_packet)
                    packets.append(current_packet)
                
                # Start new packet
                match = re.match(r"Packet #(\d+) \| (\d{2}:\d{2}:\d{2}\.\d+)", line)
                if match:
                    current_packet = PacketInfo(
                        packet_num=int(match.group(1)),
                        timestamp=match.group(2)
                    )
                payload_lines = []
                current_section = None
                
            elif current_packet:
                # Section headers
                if line.startswith("[Ethernet]"):
                    current_section = "ethernet"
                elif line.startswith("[IP]"):
                    current_section = "ip"
                elif line.startswith("[TCP]"):
                    current_section = "tcp"
                elif line.startswith("[UDP]"):
                    current_section = "udp"
                elif line.startswith("[Payload]"):
                    current_section = "payload"
                    match = re.search(r"\((\d+) bytes\)", line)
                    if match:
                        current_packet.payload_size = int(match.group(1))
                elif line.startswith("[ARP]"):
                    current_section = "arp"
                    
                # Parse fields based on section
                elif current_section == "ethernet":
                    if "Src MAC:" in line:
                        current_packet.src_mac = line.split(":")[-1].strip()
                    elif "Dst MAC:" in line:
                        current_packet.dst_mac = line.split(":")[-1].strip()
                        
                elif current_section == "ip":
                    if "Src IP:" in line:
                        current_packet.src_ip = line.split(":")[-1].strip()
                    elif "Dst IP:" in line:
                        current_packet.dst_ip = line.split(":")[-1].strip()
                    elif "TTL:" in line:
                        current_packet.ttl = int(line.split(":")[-1].strip())
                    elif "Protocol:" in line:
                        match = re.search(r"\((\w+)\)", line)
                        if match:
                            current_packet.protocol = match.group(1)
                    elif "Length:" in line:
                        match = re.search(r"(\d+)", line.split(":")[-1])
                        if match:
                            current_packet.length = int(match.group(1))
                            
                elif current_section == "tcp":
                    if "Src Port:" in line:
                        current_packet.src_port = int(line.split(":")[-1].strip())
                    elif "Dst Port:" in line:
                        current_packet.dst_port = int(line.split(":")[-1].strip())
                    elif "Flags:" in line:
                        current_packet.tcp_flags = line.split(":")[-1].strip()
                    elif "Seq:" in line:
                        current_packet.seq = int(line.split(":")[-1].strip())
                    elif "Ack:" in line and "Flags" not in line:
                        current_packet.ack = int(line.split(":")[-1].strip())
                    elif "Window:" in line:
                        current_packet.window = int(line.split(":")[-1].strip())
                        
                elif current_section == "payload":
                    if line.strip().startswith("|"):
                        payload_lines.append(line.strip()[1:].strip())
        
        # Don't forget last packet
        if current_packet:
            if payload_lines:
                current_packet.payload = "\n".join(payload_lines)
                parse_http_headers(current_packet)
            packets.append(current_packet)
    
    return packets


def parse_http_headers(packet: PacketInfo):
    """Extract HTTP headers từ payload"""
    if not packet.payload:
        return
        
    lines = packet.payload.split("\n")
    for i, line in enumerate(lines):
        # First line - HTTP method
        if i == 0 and any(m in line for m in ["GET", "POST", "HEAD", "PUT", "DELETE"]):
            parts = line.split()
            if len(parts) >= 2:
                packet.http_method = parts[0]
                packet.http_path = parts[1]
        # Headers
        if "X-Request-ID:" in line:
            packet.x_request_id = line.split(":", 1)[-1].strip()
        elif "X-Real-IP:" in line:
            packet.x_real_ip = line.split(":", 1)[-1].strip()
        elif "X-Forwarded-For:" in line:
            packet.x_forwarded_for = line.split(":", 1)[-1].strip()
        elif "User-Agent:" in line:
            packet.user_agent = line.split(":", 1)[-1].strip()


def calculate_stats(packets: List[PacketInfo]) -> TrafficStats:
    """Tính toán thống kê từ list packets"""
    stats = TrafficStats()
    stats.total_packets = len(packets)
    
    if not packets:
        return stats
    
    stats.first_packet_time = packets[0].timestamp
    stats.last_packet_time = packets[-1].timestamp
    
    # Calculate duration
    try:
        t1 = parse_timestamp(stats.first_packet_time)
        t2 = parse_timestamp(stats.last_packet_time)
        stats.duration_ms = (t2 - t1).total_seconds() * 1000
    except:
        pass
    
    for pkt in packets:
        stats.total_bytes += pkt.length
        
        # Collect unique values
        if pkt.src_ip:
            stats.unique_src_ips.add(pkt.src_ip)
        if pkt.dst_port:
            stats.unique_dst_ports.add(pkt.dst_port)
        if pkt.src_port:
            stats.unique_src_ports.add(pkt.src_port)
        
        # TCP flags analysis
        flags = pkt.tcp_flags
        if "SYN" in flags:
            stats.syn_count += 1
            if "ACK" in flags:
                stats.syn_ack_count += 1
            else:
                stats.syn_only_count += 1
        if "ACK" in flags and "SYN" not in flags:
            stats.ack_count += 1
        if "FIN" in flags:
            stats.fin_count += 1
        if "RST" in flags:
            stats.rst_count += 1
        if "PSH" in flags:
            stats.psh_count += 1
            
        # HTTP stats
        if pkt.http_method:
            stats.http_requests += 1
        if pkt.x_real_ip:
            stats.with_x_real_ip += 1
        if pkt.x_request_id:
            stats.with_x_request_id += 1
    
    # Half-open = SYN sent but no corresponding SYN-ACK
    stats.half_open_connections = max(0, stats.syn_only_count - stats.syn_ack_count)
    
    return stats


def print_header(title: str):
    """Print section header"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")


def print_comparison_table(title: str, rows: List[tuple], highlight_diff: bool = True):
    """Print comparison table with optional highlighting"""
    print(f"\n┌{'─'*78}┐")
    print(f"│  {title:<74}  │")
    print(f"├{'─'*25}┬{'─'*25}┬{'─'*25}┤")
    print(f"│  {'Metric':<22} │  {'TRƯỚC Nginx':<22} │  {'SAU Nginx':<22} │")
    print(f"├{'─'*25}┼{'─'*25}┼{'─'*25}┤")
    
    for metric, before, after in rows:
        # Determine if values are different
        diff_marker = ""
        if highlight_diff:
            if str(before) != str(after):
                diff_marker = " ⚠️"
            else:
                diff_marker = " ✅"
        
        print(f"│  {metric:<22} │  {str(before):<22} │  {str(after):<19}{diff_marker} │")
    
    print(f"└{'─'*25}┴{'─'*25}┴{'─'*25}┘")


def print_packet_comparison(before_pkt: PacketInfo, after_pkt: PacketInfo):
    """Print detailed comparison of two matched packets"""
    print(f"\n{'─'*80}")
    print(f"  MATCHED PACKET - Request ID: {after_pkt.x_request_id or 'N/A'}")
    print(f"{'─'*80}")
    
    rows = [
        ("Timestamp", before_pkt.timestamp, after_pkt.timestamp),
        ("Src IP", before_pkt.src_ip, after_pkt.src_ip),
        ("Dst IP", before_pkt.dst_ip, after_pkt.dst_ip),
        ("Src Port", before_pkt.src_port, after_pkt.src_port),
        ("Dst Port", before_pkt.dst_port, after_pkt.dst_port),
        ("TCP Flags", before_pkt.tcp_flags, after_pkt.tcp_flags),
        ("Seq", before_pkt.seq, after_pkt.seq),
        ("Payload Size", before_pkt.payload_size, after_pkt.payload_size),
        ("X-Real-IP", "N/A", after_pkt.x_real_ip or "N/A"),
        ("HTTP Method", before_pkt.http_method or "N/A", after_pkt.http_method or "N/A"),
        ("HTTP Path", before_pkt.http_path[:30] if before_pkt.http_path else "N/A", 
                     after_pkt.http_path[:30] if after_pkt.http_path else "N/A"),
    ]
    
    print_comparison_table("PACKET FIELD COMPARISON", rows)


def analyze_syn_flood(before_stats: TrafficStats, after_stats: TrafficStats):
    """Analyze SYN Flood indicators"""
    print_header("SYN FLOOD ANALYSIS")
    
    # Calculate rates
    before_syn_rate = before_stats.syn_count / max(before_stats.duration_ms / 1000, 0.001) if before_stats.duration_ms > 0 else 0
    after_syn_rate = after_stats.syn_count / max(after_stats.duration_ms / 1000, 0.001) if after_stats.duration_ms > 0 else 0
    
    rows = [
        ("Total SYN packets", before_stats.syn_count, after_stats.syn_count),
        ("SYN-only (no ACK)", before_stats.syn_only_count, after_stats.syn_only_count),
        ("SYN-ACK responses", before_stats.syn_ack_count, after_stats.syn_ack_count),
        ("Half-open conns", before_stats.half_open_connections, after_stats.half_open_connections),
        ("SYN rate (pkt/s)", f"{before_syn_rate:.1f}", f"{after_syn_rate:.1f}"),
        ("RST packets", before_stats.rst_count, after_stats.rst_count),
        ("Unique Src IPs", len(before_stats.unique_src_ips), len(after_stats.unique_src_ips)),
    ]
    
    print_comparison_table("SYN FLOOD METRICS", rows)
    
    # Detection result
    is_syn_flood = before_stats.syn_only_count > 100 or before_stats.half_open_connections > 50
    
    print("\n  📊 PHÂN TÍCH:")
    if is_syn_flood:
        print("  ⚠️  SYN FLOOD DETECTED trước Nginx!")
        print(f"      - {before_stats.syn_only_count} SYN packets không có ACK")
        print(f"      - {before_stats.half_open_connections} half-open connections")
        if after_stats.syn_count == 0:
            print("  ✅ Nginx đã CHẶN tất cả SYN flood traffic!")
        else:
            print(f"  ⚠️  {after_stats.syn_count} SYN packets vẫn qua được Nginx")
    else:
        print("  ✅ Không phát hiện SYN Flood")
    
    print("\n  💡 LƯU Ý: SYN Flood CHỈ DETECT ĐƯỢC Ở TRƯỚC NGINX!")


def analyze_port_scan(before_stats: TrafficStats, after_stats: TrafficStats):
    """Analyze Port Scanning indicators"""
    print_header("PORT SCAN ANALYSIS")
    
    # Calculate rates
    before_port_rate = len(before_stats.unique_dst_ports) / max(before_stats.duration_ms / 1000, 0.001) if before_stats.duration_ms > 0 else 0
    after_port_rate = len(after_stats.unique_dst_ports) / max(after_stats.duration_ms / 1000, 0.001) if after_stats.duration_ms > 0 else 0
    
    rows = [
        ("Unique Dst Ports", len(before_stats.unique_dst_ports), len(after_stats.unique_dst_ports)),
        ("Unique Src Ports", len(before_stats.unique_src_ports), len(after_stats.unique_src_ports)),
        ("Port scan rate (/s)", f"{before_port_rate:.1f}", f"{after_port_rate:.1f}"),
        ("RST responses", before_stats.rst_count, after_stats.rst_count),
        ("SYN packets", before_stats.syn_count, after_stats.syn_count),
        ("Total packets", before_stats.total_packets, after_stats.total_packets),
    ]
    
    print_comparison_table("PORT SCAN METRICS", rows)
    
    # Show scanned ports
    if len(before_stats.unique_dst_ports) > 1:
        ports_list = sorted(list(before_stats.unique_dst_ports))[:20]
        print(f"\n  📋 Ports scanned (trước Nginx): {ports_list}")
        if len(before_stats.unique_dst_ports) > 20:
            print(f"      ... và {len(before_stats.unique_dst_ports) - 20} ports khác")
    
    if len(after_stats.unique_dst_ports) > 0:
        ports_list = sorted(list(after_stats.unique_dst_ports))
        print(f"  📋 Ports visible (sau Nginx): {ports_list}")
    
    # Detection result
    is_port_scan = len(before_stats.unique_dst_ports) > 10
    
    print("\n  📊 PHÂN TÍCH:")
    if is_port_scan:
        print(f"  ⚠️  PORT SCAN DETECTED trước Nginx!")
        print(f"      - {len(before_stats.unique_dst_ports)} unique ports được scan")
        print(f"      - {before_stats.rst_count} RST responses (closed ports)")
        if len(after_stats.unique_dst_ports) <= 2:
            print("  ✅ Sau Nginx chỉ thấy traffic đến backend port!")
    else:
        print("  ✅ Không phát hiện Port Scan")
    
    print("\n  💡 LƯU Ý: Port Scan CHỈ DETECT ĐƯỢC Ở TRƯỚC NGINX!")


def analyze_general_traffic(before_stats: TrafficStats, after_stats: TrafficStats):
    """General traffic comparison"""
    print_header("GENERAL TRAFFIC COMPARISON")
    
    rows = [
        ("Total packets", before_stats.total_packets, after_stats.total_packets),
        ("Total bytes", before_stats.total_bytes, after_stats.total_bytes),
        ("Duration (ms)", f"{before_stats.duration_ms:.1f}", f"{after_stats.duration_ms:.1f}"),
        ("Unique Src IPs", len(before_stats.unique_src_ips), len(after_stats.unique_src_ips)),
        ("HTTP requests", before_stats.http_requests, after_stats.http_requests),
        ("With X-Real-IP", before_stats.with_x_real_ip, after_stats.with_x_real_ip),
        ("With X-Request-ID", before_stats.with_x_request_id, after_stats.with_x_request_id),
    ]
    
    print_comparison_table("TRAFFIC OVERVIEW", rows)
    
    # Show unique IPs
    print(f"\n  📋 Source IPs (trước Nginx): {list(before_stats.unique_src_ips)[:5]}")
    print(f"  📋 Source IPs (sau Nginx):   {list(after_stats.unique_src_ips)[:5]}")
    
    if after_stats.with_x_real_ip > 0:
        print("\n  ✅ X-Real-IP header được inject - có thể khôi phục IP attacker!")


def analyze_tcp_flags(before_stats: TrafficStats, after_stats: TrafficStats):
    """TCP Flags analysis"""
    print_header("TCP FLAGS ANALYSIS")
    
    rows = [
        ("SYN", before_stats.syn_count, after_stats.syn_count),
        ("SYN-ACK", before_stats.syn_ack_count, after_stats.syn_ack_count),
        ("ACK", before_stats.ack_count, after_stats.ack_count),
        ("PSH", before_stats.psh_count, after_stats.psh_count),
        ("FIN", before_stats.fin_count, after_stats.fin_count),
        ("RST", before_stats.rst_count, after_stats.rst_count),
    ]
    
    print_comparison_table("TCP FLAGS COUNT", rows)


def find_matching_packets(before_packets: List[PacketInfo], after_packets: List[PacketInfo]) -> List[tuple]:
    """Tìm các cặp packet match nhau"""
    matches = []
    
    for after_pkt in after_packets:
        if not after_pkt.x_real_ip or not after_pkt.http_path:
            continue
            
        # Tìm packet trước Nginx có cùng path và src_ip = x_real_ip
        for before_pkt in before_packets:
            if (before_pkt.src_ip == after_pkt.x_real_ip and 
                before_pkt.http_path and 
                before_pkt.http_path == after_pkt.http_path):
                matches.append((before_pkt, after_pkt))
                break
                
    return matches


def print_summary(before_stats: TrafficStats, after_stats: TrafficStats):
    """Print final summary"""
    print_header("TỔNG KẾT")
    
    print("""
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION CAPABILITY                                │
├────────────────────┬───────────────────────┬────────────────────────────────┤
│  Attack Type       │  Trước Nginx          │  Sau Nginx                     │
├────────────────────┼───────────────────────┼────────────────────────────────┤
│  SYN Flood         │  ✅ DETECT được       │  ❌ Không thấy                 │
│  Port Scan         │  ✅ DETECT được       │  ❌ Không thấy                 │
│  SQLi/XSS          │  ❌ Encrypted (HTTPS) │  ✅ DETECT được (plaintext)    │
│  Brute Force       │  ⚠️ Partial (IP only) │  ✅ DETECT được (via X-Real-IP)│
│  DDoS              │  ✅ DETECT được       │  ❌ Không thấy                 │
├────────────────────┴───────────────────────┴────────────────────────────────┤
│                                                                             │
│  📌 KHUYẾN NGHỊ:                                                            │
│     • Dùng sniffer TRƯỚC Nginx để detect: SYN Flood, Port Scan, DDoS       │
│     • Dùng sniffer SAU Nginx để detect: SQLi, XSS, Brute Force             │
│     • Parse X-Real-IP header để lấy IP thật của attacker                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
    """)


def main():
    parser = argparse.ArgumentParser(
        description="Phân tích và so sánh traffic trước/sau Nginx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
    python nginx_compare_analyzer.py -b logs/before_nginx_web.log -a logs/after_nginx_web.log
    python nginx_compare_analyzer.py --before logs/before.log --after logs/after.log --match
        """
    )
    
    parser.add_argument("-b", "--before", required=True, help="Log file TRƯỚC Nginx")
    parser.add_argument("-a", "--after", required=True, help="Log file SAU Nginx")
    parser.add_argument("-m", "--match", action="store_true", help="Hiển thị matched packets")
    parser.add_argument("-n", "--num-matches", type=int, default=3, help="Số lượng matched packets hiển thị (default: 3)")
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║           NGINX COMPARE ANALYZER - Phân tích trước/sau Nginx                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"📁 Đang đọc log TRƯỚC Nginx: {args.before}")
    before_packets = parse_log_file(args.before)
    print(f"   → Đã parse {len(before_packets)} packets")
    
    print(f"📁 Đang đọc log SAU Nginx: {args.after}")
    after_packets = parse_log_file(args.after)
    print(f"   → Đã parse {len(after_packets)} packets")
    
    # Calculate stats
    before_stats = calculate_stats(before_packets)
    after_stats = calculate_stats(after_packets)
    
    # Run analyses
    analyze_general_traffic(before_stats, after_stats)
    analyze_tcp_flags(before_stats, after_stats)
    analyze_syn_flood(before_stats, after_stats)
    analyze_port_scan(before_stats, after_stats)
    
    # Show matched packets if requested
    if args.match:
        print_header("MATCHED PACKETS (Request-by-Request)")
        matches = find_matching_packets(before_packets, after_packets)
        print(f"\n  Tìm thấy {len(matches)} cặp packet match được")
        
        for i, (before_pkt, after_pkt) in enumerate(matches[:args.num_matches]):
            print_packet_comparison(before_pkt, after_pkt)
    
    # Summary
    print_summary(before_stats, after_stats)


if __name__ == "__main__":
    main()
