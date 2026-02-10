#!/usr/bin/env python3
"""
Realtime Nginx Compare Sniffer - So sánh traffic trước/sau Nginx realtime
Chạy 2 sniffer song song và hiển thị so sánh ngay khi bắt được packet.

Usage:
    sudo python3 realtime_nginx_compare.py --before r-ext --after r-web
    sudo python3 realtime_nginx_compare.py -b r-ext -a r-web -d 60
    sudo python3 realtime_nginx_compare.py -b r-ext -a r-web --log-dir ./logs
"""

import argparse
import threading
import time
import queue
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether

# Thread-safe queues for packet exchange
before_queue = queue.Queue(maxsize=10000)
after_queue = queue.Queue(maxsize=10000)

# Shared state
running = True
start_time = None

# Log file handles
before_log_file = None
after_log_file = None
stats_log_file = None
comparison_log_file = None
log_lock = threading.Lock()


@dataclass
class PacketInfo:
    """Thông tin packet"""
    timestamp: float = 0
    timestamp_str: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: str = ""
    seq: int = 0
    ack: int = 0
    payload_size: int = 0
    payload: bytes = b""
    # HTTP headers (sau Nginx)
    x_request_id: str = ""
    x_real_ip: str = ""
    http_method: str = ""
    http_path: str = ""


@dataclass 
class RealtimeStats:
    """Thống kê realtime"""
    total_packets: int = 0
    total_bytes: int = 0
    syn_count: int = 0
    syn_only_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    psh_count: int = 0
    unique_src_ips: set = field(default_factory=set)
    unique_dst_ports: set = field(default_factory=set)
    http_requests: int = 0
    with_x_real_ip: int = 0
    
    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.syn_count = 0
        self.syn_only_count = 0
        self.syn_ack_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.fin_count = 0
        self.psh_count = 0
        self.unique_src_ips = set()
        self.unique_dst_ports = set()
        self.http_requests = 0
        self.with_x_real_ip = 0


# Global stats
before_stats = RealtimeStats()
after_stats = RealtimeStats()

# Buffer for matching packets
before_buffer: Dict[str, PacketInfo] = {}  # key = src_ip + path
after_buffer: Dict[str, PacketInfo] = {}   # key = x_real_ip + path

# Packet counters
before_packet_count = 0
after_packet_count = 0
matched_count = 0

# Lock for thread safety
stats_lock = threading.Lock()
buffer_lock = threading.Lock()


def format_tcp_flags(tcp) -> str:
    """Format TCP flags"""
    flags = []
    if tcp.flags.S: flags.append("SYN")
    if tcp.flags.A: flags.append("ACK")
    if tcp.flags.F: flags.append("FIN")
    if tcp.flags.R: flags.append("RST")
    if tcp.flags.P: flags.append("PSH")
    if tcp.flags.U: flags.append("URG")
    return "[" + ",".join(flags) + "]" if flags else "[]"


def extract_http_info(payload: bytes) -> dict:
    """Extract HTTP headers từ payload"""
    result = {
        "x_request_id": "",
        "x_real_ip": "",
        "http_method": "",
        "http_path": ""
    }
    
    try:
        text = payload.decode('utf-8', errors='ignore')
        lines = text.split('\r\n')
        
        for i, line in enumerate(lines):
            if i == 0:
                # First line - HTTP method
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"]:
                    result["http_method"] = parts[0]
                    result["http_path"] = parts[1]
            elif "X-Request-ID:" in line:
                result["x_request_id"] = line.split(":", 1)[-1].strip()
            elif "X-Real-IP:" in line:
                result["x_real_ip"] = line.split(":", 1)[-1].strip()
    except:
        pass
    
    return result


def extract_packet_info(pkt) -> Optional[PacketInfo]:
    """Extract thông tin từ packet"""
    if not pkt.haslayer(IP):
        return None
    
    ip = pkt[IP]
    info = PacketInfo(
        timestamp=time.time(),
        timestamp_str=datetime.now().strftime("%H:%M:%S.%f")[:-3],
        src_ip=ip.src,
        dst_ip=ip.dst
    )
    
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info.src_port = tcp.sport
        info.dst_port = tcp.dport
        info.tcp_flags = format_tcp_flags(tcp)
        info.seq = tcp.seq
        info.ack = tcp.ack
        
        if pkt.haslayer(Raw):
            info.payload = bytes(pkt[Raw].load)
            info.payload_size = len(info.payload)
            
            # Parse HTTP
            http_info = extract_http_info(info.payload)
            info.x_request_id = http_info["x_request_id"]
            info.x_real_ip = http_info["x_real_ip"]
            info.http_method = http_info["http_method"]
            info.http_path = http_info["http_path"]
    
    return info


def update_stats(stats: RealtimeStats, pkt_info: PacketInfo):
    """Cập nhật thống kê"""
    stats.total_packets += 1
    stats.total_bytes += pkt_info.payload_size
    
    if pkt_info.src_ip:
        stats.unique_src_ips.add(pkt_info.src_ip)
    if pkt_info.dst_port:
        stats.unique_dst_ports.add(pkt_info.dst_port)
    
    flags = pkt_info.tcp_flags
    if "SYN" in flags:
        stats.syn_count += 1
        if "ACK" in flags:
            stats.syn_ack_count += 1
        else:
            stats.syn_only_count += 1
    if "ACK" in flags and "SYN" not in flags:
        stats.ack_count += 1
    if "RST" in flags:
        stats.rst_count += 1
    if "FIN" in flags:
        stats.fin_count += 1
    if "PSH" in flags:
        stats.psh_count += 1
    
    if pkt_info.http_method:
        stats.http_requests += 1
    if pkt_info.x_real_ip:
        stats.with_x_real_ip += 1


def format_packet_log_line(location: str, pkt_info: PacketInfo) -> str:
    """Format packet info thành log line"""
    flags = pkt_info.tcp_flags
    payload_preview = ""
    if pkt_info.http_method:
        payload_preview = f" | {pkt_info.http_method} {pkt_info.http_path}"
    if pkt_info.x_real_ip:
        payload_preview += f" | X-Real-IP: {pkt_info.x_real_ip}"
    if pkt_info.x_request_id:
        payload_preview += f" | X-Request-ID: {pkt_info.x_request_id}"

    return (f"[{location}] {pkt_info.timestamp_str} | "
            f"{pkt_info.src_ip}:{pkt_info.src_port} -> {pkt_info.dst_ip}:{pkt_info.dst_port} "
            f"{flags}{payload_preview}")


def format_packet_detailed(location: str, pkt_info: PacketInfo, packet_num: int = 0) -> str:
    """Format packet với thông tin chi tiết đầy đủ"""
    lines = []
    lines.append("=" * 70)
    lines.append(f"Packet #{packet_num} | {pkt_info.timestamp_str} | {location}")
    lines.append("=" * 70)
    lines.append("[IP]")
    lines.append(f"  Src IP:   {pkt_info.src_ip}")
    lines.append(f"  Dst IP:   {pkt_info.dst_ip}")

    if pkt_info.src_port or pkt_info.dst_port:
        lines.append("[TCP]")
        lines.append(f"  Src Port: {pkt_info.src_port}")
        lines.append(f"  Dst Port: {pkt_info.dst_port}")
        lines.append(f"  Flags:    {pkt_info.tcp_flags}")
        lines.append(f"  Seq:      {pkt_info.seq}")
        lines.append(f"  Ack:      {pkt_info.ack}")

    if pkt_info.payload_size > 0:
        lines.append(f"[Payload] ({pkt_info.payload_size} bytes)")
        if pkt_info.http_method:
            # Parse HTTP payload
            try:
                text = pkt_info.payload.decode('utf-8', errors='ignore')
                http_lines = text.split('\r\n')[:15]  # First 15 lines
                for line in http_lines:
                    if line.strip():
                        lines.append(f"  | {line}")
            except:
                lines.append(f"  | (binary data)")

    lines.append("")
    return "\n".join(lines)


def format_matched_packets_detailed(before_pkt: PacketInfo, after_pkt: PacketInfo, match_num: int = 0) -> str:
    """Format matched packets với highlight thay đổi"""
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append(f"🔗 MATCHED PAIR #{match_num}")
    lines.append("=" * 70)

    # Request info
    lines.append(f"Request: {after_pkt.http_method} {after_pkt.http_path}")
    if after_pkt.x_request_id:
        lines.append(f"X-Request-ID: {after_pkt.x_request_id}")

    lines.append("\n" + "-" * 70)
    lines.append("COMPARISON TABLE:")
    lines.append("-" * 70)
    lines.append(f"{'Field':<20} | {'BEFORE Nginx':<22} | {'AFTER Nginx':<22}")
    lines.append("-" * 70)

    # Compare fields
    comparisons = [
        ("Timestamp", before_pkt.timestamp_str, after_pkt.timestamp_str),
        ("Src IP", before_pkt.src_ip, after_pkt.src_ip),
        ("Dst IP", before_pkt.dst_ip, after_pkt.dst_ip),
        ("Src Port", str(before_pkt.src_port), str(after_pkt.src_port)),
        ("Dst Port", str(before_pkt.dst_port), str(after_pkt.dst_port)),
        ("TCP Flags", before_pkt.tcp_flags, after_pkt.tcp_flags),
        ("Seq", str(before_pkt.seq), str(after_pkt.seq)),
        ("Ack", str(before_pkt.ack), str(after_pkt.ack)),
        ("Payload Size", str(before_pkt.payload_size), str(after_pkt.payload_size)),
    ]

    for field, before, after in comparisons:
        if before != after:
            marker = " [CHANGED]"
        else:
            marker = ""
        lines.append(f"{field:<20} | {before:<22} | {after:<22}{marker}")

    # Extra headers added by Nginx
    lines.append("-" * 70)
    lines.append("NGINX ADDED HEADERS:")
    lines.append("-" * 70)
    lines.append(f"X-Real-IP:           | {'(not set)':<22} | {after_pkt.x_real_ip or 'N/A':<22}")
    if after_pkt.x_request_id:
        lines.append(f"X-Request-ID:        | {'(not set)':<22} | {after_pkt.x_request_id:<22}")

    lines.append("=" * 70)
    lines.append("")

    return "\n".join(lines)


def log_packet(location: str, pkt_info: PacketInfo, packet_num: int = 0):
    """Ghi packet vào log file với format chi tiết"""
    global before_log_file, after_log_file

    # Detailed log
    detailed_log = format_packet_detailed(location, pkt_info, packet_num)

    with log_lock:
        if location == "BEFORE" and before_log_file:
            before_log_file.write(detailed_log + "\n")
            before_log_file.flush()
        elif location == "AFTER" and after_log_file:
            after_log_file.write(detailed_log + "\n")
            after_log_file.flush()


def log_matched_packets(before_pkt: PacketInfo, after_pkt: PacketInfo, match_num: int):
    """Ghi matched packets vào cả 2 log files với comparison"""
    global before_log_file, after_log_file, comparison_log_file

    comparison_log = format_matched_packets_detailed(before_pkt, after_pkt, match_num)

    with log_lock:
        # Log to separate comparison file if available
        if comparison_log_file:
            comparison_log_file.write(comparison_log)
            comparison_log_file.flush()
        # Also log to both before and after files
        if before_log_file:
            before_log_file.write(comparison_log)
            before_log_file.flush()
        if after_log_file:
            after_log_file.write(comparison_log)
            after_log_file.flush()


def print_packet_simple(location: str, pkt_info: PacketInfo, packet_num: int = 0):
    """In thông tin packet đơn giản"""
    flags = pkt_info.tcp_flags
    payload_preview = ""
    if pkt_info.http_method:
        payload_preview = f" | {pkt_info.http_method} {pkt_info.http_path[:30]}"

    print(f"[{location}] #{packet_num} {pkt_info.timestamp_str} | "
          f"{pkt_info.src_ip}:{pkt_info.src_port} → {pkt_info.dst_ip}:{pkt_info.dst_port} "
          f"{flags}{payload_preview}")

    # Also log to file
    log_packet(location, pkt_info, packet_num)


def print_matched_comparison(before_pkt: PacketInfo, after_pkt: PacketInfo):
    """In so sánh khi match được 2 packet"""
    print("\n" + "="*80)
    print("  🔗 MATCHED PACKET COMPARISON")
    print("="*80)
    
    print(f"\n  Request: {after_pkt.http_method} {after_pkt.http_path}")
    print(f"  X-Request-ID: {after_pkt.x_request_id or 'N/A'}")
    
    print(f"\n  {'Field':<15} │ {'TRƯỚC Nginx':<25} │ {'SAU Nginx':<25} │ Match?")
    print(f"  {'─'*15}─┼─{'─'*25}─┼─{'─'*25}─┼─{'─'*6}")
    
    comparisons = [
        ("Timestamp", before_pkt.timestamp_str, after_pkt.timestamp_str),
        ("Src IP", before_pkt.src_ip, after_pkt.src_ip),
        ("Dst IP", before_pkt.dst_ip, after_pkt.dst_ip),
        ("Src Port", str(before_pkt.src_port), str(after_pkt.src_port)),
        ("Dst Port", str(before_pkt.dst_port), str(after_pkt.dst_port)),
        ("TCP Flags", before_pkt.tcp_flags, after_pkt.tcp_flags),
        ("Seq", str(before_pkt.seq), str(after_pkt.seq)),
        ("Payload Size", str(before_pkt.payload_size), str(after_pkt.payload_size)),
    ]
    
    for field, before, after in comparisons:
        match = "✅" if before == after else "❌"
        print(f"  {field:<15} │ {before:<25} │ {after:<25} │ {match}")
    
    # Extra info only in after
    print(f"  {'X-Real-IP':<15} │ {'N/A':<25} │ {after_pkt.x_real_ip:<25} │ ←IP gốc")
    
    print("="*80 + "\n")


def try_match_packets():
    """Thử match packets giữa 2 buffer"""
    global before_buffer, after_buffer
    
    with buffer_lock:
        matched = []
        
        for key, after_pkt in list(after_buffer.items()):
            if not after_pkt.x_real_ip or not after_pkt.http_path:
                continue
            
            # Tạo key để tìm trong before_buffer
            before_key = f"{after_pkt.x_real_ip}|{after_pkt.http_path}"
            
            if before_key in before_buffer:
                before_pkt = before_buffer[before_key]
                matched.append((before_pkt, after_pkt))
                
                # Remove from buffers
                del before_buffer[before_key]
                del after_buffer[key]
        
        return matched


def sniffer_before(interface: str):
    """Sniffer cho traffic TRƯỚC Nginx"""
    global running, before_stats, before_buffer, before_packet_count

    def packet_callback(pkt):
        global before_packet_count
        if not running:
            return

        pkt_info = extract_packet_info(pkt)
        if not pkt_info:
            return

        with stats_lock:
            update_stats(before_stats, pkt_info)
            before_packet_count += 1
            pkt_num = before_packet_count

        # Add to buffer for matching
        if pkt_info.http_path:
            key = f"{pkt_info.src_ip}|{pkt_info.http_path}"
            with buffer_lock:
                before_buffer[key] = pkt_info

        print_packet_simple("BEFORE", pkt_info, pkt_num)
    
    print(f"[BEFORE] 📡 Bắt đầu sniff trên {interface}...")
    
    try:
        sniff(
            iface=interface,
            filter="ip",
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: not running
        )
    except Exception as e:
        print(f"[BEFORE] ❌ Lỗi: {e}")


def sniffer_after(interface: str):
    """Sniffer cho traffic SAU Nginx"""
    global running, after_stats, after_buffer, after_packet_count, matched_count

    def packet_callback(pkt):
        global after_packet_count, matched_count
        if not running:
            return

        pkt_info = extract_packet_info(pkt)
        if not pkt_info:
            return

        with stats_lock:
            update_stats(after_stats, pkt_info)
            after_packet_count += 1
            pkt_num = after_packet_count

        # Add to buffer for matching
        if pkt_info.x_real_ip and pkt_info.http_path:
            key = f"{pkt_info.x_real_ip}|{pkt_info.http_path}"
            with buffer_lock:
                after_buffer[key] = pkt_info

        print_packet_simple("AFTER ", pkt_info, pkt_num)

        # Try to match
        matches = try_match_packets()
        for before_pkt, after_pkt in matches:
            with stats_lock:
                matched_count += 1
                match_num = matched_count
            print_matched_comparison(before_pkt, after_pkt)
            # Log matched packets to files
            log_matched_packets(before_pkt, after_pkt, match_num)
    
    print(f"[AFTER ] 📡 Bắt đầu sniff trên {interface}...")
    
    try:
        sniff(
            iface=interface,
            filter="ip",
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: not running
        )
    except Exception as e:
        print(f"[AFTER ] ❌ Lỗi: {e}")


def print_realtime_stats():
    """In thống kê định kỳ"""
    global running, before_stats, after_stats, start_time
    
    while running:
        time.sleep(5)  # Mỗi 5 giây in stats
        
        if not running:
            break
        
        elapsed = time.time() - start_time
        
        with stats_lock:
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║           REALTIME NGINX COMPARE - Live Statistics                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
            """)
            
            print(f"  ⏱️  Running: {elapsed:.0f}s | Press Ctrl+C to stop\n")
            
            print(f"┌{'─'*35}┬{'─'*20}┬{'─'*20}┐")
            print(f"│  {'Metric':<32} │ {'TRƯỚC Nginx':<18} │ {'SAU Nginx':<18} │")
            print(f"├{'─'*35}┼{'─'*20}┼{'─'*20}┤")
            
            rows = [
                ("Total Packets", before_stats.total_packets, after_stats.total_packets),
                ("Packets/sec", f"{before_stats.total_packets/max(elapsed,1):.1f}", 
                               f"{after_stats.total_packets/max(elapsed,1):.1f}"),
                ("─"*30, "─"*15, "─"*15),
                ("SYN (total)", before_stats.syn_count, after_stats.syn_count),
                ("SYN-only (no ACK)", before_stats.syn_only_count, after_stats.syn_only_count),
                ("SYN-ACK", before_stats.syn_ack_count, after_stats.syn_ack_count),
                ("RST", before_stats.rst_count, after_stats.rst_count),
                ("─"*30, "─"*15, "─"*15),
                ("Unique Src IPs", len(before_stats.unique_src_ips), len(after_stats.unique_src_ips)),
                ("Unique Dst Ports", len(before_stats.unique_dst_ports), len(after_stats.unique_dst_ports)),
                ("HTTP Requests", before_stats.http_requests, after_stats.http_requests),
                ("With X-Real-IP", before_stats.with_x_real_ip, after_stats.with_x_real_ip),
            ]
            
            for metric, before, after in rows:
                if metric.startswith("─"):
                    print(f"├{'─'*35}┼{'─'*20}┼{'─'*20}┤")
                else:
                    # Highlight differences
                    diff = ""
                    if str(before) != str(after):
                        diff = " ⚠️"
                    print(f"│  {metric:<32} │ {str(before):<18} │ {str(after):<15}{diff} │")
            
            print(f"└{'─'*35}┴{'─'*20}┴{'─'*20}┘")
            
            # Detection alerts
            print("\n  📊 DETECTION STATUS:")
            
            # SYN Flood
            if before_stats.syn_only_count > 50:
                print(f"  ⚠️  SYN FLOOD: {before_stats.syn_only_count} SYN-only packets detected!")
            else:
                print("  ✅ SYN Flood: Normal")
            
            # Port Scan
            if len(before_stats.unique_dst_ports) > 10:
                print(f"  ⚠️  PORT SCAN: {len(before_stats.unique_dst_ports)} unique ports scanned!")
            else:
                print("  ✅ Port Scan: Normal")
            
            # Show IPs
            print(f"\n  📋 Source IPs (before): {list(before_stats.unique_src_ips)[:3]}")
            print(f"  📋 Source IPs (after):  {list(after_stats.unique_src_ips)[:3]}")


def main():
    global running, start_time
    
    parser = argparse.ArgumentParser(
        description="Realtime so sánh traffic trước/sau Nginx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
    sudo python3 realtime_nginx_compare.py -b r-ext -a r-web
    sudo python3 realtime_nginx_compare.py --before r-ext --after r-web --no-clear
        """
    )
    
    parser.add_argument("-b", "--before", required=True, help="Interface TRƯỚC Nginx (VD: r-ext)")
    parser.add_argument("-a", "--after", required=True, help="Interface SAU Nginx (VD: r-web)")
    parser.add_argument("--no-clear", action="store_true", help="Không clear screen khi update stats")
    parser.add_argument("-d", "--duration", type=int, default=0, help="Thời gian chạy (giây, 0=unlimited)")
    parser.add_argument("--log-dir", type=str, default="", help="Thư mục lưu log files (VD: ./logs)")
    parser.add_argument("--log-before", type=str, default="", help="File log cho traffic TRƯỚC Nginx")
    parser.add_argument("--log-after", type=str, default="", help="File log cho traffic SAU Nginx")
    parser.add_argument("--log-stats", type=str, default="", help="File log cho stats summary")
    parser.add_argument("--log-comparison", type=str, default="", help="File log cho matched packet comparisons")

    args = parser.parse_args()

    # Setup log files
    global before_log_file, after_log_file, stats_log_file, comparison_log_file
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)
        before_log_path = os.path.join(args.log_dir, f"before_nginx_{timestamp_str}.log")
        after_log_path = os.path.join(args.log_dir, f"after_nginx_{timestamp_str}.log")
        stats_log_path = os.path.join(args.log_dir, f"stats_{timestamp_str}.log")
        comparison_log_path = os.path.join(args.log_dir, f"comparison_{timestamp_str}.log")
        before_log_file = open(before_log_path, "w", encoding="utf-8")
        after_log_file = open(after_log_path, "w", encoding="utf-8")
        stats_log_file = open(stats_log_path, "w", encoding="utf-8")
        comparison_log_file = open(comparison_log_path, "w", encoding="utf-8")
        print(f"  📝 Logging to: {args.log_dir}/")
    else:
        if args.log_before:
            before_log_file = open(args.log_before, "w", encoding="utf-8")
            print(f"  📝 Before log: {args.log_before}")
        if args.log_after:
            after_log_file = open(args.log_after, "w", encoding="utf-8")
            print(f"  📝 After log: {args.log_after}")
        if args.log_stats:
            stats_log_file = open(args.log_stats, "w", encoding="utf-8")
            print(f"  📝 Stats log: {args.log_stats}")
        if args.log_comparison:
            comparison_log_file = open(args.log_comparison, "w", encoding="utf-8")
            print(f"  📝 Comparison log: {args.log_comparison}")
    
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║       REALTIME NGINX COMPARE SNIFFER - So sánh trước/sau Nginx               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Chạy 2 sniffer song song và so sánh packets realtime                        ║
║  Press Ctrl+C to stop                                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"  📡 Interface TRƯỚC Nginx: {args.before}")
    print(f"  📡 Interface SAU Nginx:   {args.after}")
    print(f"  ⏱️  Duration: {'Unlimited' if args.duration == 0 else f'{args.duration}s'}")
    
    # Write log headers
    if before_log_file:
        before_log_file.write(f"# Realtime Nginx Compare - BEFORE Nginx Log\n")
        before_log_file.write(f"# Interface: {args.before}\n")
        before_log_file.write(f"# Started: {datetime.now().isoformat()}\n")
        before_log_file.write("#" + "="*78 + "\n\n")
    if after_log_file:
        after_log_file.write(f"# Realtime Nginx Compare - AFTER Nginx Log\n")
        after_log_file.write(f"# Interface: {args.after}\n")
        after_log_file.write(f"# Started: {datetime.now().isoformat()}\n")
        after_log_file.write("#" + "="*78 + "\n\n")
    if comparison_log_file:
        comparison_log_file.write(f"# Realtime Nginx Compare - MATCHED PACKET COMPARISONS\n")
        comparison_log_file.write(f"# Interface Before: {args.before}\n")
        comparison_log_file.write(f"# Interface After: {args.after}\n")
        comparison_log_file.write(f"# Started: {datetime.now().isoformat()}\n")
        comparison_log_file.write(f"# This file shows side-by-side comparisons of matched packets\n")
        comparison_log_file.write("#" + "="*78 + "\n\n")
    
    print("\n" + "="*80 + "\n")
    
    start_time = time.time()
    
    # Start sniffer threads
    before_thread = threading.Thread(target=sniffer_before, args=(args.before,), daemon=True)
    after_thread = threading.Thread(target=sniffer_after, args=(args.after,), daemon=True)
    
    before_thread.start()
    after_thread.start()
    
    # Start stats printer (optional - can be noisy)
    # stats_thread = threading.Thread(target=print_realtime_stats, daemon=True)
    # stats_thread.start()
    
    try:
        if args.duration > 0:
            time.sleep(args.duration)
            running = False
        else:
            while running:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n⏹️  Stopping...")
        running = False
    
    # Wait for threads
    time.sleep(1)
    
    # Print final summary
    elapsed = time.time() - start_time
    
    print("\n" + "="*80)
    print("  FINAL SUMMARY")
    print("="*80)
    
    print(f"\n  Duration: {elapsed:.1f} seconds\n")
    
    print(f"  {'Metric':<25} │ {'TRƯỚC Nginx':<15} │ {'SAU Nginx':<15}")
    print(f"  {'─'*25}─┼─{'─'*15}─┼─{'─'*15}")
    
    with stats_lock:
        final_rows = [
            ("Total Packets", before_stats.total_packets, after_stats.total_packets),
            ("SYN-only", before_stats.syn_only_count, after_stats.syn_only_count),
            ("Unique Dst Ports", len(before_stats.unique_dst_ports), len(after_stats.unique_dst_ports)),
            ("HTTP Requests", before_stats.http_requests, after_stats.http_requests),
            ("With X-Real-IP", before_stats.with_x_real_ip, after_stats.with_x_real_ip),
        ]
        
        for metric, before, after in final_rows:
            diff = "⚠️" if str(before) != str(after) else "✅"
            print(f"  {metric:<25} │ {str(before):<15} │ {str(after):<15} {diff}")
    
    # Write stats to log file
    if stats_log_file:
        write_stats_log(elapsed)
    
    # Close log files
    if before_log_file:
        before_log_file.write(f"\n# Ended: {datetime.now().isoformat()}\n")
        before_log_file.write(f"# Total packets: {before_stats.total_packets}\n")
        before_log_file.close()
        print(f"  📝 Before log saved")
    if after_log_file:
        after_log_file.write(f"\n# Ended: {datetime.now().isoformat()}\n")
        after_log_file.write(f"# Total packets: {after_stats.total_packets}\n")
        after_log_file.close()
        print(f"  📝 After log saved")
    if comparison_log_file:
        comparison_log_file.write(f"\n# Ended: {datetime.now().isoformat()}\n")
        comparison_log_file.write(f"# Total matched pairs: {matched_count}\n")
        comparison_log_file.close()
        print(f"  📝 Comparison log saved ({matched_count} matched pairs)")
    if stats_log_file:
        stats_log_file.close()
        print(f"  📝 Stats log saved")

    print("\n  ✅ Done!")


def write_stats_log(elapsed: float):
    """Ghi stats vào log file"""
    global stats_log_file, before_stats, after_stats
    
    if not stats_log_file:
        return
    
    stats_log_file.write(f"# Realtime Nginx Compare - Stats Summary\n")
    stats_log_file.write(f"# Generated: {datetime.now().isoformat()}\n")
    stats_log_file.write(f"# Duration: {elapsed:.1f} seconds\n")
    stats_log_file.write("#" + "="*78 + "\n\n")
    
    stats_log_file.write(f"{'Metric':<30} | {'BEFORE Nginx':<20} | {'AFTER Nginx':<20}\n")
    stats_log_file.write(f"{'-'*30}-+-{'-'*20}-+-{'-'*20}\n")
    
    with stats_lock:
        rows = [
            ("Total Packets", before_stats.total_packets, after_stats.total_packets),
            ("Total Bytes", before_stats.total_bytes, after_stats.total_bytes),
            ("Packets/sec", f"{before_stats.total_packets/max(elapsed,1):.2f}", 
                           f"{after_stats.total_packets/max(elapsed,1):.2f}"),
            ("", "", ""),
            ("SYN (total)", before_stats.syn_count, after_stats.syn_count),
            ("SYN-only (no ACK)", before_stats.syn_only_count, after_stats.syn_only_count),
            ("SYN-ACK", before_stats.syn_ack_count, after_stats.syn_ack_count),
            ("ACK (no SYN)", before_stats.ack_count, after_stats.ack_count),
            ("RST", before_stats.rst_count, after_stats.rst_count),
            ("FIN", before_stats.fin_count, after_stats.fin_count),
            ("PSH", before_stats.psh_count, after_stats.psh_count),
            ("", "", ""),
            ("Unique Src IPs", len(before_stats.unique_src_ips), len(after_stats.unique_src_ips)),
            ("Unique Dst Ports", len(before_stats.unique_dst_ports), len(after_stats.unique_dst_ports)),
            ("HTTP Requests", before_stats.http_requests, after_stats.http_requests),
            ("With X-Real-IP", before_stats.with_x_real_ip, after_stats.with_x_real_ip),
        ]
        
        for metric, before, after in rows:
            if metric == "":
                stats_log_file.write("\n")
            else:
                diff = "*" if str(before) != str(after) else ""
                stats_log_file.write(f"{metric:<30} | {str(before):<20} | {str(after):<20} {diff}\n")
        
        # Detection summary
        stats_log_file.write("\n" + "="*72 + "\n")
        stats_log_file.write("DETECTION SUMMARY\n")
        stats_log_file.write("="*72 + "\n\n")
        
        # SYN Flood detection
        if before_stats.syn_only_count > 50:
            stats_log_file.write(f"[ALERT] SYN FLOOD DETECTED: {before_stats.syn_only_count} SYN-only packets\n")
        else:
            stats_log_file.write(f"[OK] SYN Flood: Normal ({before_stats.syn_only_count} SYN-only)\n")
        
        # Port Scan detection
        if len(before_stats.unique_dst_ports) > 10:
            stats_log_file.write(f"[ALERT] PORT SCAN DETECTED: {len(before_stats.unique_dst_ports)} unique ports\n")
        else:
            stats_log_file.write(f"[OK] Port Scan: Normal ({len(before_stats.unique_dst_ports)} ports)\n")
        
        # Source IPs
        stats_log_file.write(f"\nSource IPs (before): {list(before_stats.unique_src_ips)}\n")
        stats_log_file.write(f"Source IPs (after):  {list(after_stats.unique_src_ips)}\n")


if __name__ == "__main__":
    main()
