#!/usr/bin/env python3
"""
test_log_reader.py - Đọc và phân tích log từ Nginx access.log và iptables.

Bao gồm:
1. Đọc nginx access.log (lab_detail format) - /tmp/router-nginx/logs/access.log
2. Đọc iptables rules và kernel log
3. Phát hiện tấn công: SQLi, XSS (Sử dụng core modules)

Usage:
    python3 test_log_reader.py /tmp/router-nginx/logs/access.log
    python3 test_log_reader.py --tail /tmp/router-nginx/logs/access.log
"""

import os
import sys
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from collections import defaultdict

# Thêm đường dẫn project root vào sys.path để import modules
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from System.core.nginx_log_sensor import NidsLogParser, NidsLogEntry
    from System.feature.payload_context import PayloadContextScorer
except ImportError:
    # Fallback nếu chạy từ thư mục System/test/ hoặc System/
    try:
        from core.nginx_log_sensor import NidsLogParser, NidsLogEntry
        from feature.payload_context import PayloadContextScorer
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Please run from project root or ensure PYTHONPATH is set.")
        sys.exit(1)

# Cấu hình logging
logging.basicConfig(level=logging.ERROR)

# Đường dẫn nginx access log trong Containernet
NGINX_ACCESS_LOG_PATH = os.environ.get(
    'NGINX_ACCESS_LOG',
    '/tmp/router-nginx/logs/access.log'
)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class NginxAccessStats:
    """Thống kê từ nginx access.log."""
    total_requests: int = 0
    total_bytes: int = 0
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    get_count: int = 0
    post_count: int = 0
    other_methods: int = 0
    unique_ips: set = field(default_factory=set)
    unique_paths: set = field(default_factory=set)
    suspicious_requests: list = field(default_factory=list)
    status_by_ip: dict = field(default_factory=lambda: defaultdict(list))
    requests_per_ip: dict = field(default_factory=lambda: defaultdict(int))


@dataclass
class IptablesRule:
    """Một rule iptables được parse."""
    chain: str = ""
    table: str = "filter"
    action: str = ""
    protocol: str = ""
    source: str = ""
    destination: str = ""
    src_port: int = 0
    dst_port: int = 0
    interface_in: str = ""
    interface_out: str = ""
    state: str = ""
    extra: str = ""


@dataclass
class IptablesLogEntry:
    """Một entry từ iptables kernel log (LOG target)."""
    timestamp: str = ""
    hostname: str = ""
    prefix: str = ""
    interface_in: str = ""
    interface_out: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""
    src_port: int = 0
    dst_port: int = 0
    ttl: int = 0
    length: int = 0
    tcp_flags: str = ""
    action_taken: str = ""


# =============================================================================
# NGINX ACCESS LOG PARSER (Wrapper around core.NidsLogParser)
# =============================================================================

def parse_nginx_access_log(filepath: str, max_lines: int = 0) -> List[NidsLogEntry]:
    """Parse nginx access.log using core.NidsLogParser.
    
    Args:
        filepath: Đường dẫn tới access.log
        max_lines: Số dòng tối đa (0 = tất cả)
    """
    entries = []
    line_count = 0

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                entry = NidsLogParser.parse_line(line)
                if entry:
                    entries.append(entry)

                line_count += 1
                if max_lines > 0 and line_count >= max_lines:
                    break
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        return []

    return entries


def tail_nginx_access_log(filepath: str, callback=None, interval: float = 1.0):
    """Đọc access.log theo kiểu tail -f (real-time).
    
    Args:
        filepath: Đường dẫn tới access.log
        callback: Function(NidsLogEntry) gọi mỗi khi có dòng mới
        interval: Thời gian chờ giữa các lần check (giây)
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(0, 2)  # Seek to end
            
            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        entry = NidsLogParser.parse_line(line)
                        if entry and callback:
                            callback(entry)
                else:
                    time.sleep(interval)
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        sys.exit(1)


def calculate_access_stats(entries: List[NidsLogEntry]) -> NginxAccessStats:
    """Tính thống kê từ nginx access log entries using core attack detection."""
    stats = NginxAccessStats()
    stats.total_requests = len(entries)

    for entry in entries:
        stats.total_bytes += entry.body_bytes_sent
        stats.unique_ips.add(entry.remote_addr)
        stats.unique_paths.add(entry.path)
        stats.requests_per_ip[entry.remote_addr] += 1
        stats.status_by_ip[entry.remote_addr].append(entry.status)

        if 200 <= entry.status < 300:
            stats.status_2xx += 1
        elif 300 <= entry.status < 400:
            stats.status_3xx += 1
        elif 400 <= entry.status < 500:
            stats.status_4xx += 1
        elif entry.status >= 500:
            stats.status_5xx += 1

        if entry.method == 'GET':
            stats.get_count += 1
        elif entry.method == 'POST':
            stats.post_count += 1
        else:
            stats.other_methods += 1

        # Security Check using PayloadContextScorer
        # PayloadContextScorer expects raw bytes
        # For Log entries, payload effectively is URI + UserAgent
        # We check URI predominantly for attacks
        
        # Check SQLi
        if entry.path:
            payload_bytes = entry.path.encode('utf-8', errors='ignore')
            
            sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
            if sqli_score > 0:
                stats.suspicious_requests.append(('SQLi', entry))
            
            xss_score = PayloadContextScorer.count_xss_indicators(payload_bytes)
            if xss_score > 0:
                stats.suspicious_requests.append(('XSS', entry))

    return stats


# =============================================================================
# IPTABLES LOG/RULE PARSER (Unchanged)
# =============================================================================
# Note: Keeping existing regex logic for iptables as no core module for it was identified
import re

def parse_iptables_rules(output: str) -> List[IptablesRule]:
    """Parse output từ `iptables -S`."""
    rules = []

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        s_match = re.match(
            r"-([AI])\s+(\w+)"
            r"(.*?)"
            r"\s+-j\s+(\w+)"
            r"(.*)?$",
            line
        )
        if s_match:
            rule = IptablesRule()
            rule.chain = s_match.group(2)
            middle = s_match.group(3)
            rule.action = s_match.group(4)
            trailing = s_match.group(5) or ""

            for pattern, attr in [
                (r"-s\s+(\S+)", "source"),
                (r"-d\s+(\S+)", "destination"),
                (r"-p\s+(\w+)", "protocol"),
                (r"-i\s+(\S+)", "interface_in"),
                (r"-o\s+(\S+)", "interface_out"),
                (r"--state\s+(\S+)", "state"),
            ]:
                m = re.search(pattern, middle)
                if m:
                    setattr(rule, attr, m.group(1))

            for pattern, attr in [
                (r"--sport\s+(\d+)", "src_port"),
                (r"--dport\s+(\d+)", "dst_port"),
            ]:
                m = re.search(pattern, middle)
                if m:
                    setattr(rule, attr, int(m.group(1)))

            limit_m = re.search(r"--limit\s+(\S+)", middle)
            if limit_m:
                rule.extra = f"limit={limit_m.group(1)}"

            to_dest_m = re.search(r"--to-destination\s+(\S+)", trailing)
            if to_dest_m:
                rule.extra += f" to-dest={to_dest_m.group(1)}"

            rules.append(rule)

    return rules


def parse_iptables_kernel_log(log_content: str) -> List[IptablesLogEntry]:
    """Parse kernel log entries từ iptables LOG target."""
    entries = []

    for line in log_content.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        entry = IptablesLogEntry()

        ts_match = re.match(r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+kernel:", line)
        if ts_match:
            entry.timestamp = ts_match.group(1)
            entry.hostname = ts_match.group(2)

        prefix_match = re.search(r"\[(\w+)\]", line)
        if prefix_match:
            entry.prefix = prefix_match.group(1)
            if "DROP" in entry.prefix:
                entry.action_taken = "DROPPED"
            elif "ACCEPT" in entry.prefix:
                entry.action_taken = "ACCEPTED"
            elif "BLOCK" in entry.prefix:
                entry.action_taken = "BLOCKED"
            elif "REDIRECT" in entry.prefix:
                entry.action_taken = "REDIRECTED"

        for key, attr in [
            ("SRC", "src_ip"), ("DST", "dst_ip"),
            ("IN", "interface_in"), ("OUT", "interface_out"),
            ("PROTO", "protocol"),
        ]:
            m = re.search(rf"{key}=(\S+)", line)
            if m:
                setattr(entry, attr, m.group(1))

        for key, attr in [
            ("SPT", "src_port"), ("DPT", "dst_port"),
            ("TTL", "ttl"), ("LEN", "length"),
        ]:
            m = re.search(rf"{key}=(\d+)", line)
            if m:
                setattr(entry, attr, int(m.group(1)))

        tcp_flags = []
        for flag in ["SYN", "ACK", "FIN", "RST", "PSH", "URG"]:
            if re.search(rf"\b{flag}\b", line):
                tcp_flags.append(flag)
        if tcp_flags:
            entry.tcp_flags = ",".join(tcp_flags)

        if entry.src_ip or entry.prefix:
            entries.append(entry)

    return entries


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Chạy trực tiếp từ command line."""
    import argparse
    parser = argparse.ArgumentParser(description='Nginx & IPTables Log Reader (Refactored)')
    parser.add_argument('logfile', nargs='?', default=NGINX_ACCESS_LOG_PATH,
                        help=f'Path to access.log (default: {NGINX_ACCESS_LOG_PATH})')
    parser.add_argument('--tail', action='store_true', help='Tail -f mode (real-time)')
    parser.add_argument('--max-lines', type=int, default=0, help='Max lines to read')
    args = parser.parse_args()

    filepath = args.logfile
    
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        # Try creating dummy log file for testing if user provided 'System/test/dummy_access.log'
        if 'dummy_access.log' in filepath:
             print("ℹ️  Tip: Use write_to_file to create dummy_access.log first.")
        sys.exit(1)

    # Tail mode
    if args.tail:
        print(f"👁️  Tailing {filepath} (Ctrl+C to stop)...")
        def on_entry(entry):
            icon = "✅" if entry.status < 400 else "⚠️" if entry.status < 500 else "❌"
            print(f"{icon} {entry.time_local} | {entry.remote_addr:>15} | "
                  f"{entry.method:4} {entry.path:<40} | {entry.status} | "
                  f"{entry.body_bytes_sent}B | {entry.user_agent}")
        try:
            tail_nginx_access_log(filepath, on_entry, interval=0.5)
        except KeyboardInterrupt:
            print("\n🛑 Stopped.")
        return

    # Parse & analyze
    print(f"📄 Reading: {filepath}")
    entries = parse_nginx_access_log(filepath, max_lines=args.max_lines)
    
    if not entries:
        print("⚠️  No entries parsed. Kiểm tra định dạng log (yêu cầu lab_detail format).")
        sys.exit(1)

    stats = calculate_access_stats(entries)

    print(f"\n{'='*60}")
    print(f"📊 NGINX ACCESS LOG ANALYSIS (Core Modules)")
    print(f"{'='*60}")
    print(f"  File:            {filepath}")
    print(f"  Total requests:  {stats.total_requests}")
    print(f"  Total bytes:     {stats.total_bytes:,}")
    print(f"\n  --- Status Codes ---")
    print(f"  2xx: {stats.status_2xx} | 3xx: {stats.status_3xx} | "
          f"4xx: {stats.status_4xx} | 5xx: {stats.status_5xx}")
    print(f"\n  --- Methods ---")
    print(f"  GET: {stats.get_count} | POST: {stats.post_count} | Other: {stats.other_methods}")
    print(f"\n  --- Top IPs ---")
    for ip, count in sorted(stats.requests_per_ip.items(), key=lambda x: -x[1])[:10]:
        err_count = sum(1 for s in stats.status_by_ip[ip] if s >= 400)
        flag = " ⚠️" if err_count > 3 else ""
        print(f"    {ip:>15}: {count:>4} requests ({err_count} errors){flag}")

    if stats.suspicious_requests:
        print(f"\n{'='*60}")
        print(f"🚨 SUSPICIOUS REQUESTS ({len(stats.suspicious_requests)})")
        print(f"{'='*60}")
        for attack_type, entry in stats.suspicious_requests:
            print(f"  [{attack_type:>15}] {entry.remote_addr} {entry.method} {entry.path}")
            print(f"                    -> {entry.status} | {entry.user_agent}")
    else:
        print(f"\n✅ No suspicious requests detected")

    print(f"\n  --- Last 10 Requests ---")
    for e in entries[-10:]:
        icon = "✅" if e.status < 400 else "⚠️" if e.status < 500 else "❌"
        # Truncate path for display
        display_path = (e.path[:50] + '..') if len(e.path) > 50 else e.path
        print(f"  {icon} {e.time_local} {e.remote_addr} {e.method:4} {display_path} -> {e.status}")


if __name__ == "__main__":
    main()
