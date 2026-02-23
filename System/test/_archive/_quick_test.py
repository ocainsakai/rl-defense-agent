"""Quick test for test_log_reader.py - chạy xong tự xóa."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test.test_log_reader import (
    parse_nginx_access_log, _parse_access_line, calculate_access_stats,
    parse_iptables_rules, parse_iptables_kernel_log
)

errors = 0

# --- Test 1: Parse single line ---
print("Test 1: Parse single access line...", end=" ")
e = _parse_access_line('10.0.10.10 - - [13/Feb/2026:06:00:01 +0000] "GET /login HTTP/1.1" 200 3180 "-" "curl/8.5.0"')
assert e is not None, "Failed to parse"
assert e.remote_addr == "10.0.10.10"
assert e.method == "GET"
assert e.path == "/login"
assert e.status == 200
assert e.body_bytes_sent == 3180
assert e.user_agent == "curl/8.5.0"
assert e.timestamp > 0
print("✅")

# --- Test 2: Parse access log file ---
print("Test 2: Parse access log file...", end=" ")
lines = [
    '10.0.10.10 - - [13/Feb/2026:06:00:01 +0000] "GET / HTTP/1.1" 200 3180 "-" "curl/8.5.0"',
    '10.0.10.10 - - [13/Feb/2026:06:00:02 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.5.0"',
    '10.0.10.10 - - [13/Feb/2026:06:00:03 +0000] "GET /admin HTTP/1.1" 403 187 "-" "curl/8.5.0"',
    '10.0.10.10 - - [13/Feb/2026:06:00:04 +0000] "GET /page?id=1%27%20OR%201=1%20-- HTTP/1.1" 200 3180 "-" "sqlmap/1.7"',
    '10.0.10.10 - - [13/Feb/2026:06:00:05 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 150 "-" "Mozilla/5.0"',
    '10.0.10.10 - - [13/Feb/2026:06:00:06 +0000] "GET /../../etc/passwd HTTP/1.1" 400 150 "-" "curl/8.5.0"',
]
with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False, encoding='utf-8') as f:
    f.write("\n".join(lines) + "\n")
    tmpfile = f.name

entries = parse_nginx_access_log(tmpfile)
assert len(entries) == 6, f"Expected 6, got {len(entries)}"
os.unlink(tmpfile)
print(f"✅ ({len(entries)} entries parsed)")

# --- Test 3: Stats ---
print("Test 3: Calculate stats...", end=" ")
stats = calculate_access_stats(entries)
assert stats.total_requests == 6
assert stats.status_2xx >= 2
assert stats.status_4xx >= 2
assert stats.get_count >= 5
assert stats.post_count >= 1
print(f"✅ (2xx:{stats.status_2xx} 3xx:{stats.status_3xx} 4xx:{stats.status_4xx})")

# --- Test 4: Attack detection ---
print("Test 4: Detect attacks...", end=" ")
sqli = [s for s in stats.suspicious_requests if s[0] == 'SQLi']
xss = [s for s in stats.suspicious_requests if s[0] == 'XSS']
traversal = [s for s in stats.suspicious_requests if s[0] == 'Path Traversal']
assert len(sqli) >= 1, "No SQLi detected"
assert len(xss) >= 1, "No XSS detected"
assert len(traversal) >= 1, "No Path Traversal detected"
print(f"✅ (SQLi:{len(sqli)} XSS:{len(xss)} Traversal:{len(traversal)})")

# --- Test 5: max_lines ---
print("Test 5: max_lines limit...", end=" ")
with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False, encoding='utf-8') as f:
    f.write("\n".join(lines) + "\n")
    tmpfile = f.name
limited = parse_nginx_access_log(tmpfile, max_lines=2)
assert len(limited) == 2
os.unlink(tmpfile)
print("✅")

# --- Test 6: iptables rules ---
print("Test 6: Parse iptables rules...", end=" ")
rules_text = """-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -s 10.0.10.0/24 -d 192.168.20.20 -j DROP
-A INPUT -s 192.168.1.100 -j DROP
-I INPUT -p tcp --dport 443 -j ACCEPT
-A PREROUTING -s 10.0.10.10 -j DNAT --to-destination 192.168.30.10"""
rules = parse_iptables_rules(rules_text)
assert len(rules) == 5, f"Expected 5, got {len(rules)}"
drop_rules = [r for r in rules if r.action == "DROP"]
assert len(drop_rules) == 2
print(f"✅ ({len(rules)} rules, {len(drop_rules)} DROP)")

# --- Test 7: iptables kernel log ---
print("Test 7: Parse iptables kernel log...", end=" ")
klog = """Feb 13 10:00:01 server kernel: [IPTABLES_DROP] IN=eth0 OUT= SRC=10.0.10.10 DST=192.168.10.10 LEN=60 TTL=64 PROTO=TCP SPT=54321 DPT=443 WINDOW=65535 SYN
Feb 13 10:00:02 server kernel: [NIDS_BLOCK] IN=eth0 OUT= SRC=10.0.10.10 DST=192.168.10.10 LEN=44 TTL=50 PROTO=TCP SPT=61946 DPT=3306 WINDOW=1024 SYN
Feb 13 10:00:03 server kernel: [IPTABLES_ACCEPT] IN=eth0 OUT=eth1 SRC=192.168.10.10 DST=10.0.10.10 LEN=52 TTL=64 PROTO=TCP SPT=443 DPT=54321 SYN ACK"""
log_entries = parse_iptables_kernel_log(klog)
assert len(log_entries) == 3, f"Expected 3, got {len(log_entries)}"
assert log_entries[0].action_taken == "DROPPED"
assert log_entries[1].action_taken == "BLOCKED"
assert log_entries[2].action_taken == "ACCEPTED"
print(f"✅ ({len(log_entries)} entries)")

print(f"\n{'='*40}")
print(f"✅ ALL {7} TESTS PASSED")
print(f"{'='*40}")
