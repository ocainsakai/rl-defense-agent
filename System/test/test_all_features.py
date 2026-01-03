# -*- coding: utf-8 -*-
"""
COMPREHENSIVE TEST SUITE FOR 6 FEATURES
Test all features with simulated attack scenarios

Run: python test/test_all_features.py
"""

import sys
import os
import time
from typing import List, Dict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.layer_info import LayerInfo
from core.window_packet import PacketWindow
from core.processor import FeatureVectorBuilder
from feature.feature_logic import (
    Feature1_PacketRate,
    Feature2_SynAckRatio,
    Feature3_DistinctPorts,
    Feature4_PayloadLength,
    Feature5_FailRate,
    Feature6_ContextScore
)
from config import ai_config as config


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def create_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 80,
    protocol: str = "TCP",
    tcp_flags: str = None,
    payload: bytes = None,
    timestamp: float = None,
    http_status: int = None
) -> LayerInfo:
    """Create a simulated packet"""
    
    if timestamp is None:
        timestamp = time.time()
    
    info = LayerInfo(
        timestamp=timestamp,
        packet_number=1,
        has_ip=True,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_len=100
    )
    
    if protocol == "TCP":
        info.has_tcp = True
        info.tcp_sport = src_port
        info.tcp_dport = dst_port
        info.tcp_flags = tcp_flags if tcp_flags else "A"
    elif protocol == "UDP":
        info.has_udp = True
        info.udp_sport = src_port
        info.udp_dport = dst_port
        info.udp_len = 50
    elif protocol == "ICMP":
        info.has_icmp = True
        info.icmp_type = 3  # Destination Unreachable
        info.icmp_code = 1
    
    if payload:
        info.has_payload = True
        info.payload_bytes = payload
        info.payload_length = len(payload)
    
    if http_status:
        info.http_status = http_status
    
    return info


def print_separator(title: str):
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def print_feature_result(name: str, raw: float, normalized: float, expected: str):
    """
    Print feature result with improved threshold logic.
    
    Ngưỡng phân loại:
    - LOW:  normalized <= 0.3 (bình thường)
    - MED:  0.1 <= normalized <= 0.7 (trung bình, cần chú ý)
    - HIGH: normalized >= 0.6 (cao, có khả năng tấn công)
    
    Lưu ý: MED có overlap nhỏ với LOW và HIGH để linh hoạt hơn
    """
    if expected == "HIGH":
        status = "OK" if normalized >= 0.6 else "CHECK"
    elif expected == "LOW":
        status = "OK" if normalized <= 0.3 else "CHECK"
    elif expected == "MED":
        status = "OK" if 0.1 <= normalized <= 0.7 else "CHECK"
    else:
        status = "UNKNOWN"
    
    print(f"  {name}:")
    print(f"    Raw: {raw:.4f} | Normalized: {normalized:.4f} | Expected: {expected} [{status}]")


# ============================================================
# SCENARIO 1: NORMAL TRAFFIC
# ============================================================

def test_normal_traffic():
    """Simulate normal web browsing traffic"""
    print_separator("SCENARIO 1: NORMAL TRAFFIC (Web Browsing)")
    print("  Description: User accessing a website normally")
    print("  Expected: All features should show LOW/NORMAL values")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Simulate: 3-way handshake + HTTP request + response
    packets = [
        # Connection 1: HTTP to port 80
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="S", timestamp=base_time),
        create_packet(src_ip="10.0.0.1", dst_ip=src_ip, dst_port=80, tcp_flags="SA", timestamp=base_time+0.01),
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="A", timestamp=base_time+0.02),
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="PA", 
                     payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n", 
                     timestamp=base_time+0.03),
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="A", timestamp=base_time+0.5),
        
        # Connection 2: HTTPS to port 443
        create_packet(src_ip=src_ip, dst_port=443, tcp_flags="S", timestamp=base_time+0.1),
        create_packet(src_ip=src_ip, dst_port=443, tcp_flags="A", timestamp=base_time+0.12),
        create_packet(src_ip=src_ip, dst_port=443, tcp_flags="PA", 
                     payload=b"TLS handshake data here",
                     timestamp=base_time+0.15),
    ]
    
    # Add packets to window
    for pkt in packets:
        if pkt.src_ip == src_ip:  # Only track source IP traffic
            window.add(pkt)
    
    # Get the last packet as current
    current_info = packets[-1]
    
    # Calculate features
    f1 = Feature1_PacketRate()
    f2 = Feature2_SynAckRatio()
    f3 = Feature3_DistinctPorts()
    f4 = Feature4_PayloadLength()
    f5 = Feature5_FailRate()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F1 Packet Rate", 
                        f1.calculate_raw(current_info, window),
                        f1.calculate(current_info, window), "LOW")
    print_feature_result("F2 SYN Ratio", 
                        f2.calculate_raw(current_info, window),
                        f2.calculate(current_info, window), "LOW")
    print_feature_result("F3 Distinct Ports", 
                        f3.calculate_raw(current_info, window),
                        f3.calculate(current_info, window), "LOW")
    print_feature_result("F4 Payload Len", 
                        f4.calculate_raw(current_info, window),
                        f4.calculate(current_info, window), "LOW")
    print_feature_result("F5 Fail Rate", 
                        f5.calculate_raw(current_info, window),
                        f5.calculate(current_info, window), "LOW")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "MED")  # NEUTRAL = 0.5


# ============================================================
# SCENARIO 2: SYN FLOOD ATTACK
# ============================================================

def test_syn_flood():
    """Simulate SYN flood attack - 1000 pkt/s (limited by window maxlen)"""
    print_separator("SCENARIO 2: SYN FLOOD ATTACK")
    print("  Description: Attacker sending many SYN packets without completing handshake")
    print("  Expected: F1 MED (0.2), F2 HIGH (1.0), F3 HIGH, F5 LOW")
    print("  Note: PacketWindow maxlen=1000, so rate = 1000/5000 = 0.2")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Simulate: 3000 SYN packets in 1 second (realistic SYN flood)
    # This should give normalized rate = 3000/5000 = 0.6
    packets = []
    NUM_PACKETS = 3000
    for i in range(NUM_PACKETS):
        pkt = create_packet(
            src_ip=src_ip, 
            dst_port=80 + (i % 100),  # Cycle through 100 different ports
            tcp_flags="S",    # Only SYN
            timestamp=base_time + i * (1.0 / NUM_PACKETS)  # Spread over 1 second
        )
        packets.append(pkt)
        window.add(pkt)
    
    current_info = packets[-1]
    
    f1 = Feature1_PacketRate()
    f2 = Feature2_SynAckRatio()
    f3 = Feature3_DistinctPorts()
    f4 = Feature4_PayloadLength()
    f5 = Feature5_FailRate()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F1 Packet Rate", 
                        f1.calculate_raw(current_info, window),
                        f1.calculate(current_info, window), "MED")  # 1000/5000 = 0.2
    print_feature_result("F2 SYN Ratio", 
                        f2.calculate_raw(current_info, window),
                        f2.calculate(current_info, window), "HIGH")
    print_feature_result("F3 Distinct Ports", 
                        f3.calculate_raw(current_info, window),
                        f3.calculate(current_info, window), "HIGH")
    print_feature_result("F4 Payload Len", 
                        f4.calculate_raw(current_info, window),
                        f4.calculate(current_info, window), "LOW")
    print_feature_result("F5 Fail Rate", 
                        f5.calculate_raw(current_info, window),
                        f5.calculate(current_info, window), "LOW")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "MED")  # NEUTRAL = 0.5


# ============================================================
# SCENARIO 3: PORT SCANNING
# ============================================================

def test_port_scan():
    """Simulate port scanning attack with bidirectional RST tracking"""
    print_separator("SCENARIO 3: PORT SCANNING (Nmap-style)")
    print("  Description: Attacker scanning many ports, receiving RST from closed ports")
    print("  Expected: F1 MED, F3 HIGH, F5 HIGH (RST from victim)")
    print("  Note: 500 SYN from attacker + 500 RST from victim")
    
    window = PacketWindow(window_size=1.0)
    attacker_ip = "192.168.1.100"
    victim_ip = "10.0.0.1"  # Target server
    base_time = time.time()
    
    # Simulate: 500 port scans (SYN from attacker + RST from victim)
    packets = []
    NUM_SCANS = 500
    for i in range(NUM_SCANS):
        # SYN from attacker to victim
        syn = create_packet(
            src_ip=attacker_ip,
            dst_ip=victim_ip,
            dst_port=1000 + i,
            tcp_flags="S",
            timestamp=base_time + i * (1.0 / NUM_SCANS)
        )
        packets.append(syn)
        window.add(syn)
        
        # RST from victim back to attacker (port closed)
        rst = create_packet(
            src_ip=victim_ip,
            dst_ip=attacker_ip,
            src_port=1000 + i,
            dst_port=54321,  # Attacker's source port
            tcp_flags="R",
            timestamp=base_time + i * (1.0 / NUM_SCANS) + 0.0001
        )
        packets.append(rst)
        window.add(rst)
    
    # Use attacker's last SYN as current_info (we're analyzing attacker behavior)
    current_info = packets[-2]  # Last SYN from attacker
    
    f1 = Feature1_PacketRate()
    f2 = Feature2_SynAckRatio()
    f3 = Feature3_DistinctPorts()
    f4 = Feature4_PayloadLength()
    f5 = Feature5_FailRate()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F1 Packet Rate", 
                        f1.calculate_raw(current_info, window),
                        f1.calculate(current_info, window), "MED")  # 500 attacker pkts
    print_feature_result("F2 SYN Ratio", 
                        f2.calculate_raw(current_info, window),
                        f2.calculate(current_info, window), "HIGH")  # 1.0 -> HIGH
    print_feature_result("F3 Distinct Ports", 
                        f3.calculate_raw(current_info, window),
                        f3.calculate(current_info, window), "HIGH")
    print_feature_result("F4 Payload Len", 
                        f4.calculate_raw(current_info, window),
                        f4.calculate(current_info, window), "LOW")
    print_feature_result("F5 Fail Rate", 
                        f5.calculate_raw(current_info, window),
                        f5.calculate(current_info, window), "HIGH")  # RST from victim
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "MED")  # NEUTRAL = 0.5


# ============================================================
# SCENARIO 4: SQL INJECTION ATTACK
# ============================================================

def test_sql_injection():
    """Simulate SQL injection attack"""
    print_separator("SCENARIO 4: SQL INJECTION ATTACK")
    print("  Description: Attacker sending malicious SQL payloads")
    print("  Expected: F6 HIGH (malicious payload detected)")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Malicious payloads
    payloads = [
        b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\n",
        b"POST /search HTTP/1.1\r\n\r\nquery=1' UNION SELECT * FROM users--",
        b"GET /page?id=1; DROP TABLE users;-- HTTP/1.1\r\n",
    ]
    
    packets = []
    for i, payload in enumerate(payloads):
        pkt = create_packet(
            src_ip=src_ip,
            dst_port=80,
            tcp_flags="PA",
            payload=payload,
            timestamp=base_time + i*0.1
        )
        packets.append(pkt)
        window.add(pkt)
    
    current_info = packets[-1]
    
    f1 = Feature1_PacketRate()
    f2 = Feature2_SynAckRatio()
    f3 = Feature3_DistinctPorts()
    f4 = Feature4_PayloadLength()
    f5 = Feature5_FailRate()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F1 Packet Rate", 
                        f1.calculate_raw(current_info, window),
                        f1.calculate(current_info, window), "LOW")
    print_feature_result("F2 SYN Ratio", 
                        f2.calculate_raw(current_info, window),
                        f2.calculate(current_info, window), "LOW")
    print_feature_result("F3 Distinct Ports", 
                        f3.calculate_raw(current_info, window),
                        f3.calculate(current_info, window), "LOW")
    print_feature_result("F4 Payload Len", 
                        f4.calculate_raw(current_info, window),
                        f4.calculate(current_info, window), "LOW")
    print_feature_result("F5 Fail Rate", 
                        f5.calculate_raw(current_info, window),
                        f5.calculate(current_info, window), "LOW")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "HIGH")


# ============================================================
# SCENARIO 5: XSS ATTACK
# ============================================================

def test_xss_attack():
    """Simulate XSS attack"""
    print_separator("SCENARIO 5: XSS ATTACK")
    print("  Description: Attacker sending XSS payloads")
    print("  Expected: F6 HIGH")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    payloads = [
        b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n",
        b"POST /comment HTTP/1.1\r\n\r\nbody=<img src=x onerror=alert(1)>",
        b"GET /page?name=<svg onload=alert(1)> HTTP/1.1\r\n",
    ]
    
    packets = []
    for i, payload in enumerate(payloads):
        pkt = create_packet(
            src_ip=src_ip,
            dst_port=80,
            tcp_flags="PA",
            payload=payload,
            timestamp=base_time + i*0.1
        )
        packets.append(pkt)
        window.add(pkt)
    
    current_info = packets[-1]
    
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "HIGH")


# ============================================================
# SCENARIO 6: BRUTE FORCE ATTACK
# ============================================================

def test_brute_force():
    """Simulate brute force login attack - 500 pkt/s"""
    print_separator("SCENARIO 6: BRUTE FORCE LOGIN ATTACK")
    print("  Description: Many login attempts with HTTP 401/403 responses")
    print("  Expected: F1 LOW-MED (0.1), F5 HIGH (100% failures)")
    print("  Note: 500 login attempts/s = 0.1 normalized rate")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Simulate: 500 failed login attempts in 1 second
    # This should give normalized rate = 500/5000 = 0.1
    packets = []
    NUM_ATTEMPTS = 500
    for i in range(NUM_ATTEMPTS):
        # Login request with 401 Unauthorized response
        pkt = create_packet(
            src_ip=src_ip,
            dst_port=80,
            tcp_flags="PA",
            payload=b"POST /login HTTP/1.1\r\n\r\nuser=admin&pass=test" + str(i).encode(),
            http_status=401,  # Unauthorized
            timestamp=base_time + i * (1.0 / NUM_ATTEMPTS)
        )
        packets.append(pkt)
        window.add(pkt)
    
    current_info = packets[-1]
    
    f1 = Feature1_PacketRate()
    f5 = Feature5_FailRate()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F1 Packet Rate", 
                        f1.calculate_raw(current_info, window),
                        f1.calculate(current_info, window), "MED")  # 500/5000 = 0.1
    print_feature_result("F5 Fail Rate", 
                        f5.calculate_raw(current_info, window),
                        f5.calculate(current_info, window), "HIGH")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "MED")  # NEUTRAL = 0.5


# ============================================================
# SCENARIO 7: WEB SHELL UPLOAD
# ============================================================

def test_webshell():
    """Simulate web shell upload attack"""
    print_separator("SCENARIO 7: WEB SHELL UPLOAD")
    print("  Description: Attacker uploading PHP web shell")
    print("  Expected: F6 HIGH, F4 might be HIGH (large payload)")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    webshell_payload = b"""
    POST /upload.php HTTP/1.1
    Content-Type: multipart/form-data
    
    <?php
    if(isset($_REQUEST['cmd'])){
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
    }
    ?>
    """
    
    pkt = create_packet(
        src_ip=src_ip,
        dst_port=80,
        tcp_flags="PA",
        payload=webshell_payload,
        timestamp=base_time
    )
    window.add(pkt)
    
    f4 = Feature4_PayloadLength()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F4 Payload Len", 
                        f4.calculate_raw(pkt, window),
                        f4.calculate(pkt, window), "MED")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(pkt, window),
                        f6.calculate(pkt, window), "HIGH")


# ============================================================
# SCENARIO 8: SLOWLORIS ATTACK
# ============================================================

def test_slowloris():
    """Simulate Slowloris attack"""
    print_separator("SCENARIO 8: SLOWLORIS ATTACK")
    print("  Description: Slow HTTP attack - keeping connections open")
    print("  Expected: F1 LOW (few packets), F2 LOW (has ACKs)")
    print("  NOTE: This attack is HARD to detect with current features!")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Slowloris: Few packets, but keeps connection open
    packets = [
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="S", timestamp=base_time),
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="A", timestamp=base_time+0.1),
        # Partial HTTP header (never completes)
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="PA", 
                     payload=b"GET / HTTP/1.1\r\nHost: target\r\n",
                     timestamp=base_time+0.2),
        # Keep-alive header (never sends final \r\n\r\n)
        create_packet(src_ip=src_ip, dst_port=80, tcp_flags="PA",
                     payload=b"X-Custom: value\r\n",
                     timestamp=base_time+0.8),
    ]
    
    for pkt in packets:
        window.add(pkt)
    
    current_info = packets[-1]
    
    f1 = Feature1_PacketRate()
    f2 = Feature2_SynAckRatio()
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    print_feature_result("F1 Packet Rate", 
                        f1.calculate_raw(current_info, window),
                        f1.calculate(current_info, window), "LOW")
    print_feature_result("F2 SYN Ratio", 
                        f2.calculate_raw(current_info, window),
                        f2.calculate(current_info, window), "LOW")
    print_feature_result("F6 Context Score", 
                        f6.calculate_raw(current_info, window),
                        f6.calculate(current_info, window), "MED")  # NEUTRAL = 0.5
    
    print("\n  [!] WARNING: Slowloris attack NOT DETECTED by current features!")
    print("      This is a limitation of packet-based analysis.")


# ============================================================
# SCENARIO 9: ENCODING BYPASS ATTEMPTS
# ============================================================

def test_encoding_bypass():
    """Test encoding bypass detection"""
    print_separator("SCENARIO 9: ENCODING BYPASS ATTEMPTS")
    print("  Description: Attacker using various encoding to bypass detection")
    print("  Expected: F6 HIGH (should detect all encodings)")
    
    window = PacketWindow(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Various encoded payloads
    test_cases = [
        ("URL Encoded XSS", b"%3Cscript%3Ealert(1)%3C/script%3E"),
        ("Double Encoded", b"%253Cscript%253E"),
        ("HTML Entity", b"&#60;script&#62;alert(1)"),
        ("Null Byte SQLi", b"admin' un\x00ion sel\x00ect * from users--"),
        ("Padding Attack", b" " * 4000 + b"<script>alert(1)</script>"),
    ]
    
    f6 = Feature6_ContextScore()
    
    print("\n  Results:")
    for name, payload in test_cases:
        pkt = create_packet(
            src_ip=src_ip,
            dst_port=80,
            tcp_flags="PA",
            payload=payload,
            timestamp=base_time
        )
        window.add(pkt)
        
        raw = f6.calculate_raw(pkt, window)
        norm = f6.calculate(pkt, window)
        detected = "DETECTED" if norm > 0.5 else "BYPASSED!"
        print(f"    {name}: {detected} (raw={raw:.2f}, norm={norm:.2f})")


# ============================================================
# SCENARIO 10: COMBINED VECTOR OUTPUT
# ============================================================

def test_vector_output():
    """Test full feature vector output using FeatureVectorBuilder"""
    print_separator("SCENARIO 10: FULL FEATURE VECTOR OUTPUT")
    print("  Description: Using FeatureVectorBuilder like in production")
    
    builder = FeatureVectorBuilder(window_size=1.0)
    src_ip = "192.168.1.100"
    base_time = time.time()
    
    # Simulate attack traffic
    print("\n  Attack Traffic (SYN Flood + SQLi):")
    attack_packets = []
    for i in range(20):
        pkt = create_packet(
            src_ip=src_ip,
            dst_port=80 + i,
            tcp_flags="S",
            timestamp=base_time + i*0.01
        )
        attack_packets.append(pkt)
    
    # Add SQLi payload
    sqli_pkt = create_packet(
        src_ip=src_ip,
        dst_port=80,
        tcp_flags="PA",
        payload=b"' UNION SELECT * FROM users--",
        timestamp=base_time + 0.5
    )
    attack_packets.append(sqli_pkt)
    
    # Process and get vector
    for pkt in attack_packets:
        vector = builder.process_layer_info(pkt)
    
    print(f"    Vector: [{', '.join(f'{v:.4f}' for v in vector)}]")
    print(f"    F1 (Rate):    {vector[0]:.4f}")
    print(f"    F2 (SYN):     {vector[1]:.4f}")
    print(f"    F3 (Ports):   {vector[2]:.4f}")
    print(f"    F4 (Payload): {vector[3]:.4f}")
    print(f"    F5 (Fail):    {vector[4]:.4f}")
    print(f"    F6 (Context): {vector[5]:.4f}")


# ============================================================
# MAIN
# ============================================================

def run_all_tests():
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + "        COMPREHENSIVE FEATURE TEST SUITE".center(68) + "#")
    print("#" + "        Testing 6 Features with Attack Scenarios".center(68) + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)
    
    tests = [
        test_normal_traffic,
        test_syn_flood,
        test_port_scan,
        test_sql_injection,
        test_xss_attack,
        test_brute_force,
        test_webshell,
        test_slowloris,
        test_encoding_bypass,
        test_vector_output,
    ]
    
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"\n  [ERROR] {test.__name__}: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 70)
    print(" TEST SUMMARY")
    print("=" * 70)
    print("""
    Attack Types Tested:
    - Normal Traffic (baseline)
    - SYN Flood
    - Port Scanning
    - SQL Injection
    - XSS Attack
    - Brute Force
    - Web Shell Upload
    - Slowloris (slow attack)
    - Encoding Bypass
    
    Known Limitations:
    1. Slowloris/Slow attacks: Hard to detect with 1s window
    2. Distributed attacks: Per-IP analysis misses coordinated attacks
    3. Session-based attacks: No session tracking
    """)


if __name__ == "__main__":
    run_all_tests()
