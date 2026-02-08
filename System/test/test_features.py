"""
Unit Tests cho Feature Calculation - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. F1 - Packet Rate calculation
2. F2 - SYN/ACK Ratio  
3. F3 - IAT (Inter-Arrival Time)
4. F4 - RST Ratio
5. F5 - Distinct Ports
6. F11-F14 - SQLi/XSS Detection
"""

import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo
from feature.feature_flow import (
    FlowFeature1_PacketRate,
    FlowFeature2_SynAckRatio,
    FlowFeature3_IAT,
    FlowFeature4_RstRatio,
    FlowFeature5_DistinctPorts,
    FlowFeature11_SqliKeyword,
    FlowFeature12_SqlSpecialChar,
    FlowFeature13_XssKeyword,
    FlowFeature14_XssSpecialChar,
    FlowFeatureCalculator,
)


def log_test(test_name, description):
    print(f"\n{'='*70}")
    print(f"🧪 TEST: {test_name}")
    print(f"📝 {description}")
    print(f"{'='*70}")


def log_result(condition, success_msg, fail_msg):
    if condition:
        print(f"   ✅ PASS: {success_msg}")
    else:
        print(f"   ❌ FAIL: {fail_msg}")
    return condition


class TestF2SynAckRatio(unittest.TestCase):
    """Test F2: SYN/ACK Ratio với Scapy"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
        self.fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
    
    def test_normal_handshake_ratio(self):
        """Normal traffic: SYN ≈ ACK → ratio ≈ 1"""
        log_test("F2: Normal Handshake", "Balanced SYN/ACK → ratio ≈ 1.0")
        
        # Client SYN
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        # Client ACK
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")
        
        print(f"   📦 Packet 1: SYN")
        print(f"   📦 Packet 2: ACK")
        
        for i, pkt in enumerate([pkt1, pkt2], 1):
            info = self.parser.extract(pkt, i)
            self.fm.process_packet(info)
        
        flows = self.fm.get_all_flows()
        
        calc = FlowFeature2_SynAckRatio()
        ratio = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        
        fwd_flags = flows[0].get_fwd_tcp_flags_count()
        print(f"   - SYN count: {fwd_flags['SYN']}")
        print(f"   - ACK count: {fwd_flags['ACK']}")
        print(f"   - F2 Ratio: {ratio}")
        
        log_result(ratio == 1.0, "Ratio = 1.0 (balanced)", f"Ratio = {ratio}")
        
        print(f"\n   💡 HINT: F2 = SYN / max(ACK, 1)")
        print(f"   💡 Normal traffic có SYN và ACK cân bằng")
        
        self.assertEqual(ratio, 1.0)
    
    def test_syn_flood_ratio(self):
        """SYN Flood: Nhiều SYN, không ACK → ratio cao"""
        log_test("F2: SYN Flood Attack", "Nhiều SYN không có ACK → ratio rất cao")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        # 10 SYN packets (attack simulation)
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000+i, dport=80, flags="S")
            print(f"   📦 SYN packet {i+1}/10")
            info = self.parser.extract(pkt, i)
            fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        # Aggregate SYN count
        total_syn = sum(f.get_fwd_tcp_flags_count()['SYN'] for f in flows)
        total_ack = sum(f.get_fwd_tcp_flags_count()['ACK'] for f in flows)
        
        calc = FlowFeature2_SynAckRatio()
        ratio = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Total SYN: {total_syn}")
        print(f"   - Total ACK: {total_ack}")
        print(f"   - F2 Ratio: {ratio}")
        
        log_result(ratio == 10.0, "Ratio = 10 (10 SYN / 0 ACK)", f"Ratio = {ratio}")
        log_result(ratio > 5, "Ratio > 5 → Possible SYN Flood!", f"Ratio = {ratio}")
        
        print(f"\n   💡 HINT: SYN Flood gửi nhiều SYN mà không complete handshake")
        print(f"   💡 Detection: F2 > 10 → High probability of SYN Flood")
        
        self.assertEqual(ratio, 10.0)


class TestF4RstRatio(unittest.TestCase):
    """Test F4: RST Ratio từ Backward packets"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_port_scan_rst_ratio(self):
        """Port Scan: Server trả nhiều RST cho closed ports"""
        log_test("F4: Port Scan RST Ratio", "Server RST cho closed ports → high ratio")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        target_ports = [22, 80, 443, 8080, 3306]
        
        # Client sends SYN to each port
        for i, port in enumerate(target_ports):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000+i, dport=port, flags="S")
            print(f"   📦 Client SYN → port {port}")
            info = self.parser.extract(pkt, i)
            fm.process_packet(info)
        
        # Server RST for closed ports (22, 3306), SYN-ACK for open (80, 443, 8080)
        responses = [
            (22, "R", "RST (closed)"),
            (80, "SA", "SYN-ACK (open)"),
            (443, "SA", "SYN-ACK (open)"),
            (8080, "SA", "SYN-ACK (open)"),
            (3306, "R", "RST (closed)"),
        ]
        
        for i, (port, flags, desc) in enumerate(responses):
            pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=port, dport=5000+i, flags=flags)
            print(f"   📦 Server {desc} ← port {port}")
            info = self.parser.extract(pkt, 100+i)
            fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        calc = FlowFeature4_RstRatio()
        ratio = calc.calculate(flows)
        
        # Count actual RST and total backward
        total_rst = sum(f.get_bwd_tcp_flags_count()['RST'] for f in flows)
        total_bwd = sum(f.get_bwd_packet_count() for f in flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Total RST (backward): {total_rst}")
        print(f"   - Total backward packets: {total_bwd}")
        print(f"   - F4 RST Ratio: {ratio:.2f}")
        
        expected_ratio = 2 / 5  # 2 RST / 5 responses
        log_result(abs(ratio - expected_ratio) < 0.01, 
                   f"Ratio = {expected_ratio} (2 RST / 5 responses)", 
                   f"Ratio = {ratio}")
        
        print(f"\n   💡 HINT: F4 = RST_backward / total_backward")
        print(f"   💡 High RST ratio = nhiều ports đóng = possible port scan")
        
        self.assertAlmostEqual(ratio, 0.4, places=1)


class TestF5DistinctPorts(unittest.TestCase):
    """Test F5: Distinct Destination Ports"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_port_scan_distinct_ports(self):
        """Port Scan: Nhiều distinct destination ports"""
        log_test("F5: Port Scan Detection", "Attacker scan nhiều ports → F5 cao")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        target_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9200]
        
        print(f"   🎯 Scanning {len(target_ports)} ports: {target_ports}")
        
        for i, port in enumerate(target_ports):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=40000+i, dport=port, flags="S")
            info = self.parser.extract(pkt, i)
            fm.process_packet(info)
        
        flows = fm.get_flows_by_src("192.168.1.100")
        
        calc = FlowFeature5_DistinctPorts()
        distinct_ports = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Number of flows: {len(flows)}")
        print(f"   - F5 Distinct Ports: {distinct_ports}")
        
        log_result(distinct_ports == len(target_ports), 
                   f"F5 = {len(target_ports)} (all ports)", 
                   f"F5 = {distinct_ports}")
        
        log_result(distinct_ports > 10, 
                   "F5 > 10 → HIGH ALERT: Possible Port Scan!", 
                   "F5 <= 10")
        
        print(f"\n   💡 HINT: Normal user connects to 1-5 ports (web, email)")
        print(f"   💡 F5 > 10 → Suspicious scanning behavior")
        
        self.assertEqual(distinct_ports, len(target_ports))


class TestF11SqliKeyword(unittest.TestCase):
    """Test F11: SQLi Keyword Detection"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
    
    def test_union_select_detection(self):
        """Detect UNION SELECT SQLi"""
        log_test("F11: UNION SELECT Detection", "Classic SQLi pattern")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        sqli_payload = b"GET /page?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: target.com\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=sqli_payload)
        
        print(f"   📦 SQLi Payload: {sqli_payload[:60]}...")
        
        info = self.parser.extract(pkt, 1)
        fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        calc = FlowFeature11_SqliKeyword()
        score = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - F11 SQLi Score: {score}")
        
        log_result(score > 0, f"Score = {score} (SQLi detected!)", "Score = 0 (missed!)")
        
        print(f"\n   💡 HINT: F11 uses weighted scoring:")
        print(f"   💡 - Keywords (union, select): 1 point each")
        print(f"   💡 - Patterns (union...select): 2 points")
        print(f"   💡 Detected keywords: UNION, SELECT, FROM, users")
        
        self.assertGreater(score, 0)
    
    def test_or_1_equals_1_detection(self):
        """Detect OR 1=1 tautology"""
        log_test("F11: Tautology Detection", "OR '1'='1' bypass pattern")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        sqli_payload = b"GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=sqli_payload)
        
        print(f"   📦 SQLi Payload: {sqli_payload}")
        
        info = self.parser.extract(pkt, 1)
        fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        calc = FlowFeature11_SqliKeyword()
        score = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - F11 SQLi Score: {score}")
        
        log_result(score > 0, f"Tautology detected! Score = {score}", "Missed!")
        
        print(f"\n   💡 HINT: Pattern 'or X=X' matches SQLi tautology rule")
        
        self.assertGreater(score, 0)
    
    def test_clean_payload_no_detection(self):
        """Clean payload should not trigger detection"""
        log_test("F11: Clean Payload", "Normal HTTP request → no detection")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        clean_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=clean_payload)
        
        print(f"   📦 Clean Payload: {clean_payload[:50]}...")
        
        info = self.parser.extract(pkt, 1)
        fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        calc = FlowFeature11_SqliKeyword()
        score = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - F11 SQLi Score: {score}")
        
        log_result(score == 0, "Score = 0 (no false positive)", f"Score = {score} (false positive!)")
        
        print(f"\n   💡 HINT: Clean HTTP requests should have F11 = 0")
        
        self.assertEqual(score, 0)


class TestF13XssKeyword(unittest.TestCase):
    """Test F13: XSS Keyword Detection"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_script_tag_detection(self):
        """Detect <script> tag XSS"""
        log_test("F13: Script Tag XSS", "Classic <script>alert()</script>")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        xss_payload = b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=xss_payload)
        
        print(f"   📦 XSS Payload: {xss_payload}")
        
        info = self.parser.extract(pkt, 1)
        fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        calc = FlowFeature13_XssKeyword()
        score = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - F13 XSS Score: {score}")
        
        log_result(score > 0, f"<script> detected! Score = {score}", "Missed!")
        
        print(f"\n   💡 HINT: Pattern '<script' matches XSS rule")
        print(f"   💡 Also: 'alert(' function is suspicious")
        
        self.assertGreater(score, 0)
    
    def test_onerror_event_detection(self):
        """Detect onerror event handler XSS"""
        log_test("F13: Event Handler XSS", "<img onerror=...> attack")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        xss_payload = b'GET /page?img=<img src=x onerror="alert(document.cookie)"> HTTP/1.1\r\n\r\n'
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=xss_payload)
        
        print(f"   📦 XSS Payload: {xss_payload}")
        
        info = self.parser.extract(pkt, 1)
        fm.process_packet(info)
        
        flows = fm.get_all_flows()
        
        calc = FlowFeature13_XssKeyword()
        score = calc.calculate(flows)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - F13 XSS Score: {score}")
        
        log_result(score > 0, f"onerror detected! Score = {score}", "Missed!")
        
        print(f"\n   💡 HINT: 'onerror=' pattern is a common XSS vector")
        print(f"   💡 Event handlers: onclick, onload, onmouseover, etc.")
        
        self.assertGreater(score, 0)


class TestFeatureCalculatorIntegration(unittest.TestCase):
    """Integration test: Full pipeline"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
    
    def test_full_14_features(self):
        """Verify calculate_all() returns 14 features"""
        log_test("Full Feature Calculator", "Complete pipeline → 14 features")
        
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        # Create realistic traffic
        packets = [
            # TCP Handshake
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S"),
            Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA"),
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A"),
            # HTTP Request
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"GET /index.html HTTP/1.1\r\n\r\n"),
            # HTTP Response
            Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="PA") / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n"),
        ]
        
        for i, pkt in enumerate(packets):
            info = self.parser.extract(pkt, i)
            fm.process_packet(info)
            print(f"   📦 Packet {i+1}: {pkt.summary()[:60]}")
        
        flows = fm.get_all_flows()
        
        calc = FlowFeatureCalculator()
        features = calc.calculate_all(flows)
        
        print(f"\n   📊 KẾT QUẢ: {len(features)} features")
        
        feature_names = calc.get_feature_names()
        for i, (name, value) in enumerate(zip(feature_names, features)):
            print(f"   F{i+1:02d} {name:20s}: {value:.4f}")
        
        log_result(len(features) == 14, "14 features returned", f"{len(features)} features")
        
        print(f"\n   💡 HINT: FlowFeatureCalculator aggregates all 14 features")
        print(f"   💡 Features trả về raw values, cần normalize trước khi feed vào ML")
        
        self.assertEqual(len(features), 14)


if __name__ == '__main__':
    print("\n" + "🚀"*35)
    print("         FEATURE CALCULATION TESTS")
    print("🚀"*35)
    
    unittest.main(verbosity=2)
