"""
=============================================================================
FULL PIPELINE INTEGRATION TESTS
=============================================================================

Test toàn bộ pipeline THỰC TẾ của hệ thống:

    Scapy Packet 
        → PacketLayerExtractor.extract() 
        → LayerInfo
        → FlowManager.process_packet()
        → FlowState (direction được xác định tự động)
        → FlowFeatureCalculator.calculate_all()
        → 14 Features

KHÔNG BYPASS BẤT KỲ COMPONENT NÀO!
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, Raw, Ether, ICMP

# Import TOÀN BỘ pipeline
from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo
from feature.feature_flow import FlowFeatureCalculator


def log_test(test_name, description):
    print(f"\n{'='*70}")
    print(f"🧪 TEST: {test_name}")
    print(f"📝 {description}")
    print(f"{'='*70}")


def log_step(step_num, description):
    print(f"\n   📍 STEP {step_num}: {description}")


def log_result(condition, success_msg, fail_msg):
    if condition:
        print(f"   ✅ PASS: {success_msg}")
    else:
        print(f"   ❌ FAIL: {fail_msg}")
    return condition


class TestFullPipelineTCPHandshake(unittest.TestCase):
    """
    Test TCP 3-way handshake qua FULL PIPELINE.
    
    Scenario:
        Client (192.168.1.100:5000) → Server (10.0.0.1:80)
        
        1. Client → Server: SYN
        2. Server → Client: SYN-ACK  
        3. Client → Server: ACK
    
    Expected:
        - 1 flow được tạo
        - Forward packets: 2 (SYN, ACK từ client)
        - Backward packets: 1 (SYN-ACK từ server)
    """
    
    def setUp(self):
        """Setup pipeline components"""
        self.parser = PacketLayerExtractor(
            enable_http_parsing=True,
            use_packet_time=True  # Dùng PCAP time để control timestamps
        )
        self.fm = FlowManager(
            window_size=60.0,      # 60s window để tránh cleanup
            flow_timeout=120.0,
            cleanup_interval=10000  # Không cleanup trong test
        )
    
    def test_tcp_handshake_through_pipeline(self):
        """TCP 3-way handshake qua full pipeline"""
        log_test("TCP Handshake - Full Pipeline", 
                 "Verify FlowManager tự động classify direction")
        
        # =====================================================================
        # STEP 1: Client SYN
        # =====================================================================
        log_step(1, "Client gửi SYN")
        
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt1.time = 1000.0
        
        print(f"   📦 Packet: 192.168.1.100:5000 → 10.0.0.1:80 [SYN]")
        
        # Qua pipeline
        info1 = self.parser.extract(pkt1, 1)
        flow1 = self.fm.process_packet(info1)
        
        print(f"   📊 FlowManager returned flow với src_ip={flow1.src_ip}")
        print(f"   📊 Flow key: {flow1.flow_key}")
        print(f"   📊 Forward count: {flow1.get_fwd_packet_count()}")
        print(f"   📊 Backward count: {flow1.get_bwd_packet_count()}")
        
        # Verify: Packet đầu tiên LUÔN là forward
        log_result(flow1.get_fwd_packet_count() == 1, 
                   "Forward = 1 (packet đầu tiên)", 
                   f"Forward = {flow1.get_fwd_packet_count()}")
        log_result(flow1.get_bwd_packet_count() == 0,
                   "Backward = 0",
                   f"Backward = {flow1.get_bwd_packet_count()}")
        
        # =====================================================================
        # STEP 2: Server SYN-ACK (REVERSED direction!)
        # =====================================================================
        log_step(2, "Server trả lời SYN-ACK")
        
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        pkt2.time = 1001.0
        
        print(f"   📦 Packet: 10.0.0.1:80 → 192.168.1.100:5000 [SYN-ACK]")
        print(f"   💡 LƯU Ý: src/dst đã ĐẢO NGƯỢC so với packet 1!")
        
        info2 = self.parser.extract(pkt2, 2)
        flow2 = self.fm.process_packet(info2)
        
        print(f"   📊 Forward count: {flow2.get_fwd_packet_count()}")
        print(f"   📊 Backward count: {flow2.get_bwd_packet_count()}")
        
        # CRITICAL: Phải cùng 1 flow object!
        log_result(flow1 is flow2,
                   "Cùng 1 flow object (bidirectional tracking đúng!)",
                   "KHÁC flow object (SAI!)")
        
        # Server packet phải là BACKWARD
        log_result(flow2.get_bwd_packet_count() == 1,
                   "Backward = 1 (server response)",
                   f"Backward = {flow2.get_bwd_packet_count()}")
        
        # Forward vẫn là 1
        log_result(flow2.get_fwd_packet_count() == 1,
                   "Forward vẫn = 1",
                   f"Forward = {flow2.get_fwd_packet_count()}")
        
        # =====================================================================
        # STEP 3: Client ACK
        # =====================================================================
        log_step(3, "Client gửi ACK hoàn thành handshake")
        
        pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")
        pkt3.time = 1002.0
        
        print(f"   📦 Packet: 192.168.1.100:5000 → 10.0.0.1:80 [ACK]")
        
        info3 = self.parser.extract(pkt3, 3)
        flow3 = self.fm.process_packet(info3)
        
        print(f"   📊 Forward count: {flow3.get_fwd_packet_count()}")
        print(f"   📊 Backward count: {flow3.get_bwd_packet_count()}")
        
        # Vẫn cùng flow
        log_result(flow1 is flow3, "Cùng 1 flow", "KHÁC flow!")
        
        # Forward = 2 (SYN + ACK từ client)
        log_result(flow3.get_fwd_packet_count() == 2,
                   "Forward = 2 (SYN + ACK từ client)",
                   f"Forward = {flow3.get_fwd_packet_count()}")
        
        # Backward = 1 (SYN-ACK từ server)
        log_result(flow3.get_bwd_packet_count() == 1,
                   "Backward = 1 (SYN-ACK từ server)",
                   f"Backward = {flow3.get_bwd_packet_count()}")
        
        # =====================================================================
        # VERIFY TCP FLAGS
        # =====================================================================
        log_step(4, "Verify TCP Flags counting")
        
        fwd_flags = flow3.get_fwd_tcp_flags_count()
        bwd_flags = flow3.get_bwd_tcp_flags_count()
        
        print(f"   📊 Forward flags: {fwd_flags}")
        print(f"   📊 Backward flags: {bwd_flags}")
        
        # Forward: SYN=1 (từ pkt1), ACK=1 (từ pkt3)
        log_result(fwd_flags['SYN'] == 1, "Forward SYN = 1", f"Forward SYN = {fwd_flags['SYN']}")
        log_result(fwd_flags['ACK'] == 1, "Forward ACK = 1", f"Forward ACK = {fwd_flags['ACK']}")
        
        # Backward: SYN=1, ACK=1 (từ SYN-ACK)
        log_result(bwd_flags['SYN'] == 1, "Backward SYN = 1", f"Backward SYN = {bwd_flags['SYN']}")
        log_result(bwd_flags['ACK'] == 1, "Backward ACK = 1", f"Backward ACK = {bwd_flags['ACK']}")
        
        # =====================================================================
        # VERIFY ONLY 1 FLOW IN MANAGER
        # =====================================================================
        log_step(5, "Verify FlowManager state")
        
        print(f"   📊 Total flows: {len(self.fm.flows)}")
        
        log_result(len(self.fm.flows) == 1,
                   "Chỉ có 1 flow trong FlowManager",
                   f"Có {len(self.fm.flows)} flows!")
        
        print(f"\n   💡 PIPELINE HOẠT ĐỘNG ĐÚNG:")
        print(f"   💡 - FlowManager tự detect reverse_key")
        print(f"   💡 - So sánh packet.src_ip với flow.src_ip để xác định direction")
        print(f"   💡 - Packet từ 10.0.0.1 ≠ flow.src_ip (192.168.1.100) → BACKWARD")
        
        # Assertions
        self.assertIs(flow1, flow2)
        self.assertIs(flow1, flow3)
        self.assertEqual(flow3.get_fwd_packet_count(), 2)
        self.assertEqual(flow3.get_bwd_packet_count(), 1)
        self.assertEqual(len(self.fm.flows), 1)


class TestFullPipelineHTTPRequest(unittest.TestCase):
    """
    Test HTTP Request/Response qua FULL PIPELINE.
    
    Scenario:
        1. Client → Server: HTTP GET request
        2. Server → Client: HTTP 200 OK response
    """
    
    def setUp(self):
        self.parser = PacketLayerExtractor(
            enable_http_parsing=True,
            use_packet_time=True
        )
        self.fm = FlowManager(
            window_size=60.0,
            flow_timeout=120.0,
            cleanup_interval=10000
        )
    
    def test_http_request_response(self):
        """HTTP request và response qua pipeline"""
        log_test("HTTP Request/Response", "Verify payload extraction qua pipeline")
        
        # =====================================================================
        # Client sends HTTP GET
        # =====================================================================
        log_step(1, "Client gửi HTTP GET")
        
        http_request = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=http_request)
        pkt1.time = 1000.0
        
        print(f"   📦 HTTP Request: GET /api/users")
        print(f"   📦 Payload size: {len(http_request)} bytes")
        
        info1 = self.parser.extract(pkt1, 1)
        flow = self.fm.process_packet(info1)
        
        # Verify payload extracted
        fwd_payloads = flow.get_fwd_payloads()
        print(f"   📊 Forward payloads count: {len(fwd_payloads)}")
        
        log_result(len(fwd_payloads) == 1, "1 forward payload", f"{len(fwd_payloads)} payloads")
        log_result(fwd_payloads[0] == http_request, "Payload content matches", "Payload mismatch!")
        
        # =====================================================================
        # Server sends HTTP Response
        # =====================================================================
        log_step(2, "Server trả HTTP 200 OK")
        
        http_response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"users\":[]}"
        
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="PA") / Raw(load=http_response)
        pkt2.time = 1001.0
        
        print(f"   📦 HTTP Response: 200 OK")
        print(f"   📦 Payload size: {len(http_response)} bytes")
        
        info2 = self.parser.extract(pkt2, 2)
        flow2 = self.fm.process_packet(info2)
        
        # Same flow
        log_result(flow is flow2, "Cùng 1 flow", "KHÁC flow!")
        
        # Backward payload
        bwd_payloads = flow2.get_bwd_payloads()
        print(f"   📊 Backward payloads count: {len(bwd_payloads)}")
        
        log_result(len(bwd_payloads) == 1, "1 backward payload", f"{len(bwd_payloads)} payloads")
        log_result(bwd_payloads[0] == http_response, "Response content matches", "Response mismatch!")
        
        # =====================================================================
        # Test reassembled payload
        # =====================================================================
        log_step(3, "Test lazy reassembly")
        
        reassembled_fwd = flow2.get_reassembled_fwd_payload()
        reassembled_bwd = flow2.get_reassembled_bwd_payload()
        
        print(f"   📊 Reassembled forward: {len(reassembled_fwd)} bytes")
        print(f"   📊 Reassembled backward: {len(reassembled_bwd)} bytes")
        
        log_result(reassembled_fwd == http_request, "Forward reassembly correct", "Forward mismatch!")
        log_result(reassembled_bwd == http_response, "Backward reassembly correct", "Backward mismatch!")
        
        print(f"\n   💡 PAYLOAD PIPELINE HOẠT ĐỘNG ĐÚNG:")
        print(f"   💡 - Request payload → fwd_packets")
        print(f"   💡 - Response payload → bwd_packets")
        print(f"   💡 - Lazy reassembly nối bytes theo thứ tự")
        
        self.assertEqual(flow2.get_fwd_packet_count(), 1)
        self.assertEqual(flow2.get_bwd_packet_count(), 1)


class TestFullPipelineSQLiDetection(unittest.TestCase):
    """
    Test SQLi Detection qua FULL PIPELINE.
    
    End-to-end: Scapy packet → Features với SQLi score > 0
    """
    
    def setUp(self):
        self.parser = PacketLayerExtractor(
            enable_http_parsing=True,
            use_packet_time=True
        )
        self.fm = FlowManager(
            window_size=60.0,
            flow_timeout=120.0,
            cleanup_interval=10000
        )
        self.feature_calc = FlowFeatureCalculator()
    
    def test_sqli_detection_end_to_end(self):
        """SQLi detection từ packet → feature"""
        log_test("SQLi Detection E2E", "Full pipeline: Packet → Feature Score")
        
        # =====================================================================
        # Create SQLi attack packet
        # =====================================================================
        log_step(1, "Tạo packet với SQLi payload")
        
        sqli_payload = b"GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\nHost: target.com\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=sqli_payload)
        pkt.time = 1000.0
        
        print(f"   📦 SQLi Payload: {sqli_payload[:50]}...")
        
        # =====================================================================
        # Process through pipeline
        # =====================================================================
        log_step(2, "Process qua pipeline")
        
        # Step 2a: Parse
        info = self.parser.extract(pkt, 1)
        print(f"   📋 LayerInfo created: has_payload={info.has_payload}, len={info.payload_length}")
        
        # Step 2b: Add to flow
        flow = self.fm.process_packet(info)
        print(f"   📋 Flow created: fwd_packets={flow.get_fwd_packet_count()}")
        
        # Step 2c: Get all flows
        flows = self.fm.get_all_flows()
        print(f"   📋 Total flows: {len(flows)}")
        
        # =====================================================================
        # Calculate features
        # =====================================================================
        log_step(3, "Tính 14 features")
        
        features = self.feature_calc.calculate_all(flows)
        feature_names = self.feature_calc.get_feature_names()
        
        print(f"\n   📊 FEATURES:")
        for i, (name, value) in enumerate(zip(feature_names, features)):
            indicator = "⚠️" if "sqli" in name.lower() and value > 0 else "  "
            print(f"   {indicator} F{i+1:02d} {name:20s}: {value:.4f}")
        
        # =====================================================================
        # Verify SQLi detection
        # =====================================================================
        log_step(4, "Verify SQLi detection")
        
        # F11 = sqli_keyword
        sqli_score = features[10]  # Index 10 = F11
        
        log_result(sqli_score > 0,
                   f"F11 SQLi Score = {sqli_score} (DETECTED!)",
                   f"F11 = 0 (MISSED!)")
        
        print(f"\n   💡 END-TO-END PIPELINE:")
        print(f"   💡 1. Scapy packet với SQLi payload")
        print(f"   💡 2. PacketLayerExtractor → LayerInfo (payload_bytes)")
        print(f"   💡 3. FlowManager → FlowState (fwd_packets)")
        print(f"   💡 4. FlowFeatureCalculator → 14 features")
        print(f"   💡 5. F11 (sqli_keyword) > 0 → Attack detected!")
        
        self.assertGreater(sqli_score, 0)
        self.assertEqual(len(features), 14)


class TestFullPipelinePortScan(unittest.TestCase):
    """
    Test Port Scan Detection qua FULL PIPELINE.
    
    Scenario: Attacker scan 10 ports trên target
    Expected: F5 (Distinct Ports) = 10
    """
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=True)
        self.fm = FlowManager(
            window_size=60.0,
            flow_timeout=120.0,
            cleanup_interval=10000
        )
        self.feature_calc = FlowFeatureCalculator()
    
    def test_port_scan_detection(self):
        """Port scan detection end-to-end"""
        log_test("Port Scan Detection E2E", "Attacker scan nhiều ports")
        
        target_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017, 11211]
        
        log_step(1, f"Attacker scan {len(target_ports)} ports")
        
        for i, port in enumerate(target_ports):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=40000+i, dport=port, flags="S")
            pkt.time = 1000.0 + i * 0.1  # Mỗi packet cách 0.1s
            
            info = self.parser.extract(pkt, i)
            self.fm.process_packet(info)
        
        print(f"   📦 Scanned ports: {target_ports}")
        print(f"   📊 Flows created: {len(self.fm.flows)}")
        
        # =====================================================================
        # Get flows for attacker IP
        # =====================================================================
        log_step(2, "Get flows từ attacker IP")
        
        attacker_flows = self.fm.get_flows_by_src("192.168.1.100")
        print(f"   📊 Flows from 192.168.1.100: {len(attacker_flows)}")
        
        log_result(len(attacker_flows) == 10,
                   "10 flows (1 per port)",
                   f"{len(attacker_flows)} flows")
        
        # =====================================================================
        # Calculate features
        # =====================================================================
        log_step(3, "Tính features cho attacker")
        
        features = self.feature_calc.calculate_all(attacker_flows)
        feature_names = self.feature_calc.get_feature_names()
        
        # F5 = distinct_ports
        distinct_ports = features[4]  # Index 4 = F5
        
        print(f"\n   📊 KEY FEATURES:")
        print(f"   ⚠️ F05 distinct_ports: {distinct_ports}")
        
        log_result(distinct_ports == 10,
                   f"F5 = 10 distinct ports (PORT SCAN DETECTED!)",
                   f"F5 = {distinct_ports}")
        
        print(f"\n   💡 PORT SCAN DETECTION:")
        print(f"   💡 - Normal user: 1-5 distinct ports (web, email)")
        print(f"   💡 - Port scan: > 10 distinct ports")
        print(f"   💡 - F5 = {distinct_ports} → HIGH ALERT!")
        
        self.assertEqual(distinct_ports, 10)


class TestFullPipelineSlidingWindow(unittest.TestCase):
    """
    Test Sliding Window qua FULL PIPELINE.
    
    Verify: Packets cũ bị cleanup đúng cách
    """
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=True)
    
    def test_sliding_window_cleanup(self):
        """Sliding window cleanup trong FlowManager"""
        log_test("Sliding Window", "Packets cũ hơn window_size bị cleanup")
        
        fm = FlowManager(
            window_size=5.0,  # 5 giây window
            flow_timeout=120.0,
            cleanup_interval=10000
        )
        
        # =====================================================================
        # Packet 1 @ t=1000
        # =====================================================================
        log_step(1, "Packet @ t=1000")
        
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt1.time = 1000.0
        
        info1 = self.parser.extract(pkt1, 1)
        flow = fm.process_packet(info1)
        
        print(f"   📦 Packet 1 @ t=1000")
        print(f"   📊 Forward count: {flow.get_fwd_packet_count()}")
        
        # =====================================================================
        # Packet 2 @ t=1003 (trong window)
        # =====================================================================
        log_step(2, "Packet @ t=1003 (trong window)")
        
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")
        pkt2.time = 1003.0
        
        info2 = self.parser.extract(pkt2, 2)
        flow = fm.process_packet(info2)
        
        print(f"   📦 Packet 2 @ t=1003")
        print(f"   📊 Forward count: {flow.get_fwd_packet_count()}")
        
        log_result(flow.get_fwd_packet_count() == 2, "2 packets", f"{flow.get_fwd_packet_count()} packets")
        
        # =====================================================================
        # Packet 3 @ t=1007 (packet 1 sẽ bị cleanup)
        # =====================================================================
        log_step(3, "Packet @ t=1007 (packet 1 bị cleanup)")
        
        pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA")
        pkt3.time = 1007.0
        
        info3 = self.parser.extract(pkt3, 3)
        flow = fm.process_packet(info3)
        
        print(f"   📦 Packet 3 @ t=1007")
        print(f"   📊 Forward count: {flow.get_fwd_packet_count()}")
        
        # cutoff = 1007 - 5 = 1002
        # pkt1 (t=1000) < 1002 → bị cleanup
        # pkt2 (t=1003) >= 1002 → còn
        # pkt3 (t=1007) → mới thêm
        
        log_result(flow.get_fwd_packet_count() == 2,
                   "2 packets còn (pkt2 + pkt3, pkt1 đã cleanup)",
                   f"{flow.get_fwd_packet_count()} packets")
        
        print(f"\n   💡 SLIDING WINDOW:")
        print(f"   💡 - window_size = 5s")
        print(f"   💡 - current_time = 1007")
        print(f"   💡 - cutoff = 1007 - 5 = 1002")
        print(f"   💡 - pkt1 (t=1000) < 1002 → REMOVED")
        
        self.assertEqual(flow.get_fwd_packet_count(), 2)


class TestFullPipelineUDP(unittest.TestCase):
    """
    Test UDP flow tracking qua FULL PIPELINE.
    """
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=True)
        self.fm = FlowManager(
            window_size=60.0,
            flow_timeout=120.0,
            cleanup_interval=10000
        )
    
    def test_udp_dns_flow(self):
        """UDP DNS query/response qua pipeline"""
        log_test("UDP DNS Flow", "DNS query và response = 1 flow")
        
        # =====================================================================
        # DNS Query
        # =====================================================================
        log_step(1, "Client gửi DNS Query")
        
        pkt1 = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(load=b"\x00\x01query")
        pkt1.time = 1000.0
        
        print(f"   📦 DNS Query: 192.168.1.100:12345 → 8.8.8.8:53")
        
        info1 = self.parser.extract(pkt1, 1)
        flow1 = self.fm.process_packet(info1)
        
        print(f"   📊 Protocol: {flow1.protocol} (17 = UDP)")
        print(f"   📊 Forward: {flow1.get_fwd_packet_count()}")
        
        # =====================================================================
        # DNS Response
        # =====================================================================
        log_step(2, "Server trả DNS Response")
        
        pkt2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=12345) / Raw(load=b"\x00\x02response")
        pkt2.time = 1001.0
        
        print(f"   📦 DNS Response: 8.8.8.8:53 → 192.168.1.100:12345")
        
        info2 = self.parser.extract(pkt2, 2)
        flow2 = self.fm.process_packet(info2)
        
        print(f"   📊 Forward: {flow2.get_fwd_packet_count()}")
        print(f"   📊 Backward: {flow2.get_bwd_packet_count()}")
        
        # Same flow
        log_result(flow1 is flow2, "Cùng 1 flow", "KHÁC flow!")
        
        # Protocol = 17 (UDP)
        log_result(flow1.protocol == 17, "Protocol = 17 (UDP)", f"Protocol = {flow1.protocol}")
        
        # 1 flow total
        log_result(len(self.fm.flows) == 1, "1 flow total", f"{len(self.fm.flows)} flows")
        
        print(f"\n   💡 UDP BIDIRECTIONAL:")
        print(f"   💡 - UDP không có flags nhưng vẫn track bidirectional")
        print(f"   💡 - Query → fwd_packets")
        print(f"   💡 - Response → bwd_packets")
        
        self.assertIs(flow1, flow2)
        self.assertEqual(flow1.protocol, 17)


if __name__ == '__main__':
    print("\n" + "🚀"*35)
    print("      FULL PIPELINE INTEGRATION TESTS")
    print("🚀"*35)
    
    unittest.main(verbosity=2)
