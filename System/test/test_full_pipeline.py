"""
Full Pipeline Integration Tests

Test toàn bộ pipeline:
    Scapy Packet -> PacketLayerExtractor -> LayerInfo
    -> FlowManager -> FlowState -> FlowFeatureCalculator -> 14 Features
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator


@pytest.mark.integration
class TestFullPipelineTCPHandshake:
    """Test TCP 3-way handshake qua full pipeline."""

    def test_tcp_handshake_through_pipeline(self, pipeline):
        """TCP 3-way handshake: direction classification + flag counting"""
        parser, fm = pipeline['parser'], pipeline['fm']

        # Step 1: Client SYN
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt1.time = 1000.0
        info1 = parser.extract(pkt1, 1)
        flow1 = fm.process_packet(info1)

        assert flow1.get_fwd_packet_count() == 1
        assert flow1.get_bwd_packet_count() == 0

        # Step 2: Server SYN-ACK (reversed direction)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        pkt2.time = 1001.0
        info2 = parser.extract(pkt2, 2)
        flow2 = fm.process_packet(info2)

        assert flow1 is flow2
        assert flow2.get_bwd_packet_count() == 1

        # Step 3: Client ACK
        pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")
        pkt3.time = 1002.0
        info3 = parser.extract(pkt3, 3)
        flow3 = fm.process_packet(info3)

        assert flow1 is flow3
        assert flow3.get_fwd_packet_count() == 2
        assert flow3.get_bwd_packet_count() == 1
        assert len(fm.flows) == 1

        # Verify TCP flags
        fwd_flags = flow3.get_fwd_tcp_flags_count()
        bwd_flags = flow3.get_bwd_tcp_flags_count()
        assert fwd_flags['SYN'] == 1
        assert fwd_flags['ACK'] == 1
        assert bwd_flags['SYN'] == 1
        assert bwd_flags['ACK'] == 1


@pytest.mark.integration
class TestFullPipelineHTTPRequest:
    """Test HTTP Request/Response qua full pipeline."""

    def test_http_request_response(self, pipeline):
        """HTTP request + response: payload extraction + reassembly"""
        parser, fm = pipeline['parser'], pipeline['fm']

        http_request = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=http_request)
        pkt1.time = 1000.0
        info1 = parser.extract(pkt1, 1)
        flow = fm.process_packet(info1)

        fwd_payloads = flow.get_fwd_payloads()
        assert len(fwd_payloads) == 1
        assert fwd_payloads[0] == http_request

        http_response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"users\":[]}"
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="PA") / Raw(load=http_response)
        pkt2.time = 1001.0
        info2 = parser.extract(pkt2, 2)
        flow2 = fm.process_packet(info2)

        assert flow is flow2
        bwd_payloads = flow2.get_bwd_payloads()
        assert len(bwd_payloads) == 1
        assert bwd_payloads[0] == http_response

        assert flow2.get_reassembled_fwd_payload() == http_request
        assert flow2.get_reassembled_bwd_payload() == http_response


@pytest.mark.integration
class TestFullPipelineSQLiDetection:
    """Test SQLi Detection qua full pipeline."""

    def test_sqli_detection_end_to_end(self, pipeline):
        """SQLi detection: Packet -> Feature Score > 0"""
        parser, fm, calc = pipeline['parser'], pipeline['fm'], pipeline['calc']

        sqli_payload = b"GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\nHost: target.com\r\n\r\n"
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=sqli_payload)
        pkt.time = 1000.0

        info = parser.extract(pkt, 1)
        fm.process_packet(info)

        flows = fm.get_all_flows()
        features = calc.calculate_all(flows)

        sqli_score = features[10]  # F11 = sqli_keyword
        assert sqli_score > 0
        assert len(features) == 16


@pytest.mark.integration
class TestFullPipelinePortScan:
    """Test Port Scan Detection qua full pipeline."""

    def test_port_scan_detection(self, pipeline):
        """Port scan: F5 (Distinct Ports) = 10"""
        parser, fm, calc = pipeline['parser'], pipeline['fm'], pipeline['calc']
        target_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017, 11211]

        for i, port in enumerate(target_ports):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=40000+i, dport=port, flags="S")
            pkt.time = 1000.0 + i * 0.1
            info = parser.extract(pkt, i)
            fm.process_packet(info)

        attacker_flows = fm.get_flows_by_src("192.168.1.100")
        assert len(attacker_flows) == 10

        features = calc.calculate_all(attacker_flows)
        distinct_ports = features[4]  # F5
        assert distinct_ports == 10


@pytest.mark.integration
class TestFullPipelineSlidingWindow:
    """Test Sliding Window qua full pipeline."""

    def test_sliding_window_cleanup(self):
        """Packets cũ hơn window_size bị cleanup"""
        parser = PacketLayerExtractor(use_packet_time=True)
        fm = FlowManager(window_size=5.0, flow_timeout=120.0, cleanup_interval=10000)

        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt1.time = 1000.0
        flow = fm.process_packet(parser.extract(pkt1, 1))

        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")
        pkt2.time = 1003.0
        flow = fm.process_packet(parser.extract(pkt2, 2))
        assert flow.get_fwd_packet_count() == 2

        pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA")
        pkt3.time = 1007.0
        flow = fm.process_packet(parser.extract(pkt3, 3))
        assert flow.get_fwd_packet_count() == 2  # pkt1 cleaned up


@pytest.mark.integration
class TestFullPipelineUDP:
    """Test UDP flow tracking qua full pipeline."""

    def test_udp_dns_flow(self, pipeline):
        """UDP DNS query/response = 1 flow"""
        parser, fm = pipeline['parser'], pipeline['fm']

        pkt1 = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(load=b"\x00\x01query")
        pkt1.time = 1000.0
        flow1 = fm.process_packet(parser.extract(pkt1, 1))

        pkt2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=12345) / Raw(load=b"\x00\x02response")
        pkt2.time = 1001.0
        flow2 = fm.process_packet(parser.extract(pkt2, 2))

        assert flow1 is flow2
        assert flow1.protocol == 17
        assert len(fm.flows) == 1
