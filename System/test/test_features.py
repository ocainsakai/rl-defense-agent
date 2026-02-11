"""
Unit Tests cho Feature Calculation - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. F2 - SYN/ACK Ratio
2. F4 - RST Ratio
3. F5 - Distinct Ports
4. F11-F14 - SQLi/XSS Detection
5. Full 14-feature calculator
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator
from feature.calculators.network_features import (
    F2_SynAckRatio,
    F4_RstRatio,
    F5_DistinctPorts,
)
from feature.calculators.payload_features import (
    F11_SqliKeyword,
    F13_XssKeyword,
)


@pytest.mark.unit
class TestF2SynAckRatio:
    """Test F2: SYN/ACK Ratio"""

    def test_normal_handshake_ratio(self, parser, flow_manager):
        """Normal traffic: SYN ~ ACK -> ratio ~ 1"""
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")

        for i, pkt in enumerate([pkt1, pkt2], 1):
            info = parser.extract(pkt, i)
            flow_manager.process_packet(info)

        flows = flow_manager.get_all_flows()
        ratio = F2_SynAckRatio().calculate(flows)
        assert ratio == 1.0

    def test_syn_flood_ratio(self, parser):
        """SYN Flood: Nhiều SYN, không ACK -> ratio cao"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)

        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000+i, dport=80, flags="S")
            info = parser.extract(pkt, i)
            fm.process_packet(info)

        flows = fm.get_all_flows()
        ratio = F2_SynAckRatio().calculate(flows)
        assert ratio == 10.0


@pytest.mark.unit
class TestF4RstRatio:
    """Test F4: RST Ratio từ Backward packets"""

    def test_port_scan_rst_ratio(self, parser):
        """Server trả nhiều RST cho closed ports"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        target_ports = [22, 80, 443, 8080, 3306]

        for i, port in enumerate(target_ports):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000+i, dport=port, flags="S")
            info = parser.extract(pkt, i)
            fm.process_packet(info)

        responses = [
            (22, "R"), (80, "SA"), (443, "SA"), (8080, "SA"), (3306, "R"),
        ]

        for i, (port, flags) in enumerate(responses):
            pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=port, dport=5000+i, flags=flags)
            info = parser.extract(pkt, 100+i)
            fm.process_packet(info)

        flows = fm.get_all_flows()
        ratio = F4_RstRatio().calculate(flows)
        assert abs(ratio - 0.4) < 0.1  # 2 RST / 5 responses


@pytest.mark.unit
class TestF5DistinctPorts:
    """Test F5: Distinct Destination Ports"""

    def test_port_scan_distinct_ports(self, parser):
        """Port Scan: Nhiều distinct destination ports"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        target_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9200]

        for i, port in enumerate(target_ports):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=40000+i, dport=port, flags="S")
            info = parser.extract(pkt, i)
            fm.process_packet(info)

        flows = fm.get_flows_by_src("192.168.1.100")
        distinct_ports = F5_DistinctPorts().calculate(flows)
        assert distinct_ports == len(target_ports)


@pytest.mark.unit
class TestF11SqliKeyword:
    """Test F11: SQLi Keyword Detection"""

    def test_union_select_detection(self, parser_http):
        """Detect UNION SELECT SQLi"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        sqli_payload = b"GET /page?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: target.com\r\n\r\n"

        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=sqli_payload)
        info = parser_http.extract(pkt, 1)
        fm.process_packet(info)

        flows = fm.get_all_flows()
        score = F11_SqliKeyword().calculate(flows)
        assert score > 0

    def test_or_1_equals_1_detection(self, parser_http):
        """Detect OR 1=1 tautology"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        sqli_payload = b"GET /login?user=admin' OR '1'='1'-- HTTP/1.1\r\n\r\n"

        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=sqli_payload)
        info = parser_http.extract(pkt, 1)
        fm.process_packet(info)

        flows = fm.get_all_flows()
        score = F11_SqliKeyword().calculate(flows)
        assert score > 0

    def test_clean_payload_no_detection(self, parser_http):
        """Clean payload should not trigger detection"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        clean_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=clean_payload)
        info = parser_http.extract(pkt, 1)
        fm.process_packet(info)

        flows = fm.get_all_flows()
        score = F11_SqliKeyword().calculate(flows)
        assert score == 0


@pytest.mark.unit
class TestF13XssKeyword:
    """Test F13: XSS Keyword Detection"""

    def test_script_tag_detection(self, parser):
        """Detect <script> tag XSS"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        xss_payload = b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n\r\n"

        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=xss_payload)
        info = parser.extract(pkt, 1)
        fm.process_packet(info)

        flows = fm.get_all_flows()
        score = F13_XssKeyword().calculate(flows)
        assert score > 0

    def test_onerror_event_detection(self, parser):
        """Detect onerror event handler XSS"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        xss_payload = b'GET /page?img=<img src=x onerror="alert(document.cookie)"> HTTP/1.1\r\n\r\n'

        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=xss_payload)
        info = parser.extract(pkt, 1)
        fm.process_packet(info)

        flows = fm.get_all_flows()
        score = F13_XssKeyword().calculate(flows)
        assert score > 0


@pytest.mark.unit
class TestFeatureCalculatorIntegration:
    """Integration test: Full 16 features"""

    def test_full_16_features(self, parser_http):
        """calculate_all() returns 16 features"""
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)

        packets = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S"),
            Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA"),
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A"),
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"GET /index.html HTTP/1.1\r\n\r\n"),
            Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="PA") / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n"),
        ]

        for i, pkt in enumerate(packets):
            info = parser_http.extract(pkt, i)
            fm.process_packet(info)

        flows = fm.get_all_flows()
        calc = FlowFeatureCalculator()
        features = calc.calculate_all(flows)

        assert len(features) == 16
