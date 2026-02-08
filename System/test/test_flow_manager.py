"""
Unit Tests cho FlowManager - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. Bidirectional flow tracking (cùng 5-tuple đổi chiều -> 1 flow)
2. Forward/Backward classification
3. Flow key creation
4. Memory management (cleanup, max_flows)
"""

import pytest
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager


@pytest.mark.unit
class TestFlowManagerWithScapy:
    """Test cases cho FlowManager sử dụng Scapy packets thực"""

    def test_bidirectional_same_flow(self, parser, flow_manager):
        """Packets cùng 5-tuple nhưng đổi chiều src/dst -> cùng 1 flow"""
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")

        info1 = parser.extract(pkt1, 1)
        info2 = parser.extract(pkt2, 2)

        flow1 = flow_manager.process_packet(info1)
        flow2 = flow_manager.process_packet(info2)

        assert flow1 is flow2
        assert len(flow_manager.flows) == 1
        assert flow2.get_fwd_packet_count() == 1
        assert flow2.get_bwd_packet_count() == 1

    def test_tcp_handshake_classification(self, parser, flow_manager):
        """SYN->SYN-ACK->ACK phải được classify đúng Forward/Backward"""
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")

        for i, pkt in enumerate([pkt1, pkt2, pkt3], 1):
            info = parser.extract(pkt, i)
            flow_manager.process_packet(info)

        flow = list(flow_manager.flows.values())[0]

        assert flow.get_fwd_packet_count() == 2  # SYN + ACK from client
        assert flow.get_bwd_packet_count() == 1  # SYN-ACK from server

        fwd_flags = flow.get_fwd_tcp_flags_count()
        bwd_flags = flow.get_bwd_tcp_flags_count()
        assert fwd_flags['SYN'] == 1
        assert bwd_flags['SYN'] == 1
        assert bwd_flags['ACK'] == 1

    def test_different_flows_different_ports(self, parser, flow_manager):
        """Cùng src_ip, dst_ip nhưng khác port -> 2 flows"""
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5001, dport=443, flags="S")

        info1 = parser.extract(pkt1, 1)
        info2 = parser.extract(pkt2, 2)

        flow1 = flow_manager.process_packet(info1)
        flow2 = flow_manager.process_packet(info2)

        assert flow1 is not flow2
        assert len(flow_manager.flows) == 2

    def test_udp_flow(self, parser, flow_manager):
        """UDP packets cũng được gom flow bidirectional"""
        pkt1 = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(b"\x00\x01")
        pkt2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=12345) / Raw(b"\x00\x02")

        info1 = parser.extract(pkt1, 1)
        info2 = parser.extract(pkt2, 2)

        flow1 = flow_manager.process_packet(info1)
        flow2 = flow_manager.process_packet(info2)

        assert flow1 is flow2
        assert flow1.protocol == 17

    def test_port_scan_detection_setup(self, parser, flow_manager):
        """Attacker scan nhiều ports -> nhiều flows"""
        target_ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 9200, 11211]

        for port in target_ports:
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000+port, dport=port, flags="S")
            info = parser.extract(pkt, port)
            flow_manager.process_packet(info)

        flows = flow_manager.get_flows_by_src("192.168.1.100")

        all_ports = set()
        for f in flows:
            all_ports.update(f.get_distinct_ports())

        assert len(flows) == 10
        assert len(all_ports) == 10


@pytest.mark.unit
class TestFlowManagerCleanup:
    """Test cleanup logic với timestamps"""

    def test_flow_expiration(self):
        """Flow không có traffic sau timeout bị cleanup"""
        parser = PacketLayerExtractor(use_packet_time=True)
        fm = FlowManager(window_size=10.0, flow_timeout=5.0, cleanup_interval=1)

        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt1.time = 1000.0
        info1 = parser.extract(pkt1, 1)
        fm.process_packet(info1)

        pkt2 = Ether() / IP(src="192.168.1.200", dst="10.0.0.1") / TCP(sport=6000, dport=80, flags="S")
        pkt2.time = 1010.0
        info2 = parser.extract(pkt2, 2)
        fm.process_packet(info2)

        remaining_ips = [f.src_ip for f in fm.flows.values()]
        assert len(fm.flows) == 1
        assert "192.168.1.200" in remaining_ips
        assert "192.168.1.100" not in remaining_ips
