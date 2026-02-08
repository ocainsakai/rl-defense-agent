"""
Unit Tests cho FlowState - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. TCP Flags counting (SYN, ACK, RST, FIN, PSH, URG)
2. Packet counts (forward/backward)
3. Payload extraction
4. Sliding window cleanup
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_state import FlowState


@pytest.fixture
def flow_and_parser():
    """FlowState + Parser pair for TCP flag tests."""
    flow = FlowState(
        flow_key=("192.168.1.100", "10.0.0.1", 5000, 80, 6),
        window_size=60.0
    )
    parser = PacketLayerExtractor(use_packet_time=False)
    return flow, parser


@pytest.mark.unit
class TestFlowStateTCPFlags:
    """Test cases cho TCP Flags counting với Scapy packets"""

    def test_syn_flag_count(self, flow_and_parser):
        """Verify SYN flag được đếm đúng"""
        flow, parser = flow_and_parser
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        info = parser.extract(pkt, 1)
        flow.add_forward_packet(info)

        flags = flow.get_fwd_tcp_flags_count()
        assert flags['SYN'] == 1
        assert flags['ACK'] == 0

    def test_syn_ack_flag_count(self, flow_and_parser):
        """Verify SYN-ACK được đếm cho cả SYN và ACK"""
        flow, parser = flow_and_parser
        pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        info = parser.extract(pkt, 1)
        flow.add_backward_packet(info)

        flags = flow.get_bwd_tcp_flags_count()
        assert flags['SYN'] == 1
        assert flags['ACK'] == 1

    def test_all_tcp_flags(self, flow_and_parser):
        """Verify tất cả TCP flags được đếm đúng"""
        flow, parser = flow_and_parser
        flag_packets = [
            ("S", "SYN"), ("SA", "SYN-ACK"), ("A", "ACK"),
            ("PA", "PSH-ACK"), ("FA", "FIN-ACK"), ("R", "RST"), ("U", "URG"),
        ]

        for i, (flags, desc) in enumerate(flag_packets):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags=flags)
            info = parser.extract(pkt, i)
            flow.add_forward_packet(info)

        counts = flow.get_fwd_tcp_flags_count()
        # SYN: S + SA = 2
        assert counts['SYN'] == 2
        # ACK: SA + A + PA + FA = 4
        assert counts['ACK'] == 4
        # FIN: FA = 1
        assert counts['FIN'] == 1
        # RST: R = 1
        assert counts['RST'] == 1
        # PSH: PA = 1
        assert counts['PSH'] == 1
        # URG: U = 1
        assert counts['URG'] == 1

    def test_forward_backward_separation(self, flow_and_parser):
        """Verify forward và backward flags được đếm riêng biệt"""
        flow, parser = flow_and_parser

        # Forward: Client SYN
        pkt_fwd = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        info_fwd = parser.extract(pkt_fwd, 1)
        flow.add_forward_packet(info_fwd)

        # Backward: Server SYN-ACK
        pkt_bwd1 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        info_bwd1 = parser.extract(pkt_bwd1, 2)
        flow.add_backward_packet(info_bwd1)

        # Backward: Server RST
        pkt_bwd2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="R")
        info_bwd2 = parser.extract(pkt_bwd2, 3)
        flow.add_backward_packet(info_bwd2)

        fwd_flags = flow.get_fwd_tcp_flags_count()
        bwd_flags = flow.get_bwd_tcp_flags_count()

        assert fwd_flags['SYN'] == 1
        assert fwd_flags['RST'] == 0
        assert bwd_flags['SYN'] == 1
        assert bwd_flags['RST'] == 1


@pytest.mark.unit
class TestFlowStatePayload:
    """Test payload extraction với Scapy packets"""

    def test_payload_extraction(self, flow_and_parser):
        """Verify payload được extract đúng"""
        flow, parser = flow_and_parser
        payload_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=payload_data)
        info = parser.extract(pkt, 1)
        flow.add_forward_packet(info)

        lengths = flow.get_fwd_payload_lengths()
        payloads = flow.get_fwd_payloads()

        assert len(lengths) == 1
        assert lengths[0] == len(payload_data)
        assert payloads[0] == payload_data

    def test_reassembled_payload(self, flow_and_parser):
        """Verify lazy reassembly nối payload theo thứ tự"""
        flow, parser = flow_and_parser

        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"Hello ")
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"World!")

        info1 = parser.extract(pkt1, 1)
        info2 = parser.extract(pkt2, 2)

        flow.add_forward_packet(info1)
        flow.add_forward_packet(info2)

        reassembled = flow.get_reassembled_fwd_payload()
        assert reassembled == b"Hello World!"


@pytest.mark.unit
class TestFlowStateSlidingWindow:
    """Test sliding window cleanup"""

    def test_sliding_window_cleanup(self):
        """Verify packets cũ bị cleanup"""
        flow = FlowState(
            flow_key=("192.168.1.100", "10.0.0.1", 5000, 80, 6),
            window_size=5.0
        )
        parser = PacketLayerExtractor(use_packet_time=True)

        # Packet 1 @ t=1000
        pkt1 = Ether() / IP() / TCP(flags="S")
        pkt1.time = 1000.0
        info1 = parser.extract(pkt1, 1)
        flow.add_forward_packet(info1)

        # Packet 2 @ t=1003
        pkt2 = Ether() / IP() / TCP(flags="A")
        pkt2.time = 1003.0
        info2 = parser.extract(pkt2, 2)
        flow.add_forward_packet(info2)

        # Packet 3 @ t=1007 (pkt1 bị cleanup vì 1007 - 1000 > 5)
        pkt3 = Ether() / IP() / TCP(flags="PA")
        pkt3.time = 1007.0
        info3 = parser.extract(pkt3, 3)
        flow.add_forward_packet(info3)

        assert flow.get_fwd_packet_count() == 2
