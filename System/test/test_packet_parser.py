"""
Unit Tests cho PacketLayerExtractor - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. IP layer extraction
2. TCP layer extraction
3. UDP layer extraction
4. Payload extraction
5. TCP flags parsing
6. Timestamp handling
7. Parser statistics
"""

import time

import pytest
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether

from core.packet_parser import PacketLayerExtractor


@pytest.mark.unit
class TestPacketParserIP:
    """Test IP layer parsing"""

    def test_ip_layer_extraction(self, parser):
        """Extract IP layer fields"""
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1", ttl=64) / TCP(sport=5000, dport=80)
        info = parser.extract(pkt, 1)

        assert info.has_ip is True
        assert info.src_ip == "192.168.1.100"
        assert info.dst_ip == "10.0.0.1"
        assert info.ttl == 64
        assert info.protocol == 6  # TCP


@pytest.mark.unit
class TestPacketParserTCP:
    """Test TCP layer parsing"""

    def test_tcp_layer_extraction(self, parser):
        """Extract TCP layer fields"""
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(
            sport=5000, dport=80, flags="SA", seq=1000, ack=2000, window=65535
        )
        info = parser.extract(pkt, 1)

        assert info.has_tcp is True
        assert info.tcp_sport == 5000
        assert info.tcp_dport == 80
        assert 'S' in str(info.tcp_flags)
        assert 'A' in str(info.tcp_flags)

    @pytest.mark.parametrize("flags,desc", [
        ("S", "SYN"), ("A", "ACK"), ("F", "FIN"), ("R", "RST"),
        ("P", "PSH"), ("U", "URG"), ("SA", "SYN-ACK"), ("FA", "FIN-ACK"),
        ("PA", "PSH-ACK"), ("RA", "RST-ACK"),
    ])
    def test_all_tcp_flags(self, parser, flags, desc):
        """Test all TCP flag combinations"""
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(flags=flags)
        info = parser.extract(pkt, 1)
        assert all(f in str(info.tcp_flags) for f in flags), \
            f"Missing flag in {flags} ({desc}), got {info.tcp_flags}"


@pytest.mark.unit
class TestPacketParserUDP:
    """Test UDP layer parsing"""

    def test_udp_layer_extraction(self, parser):
        """Extract UDP layer fields"""
        pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(load=b"dns query")
        info = parser.extract(pkt, 1)

        assert info.has_udp is True
        assert info.udp_sport == 12345
        assert info.udp_dport == 53
        assert info.protocol == 17  # UDP


@pytest.mark.unit
class TestPacketParserPayload:
    """Test payload extraction"""

    def test_tcp_payload_extraction(self, parser):
        """Extract TCP payload"""
        http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1.0\r\n\r\n"
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=http_payload)

        info = parser.extract(pkt, 1)

        assert info.has_payload is True
        assert info.payload_length == len(http_payload)
        assert info.payload_bytes == http_payload

    def test_no_payload(self, parser):
        """SYN packet has no payload"""
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        info = parser.extract(pkt, 1)

        assert info.has_payload is False
        assert info.payload_length == 0


@pytest.mark.unit
class TestPacketParserTimestamp:
    """Test timestamp handling"""

    def test_pcap_timestamp(self, parser_pcap):
        """use_packet_time=True uses packet.time"""
        pkt = Ether() / IP() / TCP()
        pkt.time = 1234567890.123456

        info = parser_pcap.extract(pkt, 1)
        assert abs(info.timestamp - 1234567890.123456) < 0.001

    def test_realtime_timestamp(self, parser):
        """use_packet_time=False uses time.time()"""
        pkt = Ether() / IP() / TCP()
        pkt.time = 1000.0  # Old PCAP time

        before = time.time()
        info = parser.extract(pkt, 1)
        after = time.time()

        assert before <= info.timestamp <= after


@pytest.mark.unit
class TestPacketParserStats:
    """Test parser statistics"""

    def test_stats_counting(self):
        """Verify stats are updated correctly"""
        parser = PacketLayerExtractor(use_packet_time=False)
        parser.reset_stats()

        packets = [
            Ether() / IP() / TCP(),
            Ether() / IP() / TCP(),
            Ether() / IP() / TCP() / Raw(load=b"data"),
            Ether() / IP() / UDP(),
            Ether() / IP() / UDP(),
            Ether() / IP() / ICMP(),
        ]

        for i, pkt in enumerate(packets):
            parser.extract(pkt, i)

        stats = parser.get_stats()
        assert stats['total_packets'] == 6
        assert stats['tcp_packets'] == 3
        assert stats['udp_packets'] == 2
        assert stats['icmp_packets'] == 1
        assert stats['with_payload'] == 1
