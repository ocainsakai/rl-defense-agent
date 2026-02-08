"""
Unit Tests cho PacketLayerExtractor - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. IP layer extraction
2. TCP layer extraction  
3. UDP layer extraction
4. Payload extraction
5. TCP flags parsing
6. HTTP parsing
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether, DNS, DNSQR

from core.packet_parser import PacketLayerExtractor
from core.layer_info import LayerInfo


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


class TestPacketParserIP(unittest.TestCase):
    """Test IP layer parsing"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_ip_layer_extraction(self):
        """Extract IP layer fields"""
        log_test("IP Layer Extraction", "Verify src_ip, dst_ip, ttl, protocol")
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1", ttl=64) / TCP(sport=5000, dport=80)
        
        print(f"   📦 Packet: {pkt.summary()}")
        
        info = self.parser.extract(pkt, 1)
        
        print(f"\n   📋 Extracted LayerInfo:")
        print(f"   - has_ip: {info.has_ip}")
        print(f"   - src_ip: {info.src_ip}")
        print(f"   - dst_ip: {info.dst_ip}")
        print(f"   - ttl: {info.ttl}")
        print(f"   - protocol: {info.protocol}")
        
        log_result(info.has_ip == True, "has_ip = True", f"has_ip = {info.has_ip}")
        log_result(info.src_ip == "192.168.1.100", "src_ip correct", f"src_ip = {info.src_ip}")
        log_result(info.dst_ip == "10.0.0.1", "dst_ip correct", f"dst_ip = {info.dst_ip}")
        log_result(info.ttl == 64, "ttl = 64", f"ttl = {info.ttl}")
        log_result(info.protocol == 6, "protocol = 6 (TCP)", f"protocol = {info.protocol}")
        
        print(f"\n   💡 HINT: Protocol numbers: TCP=6, UDP=17, ICMP=1")
        
        self.assertTrue(info.has_ip)
        self.assertEqual(info.src_ip, "192.168.1.100")
        self.assertEqual(info.protocol, 6)


class TestPacketParserTCP(unittest.TestCase):
    """Test TCP layer parsing"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_tcp_layer_extraction(self):
        """Extract TCP layer fields"""
        log_test("TCP Layer Extraction", "Verify ports, flags, seq, ack")
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(
            sport=5000, 
            dport=80, 
            flags="SA",
            seq=1000,
            ack=2000,
            window=65535
        )
        
        print(f"   📦 Packet: {pkt.summary()}")
        
        info = self.parser.extract(pkt, 1)
        
        print(f"\n   📋 Extracted LayerInfo:")
        print(f"   - has_tcp: {info.has_tcp}")
        print(f"   - tcp_sport: {info.tcp_sport}")
        print(f"   - tcp_dport: {info.tcp_dport}")
        print(f"   - tcp_flags: {info.tcp_flags}")
        print(f"   - tcp_seq: {info.tcp_seq}")
        print(f"   - tcp_ack: {info.tcp_ack}")
        print(f"   - tcp_window: {info.tcp_window}")
        
        log_result(info.has_tcp == True, "has_tcp = True", f"has_tcp = {info.has_tcp}")
        log_result(info.tcp_sport == 5000, "sport = 5000", f"sport = {info.tcp_sport}")
        log_result(info.tcp_dport == 80, "dport = 80", f"dport = {info.tcp_dport}")
        log_result('S' in str(info.tcp_flags), "SYN flag present", f"flags = {info.tcp_flags}")
        log_result('A' in str(info.tcp_flags), "ACK flag present", f"flags = {info.tcp_flags}")
        
        print(f"\n   💡 HINT: tcp_flags là string, check bằng 'S' in flags")
        
        self.assertTrue(info.has_tcp)
        self.assertEqual(info.tcp_sport, 5000)
        self.assertEqual(info.tcp_dport, 80)
    
    def test_all_tcp_flags(self):
        """Test all TCP flag combinations"""
        log_test("TCP All Flags", "Verify S, A, F, R, P, U flags")
        
        test_cases = [
            ("S", "SYN"),
            ("A", "ACK"),
            ("F", "FIN"),
            ("R", "RST"),
            ("P", "PSH"),
            ("U", "URG"),
            ("SA", "SYN-ACK"),
            ("FA", "FIN-ACK"),
            ("PA", "PSH-ACK"),
            ("RA", "RST-ACK"),
        ]
        
        for flags, desc in test_cases:
            pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(flags=flags)
            info = self.parser.extract(pkt, 1)
            
            # Check each expected flag
            all_present = all(f in str(info.tcp_flags) for f in flags)
            status = "✅" if all_present else "❌"
            print(f"   {status} flags='{flags}' ({desc}) → parsed='{info.tcp_flags}'")
            
            self.assertTrue(all_present, f"Missing flag in {flags}")


class TestPacketParserUDP(unittest.TestCase):
    """Test UDP layer parsing"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_udp_layer_extraction(self):
        """Extract UDP layer fields"""
        log_test("UDP Layer Extraction", "Verify UDP ports and length")
        
        pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(load=b"dns query")
        
        print(f"   📦 Packet: {pkt.summary()}")
        
        info = self.parser.extract(pkt, 1)
        
        print(f"\n   📋 Extracted LayerInfo:")
        print(f"   - has_udp: {info.has_udp}")
        print(f"   - udp_sport: {info.udp_sport}")
        print(f"   - udp_dport: {info.udp_dport}")
        print(f"   - udp_len: {info.udp_len}")
        print(f"   - protocol: {info.protocol}")
        
        log_result(info.has_udp == True, "has_udp = True", f"has_udp = {info.has_udp}")
        log_result(info.udp_sport == 12345, "sport = 12345", f"sport = {info.udp_sport}")
        log_result(info.udp_dport == 53, "dport = 53 (DNS)", f"dport = {info.udp_dport}")
        log_result(info.protocol == 17, "protocol = 17 (UDP)", f"protocol = {info.protocol}")
        
        print(f"\n   💡 HINT: DNS sử dụng UDP port 53")
        
        self.assertTrue(info.has_udp)
        self.assertEqual(info.protocol, 17)


class TestPacketParserPayload(unittest.TestCase):
    """Test payload extraction"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_tcp_payload_extraction(self):
        """Extract TCP payload"""
        log_test("TCP Payload Extraction", "HTTP request payload")
        
        http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1.0\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=http_payload)
        
        print(f"   📦 Packet with {len(http_payload)} bytes payload")
        print(f"   📝 Payload preview: {http_payload[:40]}...")
        
        info = self.parser.extract(pkt, 1)
        
        print(f"\n   📋 Extracted LayerInfo:")
        print(f"   - has_payload: {info.has_payload}")
        print(f"   - payload_length: {info.payload_length}")
        print(f"   - payload_bytes type: {type(info.payload_bytes)}")
        
        log_result(info.has_payload == True, "has_payload = True", f"has_payload = {info.has_payload}")
        log_result(info.payload_length == len(http_payload), f"length = {len(http_payload)}", f"length = {info.payload_length}")
        log_result(info.payload_bytes == http_payload, "payload content matches", "payload mismatch!")
        
        print(f"\n   💡 HINT: Payload được lưu dưới dạng bytes để detect SQLi/XSS")
        
        self.assertTrue(info.has_payload)
        self.assertEqual(info.payload_bytes, http_payload)
    
    def test_no_payload(self):
        """Packet without payload"""
        log_test("No Payload", "SYN packet has no payload")
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        
        print(f"   📦 SYN packet (no payload)")
        
        info = self.parser.extract(pkt, 1)
        
        print(f"\n   📋 Extracted LayerInfo:")
        print(f"   - has_payload: {info.has_payload}")
        print(f"   - payload_length: {info.payload_length}")
        
        log_result(info.has_payload == False, "has_payload = False", f"has_payload = {info.has_payload}")
        log_result(info.payload_length == 0, "length = 0", f"length = {info.payload_length}")
        
        print(f"\n   💡 HINT: SYN/ACK/FIN packets thường không có payload")
        
        self.assertFalse(info.has_payload)


class TestPacketParserTimestamp(unittest.TestCase):
    """Test timestamp handling"""
    
    def test_pcap_timestamp(self):
        """Use PCAP timestamp when use_packet_time=True"""
        log_test("PCAP Timestamp", "use_packet_time=True → dùng packet.time")
        
        parser = PacketLayerExtractor(use_packet_time=True)
        
        pkt = Ether() / IP() / TCP()
        pkt.time = 1234567890.123456
        
        print(f"   📦 Packet with time = 1234567890.123456")
        
        info = parser.extract(pkt, 1)
        
        print(f"\n   📋 Extracted timestamp: {info.timestamp}")
        
        log_result(abs(info.timestamp - 1234567890.123456) < 0.001, 
                   "Timestamp from PCAP", 
                   f"Wrong timestamp: {info.timestamp}")
        
        print(f"\n   💡 HINT: use_packet_time=True quan trọng cho PCAP analysis")
        print(f"   💡 Nếu False, sẽ dùng time.time() → thời gian hiện tại")
        
        self.assertAlmostEqual(info.timestamp, 1234567890.123456, places=3)
    
    def test_realtime_timestamp(self):
        """Use current time when use_packet_time=False"""
        log_test("Realtime Timestamp", "use_packet_time=False → dùng time.time()")
        
        import time
        
        parser = PacketLayerExtractor(use_packet_time=False)
        
        pkt = Ether() / IP() / TCP()
        pkt.time = 1000.0  # Old PCAP time
        
        before = time.time()
        info = parser.extract(pkt, 1)
        after = time.time()
        
        print(f"   📦 Packet with old PCAP time = 1000.0")
        print(f"   📋 Extracted timestamp: {info.timestamp}")
        print(f"   ⏰ Current time range: [{before:.2f}, {after:.2f}]")
        
        in_range = before <= info.timestamp <= after
        log_result(in_range, "Timestamp is current time", f"Timestamp out of range")
        
        print(f"\n   💡 HINT: use_packet_time=False cho live capture")
        
        self.assertTrue(in_range)


class TestPacketParserStats(unittest.TestCase):
    """Test parser statistics"""
    
    def test_stats_counting(self):
        """Verify stats are updated correctly"""
        log_test("Parser Statistics", "Count packets by type")
        
        parser = PacketLayerExtractor(use_packet_time=False)
        parser.reset_stats()
        
        # Create different packet types
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
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP"
            has_payload = pkt.haslayer(Raw)
            print(f"   📦 Packet {i+1}: {proto}" + (" + payload" if has_payload else ""))
        
        stats = parser.get_stats()
        
        print(f"\n   📊 Statistics:")
        for key, value in stats.items():
            print(f"   - {key}: {value}")
        
        log_result(stats['total_packets'] == 6, "total = 6", f"total = {stats['total_packets']}")
        log_result(stats['tcp_packets'] == 3, "tcp = 3", f"tcp = {stats['tcp_packets']}")
        log_result(stats['udp_packets'] == 2, "udp = 2", f"udp = {stats['udp_packets']}")
        log_result(stats['icmp_packets'] == 1, "icmp = 1", f"icmp = {stats['icmp_packets']}")
        log_result(stats['with_payload'] == 1, "with_payload = 1", f"with_payload = {stats['with_payload']}")
        
        print(f"\n   💡 HINT: Stats useful for monitoring và debugging")
        
        self.assertEqual(stats['total_packets'], 6)
        self.assertEqual(stats['tcp_packets'], 3)


if __name__ == '__main__':
    print("\n" + "🚀"*35)
    print("         PACKET PARSER UNIT TESTS")
    print("🚀"*35)
    
    unittest.main(verbosity=2)
