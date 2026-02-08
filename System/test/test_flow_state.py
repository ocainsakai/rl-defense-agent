"""
Unit Tests cho FlowState - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. TCP Flags counting (SYN, ACK, RST, FIN, PSH, URG)
2. Packet counts (forward/backward)
3. Payload extraction
4. Sliding window cleanup
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_state import FlowState
from core.layer_info import LayerInfo


def log_test(test_name, description):
    """Helper: In header cho mỗi test"""
    print(f"\n{'='*70}")
    print(f"🧪 TEST: {test_name}")
    print(f"📝 {description}")
    print(f"{'='*70}")


def log_result(condition, success_msg, fail_msg):
    """Helper: In kết quả với hint"""
    if condition:
        print(f"   ✅ PASS: {success_msg}")
    else:
        print(f"   ❌ FAIL: {fail_msg}")
    return condition


class TestFlowStateTCPFlags(unittest.TestCase):
    """Test cases cho TCP Flags counting với Scapy packets"""
    
    def setUp(self):
        """Khởi tạo FlowState và Parser"""
        self.flow = FlowState(
            flow_key=("192.168.1.100", "10.0.0.1", 5000, 80, 6),
            window_size=60.0  # 60 giây để tránh cleanup
        )
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_syn_flag_count(self):
        """Verify SYN flag được đếm đúng"""
        log_test("SYN Flag Count", "Packet với SYN flag phải được đếm chính xác")
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        print(f"   📦 Created packet with flags='S' (SYN)")
        
        info = self.parser.extract(pkt, 1)
        print(f"   📋 Parsed tcp_flags: '{info.tcp_flags}'")
        
        self.flow.add_forward_packet(info)
        
        flags = self.flow.get_fwd_tcp_flags_count()
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - SYN count: {flags['SYN']}")
        print(f"   - ACK count: {flags['ACK']}")
        print(f"   - All flags: {flags}")
        
        log_result(flags['SYN'] == 1, "SYN = 1", f"SYN = {flags['SYN']}")
        log_result(flags['ACK'] == 0, "ACK = 0", f"ACK = {flags['ACK']}")
        
        print(f"\n   💡 HINT: Scapy dùng 'S' cho SYN, 'A' cho ACK trong tcp_flags string")
        
        self.assertEqual(flags['SYN'], 1)
        self.assertEqual(flags['ACK'], 0)
    
    def test_syn_ack_flag_count(self):
        """Verify SYN-ACK được đếm cho cả SYN và ACK"""
        log_test("SYN-ACK Flag Count", "SYN-ACK packet phải tăng cả SYN và ACK counter")
        
        pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        print(f"   📦 Created packet with flags='SA' (SYN-ACK)")
        
        info = self.parser.extract(pkt, 1)
        print(f"   📋 Parsed tcp_flags: '{info.tcp_flags}'")
        
        self.flow.add_backward_packet(info)  # Server response = backward
        
        flags = self.flow.get_bwd_tcp_flags_count()
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - SYN count: {flags['SYN']}")
        print(f"   - ACK count: {flags['ACK']}")
        
        log_result(flags['SYN'] == 1, "SYN = 1 (từ SA)", f"SYN = {flags['SYN']}")
        log_result(flags['ACK'] == 1, "ACK = 1 (từ SA)", f"ACK = {flags['ACK']}")
        
        print(f"\n   💡 HINT: 'SA' chứa cả 'S' và 'A' → cả 2 counters tăng")
        
        self.assertEqual(flags['SYN'], 1)
        self.assertEqual(flags['ACK'], 1)
    
    def test_all_tcp_flags(self):
        """Verify tất cả TCP flags được đếm đúng"""
        log_test("All TCP Flags", "Kiểm tra tất cả 6 loại flags: SYN, ACK, FIN, RST, PSH, URG")
        
        flag_packets = [
            ("S", "SYN"),
            ("SA", "SYN-ACK"),
            ("A", "ACK"),
            ("PA", "PSH-ACK"),
            ("FA", "FIN-ACK"),
            ("R", "RST"),
            ("U", "URG"),
        ]
        
        for i, (flags, desc) in enumerate(flag_packets):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags=flags)
            print(f"   📦 Packet {i+1}: flags='{flags}' ({desc})")
            info = self.parser.extract(pkt, i)
            self.flow.add_forward_packet(info)
        
        counts = self.flow.get_fwd_tcp_flags_count()
        
        print(f"\n   📊 KẾT QUẢ:")
        for flag_name, count in counts.items():
            print(f"   - {flag_name}: {count}")
        
        # Expected:
        # SYN: S + SA = 2
        # ACK: SA + A + PA + FA = 4
        # FIN: FA = 1
        # RST: R = 1
        # PSH: PA = 1
        # URG: U = 1
        
        log_result(counts['SYN'] == 2, "SYN = 2 (S + SA)", f"SYN = {counts['SYN']}")
        log_result(counts['ACK'] == 4, "ACK = 4 (SA + A + PA + FA)", f"ACK = {counts['ACK']}")
        log_result(counts['FIN'] == 1, "FIN = 1 (FA)", f"FIN = {counts['FIN']}")
        log_result(counts['RST'] == 1, "RST = 1 (R)", f"RST = {counts['RST']}")
        log_result(counts['PSH'] == 1, "PSH = 1 (PA)", f"PSH = {counts['PSH']}")
        log_result(counts['URG'] == 1, "URG = 1 (U)", f"URG = {counts['URG']}")
        
        print(f"\n   💡 HINT: _count_flags() check từng ký tự trong tcp_flags string")
        print(f"   💡 'S' in 'SA' → True, 'A' in 'SA' → True")
        
        self.assertEqual(counts['SYN'], 2)
        self.assertEqual(counts['ACK'], 4)
    
    def test_forward_backward_separation(self):
        """Verify forward và backward flags được đếm riêng biệt"""
        log_test("Forward/Backward Separation", "Flags từ client và server phải tách riêng")
        
        # Forward: Client SYN
        pkt_fwd = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        print(f"   📦 Forward (Client): SYN")
        info_fwd = self.parser.extract(pkt_fwd, 1)
        self.flow.add_forward_packet(info_fwd)
        
        # Backward: Server SYN-ACK
        pkt_bwd1 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        print(f"   📦 Backward (Server): SYN-ACK")
        info_bwd1 = self.parser.extract(pkt_bwd1, 2)
        self.flow.add_backward_packet(info_bwd1)
        
        # Backward: Server RST
        pkt_bwd2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="R")
        print(f"   📦 Backward (Server): RST")
        info_bwd2 = self.parser.extract(pkt_bwd2, 3)
        self.flow.add_backward_packet(info_bwd2)
        
        fwd_flags = self.flow.get_fwd_tcp_flags_count()
        bwd_flags = self.flow.get_bwd_tcp_flags_count()
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Forward flags: {fwd_flags}")
        print(f"   - Backward flags: {bwd_flags}")
        
        # Forward: chỉ SYN
        log_result(fwd_flags['SYN'] == 1, "Forward SYN = 1", f"Forward SYN = {fwd_flags['SYN']}")
        log_result(fwd_flags['RST'] == 0, "Forward RST = 0", f"Forward RST = {fwd_flags['RST']}")
        
        # Backward: SYN-ACK + RST
        log_result(bwd_flags['SYN'] == 1, "Backward SYN = 1", f"Backward SYN = {bwd_flags['SYN']}")
        log_result(bwd_flags['RST'] == 1, "Backward RST = 1", f"Backward RST = {bwd_flags['RST']}")
        
        print(f"\n   💡 HINT: Forward/Backward separation quan trọng cho F4 (RST Ratio)")
        print(f"   💡 RST từ server (backward) = port đóng hoặc connection refused")
        
        self.assertEqual(fwd_flags['SYN'], 1)
        self.assertEqual(bwd_flags['RST'], 1)


class TestFlowStatePayload(unittest.TestCase):
    """Test payload extraction với Scapy packets"""
    
    def setUp(self):
        self.flow = FlowState(
            flow_key=("192.168.1.100", "10.0.0.1", 5000, 80, 6),
            window_size=60.0
        )
        self.parser = PacketLayerExtractor(use_packet_time=False)
    
    def test_payload_extraction(self):
        """Verify payload được extract đúng"""
        log_test("Payload Extraction", "Raw payload từ packet phải được lưu đúng")
        
        payload_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=payload_data)
        
        print(f"   📦 Created packet with {len(payload_data)} bytes payload")
        print(f"   📝 Payload: {payload_data[:50]}...")
        
        info = self.parser.extract(pkt, 1)
        
        print(f"\n   📋 Parsed info:")
        print(f"   - has_payload: {info.has_payload}")
        print(f"   - payload_length: {info.payload_length}")
        
        self.flow.add_forward_packet(info)
        
        lengths = self.flow.get_fwd_payload_lengths()
        payloads = self.flow.get_fwd_payloads()
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Payload lengths: {lengths}")
        print(f"   - Payload count: {len(payloads)}")
        
        log_result(len(lengths) == 1, "1 payload recorded", f"{len(lengths)} payloads")
        log_result(lengths[0] == len(payload_data), f"Length = {len(payload_data)}", f"Length = {lengths[0]}")
        log_result(payloads[0] == payload_data, "Payload content matches", "Payload mismatch!")
        
        print(f"\n   💡 HINT: Payload được lưu nguyên bytes để detect SQLi/XSS patterns")
        
        self.assertEqual(lengths[0], len(payload_data))
        self.assertEqual(payloads[0], payload_data)
    
    def test_reassembled_payload(self):
        """Verify lazy reassembly nối payload theo thứ tự"""
        log_test("Payload Reassembly", "Multiple packets → concatenated payload")
        
        # Packet 1
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"Hello ")
        info1 = self.parser.extract(pkt1, 1)
        print(f"   📦 Packet 1: 'Hello '")
        
        # Packet 2
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"World!")
        info2 = self.parser.extract(pkt2, 2)
        print(f"   📦 Packet 2: 'World!'")
        
        self.flow.add_forward_packet(info1)
        self.flow.add_forward_packet(info2)
        
        reassembled = self.flow.get_reassembled_fwd_payload()
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Reassembled: {reassembled}")
        print(f"   - Length: {len(reassembled)}")
        
        log_result(reassembled == b"Hello World!", "Đúng: 'Hello World!'", f"Sai: {reassembled}")
        
        print(f"\n   💡 HINT: Lazy reassembly nối bytes theo thứ tự thêm vào")
        print(f"   💡 Dùng để detect attack patterns bị split qua nhiều packets")
        
        self.assertEqual(reassembled, b"Hello World!")


class TestFlowStateSlidingWindow(unittest.TestCase):
    """Test sliding window cleanup"""
    
    def test_sliding_window_cleanup(self):
        """Verify packets cũ bị cleanup"""
        log_test("Sliding Window Cleanup", "Packets cũ hơn window_size bị xóa")
        
        flow = FlowState(
            flow_key=("192.168.1.100", "10.0.0.1", 5000, 80, 6),
            window_size=5.0  # 5 giây window
        )
        
        parser = PacketLayerExtractor(use_packet_time=True)
        
        # Packet 1 @ t=1000
        pkt1 = Ether() / IP() / TCP(flags="S")
        pkt1.time = 1000.0
        info1 = parser.extract(pkt1, 1)
        flow.add_forward_packet(info1)
        print(f"   📦 Packet 1 @ t=1000.0 → fwd_count = {flow.get_fwd_packet_count()}")
        
        # Packet 2 @ t=1003
        pkt2 = Ether() / IP() / TCP(flags="A")
        pkt2.time = 1003.0
        info2 = parser.extract(pkt2, 2)
        flow.add_forward_packet(info2)
        print(f"   📦 Packet 2 @ t=1003.0 → fwd_count = {flow.get_fwd_packet_count()}")
        
        # Packet 3 @ t=1007 (pkt1 sẽ bị cleanup vì 1007 - 1000 > 5)
        pkt3 = Ether() / IP() / TCP(flags="PA")
        pkt3.time = 1007.0
        info3 = parser.extract(pkt3, 3)
        flow.add_forward_packet(info3)
        print(f"   📦 Packet 3 @ t=1007.0 → fwd_count = {flow.get_fwd_packet_count()}")
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Forward packets remaining: {flow.get_fwd_packet_count()}")
        
        # pkt1 (t=1000) bị xóa vì 1007 - 1000 > 5
        # pkt2 (t=1003) còn vì 1007 - 1003 = 4 < 5
        # pkt3 (t=1007) mới thêm
        
        log_result(flow.get_fwd_packet_count() == 2, 
                   "2 packets còn lại (pkt2, pkt3)", 
                   f"{flow.get_fwd_packet_count()} packets")
        
        print(f"\n   💡 HINT: window_size = 5s, current_time = 1007")
        print(f"   💡 cutoff = 1007 - 5 = 1002 → pkt1 (t=1000) < cutoff → bị xóa")
        
        self.assertEqual(flow.get_fwd_packet_count(), 2)


if __name__ == '__main__':
    print("\n" + "🚀"*35)
    print("         FLOW STATE UNIT TESTS")
    print("🚀"*35)
    
    unittest.main(verbosity=2)
