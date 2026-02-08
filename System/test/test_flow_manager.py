"""
Unit Tests cho FlowManager - SỬ DỤNG SCAPY PACKETS THỰC

Verify:
1. Bidirectional flow tracking (cùng 5-tuple đổi chiều → 1 flow)
2. Forward/Backward classification
3. Flow key creation
4. Memory management (cleanup, max_flows)
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo


def log_test(test_name, description):
    """Helper: In header cho mỗi test"""
    print(f"\n{'='*70}")
    print(f"🧪 TEST: {test_name}")
    print(f"📝 {description}")
    print(f"{'='*70}")


def log_packet(pkt, label="Packet"):
    """Helper: In thông tin packet"""
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport if pkt.haslayer(UDP) else 0
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0
        flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else "N/A"
        print(f"   📦 {label}: {src}:{sport} → {dst}:{dport} [{proto}] Flags={flags}")


def log_result(condition, success_msg, fail_msg):
    """Helper: In kết quả với hint"""
    if condition:
        print(f"   ✅ PASS: {success_msg}")
    else:
        print(f"   ❌ FAIL: {fail_msg}")
    return condition


class TestFlowManagerWithScapy(unittest.TestCase):
    """Test cases cho FlowManager sử dụng Scapy packets thực"""
    
    def setUp(self):
        """Khởi tạo parser và flow manager"""
        self.parser = PacketLayerExtractor(
            enable_http_parsing=True,
            use_packet_time=False  # Dùng thời gian hiện tại
        )
        self.fm = FlowManager(
            window_size=10.0,
            flow_timeout=30.0,
            cleanup_interval=1000
        )
    
    def test_bidirectional_same_flow(self):
        """
        Packets cùng 5-tuple nhưng đổi chiều src/dst → phải cùng 1 flow
        """
        log_test("Bidirectional Same Flow", 
                 "Packet A→B và B→A phải thuộc CÙNG 1 flow (không tạo 2 flows)")
        
        # Tạo packet 1: Client → Server (SYN)
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        log_packet(pkt1, "Packet 1 (Client→Server SYN)")
        
        # Tạo packet 2: Server → Client (SYN-ACK)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        log_packet(pkt2, "Packet 2 (Server→Client SYN-ACK)")
        
        # Parse và process
        info1 = self.parser.extract(pkt1, 1)
        info2 = self.parser.extract(pkt2, 2)
        
        flow1 = self.fm.process_packet(info1)
        flow2 = self.fm.process_packet(info2)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Flow sau packet 1: src_ip={flow1.src_ip}, fwd={flow1.get_fwd_packet_count()}, bwd={flow1.get_bwd_packet_count()}")
        print(f"   - Flow sau packet 2: src_ip={flow2.src_ip}, fwd={flow2.get_fwd_packet_count()}, bwd={flow2.get_bwd_packet_count()}")
        print(f"   - Số flows trong FlowManager: {len(self.fm.flows)}")
        
        # Assertions với hints
        same_flow = flow1 is flow2
        log_result(same_flow, 
                   "Cả 2 packets cùng 1 flow object (đúng!)",
                   "2 packets tạo ra 2 flows khác nhau (SAI!)")
        
        single_flow = len(self.fm.flows) == 1
        log_result(single_flow,
                   f"Chỉ có 1 flow trong manager",
                   f"Có {len(self.fm.flows)} flows (SAI!)")
        
        fwd_count = flow2.get_fwd_packet_count() == 1
        log_result(fwd_count,
                   "Forward count = 1 (packet từ client)",
                   f"Forward count = {flow2.get_fwd_packet_count()} (SAI!)")
        
        bwd_count = flow2.get_bwd_packet_count() == 1
        log_result(bwd_count,
                   "Backward count = 1 (packet từ server)",
                   f"Backward count = {flow2.get_bwd_packet_count()} (SAI!)")
        
        print(f"\n   💡 HINT: FlowManager check cả flow_key VÀ reverse_key trước khi tạo flow mới")
        print(f"   💡 Logic: packet2.src_ip (10.0.0.1) != flow.src_ip (192.168.1.100) → BACKWARD")
        
        self.assertIs(flow1, flow2)
        self.assertEqual(len(self.fm.flows), 1)
    
    def test_tcp_handshake_classification(self):
        """
        Mô phỏng TCP 3-way handshake và verify direction
        """
        log_test("TCP 3-Way Handshake",
                 "SYN→SYN-ACK→ACK phải được classify đúng Forward/Backward")
        
        # Packet 1: Client SYN
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        log_packet(pkt1, "Step 1: Client SYN")
        
        # Packet 2: Server SYN-ACK  
        pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=5000, flags="SA")
        log_packet(pkt2, "Step 2: Server SYN-ACK")
        
        # Packet 3: Client ACK
        pkt3 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="A")
        log_packet(pkt3, "Step 3: Client ACK")
        
        # Process all
        for i, pkt in enumerate([pkt1, pkt2, pkt3], 1):
            info = self.parser.extract(pkt, i)
            self.fm.process_packet(info)
        
        flow = list(self.fm.flows.values())[0]
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Forward packets (Client→Server): {flow.get_fwd_packet_count()}")
        print(f"   - Backward packets (Server→Client): {flow.get_bwd_packet_count()}")
        
        fwd_flags = flow.get_fwd_tcp_flags_count()
        bwd_flags = flow.get_bwd_tcp_flags_count()
        
        print(f"   - Forward flags: SYN={fwd_flags['SYN']}, ACK={fwd_flags['ACK']}")
        print(f"   - Backward flags: SYN={bwd_flags['SYN']}, ACK={bwd_flags['ACK']}")
        
        # Verify
        log_result(flow.get_fwd_packet_count() == 2,
                   "Forward = 2 (SYN + ACK từ client)",
                   f"Forward = {flow.get_fwd_packet_count()}")
        
        log_result(flow.get_bwd_packet_count() == 1,
                   "Backward = 1 (SYN-ACK từ server)",
                   f"Backward = {flow.get_bwd_packet_count()}")
        
        log_result(fwd_flags['SYN'] == 1,
                   "Forward SYN = 1 (client gửi 1 SYN)",
                   f"Forward SYN = {fwd_flags['SYN']}")
        
        log_result(bwd_flags['SYN'] == 1 and bwd_flags['ACK'] == 1,
                   "Backward có SYN-ACK (server response)",
                   f"Backward SYN={bwd_flags['SYN']}, ACK={bwd_flags['ACK']}")
        
        print(f"\n   💡 HINT: Forward = packets có src_ip == flow.src_ip (client IP)")
        print(f"   💡 Packet đầu tiên LUÔN là Forward và xác định flow.src_ip")
        
        self.assertEqual(flow.get_fwd_packet_count(), 2)
        self.assertEqual(flow.get_bwd_packet_count(), 1)
    
    def test_different_flows_different_ports(self):
        """
        Packets khác port → phải là 2 flows khác nhau
        """
        log_test("Different Ports = Different Flows",
                 "Cùng src_ip, dst_ip nhưng khác port → 2 flows riêng biệt")
        
        # Flow 1: Port 80
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        log_packet(pkt1, "Flow 1: Port 80")
        
        # Flow 2: Port 443
        pkt2 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5001, dport=443, flags="S")
        log_packet(pkt2, "Flow 2: Port 443")
        
        info1 = self.parser.extract(pkt1, 1)
        info2 = self.parser.extract(pkt2, 2)
        
        flow1 = self.fm.process_packet(info1)
        flow2 = self.fm.process_packet(info2)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Flow 1 key: {flow1.flow_key}")
        print(f"   - Flow 2 key: {flow2.flow_key}")
        print(f"   - Số flows: {len(self.fm.flows)}")
        
        log_result(flow1 is not flow2,
                   "2 flows khác nhau (đúng - khác port)",
                   "Cùng 1 flow (SAI!)")
        
        log_result(len(self.fm.flows) == 2,
                   "FlowManager có 2 flows",
                   f"FlowManager có {len(self.fm.flows)} flows")
        
        print(f"\n   💡 HINT: 5-tuple = (src_ip, dst_ip, src_port, dst_port, protocol)")
        print(f"   💡 Khác BẤT KỲ element nào → flow khác nhau")
        
        self.assertIsNot(flow1, flow2)
        self.assertEqual(len(self.fm.flows), 2)
    
    def test_udp_flow(self):
        """
        Verify UDP flow tracking
        """
        log_test("UDP Flow Tracking",
                 "UDP packets cũng được gom flow bidirectional")
        
        # DNS Query
        pkt1 = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=12345, dport=53) / Raw(b"\x00\x01")
        log_packet(pkt1, "DNS Query (Client→Server)")
        
        # DNS Response
        pkt2 = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=12345) / Raw(b"\x00\x02")
        log_packet(pkt2, "DNS Response (Server→Client)")
        
        info1 = self.parser.extract(pkt1, 1)
        info2 = self.parser.extract(pkt2, 2)
        
        flow1 = self.fm.process_packet(info1)
        flow2 = self.fm.process_packet(info2)
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Protocol: {flow1.protocol} (17 = UDP)")
        print(f"   - Forward (query): {flow1.get_fwd_packet_count()}")
        print(f"   - Backward (response): {flow2.get_bwd_packet_count()}")
        
        log_result(flow1 is flow2,
                   "Query và Response cùng 1 flow",
                   "Khác flow (SAI!)")
        
        log_result(flow1.protocol == 17,
                   "Protocol = 17 (UDP)",
                   f"Protocol = {flow1.protocol}")
        
        print(f"\n   💡 HINT: UDP không có flags, nhưng vẫn track bidirectional bằng 5-tuple")
        
        self.assertIs(flow1, flow2)
        self.assertEqual(flow1.protocol, 17)
    
    def test_port_scan_detection_setup(self):
        """
        Mô phỏng port scan và verify distinct ports
        """
        log_test("Port Scan Scenario",
                 "Attacker scan nhiều ports → nhiều flows với distinct dst_ports")
        
        target_ports = [22, 80, 443, 8080, 3306, 5432, 6379, 27017, 9200, 11211]
        
        print(f"   🎯 Target ports: {target_ports}")
        
        for port in target_ports:
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000+port, dport=port, flags="S")
            info = self.parser.extract(pkt, port)
            self.fm.process_packet(info)
        
        # Lấy tất cả flows từ src_ip này
        flows = self.fm.get_flows_by_src("192.168.1.100")
        
        # Gom distinct ports
        all_ports = set()
        for f in flows:
            all_ports.update(f.get_distinct_ports())
        
        print(f"\n   📊 KẾT QUẢ:")
        print(f"   - Số flows từ attacker IP: {len(flows)}")
        print(f"   - Distinct destination ports: {len(all_ports)}")
        print(f"   - Ports: {sorted(all_ports)}")
        
        log_result(len(flows) == 10,
                   f"10 flows (1 flow/port)",
                   f"{len(flows)} flows")
        
        log_result(len(all_ports) == 10,
                   "10 distinct ports (F5 = 10)",
                   f"{len(all_ports)} ports")
        
        print(f"\n   💡 HINT: F5 (Distinct Ports) > 10 → Có thể là Port Scan!")
        print(f"   💡 Normal user thường chỉ connect đến 1-5 ports")
        
        self.assertEqual(len(flows), 10)
        self.assertEqual(len(all_ports), 10)


class TestFlowManagerCleanup(unittest.TestCase):
    """Test cleanup logic với timestamps"""
    
    def setUp(self):
        self.parser = PacketLayerExtractor(use_packet_time=True)  # Dùng PCAP time
    
    def test_flow_expiration(self):
        """
        Verify flows hết hạn bị cleanup
        """
        log_test("Flow Expiration",
                 "Flow không có traffic sau timeout → bị xóa")
        
        fm = FlowManager(
            window_size=10.0,
            flow_timeout=5.0,  # 5 giây timeout
            cleanup_interval=1  # Cleanup mỗi packet
        )
        
        # Packet 1 tại t=1000
        pkt1 = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="S")
        pkt1.time = 1000.0
        log_packet(pkt1, "Packet 1 @ t=1000")
        
        info1 = self.parser.extract(pkt1, 1)
        fm.process_packet(info1)
        
        print(f"   - Flows sau packet 1: {len(fm.flows)}")
        
        # Packet 2 tại t=1010 (flow cũ đã timeout)
        pkt2 = Ether() / IP(src="192.168.1.200", dst="10.0.0.1") / TCP(sport=6000, dport=80, flags="S")
        pkt2.time = 1010.0
        log_packet(pkt2, "Packet 2 @ t=1010 (từ IP khác)")
        
        info2 = self.parser.extract(pkt2, 2)
        fm.process_packet(info2)
        
        print(f"   - Flows sau packet 2: {len(fm.flows)}")
        
        # Check flow cũ đã bị xóa
        remaining_ips = [f.src_ip for f in fm.flows.values()]
        print(f"   - Remaining src_ips: {remaining_ips}")
        
        log_result(len(fm.flows) == 1,
                   "Flow cũ bị cleanup (chỉ còn flow mới)",
                   f"Có {len(fm.flows)} flows")
        
        log_result("192.168.1.200" in remaining_ips,
                   "Flow mới (192.168.1.200) còn tồn tại",
                   "Flow mới không tồn tại")
        
        log_result("192.168.1.100" not in remaining_ips,
                   "Flow cũ (192.168.1.100) đã bị cleanup",
                   "Flow cũ vẫn tồn tại (SAI!)")
        
        print(f"\n   💡 HINT: Flow timeout = 5s, packet 2 đến sau 10s → flow 1 expired")
        print(f"   💡 Cleanup chạy mỗi cleanup_interval packets")
        
        self.assertEqual(len(fm.flows), 1)


if __name__ == '__main__':
    print("\n" + "🚀"*35)
    print("         FLOW MANAGER UNIT TESTS")
    print("🚀"*35)
    
    unittest.main(verbosity=2)
