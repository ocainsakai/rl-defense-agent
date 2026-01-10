"""
Test script để xác nhận logic FlowManager và bidirectional tracking hoạt động đúng.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo
import time


def create_test_packet(src_ip, dst_ip, src_port, dst_port, protocol=6, tcp_flags="S"):
    """Tạo LayerInfo giả để test"""
    info = LayerInfo(
        timestamp=time.time(),
        packet_number=0,
        has_ip=True,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
    )
    
    if protocol == 6:  # TCP
        info.has_tcp = True
        info.tcp_sport = src_port
        info.tcp_dport = dst_port
        info.tcp_flags = tcp_flags
    elif protocol == 17:  # UDP
        info.has_udp = True
        info.udp_sport = src_port
        info.udp_dport = dst_port
    
    return info


def test_bidirectional_tracking():
    """Test: Forward và Backward packets phải gộp vào cùng 1 FlowState"""
    
    print("=" * 60)
    print("TEST 1: Bidirectional Tracking")
    print("=" * 60)
    
    manager = FlowManager(window_size=60.0, flow_timeout=120.0)
    
    # Packet 1: Client → Server (Forward)
    pkt1 = create_test_packet(
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        tcp_flags="S"
    )
    flow1 = manager.process_packet(pkt1)
    print(f"Packet 1 (Forward): 192.168.1.10:54321 → 10.0.0.1:80")
    print(f"  → Flow created: {flow1.flow_key}")
    print(f"  → Total flows: {len(manager.flows)}")
    
    # Packet 2: Server → Client (Backward - SHOULD use same flow!)
    pkt2 = create_test_packet(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=54321,
        tcp_flags="SA"
    )
    flow2 = manager.process_packet(pkt2)
    print(f"\nPacket 2 (Backward): 10.0.0.1:80 → 192.168.1.10:54321")
    print(f"  → Flow used: {flow2.flow_key}")
    print(f"  → Total flows: {len(manager.flows)}")
    
    # Kiểm tra
    if flow1 is flow2:
        print("\n✅ PASS: Cả 2 packets gộp vào CÙNG 1 FlowState")
    else:
        print("\n❌ FAIL: 2 packets tạo 2 FlowState khác nhau!")
        return False
    
    # Kiểm tra packet counts
    print(f"\nFlowState contents:")
    print(f"  → Forward packets: {flow1.get_fwd_packet_count()}")
    print(f"  → Backward packets: {flow1.get_bwd_packet_count()}")
    
    if flow1.get_fwd_packet_count() == 1 and flow1.get_bwd_packet_count() == 1:
        print("✅ PASS: Forward và Backward được phân loại đúng")
    else:
        print("❌ FAIL: Phân loại Forward/Backward sai!")
        return False
    
    return True


def test_different_connections():
    """Test: 2 connections khác nhau phải tạo 2 FlowState khác nhau"""
    
    print("\n" + "=" * 60)
    print("TEST 2: Different Connections")
    print("=" * 60)
    
    manager = FlowManager(window_size=60.0, flow_timeout=120.0)
    
    # Connection 1: Port 80
    pkt1 = create_test_packet("192.168.1.10", "10.0.0.1", 54321, 80)
    flow1 = manager.process_packet(pkt1)
    print(f"Connection 1: 192.168.1.10:54321 → 10.0.0.1:80")
    
    # Connection 2: Port 443 (KHÁC port → KHÁC flow)
    pkt2 = create_test_packet("192.168.1.10", "10.0.0.1", 54322, 443)
    flow2 = manager.process_packet(pkt2)
    print(f"Connection 2: 192.168.1.10:54322 → 10.0.0.1:443")
    
    print(f"\nTotal flows: {len(manager.flows)}")
    
    if flow1 is not flow2:
        print("✅ PASS: 2 connections khác nhau tạo 2 FlowState khác nhau")
        return True
    else:
        print("❌ FAIL: 2 connections bị gộp nhầm vào 1 FlowState!")
        return False


def test_port_scan_creates_many_flows():
    """Test: Port scan (nhiều dst_port) phải tạo nhiều FlowState"""
    
    print("\n" + "=" * 60)
    print("TEST 3: Port Scan Detection")
    print("=" * 60)
    
    manager = FlowManager(window_size=60.0, flow_timeout=120.0)
    
    # Simulate port scan: 1 src → nhiều dst_ports
    for port in [22, 23, 80, 443, 8080]:
        pkt = create_test_packet("10.0.0.50", "192.168.1.1", 40000, port)
        manager.process_packet(pkt)
        print(f"  Scan port {port}")
    
    print(f"\nTotal flows: {len(manager.flows)}")
    
    if len(manager.flows) == 5:
        print("✅ PASS: Mỗi port tạo 1 flow riêng (đúng cho 5-tuple)")
        return True
    else:
        print(f"❌ FAIL: Expected 5 flows, got {len(manager.flows)}")
        return False


def test_flow_key_creation():
    """Test: Kiểm tra flow_key được tạo đúng format"""
    
    print("\n" + "=" * 60)
    print("TEST 4: Flow Key Format")
    print("=" * 60)
    
    manager = FlowManager()
    
    pkt = create_test_packet("192.168.1.10", "10.0.0.1", 54321, 80, protocol=6)
    flow_key = manager._make_flow_key(pkt)
    
    print(f"Packet: 192.168.1.10:54321 → 10.0.0.1:80 (TCP)")
    print(f"Flow key: {flow_key}")
    
    expected = ('192.168.1.10', '10.0.0.1', 54321, 80, 6)
    if flow_key == expected:
        print("✅ PASS: Flow key format đúng")
        return True
    else:
        print(f"❌ FAIL: Expected {expected}")
        return False


def test_reverse_key_creation():
    """Test: Kiểm tra reverse_key được tạo đúng"""
    
    print("\n" + "=" * 60)
    print("TEST 5: Reverse Key Detection")
    print("=" * 60)
    
    manager = FlowManager()
    
    flow_key = ('192.168.1.10', '10.0.0.1', 54321, 80, 6)
    reverse_key = manager._make_reverse_key(flow_key)
    
    print(f"Flow key:    {flow_key}")
    print(f"Reverse key: {reverse_key}")
    
    expected = ('10.0.0.1', '192.168.1.10', 80, 54321, 6)
    if reverse_key == expected:
        print("✅ PASS: Reverse key đúng")
        return True
    else:
        print(f"❌ FAIL: Expected {expected}")
        return False


def main():
    print("\n" + "=" * 60)
    print("TESTING FLOW MANAGER LOGIC")
    print("=" * 60 + "\n")
    
    results = []
    
    results.append(("Flow Key Format", test_flow_key_creation()))
    results.append(("Reverse Key Detection", test_reverse_key_creation()))
    results.append(("Bidirectional Tracking", test_bidirectional_tracking()))
    results.append(("Different Connections", test_different_connections()))
    results.append(("Port Scan Flows", test_port_scan_creates_many_flows()))
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 ALL TESTS PASSED - Logic code đã ĐÚNG!")
    else:
        print("⚠️  SOME TESTS FAILED - Cần kiểm tra lại code!")
    print("=" * 60)


if __name__ == "__main__":
    main()
