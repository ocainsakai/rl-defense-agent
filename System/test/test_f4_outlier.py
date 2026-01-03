# -*- coding: utf-8 -*-
"""
TEST: F4 Outlier Detection
Verify F4 can detect buffer overflow (large single packet)

Run: python test/test_f4_outlier.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.layer_info import LayerInfo
from core.window_packet import PacketWindow
from feature.feature_logic import Feature4_PayloadLength
from config import ai_config as config


def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def test_normal_traffic():
    """Test F4 with uniform payload sizes"""
    print_header("1. NORMAL TRAFFIC (Uniform Payloads)")
    
    window = PacketWindow(window_size=1.0)
    f4 = Feature4_PayloadLength()
    base_time = time.time()
    
    # All packets have similar payload sizes
    for i in range(100):
        info = LayerInfo(
            timestamp=base_time + i * 0.01,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            has_payload=True,
            payload_bytes=b"X" * 200,  # Uniform 200 bytes
            payload_length=200
        )
        window.add(info)
    
    raw = f4.calculate_raw(info, window)
    norm = f4.calculate(info, window)
    
    print(f"  100 packets × 200 bytes")
    print(f"  Average: 200, Max: 200")
    print(f"  F4 Raw:        {raw:.0f} bytes")
    print(f"  F4 Normalized: {norm:.4f}")
    print(f"  Expected:      ~200 (returns average)")
    
    assert 190 <= raw <= 210, f"Expected ~200, got {raw}"
    print("  [OK] Returns average for uniform traffic")


def test_buffer_overflow():
    """Test F4 detects buffer overflow outlier"""
    print_header("2. BUFFER OVERFLOW (Single Large Packet)")
    
    window = PacketWindow(window_size=1.0)
    f4 = Feature4_PayloadLength()
    base_time = time.time()
    
    # 99 normal packets + 1 large exploit packet
    for i in range(99):
        info = LayerInfo(
            timestamp=base_time + i * 0.01,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            has_payload=True,
            payload_bytes=b"X" * 100,  # Normal 100 bytes
            payload_length=100
        )
        window.add(info)
    
    # Large exploit packet
    exploit_info = LayerInfo(
        timestamp=base_time + 0.99,
        packet_number=100,
        has_ip=True,
        src_ip="192.168.1.100",
        has_payload=True,
        payload_bytes=b"A" * 8000,  # BUFFER OVERFLOW - 8000 bytes!
        payload_length=8000
    )
    window.add(exploit_info)
    
    raw = f4.calculate_raw(exploit_info, window)
    norm = f4.calculate(exploit_info, window)
    
    avg = (99 * 100 + 8000) / 100  # = 179 bytes
    
    print(f"  99 packets × 100 bytes + 1 packet × 8000 bytes")
    print(f"  Average: {avg:.0f}, Max: 8000")
    print(f"  F4 Raw:        {raw:.0f} bytes")
    print(f"  F4 Normalized: {norm:.4f}")
    print(f"  Expected:      8000 (returns max due to outlier)")
    
    assert raw == 8000, f"Expected 8000 (max), got {raw}"
    assert norm >= 0.9, f"Expected normalized >= 0.9, got {norm}"
    print("  [OK] Detects outlier and returns max")


def test_small_outlier_ignored():
    """Test F4 ignores small outliers (< 500 bytes)"""
    print_header("3. SMALL OUTLIER (Ignored)")
    
    window = PacketWindow(window_size=1.0)
    f4 = Feature4_PayloadLength()
    base_time = time.time()
    
    # 99 tiny packets + 1 slightly larger
    for i in range(99):
        info = LayerInfo(
            timestamp=base_time + i * 0.01,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            has_payload=True,
            payload_bytes=b"X" * 50,  # Tiny 50 bytes
            payload_length=50
        )
        window.add(info)
    
    # Slightly larger packet (but < 500 bytes threshold)
    larger_info = LayerInfo(
        timestamp=base_time + 0.99,
        packet_number=100,
        has_ip=True,
        src_ip="192.168.1.100",
        has_payload=True,
        payload_bytes=b"A" * 400,  # 400 bytes (8× avg, but < 500 threshold)
        payload_length=400
    )
    window.add(larger_info)
    
    raw = f4.calculate_raw(larger_info, window)
    
    avg = (99 * 50 + 400) / 100  # = 53.5 bytes
    
    print(f"  99 packets × 50 bytes + 1 packet × 400 bytes")
    print(f"  Average: {avg:.1f}, Max: 400")
    print(f"  F4 Raw:        {raw:.1f} bytes")
    print(f"  Expected:      ~{avg:.1f} (returns average, outlier < 500)")
    
    assert abs(raw - avg) < 1, f"Expected ~{avg}, got {raw}"
    print("  [OK] Ignores small outliers")


def test_syn_flood():
    """Test F4 with SYN flood (no payload)"""
    print_header("4. SYN FLOOD (Zero Payload)")
    
    window = PacketWindow(window_size=1.0)
    f4 = Feature4_PayloadLength()
    base_time = time.time()
    
    # SYN packets have no payload
    for i in range(1000):
        info = LayerInfo(
            timestamp=base_time + i * 0.001,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            has_tcp=True,
            tcp_flags="S",
            has_payload=False,  # No payload
            payload_length=0
        )
        window.add(info)
    
    raw = f4.calculate_raw(info, window)
    norm = f4.calculate(info, window)
    
    print(f"  1000 SYN packets (no payload)")
    print(f"  F4 Raw:        {raw:.0f} bytes")
    print(f"  F4 Normalized: {norm:.4f}")
    print(f"  Expected:      0")
    
    assert raw == 0, f"Expected 0, got {raw}"
    print("  [OK] Returns 0 for SYN flood")


def main():
    print("\n" + "#" * 60)
    print("#    F4 OUTLIER DETECTION TEST")
    print("#" * 60)
    
    tests = [
        test_normal_traffic,
        test_buffer_overflow,
        test_small_outlier_ignored,
        test_syn_flood,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n  [FAILED] {e}")
            failed += 1
        except Exception as e:
            print(f"\n  [ERROR] {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"  RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n  ✅ F4 OUTLIER DETECTION WORKING!")
        print("     - Normal traffic: returns average")
        print("     - Buffer overflow: returns max")
        print("     - Small outliers: ignored (< 500 bytes)")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
