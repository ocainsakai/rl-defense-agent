# -*- coding: utf-8 -*-
"""
TEST: Verify Phase 1 Optimizations
- maxlen = 2000
- MAX_PACKET_RATE = 2000

Run: python test/test_phase1_config.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.layer_info import LayerInfo
from core.window_packet import PacketWindow
from core.processor import FeatureVectorBuilder
from config import ai_config as config
from feature.feature_logic import Feature1_PacketRate


def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def test_config_values():
    """Verify config values are correct"""
    print_header("1. CONFIG VALUES")
    
    print(f"  MAX_PACKET_RATE = {config.MAX_PACKET_RATE}")
    assert config.MAX_PACKET_RATE == 2000.0, f"Expected 2000, got {config.MAX_PACKET_RATE}"
    print("  [OK] MAX_PACKET_RATE = 2000")
    
    # Check maxlen by creating window and adding packets
    window = PacketWindow(window_size=1.0)
    base_time = time.time()
    
    # Add 2500 packets (should be capped at 2000)
    for i in range(2500):
        info = LayerInfo(
            timestamp=base_time + i * 0.0001,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100"
        )
        window.add(info)
    
    count = window.get_count("192.168.1.100")
    print(f"  Added 2500 packets, stored = {count}")
    assert count == 2000, f"Expected maxlen=2000, but stored {count}"
    print("  [OK] maxlen = 2000")


def test_normalized_values():
    """Verify normalized values are correct with new config"""
    print_header("2. NORMALIZED VALUES")
    
    window = PacketWindow(window_size=1.0)
    f1 = Feature1_PacketRate()
    base_time = time.time()
    
    # Test case 1: 1000 packets/s → should be 0.5 normalized
    for i in range(1000):
        info = LayerInfo(
            timestamp=base_time + i * 0.001,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100"
        )
        window.add(info)
    
    raw = f1.calculate_raw(info, window)
    norm = f1.calculate(info, window)
    
    print(f"  1000 packets in 1s:")
    print(f"    Raw:        {raw:.0f} pkt/s")
    print(f"    Normalized: {norm:.4f}")
    print(f"    Expected:   ~0.5 (1000/2000)")
    assert 0.4 <= norm <= 0.6, f"Expected ~0.5, got {norm}"
    print("  [OK] 1000 pkt/s → ~0.5")
    
    # Test case 2: 2000 packets/s → should be 1.0 normalized
    window.clear()
    for i in range(2000):
        info = LayerInfo(
            timestamp=base_time + i * 0.0005,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100"
        )
        window.add(info)
    
    raw = f1.calculate_raw(info, window)
    norm = f1.calculate(info, window)
    
    print(f"\n  2000 packets in 1s:")
    print(f"    Raw:        {raw:.0f} pkt/s")
    print(f"    Normalized: {norm:.4f}")
    print(f"    Expected:   1.0 (2000/2000)")
    assert norm >= 0.95, f"Expected ~1.0, got {norm}"
    print("  [OK] 2000 pkt/s → 1.0")


def test_attack_scenarios():
    """Test attack detection with new config"""
    print_header("3. ATTACK SCENARIO DETECTION")
    
    builder = FeatureVectorBuilder(window_size=1.0)
    base_time = time.time()
    
    # Scenario: SYN Flood with 1500 pkt/s
    print("\n  SYN FLOOD (1500 pkt/s):")
    
    for i in range(1500):
        info = LayerInfo(
            timestamp=base_time + i * 0.00067,  # ~1500 in 1s
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            has_tcp=True,
            tcp_sport=54321,
            tcp_dport=80 + (i % 50),
            tcp_flags="S"  # Only SYN
        )
        vector = builder.process_layer_info(info)
    
    print(f"    F1 (Packet Rate): {vector[0]:.4f} (expected: ~0.75)")
    print(f"    F2 (SYN Ratio):   {vector[1]:.4f} (expected: 1.0)")
    print(f"    F3 (Ports):       {vector[2]:.4f} (expected: ~0.5)")
    
    # Check F1 is high
    assert vector[0] >= 0.6, f"F1 too low: {vector[0]}"
    print("  [OK] F1 correctly shows HIGH rate")
    
    # Check F2 is maximum (all SYN, no ACK)
    assert vector[1] >= 0.9, f"F2 too low: {vector[1]}"
    print("  [OK] F2 correctly shows HIGH SYN ratio")


def test_normal_traffic():
    """Test normal traffic doesn't trigger false positive"""
    print_header("4. NORMAL TRAFFIC (No False Positive)")
    
    builder = FeatureVectorBuilder(window_size=1.0)
    base_time = time.time()
    
    # Scenario: Normal web browsing - 50 pkt/s
    print("\n  Normal browsing (50 pkt/s):")
    
    for i in range(50):
        info = LayerInfo(
            timestamp=base_time + i * 0.02,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            has_tcp=True,
            tcp_sport=54321,
            tcp_dport=443,  # HTTPS only
            tcp_flags="A" if i % 3 != 0 else "S"  # Mix of SYN and ACK
        )
        vector = builder.process_layer_info(info)
    
    print(f"    F1 (Packet Rate): {vector[0]:.4f} (expected: <0.1)")
    print(f"    F2 (SYN Ratio):   {vector[1]:.4f} (expected: ~0.33)")
    print(f"    F3 (Ports):       {vector[2]:.4f} (expected: ~0.01)")
    
    # Check F1 is low
    assert vector[0] < 0.1, f"F1 too high for normal traffic: {vector[0]}"
    print("  [OK] F1 correctly shows LOW rate")
    
    # Check F3 is low (only 1 port)
    assert vector[2] < 0.05, f"F3 too high: {vector[2]}"
    print("  [OK] F3 correctly shows single port")


def test_performance():
    """Test performance with new config"""
    print_header("5. PERFORMANCE")
    
    window = PacketWindow(window_size=1.0)
    base_time = time.time()
    
    # Add 2000 packets
    start = time.perf_counter()
    for i in range(2000):
        info = LayerInfo(
            timestamp=base_time + i * 0.0005,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            has_tcp=True,
            tcp_flags="S"
        )
        window.add(info)
    add_time = (time.perf_counter() - start) * 1000
    
    print(f"  Add 2000 packets: {add_time:.2f} ms")
    print(f"  Rate: {2000 / (add_time/1000):,.0f} pkt/s")
    
    # Feature calculation
    from feature.feature_logic import (
        Feature1_PacketRate, Feature2_SynAckRatio, Feature3_DistinctPorts,
        Feature4_PayloadLength, Feature5_FailRate, Feature6_ContextScore
    )
    
    features = [
        Feature1_PacketRate(),
        Feature2_SynAckRatio(),
        Feature3_DistinctPorts(),
        Feature4_PayloadLength(),
        Feature5_FailRate(),
        Feature6_ContextScore()
    ]
    
    start = time.perf_counter()
    for _ in range(100):
        for f in features:
            f.calculate(info, window)
    calc_time = (time.perf_counter() - start) * 1000
    
    print(f"  Calculate 6 features x 100: {calc_time:.2f} ms")
    print(f"  Per vector: {calc_time/100:.3f} ms")
    
    assert calc_time/100 < 5, f"Too slow: {calc_time/100:.3f} ms per vector"
    print("  [OK] Performance acceptable for real-time")


def main():
    print("\n" + "#" * 60)
    print("#    PHASE 1 OPTIMIZATION TEST")
    print("#" * 60)
    
    tests = [
        test_config_values,
        test_normalized_values,
        test_attack_scenarios,
        test_normal_traffic,
        test_performance,
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
        print("\n  ✅ PHASE 1 OPTIMIZATION COMPLETE!")
        print("     - maxlen = 2000")
        print("     - MAX_PACKET_RATE = 2000")
        print("     - All tests passed")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
