# -*- coding: utf-8 -*-
"""
SYSTEM MEASUREMENT SCRIPT FOR RL DEFENSE AGENT
Đo các thông số: RAM, Throughput, Latency

Run: python test/measure_system.py
"""

import sys
import os
import time
import gc

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("[WARNING] psutil not installed. Run: pip install psutil")

from core.layer_info import LayerInfo
from core.window_packet import PacketWindow
from feature.feature_logic import (
    Feature1_PacketRate, 
    Feature2_SynAckRatio,
    Feature3_DistinctPorts, 
    Feature4_PayloadLength,
    Feature5_FailRate, 
    Feature6_ContextScore
)


def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def measure_ram():
    """Đo RAM hệ thống"""
    print_header("1. RAM INFORMATION")
    
    if not HAS_PSUTIL:
        print("  [SKIPPED] psutil not available")
        return None
    
    mem = psutil.virtual_memory()
    
    total_gb = mem.total / (1024**3)
    available_gb = mem.available / (1024**3)
    used_percent = mem.percent
    suggested_gb = available_gb * 0.2  # 20% of available
    
    print(f"  Total RAM:       {total_gb:.2f} GB")
    print(f"  Available RAM:   {available_gb:.2f} GB")
    print(f"  Used:            {used_percent:.1f}%")
    print(f"  Suggested for detection: {suggested_gb:.2f} GB (20% of available)")
    
    return {
        'total_gb': total_gb,
        'available_gb': available_gb,
        'suggested_gb': suggested_gb
    }


def measure_memory_usage():
    """Đo memory usage của các components"""
    print_header("2. MEMORY USAGE PER COMPONENT")
    
    if not HAS_PSUTIL:
        print("  [SKIPPED] psutil not available")
        return None
    
    process = psutil.Process(os.getpid())
    
    # Baseline
    gc.collect()
    baseline_mem = process.memory_info().rss / (1024**2)  # MB
    
    # Measure PacketWindow with 1000 packets
    window = PacketWindow(window_size=1.0)
    base_time = time.time()
    
    for i in range(1000):
        info = LayerInfo(
            timestamp=base_time + i * 0.001,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            has_tcp=True,
            tcp_sport=54321,
            tcp_dport=80,
            tcp_flags="S",
            has_payload=True,
            payload_bytes=b"test data " * 10,
            payload_length=100
        )
        window.add(info)
    
    gc.collect()
    window_mem = process.memory_info().rss / (1024**2) - baseline_mem
    
    # Measure with 10 IPs x 1000 packets each
    for ip_idx in range(9):  # Already have 1 IP
        for i in range(1000):
            info = LayerInfo(
                timestamp=base_time + i * 0.001,
                packet_number=i,
                has_ip=True,
                src_ip=f"192.168.1.{ip_idx + 1}",
                dst_ip="10.0.0.1",
                has_tcp=True,
                tcp_sport=54321 + i,
                tcp_dport=80 + (i % 100),
                tcp_flags="S" if i % 2 == 0 else "A",
                has_payload=True,
                payload_bytes=b"test data " * 10,
                payload_length=100
            )
            window.add(info)
    
    gc.collect()
    multi_ip_mem = process.memory_info().rss / (1024**2) - baseline_mem
    
    per_ip_mem = multi_ip_mem / 10  # 10 IPs
    
    print(f"  Baseline memory:           {baseline_mem:.2f} MB")
    print(f"  + 1000 packets (1 IP):     +{window_mem:.2f} MB")
    print(f"  + 10000 packets (10 IPs):  +{multi_ip_mem:.2f} MB")
    print(f"  Average per IP:            {per_ip_mem:.2f} MB")
    
    # Estimate capacity
    if HAS_PSUTIL:
        available_mb = psutil.virtual_memory().available / (1024**2)
        suggested_mb = available_mb * 0.2
        max_ips = int(suggested_mb / per_ip_mem) if per_ip_mem > 0 else 10000
        print(f"\n  => Estimated capacity: ~{max_ips:,} IPs with 1000 packets each")
    
    # Cleanup
    del window
    gc.collect()
    
    return {
        'per_ip_mb': per_ip_mem,
        'baseline_mb': baseline_mem
    }


def measure_throughput():
    """Đo throughput xử lý features"""
    print_header("3. THROUGHPUT BENCHMARK")
    
    window = PacketWindow(window_size=1.0)
    features = [
        Feature1_PacketRate(),
        Feature2_SynAckRatio(),
        Feature3_DistinctPorts(),
        Feature4_PayloadLength(),
        Feature5_FailRate(),
        Feature6_ContextScore()
    ]
    
    # Test different scales
    test_sizes = [1000, 5000, 10000]
    results = {}
    
    for num_packets in test_sizes:
        # Reset window
        window.clear()
        base_time = time.time()
        
        # Generate test packets
        test_packets = []
        for i in range(num_packets):
            info = LayerInfo(
                timestamp=base_time + i * 0.0001,
                packet_number=i,
                has_ip=True,
                src_ip=f"192.168.1.{i % 255}",
                dst_ip="10.0.0.1",
                has_tcp=True,
                tcp_sport=54321 + (i % 1000),
                tcp_dport=80 + (i % 100),
                tcp_flags="S" if i % 3 == 0 else ("A" if i % 3 == 1 else "PA"),
                has_payload=i % 2 == 0,
                payload_bytes=b"test data " * 10 if i % 2 == 0 else None,
                payload_length=100 if i % 2 == 0 else 0
            )
            test_packets.append(info)
        
        # Benchmark: window.add()
        start = time.perf_counter()
        for pkt in test_packets:
            window.add(pkt)
        add_time = time.perf_counter() - start
        add_pps = num_packets / add_time if add_time > 0 else float('inf')
        
        # Benchmark: feature calculation
        test_info = test_packets[-1]
        start = time.perf_counter()
        iterations = 1000
        for _ in range(iterations):
            for f in features:
                f.calculate(test_info, window)
        calc_time = time.perf_counter() - start
        calc_pps = iterations / calc_time if calc_time > 0 else float('inf')
        
        results[num_packets] = {
            'add_pps': add_pps,
            'calc_pps': calc_pps
        }
        
        print(f"\n  [{num_packets:,} packets]")
        print(f"    window.add():     {add_pps:,.0f} pkt/s")
        print(f"    6 features calc:  {calc_pps:,.0f} vectors/s")
    
    # Summary
    avg_add = sum(r['add_pps'] for r in results.values()) / len(results)
    avg_calc = sum(r['calc_pps'] for r in results.values()) / len(results)
    combined = min(avg_add, avg_calc)
    
    print(f"\n  => Average Throughput:")
    print(f"     window.add():    {avg_add:,.0f} pkt/s")
    print(f"     feature calc:    {avg_calc:,.0f} vectors/s")
    print(f"     Combined:        ~{combined:,.0f} pkt/s")
    
    # Cleanup
    del window
    gc.collect()
    
    return {
        'add_pps': avg_add,
        'calc_pps': avg_calc,
        'combined_pps': combined
    }


def measure_latency():
    """Đo latency per packet"""
    print_header("4. LATENCY BENCHMARK")
    
    window = PacketWindow(window_size=1.0)
    features = [
        Feature1_PacketRate(),
        Feature2_SynAckRatio(),
        Feature3_DistinctPorts(),
        Feature4_PayloadLength(),
        Feature5_FailRate(),
        Feature6_ContextScore()
    ]
    
    # Pre-populate window
    base_time = time.time()
    for i in range(500):
        info = LayerInfo(
            timestamp=base_time + i * 0.001,
            packet_number=i,
            has_ip=True,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            has_tcp=True,
            tcp_sport=54321,
            tcp_dport=80,
            tcp_flags="S",
            has_payload=True,
            payload_bytes=b"test " * 20,
            payload_length=100
        )
        window.add(info)
    
    # Warm-up
    for _ in range(10):
        test_info = LayerInfo(
            timestamp=time.time(),
            packet_number=999,
            has_ip=True,
            src_ip="192.168.1.100",
            has_tcp=True,
            tcp_flags="PA",
            has_payload=True,
            payload_bytes=b"<script>alert(1)</script>",
            payload_length=27
        )
        window.add(test_info)
        for f in features:
            f.calculate(test_info, window)
    
    # Measure latency
    latencies = []
    
    for i in range(1000):
        test_info = LayerInfo(
            timestamp=time.time(),
            packet_number=1000 + i,
            has_ip=True,
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            has_tcp=True,
            tcp_sport=54321,
            tcp_dport=80,
            tcp_flags="PA",
            has_payload=True,
            payload_bytes=b"' OR 1=1--" if i % 10 == 0 else b"normal data",
            payload_length=20
        )
        
        start = time.perf_counter()
        window.add(test_info)
        for f in features:
            f.calculate(test_info, window)
        latency_ms = (time.perf_counter() - start) * 1000
        latencies.append(latency_ms)
    
    latencies.sort()
    
    avg = sum(latencies) / len(latencies)
    min_lat = min(latencies)
    max_lat = max(latencies)
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    
    print(f"  Samples:    1000 packets")
    print(f"  Min:        {min_lat:.4f} ms")
    print(f"  Avg:        {avg:.4f} ms")
    print(f"  Median:     {p50:.4f} ms")
    print(f"  P95:        {p95:.4f} ms")
    print(f"  P99:        {p99:.4f} ms")
    print(f"  Max:        {max_lat:.4f} ms")
    
    # Suitability
    print(f"\n  => Suitability:")
    if p99 < 1:
        print("     [OK] Inline IPS / Blocking")
        print("     [OK] RL Agent Real-time Action")
        print("     [OK] Alert System")
    elif p99 < 5:
        print("     [OK] RL Agent Real-time Action")
        print("     [OK] Alert System")
        print("     [WARN] Inline IPS may have issues")
    elif p99 < 10:
        print("     [OK] Alert System")
        print("     [WARN] RL Agent may be slow")
    else:
        print("     [WARN] Only suitable for offline analysis")
    
    # Cleanup
    del window
    gc.collect()
    
    return {
        'avg_ms': avg,
        'p95_ms': p95,
        'p99_ms': p99,
        'max_ms': max_lat
    }


def generate_recommendation(ram, mem_usage, throughput, latency):
    """Generate recommendation based on measurements"""
    print_header("5. RECOMMENDATIONS")
    
    # Flow-based suitability
    print("  FLOW-BASED ENHANCEMENT:")
    
    can_flow = True
    reasons = []
    
    if throughput and throughput['combined_pps'] < 5000:
        can_flow = False
        reasons.append("Throughput too low for additional flow overhead")
    
    if latency and latency['p99_ms'] > 5:
        can_flow = False
        reasons.append("Latency already high, flow tracking may worsen")
    
    if ram and ram['available_gb'] < 1:
        can_flow = False
        reasons.append("Insufficient RAM for flow table")
    
    if can_flow:
        print("     [RECOMMENDED] System can support Flow-Based Enhancement")
        print("     Expected overhead: +10-20% latency, similar memory")
    else:
        print("     [NOT RECOMMENDED] Keep Packet-Based approach")
        for reason in reasons:
            print(f"     - {reason}")
    
    # Configuration suggestions
    print("\n  SUGGESTED CONFIGURATION:")
    
    if ram:
        max_ips = int(ram['suggested_gb'] * 1024 / 0.5)  # ~0.5 MB per IP
        print(f"     max_ips: {min(max_ips, 50000):,}")
    
    if throughput:
        if throughput['combined_pps'] > 50000:
            print("     maxlen: 5000 (high throughput)")
        elif throughput['combined_pps'] > 10000:
            print("     maxlen: 2000")
        else:
            print("     maxlen: 1000 (default)")
    
    if latency:
        if latency['p99_ms'] < 1:
            print("     window_size: 1.0s (can increase if needed)")
        else:
            print("     window_size: 0.5s (reduce for better latency)")
    
    # Summary
    print("\n  SYSTEM GRADE:")
    grade = "A"
    
    if latency and latency['p99_ms'] > 5:
        grade = "C"
    elif latency and latency['p99_ms'] > 1:
        grade = "B"
    
    if throughput and throughput['combined_pps'] < 10000:
        grade = min(grade, "B")
    if throughput and throughput['combined_pps'] < 5000:
        grade = "C"
    
    grade_desc = {
        "A": "Excellent - Suitable for production IDS/IPS",
        "B": "Good - Suitable for RL Agent training/testing",
        "C": "Fair - Suitable for development/debugging"
    }
    
    print(f"     Grade: {grade} - {grade_desc.get(grade, 'Unknown')}")


def main():
    print("\n" + "#" * 60)
    print("#" + " " * 58 + "#")
    print("#    SYSTEM MEASUREMENT FOR RL DEFENSE AGENT".ljust(59) + "#")
    print("#" + " " * 58 + "#")
    print("#" * 60)
    
    # Run measurements
    ram = measure_ram()
    mem_usage = measure_memory_usage()
    throughput = measure_throughput()
    latency = measure_latency()
    
    # Generate recommendation
    generate_recommendation(ram, mem_usage, throughput, latency)
    
    print("\n" + "=" * 60)
    print("  MEASUREMENT COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
