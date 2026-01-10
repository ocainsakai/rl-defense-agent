"""Debug F6 by adding detailed logging to analyze padding.pcap"""

import sys
from scapy.all import PcapReader, TCP, Raw
from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.feature_flow import FlowFeatureCalculator, FlowFeature6_ContextScore
from feature.payload_context import PayloadContextScorer, score_payload
from config import ai_config as config

pcap_file = r"C:\Users\VyVa\Desktop\PCAP_Sample\padding.pcap"

print("="*80)
print("F6 DEBUGGING - PADDING.PCAP")
print("="*80)

# Parser
parser = PacketLayerExtractor(
    enable_http_parsing=True,
    use_packet_time=True
)

# FlowManager
flow_manager = FlowManager(
    window_size=999999.0,
    flow_timeout=999999.0,
    cleanup_interval=999999
)

print("\n[1] Reading PCAP...")
with PcapReader(pcap_file) as pcap_reader:
    for pkt_num, pkt in enumerate(pcap_reader, 1):
        info = parser.extract(pkt, pkt_num)
        if info and info.has_ip:
            flow_manager.process_packet(info)

flows = flow_manager.get_all_flows()
print(f"[+] Total flows: {len(flows)}")

# Find TCP flows to port 80
tcp_80_flows = [f for f in flows if f.protocol == 6 and f.dst_port == 80]
print(f"[+] TCP flows to port 80: {len(tcp_80_flows)}")

if not tcp_80_flows:
    print("\n❌ No TCP port 80 flows found!")
    sys.exit(1)

# Analyze first flow in detail
flow = tcp_80_flows[0]

print(f"\n{'='*80}")
print(f"ANALYZING FLOW: {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}")
print(f"{'='*80}")

fwd_packets = flow.get_fwd_packets()
print(f"\nForward packets: {len(fwd_packets)}")

# Find packets with payload
payload_packets = [p for p in fwd_packets if p.has_payload and p.payload_bytes]
print(f"Packets with payload: {len(payload_packets)}")

if not payload_packets:
    print("\n❌ No payloads found in forward packets!")
    sys.exit(1)

# Analyze each payload
for idx, pkt in enumerate(payload_packets, 1):
    print(f"\n{'-'*80}")
    print(f"PAYLOAD {idx}/{len(payload_packets)}")
    print(f"{'-'*80}")
    
    payload = pkt.payload_bytes
    print(f"Length: {len(payload)} bytes")
    
    # Show first 200 bytes
    print(f"\nFirst 200 bytes (raw):")
    print(payload[:200])
    
    # Show as hex
    print(f"\nFirst 100 bytes (hex):")
    hex_str = ' '.join(f'{b:02x}' for b in payload[:100])
    print(hex_str)
    
    # Character frequency
    from collections import Counter
    byte_counts = Counter(payload)
    most_common = byte_counts.most_common(5)
    
    print(f"\nTop 5 frequent bytes:")
    total_len = len(payload)
    for byte_val, count in most_common:
        char_repr = chr(byte_val) if 32 <= byte_val <= 126 else f'\\x{byte_val:02x}'
        ratio = count / total_len
        print(f"  {char_repr!r} (0x{byte_val:02x}): {count}/{total_len} ({ratio*100:.1f}%)")
    
    # Check if most common byte is dominant
    if most_common:
        dominant_byte, dominant_count = most_common[0]
        dominance_ratio = dominant_count / total_len
        print(f"\nDominance ratio: {dominance_ratio:.3f} (threshold: 0.70)")
        print(f"Dominant: {'YES ✓' if dominance_ratio > 0.70 else 'NO ✗'}")
    
    # Test padding detection
    print(f"\n{'—'*40}")
    print("PADDING DETECTION TEST")
    print(f"{'—'*40}")
    
    is_padding = PayloadContextScorer._detect_padding_attack(payload)
    print(f"_detect_padding_attack(): {is_padding}")
    
    # Test smart strip
    stripped = PayloadContextScorer._smart_strip_padding(payload)
    print(f"\nSmart strip result:")
    print(f"  Original length: {len(payload)}")
    print(f"  Stripped length: {len(stripped)}")
    print(f"  Removed: {len(payload) - len(stripped)} bytes")
    
    if stripped != payload and len(stripped) < 500:
        print(f"  Stripped content: {stripped}")
    
    # Test F6 score
    print(f"\n{'—'*40}")
    print("F6 SCORING TEST")
    print(f"{'—'*40}")
    
    score = score_payload(payload)
    print(f"F6 Score: {score}")
    print(f"MALICIOUS = {config.CONTEXT_MALICIOUS}")
    print(f"NEUTRAL = {config.CONTEXT_NEUTRAL}")
    print(f"SAFE = {config.CONTEXT_SAFE}")
    
    # Decode and search for patterns
    print(f"\nPattern search:")
    try:
        decoded = payload.decode('utf-8', errors='ignore').lower()
        print(f"Decoded (first 300 chars): {decoded[:300]}")
        
        patterns = {
            "SQL injection": ["' or '", "union select", "1'='1", "or 1=1"],
            "XSS": ["<script", "javascript:", "onerror="],
            "Command injection": [";cat", "|sh", ";ls", "/etc/passwd"],
        }
        
        found_patterns = []
        for category, keywords in patterns.items():
            for kw in keywords:
                if kw in decoded:
                    found_patterns.append(f"{category}: '{kw}'")
        
        if found_patterns:
            print(f"✅ FOUND: {', '.join(found_patterns)}")
        else:
            print(f"❌ No malicious patterns found")
            
    except Exception as e:
        print(f"❌ Decode error: {e}")

# Test F6 with entire flow
print(f"\n{'='*80}")
print("F6 TEST WITH ENTIRE FLOW")
print(f"{'='*80}")

f6 = FlowFeature6_ContextScore()
flow_score = f6.calculate([flow])

print(f"Flow F6 Score: {flow_score}")
print(f"Flow dst_port: {flow.dst_port}")
print(f"HTTP_PORTS: {f6.HTTP_PORTS}")
print(f"Port in HTTP_PORTS: {flow.dst_port in f6.HTTP_PORTS}")

if flow_score == 0.0:
    print(f"\n❌ F6 = 0.0 - Possible reasons:")
    print(f"   1. dst_port não está em HTTP_PORTS")
    print(f"   2. Không có payload nào được scan")
    print(f"   3. Payload không có malicious patterns")
    print(f"   4. Padding detection không trigger")
