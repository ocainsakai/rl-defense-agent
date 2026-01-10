"""Debug script to check payloads in padding.pcap"""

from scapy.all import rdpcap, TCP, Raw
from feature.payload_context import score_payload, PayloadContextScorer
from config import ai_config as config

pcap_file = r"C:\Users\VyVa\Desktop\PCAP_Sample\padding.pcap"

print("="*80)
print("DEBUGGING F6 PADDING DETECTION")
print("="*80)

packets = rdpcap(pcap_file)

print(f"\nTotal packets: {len(packets)}")

# Find TCP packets with payload going to port 80
tcp_payloads = []
for i, pkt in enumerate(packets):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        tcp_layer = pkt[TCP]
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            payload = bytes(pkt[Raw].load)
            tcp_payloads.append({
                'packet_num': i+1,
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'payload': payload,
                'length': len(payload)
            })

print(f"TCP packets with payload (port 80): {len(tcp_payloads)}")

# Analyze first few payloads
for idx, p in enumerate(tcp_payloads[:5], 1):
    print(f"\n{'='*80}")
    print(f"PAYLOAD {idx} (Packet #{p['packet_num']})")
    print(f"{'='*80}")
    print(f"Direction: {p['src_port']} → {p['dst_port']}")
    print(f"Length: {p['length']} bytes")
    
    payload = p['payload']
    
    # Show first 200 bytes
    print(f"\nFirst 200 bytes:")
    print(payload[:200])
    
    # Show as hex
    print(f"\nFirst 100 bytes (hex):")
    hex_str = ' '.join(f'{b:02x}' for b in payload[:100])
    print(hex_str)
    
    # Count character frequencies
    from collections import Counter
    byte_counts = Counter(payload)
    most_common = byte_counts.most_common(5)
    
    print(f"\nTop 5 most frequent bytes:")
    for byte_val, count in most_common:
        char_repr = chr(byte_val) if 32 <= byte_val <= 126 else f'\\x{byte_val:02x}'
        ratio = count / len(payload) * 100
        print(f"  {char_repr!r} (0x{byte_val:02x}): {count} times ({ratio:.1f}%)")
    
    # Test padding detection
    is_padding = PayloadContextScorer._detect_padding_attack(payload)
    print(f"\nDetected as padding attack: {is_padding}")
    
    # Test smart strip
    stripped = PayloadContextScorer._smart_strip_padding(payload)
    print(f"After smart strip: {len(stripped)} bytes")
    if stripped != payload:
        print(f"Stripped content (first 100): {stripped[:100]}")
    
    # Test F6 score
    score = score_payload(payload)
    print(f"\nF6 Score: {score}")
    print(f"Expected: {config.CONTEXT_MALICIOUS if 'inject' in payload.lower() or b'or' in payload.lower() else config.CONTEXT_NEUTRAL}")
    
    if score == 0.0:
        print("\n⚠️ F6 = 0.0 - Analyzing why...")
        
        # Decode to string
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            print(f"Decoded: {payload_str[:200]}")
            
            # Check for keywords
            keywords = ["inject", "select", "union", "script", "or '1'='1", "or 1=1"]
            found = [kw for kw in keywords if kw in payload_str]
            if found:
                print(f"❌ FOUND keywords but F6 didn't detect: {found}")
            else:
                print(f"✓ No malicious keywords found")
        except:
            print("Cannot decode payload")

print(f"\n{'='*80}")
print("RECOMMENDATION:")
print("If payloads have malicious keywords but F6=0.0, check:")
print("1. Port filtering (is dst_port in HTTP_PORTS?)")
print("2. Payload normalization (does it decode properly?)")
print("3. Pattern matching (are patterns too strict?)")
