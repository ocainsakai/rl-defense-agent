"""Test payload thực tế từ padding.pcap"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature.payload_context import score_payload, PayloadContextScorer
from config import ai_config as config

# Payload thực tế từ user
payload = b"""GET /++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++union+select+1%2C2%2C3 HTTP/1.1
Host: 192.168.234.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br, zstd
Accept: */*
Connection: keep-alive

"""

print("="*80)
print("TEST PAYLOAD THỰC TẾ TỪ PADDING.PCAP")
print("="*80)

print(f"\nPayload length: {len(payload)} bytes")

# Count '+'
plus_count = payload.count(b'+')
print(f"Dấu '+' count: {plus_count}/{len(payload)} ({plus_count/len(payload)*100:.1f}%)")

# Tìm keyword
if b'union' in payload.lower():
    print("✅ Tìm thấy 'union' trong payload")
if b'select' in payload.lower():
    print("✅ Tìm thấy 'select' trong payload")

# Test detection
print(f"\n{'='*80}")
print("TESTING DETECTION")
print(f"{'='*80}")

is_padding = PayloadContextScorer._detect_padding_attack(payload)
print(f"\n1. _detect_padding_attack(): {is_padding}")

# Test stripping
stripped = PayloadContextScorer._smart_strip_padding(payload)
print(f"\n2. _smart_strip_padding():")
print(f"   Original: {len(payload)} bytes")
print(f"   Stripped: {len(stripped)} bytes")
print(f"   Removed: {len(payload) - len(stripped)} bytes")

if stripped != payload:
    print(f"\n   Stripped content (first 300):")
    print(f"   {stripped[:300]}")

# Test scoring
print(f"\n3. score_payload():")
score = score_payload(payload)
print(f"   F6 Score: {score}")
print(f"   Expected: {config.CONTEXT_MALICIOUS} (malicious)")

if score == config.CONTEXT_MALICIOUS:
    print(f"\n   ✅ SUCCESS - F6 detected SQL injection!")
else:
    print(f"\n   ❌ FAILED - F6 = {score}")
    print(f"\n   Debugging:")
    
    # Decode and show
    decoded = payload.decode('utf-8', errors='ignore')
    print(f"   Decoded: {decoded[:500]}")
    
    # URL decode
    from urllib.parse import unquote
    url_decoded = unquote(decoded)
    print(f"\n   URL decoded: {url_decoded[:500]}")
    
    # Check if 'union select' is there
    if 'union' in url_decoded.lower() and 'select' in url_decoded.lower():
        print(f"\n   ✅ 'union select' is in URL decoded string")
        print(f"   ❌ But F6 didn't detect it - pattern matching issue?")

print(f"\n{'='*80}")
