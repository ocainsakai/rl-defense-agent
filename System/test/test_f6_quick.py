"""Quick test for F6 padding fix"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature.payload_context import score_payload
from config import ai_config as config

# Test 1: SQL injection hidden in '+' padding
payload1 = b"+" * 400 + b"' OR '1'='1" + b"+" * 400
score1 = score_payload(payload1)

print(f"Test 1: SQL injection in '+' padding")
print(f"  Payload: {payload1[:50]}...{payload1[-50:]}")
print(f"  Score: {score1}")
print(f"  Expected: {config.CONTEXT_MALICIOUS}")
print(f"  Result: {'✅ PASS' if score1 == config.CONTEXT_MALICIOUS else '❌ FAIL'}")

# Test 2: UNION SELECT in '+' padding
payload2 = b"+" * 200 + b"UNION SELECT password" + b"+" * 200
score2 = score_payload(payload2)

print(f"\nTest 2: UNION SELECT in '+' padding")
print(f"  Score: {score2}")
print(f"  Expected: {config.CONTEXT_MALICIOUS}")
print(f"  Result: {'✅ PASS' if score2 == config.CONTEXT_MALICIOUS else '❌ FAIL'}")

# Test 3: XSS in '+' padding
payload3 = b"+" * 500 + b"<script>alert(1)</script>" + b"+" * 500
score3 = score_payload(payload3)

print(f"\nTest 3: XSS in '+' padding")
print(f"  Score: {score3}")
print(f"  Expected: {config.CONTEXT_MALICIOUS}")
print(f"  Result: {'✅ PASS' if score3 == config.CONTEXT_MALICIOUS else '❌ FAIL'}")

# Summary
total = 3
passed = sum([
    score1 == config.CONTEXT_MALICIOUS,
    score2 == config.CONTEXT_MALICIOUS,
    score3 == config.CONTEXT_MALICIOUS
])

print(f"\n{'='*60}")
print(f"SUMMARY: {passed}/{total} tests passed")
if passed == total:
    print("✅ F6 PADDING DETECTION IS FIXED!")
else:
    print("❌ F6 still has issues")

sys.exit(0 if passed == total else 1)
