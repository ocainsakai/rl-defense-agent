"""Quick test for F6 padding fix"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature.payload_context import score_payload
from config import ai_config as config

def test_padding_attack(name, payload, expected):
    """Test one padding attack case"""
    score = score_payload(payload)
    passed = (score == expected)
    
    status = "PASS" if passed else "FAIL"
    print(f"{name}: {status} (score={score}, expected={expected})")
    
    return passed

# Run tests
print("="*60)
print("F6 PADDING DETECTION TESTS")
print("="*60)

results = []

# Test 1: SQL injection hidden in '+' padding
results.append(test_padding_attack(
    "SQL in '+' padding",
    b"+" * 400 + b"' OR '1'='1" + b"+" * 400,
    config.CONTEXT_MALICIOUS
))

# Test 2: UNION SELECT in '+' padding
results.append(test_padding_attack(
    "UNION SELECT in '+' padding",
    b"+" * 200 + b"UNION SELECT password" + b"+" * 200,
    config.CONTEXT_MALICIOUS
))

# Test 3: XSS in '+' padding
results.append(test_padding_attack(
    "XSS in '+' padding",
    b"+" * 500 + b"<script>alert(1)</script>" + b"+" * 500,
    config.CONTEXT_MALICIOUS
))

# Test 4: Command injection in 'a' padding
results.append(test_padding_attack(
    "Command injection in 'a' padding",
    b"a" * 300 + b";cat /etc/passwd" + b"a" * 300,
    config.CONTEXT_MALICIOUS
))

# Test 5: Clean text in '+' padding (should be neutral)
results.append(test_padding_attack(
    "Clean text in padding",
    b"+" * 400 + b"hello world" + b"+" * 400,
    config.CONTEXT_NEUTRAL
))

# Summary
print("="*60)
passed = sum(results)
total = len(results)
print(f"SUMMARY: {passed}/{total} tests passed")

if passed == total:
    print("SUCCESS: F6 padding detection is working!")
    sys.exit(0)
else:
    print("FAILED: F6 still has issues with padding detection")
    sys.exit(1)
