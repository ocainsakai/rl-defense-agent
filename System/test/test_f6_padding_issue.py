"""test/test_f6_padding_issue.py

Test case để reproduce và fix vấn đề F6 không detect được padding attack
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from feature.payload_context import score_payload
from config import ai_config as config


def test_padding_with_plus_signs():
    """Test payload với padding bằng dấu '+' (như trong Wireshark)"""
    
    print("\n" + "="*80)
    print("TEST: PADDING ATTACK VỚI DẤU '+' (0x2b)")
    print("="*80)
    
    # Payload giống trong Wireshark: rất nhiều dấu '+' và malicious keyword ở giữa
    # Trong hex: 2b 2b 2b ... inject ... 2b 2b 2b
    
    test_cases = [
        {
            "name": "SQL Injection ẩn trong padding '+'",
            "payload": b"+" * 400 + b"' OR '1'='1" + b"+" * 400,
            "expected": config.CONTEXT_MALICIOUS,
            "description": "SQL injection bị ẩn giữa 800 ký tự '+'"
        },
        {
            "name": "XSS ẩn trong padding '+'",
            "payload": b"+" * 500 + b"<script>alert(1)</script>" + b"+" * 500,
            "expected": config.CONTEXT_MALICIOUS,
            "description": "XSS bị ẩn giữa 1000 ký tự '+'"
        },
        {
            "name": "Keyword 'inject' trong padding",
            "payload": b"2b" * 300 + b"inject" + b"2b" * 300,
            "expected": config.CONTEXT_NEUTRAL,  # 'inject' alone is not malicious
            "description": "Keyword không malicious"
        },
        {
            "name": "UNION SELECT ẩn trong padding",
            "payload": b"+" * 200 + b"UNION SELECT password FROM users" + b"+" * 200,
            "expected": config.CONTEXT_MALICIOUS,
            "description": "UNION SELECT trong padding"
        },
    ]
    
    results = []
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n[TEST {i}] {test['name']}")
        print("-" * 80)
        print(f"Description: {test['description']}")
        print(f"Payload length: {len(test['payload'])} bytes")
        
        # Show payload preview
        payload_str = test['payload'][:50] + b"..." + test['payload'][-50:]
        print(f"Payload preview: {payload_str}")
        
        # Test
        score = score_payload(test['payload'])
        expected = test['expected']
        passed = (score == expected)
        
        print(f"\nResult:")
        print(f"  Score:    {score}")
        print(f"  Expected: {expected}")
        print(f"  Status:   {'✅ PASS' if passed else '❌ FAIL'}")
        
        if not passed:
            print(f"\n  🔍 DEBUG INFO:")
            print(f"     - Payload bắt đầu: {test['payload'][:100]}")
            print(f"     - Payload kết thúc: {test['payload'][-100:]}")
            
            # Check if detected as padding
            from feature.payload_context import PayloadContextScorer
            is_padding = PayloadContextScorer._detect_padding_attack(test['payload'])
            print(f"     - Detected as padding attack: {is_padding}")
            
            if is_padding:
                stripped = test['payload'].strip(b" \t\n\r\x00")
                print(f"     - After strip: {stripped[:100]}... (length: {len(stripped)})")
                print(f"     - ⚠️ ISSUE: strip() chỉ loại bỏ space/tab/newline")
                print(f"     - ⚠️ Dấu '+' (0x2b) KHÔNG bị strip!")
        
        results.append(passed)
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    passed_count = sum(results)
    total_count = len(results)
    
    print(f"Passed: {passed_count}/{total_count}")
    
    if passed_count < total_count:
        print("\n❌ PHÁT HIỆN VẤN ĐỀ:")
        print("""
VẤN ĐỀ:
- _detect_padding_attack() chỉ kiểm tra padding_chars = {space, tab, newline, ...}
- Dấu '+' (0x2b = 43) KHÔNG nằm trong padding_chars
- strip() chỉ loại bỏ space/tab/newline, KHÔNG loại bỏ '+'
- Malicious keywords bị ẩn trong dấu '+' KHÔNG được detect!

GIẢI PHÁP:
1. Mở rộng padding_chars để bao gồm các ký tự có thể dùng để padding
2. Cải thiện stripping logic để loại bỏ repetitive characters
3. Scan TOÀN BỘ payload, không chỉ sau khi strip
        """)
    else:
        print("\n✅ TẤT CẢ TESTS PASS")
    
    return all(results)


def test_current_padding_detection():
    """Test logic hiện tại của _detect_padding_attack()"""
    
    print("\n" + "="*80)
    print("TEST: CURRENT PADDING DETECTION LOGIC")
    print("="*80)
    
    from feature.payload_context import PayloadContextScorer
    
    test_cases = [
        (b" " * 1000 + b"test", True, "Space padding"),
        (b"+" * 1000 + b"test", False, "'+' padding (NOT detected!)"),
        (b"a" * 1000 + b"test", True, "Repetitive 'a' (low diversity)"),
        (b"2b" * 500 + b"test", True, "Repetitive '2b' (low diversity)"),
    ]
    
    print("\nPADDING_CHARS currently includes:")
    print("  - ord(' ') = 32 (space)")
    print("  - ord('\\t') = 9 (tab)")
    print("  - ord('\\n') = 10 (newline)")
    print("  - ord('\\r') = 13 (carriage return)")
    print("  - 0 (null)")
    print("  - 11, 12 (vertical tab, form feed)")
    print("\n⚠️ MISSING: ord('+') = 43")
    
    for payload, expected, desc in test_cases:
        result = PayloadContextScorer._detect_padding_attack(payload)
        status = "✅" if result == expected else "❌"
        print(f"\n{status} {desc}")
        print(f"   Payload: {payload[:50]}...")
        print(f"   Detected: {result}, Expected: {expected}")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("F6 PADDING ATTACK DETECTION - ISSUE REPRODUCTION")
    print("="*80)
    
    test_current_padding_detection()
    success = test_padding_with_plus_signs()
    
    sys.exit(0 if success else 1)
