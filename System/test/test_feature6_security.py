# -*- coding: utf-8 -*-
"""
Unit tests for Feature6_ContextScore Security Enhancements

Run tests: 
    python -m pytest test/test_feature6_security.py -v
Or:
    python test/test_feature6_security.py
"""

import sys
import time
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature.feature_logic import Feature6_ContextScore
from core.layer_info import LayerInfo
from core.window_packet import PacketWindow
from config import ai_config as config


def make_info(payload):
    """Helper function to create LayerInfo with payload"""
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    return LayerInfo(
        timestamp=time.time(),
        packet_number=1,
        has_payload=True,
        payload_bytes=payload,
        payload_length=len(payload)
    )


class TestReDoSProtection:
    """Tests for ReDoS protection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_redos_union_spaces(self):
        """Test ReDoS with many spaces in UNION SELECT"""
        attack_payload = b"' " + b" " * 100 + b"or" + b" " * 100 + b"1=2"
        info = make_info(attack_payload)
        
        start = time.time()
        self.feature.calculate_raw(info, self.window)
        elapsed = time.time() - start
        
        assert elapsed < 0.1, f"ReDoS detected! Took {elapsed:.3f}s"
        print(f"  ReDoS test passed: {elapsed*1000:.2f}ms")
    
    def test_redos_nested_spaces(self):
        """Test ReDoS with nested patterns"""
        attack_payload = b"union" + b" \t\n" * 50 + b"select"
        info = make_info(attack_payload)
        
        start = time.time()
        result = self.feature.calculate_raw(info, self.window)
        elapsed = time.time() - start
        
        assert elapsed < 0.1, f"ReDoS detected! Took {elapsed:.3f}s"
        assert result == config.CONTEXT_MALICIOUS
        print(f"  Nested spaces test passed: {elapsed*1000:.2f}ms")


class TestEncodingBypass:
    """Tests for encoding bypass detection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_url_encoded_xss(self):
        """Detect XSS via URL encoding"""
        payload = b"%3Cscript%3Ealert(1)%3C/script%3E"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "URL encoded XSS not detected!"
        print("  URL encoded XSS detected")
    
    def test_double_url_encoded(self):
        """Detect double URL encoding"""
        payload = b"%253Cscript%253E"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "Double URL encoding bypass!"
        print("  Double URL encoded XSS detected")
    
    def test_html_entity_xss(self):
        """Detect HTML entity encoding"""
        payload = b"&#60;script&#62;alert(1)"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "HTML entity XSS not detected!"
        print("  HTML entity XSS detected")
    
    def test_null_byte_injection(self):
        """Detect null byte injection"""
        payload = b"un\x00ion sel\x00ect"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "Null byte injection bypass!"
        print("  Null byte injection detected")


class TestPaddingAttack:
    """Tests for padding attack detection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_whitespace_padding_start(self):
        """4000 spaces + malicious -> Should detect"""
        payload = b" " * 4000 + b"<script>alert(1)</script>"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "Whitespace padding bypass!"
        print("  Whitespace padding at start detected")
    
    def test_whitespace_padding_both_ends(self):
        """Padding before and after -> Should detect"""
        payload = b" " * 2000 + b"<script>alert(1)</script>" + b" " * 2000
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "Both ends padding bypass!"
        print("  Both ends padding detected")
    
    def test_null_byte_padding(self):
        """Null bytes padding -> Should detect"""
        payload = b"\x00" * 4000 + b"union select * from users"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "Null byte padding bypass!"
        print("  Null byte padding detected")
    
    def test_malicious_at_tail(self):
        """Malicious at tail -> Should detect via TAIL sample"""
        payload = b"A" * 5000 + b"<script>alert(1)</script>"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS, "Tail attack not detected!"
        print("  Malicious at tail detected")


class TestSQLInjection:
    """Tests for SQL Injection detection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_union_select(self):
        """Classic UNION SELECT"""
        payload = b"1' UNION SELECT username,password FROM users--"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  UNION SELECT detected")
    
    def test_or_bypass(self):
        """OR bypass"""
        payload = b"admin' OR '1'='1"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  OR bypass detected")
    
    def test_time_based_blind(self):
        """Time-based blind SQLi"""
        payload = b"1' AND SLEEP(5)--"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  Time-based blind SQLi detected")


class TestCommandInjection:
    """Tests for Command Injection detection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_semicolon_command(self):
        """Semicolon command injection"""
        payload = b"; cat /etc/passwd"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  Semicolon injection detected")
    
    def test_path_traversal(self):
        """Path traversal"""
        payload = b"../../../etc/passwd"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  Path traversal detected")


class TestWebShell:
    """Tests for Web Shell detection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_php_eval(self):
        """PHP eval shell"""
        payload = b"<?php eval($_POST['cmd']); ?>"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  PHP eval shell detected")
    
    def test_system_call(self):
        """System call"""
        payload = b"<?php system($_GET['c']); ?>"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_MALICIOUS
        print("  System call detected")


class TestSafePatterns:
    """Tests for safe traffic detection"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_image_upload(self):
        """Image upload should be SAFE"""
        payload = b"POST /upload HTTP/1.1\r\nContent-Type: image/png\r\n"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_SAFE
        print("  Image upload marked SAFE")
    
    def test_normal_html(self):
        """Normal HTML should be NEUTRAL"""
        payload = b"<html><head><title>Hello</title></head></html>"
        info = make_info(payload)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_NEUTRAL
        print("  Normal HTML marked NEUTRAL")
    
    def test_empty_payload(self):
        """Empty payload should be NEUTRAL"""
        info = LayerInfo(timestamp=time.time(), packet_number=1)
        result = self.feature.calculate_raw(info, self.window)
        assert result == config.CONTEXT_NEUTRAL
        print("  Empty payload marked NEUTRAL")


class TestPerformance:
    """Performance tests"""
    
    def setup_method(self):
        self.feature = Feature6_ContextScore()
        self.window = PacketWindow(window_size=1.0)
    
    def test_large_payload_performance(self):
        """64KB payload should complete quickly"""
        payload = b"A" * 63000 + b"<script>alert(1)</script>" + b"B" * 1000
        info = make_info(payload)
        
        start = time.time()
        result = self.feature.calculate_raw(info, self.window)
        elapsed = time.time() - start
        
        assert result == config.CONTEXT_MALICIOUS
        assert elapsed < 0.5, f"Too slow: {elapsed:.3f}s"
        print(f"  64KB payload processed in {elapsed*1000:.2f}ms")


def run_all_tests():
    """Run all test classes"""
    test_classes = [
        TestReDoSProtection,
        TestEncodingBypass,
        TestPaddingAttack,
        TestSQLInjection,
        TestCommandInjection,
        TestWebShell,
        TestSafePatterns,
        TestPerformance,
    ]
    
    total_passed = 0
    total_failed = 0
    
    print("=" * 60)
    print("Feature6_ContextScore Security Tests")
    print("=" * 60)
    
    for test_class in test_classes:
        print(f"\n[*] {test_class.__name__}")
        print("-" * 40)
        
        instance = test_class()
        test_methods = [m for m in dir(instance) if m.startswith('test_')]
        
        for method_name in test_methods:
            try:
                instance.setup_method()
                getattr(instance, method_name)()
                total_passed += 1
            except AssertionError as e:
                print(f"  [FAILED] {method_name}: {e}")
                total_failed += 1
            except Exception as e:
                print(f"  [ERROR] {method_name}: {e}")
                total_failed += 1
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {total_passed} passed, {total_failed} failed")
    print("=" * 60)
    
    return total_failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
