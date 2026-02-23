#!/usr/bin/env python3
"""
test_dual_sensor.py - Tests for Dual-Source Feature Extraction.

Tests:
1. LogLayerInfo / LogFlowState adapter compatibility
2. NidsLogParser parsing lab_detail format
3. FeatureMerger merge scenarios
4. LogFeatureCalculator with attack payloads
5. End-to-end: sample log → 30 features
"""

import os
import sys
import time
import tempfile
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestLogFlowAdapter(unittest.TestCase):
    """Test LogLayerInfo, LogResponseLayerInfo, LogFlowState."""

    def test_log_layer_info_basic(self):
        """LogLayerInfo has correct attributes."""
        from core.log_flow_adapter import LogLayerInfo

        pkt = LogLayerInfo(
            remote_addr="10.0.10.10",
            timestamp=1700000000.0,
            method="GET",
            path="/login?user=admin",
            user_agent="Mozilla/5.0",
            host="192.168.10.10",
        )

        self.assertTrue(pkt.has_ip)
        self.assertTrue(pkt.has_http)
        self.assertTrue(pkt.has_tcp)
        self.assertTrue(pkt.has_payload)
        self.assertEqual(pkt.src_ip, "10.0.10.10")
        self.assertEqual(pkt.http_method, "GET")
        self.assertEqual(pkt.http_uri, "/login?user=admin")
        self.assertEqual(pkt.http_user_agent, "Mozilla/5.0")
        self.assertIsInstance(pkt.payload_bytes, bytes)
        self.assertGreater(pkt.payload_length, 0)
        self.assertFalse(pkt.is_reset)

    def test_log_layer_info_composite_payload(self):
        """Composite payload = [URI] + [User-Agent]."""
        from core.log_flow_adapter import LogLayerInfo

        pkt = LogLayerInfo(
            remote_addr="10.0.10.10",
            timestamp=1700000000.0,
            method="GET",
            path="/search?q=test",
            user_agent="TestBot",
        )

        payload = pkt.payload_bytes
        self.assertIn(b"/search?q=test", payload)
        self.assertIn(b"TestBot", payload)

    def test_log_response_layer_info(self):
        """LogResponseLayerInfo has status code."""
        from core.log_flow_adapter import LogResponseLayerInfo

        pkt = LogResponseLayerInfo(
            remote_addr="10.0.10.10",
            timestamp=1700000000.0,
            status=401,
        )

        self.assertTrue(pkt.has_http)
        self.assertEqual(pkt.http_status, 401)
        self.assertFalse(pkt.has_payload)

    def test_log_flow_state_interface(self):
        """LogFlowState implements FlowState interface."""
        from core.log_flow_adapter import (
            LogLayerInfo, LogResponseLayerInfo, LogFlowState
        )

        fwd = [
            LogLayerInfo("10.0.10.10", 1700000000.0, "GET", "/page1", "Bot"),
            LogLayerInfo("10.0.10.10", 1700000001.0, "GET", "/page2", "Bot"),
        ]
        bwd = [
            LogResponseLayerInfo("10.0.10.10", 1700000000.5, 200),
            LogResponseLayerInfo("10.0.10.10", 1700000001.5, 401),
        ]

        flow = LogFlowState("10.0.10.10", fwd, bwd, window_size=5.0)

        # Counts
        self.assertEqual(flow.get_fwd_packet_count(), 2)
        self.assertEqual(flow.get_bwd_packet_count(), 2)
        self.assertEqual(flow.get_packet_count(), 4)

        # Packets
        self.assertEqual(len(flow.get_fwd_packets()), 2)
        self.assertEqual(len(flow.get_bwd_packets()), 2)
        self.assertEqual(len(flow.get_all_packets()), 4)

        # TCP flags (empty from log)
        flags = flow.get_fwd_tcp_flags_count()
        self.assertEqual(flags['SYN'], 0)

        # Ports
        self.assertEqual(flow.get_distinct_ports(), {443})

        # Payloads
        self.assertGreater(len(flow.get_fwd_payloads()), 0)
        self.assertEqual(len(flow.get_bwd_payloads()), 0)

        # Properties
        self.assertEqual(flow.src_ip, "10.0.10.10")
        self.assertEqual(flow.effective_src_ip, "10.0.10.10")
        self.assertGreater(flow.duration, 0)

    def test_build_composite_payload_compatibility(self):
        """LogLayerInfo works with HttpPayloadExtractor.build_composite_payload."""
        from core.log_flow_adapter import LogLayerInfo
        from core.packet_parser import HttpPayloadExtractor

        pkt = LogLayerInfo(
            remote_addr="10.0.10.10",
            timestamp=1700000000.0,
            method="GET",
            path="/search?q=' OR 1=1--",
            user_agent="sqlmap/1.0",
        )

        # build_composite_payload uses getattr() - should work with any object
        composite = HttpPayloadExtractor.build_composite_payload(pkt)
        self.assertIsInstance(composite, bytes)
        self.assertIn(b"OR 1=1", composite)
        self.assertIn(b"sqlmap", composite)


class TestNidsLogParser(unittest.TestCase):
    """Test NidsLogParser for lab_detail format."""

    SAMPLE_LOG_LINE = (
        '10.0.10.10 - - [13/Feb/2026:10:30:45 +0700] '
        '"GET /search?q=test HTTP/1.1" 200 1234 '
        'rt=0.002 urt=0.001 '
        'uaddr="192.168.10.10:8080" ustatus="200" '
        'host="192.168.10.10" sni="192.168.10.10" '
        'tls=TLSv1.3/TLS_AES_256_GCM_SHA384 '
        'ref="-" ua="Mozilla/5.0 (X11; Linux x86_64)" '
        'xff="-" '
        'cl="0" ct="-" '
        'reqid="abc123def456"'
    )

    SQLI_LOG_LINE = (
        "10.0.10.10 - - [13/Feb/2026:10:31:00 +0700] "
        "\"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 5678 "
        "rt=0.005 urt=0.003 "
        'uaddr="192.168.10.10:8080" ustatus="200" '
        'host="192.168.10.10" sni="192.168.10.10" '
        "tls=TLSv1.3/TLS_AES_256_GCM_SHA384 "
        'ref="-" ua="sqlmap/1.7" '
        'xff="-" '
        'cl="0" ct="-" '
        'reqid="sqli001"'
    )

    AUTH_FAIL_LINE = (
        '10.0.10.10 - - [13/Feb/2026:10:32:00 +0700] '
        '"POST /login HTTP/1.1" 401 150 '
        'rt=0.010 urt=0.008 '
        'uaddr="192.168.10.10:8080" ustatus="401" '
        'host="192.168.10.10" sni="192.168.10.10" '
        'tls=TLSv1.3/TLS_AES_256_GCM_SHA384 '
        'ref="-" ua="curl/7.68.0" '
        'xff="-" '
        'cl="50" ct="application/x-www-form-urlencoded" '
        'reqid="auth001"'
    )

    def test_parse_basic_line(self):
        """Parse a standard lab_detail log line."""
        from core.nginx_log_sensor import NidsLogParser

        entry = NidsLogParser.parse_line(self.SAMPLE_LOG_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.remote_addr, "10.0.10.10")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/search?q=test")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.body_bytes_sent, 1234)
        self.assertAlmostEqual(entry.request_time, 0.002)
        self.assertEqual(entry.host, "192.168.10.10")
        self.assertIn("Mozilla", entry.user_agent)
        self.assertEqual(entry.request_id, "abc123def456")
        self.assertGreater(entry.timestamp, 0)

    def test_parse_sqli_line(self):
        """Parse a line with SQLi payload in URI."""
        from core.nginx_log_sensor import NidsLogParser

        entry = NidsLogParser.parse_line(self.SQLI_LOG_LINE)
        self.assertIsNotNone(entry)
        self.assertIn("OR 1=1", entry.path)
        self.assertEqual(entry.user_agent, "sqlmap/1.7")
        self.assertEqual(entry.request_id, "sqli001")

    def test_parse_auth_failure(self):
        """Parse 401 auth failure line."""
        from core.nginx_log_sensor import NidsLogParser

        entry = NidsLogParser.parse_line(self.AUTH_FAIL_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.status, 401)
        self.assertEqual(entry.method, "POST")
        self.assertEqual(entry.content_length, 50)
        self.assertEqual(entry.content_type, "application/x-www-form-urlencoded")

    def test_parse_invalid_line(self):
        """Invalid lines return None."""
        from core.nginx_log_sensor import NidsLogParser

        self.assertIsNone(NidsLogParser.parse_line(""))
        self.assertIsNone(NidsLogParser.parse_line("not a log line"))
        self.assertIsNone(NidsLogParser.parse_line("garbage data 123"))


class TestNginxLogSensor(unittest.TestCase):
    """Test NginxLogSensor read + flush cycle."""

    def _create_temp_log(self, lines):
        """Create temp log file with given lines."""
        fd = tempfile.NamedTemporaryFile(
            mode='w', suffix='.log', delete=False, encoding='utf-8'
        )
        for line in lines:
            fd.write(line + "\n")
        fd.flush()
        fd.close()
        return fd.name

    def test_read_and_flush(self):
        """Read log entries and flush to features."""
        from core.nginx_log_sensor import NginxLogSensor

        log_lines = [
            '10.0.10.10 - - [13/Feb/2026:10:30:45 +0700] '
            '"GET /page1 HTTP/1.1" 200 100 '
            'rt=0.001 urt=0.001 '
            'uaddr="192.168.10.10:8080" ustatus="200" '
            'host="192.168.10.10" sni="192.168.10.10" '
            'tls=TLSv1.3/TLS_AES_256_GCM_SHA384 '
            'ref="-" ua="Mozilla/5.0" '
            'xff="-" cl="0" ct="-" reqid="r1"',

            '10.0.10.10 - - [13/Feb/2026:10:30:46 +0700] '
            '"GET /page2 HTTP/1.1" 200 200 '
            'rt=0.002 urt=0.001 '
            'uaddr="192.168.10.10:8080" ustatus="200" '
            'host="192.168.10.10" sni="192.168.10.10" '
            'tls=TLSv1.3/TLS_AES_256_GCM_SHA384 '
            'ref="-" ua="Mozilla/5.0" '
            'xff="-" cl="0" ct="-" reqid="r2"',
        ]

        log_file = self._create_temp_log(log_lines)
        try:
            sensor = NginxLogSensor(log_file, window_size=5.0)
            # Don't skip to end - read from beginning
            sensor._file_pos = 0

            count = sensor.read_new_entries()
            self.assertEqual(count, 2)
            self.assertEqual(sensor.get_buffer_size(), 2)

            # Flush
            results = sensor.flush_window()
            self.assertIn("10.0.10.10", results)

            result = results["10.0.10.10"]
            self.assertEqual(result.src_ip, "10.0.10.10")
            self.assertEqual(result.request_count, 2)

            # Check features dict has expected keys
            self.assertIn('F6', result.features)
            self.assertIn('F7', result.features)
            self.assertIn('F8', result.features)
            self.assertIn('F11', result.features)

            # Buffer should be empty after flush
            self.assertEqual(sensor.get_buffer_size(), 0)
        finally:
            os.unlink(log_file)

    def test_sqli_detection_from_log(self):
        """SQLi in URI should produce non-zero F11 (SqliKeyword)."""
        from core.nginx_log_sensor import NginxLogSensor

        log_lines = [
            "10.0.10.10 - - [13/Feb/2026:10:30:45 +0700] "
            "\"GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\" 200 100 "
            "rt=0.001 urt=0.001 "
            'uaddr="192.168.10.10:8080" ustatus="200" '
            'host="192.168.10.10" sni="192.168.10.10" '
            "tls=TLSv1.3/TLS_AES_256_GCM_SHA384 "
            'ref="-" ua="sqlmap/1.7" '
            'xff="-" cl="0" ct="-" reqid="sqli1"',
        ]

        log_file = self._create_temp_log(log_lines)
        try:
            sensor = NginxLogSensor(log_file, window_size=5.0)
            sensor._file_pos = 0

            sensor.read_new_entries()
            results = sensor.flush_window()

            features = results["10.0.10.10"].features

            # F11 (SqliKeyword) should be > 0 for UNION SELECT
            sqli_score = features.get('F11', 0.0)
            self.assertGreater(sqli_score, 0.0,
                               f"F11 (SqliKeyword) should detect UNION SELECT, got {sqli_score}")

            # F14 (SqlUnionSelect) should be > 0 for UNION SELECT
            union_detect = features.get('F14', 0.0)
            self.assertGreater(union_detect, 0.0,
                               f"F14 (SqlUnionSelect) should detect UNION SELECT")
        finally:
            os.unlink(log_file)

    def test_auth_failure_detection(self):
        """401 status should produce non-zero F7 (AuthFailureRate)."""
        from core.nginx_log_sensor import NginxLogSensor

        log_lines = [
            '10.0.10.10 - - [13/Feb/2026:10:30:45 +0700] '
            '"POST /login HTTP/1.1" 401 50 '
            'rt=0.010 urt=0.008 '
            'uaddr="192.168.10.10:8080" ustatus="401" '
            'host="192.168.10.10" sni="192.168.10.10" '
            'tls=TLSv1.3/TLS_AES_256_GCM_SHA384 '
            'ref="-" ua="curl/7.68.0" '
            'xff="-" cl="50" ct="application/x-www-form-urlencoded" '
            'reqid="auth1"',
        ]

        log_file = self._create_temp_log(log_lines)
        try:
            sensor = NginxLogSensor(log_file, window_size=5.0)
            sensor._file_pos = 0

            sensor.read_new_entries()
            results = sensor.flush_window()

            features = results["10.0.10.10"].features
            auth_fail = features.get('F7', 0.0)
            self.assertGreater(auth_fail, 0.0,
                               f"F7 (AuthFailureRate) should detect 401, got {auth_fail}")
        finally:
            os.unlink(log_file)


class TestFeatureMerger(unittest.TestCase):
    """Test FeatureMerger scenarios."""

    def test_merge_both_sensors(self):
        """Merge with both network and log features."""
        from core.feature_merger import FeatureMerger

        merger = FeatureMerger()

        net_features = {
            'F1': 100.0, 'F2': 1.5, 'F3': 0.01, 'F4': 0.0,
            'F5': 3.0, 'F9': 500.0, 'F10': 2.0, 'F11': 50.0,
        }
        log_features = {
            'F6': 0.8, 'F7': 0.0, 'F8': 0.0,
            'F12': 0.1,
            'F13': 1.0, 'F14': 0.0, 'F15': 1.0,
            'F16': 0.0, 'F17': 2.0,
            'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
        }

        vector = merger.merge(
            network_features=net_features,
            log_features=log_features,
            window_end=1700000000.0,
            src_ip="10.0.10.10",
            packet_count=100,
            request_count=5,
        )

        self.assertEqual(len(vector.features), 30)
        self.assertEqual(vector.src_ip, "10.0.10.10")
        self.assertTrue(vector.network_available)
        self.assertTrue(vector.log_available)
        self.assertEqual(vector.packet_count, 100)
        self.assertEqual(vector.request_count, 5)

        # Check specific values
        self.assertEqual(vector.features[0], 100.0)    # F1
        self.assertEqual(vector.features[5], 0.8)      # F6
        self.assertEqual(vector.features[10], 8.0)      # F11

    def test_merge_network_only(self):
        """Merge with only network features (log missing)."""
        from core.feature_merger import FeatureMerger

        merger = FeatureMerger()
        net_features = {'F1': 50.0, 'F2': 1.0, 'F3': 0.05}

        vector = merger.merge(
            network_features=net_features,
            log_features=None,
            window_end=1700000000.0,
            src_ip="10.0.10.10",
        )

        self.assertEqual(len(vector.features), 30)
        self.assertTrue(vector.network_available)
        self.assertFalse(vector.log_available)
        self.assertEqual(vector.features[0], 50.0)     # F1
        self.assertEqual(vector.features[5], 0.0)      # F6 (missing)

    def test_merge_log_only(self):
        """Merge with only log features (network missing)."""
        from core.feature_merger import FeatureMerger

        merger = FeatureMerger()
        log_features = {'F6': 0.9, 'F7': 0.5, 'F11': 10.0}

        vector = merger.merge(
            network_features=None,
            log_features=log_features,
            window_end=1700000000.0,
            src_ip="10.0.10.10",
        )

        self.assertEqual(len(vector.features), 30)
        self.assertFalse(vector.network_available)
        self.assertTrue(vector.log_available)
        self.assertEqual(vector.features[0], 0.0)      # F1 (missing)
        self.assertEqual(vector.features[5], 0.9)      # F6

    def test_merge_all_multiple_ips(self):
        """merge_all handles multiple src_ips."""
        from core.feature_merger import FeatureMerger
        from core.network_sensor import NetworkFeatureResult
        from core.nginx_log_sensor import LogFeatureResult

        merger = FeatureMerger()

        net = {
            "10.0.10.10": NetworkFeatureResult(
                src_ip="10.0.10.10", window_start=0, window_end=1,
                features={'F1': 100.0}, packet_count=50
            ),
            "10.0.10.20": NetworkFeatureResult(
                src_ip="10.0.10.20", window_start=0, window_end=1,
                features={'F1': 200.0}, packet_count=80
            ),
        }
        log = {
            "10.0.10.10": LogFeatureResult(
                src_ip="10.0.10.10", window_start=0, window_end=1,
                features={'F6': 0.5}, request_count=3
            ),
        }

        vectors = merger.merge_all(net, log, window_end=1.0)
        self.assertEqual(len(vectors), 2)

        # 10.0.10.10 has both
        v1 = vectors[0]
        self.assertEqual(v1.src_ip, "10.0.10.10")
        self.assertTrue(v1.network_available)
        self.assertTrue(v1.log_available)

        # 10.0.10.20 has only network
        v2 = vectors[1]
        self.assertEqual(v2.src_ip, "10.0.10.20")
        self.assertTrue(v2.network_available)
        self.assertFalse(v2.log_available)

    def test_to_dict(self):
        """to_dict produces JSON-serializable output."""
        from core.feature_merger import FeatureMerger, MergedFeatureVector

        merger = FeatureMerger()
        vector = MergedFeatureVector(
            timestamp=1700000000.0,
            src_ip="10.0.10.10",
            features=[float(i) for i in range(30)],
        )

        d = merger.to_dict(vector)
        self.assertEqual(d['src_ip'], "10.0.10.10")
        self.assertEqual(d['pps'], 0.0)             # F1
        self.assertEqual(d['distinct_ports'], 4.0)   # F5

        # Should be JSON-serializable
        import json
        json_str = json.dumps(d)
        self.assertIsInstance(json_str, str)


class TestNetworkFeatureCalculator(unittest.TestCase):
    """Test NetworkFeatureCalculator uses correct subset."""

    def test_calculator_has_8_features(self):
        """NetworkFeatureCalculator has exactly 8 features."""
        from core.network_sensor import NetworkFeatureCalculator, NETWORK_FEATURE_CODES

        calc = NetworkFeatureCalculator()
        self.assertEqual(len(calc.calculators), 8)

        codes = [code for code, _ in calc.calculators]
        for expected in NETWORK_FEATURE_CODES:
            self.assertIn(expected, codes)


class TestLogFeatureCalculator(unittest.TestCase):
    """Test LogFeatureCalculator uses correct subset."""

    def test_calculator_has_22_features(self):
        """LogFeatureCalculator has exactly 22 features."""
        from core.nginx_log_sensor import LogFeatureCalculator, LOG_FEATURE_CODES

        calc = LogFeatureCalculator()
        self.assertEqual(len(calc.calculators), 22)

        codes = [code for code, _ in calc.calculators]
        for expected in LOG_FEATURE_CODES:
            self.assertIn(expected, codes)


class TestEndToEnd(unittest.TestCase):
    """End-to-end test: log file → features."""

    def test_full_pipeline_sqli(self):
        """Full pipeline: SQLi log → 22 features with detection."""
        from core.nginx_log_sensor import NginxLogSensor

        # Multiple SQLi attempts from same IP
        log_lines = [
            "10.0.10.10 - - [13/Feb/2026:10:30:45 +0700] "
            "\"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 100 "
            "rt=0.001 urt=0.001 "
            'uaddr="192.168.10.10:8080" ustatus="200" '
            'host="192.168.10.10" sni="192.168.10.10" '
            "tls=TLSv1.3/TLS_AES_256_GCM_SHA384 "
            'ref="-" ua="sqlmap/1.7" '
            'xff="-" cl="0" ct="-" reqid="s1"',

            "10.0.10.10 - - [13/Feb/2026:10:30:46 +0700] "
            "\"GET /search?q=' UNION SELECT username,password FROM users-- HTTP/1.1\" 500 50 "
            "rt=0.100 urt=0.095 "
            'uaddr="192.168.10.10:8080" ustatus="500" '
            'host="192.168.10.10" sni="192.168.10.10" '
            "tls=TLSv1.3/TLS_AES_256_GCM_SHA384 "
            'ref="-" ua="sqlmap/1.7" '
            'xff="-" cl="0" ct="-" reqid="s2"',

            "10.0.10.10 - - [13/Feb/2026:10:30:47 +0700] "
            "\"GET /search?q='; DROP TABLE users;-- HTTP/1.1\" 500 50 "
            "rt=0.050 urt=0.045 "
            'uaddr="192.168.10.10:8080" ustatus="500" '
            'host="192.168.10.10" sni="192.168.10.10" '
            "tls=TLSv1.3/TLS_AES_256_GCM_SHA384 "
            'ref="-" ua="sqlmap/1.7" '
            'xff="-" cl="0" ct="-" reqid="s3"',
        ]

        fd = tempfile.NamedTemporaryFile(
            mode='w', suffix='.log', delete=False, encoding='utf-8'
        )
        for line in log_lines:
            fd.write(line + "\n")
        fd.close()

        try:
            sensor = NginxLogSensor(fd.name, window_size=10.0)
            sensor._file_pos = 0

            count = sensor.read_new_entries()
            self.assertEqual(count, 3)

            results = sensor.flush_window()
            features = results["10.0.10.10"].features

            # Should detect SQLi
            self.assertGreater(features.get('F11', 0.0), 0.0, "F11 SqliKeyword")
            self.assertGreater(features.get('F12', 0.0), 0.0, "F12 SqlSpecialChar")

            # Should detect server errors (2 out of 3 responses are 500)
            self.assertGreater(features.get('F8', 0.0), 0.0, "F8 ServerErrorRate")

            # URL concentration should be high (all same /search path)
            self.assertGreater(features.get('F6', 0.0), 0.5, "F6 URLConcentration")

            print("\n=== SQLi Detection Results ===")
            for code in sorted(features.keys()):
                val = features[code]
                if val > 0:
                    print(f"  {code}: {val:.4f}")
        finally:
            os.unlink(fd.name)

    def test_full_pipeline_xss(self):
        """Full pipeline: XSS log → features with detection."""
        from core.nginx_log_sensor import NginxLogSensor

        log_lines = [
            "10.0.10.10 - - [13/Feb/2026:10:30:45 +0700] "
            "\"GET /comment?text=<script>alert(document.cookie)</script> HTTP/1.1\" 200 100 "
            "rt=0.001 urt=0.001 "
            'uaddr="192.168.10.10:8080" ustatus="200" '
            'host="192.168.10.10" sni="192.168.10.10" '
            "tls=TLSv1.3/TLS_AES_256_GCM_SHA384 "
            'ref="-" ua="Mozilla/5.0" '
            'xff="-" cl="0" ct="-" reqid="x1"',
        ]

        fd = tempfile.NamedTemporaryFile(
            mode='w', suffix='.log', delete=False, encoding='utf-8'
        )
        for line in log_lines:
            fd.write(line + "\n")
        fd.close()

        try:
            sensor = NginxLogSensor(fd.name, window_size=10.0)
            sensor._file_pos = 0

            sensor.read_new_entries()
            results = sensor.flush_window()
            features = results["10.0.10.10"].features

            # Should detect XSS
            self.assertGreater(features.get('F18', 0.0), 0.0, "F18 CrsXssScore")
            # F14 XssSpecialChar removed from active pipeline

            print("\n=== XSS Detection Results ===")
            for code in sorted(features.keys()):
                val = features[code]
                if val > 0:
                    print(f"  {code}: {val:.4f}")
        finally:
            os.unlink(fd.name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
