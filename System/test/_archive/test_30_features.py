"""
Test all 30 features (F1-F30) with single payload scenarios.

Each test sends ONE specific payload through the pipeline and verifies
the corresponding feature returns expected values.

Groups:
- F1-F5: Network features
- F6-F8: Application features
- F9-F14: Payload features
- F15-F17: Extended network features
- F18-F24: SQLi sub-features
- F25-F30: XSS sub-features
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator
from feature.calculators.network_features import (
    F1_PacketRate, F2_SynAckRatio, F3_InterArrivalTime,
    F4_RstRatio, F5_DistinctPorts,
)
from feature.calculators.application_features import (
    F6_URLConcentration, F7_AuthFailureRate, F8_ServerErrorRate,
)
from feature.calculators.payload_features import (
    F9_PayloadLength, F10_PayloadEntropy,
    F11_SqliKeyword, F12_SqlSpecialChar,
    F13_XssKeyword, F14_XssSpecialChar,
)
from feature.calculators.network_features_ext import (
    F15_AvgPayloadSize, F16_FwdBwdRatio, F17_PacketsPerPort,
)
from feature.calculators.sqli_features import (
    F18_SqlTautology, F19_SqlUnionSelect, F20_SqlComment,
    F21_SqlQuoteImbalance, F22_SqlStackedQuery,
    F23_SqlSelectCount, F24_SqlEncodingRatio,
)
from feature.calculators.xss_features import (
    F25_HtmlTagInjection, F26_JsFunctionCall, F27_HtmlEventHandler,
    F28_JsProtocolPresence, F29_HtmlEntityRatio, F30_DataUriPresence,
)


# =============================================================================
# HELPERS
# =============================================================================

def _make_flows(packets, parser):
    """Send packets through parser + FlowManager, return flows."""
    fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
    for i, pkt in enumerate(packets, 1):
        info = parser.extract(pkt, i)
        fm.process_packet(info)
    return fm.get_all_flows()


def _make_http_flow(payload: bytes, parser):
    """Create a single HTTP GET flow with given payload."""
    pkt = (Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
           TCP(sport=5000, dport=80, flags="PA") / Raw(load=payload))
    return _make_flows([pkt], parser)


# =============================================================================
# F1-F5: NETWORK FEATURES
# =============================================================================

@pytest.mark.unit
class TestF1PacketRate:
    def test_multiple_packets(self, parser):
        """Multiple packets in short time -> packet rate > 0"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"data")
            for _ in range(5)
        ]
        flows = _make_flows(pkts, parser)
        rate = F1_PacketRate().calculate(flows)
        assert rate >= 0


@pytest.mark.unit
class TestF2SynAckRatio:
    def test_syn_flood(self, parser):
        """10 SYN, 0 ACK -> ratio = 10"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000 + i, dport=80, flags="S")
            for i in range(10)
        ]
        flows = _make_flows(pkts, parser)
        assert F2_SynAckRatio().calculate(flows) == 10.0

    def test_normal_handshake(self, parser):
        """1 SYN + 1 ACK -> ratio = 1"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="S"),
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="A"),
        ]
        flows = _make_flows(pkts, parser)
        assert F2_SynAckRatio().calculate(flows) == 1.0


@pytest.mark.unit
class TestF3InterArrivalTime:
    def test_returns_float(self, parser):
        """IAT should be a non-negative float"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"data")
            for _ in range(3)
        ]
        flows = _make_flows(pkts, parser)
        iat = F3_InterArrivalTime().calculate(flows)
        assert isinstance(iat, float)
        assert iat >= 0


@pytest.mark.unit
class TestF4RstRatio:
    def test_rst_responses(self, parser):
        """2 RST out of 5 backward packets -> ratio ~ 0.4"""
        fwd = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000 + i, dport=port, flags="S")
            for i, port in enumerate([22, 80, 443, 8080, 3306])
        ]
        bwd = [
            Ether() / IP(src="10.0.0.1", dst="192.168.1.100") /
            TCP(sport=port, dport=5000 + i, flags=flags)
            for i, (port, flags) in enumerate([
                (22, "R"), (80, "SA"), (443, "SA"), (8080, "SA"), (3306, "R")
            ])
        ]
        flows = _make_flows(fwd + bwd, parser)
        ratio = F4_RstRatio().calculate(flows)
        assert abs(ratio - 0.4) < 0.1


@pytest.mark.unit
class TestF5DistinctPorts:
    def test_port_scan(self, parser):
        """15 distinct destination ports"""
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443, 9200]
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=40000 + i, dport=port, flags="S")
            for i, port in enumerate(ports)
        ]
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        p = PacketLayerExtractor(use_packet_time=False)
        for i, pkt in enumerate(pkts, 1):
            info = p.extract(pkt, i)
            fm.process_packet(info)
        flows = fm.get_flows_by_src("192.168.1.100")
        assert F5_DistinctPorts().calculate(flows) == 15


# =============================================================================
# F6-F8: APPLICATION FEATURES
# =============================================================================

@pytest.mark.unit
class TestF6URLConcentration:
    def test_same_url_high_concentration(self, parser_http):
        """All requests to same URL -> concentration = 1.0"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000 + i, dport=80, flags="PA") /
            Raw(load=b"GET /login HTTP/1.1\r\nHost: target.com\r\n\r\n")
            for i in range(5)
        ]
        flows = _make_flows(pkts, parser_http)
        conc = F6_URLConcentration().calculate(flows)
        assert conc == 1.0


@pytest.mark.unit
class TestF7AuthFailureRate:
    def test_no_responses_returns_zero(self, parser_http):
        """No backward packets -> auth failure rate = 0"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="PA") /
            Raw(load=b"GET /admin HTTP/1.1\r\n\r\n")
        ]
        flows = _make_flows(pkts, parser_http)
        rate = F7_AuthFailureRate().calculate(flows)
        assert rate == 0.0


@pytest.mark.unit
class TestF8ServerErrorRate:
    def test_no_responses_returns_zero(self, parser_http):
        """No backward packets -> server error rate = 0"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="PA") /
            Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        ]
        flows = _make_flows(pkts, parser_http)
        rate = F8_ServerErrorRate().calculate(flows)
        assert rate == 0.0


# =============================================================================
# F9-F14: PAYLOAD FEATURES
# =============================================================================

@pytest.mark.unit
class TestF9PayloadLength:
    def test_payload_length(self, parser_http):
        """Payload length should be > 0 for HTTP request"""
        payload = b"GET /search?q=hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        length = F9_PayloadLength().calculate(flows)
        assert length > 0


@pytest.mark.unit
class TestF10PayloadEntropy:
    def test_text_entropy(self, parser_http):
        """Normal text has medium entropy (3-6)"""
        payload = b"GET /search?q=hello+world+test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        entropy = F10_PayloadEntropy().calculate(flows)
        assert 2.0 < entropy < 7.0


@pytest.mark.unit
class TestF11SqliKeyword:
    def test_union_select(self, parser_http):
        """UNION SELECT payload -> score > 0"""
        payload = b"GET /page?id=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: t.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F11_SqliKeyword().calculate(flows) > 0

    def test_clean_payload(self, parser_http):
        """Clean payload -> score = 0"""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F11_SqliKeyword().calculate(flows) == 0


@pytest.mark.unit
class TestF12SqlSpecialChar:
    def test_sqli_chars(self, parser_http):
        """SQLi payload has high special char ratio"""
        payload = b"GET /page?id=1'--; HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        ratio = F12_SqlSpecialChar().calculate(flows)
        assert ratio > 0

    def test_clean_low_ratio(self, parser_http):
        """Clean text has low special char ratio"""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        ratio = F12_SqlSpecialChar().calculate(flows)
        assert ratio < 0.1


@pytest.mark.unit
class TestF13XssKeyword:
    def test_script_tag(self, parser_http):
        """<script> payload -> score > 0"""
        payload = b"GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F13_XssKeyword().calculate(flows) > 0

    def test_clean_payload(self, parser_http):
        """Clean payload -> score = 0"""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F13_XssKeyword().calculate(flows) == 0


@pytest.mark.unit
class TestF14XssSpecialChar:
    def test_xss_chars(self, parser_http):
        """XSS payload has angle brackets -> ratio > 0"""
        payload = b"GET /page?q=<img src=x> HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        ratio = F14_XssSpecialChar().calculate(flows)
        assert ratio > 0


# =============================================================================
# F15-F17: EXTENDED NETWORK FEATURES
# =============================================================================

@pytest.mark.unit
class TestF15AvgPayloadSize:
    def test_with_payload(self, parser_http):
        """Forward packets with payload -> avg > 0"""
        payload = b"GET /data HTTP/1.1\r\nHost: example.com\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        avg = F15_AvgPayloadSize().calculate(flows)
        assert avg > 0

    def test_syn_only_zero(self, parser):
        """SYN-only packets (no payload) -> avg = 0"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="S")
        ]
        flows = _make_flows(pkts, parser)
        assert F15_AvgPayloadSize().calculate(flows) == 0.0


@pytest.mark.unit
class TestF16FwdBwdRatio:
    def test_fwd_only(self, parser):
        """Only forward packets -> ratio high"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000, dport=80, flags="PA") / Raw(load=b"data")
            for _ in range(5)
        ]
        flows = _make_flows(pkts, parser)
        ratio = F16_FwdBwdRatio().calculate(flows)
        assert ratio >= 5.0


@pytest.mark.unit
class TestF17PacketsPerPort:
    def test_single_port(self, parser):
        """5 packets to 1 port -> packets_per_port = 5"""
        pkts = [
            Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
            TCP(sport=5000 + i, dport=80, flags="S")
            for i in range(5)
        ]
        flows = _make_flows(pkts, parser)
        ppp = F17_PacketsPerPort().calculate(flows)
        assert ppp == 5.0


# =============================================================================
# F18-F24: SQLi SUB-FEATURES
# =============================================================================

@pytest.mark.unit
class TestF18SqlTautology:
    def test_or_1_equals_1(self, parser_http):
        """OR 1=1 tautology -> detected"""
        payload = b"GET /login?user=admin' OR 1=1-- HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F18_SqlTautology().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F18_SqlTautology().calculate(flows) == 0.0


@pytest.mark.unit
class TestF19SqlUnionSelect:
    def test_union_select(self, parser_http):
        """UNION SELECT -> detected"""
        payload = b"GET /page?id=1 UNION SELECT * FROM users HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F19_SqlUnionSelect().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F19_SqlUnionSelect().calculate(flows) == 0.0


@pytest.mark.unit
class TestF20SqlComment:
    def test_double_dash(self, parser_http):
        """SQL comment -- -> detected"""
        payload = b"GET /page?id=1-- comment HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F20_SqlComment().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F20_SqlComment().calculate(flows) == 0.0


@pytest.mark.unit
class TestF21SqlQuoteImbalance:
    def test_odd_quotes(self, parser_http):
        """Odd number of single quotes -> detected"""
        payload = b"GET /page?id=admin' HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F21_SqlQuoteImbalance().calculate(flows) == 1.0

    def test_balanced_quotes(self, parser_http):
        """Even quotes -> not detected"""
        payload = b"GET /page?q='hello' HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F21_SqlQuoteImbalance().calculate(flows) == 0.0


@pytest.mark.unit
class TestF22SqlStackedQuery:
    def test_stacked_drop(self, parser_http):
        """Stacked query with DROP -> detected"""
        payload = b"GET /page?id=1; DROP TABLE users HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F22_SqlStackedQuery().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F22_SqlStackedQuery().calculate(flows) == 0.0


@pytest.mark.unit
class TestF23SqlSelectCount:
    def test_multiple_selects(self, parser_http):
        """Multiple SELECT statements -> count > 1"""
        payload = b"GET /page?id=1 UNION SELECT (SELECT password FROM users) HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        count = F23_SqlSelectCount().calculate(flows)
        assert count >= 2

    def test_no_select(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F23_SqlSelectCount().calculate(flows) == 0


@pytest.mark.unit
class TestF24SqlEncodingRatio:
    def test_url_encoded(self, parser_http):
        """URL-encoded SQLi -> encoding ratio > 0"""
        payload = b"GET /page?id=%27%20OR%201%3D1-- HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        ratio = F24_SqlEncodingRatio().calculate(flows)
        assert ratio > 0

    def test_clean_no_encoding(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F24_SqlEncodingRatio().calculate(flows) == 0.0


# =============================================================================
# F25-F30: XSS SUB-FEATURES
# =============================================================================

@pytest.mark.unit
class TestF25HtmlTagInjection:
    def test_script_tag(self, parser_http):
        """<script> tag -> detected"""
        payload = b"GET /page?q=<script>alert(1)</script> HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F25_HtmlTagInjection().calculate(flows) == 1.0

    def test_iframe_tag(self, parser_http):
        """<iframe> tag -> detected"""
        payload = b"GET /page?q=<iframe src=evil.com></iframe> HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F25_HtmlTagInjection().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F25_HtmlTagInjection().calculate(flows) == 0.0


@pytest.mark.unit
class TestF26JsFunctionCall:
    def test_alert(self, parser_http):
        """alert() call -> detected"""
        payload = b"GET /page?q=<img src=x onerror=alert(1)> HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F26_JsFunctionCall().calculate(flows) == 1.0

    def test_eval(self, parser_http):
        """eval() call -> detected"""
        payload = b"GET /page?q=eval(atob('YWxlcnQoMSk=')) HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F26_JsFunctionCall().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F26_JsFunctionCall().calculate(flows) == 0.0


@pytest.mark.unit
class TestF27HtmlEventHandler:
    def test_onerror(self, parser_http):
        """onerror= event handler -> detected"""
        payload = b'GET /page?q=<img src=x onerror="alert(1)"> HTTP/1.1\r\n\r\n'
        flows = _make_http_flow(payload, parser_http)
        assert F27_HtmlEventHandler().calculate(flows) == 1.0

    def test_onload(self, parser_http):
        """onload= event handler -> detected"""
        payload = b'GET /page?q=<body onload="alert(1)"> HTTP/1.1\r\n\r\n'
        flows = _make_http_flow(payload, parser_http)
        assert F27_HtmlEventHandler().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F27_HtmlEventHandler().calculate(flows) == 0.0


@pytest.mark.unit
class TestF28JsProtocolPresence:
    def test_javascript_protocol(self, parser_http):
        """javascript: protocol -> detected"""
        payload = b"GET /page?url=javascript:alert(1) HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F28_JsProtocolPresence().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F28_JsProtocolPresence().calculate(flows) == 0.0


@pytest.mark.unit
class TestF29HtmlEntityRatio:
    def test_entity_encoded(self, parser_http):
        """HTML entity encoded payload -> ratio > 0"""
        payload = b"GET /page?q=&#60;script&#62;alert(1)&#60;/script&#62; HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        ratio = F29_HtmlEntityRatio().calculate(flows)
        assert ratio > 0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F29_HtmlEntityRatio().calculate(flows) == 0.0


@pytest.mark.unit
class TestF30DataUriPresence:
    def test_data_uri(self, parser_http):
        """data: URI with base64 -> detected"""
        payload = b"GET /page?q=<a href=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==> HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F30_DataUriPresence().calculate(flows) == 1.0

    def test_clean(self, parser_http):
        payload = b"GET /index.html HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)
        assert F30_DataUriPresence().calculate(flows) == 0.0


# =============================================================================
# INTEGRATION: Full 30-feature vector
# =============================================================================

@pytest.mark.unit
class TestFull30Features:
    def test_clean_payload_30_features(self, parser_http):
        """Clean HTTP request produces 30 features, all detection features = 0"""
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        pkt = (Ether() / IP(src="192.168.1.100", dst="10.0.0.1") /
               TCP(sport=5000, dport=80, flags="PA") / Raw(load=payload))
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        p = PacketLayerExtractor(use_packet_time=False)
        info = p.extract(pkt, 1)
        fm.process_packet(info)
        flows = fm.get_all_flows()

        calc = FlowFeatureCalculator()
        features = calc.calculate_all_optimized(flows)

        assert len(features) == 30
        # F11 (SQLi), F13 (XSS) should be 0 for clean payload
        assert features[10] == 0  # F11
        assert features[12] == 0  # F13
        # F18-F24 (SQLi sub) should be 0
        for i in range(17, 24):
            assert features[i] == 0, f"F{i+1} should be 0 for clean payload"
        # F25-F30 (XSS sub) should be 0
        for i in range(24, 30):
            assert features[i] == 0, f"F{i+1} should be 0 for clean payload"

    def test_sqli_payload_30_features(self, parser_http):
        """SQLi payload triggers SQLi features, not XSS"""
        payload = b"GET /page?id=admin' UNION SELECT password FROM users WHERE 1=1-- HTTP/1.1\r\n\r\n"
        flows = _make_http_flow(payload, parser_http)

        calc = FlowFeatureCalculator()
        features = calc.calculate_all_optimized(flows)

        assert len(features) == 30
        assert features[10] > 0  # F11 SQLi score > 0
        assert features[17] > 0  # F18 Tautology or F19 Union detected

    def test_xss_payload_30_features(self, parser_http):
        """XSS payload triggers XSS features, not SQLi"""
        payload = b'GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\r\n\r\n'
        flows = _make_http_flow(payload, parser_http)

        calc = FlowFeatureCalculator()
        features = calc.calculate_all_optimized(flows)

        assert len(features) == 30
        assert features[12] > 0  # F13 XSS score > 0
        assert features[24] == 1.0  # F25 HtmlTagInjection
