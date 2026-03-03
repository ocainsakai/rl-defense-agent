"""Đặc trưng phụ XSS — Phát hiện Cross-Site Scripting dựa trên CRS.

Đặc trưng:
- F18: CrsXssScore      - Số rule OWASP CRS 941 bị kích hoạt (0 đến N)
- F19: JsFunctionCall   - Gọi hàm JS nguy hiểm (giữ lại: F1=0.995 khi kiểm thử)
- F20: HtmlEventHandler - HTML event handler (giữ lại: F1=0.755 khi kiểm thử)

Nguồn CRS: REQUEST-941-APPLICATION-ATTACK-XSS.conf (paranoia level 1)
  Bao gồm: script tags, event handler, JS URI, NoScript injection,
           IE XSS filter, obfuscation JSFuck, AngularJS SSTI,
           từ khóa blacklist node-validator, ...

Thay thế (đã gộp vào F18_CrsXssScore):
  F18 cũ HtmlTagInjection, F28 JsProtocolPresence,
      F29 HtmlEntityRatio, F30 DataUriPresence
"""

import re
import logging
from typing import List

from core.flow_state import FlowState
from core.crs_loader import load_rx_patterns, load_pm_phrases, CRS_XSS_CONF
from feature.base import FeatureBase, FeatureMetadata, register_feature
from feature.context import FeatureContext

logger = logging.getLogger(__name__)


# =============================================================================
# PATTERN CRS — tải một lần khi import module
# =============================================================================

# F18: Rule CRS 941 — Benchmark trên LSNM2024 dataset (2026-03, n=3000 normal + 9 attack):
#   PL   Rules  TP  FP  F1      FPR
#   PL1  22     9   0   1.0000  0.0000
#   PL2  27     9   0   1.0000  0.0000  [DÙNG]
#   PL3  27     9   0   1.0000  0.0000  (PL3 == PL2 vì không có rule PL3 trong XSS conf)
#
# CHÚ Ý: Benchmark XSS bị giới hạn — LSNM2024 XSS dataset (WebGoat) gửi payload
# qua HTTP POST body, không phải GET URI. CSV chỉ ghi URL → chỉ 9/3000 URI
# chứa XSS keyword. Kết quả trên KHÔNG đủ tin cậy để quyết định thay đổi PL.
# → Giữ PL2 cho đến khi có benchmark từ PCAP với POST body đầy đủ.
# Chạy lại: python3 tools/benchmark_crs_pl.py
_CRS_XSS_PATTERNS = load_rx_patterns(CRS_XSS_CONF, paranoia_level=2)

_CRS_XSS_PHRASES = load_pm_phrases(CRS_XSS_CONF)
# Danh sách chuỗi chữ thường — 9 cụm từ từ các rule @pm
# VD: ['document.cookie', 'document.write', '.innerhtml', 'window.location', ...]

# F19: Pattern hàm JS nguy hiểm (giữ lại — đã kiểm thử: F1=0.995, FPR=0.0%)
_JS_FUNCTION_PATTERNS = [
    re.compile(r"\balert\s*\(",         re.IGNORECASE),
    re.compile(r"\beval\s*\(",          re.IGNORECASE),
    re.compile(r"\bprompt\s*\(",        re.IGNORECASE),
    re.compile(r"\bconfirm\s*\(",       re.IGNORECASE),
    re.compile(r"\bexpression\s*\(",    re.IGNORECASE),
    re.compile(r"document\.(?:cookie|write|domain)", re.IGNORECASE),
    re.compile(r"window\.location",     re.IGNORECASE),
    re.compile(r"(?:inner|outer)html\s*=", re.IGNORECASE),
]

# F20: Pattern event handler HTML (giữ lại — đã kiểm thử: F1=0.755, FPR=0.0%)
_EVENT_HANDLER_PATTERNS = [
    re.compile(r"\bon(?:error|load|click|mouse(?:over|out|down|up)|focus|blur)\s*=",     re.IGNORECASE),
    re.compile(r"\bon(?:change|submit|reset|select|input|invalid)\s*=",                   re.IGNORECASE),
    re.compile(r"\bon(?:key(?:down|up|press)|dblclick|contextmenu)\s*=",                  re.IGNORECASE),
    re.compile(r"\bon(?:toggle|animationstart|animationend|transitionend)\s*=",           re.IGNORECASE),
    re.compile(r"\bon(?:pointer(?:down|up|move|enter|leave)|wheel)\s*=",                  re.IGNORECASE),
    re.compile(r"\bon(?:touch(?:start|end|move|cancel)|loadstart)\s*=",                   re.IGNORECASE),
    re.compile(r"\bon(?:drag(?:start|end|over|leave|enter)?|drop|paste|copy|cut)\s*=",   re.IGNORECASE),
]


# =============================================================================
# CÁC LỚP ĐẶC TRƯNG
# =============================================================================

@register_feature(FeatureMetadata(
    name="CrsXssScore",
    code="F18",
    description=(
        "Điểm CRS 941 trung bình mỗi HTTP request — số rule XSS kích hoạt / số request. "
        "Bao gồm: script tag, event handler, JS URI, NoScript injection, "
        "IE XSS filter, JSFuck, AngularJS SSTI, từ khóa node-validator. "
        f"Nguồn: REQUEST-941-APPLICATION-ATTACK-XSS.conf PL1"
    ),
    category="xss",
))
class F18_CrsXssScore(FeatureBase):
    """
    F18: ĐIỂM BẤT THƯỜNG CRS XSS (bình quân mỗi request)

    Tổng số rule CRS 941 bị kích hoạt / số HTTP request trong window.
    Bao gồm cả rule @rx (regex) và @pm (phrase match).
    Normalize theo request count để tránh false positive do traffic volume cao.

    Ví dụ:
      score=0  → không có dấu hiệu XSS
      score=1  → 1 rule kích hoạt trung bình mỗi request (dấu hiệu yếu)
      score=8  → 8 rule kích hoạt trung bình mỗi request (chắc chắn là tấn công)

    Thay thế: F25(HtmlTagInjection), F28(JsProtocol),
              F29(HtmlEntityRatio), F30(DataUri)

    Returns:
        float ≥ 0.0 — số rule trung bình mỗi HTTP request
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        total_score = 0.0
        http_request_count = 0
        for f in flows:
            for pkt in f.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue

                http_request_count += 1

                # Rule @rx: mỗi pattern khớp = +1
                for _rule_id, _msg, pattern in _CRS_XSS_PATTERNS:
                    if pattern.search(normalized):
                        total_score += 1.0

                # Cụm từ @pm: mỗi cụm từ khớp = +1
                for phrase in _CRS_XSS_PHRASES:
                    if phrase in normalized:
                        total_score += 1.0

        if http_request_count == 0:
            return 0.0
        return total_score / http_request_count


@register_feature(FeatureMetadata(
    name="JsFunctionCall",
    code="F19",
    description="Gọi hàm JS nguy hiểm — alert(), eval(), document.cookie (F1=0.995 khi kiểm thử)",
    category="xss",
))
class F19_JsFunctionCall(FeatureBase):
    """
    F19: GỌI HÀM JAVASCRIPT

    Phát hiện gọi hàm JavaScript nguy hiểm.
    VD: alert(1), eval('code'), document.cookie, window.location

    Giữ nguyên vì: TPR=99.0%, FPR=0.0%, F1=0.995 trên test dataset.

    Returns:
        Binary 0.0 or 1.0
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        for f in flows:
            for pkt in f.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue
                for pattern in _JS_FUNCTION_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="HtmlEventHandler",
    code="F20",
    description="HTML event handler injection — onerror=, onload=, onclick= (F1=0.755 khi kiểm thử)",
    category="xss",
))
class F20_HtmlEventHandler(FeatureBase):
    """
    F20: EVENT HANDLER HTML

    Phát hiện sử dụng event handler HTML để kích hoạt JavaScript.
    VD: <img onerror=alert(1)>, <svg onload=alert(1)>

    Giữ nguyên vì: TPR=60.6%, FPR=0.0%, F1=0.755 trên test dataset.

    Returns:
        Binary 0.0 or 1.0
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        for f in flows:
            for pkt in f.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue
                for pattern in _EVENT_HANDLER_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


__all__ = [
    'F18_CrsXssScore',
    'F19_JsFunctionCall',
    'F20_HtmlEventHandler',
]
