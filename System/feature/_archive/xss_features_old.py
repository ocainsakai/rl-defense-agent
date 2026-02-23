"""XSS sub-features (F25-F30) - Granular Cross-Site Scripting detection.

Features:
- F25: HtmlTagInjection - Dangerous HTML tag injection (<script>, <iframe>...)
- F26: JsFunctionCall - Dangerous JS function calls (alert, eval...)
- F27: HtmlEventHandler - HTML event handlers (onerror=, onload=...)
- F28: JsProtocolPresence - JS protocol handlers (javascript:, vbscript:)
- F29: HtmlEntityRatio - HTML entity encoding density
- F30: DataUriPresence - Data URI with base64 payload

Patterns sourced from:
- payload_context.py _XSS_PATTERNS (OWASP CRS 941 + PayloadsAllTheThings)
- Patterns are self-contained (copied, not imported) to avoid fragile dependencies.
"""

import re
import logging
from typing import List
from urllib.parse import unquote_plus
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature
from feature.context import FeatureContext

logger = logging.getLogger(__name__)


# =============================================================================
# COMPILED REGEX PATTERNS (module-level, compiled once)
# Source: payload_context.py lines 167-210 (OWASP CRS 941 + PayloadsAllTheThings)
# =============================================================================

# F25: Dangerous HTML tag patterns (payload_context.py lines 169-184)
_HTML_TAG_PATTERNS = [
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"<\s*/\s*script", re.IGNORECASE),
    re.compile(r"<\s*(?:iframe|frame|frameset)\b", re.IGNORECASE),
    re.compile(r"<\s*(?:object|embed|applet)\b", re.IGNORECASE),
    re.compile(r"<\s*(?:svg|math)\b", re.IGNORECASE),
    re.compile(r"<\s*(?:video|audio|source)\b", re.IGNORECASE),
    re.compile(r"<\s*(?:details|marquee|meter)\b", re.IGNORECASE),
    re.compile(r"<\s*(?:keygen|isindex|base)\b", re.IGNORECASE),
]

# F26: Dangerous JS function patterns (payload_context.py lines 201-208)
_JS_FUNCTION_PATTERNS = [
    re.compile(r"\balert\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bprompt\s*\(", re.IGNORECASE),
    re.compile(r"\bconfirm\s*\(", re.IGNORECASE),
    re.compile(r"\bexpression\s*\(", re.IGNORECASE),
    re.compile(r"document\.(?:cookie|write|domain)", re.IGNORECASE),
    re.compile(r"window\.location", re.IGNORECASE),
    re.compile(r"(?:inner|outer)html\s*=", re.IGNORECASE),
]

# F27: HTML event handler patterns (payload_context.py lines 188-194)
_EVENT_HANDLER_PATTERNS = [
    re.compile(r"\bon(?:error|load|click|mouse(?:over|out|down|up)|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"\bon(?:change|submit|reset|select|input|invalid)\s*=", re.IGNORECASE),
    re.compile(r"\bon(?:key(?:down|up|press)|dblclick|contextmenu)\s*=", re.IGNORECASE),
    re.compile(r"\bon(?:toggle|animationstart|animationend|transitionend)\s*=", re.IGNORECASE),
    re.compile(r"\bon(?:pointer(?:down|up|move|enter|leave)|wheel)\s*=", re.IGNORECASE),
    re.compile(r"\bon(?:touch(?:start|end|move|cancel)|loadstart)\s*=", re.IGNORECASE),
    re.compile(r"\bon(?:drag(?:start|end|over|leave|enter)?|drop|paste|copy|cut)\s*=", re.IGNORECASE),
]

# F28: JS protocol patterns (payload_context.py lines 173-176)
_JS_PROTOCOL_PATTERNS = [
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"java\s*script\s*:", re.IGNORECASE),
]

# F29: HTML entity pattern
_HTML_ENTITY_PATTERN = re.compile(r'&(?:#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);')

# F30: Data URI pattern (payload_context.py line 175)
_DATA_URI_PATTERNS = [
    re.compile(r"data\s*:[^,]*;?base64", re.IGNORECASE),
]


# =============================================================================
# FEATURE CLASSES
# =============================================================================

@register_feature(FeatureMetadata(
    name="HtmlTagInjection",
    code="F25",
    description="Dangerous HTML tag injection - <script>, <iframe>, <svg> (OWASP CRS 941110)",
    category="xss",
    depends_on=None
))
class F25_HtmlTagInjection(FeatureBase):
    """
    F25: HTML TAG INJECTION

    Phát hiện chèn tag HTML nguy hiểm để thực thi mã.
    VD: <script>alert(1)</script>, <iframe src=...>, <svg onload=...>

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
                for pattern in _HTML_TAG_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="JsFunctionCall",
    code="F26",
    description="Dangerous JS function call - alert(), eval(), document.cookie (OWASP CRS 941)",
    category="xss",
    depends_on=None
))
class F26_JsFunctionCall(FeatureBase):
    """
    F26: JS FUNCTION CALL

    Phát hiện gọi hàm JavaScript nguy hiểm.
    VD: alert(1), eval('code'), document.cookie, window.location

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
    code="F27",
    description="HTML event handler injection - onerror=, onload= (OWASP CRS 941120)",
    category="xss",
    depends_on=None
))
class F27_HtmlEventHandler(FeatureBase):
    """
    F27: HTML EVENT HANDLER

    Phát hiện sử dụng event handler HTML để trigger JavaScript.
    VD: <img onerror=alert(1)>, <svg onload=alert(1)>, <body onfocus=...>

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


@register_feature(FeatureMetadata(
    name="JsProtocolPresence",
    code="F28",
    description="JS protocol handler - javascript:, vbscript: (OWASP CRS 941130)",
    category="xss",
    depends_on=None
))
class F28_JsProtocolPresence(FeatureBase):
    """
    F28: JS PROTOCOL PRESENCE

    Phát hiện dùng protocol handler để chạy JavaScript.
    VD: <a href="javascript:alert(1)">, vbscript:MsgBox

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
                for pattern in _JS_PROTOCOL_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="HtmlEntityRatio",
    code="F29",
    description="HTML entity encoding density - high ratio indicates XSS obfuscation",
    category="xss",
    depends_on=None
))
class F29_HtmlEntityRatio(FeatureBase):
    """
    F29: HTML ENTITY RATIO

    Tỷ lệ HTML entity encoding trong payload.
    Attacker encode XSS payload bằng &#x3C; thay vì <, &#x3E; thay vì >.
    Tỷ lệ cao = khả năng obfuscation.

    Logic: Đếm trên RAW payload (URL-decoded nhưng KHÔNG html.unescape).

    Returns:
        Ratio [0, 1], NOT normalized
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        total_entity_chars = 0
        total_len = 0

        for f in flows:
            for pkt in f.get_fwd_packets():
                raw = ctx.get_raw_payload(pkt)
                if not raw:
                    continue

                # Decode bytes → string → URL decode only (NO html.unescape)
                text = raw.decode('utf-8', errors='ignore')
                text = unquote_plus(text)
                total_len += len(text)

                # Count HTML entities (&#x3C;, &#60;, &amp;, etc.)
                matches = _HTML_ENTITY_PATTERN.findall(text)
                total_entity_chars += sum(len(m) for m in matches)

        if total_len == 0:
            return 0.0

        ratio = float(total_entity_chars) / float(total_len)
        return min(ratio, 1.0)


@register_feature(FeatureMetadata(
    name="DataUriPresence",
    code="F30",
    description="Data URI with base64 payload - XSS via embedded content",
    category="xss",
    depends_on=None
))
class F30_DataUriPresence(FeatureBase):
    """
    F30: DATA URI PRESENCE

    Phát hiện nhúng mã JS qua data URI scheme.
    VD: <object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

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
                for pattern in _DATA_URI_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


__all__ = [
    'F25_HtmlTagInjection',
    'F26_JsFunctionCall',
    'F27_HtmlEventHandler',
    'F28_JsProtocolPresence',
    'F29_HtmlEntityRatio',
    'F30_DataUriPresence',
]
