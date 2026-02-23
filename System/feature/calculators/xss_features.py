"""XSS sub-features — CRS-powered Cross-Site Scripting detection.

Features:
- F18: CrsXssScore      - Count of OWASP CRS 941 rules that fire (0 to N)
- F19: JsFunctionCall   - Dangerous JS function calls (kept: tested F1=0.995)
- F20: HtmlEventHandler - HTML event handlers (kept: tested F1=0.755)

CRS Source: REQUEST-941-APPLICATION-ATTACK-XSS.conf (paranoia level 1)
  Covers: script tags, event handlers, JS URI, NoScript injection,
          IE XSS filters, JSFuck obfuscation, AngularJS SSTI,
          node-validator blacklist keywords, ...

Replaces (merged into F18_CrsXssScore):
  OLD F18 HtmlTagInjection, F28 JsProtocolPresence,
      F29 HtmlEntityRatio, F30 DataUriPresence

Backup of old hand-coded version: xss_features_old.py
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
# CRS PATTERNS — loaded once at module import
# =============================================================================

_CRS_XSS_PATTERNS = load_rx_patterns(CRS_XSS_CONF, paranoia_level=1)
# List of (rule_id, msg, compiled_pattern) — 22 patterns at PL1

_CRS_XSS_PHRASES = load_pm_phrases(CRS_XSS_CONF)
# List of lowercase strings — 9 phrases from @pm rules
# e.g. ['document.cookie', 'document.write', '.innerhtml', 'window.location', ...]

# F19: Dangerous JS function patterns (kept — tested: F1=0.995, FPR=0.0%)
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

# F20: HTML event handler patterns (kept — tested: F1=0.755, FPR=0.0%)
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
# FEATURE CLASSES
# =============================================================================

@register_feature(FeatureMetadata(
    name="CrsXssScore",
    code="F18",
    description=(
        "OWASP CRS 941 anomaly score — count of XSS rules that fire. "
        "Covers: script tags, event handlers, JS URI, NoScript injection, "
        "IE XSS filters, JSFuck, AngularJS SSTI, node-validator keywords. "
        f"Source: REQUEST-941-APPLICATION-ATTACK-XSS.conf PL1"
    ),
    category="xss",
))
class F18_CrsXssScore(FeatureBase):
    """
    F25: CRS XSS ANOMALY SCORE

    Dem so rule CRS 941 bi kich hoat tren payload da normalize.
    Bao gom ca @rx (regex) va @pm (phrase match) rules.

    Vi du:
      score=0  → khong co dau hieu XSS
      score=1  → 1 rule fire (dau hieu yeu)
      score=8  → 8 rules fire (chac chan la tan cong)

    Thay the: F25(HtmlTagInjection), F28(JsProtocol),
              F29(HtmlEntityRatio), F30(DataUri)

    Returns:
        float — tong so rule kich hoat (0.0 den len(_CRS_XSS_PATTERNS) + @pm)
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        total_score = 0.0
        for f in flows:
            for pkt in f.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue

                # @rx rules: each matching pattern = +1
                for _rule_id, _msg, pattern in _CRS_XSS_PATTERNS:
                    if pattern.search(normalized):
                        total_score += 1.0

                # @pm phrases: each matching phrase = +1
                for phrase in _CRS_XSS_PHRASES:
                    if phrase in normalized:
                        total_score += 1.0

        return total_score


@register_feature(FeatureMetadata(
    name="JsFunctionCall",
    code="F19",
    description="Dangerous JS function call — alert(), eval(), document.cookie (F1=0.995 on test)",
    category="xss",
))
class F19_JsFunctionCall(FeatureBase):
    """
    F26: JS FUNCTION CALL

    Phat hien goi ham JavaScript nguy hiem.
    VD: alert(1), eval('code'), document.cookie, window.location

    Giu nguyen vi: TPR=99.0%, FPR=0.0%, F1=0.995 tren test dataset.

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
    description="HTML event handler injection — onerror=, onload=, onclick= (F1=0.755 on test)",
    category="xss",
))
class F20_HtmlEventHandler(FeatureBase):
    """
    F27: HTML EVENT HANDLER

    Phat hien su dung event handler HTML de trigger JavaScript.
    VD: <img onerror=alert(1)>, <svg onload=alert(1)>

    Giu nguyen vi: TPR=60.6%, FPR=0.0%, F1=0.755 tren test dataset.

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
