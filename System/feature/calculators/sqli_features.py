"""SQLi sub-features — CRS-powered + granular SQL Injection detection.

Features:
- F13: CrsSquliScore  - OWASP CRS 942 anomaly score (0 to N) — broad coverage
- F14: SqlUnionSelect - UNION SELECT injection — data extraction technique
- F15: SqlComment     - SQL comment injection (--, #, /**/) — query truncation
- F16: SqlStackedQuery - Stacked query injection (; DROP...) — destructive commands
- F17: SqlSelectCount - Number of SELECT keywords — UNION chaining signal

CRS Source: REQUEST-942-APPLICATION-ATTACK-SQLI.conf (paranoia level 1)
  F18 covers: DB names, SQL functions, blind SQLi (sleep/benchmark),
              tautology, encoding evasion, error-based, boolean-based blind, ...
  F14/F15/F16: granular standalone signals for specific high-risk techniques.

Removed (not restored):
  F21 SqlQuoteImbalance — FP rate too high (normal text has unbalanced quotes)
  F24 SqlEncodingRatio  — overlap with F18 CRS encoding rules

Backup of old hand-coded version: sqli_features_old.py
"""

import math
import re
import logging
from typing import List

from core.flow_state import FlowState
from core.crs_loader import load_rx_patterns, CRS_SQLI_CONF
from feature.base import FeatureBase, FeatureMetadata, register_feature
from feature.context import FeatureContext

logger = logging.getLogger(__name__)


# =============================================================================
# PATTERNS — loaded/compiled once at module import
# =============================================================================

# F13: CRS 942 rules at PL1 — 19 patterns, broad SQLi coverage
_CRS_SQLI_PATTERNS = load_rx_patterns(CRS_SQLI_CONF, paranoia_level=1)

# F14: UNION-based injection
_UNION_PATTERNS = [
    re.compile(r"\bunion\b[\s\S]{0,50}\bselect\b", re.IGNORECASE),
    re.compile(r"\bunion\b\s+\ball\b\s+\bselect\b", re.IGNORECASE),
]

# F15: SQL comment injection (FIXED: --(?:\s|$) catches admin'--)
_COMMENT_PATTERNS = [
    re.compile(r"--(?:\s|$)", re.IGNORECASE),
    re.compile(r"#(?![0-9a-fA-F]{3,6}\b)", re.IGNORECASE),
    re.compile(r"/\*[\s\S]*?\*/", re.IGNORECASE),
    re.compile(r"/\*![0-9]*", re.IGNORECASE),
]

# F16: Stacked query — semicolon followed by destructive DDL/DML
_STACKED_QUERY_PATTERNS = [
    re.compile(r";\s*(?:drop|delete|insert|update|truncate|alter)\b", re.IGNORECASE),
]

# F17: SELECT count
_SELECT_PATTERN = re.compile(r"\bselect\b", re.IGNORECASE)


# =============================================================================
# FEATURE CLASSES
# =============================================================================

@register_feature(FeatureMetadata(
    name="SqlSpecialChar",
    code="F12",
    description="SQL special character ratio — proportion of ', -, ;, #, = in payload",
    category="sqli",
))
class F12_SqlSpecialChar(FeatureBase):
    """
    F12: SQL SPECIAL CHARACTER RATIO

    Ratio of SQL-significant characters in forward payloads.
    Special chars: ' - ; # =

    Returns:
        Ratio [0, 1], NOT normalized
    """

    SQLI_CHARS = set(b"'-;#=")

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        total_len = 0
        char_count = 0

        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        for f in flows:
            for pkt in f.get_fwd_packets():
                payload = ctx.get_raw_payload(pkt)
                if not payload:
                    continue
                total_len += len(payload)
                char_count += sum(1 for b in payload if b in self.SQLI_CHARS)

        if total_len == 0:
            return 0.0

        return float(char_count) / float(total_len)


@register_feature(FeatureMetadata(
    name="CrsSquliScore",
    code="F13",
    description=(
        "OWASP CRS 942 anomaly score — count of SQLi rules that fire. "
        "Covers: DB names, SQL functions (sleep/benchmark), tautology, "
        "encoding evasion, error-based, boolean blind. "
        "Source: REQUEST-942-APPLICATION-ATTACK-SQLI.conf PL1"
    ),
    category="sqli",
))
class F13_CrsSquliScore(FeatureBase):
    """
    F13: CRS SQLi ANOMALY SCORE

    Dem so rule CRS 942 bi kich hoat tren payload da normalize.
    Gia tri cang cao → cang nhieu chi dau SQLi → tin hieu manh hon cho RL.

    Vi du:
      score=0  → khong co dau hieu SQLi
      score=1  → 1 rule fire (dau hieu yeu, co the FP)
      score=5  → 5 rules fire (rat co kha nang la tan cong)

    Returns:
        float — so rule kich hoat (0.0 den len(_CRS_SQLI_PATTERNS))
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
                for _rule_id, _msg, pattern in _CRS_SQLI_PATTERNS:
                    if pattern.search(normalized):
                        total_score += 1.0

        return total_score


@register_feature(FeatureMetadata(
    name="SqlUnionSelect",
    code="F14",
    description="UNION SELECT injection — extracts data from other tables (F19)",
    category="sqli",
))
class F14_SqlUnionSelect(FeatureBase):
    """
    F14: SQL UNION-BASED INJECTION

    Phat hien UNION injection: noi ket qua truy van de trich xuat du lieu.
    VD: UNION SELECT username,password FROM users
        UNION ALL SELECT NULL,NULL,NULL--

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
                for pattern in _UNION_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SqlComment",
    code="F15",
    description="SQL comment injection — --, #, /**/ truncate the original query (F20)",
    category="sqli",
))
class F15_SqlComment(FeatureBase):
    """
    F15: SQL COMMENT INJECTION

    Phat hien comment injection: cat phan con lai cua truy van SQL goc.
    VD: admin'--   admin'#   ' OR 1=1/*

    Note: pattern --(?:\\s|$) catches end-of-string case (admin'--)

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
                for pattern in _COMMENT_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SqlStackedQuery",
    code="F16",
    description="Stacked query injection — semicolon + DDL/DML command (F22)",
    category="sqli",
))
class F16_SqlStackedQuery(FeatureBase):
    """
    F16: SQL STACKED QUERY

    Phat hien stacked query: chen lenh SQL thu 2 sau dau cham phay.
    Day la ky thuat nguy hiem nhat — co the xoa database, them user, ...
    VD: 1; DROP TABLE users--
        1; DELETE FROM sessions; --

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
                for pattern in _STACKED_QUERY_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SqlSelectCount",
    code="F17",
    description="Count of SELECT statements — multiple SELECTs indicate UNION chaining (F1=0.766 on test)",
    category="sqli",
))
class F17_SqlSelectCount(FeatureBase):
    """
    F17: SQL SELECT COUNT

    Dem so lan xuat hien SELECT: Nhieu SELECT = subquery injection hoac UNION chaining.
    VD: SELECT * FROM users UNION SELECT * FROM passwords -> count = 2

    Giu nguyen vi: TPR=62.1%, FPR=0.0%, F1=0.766 tren test dataset.

    Returns:
        Integer count as float, NOT normalized
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        total_count = 0
        for f in flows:
            for pkt in f.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue
                total_count += len(_SELECT_PATTERN.findall(normalized))

        return float(total_count)


__all__ = [
    'F12_SqlSpecialChar',
    'F13_CrsSquliScore',
    'F14_SqlUnionSelect',
    'F15_SqlComment',
    'F16_SqlStackedQuery',
    'F17_SqlSelectCount',
]
