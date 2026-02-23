"""SQLi sub-features (F18-F24) - Granular SQL Injection detection.

Features:
- F18: SqlTautology - Tautology injection (OR 1=1, 'a'='a')
- F19: SqlUnionSelect - UNION-based injection
- F20: SqlComment - SQL comment injection (--, #, /**/)
- F21: SqlQuoteImbalance - Unbalanced quotes detection
- F22: SqlStackedQuery - Stacked query injection (; DROP...)
- F23: SqlSelectCount - Number of SELECT statements
- F24: SqlEncodingRatio - URL-encoded character ratio

Patterns sourced from:
- payload_context.py _SQL_PATTERNS (OWASP CRS 942 + PayloadsAllTheThings)
- Patterns are self-contained (copied, not imported) to avoid fragile dependencies.
"""

import re
import logging
from typing import List
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature
from feature.context import FeatureContext

logger = logging.getLogger(__name__)


# =============================================================================
# COMPILED REGEX PATTERNS (module-level, compiled once)
# Source: payload_context.py lines 119-164 (OWASP CRS 942)
# =============================================================================

# F18: Tautology patterns (payload_context.py lines 125-129)
_TAUTOLOGY_PATTERNS = [
    re.compile(r"'\s{0,5}\bor\b\s{1,10}['\"]?\d", re.IGNORECASE),
    re.compile(r"'\s{0,5}\band\b\s{1,10}['\"]?\d", re.IGNORECASE),
    re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"\bor\b\s+true\b", re.IGNORECASE),
    re.compile(r"\bor\b\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]", re.IGNORECASE),
]

# F19: UNION-based patterns (payload_context.py lines 121-122)
_UNION_PATTERNS = [
    re.compile(r"\bunion\b[\s\S]{0,50}\bselect\b", re.IGNORECASE),
    re.compile(r"\bunion\b\s+\ball\b\s+\bselect\b", re.IGNORECASE),
]

# F20: Comment patterns (payload_context.py lines 140-143)
_COMMENT_PATTERNS = [
    re.compile(r"--(?:\s|$)", re.IGNORECASE),    # FIXED: was r"--\s", missed admin'--
    re.compile(r"#(?![0-9a-fA-F]{3,6}\b)", re.IGNORECASE),
    re.compile(r"/\*[\s\S]*?\*/", re.IGNORECASE),
    re.compile(r"/\*![0-9]*", re.IGNORECASE),
]

# F22: Stacked query pattern (payload_context.py line 164)
_STACKED_QUERY_PATTERNS = [
    re.compile(r";\s*(?:drop|delete|insert|update|truncate|alter)\b", re.IGNORECASE),
]

# F23: SELECT count
_SELECT_PATTERN = re.compile(r"\bselect\b", re.IGNORECASE)

# F24: URL-encoded character pattern
_URL_ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")


# =============================================================================
# FEATURE CLASSES
# =============================================================================

@register_feature(FeatureMetadata(
    name="SqlTautology",
    code="F18",
    description="SQL tautology injection - OR 1=1, 'a'='a' (OWASP CRS 942380)",
    category="sqli",
    depends_on=None
))
class F18_SqlTautology(FeatureBase):
    """
    F18: SQL TAUTOLOGY DETECTION

    Phát hiện tautology injection: Làm điều kiện WHERE luôn đúng.
    VD: ' OR 1=1 --, ' OR 'a'='a', OR true

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
                for pattern in _TAUTOLOGY_PATTERNS:
                    if pattern.search(normalized):
                        return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SqlUnionSelect",
    code="F19",
    description="SQL UNION-based injection - UNION SELECT (OWASP CRS 942270)",
    category="sqli",
    depends_on=None
))
class F19_SqlUnionSelect(FeatureBase):
    """
    F19: SQL UNION-BASED INJECTION

    Phát hiện UNION injection: Nối kết quả truy vấn để trích xuất dữ liệu.
    VD: UNION SELECT username,password FROM users

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
    code="F20",
    description="SQL comment injection - --, #, /**/ (OWASP CRS 942500)",
    category="sqli",
    depends_on=None
))
class F20_SqlComment(FeatureBase):
    """
    F20: SQL COMMENT INJECTION

    Phát hiện comment injection: Cắt bỏ phần còn lại của truy vấn SQL gốc.
    VD: admin'--, admin'#, admin'/**/

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
    name="SqlQuoteImbalance",
    code="F21",
    description="SQL quote imbalance - odd number of ' or \" indicates injection",
    category="sqli",
    depends_on=None
))
class F21_SqlQuoteImbalance(FeatureBase):
    """
    F21: SQL QUOTE IMBALANCE

    Phát hiện quote không cân bằng: Payload hợp lệ luôn có quote cân bằng.
    Quote lẻ = đang cố "thoát" khỏi string SQL.
    VD: admin' (1 single quote = lẻ → injection attempt)

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

                single_count = normalized.count("'")
                double_count = normalized.count('"')

                if single_count % 2 != 0 or double_count % 2 != 0:
                    return 1.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SqlStackedQuery",
    code="F22",
    description="SQL stacked query - ; followed by DDL command (OWASP CRS)",
    category="sqli",
    depends_on=None
))
class F22_SqlStackedQuery(FeatureBase):
    """
    F22: SQL STACKED QUERY

    Phát hiện stacked query: Chèn lệnh SQL thứ 2 sau dấu chấm phẩy.
    VD: ; DROP TABLE users, ; DELETE FROM sessions

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
    code="F23",
    description="Count of SELECT statements - multiple SELECTs indicate UNION chaining",
    category="sqli",
    depends_on=None
))
class F23_SqlSelectCount(FeatureBase):
    """
    F23: SQL SELECT COUNT

    Đếm số lần xuất hiện SELECT: Nhiều SELECT = subquery injection hoặc UNION chaining.
    VD: SELECT * FROM users UNION SELECT * FROM passwords → count = 2

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


@register_feature(FeatureMetadata(
    name="SqlEncodingRatio",
    code="F24",
    description="URL-encoded character ratio - high ratio indicates WAF evasion",
    category="sqli",
    depends_on=None
))
class F24_SqlEncodingRatio(FeatureBase):
    """
    F24: SQL ENCODING RATIO

    Tỷ lệ ký tự URL-encoded trong payload RAW (trước khi normalize).
    Attacker encode payload (%27 = ', %3D = =, %20 = space) để trốn WAF.

    Công thức: (match_count * 3) / max(len(raw_text), 1)
    - Mỗi %XX chiếm 3 ký tự trong raw text

    Returns:
        Ratio [0, 1], NOT normalized
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        total_encoded_chars = 0
        total_len = 0

        for f in flows:
            for pkt in f.get_fwd_packets():
                raw = ctx.get_raw_payload(pkt)
                if not raw:
                    continue

                raw_text = raw.decode('utf-8', errors='ignore')
                total_len += len(raw_text)
                matches = _URL_ENCODED_PATTERN.findall(raw_text)
                total_encoded_chars += len(matches) * 3

        if total_len == 0:
            return 0.0

        ratio = float(total_encoded_chars) / float(total_len)
        return min(ratio, 1.0)


__all__ = [
    'F18_SqlTautology',
    'F19_SqlUnionSelect',
    'F20_SqlComment',
    'F21_SqlQuoteImbalance',
    'F22_SqlStackedQuery',
    'F23_SqlSelectCount',
    'F24_SqlEncodingRatio',
]
