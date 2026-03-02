"""Đặc trưng phụ SQLi — Phát hiện SQL Injection mạnh mẽ dựa trên CRS.

Đặc trưng:
- F12: SqlSpecialChar   - Tỷ lệ ký tự đặc biệt SQL (', -, ;, #, =)
- F13: CrsSquliScore    - Điểm bất thường OWASP CRS 942 (0 đến N) — phủ rộng
- F14: SqlUnionSelect   - UNION SELECT injection — kỹ thuật trích xuất dữ liệu
- F15: SqlComment       - SQL comment injection (--, #, /**/) — cắt query
- F16: SqlStackedQuery  - Stacked query injection (; DROP...) — lệnh phá hoại
- F17: SqlSelectCount   - Số lượng từ khóa SELECT — dấu hiệu UNION chaining

Nguồn CRS: REQUEST-942-APPLICATION-ATTACK-SQLI.conf (paranoia level 1)
  F13 bao gồm: tên DB, hàm SQL, blind SQLi (sleep/benchmark),
               tautology, encoding evasion, error-based, boolean-based blind...
  F14/F15/F16: dấu hiệu đơn lẻ chi tiết cho kỹ thuật rủi ro cao cụ thể.
"""

import re
import logging
from typing import List

from core.flow_state import FlowState
from core.crs_loader import load_rx_patterns, CRS_SQLI_CONF
from feature.base import FeatureBase, FeatureMetadata, register_feature
from feature.context import FeatureContext

logger = logging.getLogger(__name__)


# =============================================================================
# PATTERN — tải/compile một lần khi import module
# =============================================================================

# F13: Rule CRS 942 — Benchmark trên LSNM2024 dataset (2026-03, n=3000 normal + 2809 attack):
#   PL   Rules  TP    FP   FN    F1      FPR
#   PL1  19     1695  0    1114  0.7527  0.0000  ← zero FP nhưng bỏ sót 40% tấn công
#   PL2  50     2809  459  0     0.9245  0.1530  ← F1 tốt nhất, recall=100%  [DÙNG]
#   PL3  57     2809  520  0     0.9153  0.1733  ← thêm FP, không tốt hơn PL2
#
# Quyết định: Giữ PL2 — F1 cao nhất (0.9245), mặc dù FPR=15.3% trên benign URI.
# FPR cao chủ yếu do PL2 nhạy với các query pattern phổ biến trong dataset
# (DVWA, mutillidae navigation). Trong production thực, FPR sẽ thấp hơn.
# Chạy lại benchmark: python3 tools/benchmark_crs_pl.py
_CRS_SQLI_PATTERNS = load_rx_patterns(CRS_SQLI_CONF, paranoia_level=2)

# F14: UNION-based injection
# Pattern duy nhất bắt được cả "UNION SELECT" và "UNION ALL SELECT" (ALL < 50 chars)
_UNION_PATTERNS = [
    re.compile(r"\bunion\b[\s\S]{0,50}\bselect\b", re.IGNORECASE),
]

# F15: SQL comment injection
# --(?:\s|$|[^a-zA-Z]) bắt được admin'--&pass=x nhưng loại trừ CSS --var-name
_COMMENT_PATTERNS = [
    re.compile(r"--(?:\s|$|[^a-zA-Z])", re.IGNORECASE),
    re.compile(r"#(?![0-9a-fA-F]{3,6}\b)", re.IGNORECASE),
    re.compile(r"/\*[\s\S]*?\*/", re.IGNORECASE),
    re.compile(r"/\*![0-9]*", re.IGNORECASE),
]

# F16: Stacked query — dấu chấm phẩy theo sau là DDL/DML phá hoại hoặc lệnh hệ thống
_STACKED_QUERY_PATTERNS = [
    re.compile(
        r";\s*(?:drop|delete|insert|update|truncate|alter"
        r"|exec(?:ute)?|call|grant|revoke|create|load\s+data|shutdown|xp_\w+)\b",
        re.IGNORECASE
    ),
]

# F17: Đếm SELECT
_SELECT_PATTERN = re.compile(r"\bselect\b", re.IGNORECASE)


# =============================================================================
# CÁC LỚP ĐẶC TRƯNG
# =============================================================================

@register_feature(FeatureMetadata(
    name="SqlSpecialChar",
    code="F12",
    description="Tỷ lệ ký tự đặc biệt SQL — tỷ lệ ', -, ;, #, = trong payload",
    category="sqli",
))
class F12_SqlSpecialChar(FeatureBase):
    """
    F12: TỶ LỆ KÝ TỰ ĐẶC BIỆT SQL

    Tỷ lệ ký tự có nghĩa trong SQL so với payload chiều xuôi.
    Ký tự đặc biệt: ' - ; # =

    Returns:
        Ratio [0, 1], chưa chuẩn hóa
    """

    # Chỉ giữ ký tự hiếm trong normal web traffic: ' ; #
    # Bỏ '=' (xuất hiện trong mọi GET query string) và '-' (UUID, headers, dates)
    SQLI_CHARS = set("';#")

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        total_len = 0
        char_count = 0

        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        for f in flows:
            for pkt in f.get_fwd_packets():
                # Dùng get_normalized (URL decoded) để bắt %27 → '
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue
                total_len += len(normalized)
                char_count += sum(1 for c in normalized if c in self.SQLI_CHARS)

        if total_len == 0:
            return 0.0

        return float(char_count) / float(total_len)


@register_feature(FeatureMetadata(
    name="CrsSquliScore",
    code="F13",
    description=(
        "Điểm CRS 942 trung bình mỗi HTTP request — số rule SQLi kích hoạt / số request. "
        "Bao gồm: tên DB, hàm SQL (sleep/benchmark), tautology, "
        "encoding evasion, error-based, boolean blind. "
        "Nguồn: REQUEST-942-APPLICATION-ATTACK-SQLI.conf PL1"
    ),
    category="sqli",
))
class F13_CrsSquliScore(FeatureBase):
    """
    F13: ĐIỂM BẤT THƯỜNG CRS SQLi (bình quân mỗi request)

    Tổng số rule CRS 942 bị kích hoạt / số HTTP request trong window.
    Normalize theo request count để tránh false positive do traffic volume cao.

    Ví dụ:
      60 request bình thường × 1 rule mỗi cái = 60/60 = 1.0  (trước: 60.0)
      10 request SQLi × 4 rule mỗi cái        = 40/10 = 4.0  (phân biệt được)

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
                for _rule_id, _msg, pattern in _CRS_SQLI_PATTERNS:
                    if pattern.search(normalized):
                        total_score += 1.0

        if http_request_count == 0:
            return 0.0
        return total_score / http_request_count


@register_feature(FeatureMetadata(
    name="SqlUnionSelect",
    code="F14",
    description="UNION SELECT injection — trích xuất dữ liệu từ bảng khác",
    category="sqli",
))
class F14_SqlUnionSelect(FeatureBase):
    """
    F14: SQL UNION-BASED INJECTION

    Phát hiện UNION injection: nối kết quả truy vấn để trích xuất dữ liệu.
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
    description="SQL comment injection — --, #, /**/ cắt query gốc",
    category="sqli",
))
class F15_SqlComment(FeatureBase):
    """
    F15: SQL COMMENT INJECTION

    Phát hiện comment injection: cắt phần còn lại của truy vấn SQL gốc.
    VD: admin'--   admin'#   ' OR 1=1/*

    Note: pattern --(?:\\s|$) bắt được trường hợp cuối chuỗi (admin'--)

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
    description="Stacked query injection — dấu chấm phẩy + lệnh DDL/DML",
    category="sqli",
))
class F16_SqlStackedQuery(FeatureBase):
    """
    F16: SQL STACKED QUERY

    Phát hiện stacked query: chèn lệnh SQL thứ 2 sau dấu chấm phẩy.
    Đây là kỹ thuật nguy hiểm nhất — có thể xóa database, thêm user, ...
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
    description="Số SELECT trung bình mỗi HTTP request — nhiều SELECT biểu thị UNION chaining (F1=0.766 khi kiểm thử)",
    category="sqli",
))
class F17_SqlSelectCount(FeatureBase):
    """
    F17: SỐ SELECT TRUNG BÌNH MỖI HTTP REQUEST

    Đếm số lần xuất hiện SELECT / số HTTP request trong window.
    Normalize theo request count để nhất quán với F13 (CrsSquliScore).

    VD: SELECT * FROM users UNION SELECT * FROM passwords → 2 SELECT / 1 request = 2.0

    Returns:
        float >= 0.0 — số SELECT trung bình mỗi HTTP request
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)

        total_count = 0
        http_request_count = 0
        for f in flows:
            for pkt in f.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)
                if not normalized:
                    continue
                http_request_count += 1
                total_count += len(_SELECT_PATTERN.findall(normalized))

        if http_request_count == 0:
            return 0.0
        return float(total_count) / http_request_count


__all__ = [
    'F12_SqlSpecialChar',
    'F13_CrsSquliScore',
    'F14_SqlUnionSelect',
    'F15_SqlComment',
    'F16_SqlStackedQuery',
    'F17_SqlSelectCount',
]
