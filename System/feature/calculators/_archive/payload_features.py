"""Payload-level features (F9-F14) - Refactored with plugin architecture.

Các features phân tích payload để phát hiện SQLi, XSS, obfuscation, abnormal data.

Features:
- F9: PayloadLength - Total payload size (detects abnormal/large payloads)
- F10: PayloadEntropy - Shannon entropy (detects obfuscation/encryption)
- F11: SqliKeyword - SQLi weighted scoring (keyword + pattern detection)
- F12: SqlSpecialChar - SQL special character ratio
- F13: XssKeyword - XSS weighted scoring (keyword + pattern detection)
- F14: XssSpecialChar - XSS special character ratio

Dependencies:
- FeatureContext: Caching layer for payload normalization
- PayloadContextScorer: SQLi/XSS pattern detection
- HttpPayloadExtractor: Composite payload extraction

Author: NIDS Team
Date: 2024
"""

import math
import logging
from collections import Counter
from typing import List, Optional
from core.flow_state import FlowState
from core.packet_parser import HttpPayloadExtractor
from feature.base import FeatureBase, FeatureMetadata, register_feature
from feature.payload_context import PayloadContextScorer

logger = logging.getLogger(__name__)


from feature.context import FeatureContext


@register_feature(FeatureMetadata(
    name="PayloadLength",
    code="FX9",
    description="Total payload size - detects abnormal/large payloads",
    category="payload",
    depends_on=None
))
class F9_PayloadLength(FeatureBase):
    """
    F9: PAYLOAD LENGTH
    
    Công thức: sum(all forward payload lengths)
    
    Ứng dụng:
    - Large abnormal payloads có thể chứa shellcode, buffer overflow
    - Phối hợp với entropy để phát hiện obfuscated data
    
    Returns:
        Raw length (bytes), NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate total payload length from forward packets."""
        total_length = 0
        
        # Use FeatureContext for consistent composite payload extraction
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                # Always use composite payload for consistency
                payload = ctx.get_raw_payload(pkt)
                if payload:
                    total_length += len(payload)
        
        return float(total_length)


@register_feature(FeatureMetadata(
    name="PayloadEntropy",
    code="FX10",
    description="Shannon entropy - detects obfuscation/encryption",
    category="payload",
    depends_on=None
))
class F10_PayloadEntropy(FeatureBase):
    """
    F10: PAYLOAD ENTROPY (Shannon Entropy)
    
    Công thức: -sum(p * log2(p)) cho mỗi byte value
    
    Ứng dụng:
    - High entropy (~7-8): Encrypted/compressed/obfuscated data
    - Medium entropy (~4-5): Normal text
    - Low entropy (~1-2): Repetitive data
    
    Returns:
        Raw entropy [0, 8], NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate Shannon entropy of combined forward payloads."""
        byte_counts = Counter()
        total_len = 0
        
        # Use FeatureContext for consistent composite payload extraction
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                # Always use composite payload for consistency
                payload = ctx.get_raw_payload(pkt)
                
                if payload:
                    byte_counts.update(payload)
                    total_len += len(payload)
        
        if total_len < 10:
            return 0.0
        
        # Calculate Shannon entropy from frequency distribution
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
        
        return entropy  # Range [0, 8]


@register_feature(FeatureMetadata(
    name="SqliKeyword",
    code="FX11",
    description="SQLi weighted scoring - keyword and pattern detection",
    category="payload",
    depends_on=["PayloadContextScorer"]
))
class F11_SqliKeyword(FeatureBase):
    """
    F11: SQLi WEIGHTED SCORE
    
    Tính tổng điểm SQLi dựa trên weighted scoring:
    - Keyword (union, select...): 1 điểm
    - Pattern match (union...select, or 1=1): 2 điểm
    
    Logic: Aggregate score từ tất cả packets
    
    Returns:
        Weighted score (float), NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate total SQLi score based on keyword + pattern."""
        total_score = 0.0
        
        # Use FeatureContext for caching
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                raw_payload = ctx.get_raw_payload(pkt)
                # Call scoring function with weighted scoring
                total_score += PayloadContextScorer.count_sqli_indicators(raw_payload)
        
        return total_score


@register_feature(FeatureMetadata(
    name="SqlSpecialChar",
    code="F12",
    description="SQL special character ratio",
    category="payload",
    depends_on=None
))
class F12_SqlSpecialChar(FeatureBase):
    """
    F12: SQL SPECIAL CHARACTER RATIO
    
    Tỷ lệ ký tự đặc biệt SQLi trong payload.
    Special chars: ' - ; # = --
    
    Returns:
        Ratio [0, 1], NOT normalized
    """
    
    SQLI_CHARS = set(b"'-;#=")
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate SQL special character ratio."""
        total_len = 0
        char_count = 0
        
        # Use FeatureContext for consistency
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
    name="XssKeyword",
    code="FX13",
    description="XSS weighted scoring - keyword and pattern detection",
    category="payload",
    depends_on=["PayloadContextScorer"]
))
class F13_XssKeyword(FeatureBase):
    """
    F13: XSS WEIGHTED SCORE
    
    Tính tổng điểm XSS dựa trên weighted scoring:
    - Keyword (script, alert, onerror...): 1 điểm
    - Pattern match (<script>, onerror=...): 2 điểm
    
    Logic: Aggregate score từ tất cả packets
    
    Returns:
        Weighted score (float), NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate total XSS score based on keyword + pattern."""
        total_score = 0.0
        
        # Use FeatureContext for caching
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                raw_payload = ctx.get_raw_payload(pkt)
                # Call scoring function with weighted scoring
                total_score += PayloadContextScorer.count_xss_indicators(raw_payload)
        
        return total_score


@register_feature(FeatureMetadata(
    name="XssSpecialChar",
    code="FX14",
    description="XSS special character ratio",
    category="payload",
    depends_on=None
))
class F14_XssSpecialChar(FeatureBase):
    """
    F14: XSS SPECIAL CHARACTER RATIO
    
    Tỷ lệ ký tự đặc biệt XSS trong payload.
    Special chars: < > ( ) = /
    
    Returns:
        Ratio [0, 1], NOT normalized
    """
    
    XSS_CHARS = set(b"<>()=/")
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate XSS special character ratio."""
        total_len = 0
        char_count = 0
        
        # Use FeatureContext for consistency
        context = kwargs.get('context')
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                payload = ctx.get_raw_payload(pkt)
                
                if not payload:
                    continue
                
                total_len += len(payload)
                char_count += sum(1 for b in payload if b in self.XSS_CHARS)
        
        if total_len == 0:
            return 0.0
        
        return float(char_count) / float(total_len)


# Export all features
__all__ = [
    'F9_PayloadLength',
    'F10_PayloadEntropy',
    'F11_SqliKeyword',
    'F12_SqlSpecialChar',
    'F13_XssKeyword',
    'F14_XssSpecialChar',
]
