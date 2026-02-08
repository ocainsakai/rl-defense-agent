# feature/payload_features.py
"""
Payload-based Features cho SQLi/XSS Detection.
20 Features tập trung vào phân tích nội dung payload.

Sử dụng:
    from feature.payload_features import PayloadFeatureExtractor
    
    extractor = PayloadFeatureExtractor()
    features = extractor.extract_all(payload_bytes)
    # features = dict với 20 features
"""

import math
import re
import json
from collections import Counter
from typing import Dict, Any, List, Optional
from urllib.parse import unquote_plus


class PayloadFeatureExtractor:
    """Extract 20 payload-based features for SQLi/XSS detection."""
    
    # SQL Keywords (từ dataset analysis)
    SQL_KEYWORDS = [
        'select', 'union', 'from', 'where', 'and', 'or', 
        'insert', 'update', 'delete', 'drop', 'truncate',
        'create', 'alter', 'exec', 'table', 'declare',
        'sleep', 'benchmark', 'waitfor', 'version',
        'concat', 'substring', 'ascii', 'char', 'cast', 'like'
    ]
    
    # XSS Keywords (URI schemes, risky tags, sinks)
    XSS_KEYWORDS = [
        # URI Schemes
        'javascript', 'vbscript', 'data', 'file',
        # Tags (dangerous ones)
        'script', 'iframe', 'object', 'embed', 'applet', 
        'base', 'form', 'meta', 'link', 'style', 'svg', 'math',
        # DOM Sinks & JS Functions
        'document.cookie', 'document.write', 'window.location', 
        'eval', 'setTimeout', 'setInterval', 'alert', 'prompt', 'confirm'
    ]
    
    # Special chars - Expanded for XSS
    SQL_SPECIAL = set("'\"()-;=#/*$|+@%&")
    XSS_SPECIAL = set("<>()=\"'/;:!{}[]`")  # Added :!{}[]`
    
    def __init__(self):
        # Pre-compile regex patterns
        self._sql_kw_pattern = re.compile(
            r'\b(' + '|'.join(self.SQL_KEYWORDS) + r')\b', 
            re.IGNORECASE
        )
        # XSS Keyword Pattern
        self._xss_kw_pattern = re.compile(
            r'\b(' + '|'.join(map(re.escape, self.XSS_KEYWORDS)) + r')\b', 
            re.IGNORECASE
        )
        
        # Enhanced Event Handler Pattern (catch onX=...)
        self._xss_event_pattern = re.compile(
            r'\bon\w+\s*=',
            re.IGNORECASE
        )
        
        # Structure Pattern (validish HTML/JS structure)
        # Matches: <tag ..., javascript:..., data:..., expression(...)
        self._xss_structure_pattern = re.compile(
            r'<\s*[a-zA-Z]+|'  # Tag open
            r'(?:javascript|vbscript|data):|'  # URI schemes
            r'expression\s*\(|'  # CSS expression
            r'url\s*\(',         # CSS url
            re.IGNORECASE
        )
        
        self._numeric_compare = re.compile(r'\b(\d+)\s*=\s*\1\b')  # 1=1, 0=0
        self._url_encoded = re.compile(r'%[0-9A-Fa-f]{2}')
        self._case_mix = re.compile(r'[a-z][A-Z]|[A-Z][a-z]')
    
    def extract_all(self, payload: bytes) -> Dict[str, float]:
        """
        Extract all 20 features from payload bytes.
        
        Returns:
            Dict với 20 features, tất cả là float
        """
        if not payload:
            return self._empty_features()
        
        # Normalize payload
        try:
            text = payload.decode('utf-8', errors='ignore')
            decoded = unquote_plus(text)
        except Exception:
            text = ""
            decoded = ""
        
        length = len(decoded) if decoded else 1  # Avoid div by zero
        
        return {
            # 1-2: Quote features
            'quote_count': self._quote_count(decoded),
            'quote_imbalance': self._quote_imbalance(decoded),
            
            # 3: Special char ratio
            'special_char_ratio': self._special_char_ratio(decoded, length),
            
            # 4-5: SQL keyword features
            'sql_keyword_count': self._sql_keyword_count(decoded),
            'sql_keyword_density': self._sql_keyword_density(decoded),
            
            # 6-7: SQL terminators
            'comment_indicator': self._comment_indicator(decoded),
            'semicolon_count': float(decoded.count(';')),
            
            # 8-9: Comparison features
            'equals_count': float(decoded.count('=')),
            'numeric_comparison': self._numeric_comparison(decoded),
            
            # 10-11: Basic stats
            'entropy': self._entropy(payload),
            'length': float(len(payload)),
            
            # 12-13: Case features
            'uppercase_ratio': self._uppercase_ratio(decoded),
            'case_variation': self._case_variation(decoded),
            
            # 14-15: Encoding/Whitespace
            'encoding_layers': self._encoding_layers(text),
            'whitespace_ratio': self._whitespace_ratio(decoded, length),
            
            # 16-17: XSS specific
            'tag_count': self._tag_count(decoded),
            'event_handler_count': self._event_handler_count(decoded),
            'xss_keyword_count': self._xss_keyword_count(decoded),
            'xss_structure_score': self._xss_structure_score(decoded),
            
            # 18-20: Structure features
            'parenthesis_count': self._parenthesis_count(decoded),
            'or_and_count': self._or_and_count(decoded),
            'avg_word_length': self._avg_word_length(decoded),
            'digit_ratio': self._digit_ratio(decoded, length),
        }

    def extract_behavioral_json(self, payload: str) -> str:
        """
        Extract features and return JSON string (for RL/PPO agents).
        Matches the output format of the old BehavioralFeatureExtractor.
        """
        # Convert string to bytes for internal processing
        if isinstance(payload, str):
            payload_bytes = payload.encode('utf-8', errors='ignore')
        else:
            payload_bytes = payload
            payload = payload.decode('utf-8', errors='ignore')
            
        features = self.extract_all(payload_bytes)
        
        # Add raw metrics that are specific to RL needs (integers/counts)
        # Note: extract_all returns floats, RL might expect some ints, but JSON handles both.
        # We extend the standardized features with specific raw counts.
        raw_metrics = self._extract_raw_metrics(payload, features)
        
        return json.dumps(raw_metrics)

    def _extract_raw_metrics(self, text: str, standard_features: Dict[str, float]) -> Dict[str, Any]:
        """Combine standard features with raw counts for RL."""
        lower_text = text.lower()
        
        # Base features from standard extraction
        metrics = standard_features.copy()
        
        # Add brackets raw counts
        metrics.update(self._count_brackets(text))
        
        # Add explicit encoding counts
        metrics['url_encoded_count'] = len(re.findall(r'%[0-9a-fA-F]{2}', text))
        metrics['hex_encoded_count'] = len(re.findall(r'0x[0-9a-fA-F]+', text))
        metrics['unicode_encoded_count'] = len(re.findall(r'\\u[0-9a-fA-F]{4}', text))
        
        # Add specific keyword boolean flags (often used in RL state)
        metrics['has_javascript'] = 1 if 'javascript:' in lower_text else 0
        metrics['has_union'] = 1 if 'union' in lower_text else 0
        metrics['has_select'] = 1 if 'select' in lower_text else 0
        metrics['has_or_and'] = 1 if 'or' in lower_text or 'and' in lower_text else 0
        
        # Add derived metrics
        metrics['word_count'] = len(text.split())
        
        return metrics

    def _count_brackets(self, text: str) -> Dict[str, int]:
        """Count specific bracket types."""
        return {
            'single_quote_count': text.count("'"),
            'double_quote_count': text.count('"'),
            'bracket_count': text.count('[') + text.count(']') + text.count('{') + text.count('}'),
            'angle_bracket_count': text.count('<') + text.count('>'),
        }
    
    def _empty_features(self) -> Dict[str, float]:
        """Return zero-initialized features dict."""
        return {
            'quote_count': 0.0, 'quote_imbalance': 0.0,
            'special_char_ratio': 0.0, 'sql_keyword_count': 0.0,
            'sql_keyword_density': 0.0, 'comment_indicator': 0.0,
            'semicolon_count': 0.0, 'equals_count': 0.0,
            'numeric_comparison': 0.0, 'entropy': 0.0,
            'length': 0.0, 'uppercase_ratio': 0.0,
            'case_variation': 0.0, 'encoding_layers': 0.0,
            'whitespace_ratio': 0.0, 'tag_count': 0.0,
            'event_handler_count': 0.0, 'xss_keyword_count': 0.0,
            'xss_structure_score': 0.0, 'parenthesis_count': 0.0,
            'or_and_count': 0.0, 'avg_word_length': 0.0, 'digit_ratio': 0.0,
        }
    
    # =========================================================================
    # Feature Implementations
    # =========================================================================
    
    def _quote_count(self, text: str) -> float:
        """F1: Count quotes."""
        return float(text.count("'") + text.count('"'))
    
    def _quote_imbalance(self, text: str) -> float:
        """F2: Unbalanced quotes (odd count = suspicious)."""
        single = text.count("'") % 2
        double = text.count('"') % 2
        return float(single + double)
    
    def _special_char_ratio(self, text: str, length: int) -> float:
        """F3: Ratio of special characters."""
        special = sum(1 for c in text if c in self.SQL_SPECIAL | self.XSS_SPECIAL)
        return special / length if length > 0 else 0.0
    
    def _sql_keyword_count(self, text: str) -> float:
        """F4: Count SQL keywords."""
        matches = self._sql_kw_pattern.findall(text)
        return float(len(matches))
    
    def _sql_keyword_density(self, text: str) -> float:
        """F5: SQL keywords / total words."""
        words = text.split()
        if not words:
            return 0.0
        kw_count = len(self._sql_kw_pattern.findall(text))
        return kw_count / len(words)
    
    def _comment_indicator(self, text: str) -> float:
        """F6: Has SQL comment markers."""
        if '--' in text or '/*' in text or '*/' in text or '#' in text:
            return 1.0
        return 0.0
    
    def _numeric_comparison(self, text: str) -> float:
        """F9: Has 1=1, 0=0 patterns."""
        if self._numeric_compare.search(text):
            return 1.0
        # Also check common patterns
        if "'1'='1'" in text or "'a'='a'" in text or "1=1" in text:
            return 1.0
        return 0.0
    
    def _entropy(self, payload: bytes) -> float:
        """F10: Shannon entropy."""
        if len(payload) < 10:
            return 0.0
        counts = Counter(payload)
        total = len(payload)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy
    
    def _uppercase_ratio(self, text: str) -> float:
        """F12: Uppercase / alpha chars."""
        alpha = sum(1 for c in text if c.isalpha())
        if alpha == 0:
            return 0.0
        upper = sum(1 for c in text if c.isupper())
        return upper / alpha
    
    def _case_variation(self, text: str) -> float:
        """F13: Mixed case detection (sCrIpT pattern)."""
        matches = self._case_mix.findall(text)
        return float(len(matches))
    
    def _encoding_layers(self, text: str) -> float:
        """F14: Count URL-encoded sequences (%XX)."""
        matches = self._url_encoded.findall(text)
        return float(len(matches))
    
    def _whitespace_ratio(self, text: str, length: int) -> float:
        """F15: Whitespace / length."""
        spaces = sum(1 for c in text if c.isspace())
        return spaces / length if length > 0 else 0.0
    
    def _tag_count(self, text: str) -> float:
        """F16: HTML tag indicators."""
        return float(text.count('<') + text.count('>'))
    
    def _event_handler_count(self, text: str) -> float:
        """F17: XSS event handlers (onX=)."""
        matches = self._xss_event_pattern.findall(text)
        return float(len(matches))

    def _xss_keyword_count(self, text: str) -> float:
        """New: Count XSS-specific keywords (tags, schemes, sinks)."""
        matches = self._xss_kw_pattern.findall(text)
        return float(len(matches))

    def _xss_structure_score(self, text: str) -> float:
        """New: Detect structural XSS patterns (1.0 if found, else 0.0)."""
        if self._xss_structure_pattern.search(text):
            return 1.0
        return 0.0
    
    def _parenthesis_count(self, text: str) -> float:
        """F18: Count parentheses (function calls)."""
        return float(text.count('(') + text.count(')'))
    
    def _or_and_count(self, text: str) -> float:
        """F19: Count OR/AND keywords."""
        lower = text.lower()
        # Use word boundary to avoid matching "normal", "android", etc.
        or_count = len(re.findall(r'\bor\b', lower))
        and_count = len(re.findall(r'\band\b', lower))
        return float(or_count + and_count)
    
    def _avg_word_length(self, text: str) -> float:
        """F20: Average word length."""
        words = text.split()
        if not words:
            return 0.0
        total_chars = sum(len(w) for w in words)
        return total_chars / len(words)
    
    def _digit_ratio(self, text: str, length: int) -> float:
        """F21: Ratio of digits (char() obfuscation, hex)."""
        digits = sum(1 for c in text if c.isdigit())
        return digits / length if length > 0 else 0.0
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    @staticmethod
    def get_feature_names() -> list:
        """Return list of 20 feature names."""
        return [
            'quote_count', 'quote_imbalance', 'special_char_ratio',
            'sql_keyword_count', 'sql_keyword_density', 'comment_indicator',
            'semicolon_count', 'equals_count', 'numeric_comparison',
            'entropy', 'length', 'uppercase_ratio', 'case_variation',
            'encoding_layers', 'whitespace_ratio', 'tag_count',
            'event_handler_count', 'xss_keyword_count', 'xss_structure_score',
            'parenthesis_count', 'or_and_count',
            'avg_word_length', 'digit_ratio'
        ]
    
    def extract_vector(self, payload: bytes) -> list:
        """Extract features as list (for ML models)."""
        features = self.extract_all(payload)
        return [features[name] for name in self.get_feature_names()]


# =============================================================================
# Quick Test
# =============================================================================

if __name__ == "__main__":
    extractor = PayloadFeatureExtractor()
    
    # Test cases
    test_payloads = [
        b"normal search query",
        b"' OR 1=1 --",
        b"<script>alert(1)</script>",
        b"admin' UNION SELECT * FROM users --",
        b"%27%20OR%201%3D1%20--",  # URL encoded
        b"<img src=x onerror=alert(1)>",
        b"'; DROP TABLE users; --",
        b"<sCrIpT>alert('XSS')</sCrIpT>",  # Mixed case
    ]
    
    print("=" * 80)
    print("PAYLOAD FEATURE EXTRACTION TEST")
    print("=" * 80)
    
    for payload in test_payloads:
        print(f"\n📦 Payload: {payload[:50]}...")
        features = extractor.extract_all(payload)
        
        # Show non-zero features
        non_zero = {k: v for k, v in features.items() if v > 0}
        for name, value in non_zero.items():
            print(f"   {name}: {value:.2f}")
