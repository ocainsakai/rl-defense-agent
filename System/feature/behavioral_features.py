"""
feature/behavioral_features.py

Behavioral Features cho SQLi/XSS Detection.
Output: JSON format de dua vao PPO/RL.

Features do hanh vi payload, KHONG phai rule-based patterns.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Dict, Any


class BehavioralFeatureExtractor:
    """
    Trich xuat behavioral features tu payload.
    Output JSON cho PPO/RL.
    """
    
    # SQL Keywords (khong phai regex, chi de dem)
    SQL_KEYWORDS = frozenset([
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'truncate', 'alter', 'create', 'from', 'where', 'and', 'or',
        'having', 'group', 'order', 'by', 'limit', 'offset',
        'join', 'left', 'right', 'inner', 'outer', 'table', 'database',
        'exec', 'execute', 'xp_', 'sp_', 'declare', 'set', 'cast',
    ])
    
    # XSS Keywords
    XSS_KEYWORDS = frozenset([
        'script', 'javascript', 'onerror', 'onload', 'onclick',
        'onmouseover', 'onfocus', 'onblur', 'eval', 'alert',
        'document', 'cookie', 'window', 'location', 'innerhtml',
        'iframe', 'svg', 'img', 'body', 'input', 'form',
    ])
    
    # Special characters
    SPECIAL_CHARS = frozenset("'\"`;(){}[]<>=!@#$%^&*|\\/-+~`")
    
    @classmethod
    def extract(cls, payload: str) -> Dict[str, Any]:
        """
        Trich xuat tat ca behavioral features tu payload.
        
        Args:
            payload: Payload text (string)
            
        Returns:
            Dict chua tat ca features (raw values)
        """
        if not payload:
            return cls._empty_features()
        
        payload_lower = payload.lower()
        words = re.findall(r'\b\w+\b', payload_lower)
        
        features = {
            # === STRUCTURE FEATURES ===
            "length": len(payload),
            "word_count": len(words),
            "avg_word_length": sum(len(w) for w in words) / len(words) if words else 0,
            
            # === CHARACTER RATIO FEATURES ===
            "special_char_count": sum(1 for c in payload if c in cls.SPECIAL_CHARS),
            "special_char_ratio": sum(1 for c in payload if c in cls.SPECIAL_CHARS) / len(payload),
            "uppercase_ratio": sum(1 for c in payload if c.isupper()) / len(payload) if payload else 0,
            "digit_ratio": sum(1 for c in payload if c.isdigit()) / len(payload) if payload else 0,
            "whitespace_ratio": sum(1 for c in payload if c.isspace()) / len(payload) if payload else 0,
            
            # === QUOTE FEATURES ===
            "single_quote_count": payload.count("'"),
            "double_quote_count": payload.count('"'),
            "quote_imbalance": abs(payload.count("'") - payload.count('"')),
            "unclosed_quotes": payload.count("'") % 2 + payload.count('"') % 2,
            
            # === BRACKET FEATURES ===
            "parenthesis_count": payload.count("(") + payload.count(")"),
            "parenthesis_imbalance": abs(payload.count("(") - payload.count(")")),
            "bracket_count": payload.count("[") + payload.count("]") + payload.count("{") + payload.count("}"),
            "angle_bracket_count": payload.count("<") + payload.count(">"),
            
            # === SQL INDICATORS ===
            "sql_keyword_count": sum(1 for w in words if w in cls.SQL_KEYWORDS),
            "sql_keyword_density": sum(1 for w in words if w in cls.SQL_KEYWORDS) / len(words) if words else 0,
            "semicolon_count": payload.count(";"),
            "equals_count": payload.count("="),
            "dash_dash_count": payload.count("--"),
            "slash_star_count": payload.count("/*"),
            "has_comment": 1 if ("--" in payload or "/*" in payload or "#" in payload) else 0,
            
            # === XSS INDICATORS ===
            "xss_keyword_count": sum(1 for w in words if w in cls.XSS_KEYWORDS),
            "xss_keyword_density": sum(1 for w in words if w in cls.XSS_KEYWORDS) / len(words) if words else 0,
            "script_tag_count": payload_lower.count("<script") + payload_lower.count("</script"),
            "event_handler_count": len(re.findall(r'\bon\w+\s*=', payload_lower)),
            "has_javascript": 1 if "javascript:" in payload_lower else 0,
            
            # === ENTROPY & RANDOMNESS ===
            "entropy": cls._calculate_entropy(payload),
            "char_diversity": len(set(payload)) / len(payload) if payload else 0,
            
            # === ENCODING INDICATORS ===
            "url_encoded_count": len(re.findall(r'%[0-9a-fA-F]{2}', payload)),
            "hex_encoded_count": len(re.findall(r'0x[0-9a-fA-F]+', payload)),
            "unicode_encoded_count": len(re.findall(r'\\u[0-9a-fA-F]{4}', payload)),
            
            # === PATTERN INDICATORS ===
            "has_or_and": 1 if re.search(r'\b(or|and)\b', payload_lower) else 0,
            "has_union": 1 if 'union' in payload_lower else 0,
            "has_select": 1 if 'select' in payload_lower else 0,
            "numeric_comparison": len(re.findall(r'\d+\s*=\s*\d+', payload)),
            "string_comparison": len(re.findall(r'[\'\"]\w*[\'\"]?\s*=\s*[\'\"]?\w*[\'\"]]', payload)),
            
            # === EVASION INDICATORS ===
            "case_variation": cls._calculate_case_variation(payload),
            "concat_function": 1 if re.search(r'concat\s*\(', payload_lower) else 0,
            "char_function": 1 if re.search(r'char\s*\(', payload_lower) else 0,
        }
        
        return features
    
    @classmethod
    def extract_json(cls, payload: str) -> str:
        """
        Trich xuat features va tra ve JSON string.
        
        Args:
            payload: Payload text
            
        Returns:
            JSON string chua features
        """
        features = cls.extract(payload)
        return json.dumps(features)
    
    @classmethod
    def extract_vector(cls, payload: str) -> list:
        """
        Trich xuat features va tra ve list (vector).
        Phu hop cho numpy/tensor conversion.
        
        Args:
            payload: Payload text
            
        Returns:
            List cac gia tri feature (theo thu tu co dinh)
        """
        features = cls.extract(payload)
        return list(features.values())
    
    @classmethod
    def get_feature_names(cls) -> list:
        """Tra ve ten cac features theo thu tu."""
        return list(cls._empty_features().keys())
    
    @classmethod
    def _empty_features(cls) -> Dict[str, Any]:
        """Tra ve dict features rong (gia tri 0)."""
        return {
            "length": 0,
            "word_count": 0,
            "avg_word_length": 0,
            "special_char_count": 0,
            "special_char_ratio": 0,
            "uppercase_ratio": 0,
            "digit_ratio": 0,
            "whitespace_ratio": 0,
            "single_quote_count": 0,
            "double_quote_count": 0,
            "quote_imbalance": 0,
            "unclosed_quotes": 0,
            "parenthesis_count": 0,
            "parenthesis_imbalance": 0,
            "bracket_count": 0,
            "angle_bracket_count": 0,
            "sql_keyword_count": 0,
            "sql_keyword_density": 0,
            "semicolon_count": 0,
            "equals_count": 0,
            "dash_dash_count": 0,
            "slash_star_count": 0,
            "has_comment": 0,
            "xss_keyword_count": 0,
            "xss_keyword_density": 0,
            "script_tag_count": 0,
            "event_handler_count": 0,
            "has_javascript": 0,
            "entropy": 0,
            "char_diversity": 0,
            "url_encoded_count": 0,
            "hex_encoded_count": 0,
            "unicode_encoded_count": 0,
            "has_or_and": 0,
            "has_union": 0,
            "has_select": 0,
            "numeric_comparison": 0,
            "string_comparison": 0,
            "case_variation": 0,
            "concat_function": 0,
            "char_function": 0,
        }
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Tinh Shannon entropy cua text."""
        if not text:
            return 0.0
        
        freq = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    @staticmethod
    def _calculate_case_variation(text: str) -> float:
        """
        Tinh muc do tron hoa/thuong (evasion technique).
        Tra ve so cap chuyen doi case trong text.
        """
        if len(text) < 2:
            return 0
        
        variations = 0
        for i in range(1, len(text)):
            if text[i-1].isupper() != text[i].isupper():
                if text[i-1].isalpha() and text[i].isalpha():
                    variations += 1
        
        return variations
