"""feature/payload_context.py

Shared payload signature scoring.

Purpose
- Provide the robust payload scanning logic (decode + anti-evasion) without
  depending on PacketWindow.
- Used by flow-based feature extraction (FlowState).

Contract
- score_payload(raw_bytes) returns one of: config.CONTEXT_SAFE (-1.0),
  config.CONTEXT_NEUTRAL (0.0), config.CONTEXT_MALICIOUS (1.0)
"""

from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import unquote

from config import ai_config as config


class PayloadContextScorer:
    """Robust payload signature scorer.

    This is adapted from the window-based Feature6 implementation, but designed
    to accept raw payload bytes directly.
    """

    # Max bytes processed per payload (DoS guard)
    MAX_PAYLOAD_TOTAL = 65536

    # Sampling chunk size
    SCAN_CHUNK_SIZE = 4096

    # Padding attack heuristics
    PADDING_RATIO_THRESHOLD = 0.8
    MIN_PAYLOAD_FOR_RATIO = 1000

    # URL decode recursion limit
    MAX_DECODE_ITERATIONS = 3

    # Fail-fast suspicious chars (after normalization)
    SUSPICIOUS_CHARS = frozenset('<>\'"`;(){}[]$&|\\/')

    # -------------------------
    # Pattern definitions
    # -------------------------

    _SQL_PATTERNS = [
        r"union\s{1,10}select",
        r"union\s{1,10}all\s{1,10}select",
        r"'\s{0,5}or\s{1,10}['\"0-9]",
        r"'\s{0,5}and\s{1,10}['\"0-9]",
        r";\s{0,5}drop\s{1,10}table",
        r";\s{0,5}delete\s{1,10}from",
        r"'\s{0,5};\s{0,5}--",
        r"order\s{1,10}by\s{1,10}\d{1,5}",
        r"group\s{1,10}by\s{1,10}\d{1,5}",
        r"having\s{1,10}['\"0-9]",
        r"waitfor\s{1,10}delay",
        r"benchmark\s{0,3}\(",
        r"sleep\s{0,3}\(",
        r"load_file\s{0,3}\(",
        r"into\s{1,10}outfile",
        r"into\s{1,10}dumpfile",
    ]

    _XSS_PATTERNS = [
        r"<script",
        r"javascript\s{0,3}:",
        r"on(?:error|load|click|mouse|focus|blur|change|submit)\s{0,3}=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"<svg\s{0,5}onload",
        r"<img\s{1,10}src\s{0,3}=\s{0,3}[\"']?javascript:",
        r"expression\s{0,3}\(",
        r"vbscript\s{0,3}:",
        r"<body\s{1,10}onload",
        r"<input\s{1,10}onfocus",
    ]

    _CMD_PATTERNS = [
        r";\s{0,3}cat\s",
        r";\s{0,3}ls\s",
        r";\s{0,3}id\s{0,3}$",
        r";\s{0,3}whoami",
        r";\s{0,3}uname",
        r"\|\s{0,3}cat\s",
        r"\|\s{0,3}sh\s{0,3}$",
        r"\|\s{0,3}bash",
        r"`[^`]{1,100}`",
        r"\$\([^)]{1,100}\)",
        r"\$\{[^}]{1,50}\}",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self",
        r"c:\\windows\\system32",
        r"cmd\.exe",
        r"powershell",
        r"certutil\s{0,5}-urlcache",
    ]

    _TRAVERSAL_PATTERNS = [
        r"\.\.[/\\]",
        r"\.\.%2[fF]",
        r"\.\.%5[cC]",
        r"%2e%2e[/\\%]",
        r"\.\.%c0%af",
        r"\.\.%c1%9c",
    ]

    _WEBSHELL_PATTERNS = [
        r"<\?php",
        r"<\?=",
        r"eval\s{0,3}\(",
        r"base64_decode\s{0,3}\(",
        r"gzinflate\s{0,3}\(",
        r"gzuncompress\s{0,3}\(",
        r"str_rot13\s{0,3}\(",
        r"system\s{0,3}\(",
        r"exec\s{0,3}\(",
        r"passthru\s{0,3}\(",
        r"shell_exec\s{0,3}\(",
        r"popen\s{0,3}\(",
        r"proc_open\s{0,3}\(",
        r"assert\s{0,3}\(",
        r"preg_replace\s{0,3}\(.{0,20}/e",
        r"create_function\s{0,3}\(",
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s{0,3}\[",
    ]

    _SSRF_PATTERNS = [
        r"file://",
        r"gopher://",
        r"dict://",
        r"ftp://",
        r"ldap://",
        r"<!entity\s",
        r"<!doctype\s{1,10}[^>]{0,50}entity",
        r"xmlns:xi\s{0,3}=",
    ]

    _SAFE_PATTERNS = [
        r"^post\s{1,5}/upload",
        r"content-type:\s{0,5}image/",
        r"content-type:\s{0,5}application/json",
        r"content-type:\s{0,5}text/plain",
        r"content-type:\s{0,5}multipart/form-data",
    ]

    _DANGEROUS_REGEX: list[re.Pattern] | None = None
    _SAFE_REGEX: list[re.Pattern] | None = None

    @classmethod
    def _init_patterns(cls) -> None:
        if cls._DANGEROUS_REGEX is not None and cls._SAFE_REGEX is not None:
            return

        all_dangerous = (
            cls._SQL_PATTERNS
            + cls._XSS_PATTERNS
            + cls._CMD_PATTERNS
            + cls._TRAVERSAL_PATTERNS
            + cls._WEBSHELL_PATTERNS
            + cls._SSRF_PATTERNS
        )
        cls._DANGEROUS_REGEX = [re.compile(p, re.IGNORECASE) for p in all_dangerous]
        cls._SAFE_REGEX = [re.compile(p, re.IGNORECASE) for p in cls._SAFE_PATTERNS]

    @classmethod
    def score_payload(cls, raw_bytes: bytes | None) -> float:
        """Score one payload bytes blob."""
        if not raw_bytes:
            return config.CONTEXT_NEUTRAL

        cls._init_patterns()

        raw_bytes = raw_bytes[: cls.MAX_PAYLOAD_TOTAL]

        if cls._is_binary_payload(raw_bytes):
            return config.CONTEXT_NEUTRAL

        # Padding attack: try stripped variant first
        if cls._detect_padding_attack(raw_bytes):
            # Try smart stripping (removes most frequent repetitive char)
            stripped = cls._smart_strip_padding(raw_bytes)
            if stripped and stripped != raw_bytes:
                normalized = cls._normalize_payload(stripped)
                if cls._scan_for_patterns(normalized) == config.CONTEXT_MALICIOUS:
                    return config.CONTEXT_MALICIOUS
            
            # Also try traditional whitespace stripping
            stripped_ws = raw_bytes.strip(b" \t\n\r\x00")
            if stripped_ws and stripped_ws != raw_bytes:
                normalized = cls._normalize_payload(stripped_ws)
                if cls._scan_for_patterns(normalized) == config.CONTEXT_MALICIOUS:
                    return config.CONTEXT_MALICIOUS

        # Multi-point sampling
        has_safe = False
        for sample_bytes in cls._multi_point_sample(raw_bytes):
            normalized = cls._normalize_payload(sample_bytes)
            result = cls._scan_for_patterns(normalized)
            if result == config.CONTEXT_MALICIOUS:
                return config.CONTEXT_MALICIOUS
            if result == config.CONTEXT_SAFE:
                has_safe = True

        if has_safe:
            return config.CONTEXT_SAFE
        return config.CONTEXT_NEUTRAL

    @classmethod
    def _has_suspicious_chars(cls, sample: str) -> bool:
        return any(c in cls.SUSPICIOUS_CHARS for c in sample)

    @classmethod
    def _is_binary_payload(cls, raw_bytes: bytes) -> bool:
        if len(raw_bytes) < 100:
            return False

        sample = raw_bytes[:1000]
        printable_count = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        ratio = printable_count / len(sample)
        return ratio < 0.70

    @classmethod
    def _detect_padding_attack(cls, raw_bytes: bytes) -> bool:
        """Detect padding attacks using ANY repetitive character.
        
        Strategy:
        1. Check for traditional whitespace padding
        2. Check for low character diversity (repetitive chars)
        3. Check if most frequent char dominates the payload
        """
        if len(raw_bytes) < cls.MIN_PAYLOAD_FOR_RATIO:
            return False

        # Check 1: Traditional whitespace padding
        padding_chars = {ord(" "), ord("\t"), ord("\n"), ord("\r"), 0, 11, 12}
        padding_count = sum(1 for b in raw_bytes if b in padding_chars)
        ratio = padding_count / len(raw_bytes)
        if ratio > cls.PADDING_RATIO_THRESHOLD:
            return True

        # Check 2: Low diversity (very few unique chars)
        sample = raw_bytes[:100]
        if len(set(sample)) <= 3:
            return True
        
        # Check 3: Single character dominance (e.g., lots of '+' or 'a')
        # Count frequency of most common byte
        from collections import Counter
        byte_counts = Counter(raw_bytes)
        if byte_counts:
            most_common_byte, count = byte_counts.most_common(1)[0]
            dominance_ratio = count / len(raw_bytes)
            # If any single byte appears in >70% of payload, likely padding
            if dominance_ratio > 0.70:
                return True

        return False

    @classmethod
    def _smart_strip_padding(cls, raw_bytes: bytes) -> bytes:
        """Smart stripping that removes repetitive padding chars.
        
        This handles padding attacks using ANY character ('+', 'a', etc.),
        not just whitespace.
        
        Strategy:
        1. Find the most frequent byte in the payload
        2. If it dominates (>60%), strip it from edges
        3. Return the core content
        """
        if len(raw_bytes) < 100:
            return raw_bytes
        
        # Count byte frequencies
        from collections import Counter
        byte_counts = Counter(raw_bytes)
        
        if not byte_counts:
            return raw_bytes
        
        # Find most common byte
        most_common_byte, count = byte_counts.most_common(1)[0]
        dominance_ratio = count / len(raw_bytes)
        
        # If this byte dominates (>60%), it's likely padding
        if dominance_ratio > 0.60:
            # Strip this byte from both ends
            padding_char = bytes([most_common_byte])
            stripped = raw_bytes.strip(padding_char)
            return stripped
        
        return raw_bytes

    @classmethod
    def _collapse_whitespace(cls, text: str) -> str:
        collapsed = re.sub(r"\s+", " ", text)
        return collapsed.strip()

    @classmethod
    def _multi_point_sample(cls, raw_bytes: bytes) -> list[bytes]:
        total_len = len(raw_bytes)
        chunk = cls.SCAN_CHUNK_SIZE

        samples: list[bytes] = [raw_bytes[:chunk]]

        if total_len > chunk * 2:
            mid_start = (total_len // 2) - (chunk // 2)
            mid_end = mid_start + chunk
            samples.append(raw_bytes[mid_start:mid_end])

        if total_len > chunk:
            samples.append(raw_bytes[-chunk:])

        stripped = raw_bytes.lstrip(b" \t\n\r\x00")
        if stripped and stripped != raw_bytes[: len(stripped)]:
            samples.append(stripped[:chunk])

        return samples

    @classmethod
    def _normalize_payload(cls, raw_bytes: bytes) -> str:
        try:
            payload = raw_bytes.decode("utf-8", errors="ignore")

            for _ in range(cls.MAX_DECODE_ITERATIONS):
                decoded = unquote(payload)
                if decoded == payload:
                    break
                payload = decoded

            payload = html.unescape(payload)
            payload = unicodedata.normalize("NFKC", payload)
            payload = payload.replace("\x00", "")
            payload = cls._collapse_whitespace(payload)
            payload = payload.lower()
            return payload
        except Exception:
            return ""

    @classmethod
    def _scan_for_patterns(cls, payload: str) -> float:
        if not payload:
            return config.CONTEXT_NEUTRAL

        if not cls._has_suspicious_chars(payload):
            return config.CONTEXT_NEUTRAL

        assert cls._DANGEROUS_REGEX is not None
        assert cls._SAFE_REGEX is not None

        for regex in cls._DANGEROUS_REGEX:
            if regex.search(payload):
                return config.CONTEXT_MALICIOUS

        for regex in cls._SAFE_REGEX:
            if regex.search(payload):
                return config.CONTEXT_SAFE

        return config.CONTEXT_NEUTRAL


def score_payload(raw_bytes: bytes | None) -> float:
    """Convenience wrapper."""
    return PayloadContextScorer.score_payload(raw_bytes)
