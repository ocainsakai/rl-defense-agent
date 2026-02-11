"""feature/payload_context.py

Shared payload signature scoring.

Purpose
- Provide the robust payload scanning logic (decode + anti-evasion) without
  depending on PacketWindow.
- Used by flow-based feature extraction (FlowState).

Contract
- score_payload(raw_bytes) returns one of: CONTEXT_NEUTRAL (0.0),
  CONTEXT_MALICIOUS (1.0)
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
import warnings
from collections import Counter
from urllib.parse import unquote, unquote_plus

from feature.context import PayloadNormalizer

try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False

# =============================================================================
# CONTEXT SCORES
# =============================================================================
# Chỉ có 2 giá trị: 0 (NEUTRAL) và 1 (MALICIOUS)
CONTEXT_NEUTRAL = 0.0
CONTEXT_MALICIOUS = 1.0


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
    # OWASP: Thêm = và - để bắt integer-based SQLi và comment attacks
    SUSPICIOUS_CHARS = frozenset('<>\'"`;(){}[]$&|\\/-=#,')
    
    # Suspicious bytes for RAW payload check (before normalize) - O(1) lookup
    # ASCII equivalents of SUSPICIOUS_CHARS
    SUSPICIOUS_BYTES = frozenset(b'<>\'"`;(){}[]$&|\\/-=#,')

    # -------------------------
    # Base64 and Aho-Corasick (NEW)
    # -------------------------
    
    # Base64 pattern: Valid chars, length >= 12, ends with 0-2 padding
    _B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{12,}={0,2}')

    # Aho-Corasick automaton for fast keyword matching
    _KEYWORD_AUTOMATON = None

    # Keywords for fast matching (fixed strings, no regex)
    # Based on OWASP CRS 942 + PayloadsAllTheThings
    _SQL_KEYWORDS = [
        # Basic SQL commands
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'truncate', 'alter', 'create', 'replace',
        # Functions & targets
        'information_schema', 'load_file', 'outfile', 'dumpfile',
        'benchmark', 'sleep', 'waitfor', 'pg_sleep',
        # Blind injection functions
        'ascii', 'ord', 'char', 'substring', 'mid', 'left', 'right',
        'concat', 'group_concat', 'extractvalue', 'updatexml',
        # DB specific
        'mysql', 'sqlite', 'postgres', 'mssql', 'sysdatabases',
    ]
    _XSS_KEYWORDS = [
        # Script tags
        'script', 'javascript', 'vbscript', 'livescript',
        # Event handlers (comprehensive list from PayloadsAllTheThings)
        'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur',
        'onchange', 'onsubmit', 'onmouseout', 'onmousedown', 'onmouseup',
        'onkeydown', 'onkeyup', 'onkeypress', 'ondblclick', 'oncontextmenu',
        'ontoggle', 'onanimationstart', 'onanimationend', 'ontransitionend',
        'onpointerdown', 'onpointerup', 'onpointermove', 'onwheel',
        'ontouchstart', 'ontouchend', 'ontouchmove', 'onloadstart',
        'ondrag', 'ondrop', 'onpaste', 'oncopy', 'oncut', 'oninput',
        # Dangerous tags
        'iframe', 'svg', 'object', 'embed', 'frame', 'frameset',
        'details', 'video', 'audio', 'source', 'img', 'body',
        'marquee', 'meter', 'keygen', 'isindex', 'math', 'base',
        # Dangerous functions/props
        'eval', 'alert', 'confirm', 'prompt', 'innerhtml', 'outerhtml',
        'document.cookie', 'document.write', 'document.domain',
        'window.location', 'location.href', 'srcdoc', 'autofocus',
    ]

    # -------------------------
    # Pattern definitions
    # -------------------------

    _SQL_PATTERNS = [
        # ===== UNION-Based (OWASP 942270) =====
        r"\bunion\b[\s\S]{0,50}\bselect\b",
        r"\bunion\b\s+\ball\b\s+\bselect\b",
        
        # ===== Tautologies (OWASP 942380) =====
        r"'\s{0,5}\bor\b\s{1,10}['\"]?\d",     # ' or '1
        r"'\s{0,5}\band\b\s{1,10}['\"]?\d",    # ' and '1
        r"\bor\b\s+\d+\s*=\s*\d+",              # or 1=1
        r"\bor\b\s+true\b",                      # or true
        r"\bor\b\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]\b",  # or 'a'='a'
        
        # ===== DDL Attacks (OWASP 942150) =====
        r"\bdrop\b\s{1,10}\b(?:table|database|index)\b",
        r"\bdelete\b\s+\bfrom\b",
        r"\btruncate\b\s+\btable\b",
        r"\balter\b\s+\btable\b",
        r"\binsert\b\s+\binto\b",
        r"\bupdate\b\s+\w+\s+\bset\b",
        
        # ===== Comment Attacks (OWASP 942500) =====
        r"--\s",                                 # SQL line comment
        r"#(?![0-9a-fA-F]{3,6}\b)",             # MySQL comment (not CSS hex)
        r"/\*[\s\S]*?\*/",                       # Inline comment
        r"/\*![0-9]*",                           # MySQL version comment
        
        # ===== Blind Injection (OWASP 942280) =====
        r"\b(?:benchmark|sleep|pg_sleep)\s*\(",
        r"\bwaitfor\b\s+\b(?:delay|time)\b",
        r"\b(?:ascii|ord|char)\s*\(",
        r"\b(?:substring|mid|left|right)\s*\(",
        r"\b(?:concat|group_concat)\s*\(",
        
        # ===== Error-Based (OWASP) =====
        r"\b(?:extractvalue|updatexml)\s*\(",
        
        # ===== File Operations =====
        r"\bload_file\s*\(",
        r"\binto\s+(?:out|dump)file\b",
        
        # ===== DB Detection =====
        r"\binformation_schema\b",
        r"\b(?:sys(?:databases|objects)|master\.\.)",
        
        # ===== Stacked Queries =====
        r";\s*(?:drop|delete|insert|update|truncate|alter)\b",
    ]

    _XSS_PATTERNS = [
        # ===== Script Tags (OWASP 941110) =====
        r"<\s*script",
        r"<\s*/\s*script",
        
        # ===== Protocol Handlers (OWASP 941130) =====
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data\s*:[^,]*;?base64",              # data:text/html;base64,...
        r"java\s*script\s*:",                  # java script: obfuscation
        
        # ===== Dangerous HTML5 Tags (PayloadsAllTheThings) =====
        r"<\s*(?:iframe|frame|frameset)\b",
        r"<\s*(?:object|embed|applet)\b",
        r"<\s*(?:svg|math)\b",
        r"<\s*(?:video|audio|source)\b",
        r"<\s*(?:details|marquee|meter)\b",
        r"<\s*(?:keygen|isindex|base)\b",
        r"<\s*(?:body|img|input|button|form)\b[^>]*\bon\w+\s*=", # tags with events
        
        # ===== Event Handlers (OWASP 941120 + PayloadsAllTheThings) =====
        r"\bon(?:error|load|click|mouse(?:over|out|down|up)|focus|blur)\s*=",
        r"\bon(?:change|submit|reset|select|input|invalid)\s*=",
        r"\bon(?:key(?:down|up|press)|dblclick|contextmenu)\s*=",
        r"\bon(?:toggle|animationstart|animationend|transitionend)\s*=",
        r"\bon(?:pointer(?:down|up|move|enter|leave)|wheel)\s*=",
        r"\bon(?:touch(?:start|end|move|cancel)|loadstart)\s*=",
        r"\bon(?:drag(?:start|end|over|leave|enter)?|drop|paste|copy|cut)\s*=",
        
        # ===== Auto-Execution (autofocus + onfocus) =====
        r"autofocus[^>]*onfocus\s*=",
        r"onfocus\s*=[^>]*autofocus",
        
        # ===== Dangerous JS Functions =====
        r"\balert\s*\(",
        r"\beval\s*\(",
        r"\bprompt\s*\(",
        r"\bconfirm\s*\(",
        r"\bexpression\s*\(",
        r"document\.(?:cookie|write|domain)",
        r"window\.location",
        r"(?:inner|outer)html\s*=",
        r"srcdoc\s*=",
    ]

    # NOTE: Chỉ giữ SQLi và XSS patterns theo yêu cầu
    # CMD, Traversal, Webshell, SSRF patterns đã được loại bỏ

    # NOTE: _SAFE_PATTERNS removed (was dead code - never used)

    _DANGEROUS_REGEX: list[re.Pattern] | None = None
    _SQLI_REGEX: list[re.Pattern] | None = None
    _XSS_REGEX: list[re.Pattern] | None = None
    
    # Combined Regex (single pass instead of loop)
    _COMBINED_DANGEROUS_REGEX: re.Pattern | None = None

    @classmethod
    def _init_patterns(cls) -> None:
        if cls._DANGEROUS_REGEX is not None:
            return

        # Chỉ compile SQLi + XSS patterns
        all_dangerous = (
            cls._SQL_PATTERNS
            + cls._XSS_PATTERNS
        )
        cls._DANGEROUS_REGEX = [re.compile(p, re.IGNORECASE) for p in all_dangerous]
        
        # Compile riêng cho weighted scoring (F11, F13)
        cls._SQLI_REGEX = [re.compile(p, re.IGNORECASE) for p in cls._SQL_PATTERNS]
        cls._XSS_REGEX = [re.compile(p, re.IGNORECASE) for p in cls._XSS_PATTERNS]
        
        # ✅ Combined Regex: Single pass instead of N loops
        # Uses non-capturing groups (?:...) for performance
        combined_pattern = '|'.join(f'(?:{p})' for p in all_dangerous)
        cls._COMBINED_DANGEROUS_REGEX = re.compile(combined_pattern, re.IGNORECASE)

    @classmethod
    def _has_suspicious_bytes(cls, raw_bytes: bytes) -> bool:
        """Check 1: Siêu nhanh - O(n) với O(1) set lookup per byte."""
        return any(b in cls.SUSPICIOUS_BYTES for b in raw_bytes[:1000])

    @classmethod
    def score_payload(cls, raw_bytes: bytes | None) -> float:
        """
        Score one payload bytes blob.
        
        Optimized Fail-Fast Pipeline:
        1. Check SUSPICIOUS_BYTES on raw bytes (O(n), no decode)
        2. Check binary payload (skip images/binaries)
        3. Normalize string
        4. Scan with Combined Regex (single pass)
        """
        if not raw_bytes:
            return CONTEXT_NEUTRAL

        raw_bytes = raw_bytes[: cls.MAX_PAYLOAD_TOTAL]
        
        # =====================================================================
        # CHECK 1 (Siêu nhanh): Suspicious bytes trên raw data
        # Nếu không có byte nghi ngờ nào → Check keywords trước khi skip
        # =====================================================================
        if not cls._has_suspicious_bytes(raw_bytes):
            # Fallback: Check keywords với Aho-Corasick sau khi decode
            # (Để bắt payloads như UNION+SELECT không có special chars)
            try:
                # unquote_plus imported at top of file
                decoded = unquote_plus(raw_bytes.decode('utf-8', errors='ignore'))
                cls._init_keyword_automaton()
                if not cls._scan_keywords_fast(decoded.lower()):
                    return CONTEXT_NEUTRAL  # Thực sự sạch
                # Có keyword → tiếp tục check
            except Exception:
                return CONTEXT_NEUTRAL

        # =====================================================================
        # CHECK 2 (Nhanh): Binary payload detection
        # Skip images, executables, compressed files
        # =====================================================================
        if cls._is_binary_payload(raw_bytes):
            return CONTEXT_NEUTRAL

        # =====================================================================
        # CHECK 3 & 4: Normalize + Combined Regex Scan
        # =====================================================================
        cls._init_patterns()

        # Padding attack: try stripped variant first
        if cls._detect_padding_attack(raw_bytes):
            # Try smart stripping (removes most frequent repetitive char)
            stripped = cls._smart_strip_padding(raw_bytes)
            if stripped and stripped != raw_bytes:
                normalized = PayloadNormalizer.normalize(stripped)
                if cls._scan_for_patterns_combined(normalized) == CONTEXT_MALICIOUS:
                    return CONTEXT_MALICIOUS
            
            # Also try traditional whitespace stripping
            stripped_ws = raw_bytes.strip(b" \t\n\r\x00")
            if stripped_ws and stripped_ws != raw_bytes:
                normalized = PayloadNormalizer.normalize(stripped_ws)
                if cls._scan_for_patterns_combined(normalized) == CONTEXT_MALICIOUS:
                    return CONTEXT_MALICIOUS

        # Multi-point sampling with Combined Regex
        for sample_bytes in cls._multi_point_sample(raw_bytes):
            normalized = PayloadNormalizer.normalize(sample_bytes)
            result = cls._scan_for_patterns_combined(normalized)
            if result == CONTEXT_MALICIOUS:
                return CONTEXT_MALICIOUS

        return CONTEXT_NEUTRAL

    # =========================================================================
    # WEIGHTED COUNTING FOR F11/F13 (Keywords=1pt, Patterns=2pt)
    # =========================================================================
    
    @classmethod
    def count_sqli_indicators(cls, raw_bytes: bytes | None) -> float:
        """
        Đếm weighted SQLi indicators cho Feature F11.
        
        Scoring:
        - Mỗi keyword (union, select...): 1 điểm
        - Mỗi pattern match (union...select, or 1=1): 2 điểm
        
        Returns:
            float: Tổng điểm SQLi
        """
        if not raw_bytes:
            return 0.0
        
        # Skip binary payloads
        if cls._is_binary_payload(raw_bytes):
            return 0.0
        
        # Normalize payload
        normalized = PayloadNormalizer.normalize(raw_bytes)
        if not normalized:
            return 0.0
        
        # Aho-Corasick: Check keywords trước (O(n))
        cls._init_keyword_automaton()
        found_keywords = cls._scan_keywords_fast(normalized)
        sql_keywords = [kw for kw in found_keywords if kw.lower() in 
                        [k.lower() for k in cls._SQL_KEYWORDS]]
        
        # Nếu không có keyword VÀ không có suspicious chars → skip regex
        if not sql_keywords and not cls._has_suspicious_chars(normalized):
            return 0.0
        
        score = float(len(sql_keywords))  # 1 điểm mỗi keyword
        
        # Pattern matching (2 điểm mỗi match)
        cls._init_patterns()
        if cls._SQLI_REGEX:
            for regex in cls._SQLI_REGEX:
                matches = regex.findall(normalized)
                score += len(matches) * 2.0
        
        return score
    
    @classmethod
    def count_xss_indicators(cls, raw_bytes: bytes | None) -> float:
        """
        Đếm weighted XSS indicators cho Feature F13.
        
        Scoring:
        - Mỗi keyword (script, alert, onerror...): 1 điểm
        - Mỗi pattern match (<script>, onerror=...): 2 điểm
        
        Returns:
            float: Tổng điểm XSS
        """
        if not raw_bytes:
            return 0.0
        
        # Skip binary payloads
        if cls._is_binary_payload(raw_bytes):
            return 0.0
        
        # Normalize payload
        normalized = PayloadNormalizer.normalize(raw_bytes)
        if not normalized:
            return 0.0
        
        # XSS cần ít nhất một trong: <, >, =
        if not any(c in normalized for c in "<>="):
            return 0.0
        
        # Aho-Corasick: Check keywords
        cls._init_keyword_automaton()
        found_keywords = cls._scan_keywords_fast(normalized)
        xss_keywords = [kw for kw in found_keywords if kw.lower() in 
                        [k.lower() for k in cls._XSS_KEYWORDS]]
        
        score = float(len(xss_keywords))  # 1 điểm mỗi keyword
        
        # Pattern matching (2 điểm mỗi match)
        cls._init_patterns()
        if cls._XSS_REGEX:
            for regex in cls._XSS_REGEX:
                matches = regex.findall(normalized)
                score += len(matches) * 2.0
        
        return score

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
        # Count frequency of most common byte (Counter imported at top)
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
        2. If it dominates (>60%), try to strip it carefully
        3. IMPORTANT: Don't over-strip! 
           Example: "+++union+select+++" should preserve "union+select"
        
        Solution: Only strip CONTINUOUS blocks from edges, not all occurrences
        """
        if len(raw_bytes) < 100:
            return raw_bytes
        
        # Count byte frequencies (Counter imported at top)
        byte_counts = Counter(raw_bytes)
        
        if not byte_counts:
            return raw_bytes
        
        # Find most common byte
        most_common_byte, count = byte_counts.most_common(1)[0]
        dominance_ratio = count / len(raw_bytes)
        
        # If this byte dominates (>60%), it's likely padding
        if dominance_ratio > 0.60:
            # ✅ FIX: Strip conservatively to avoid removing content
            # Instead of strip() which removes ALL occurrences from edges,
            # remove only continuous blocks of padding char
            
            padding_char = bytes([most_common_byte])
            
            # Find where continuous padding ends from left
            left_idx = 0
            for i, b in enumerate(raw_bytes):
                if bytes([b]) != padding_char:
                    left_idx = i
                    break
            
            # Find where continuous padding starts from right  
            right_idx = len(raw_bytes)
            for i in range(len(raw_bytes) - 1, -1, -1):
                if bytes([raw_bytes[i]]) != padding_char:
                    right_idx = i + 1
                    break
            
            # Extract middle content
            if left_idx < right_idx:
                stripped = raw_bytes[left_idx:right_idx]
                return stripped
        
        return raw_bytes

    @classmethod
    def _collapse_whitespace(cls, text: str) -> str:
        collapsed = re.sub(r"\s+", " ", text)
        return collapsed.strip()

    # =========================================================================
    # BASE64 DECODING
    # =========================================================================
    @classmethod
    def _try_base64_decode(cls, payload: str) -> str:
        """
        Thử decode các đoạn Base64 trong payload.
        
        Chỉ thay thế nếu nội dung decode được:
        - Phần lớn là printable (>80%)
        - Có độ dài hợp lý
        """
        for match in cls._B64_PATTERN.finditer(payload):
            candidate = match.group()
            try:
                # Thử decode Base64
                decoded_bytes = base64.b64decode(candidate)
                decoded = decoded_bytes.decode('utf-8', errors='ignore')
                
                # Chỉ thay thế nếu decode được text hợp lệ
                if len(decoded) < 3:
                    continue
                
                printable_count = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
                printable_ratio = printable_count / len(decoded)
                
                if printable_ratio > 0.80:
                    payload = payload.replace(candidate, decoded, 1)
            except Exception:
                pass
        return payload

    # =========================================================================
    # AHO-CORASICK FAST KEYWORD MATCHING
    # =========================================================================
    @classmethod
    def _init_keyword_automaton(cls) -> None:
        """Khởi tạo Aho-Corasick automaton từ keywords SQL/XSS."""
        if cls._KEYWORD_AUTOMATON is not None:
            return
        
        if not HAS_AHOCORASICK:
            return
        
        cls._KEYWORD_AUTOMATON = ahocorasick.Automaton()
        
        all_keywords = cls._SQL_KEYWORDS + cls._XSS_KEYWORDS
        for idx, kw in enumerate(all_keywords):
            cls._KEYWORD_AUTOMATON.add_word(kw.lower(), (idx, kw))
        
        cls._KEYWORD_AUTOMATON.make_automaton()

    @classmethod
    def _scan_keywords_fast(cls, payload: str) -> list:
        """
        Matching từ khóa O(n) với Aho-Corasick.
        
        Trả về: Danh sách từ khóa được tìm thấy.
        """
        if not HAS_AHOCORASICK or cls._KEYWORD_AUTOMATON is None:
            return []
        
        try:
            return [kw for _, (_, kw) in cls._KEYWORD_AUTOMATON.iter(payload.lower())]
        except Exception:
            return []

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
        """DEPRECATED: Sử dụng PayloadNormalizer.normalize() thay thế.
        
        Phương thức này được giữ lại để tương thích ngược nhưng sẽ bị xóa
        trong phiên bản tương lai. Vui lòng sử dụng:
        
            from feature.context import PayloadNormalizer
            normalized = PayloadNormalizer.normalize(raw_bytes)
        
        Args:
            raw_bytes: Payload bytes để chuẩn hóa
        
        Returns:
            Chuỗi chuẩn hóa
        """
        warnings.warn(
            "_normalize_payload is deprecated and will be removed in v2.0. "
            "Use PayloadNormalizer.normalize() from feature.context instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
        # Import ở đây để tránh circular import
        try:
            from feature.context import PayloadNormalizer
            return PayloadNormalizer.normalize(raw_bytes)
        except ImportError:
            # Fallback to old implementation nếu context chưa có
            try:
                payload = raw_bytes.decode("utf-8", errors="ignore")

                # ✅ FIX: Use unquote_plus() to decode '+' as space
                # unquote() does NOT decode '+' → ' '
                # unquote_plus() DOES decode '+' → ' ' (for URL query strings)
                # (unquote_plus imported at top of file)
                
                for _ in range(cls.MAX_DECODE_ITERATIONS):
                    decoded = unquote_plus(payload)
                    if decoded == payload:
                        break
                    payload = decoded

                # ✅ NEW: Decode Base64 encoded content
                payload = cls._try_base64_decode(payload)

                payload = html.unescape(payload)
                payload = unicodedata.normalize("NFKC", payload)
                
                # ✅ FIX: Normalize Unicode quotes to ASCII equivalents
                # Many browsers/apps use "smart quotes" that evade detection
                QUOTE_MAP = {
                    '\u2018': "'",  # '
                    '\u2019': "'",  # '
                    '\u201A': "'",  # ‚
                    '\u201B': "'",  # ‛
                    '\u201C': '"',  # "
                    '\u201D': '"',  # "
                    '\u201E': '"',  # „
                    '\u201F': '"',  # ‟
                    '\u00B4': "'",  # ´ acute accent
                    '\u2032': "'",  # ′ prime
                    '\u2033': '"',  # ″ double prime
                    '\u0060': "'",  # ` grave → single quote for consistency
                }
                for uc, asc in QUOTE_MAP.items():
                    payload = payload.replace(uc, asc)
                
                payload = payload.replace("\x00", "")
                payload = cls._collapse_whitespace(payload)
                payload = payload.lower()
                return payload
            except Exception:
                return ""

    @classmethod
    def _scan_for_patterns(cls, payload: str) -> float:
        """Legacy method - kept for backward compatibility."""
        return cls._scan_for_patterns_combined(payload)
    
    @classmethod
    def _scan_for_patterns_combined(cls, payload: str) -> float:
        """
        CHECK 4: Combined Regex - Single pass instead of N loops.
        
        Performance: O(n) instead of O(n * M) where M = number of patterns
        The combined regex '(p1)|(p2)|...' matches in one pass.
        """
        if not payload:
            return CONTEXT_NEUTRAL

        # Đã check suspicious bytes ở score_payload rồi, 
        # nhưng vẫn giữ check chars cho các entry points khác
        if not cls._has_suspicious_chars(payload):
            # Fallback: Check keywords với Aho-Corasick
            cls._init_keyword_automaton()
            if not cls._scan_keywords_fast(payload.lower()):
                return CONTEXT_NEUTRAL
            # Có keyword (union, select...) → tiếp tục check regex
        
        # Combined Regex: Single search instead of loop
        if cls._COMBINED_DANGEROUS_REGEX is not None:
            if cls._COMBINED_DANGEROUS_REGEX.search(payload):
                return CONTEXT_MALICIOUS
        else:
            # Fallback to loop if combined regex not initialized
            assert cls._DANGEROUS_REGEX is not None
            for regex in cls._DANGEROUS_REGEX:
                if regex.search(payload):
                    return CONTEXT_MALICIOUS

        return CONTEXT_NEUTRAL


def score_payload(raw_bytes: bytes | None) -> float:
    """Convenience wrapper."""
    return PayloadContextScorer.score_payload(raw_bytes)
