"""feature/payload_context.py

Chấm điểm chữ ký payload dùng chung.

Mục đích
- Cung cấp logic quét payload mạnh mẽ (decode + chống né tránh) mà không
  phụ thuộc vào PacketWindow.
- Được sử dụng bởi trích xuất feature dựa trên flow (FlowState).

Giao ước
- score_payload(raw_bytes) trả về một trong: CONTEXT_NEUTRAL (0.0),
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
# ĐIỂM NGỮ CẢNH
# =============================================================================
# Chỉ có 2 giá trị: 0 (NEUTRAL) và 1 (MALICIOUS)
CONTEXT_NEUTRAL = 0.0
CONTEXT_MALICIOUS = 1.0


class PayloadContextScorer:
    """Bộ chấm điểm chữ ký payload mạnh mẽ.

    Được chuyển đổi từ triển khai Feature6 dựa trên window, nhưng thiết kế
    để nhận trực tiếp payload bytes thô.
    """

    # Số byte tối đa xử lý mỗi payload (chống DoS)
    MAX_PAYLOAD_TOTAL = 65536

    # Kích thước chunk lấy mẫu
    SCAN_CHUNK_SIZE = 4096

    # Ngưỡng phát hiện tấn công padding
    PADDING_RATIO_THRESHOLD = 0.8
    MIN_PAYLOAD_FOR_RATIO = 1000

    # Giới hạn đệ quy URL decode
    MAX_DECODE_ITERATIONS = 3

    # Ký tự nghi ngờ để kiểm tra nhanh (sau khi normalize)
    # OWASP: Thêm = và - để bắt integer-based SQLi và comment attacks
    SUSPICIOUS_CHARS = frozenset('<>\'"`;(){}[]$&|\\/-=#,')

    # Byte nghi ngờ cho kiểm tra payload THÔ (trước normalize) - tra cứu O(1)
    # Tương đương ASCII của SUSPICIOUS_CHARS
    SUSPICIOUS_BYTES = frozenset(b'<>\'"`;(){}[]$&|\\/-=#,')

    # -------------------------
    # Base64 và Aho-Corasick
    # -------------------------

    # Pattern Base64: Ký tự hợp lệ, độ dài >= 12, kết thúc bằng 0-2 padding
    _B64_PATTERN = re.compile(r'[A-Za-z0-9+/]{12,}={0,2}')

    # Aho-Corasick automaton cho matching từ khóa nhanh
    _KEYWORD_AUTOMATON = None

    # Từ khóa cho matching nhanh (chuỗi cố định, không dùng regex)
    # Dựa trên OWASP CRS 942 + PayloadsAllTheThings
    _SQL_KEYWORDS = [
        # Lệnh SQL cơ bản
        'select', 'union', 'insert', 'update', 'delete', 'drop',
        'truncate', 'alter', 'create', 'replace',
        # Hàm & mục tiêu
        'information_schema', 'load_file', 'outfile', 'dumpfile',
        'benchmark', 'sleep', 'waitfor', 'pg_sleep',
        # Hàm blind injection
        'ascii', 'ord', 'char', 'substring', 'mid', 'left', 'right',
        'concat', 'group_concat', 'extractvalue', 'updatexml',
        # Riêng theo DB
        'mysql', 'sqlite', 'postgres', 'mssql', 'sysdatabases',
    ]
    _XSS_KEYWORDS = [
        # Thẻ script
        'script', 'javascript', 'vbscript', 'livescript',
        # Event handler (danh sách đầy đủ từ PayloadsAllTheThings)
        'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur',
        'onchange', 'onsubmit', 'onmouseout', 'onmousedown', 'onmouseup',
        'onkeydown', 'onkeyup', 'onkeypress', 'ondblclick', 'oncontextmenu',
        'ontoggle', 'onanimationstart', 'onanimationend', 'ontransitionend',
        'onpointerdown', 'onpointerup', 'onpointermove', 'onwheel',
        'ontouchstart', 'ontouchend', 'ontouchmove', 'onloadstart',
        'ondrag', 'ondrop', 'onpaste', 'oncopy', 'oncut', 'oninput',
        # Thẻ nguy hiểm
        'iframe', 'svg', 'object', 'embed', 'frame', 'frameset',
        'details', 'video', 'audio', 'source', 'img', 'body',
        'marquee', 'meter', 'keygen', 'isindex', 'math', 'base',
        # Hàm/thuộc tính nguy hiểm
        'eval', 'alert', 'confirm', 'prompt', 'innerhtml', 'outerhtml',
        'document.cookie', 'document.write', 'document.domain',
        'window.location', 'location.href', 'srcdoc', 'autofocus',
    ]

    # -------------------------
    # Định nghĩa pattern
    # -------------------------

    _SQL_PATTERNS = [
        # ===== UNION-Based (OWASP 942270) =====
        r"\bunion\b[\s\S]{0,50}\bselect\b",
        r"\bunion\b\s+\ball\b\s+\bselect\b",

        # ===== Tautology (OWASP 942380) =====
        r"'\s{0,5}\bor\b\s{1,10}['\"]?\d",     # ' or '1
        r"'\s{0,5}\band\b\s{1,10}['\"]?\d",    # ' and '1
        r"\bor\b\s+\d+\s*=\s*\d+",              # or 1=1
        r"\bor\b\s+true\b",                      # or true
        r"\bor\b\s+['\"]\w+['\"]\s*=\s*['\"]\w+['\"]\b",  # or 'a'='a'

        # ===== Tấn công DDL (OWASP 942150) =====
        r"\bdrop\b\s{1,10}\b(?:table|database|index)\b",
        r"\bdelete\b\s+\bfrom\b",
        r"\btruncate\b\s+\btable\b",
        r"\balter\b\s+\btable\b",
        r"\binsert\b\s+\binto\b",
        r"\bupdate\b\s+\w+\s+\bset\b",

        # ===== Tấn công Comment (OWASP 942500) =====
        r"--\s",                                 # SQL line comment
        r"#(?![0-9a-fA-F]{3,6}\b)",             # MySQL comment (không phải CSS hex)
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

        # ===== Thao tác file =====
        r"\bload_file\s*\(",
        r"\binto\s+(?:out|dump)file\b",

        # ===== Phát hiện DB =====
        r"\binformation_schema\b",
        r"\b(?:sys(?:databases|objects)|master\.\.)",

        # ===== Stacked Query =====
        r";\s*(?:drop|delete|insert|update|truncate|alter)\b",
    ]

    _XSS_PATTERNS = [
        # ===== Thẻ Script (OWASP 941110) =====
        r"<\s*script",
        r"<\s*/\s*script",

        # ===== Xử lý Protocol (OWASP 941130) =====
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data\s*:[^,]*;?base64",              # data:text/html;base64,...
        r"java\s*script\s*:",                  # java script: obfuscation

        # ===== Thẻ HTML5 nguy hiểm (PayloadsAllTheThings) =====
        r"<\s*(?:iframe|frame|frameset)\b",
        r"<\s*(?:object|embed|applet)\b",
        r"<\s*(?:svg|math)\b",
        r"<\s*(?:video|audio|source)\b",
        r"<\s*(?:details|marquee|meter)\b",
        r"<\s*(?:keygen|isindex|base)\b",
        r"<\s*(?:body|img|input|button|form)\b[^>]*\bon\w+\s*=", # thẻ với event

        # ===== Event Handler (OWASP 941120 + PayloadsAllTheThings) =====
        r"\bon(?:error|load|click|mouse(?:over|out|down|up)|focus|blur)\s*=",
        r"\bon(?:change|submit|reset|select|input|invalid)\s*=",
        r"\bon(?:key(?:down|up|press)|dblclick|contextmenu)\s*=",
        r"\bon(?:toggle|animationstart|animationend|transitionend)\s*=",
        r"\bon(?:pointer(?:down|up|move|enter|leave)|wheel)\s*=",
        r"\bon(?:touch(?:start|end|move|cancel)|loadstart)\s*=",
        r"\bon(?:drag(?:start|end|over|leave|enter)?|drop|paste|copy|cut)\s*=",

        # ===== Tự động thực thi (autofocus + onfocus) =====
        r"autofocus[^>]*onfocus\s*=",
        r"onfocus\s*=[^>]*autofocus",

        # ===== Hàm JS nguy hiểm =====
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

    # Chỉ giữ SQLi và XSS patterns theo yêu cầu
    # CMD, Traversal, Webshell, SSRF patterns đã được loại bỏ

    _DANGEROUS_REGEX: list[re.Pattern] | None = None
    _SQLI_REGEX: list[re.Pattern] | None = None
    _XSS_REGEX: list[re.Pattern] | None = None

    # Regex kết hợp (quét một lượt thay vì vòng lặp)
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

        # Regex kết hợp: Quét một lượt thay vì N vòng lặp
        # Dùng non-capturing groups (?:...) để tối ưu hiệu năng
        combined_pattern = '|'.join(f'(?:{p})' for p in all_dangerous)
        cls._COMBINED_DANGEROUS_REGEX = re.compile(combined_pattern, re.IGNORECASE)

    @classmethod
    def _has_suspicious_bytes(cls, raw_bytes: bytes) -> bool:
        """Kiểm tra 1: Siêu nhanh - O(n) với O(1) set lookup mỗi byte."""
        return any(b in cls.SUSPICIOUS_BYTES for b in raw_bytes[:1000])

    @classmethod
    def score_payload(cls, raw_bytes: bytes | None) -> float:
        """
        Chấm điểm một blob payload bytes.

        Pipeline tối ưu Fail-Fast:
        1. Kiểm tra SUSPICIOUS_BYTES trên raw bytes (O(n), không decode)
        2. Kiểm tra binary payload (bỏ qua ảnh/binary)
        3. Chuẩn hóa chuỗi
        4. Quét bằng Regex kết hợp (một lượt)
        """
        if not raw_bytes:
            return CONTEXT_NEUTRAL

        raw_bytes = raw_bytes[: cls.MAX_PAYLOAD_TOTAL]

        # =====================================================================
        # KIỂM TRA 1 (Siêu nhanh): Byte nghi ngờ trên dữ liệu thô
        # Nếu không có byte nghi ngờ nào → Kiểm tra keyword trước khi bỏ qua
        # =====================================================================
        if not cls._has_suspicious_bytes(raw_bytes):
            # Fallback: Kiểm tra keyword bằng Aho-Corasick sau khi decode
            # (Để bắt payload như UNION+SELECT không có ký tự đặc biệt)
            try:
                decoded = unquote_plus(raw_bytes.decode('utf-8', errors='ignore'))
                cls._init_keyword_automaton()
                if not cls._scan_keywords_fast(decoded.lower()):
                    return CONTEXT_NEUTRAL  # Thực sự sạch
                # Có keyword → tiếp tục kiểm tra
            except Exception:
                return CONTEXT_NEUTRAL

        # =====================================================================
        # KIỂM TRA 2 (Nhanh): Phát hiện binary payload
        # Bỏ qua ảnh, file thực thi, file nén
        # =====================================================================
        if cls._is_binary_payload(raw_bytes):
            return CONTEXT_NEUTRAL

        # =====================================================================
        # KIỂM TRA 3 & 4: Chuẩn hóa + Quét Regex kết hợp
        # =====================================================================
        cls._init_patterns()

        # Tấn công padding: thử biến thể đã cắt trước
        if cls._detect_padding_attack(raw_bytes):
            # Thử cắt thông minh (loại bỏ ký tự lặp nhiều nhất)
            stripped = cls._smart_strip_padding(raw_bytes)
            if stripped and stripped != raw_bytes:
                normalized = PayloadNormalizer.normalize(stripped)
                if cls._scan_for_patterns_combined(normalized) == CONTEXT_MALICIOUS:
                    return CONTEXT_MALICIOUS

            # Cũng thử cắt khoảng trắng truyền thống
            stripped_ws = raw_bytes.strip(b" \t\n\r\x00")
            if stripped_ws and stripped_ws != raw_bytes:
                normalized = PayloadNormalizer.normalize(stripped_ws)
                if cls._scan_for_patterns_combined(normalized) == CONTEXT_MALICIOUS:
                    return CONTEXT_MALICIOUS

        # Lấy mẫu đa điểm với Regex kết hợp
        for sample_bytes in cls._multi_point_sample(raw_bytes):
            normalized = PayloadNormalizer.normalize(sample_bytes)
            result = cls._scan_for_patterns_combined(normalized)
            if result == CONTEXT_MALICIOUS:
                return CONTEXT_MALICIOUS

        return CONTEXT_NEUTRAL

    # =========================================================================
    # ĐẾM CÓ TRỌNG SỐ CHO F11/F13 (Keyword=1đ, Pattern=2đ)
    # =========================================================================

    @classmethod
    def count_sqli_indicators(cls, raw_bytes: bytes | None) -> float:
        """
        Đếm weighted SQLi indicators cho Feature F11.

        Chấm điểm:
        - Mỗi keyword (union, select...): 1 điểm
        - Mỗi pattern match (union...select, or 1=1): 2 điểm

        Returns:
            float: Tổng điểm SQLi
        """
        if not raw_bytes:
            return 0.0

        # Bỏ qua binary payload
        if cls._is_binary_payload(raw_bytes):
            return 0.0

        # Chuẩn hóa payload
        normalized = PayloadNormalizer.normalize(raw_bytes)
        if not normalized:
            return 0.0

        # Aho-Corasick: Kiểm tra keyword trước (O(n))
        cls._init_keyword_automaton()
        found_keywords = cls._scan_keywords_fast(normalized)
        sql_keywords = [kw for kw in found_keywords if kw.lower() in
                        [k.lower() for k in cls._SQL_KEYWORDS]]

        # Nếu không có keyword VÀ không có ký tự nghi ngờ → bỏ qua regex
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

        Chấm điểm:
        - Mỗi keyword (script, alert, onerror...): 1 điểm
        - Mỗi pattern match (<script>, onerror=...): 2 điểm

        Returns:
            float: Tổng điểm XSS
        """
        if not raw_bytes:
            return 0.0

        # Bỏ qua binary payload
        if cls._is_binary_payload(raw_bytes):
            return 0.0

        # Chuẩn hóa payload
        normalized = PayloadNormalizer.normalize(raw_bytes)
        if not normalized:
            return 0.0

        # XSS cần ít nhất một trong: <, >, =
        if not any(c in normalized for c in "<>="):
            return 0.0

        # Aho-Corasick: Kiểm tra keyword
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
        """Phát hiện tấn công padding bằng BẤT KỲ ký tự lặp nào.

        Chiến lược:
        1. Kiểm tra padding khoảng trắng truyền thống
        2. Kiểm tra độ đa dạng ký tự thấp (ký tự lặp)
        3. Kiểm tra nếu ký tự phổ biến nhất chiếm ưu thế payload
        """
        if len(raw_bytes) < cls.MIN_PAYLOAD_FOR_RATIO:
            return False

        # Kiểm tra 1: Padding khoảng trắng truyền thống
        padding_chars = {ord(" "), ord("\t"), ord("\n"), ord("\r"), 0, 11, 12}
        padding_count = sum(1 for b in raw_bytes if b in padding_chars)
        ratio = padding_count / len(raw_bytes)
        if ratio > cls.PADDING_RATIO_THRESHOLD:
            return True

        # Kiểm tra 2: Đa dạng thấp (rất ít ký tự duy nhất)
        sample = raw_bytes[:100]
        if len(set(sample)) <= 3:
            return True

        # Kiểm tra 3: Một ký tự chiếm ưu thế (vd: nhiều '+' hoặc 'a')
        # Đếm tần suất byte phổ biến nhất
        byte_counts = Counter(raw_bytes)
        if byte_counts:
            most_common_byte, count = byte_counts.most_common(1)[0]
            dominance_ratio = count / len(raw_bytes)
            # Nếu bất kỳ byte nào xuất hiện >70% payload, có thể là padding
            if dominance_ratio > 0.70:
                return True

        return False

    @classmethod
    def _smart_strip_padding(cls, raw_bytes: bytes) -> bytes:
        """Cắt thông minh loại bỏ ký tự padding lặp.

        Xử lý tấn công padding dùng BẤT KỲ ký tự nào ('+', 'a', v.v.),
        không chỉ khoảng trắng.

        Chiến lược:
        1. Tìm byte phổ biến nhất trong payload
        2. Nếu nó chiếm ưu thế (>60%), thử cắt cẩn thận
        3. QUAN TRỌNG: Không cắt quá mức!
           Ví dụ: "+++union+select+++" nên giữ lại "union+select"

        Giải pháp: Chỉ cắt các khối LIÊN TỤC từ hai đầu, không phải tất cả
        """
        if len(raw_bytes) < 100:
            return raw_bytes

        # Đếm tần suất byte
        byte_counts = Counter(raw_bytes)

        if not byte_counts:
            return raw_bytes

        # Tìm byte phổ biến nhất
        most_common_byte, count = byte_counts.most_common(1)[0]
        dominance_ratio = count / len(raw_bytes)

        # Nếu byte này chiếm ưu thế (>60%), có thể là padding
        if dominance_ratio > 0.60:
            # Cắt cẩn thận để tránh loại bỏ nội dung
            # Thay vì strip() loại bỏ TẤT CẢ từ hai đầu,
            # chỉ loại bỏ khối liên tục của ký tự padding

            padding_char = bytes([most_common_byte])

            # Tìm vị trí kết thúc padding liên tục từ trái
            left_idx = 0
            for i, b in enumerate(raw_bytes):
                if bytes([b]) != padding_char:
                    left_idx = i
                    break

            # Tìm vị trí bắt đầu padding liên tục từ phải
            right_idx = len(raw_bytes)
            for i in range(len(raw_bytes) - 1, -1, -1):
                if bytes([raw_bytes[i]]) != padding_char:
                    right_idx = i + 1
                    break

            # Trích xuất nội dung ở giữa
            if left_idx < right_idx:
                stripped = raw_bytes[left_idx:right_idx]
                return stripped

        return raw_bytes

    @classmethod
    def _collapse_whitespace(cls, text: str) -> str:
        collapsed = re.sub(r"\s+", " ", text)
        return collapsed.strip()

    # =========================================================================
    # GIẢI MÃ BASE64
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
    # MATCHING TỪ KHÓA NHANH BẰNG AHO-CORASICK
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
            # Fallback sang triển khai cũ nếu context chưa có
            try:
                payload = raw_bytes.decode("utf-8", errors="ignore")

                # Dùng unquote_plus() để decode '+' thành khoảng trắng
                # unquote() KHÔNG decode '+' → ' '
                # unquote_plus() CÓ decode '+' → ' ' (cho URL query string)

                for _ in range(cls.MAX_DECODE_ITERATIONS):
                    decoded = unquote_plus(payload)
                    if decoded == payload:
                        break
                    payload = decoded

                # Decode nội dung Base64 encoded
                payload = cls._try_base64_decode(payload)

                payload = html.unescape(payload)
                payload = unicodedata.normalize("NFKC", payload)

                # Chuẩn hóa Unicode quotes thành tương đương ASCII
                # Nhiều trình duyệt/ứng dụng dùng "smart quotes" để né phát hiện
                QUOTE_MAP = {
                    '\u2018': "'",  # '
                    '\u2019': "'",  # '
                    '\u201A': "'",  # ‚
                    '\u201B': "'",  # ‛
                    '\u201C': '"',  # "
                    '\u201D': '"',  # "
                    '\u201E': '"',  # „
                    '\u201F': '"',  # ‟
                    '\u00B4': "'",  # ´ dấu sắc
                    '\u2032': "'",  # ′ dấu phẩy
                    '\u2033': '"',  # ″ dấu phẩy kép
                    '\u0060': "'",  # ` grave → nháy đơn cho nhất quán
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
        """Phương thức cũ - giữ lại để tương thích ngược."""
        return cls._scan_for_patterns_combined(payload)

    @classmethod
    def _scan_for_patterns_combined(cls, payload: str) -> float:
        """
        KIỂM TRA 4: Regex kết hợp - Quét một lượt thay vì N vòng lặp.

        Hiệu năng: O(n) thay vì O(n * M) với M = số lượng pattern
        Regex kết hợp '(p1)|(p2)|...' match trong một lượt.
        """
        if not payload:
            return CONTEXT_NEUTRAL

        # Đã kiểm tra byte nghi ngờ ở score_payload rồi,
        # nhưng vẫn giữ kiểm tra ký tự cho các entry point khác
        if not cls._has_suspicious_chars(payload):
            # Fallback: Kiểm tra keyword bằng Aho-Corasick
            cls._init_keyword_automaton()
            if not cls._scan_keywords_fast(payload.lower()):
                return CONTEXT_NEUTRAL
            # Có keyword (union, select...) → tiếp tục kiểm tra regex

        # Regex kết hợp: Tìm kiếm một lần thay vì vòng lặp
        if cls._COMBINED_DANGEROUS_REGEX is not None:
            if cls._COMBINED_DANGEROUS_REGEX.search(payload):
                return CONTEXT_MALICIOUS
        else:
            # Fallback sang vòng lặp nếu regex kết hợp chưa khởi tạo
            assert cls._DANGEROUS_REGEX is not None
            for regex in cls._DANGEROUS_REGEX:
                if regex.search(payload):
                    return CONTEXT_MALICIOUS

        return CONTEXT_NEUTRAL


def score_payload(raw_bytes: bytes | None) -> float:
    """Hàm tiện ích bọc ngoài."""
    return PayloadContextScorer.score_payload(raw_bytes)
