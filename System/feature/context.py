"""Chuẩn hóa payload và ngữ cảnh cho tính toán đặc trưng.

- PayloadNormalizer: pipeline canonicalization thống nhất (URL, HTML, Unicode, Base64/hex)
- FeatureContext: cache normalized payload per packet, giảm từ O(N×F) xuống O(N)
"""

import base64
import html
import re
import logging
import unicodedata
from typing import Optional
from urllib.parse import unquote, unquote_plus
from core.packet_parser import HttpPayloadExtractor

logger = logging.getLogger(__name__)


class PayloadNormalizer:
    """Pipeline canonicalization HTTP payload trước khi so khớp pattern.

    Tất cả phương thức là static — không cần khởi tạo.
    """
    
    # Hằng số cấu hình
    MAX_ITERATIONS = 2  # Ngăn vòng lặp decode vô hạn; max=2 đủ cho double-encoding [Akhavani et al., ACSAC 2025]
    MAX_PAYLOAD_SIZE = 65536  # 64 KB
    
    # Mẫu regex được biên dịch sẵn cho hiệu năng
    _BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{12,}={0,2}$')  # legacy: whole-string check
    _BASE64_SEGMENT = re.compile(r'[A-Za-z0-9+/]{8,}={0,2}')     # substring Base64 detection (min 8 = 6 decoded bytes, e.g. "SELECT")
    _HEX_SQL_PATTERN = re.compile(r'\b0x([0-9a-fA-F]{4,})\b', re.IGNORECASE)  # SQL hex: 0x53454c454354
    _WHITESPACE_PATTERN = re.compile(r'\s+')
    
    @staticmethod
    def normalize(payload: bytes) -> str:
        """Chuẩn hóa payload HTTP thành chuỗi để so khớp pattern.

        Core (6 bước):
          bytes→str → URL decode ≤2× → HTML decode → Unicode NFKC → whitespace → lowercase
        Optional: Base64/hex conditional decode (chỉ khi có segment khớp pattern)

        >>> PayloadNormalizer.normalize(b"SELECT%20*%20FROM%20users")
        'select * from users'
        >>> PayloadNormalizer.normalize(b"q=U0VMRUNUICo=&page=1")
        'q=select *&page=1'
        """
        # --- Resource guard (không phải bước canonicalization) ---
        if not payload:
            return ""
        if len(payload) > PayloadNormalizer.MAX_PAYLOAD_SIZE:
            logger.warning(
                f"Payload too large ({len(payload)} bytes), truncating to {PayloadNormalizer.MAX_PAYLOAD_SIZE}"
            )
            payload = payload[:PayloadNormalizer.MAX_PAYLOAD_SIZE]

        # --- Core pipeline ---

        # 1. Bytes → string (UTF-8, fallback Latin-1)
        text = PayloadNormalizer._bytes_to_string(payload)

        # 2. URL decode đệ quy (≤2 lần) — xử lý double-encoding bypass [Akhavani et al., ACSAC 2025]
        text = PayloadNormalizer._recursive_url_decode(text, PayloadNormalizer.MAX_ITERATIONS)

        # 3. HTML entity decode — bắt &lt;script&gt; và tương tự [Tadhani et al., Sci Rep 2024]
        text = html.unescape(text)

        # 4. Unicode NFKC + smart quotes → ASCII — ngăn homoglyph bypass [OWASP Input Validation 2023]
        text = unicodedata.normalize("NFKC", text)
        _QUOTE_MAP = {
            '\u2018': "'", '\u2019': "'", '\u201A': "'", '\u201B': "'",
            '\u201C': '"', '\u201D': '"', '\u201E': '"', '\u201F': '"',
            '\u00B4': "'", '\u2032': "'", '\u2033': '"', '\u0060': "'",
        }
        for uc, asc in _QUOTE_MAP.items():
            text = text.replace(uc, asc)

        # --- Optional: Base64/hex conditional decode ---
        # Phải đứng TRƯỚC lowercase vì Base64 phân biệt hoa/thường.
        # Chỉ decode khi request chứa substring trông giống Base64 (≥20 chars)
        # hoặc hex SQL-style (0x...). Không áp dụng cho mọi request.
        # [Qbea'h et al., ICISSP 2020] — transformed SQLi/XSS detection
        text = PayloadNormalizer._decode_encoded_segments(text)

        # 5. Chuẩn hóa khoảng trắng — loại whitespace dư, non-printable [Tadhani et al., Sci Rep 2024]
        text = PayloadNormalizer._normalize_whitespace(text)

        # 6. Chuyển thành chữ thường — case-mixing bypass [Tadhani et al., Sci Rep 2024]
        text = text.lower()

        return text
    
    @staticmethod
    def _bytes_to_string(data: bytes) -> str:
        """Chuyển đổi bytes thành chuỗi với fallback encoding.
        
        Thử UTF-8 trước (encoding phổ biến nhất), sau đó fallback sang Latin-1
        nếu UTF-8 thất bại.
        
        Args:
            data: Dữ liệu bytes để chuyển đổi
        
        Returns:
            Chuỗi đã decode. Các lỗi được bỏ qua (errors='ignore').
        """
        try:
            return data.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"UTF-8 decode failed, trying Latin-1: {e}")
            try:
                return data.decode('latin1', errors='ignore')
            except Exception as e2:
                logger.warning(f"Both UTF-8 and Latin-1 decode failed: {e2}")
                # Phương án cuối cùng: chuyển đổi từng byte
                return ''.join(chr(b) if b < 128 else '?' for b in data)
    
    @staticmethod
    def _recursive_url_decode(text: str, max_tries: int) -> str:
        """Decode URL đệ quy cho đến khi không còn thay đổi.
        
        Một số tấn công sử dụng URL encoding nhiều lần (double/triple encoding)
        để trốn tránh phát hiện. Chúng ta decode đệ quy để phát hiện các mẫu này.
        
        Args:
            text: Chuỗi để decode
            max_tries: Số lần decode tối đa
        
        Returns:
            Chuỗi đã decode hoàn toàn
        
        Example:
            >>> PayloadNormalizer._recursive_url_decode("SELECT%2520*", 3)
            'SELECT *'
        """
        for iteration in range(max_tries):
            try:
                decoded = unquote_plus(text, errors='ignore')
                if decoded == text:  # Không còn thay đổi = hoàn tất
                    break
                text = decoded
            except Exception as e:
                logger.debug(f"URL decode iteration {iteration} failed: {e}")
                break
        
        return text
    
    @staticmethod
    def _recursive_base64_decode(text: str, max_tries: int) -> str:
        """Decode Base64 đệ quy nếu TOÀN BỘ chuỗi trông giống Base64 (legacy).

        Chỉ thử decode nếu chuỗi trông giống Base64:
        - Độ dài >= 12 ký tự
        - Chỉ chứa [A-Za-z0-9+/]
        - Kết thúc bằng 0-2 ký tự padding '='

        Note: Dùng _decode_encoded_segments() cho substring-based detection.
        """
        for iteration in range(max_tries):
            stripped = text.strip()
            if not PayloadNormalizer._BASE64_PATTERN.match(stripped):
                break
            if len(stripped) < 12:
                break
            try:
                decoded_bytes = base64.b64decode(stripped, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                if not decoded_str or decoded_str == text:
                    break
                text = decoded_str
            except Exception as e:
                logger.debug(f"Base64 decode iteration {iteration} failed: {e}")
                break
        return text

    @staticmethod
    def _decode_encoded_segments(text: str) -> str:
        """Decode Base64 và hex có điều kiện — chỉ khi request chứa segment trông giống encoding.

        Thay vì decode toàn bộ string, tìm các SUBSTRING khớp pattern
        rồi thử decode từng phần. Giữ nguyên phần không phải encoding.

        Điều kiện kích hoạt:
        - Base64: segment ≥20 chars, chỉ chứa [A-Za-z0-9+/=],
                  decode ra UTF-8 với >80% printable chars, kết quả ≠ input
        - Hex (SQL-style): prefix 0x + ≥4 hex digits (VD: 0x53454c454354 → SELECT)

        Ví dụ:
            "q=U0VMRUNUICogRlJPTSB1c2Vycw==" → "q=select * from users"
            "id=0x41444d494e"                 → "id=ADMIN"
            "SELECT * FROM users"             → "SELECT * FROM users"  (không thay đổi)

        [Qbea'h et al., ICISSP 2020] — transformed SQLi/XSS detection via decode+match
        """
        # 1. Hex decode: 0x... pattern (SQL injection style)
        def _try_hex(m: re.Match) -> str:
            try:
                result = bytes.fromhex(m.group(1)).decode('utf-8', errors='ignore')
                if result and sum(c.isprintable() for c in result) / len(result) > 0.8:
                    return result
            except Exception:
                pass
            return m.group(0)

        text = PayloadNormalizer._HEX_SQL_PATTERN.sub(_try_hex, text)

        # 2. Base64 decode: tìm substring trông giống Base64 (≥20 chars)
        def _try_b64(m: re.Match) -> str:
            segment = m.group(0)
            try:
                # Thêm padding nếu cần
                padded = segment + '=' * (-len(segment) % 4)
                decoded = base64.b64decode(padded, validate=True).decode('utf-8', errors='ignore')
                # Chỉ thay thế nếu kết quả là text có ý nghĩa (>80% printable)
                if decoded and decoded != segment:
                    printable = sum(c.isprintable() for c in decoded) / len(decoded)
                    if printable > 0.8:
                        return decoded
            except Exception:
                pass
            return segment

        text = PayloadNormalizer._BASE64_SEGMENT.sub(_try_b64, text)

        return text
    
    @staticmethod
    def _normalize_whitespace(text: str) -> str:
        """Chuẩn hóa khoảng trắng và ký tự không in được.
        
        - Thay thế nhiều khoảng trắng liên tiếp bằng một khoảng trắng
        - Loại bỏ các ký tự không in được (trừ \\n và \\t)
        - Loại bỏ khoảng trắng ở đầu và cuối
        
        Args:
            text: Chuỗi để chuẩn hóa
        
        Returns:
            Chuỗi với khoảng trắng chuẩn hóa
        """
        # Thay thế nhiều khoảng trắng bằng một khoảng trắng
        text = PayloadNormalizer._WHITESPACE_PATTERN.sub(' ', text)
        
        # Loại bỏ các ký tự không in được (giữ \\n, \\t, và khoảng trắng)
        text = ''.join(c for c in text if c.isprintable() or c in '\n\t ')
        
        # Loại bỏ khoảng trắng ở đầu và cuối
        return text.strip()
    
    @staticmethod
    def normalize_for_display(payload: bytes, max_length: int = 100) -> str:
        """Chuẩn hóa payload để hiển thị (ví dụ: trong log, UI).
        
        Khác với normalize(), phương thức này:
        - Không chuyển đổi thành chữ thường
        - Cắt ngắn đến độ dài tối đa
        - Thay thế các ký tự không an toàn bằng '?'
        
        Args:
            payload: Payload bytes để chuẩn hóa
            max_length: Độ dài tối đa của chuỗi đầu ra
        
        Returns:
            Chuỗi an toàn để hiển thị
        """
        if not payload:
            return "<empty>"
        
        # Giới hạn kích thước
        if len(payload) > PayloadNormalizer.MAX_PAYLOAD_SIZE:
            payload = payload[:PayloadNormalizer.MAX_PAYLOAD_SIZE]
        
        # Chuyển đổi sang chuỗi
        text = PayloadNormalizer._bytes_to_string(payload)
        
        # HTML unescape
        text = html.unescape(text)
        
        # Thay thế ký tự không an toàn
        safe_text = ''.join(c if c.isprintable() else '?' for c in text)
        
        # Cắt ngắn nếu cần
        if len(safe_text) > max_length:
            safe_text = safe_text[:max_length] + "..."
        
        return safe_text


class FeatureContext:
    """Cache normalized payload per packet, giảm từ O(N×F) xuống O(N).

    Không cache: 100 packets × 8 features = 800 normalize calls
    Có cache:    100 packets × 1           = 100 normalize calls
    """

    def __init__(self, flows):
        self.flows = flows
        self._normalized_cache = {}   # packet_id → normalized_str
        self._raw_cache = {}          # packet_id → raw_bytes
        self._payload_extractor = HttpPayloadExtractor

    def get_normalized(self, pkt) -> str:
        """Lấy normalized payload string (cached)."""
        pkt_id = id(pkt)
        if pkt_id not in self._normalized_cache:
            raw = self.get_raw_payload(pkt)
            self._normalized_cache[pkt_id] = PayloadNormalizer.normalize(raw)
        return self._normalized_cache[pkt_id]

    def get_raw_payload(self, pkt) -> bytes:
        """Lấy composite raw payload bytes (cached)."""
        pkt_id = id(pkt)
        if pkt_id not in self._raw_cache:
            self._raw_cache[pkt_id] = self._payload_extractor.build_composite_payload(pkt)
        return self._raw_cache[pkt_id]

    def get_fwd_packets_with_payloads(self):
        """Generator trả về (packet, raw_payload, normalized_payload) tuples.

        Optimized iteration cho các features cần cả raw và normalized.
        """
        for flow in self.flows:
            for pkt in flow.get_fwd_packets():
                raw = self.get_raw_payload(pkt)
                if raw:
                    yield pkt, raw, self.get_normalized(pkt)
