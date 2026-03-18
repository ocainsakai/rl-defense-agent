"""Chuẩn hóa payload thống nhất và ngữ cảnh cho tính toán đặc trưng.

Module này cung cấp:
- PayloadNormalizer: Chuẩn hóa payload là nguồn duy nhất chân lý
- FeatureContext: Ngữ cảnh chia sẻ cho tính toán đặc trưng

Mục đích:
- Thống nhất 3 triển khai chuẩn hóa khác nhau thành một
- Đảm bảo tất cả các thành phần sử dụng cùng một logic chuẩn hóa
- Ngăn chặn phát hiện không nhất quán

Các bước chuẩn hóa (theo thứ tự):
1. Bảo vệ kích thước
2. Chuyển đổi nhị phân sang chuỗi (với fallback)
3. Decode thực thể HTML
4. Decode URL (đệ quy)
5. Decode Base64 (đệ quy)
6. Chuẩn hóa khoảng trắng
7. Chuyển đổi thành chữ thường

Example:
    from feature.context import PayloadNormalizer
    
    # Chuẩn hóa payload
    payload = b"SELECT%20*%20FROM%20users"
    normalized = PayloadNormalizer.normalize(payload)
    # normalized = "select * from users"
    
    # Sử dụng trong PayloadContextScorer
    class PayloadContextScorer:
        def score_payload(self, raw_bytes):
            normalized = PayloadNormalizer.normalize(raw_bytes)
            return self._check_patterns(normalized)
"""

import base64
import html
import re
import logging
import unicodedata
from typing import Optional
from urllib.parse import unquote, unquote_plus

logger = logging.getLogger(__name__)


class PayloadNormalizer:
    """Chuẩn hóa payload là nguồn duy nhất chân lý.
    
    Lớp này cung cấp một pipeline chuẩn hóa thống nhất để xử lý
    các payload HTTP, đảm bảo rằng tất cả các thành phần trong hệ thống
    sử dụng cùng một logic chuẩn hóa.
    
    Attributes:
        MAX_ITERATIONS: Số lần lặp tối đa cho decode đệ quy (3)
        MAX_PAYLOAD_SIZE: Kích thước payload tối đa để xử lý (64KB)
    
    Note:
        Tất cả các phương thức là tĩnh - không cần khởi tạo lớp.
    """
    
    # Hằng số cấu hình
    MAX_ITERATIONS = 2  # Ngăn vòng lặp decode vô hạn; max=2 đủ cho double-encoding (bypass phổ biến nhất, Spett 2005)
    MAX_PAYLOAD_SIZE = 65536  # 64 KB
    
    # Mẫu regex được biên dịch sẵn cho hiệu năng
    _BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{12,}={0,2}$')
    _WHITESPACE_PATTERN = re.compile(r'\s+')
    
    @staticmethod
    def normalize(payload: bytes) -> str:
        """Chuẩn hóa payload thành chuỗi để so khớp mẫu.
        
        Pipeline chuẩn hóa thống nhất áp dụng các biến đổi sau:
        1. Kiểm tra kích thước (trả về "" nếu quá lớn)
        2. Chuyển đổi bytes -> string (UTF-8 với fallback Latin-1)
        3. HTML entity decode (unescape)
        4. URL decode đệ quy (tối đa 3 lần)
        5. Base64 decode đệ quy (tối đa 3 lần)
        6. Chuẩn hóa khoảng trắng (nhiều khoảng trắng -> 1 khoảng trắng)
        7. Chuyển đổi thành chữ thường
        
        Args:
            payload: Các byte thô từ gói tin HTTP
        
        Returns:
            Chuỗi chuẩn hóa để so khớp mẫu. Trả về chuỗi rỗng nếu:
            - payload là None
            - payload quá lớn (> MAX_PAYLOAD_SIZE)
        
        Example:
            >>> payload = b"SELECT%20%2A%20FROM%20users"
            >>> PayloadNormalizer.normalize(payload)
            'select * from users'
            
            >>> payload = b"U0VMRUNUICogRlJPTSB1c2Vycw=="  # Base64
            >>> PayloadNormalizer.normalize(payload)
            'select * from users'
        """
        # 1. Kiểm tra kích thước
        if not payload:
            return ""
        
        if len(payload) > PayloadNormalizer.MAX_PAYLOAD_SIZE:
            logger.warning(
                f"Payload too large ({len(payload)} bytes), truncating to {PayloadNormalizer.MAX_PAYLOAD_SIZE}"
            )
            payload = payload[:PayloadNormalizer.MAX_PAYLOAD_SIZE]
        
        # 2. Chuyển đổi bytes thành chuỗi
        text = PayloadNormalizer._bytes_to_string(payload)
        
        # 3. Decode thực thể HTML
        text = html.unescape(text)

        # 4. Chuẩn hóa Unicode (NFKC) + smart quotes → ASCII
        text = unicodedata.normalize("NFKC", text)
        _QUOTE_MAP = {
            '\u2018': "'", '\u2019': "'", '\u201A': "'", '\u201B': "'",
            '\u201C': '"', '\u201D': '"', '\u201E': '"', '\u201F': '"',
            '\u00B4': "'", '\u2032': "'", '\u2033': '"', '\u0060': "'",
        }
        for uc, asc in _QUOTE_MAP.items():
            text = text.replace(uc, asc)

        # 5. Decode URL (đệ quy, tối đa 3 lần lặp)
        text = PayloadNormalizer._recursive_url_decode(text, PayloadNormalizer.MAX_ITERATIONS)

        # 6. Decode Base64 (đệ quy, tối đa 3 lần lặp)
        text = PayloadNormalizer._recursive_base64_decode(text, PayloadNormalizer.MAX_ITERATIONS)

        # 7. Chuẩn hóa khoảng trắng
        text = PayloadNormalizer._normalize_whitespace(text)

        # 8. Chuyển đổi thành chữ thường để so sánh không phân biệt chữ hoa chữ thường
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
        """Decode Base64 đệ quy nếu mẫu khớp.
        
        Chỉ thử decode nếu chuỗi trông giống Base64:
        - Độ dài >= 12 ký tự
        - Chỉ chứa [A-Za-z0-9+/]
        - Kết thúc bằng 0-2 ký tự padding '='
        
        Args:
            text: Chuỗi để decode
            max_tries: Số lần decode tối đa
        
        Returns:
            Chuỗi đã decode (hoặc chuỗi gốc nếu không phải Base64)
        
        Example:
            >>> PayloadNormalizer._recursive_base64_decode("U0VMRUNUICo=", 3)
            'SELECT *'
        """
        for iteration in range(max_tries):
            # Kiểm tra xem có trông giống Base64 không
            stripped = text.strip()
            if not PayloadNormalizer._BASE64_PATTERN.match(stripped):
                break
            
            if len(stripped) < 12:  # Quá ngắn để là Base64 hợp lệ
                break
            
            try:
                # Thử decode
                decoded_bytes = base64.b64decode(stripped, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                
                # Nếu decode tạo ra chuỗi rỗng hoặc giống chuỗi gốc, dừng
                if not decoded_str or decoded_str == text:
                    break
                
                text = decoded_str
            except Exception as e:
                logger.debug(f"Base64 decode iteration {iteration} failed: {e}")
                break
        
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
    """Context object cho tính toán đặc trưng hiệu quả với caching.

    Mục đích:
    - Cache normalized payloads để tránh tính toán lặp lại
    - Giảm normalize_payload calls từ O(N × Features) xuống O(N)
    - Cache WAMM predictions để tránh gọi XGBoost hai lần (F15 + F16)

    Hiệu suất:
    - Không cache: 100 packets × 8 features = 800 normalize calls
    - Có cache: 100 packets × 1 = 100 normalize calls (nhanh hơn ~8x)

    Example:
        from feature.context import FeatureContext

        ctx = FeatureContext(flows, wamm_classifier=wamm)
        for flow in flows:
            for pkt in flow.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)  # Cached!
                raw = ctx.get_raw_payload(pkt)         # Cached!
    """

    def __init__(self, flows, wamm_classifier=None):
        """Khởi tạo context với flows.

        Args:
            flows: List of FlowState objects để phân tích
            wamm_classifier: Optional WammClassifier instance cho F15/F16
        """
        from core.packet_parser import HttpPayloadExtractor
        self.flows = flows
        self._normalized_cache = {}   # packet_id → normalized_str
        self._raw_cache = {}          # packet_id → raw_bytes
        self._wamm_cache = {}         # packet_id → (attack_type, confidence)
        self._wamm = wamm_classifier
        self._payload_extractor = HttpPayloadExtractor

    def get_normalized(self, pkt) -> str:
        """Lấy normalized payload string (cached).

        Trả về kết quả cached nếu có, nếu không thì tính toán và cache.
        Được sử dụng bởi các features dựa trên pattern (F11-F14).
        """
        pkt_id = id(pkt)
        if pkt_id not in self._normalized_cache:
            raw = self.get_raw_payload(pkt)
            self._normalized_cache[pkt_id] = PayloadNormalizer.normalize(raw)
        return self._normalized_cache[pkt_id]

    def get_raw_payload(self, pkt) -> bytes:
        """Lấy composite raw payload bytes (cached).

        Delegates to HttpPayloadExtractor.build_composite_payload().
        """
        pkt_id = id(pkt)
        if pkt_id not in self._raw_cache:
            self._raw_cache[pkt_id] = self._payload_extractor.build_composite_payload(pkt)
        return self._raw_cache[pkt_id]

    def get_wamm_prediction(self, pkt) -> tuple:
        """Lấy WAMM classifier prediction (cached).

        Returns:
            (attack_type, confidence) trong đó attack_type: 0=normal, 1=sqli, 2=xss
        """
        pkt_id = id(pkt)
        if pkt_id not in self._wamm_cache:
            if self._wamm is not None:
                payload = self.get_raw_payload(pkt)
                if payload:
                    self._wamm_cache[pkt_id] = self._wamm.predict(payload)
                else:
                    self._wamm_cache[pkt_id] = (0, 0.0)
            else:
                self._wamm_cache[pkt_id] = (0, 0.0)
        return self._wamm_cache[pkt_id]

    def get_fwd_packets_with_payloads(self):
        """Generator trả về (packet, raw_payload, normalized_payload) tuples.

        Optimized iteration cho các features cần cả raw và normalized.
        """
        for flow in self.flows:
            for pkt in flow.get_fwd_packets():
                raw = self.get_raw_payload(pkt)
                if raw:
                    yield pkt, raw, self.get_normalized(pkt)
