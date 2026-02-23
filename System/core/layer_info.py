from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import json


@dataclass
class LayerInfo:
    """
    Chứa những thông tin đã được phân tích từ một gói tin mạng.
    Thiết kế: Tất cả các trường đều là Optional để xử lý các gói tin không hoàn chỉnh

    Chỉ hỗ trợ: IP + TCP + HTTP (không UDP, ICMP, raw payload)
    """

    # Metadata
    timestamp: float
    packet_number: int

    # =========================================================================
    # IP LAYER - Tầng Internet Protocol
    # =========================================================================
    has_ip: bool = False                    # Có tầng IP không?
    ip_version: Optional[int] = None        # Phiên bản IP (4 hoặc 6)
    src_ip: Optional[str] = None            # Địa chỉ IP nguồn (VD: "192.168.1.1")
    dst_ip: Optional[str] = None            # Địa chỉ IP đích
    ttl: Optional[int] = None               # Time To Live (số hop tối đa)
    ip_len: Optional[int] = None            # Độ dài gói tin IP (bytes)
    protocol: Optional[int] = None          # Giao thức tầng trên (6=TCP)

    # =========================================================================
    # TCP LAYER - Tầng Transmission Control Protocol
    # =========================================================================
    has_tcp: bool = False                   # Có tầng TCP không?
    tcp_sport: Optional[int] = None         # Cổng nguồn (0-65535)
    tcp_dport: Optional[int] = None         # Cổng đích (0-65535)
    tcp_flags: Optional[str] = None         # Cờ TCP: S=SYN, A=ACK, F=FIN, R=RST, P=PSH
    tcp_seq: Optional[int] = None           # Sequence number
    tcp_ack: Optional[int] = None           # Acknowledgment number
    tcp_window: Optional[int] = None        # Window size (kích thước buffer nhận)

    # =========================================================================
    # HTTP PAYLOAD - Composite payload từ HTTP (URI + User-Agent + Body)
    # =========================================================================
    has_payload: bool = False               # Có HTTP payload không?
    payload_bytes: Optional[bytes] = None   # Composite HTTP payload (URI + User-Agent + Body)
    payload_length: int = 0                 # Độ dài payload (bytes)

    # =========================================================================
    # APPLICATION LAYER - Tầng ứng dụng (HTTP, DNS)
    # =========================================================================
    has_http: bool = False                  # Có HTTP request/response không?
    http_method: Optional[str] = None       # HTTP method (GET, POST, PUT, DELETE)
    http_uri: Optional[str] = None          # URI được yêu cầu (VD: /api/users)
    http_host: Optional[str] = None         # Host header (VD: www.example.com)
    http_user_agent: Optional[str] = None   # User-Agent header
    http_status: Optional[int] = None       # HTTP status code (200, 404, 500, v.v.)

    # Nginx Proxy Headers (injected sau Nginx)
    x_real_ip: Optional[str] = None         # IP gốc của client (từ X-Real-IP header)
    x_request_id: Optional[str] = None      # Request ID để tracking (từ X-Request-ID header)

    has_dns: bool = False                   # Có DNS query không?
    dns_query: Optional[str] = None         # Tên miền được truy vấn (VD: www.google.com)

    def __post_init__(self):
        """
        Gọi sanitize ngay khi init nếu dữ liệu được truyền vào constructor.
        """
        self.sanitize()

    def sanitize(self):
        """
        Giai đoạn Data Sanitization
        Đảm bảo dữ liệu đúng kiểu trước khi sử dụng.
        Cần được gọi thủ công nếu populate fields sau khi init.
        """
        # 1. Xử lý Payload (đảm bảo là bytes)
        if self.payload_bytes and not isinstance(self.payload_bytes, bytes):
            # Nếu lỡ truyền vào str, encode lại thành bytes
            if isinstance(self.payload_bytes, str):
                 self.payload_bytes = self.payload_bytes.encode('utf-8', errors='ignore')
            else:
                 self.payload_bytes = bytes(self.payload_bytes)

        # 2. Xử lý TCP Flags (Scapy FlagValue -> str)
        if self.tcp_flags is not None:
            self.tcp_flags = str(self.tcp_flags)

        # 3. Xử lý HTTP Fields (Bytes -> Str)
        # Scapy thường trả về bytes cho HTTP headers, cần decode để tránh lỗi JSON
        self.http_method = self._safe_decode(self.http_method)
        self.http_uri = self._safe_decode(self.http_uri)
        self.http_host = self._safe_decode(self.http_host)
        self.http_user_agent = self._safe_decode(self.http_user_agent)
        self.x_real_ip = self._safe_decode(self.x_real_ip)
        self.x_request_id = self._safe_decode(self.x_request_id)
        self.dns_query = self._safe_decode(self.dns_query)


    def _safe_decode(self, value: Any) -> Optional[str]:
        """Hàm phụ trợ: Chuyển bytes thành str an toàn"""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        return str(value)

    @property
    def is_reset(self) -> bool:
         return self.has_tcp and self.tcp_flags and "R" in self.tcp_flags

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)

        # Chuyển payload bytes thành hex
        if data['payload_bytes']:
            data['payload_bytes'] = data['payload_bytes'].hex()

        # Xử lý TCP Flags
        if data.get('tcp_flags') is not None:
            data['tcp_flags'] = str(data['tcp_flags'])
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
