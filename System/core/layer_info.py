from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import json


@dataclass
class LayerInfo:
    """
    Chứa những thông tin đã được phân tích từ một gói tin mạng.
    Thiết kế: Tất cả các trường đều là Optional để xử lý các gói tin không hoàn chỉnh
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
    protocol: Optional[int] = None          # Giao thức tầng trên (6=TCP, 17=UDP, 1=ICMP)
    
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
    # UDP LAYER - Tầng User Datagram Protocol
    # =========================================================================
    has_udp: bool = False                   # Có tầng UDP không?
    udp_sport: Optional[int] = None         # Cổng nguồn
    udp_dport: Optional[int] = None         # Cổng đích
    udp_len: Optional[int] = None           # Độ dài gói tin UDP
    
    # =========================================================================
    # ICMP LAYER - Tầng Internet Control Message Protocol
    # =========================================================================
    has_icmp: bool = False                  # Có tầng ICMP không?
    icmp_type: Optional[int] = None         # Loại ICMP (8=Echo Request, 0=Reply, 3=Unreachable)
    icmp_code: Optional[int] = None         # Mã chi tiết của ICMP type
    
    # =========================================================================
    # PAYLOAD/RAW LAYER - Dữ liệu thô
    # =========================================================================
    has_payload: bool = False               # Có payload không?
    payload_bytes: Optional[bytes] = None   # Dữ liệu thô dạng bytes
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
    
    has_dns: bool = False                   # Có DNS query không?
    dns_query: Optional[str] = None         # Tên miền được truy vấn (VD: www.google.com)

    def __post_init__(self):
        """
        Giai đoạn Data Sanitization
        Đảm bảo dữ liệu đúng kiểu trước khi sử dụng.
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
        self.dns_query = self._safe_decode(self.dns_query)
    
    def _safe_decode(self, value: Any) -> Optional[str]:
        """Hàm phụ trợ: Chuyển bytes thành str an toàn"""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace') # errors='replace' để tránh crash nếu gặp ký tự lạ
        return str(value)
    
    @property
    def is_reset(self) -> bool:
         # Vì tcp_flags giờ là str (ví dụ "R" hoặc "RA"), cần sửa logic check
         # Cách đơn giản: check xem chữ "R" có trong chuỗi flags không
         return self.has_tcp and self.tcp_flags and "R" in self.tcp_flags
    
    @property
    def is_icmp_unreach(self) -> bool:
        # Kiểm tra có ICMP và có type = 3 (Destination Unreachable)
        return self.has_icmp and self.icmp_type == 3

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)

        # Chuyển payload bytes thành hex 
        if data['payload_bytes']:
            data['payload_bytes'] = data['payload_bytes'].hex()
            
        # Xử lý TCP Flags 
        # Cần ép kiểu về string để JSON không bị lỗi
        if data.get('tcp_flags') is not None:
            data['tcp_flags'] = str(data['tcp_flags'])
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
        