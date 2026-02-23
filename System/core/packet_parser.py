"""
=============================================================================
PACKET PARSER - Module phân tích gói tin mạng
=============================================================================

CHỨC NĂNG:
- Trích xuất thông tin từ gói tin Scapy (IP + TCP + HTTP)
- HTTP parsing luôn được bật để trích xuất payload cho feature extraction
- Không hỗ trợ UDP, ICMP, raw payload (chỉ HTTP composite payload)

PIPELINE:
1. Extract IP layer (src_ip, dst_ip, TTL, protocol)
2. Extract TCP layer (ports, flags, seq, ack)
3. Extract HTTP layer (method, URI, host, user-agent, status)
4. Build composite payload (URI + User-Agent + Body) cho feature extraction
"""

import time
from typing import Dict, List, Optional
from scapy.all import IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

from core.layer_info import LayerInfo


class HttpPayloadExtractor:
    """
    Extract HTTP information and build composite payload for analysis.

    Responsibilities:
    - Extract HTTP request/response from Scapy packet
    - Build composite payload [URI + User-Agent + Body] for pattern matching

    Separation of Concerns:
    - This class: Raw extraction (bytes, no transformation)
    - PayloadContextScorer: Normalization for pattern matching
    """

    @staticmethod
    def extract_http_info(packet, info: 'LayerInfo') -> bool:
        """
        Extract HTTP request/response into LayerInfo.

        Returns:
            bool: True if HTTP layer was found and extracted
        """
        found_http = False

        # HTTP Request
        if packet.haslayer(HTTPRequest):
            info.has_http = True
            http_req = packet[HTTPRequest]
            info.http_method = http_req.Method
            info.http_uri = http_req.Path
            info.http_host = http_req.Host
            info.http_user_agent = http_req.User_Agent

            # Extract X-Real-IP and X-Request-ID from headers (Nginx proxy headers)
            HttpPayloadExtractor._extract_proxy_headers(packet, info)
            found_http = True

        # HTTP Response
        if packet.haslayer(HTTPResponse):
            info.has_http = True
            http_resp = packet[HTTPResponse]
            try:
                info.http_status = int(http_resp.Status_Code) if http_resp.Status_Code else None
            except (ValueError, TypeError):
                info.http_status = None
            found_http = True

        # Build composite payload từ HTTP (URI + User-Agent + Body)
        if found_http:
            composite = HttpPayloadExtractor.build_composite_payload_from_packet(packet, info)
            if composite:
                info.has_payload = True
                info.payload_bytes = composite
                info.payload_length = len(composite)

        return found_http

    @staticmethod
    def _extract_proxy_headers(packet, info: 'LayerInfo'):
        """
        Extract Nginx proxy headers (X-Real-IP, X-Request-ID) from raw payload.

        Scapy không tự parse các custom headers, nên cần parse thủ công từ Raw layer.
        """
        if not packet.haslayer(Raw):
            return

        try:
            raw_data = bytes(packet[Raw].load)
            text = raw_data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')

            for line in lines:
                line_lower = line.lower()

                # X-Real-IP header (IP gốc của client)
                if line_lower.startswith('x-real-ip:'):
                    info.x_real_ip = line.split(':', 1)[-1].strip()

                # X-Request-ID header (tracking ID)
                elif line_lower.startswith('x-request-id:'):
                    info.x_request_id = line.split(':', 1)[-1].strip()

                # X-Forwarded-For (fallback nếu không có X-Real-IP)
                elif line_lower.startswith('x-forwarded-for:') and not info.x_real_ip:
                    xff_value = line.split(':', 1)[-1].strip()
                    info.x_real_ip = xff_value.split(',')[0].strip()

        except Exception:
            pass  # Ignore parse errors

    @staticmethod
    def build_composite_payload_from_packet(packet, info: 'LayerInfo') -> bytes:
        """
        Build composite payload từ HTTP packet: [URI] + [User-Agent] + [Body]

        Trích xuất body trực tiếp từ Scapy Raw layer (HTTP body).
        """
        parts = []

        # Header 1: URI (quan trọng cho SQLi/XSS qua GET params)
        uri = info.http_uri
        if uri:
            if isinstance(uri, str):
                parts.append(uri.encode('utf-8', errors='ignore'))
            elif isinstance(uri, bytes):
                parts.append(uri)

        # Header 2: User-Agent (vector tấn công phổ biến)
        ua = info.http_user_agent
        if ua:
            if isinstance(ua, str):
                parts.append(ua.encode('utf-8', errors='ignore'))
            elif isinstance(ua, bytes):
                parts.append(ua)

        # Body: Từ Raw layer (HTTP body cho POST requests)
        if packet.haslayer(Raw):
            body = bytes(packet[Raw].load)
            if body:
                parts.append(body)

        return b' '.join(parts) if parts else b''

    @staticmethod
    def build_composite_payload(pkt) -> bytes:
        """
        Build composite payload từ LayerInfo object: [URI] + [User-Agent] + [Body]

        Logic Fail-Fast:
        - Regex quét từ trái sang phải
        - Tấn công thường nằm ở URI (GET) hoặc User-Agent
        - Đặt Header trước Body → phát hiện sớm, tránh quét Body lớn

        Args:
            pkt: LayerInfo object with HTTP attributes

        Returns:
            bytes: Composite payload for analysis
        """
        body = getattr(pkt, 'payload_bytes', None) or b''

        if not getattr(pkt, 'has_http', False):
            return body

        parts = []

        # Header 1: URI
        uri = getattr(pkt, 'http_uri', None)
        if uri:
            if isinstance(uri, str):
                parts.append(uri.encode('utf-8', errors='ignore'))
            elif isinstance(uri, bytes):
                parts.append(uri)

        # Header 2: User-Agent
        ua = getattr(pkt, 'http_user_agent', None)
        if ua:
            if isinstance(ua, str):
                parts.append(ua.encode('utf-8', errors='ignore'))
            elif isinstance(ua, bytes):
                parts.append(ua)

        # Body
        parts.append(body)

        return b' '.join(parts)


class PacketLayerExtractor:
    """
    Extract all layers from packet in ONE pass

    Responsibilities:
    - Parse Scapy packet
    - Extract IP + TCP + HTTP layer information
    - Build HTTP composite payload cho feature extraction
    - Handle malformed packets gracefully

    Performance: O(1) per packet (single pass)

    NOTE: HTTP parsing luôn được bật. Không hỗ trợ UDP/ICMP/raw payload.
    """

    def __init__(self, use_packet_time: bool = False):
        """
        Hàm khởi tạo PacketLayerExtractor

        Args:
            use_packet_time: Dùng timestamp từ PCAP thay vì thời gian hiện tại
        """
        self.use_packet_time = use_packet_time

        # Thống kê: Đếm số lượng các loại gói tin đã xử lý
        self.stats = {
            'total_packets': 0,        # Tổng số gói tin
            'malformed_packets': 0,    # Số gói tin bị lỗi/hỏng
            'ip_packets': 0,           # Số gói tin IP
            'tcp_packets': 0,          # Số gói tin TCP
            'http_requests': 0         # Số HTTP request/response
        }

    def extract(self, packet, packet_number: int = 0) -> LayerInfo:
        """
        Trích xuất tất cả thông tin từ các tầng của gói tin

        Args:
            packet: Đối tượng gói tin Scapy cần phân tích
            packet_number: Số thứ tự gói tin để theo dõi

        Returns:
            LayerInfo chứa toàn bộ dữ liệu đã trích xuất

        Pipeline:
        1. IP layer (src_ip, dst_ip, TTL, protocol)
        2. TCP layer (ports, flags, seq, ack)
        3. HTTP layer + composite payload (URI + User-Agent + Body)
        """
        self.stats['total_packets'] += 1

        # Lấy timestamp
        if self.use_packet_time and hasattr(packet, 'time'):
            pkt_timestamp = float(packet.time)
        else:
            pkt_timestamp = time.time()

        info = LayerInfo(
            timestamp=pkt_timestamp,
            packet_number=packet_number
        )

        try:
            # Bước 1: Trích xuất tầng IP
            self._extract_ip_layer(packet, info)

            # Bước 2: Trích xuất tầng TCP
            self._extract_tcp_layer(packet, info)

            # Bước 3: Trích xuất HTTP + build composite payload
            self._extract_http_layer(packet, info)

            # Finalize: Sanitize data (decode bytes -> str)
            info.sanitize()

        except Exception as e:
            self.stats['malformed_packets'] += 1

        return info

    def _extract_ip_layer(self, packet, info: LayerInfo):
        """Trích xuất thông tin tầng IP"""
        if packet.haslayer(IP):
            info.has_ip = True
            info.ip_version = packet[IP].version
            info.src_ip = packet[IP].src
            info.dst_ip = packet[IP].dst
            info.ttl = packet[IP].ttl
            info.ip_len = packet[IP].len
            info.protocol = packet[IP].proto

            self.stats['ip_packets'] += 1

    def _extract_tcp_layer(self, packet, info: LayerInfo):
        """Trích xuất thông tin tầng TCP"""
        if packet.haslayer(TCP):
            info.has_tcp = True
            info.tcp_sport = packet[TCP].sport
            info.tcp_dport = packet[TCP].dport
            info.tcp_flags = packet[TCP].flags
            info.tcp_seq = packet[TCP].seq
            info.tcp_ack = packet[TCP].ack
            info.tcp_window = packet[TCP].window

            self.stats['tcp_packets'] += 1

    def _extract_http_layer(self, packet, info: LayerInfo):
        """
        Phân tích HTTP và build composite payload.
        HTTP parsing luôn được bật.
        """
        if HttpPayloadExtractor.extract_http_info(packet, info):
            self.stats['http_requests'] += 1

    def parse(self, packet, packet_number: int = 0) -> LayerInfo:
        """Bí danh (alias) cho hàm extract() - để tương thích ngược"""
        return self.extract(packet, packet_number)

    def extract_batch(self, packets: List) -> List[LayerInfo]:
        """Trích xuất nhiều gói tin cùng lúc (batch processing)"""
        return [self.extract(pkt, i) for i, pkt in enumerate(packets)]

    def get_stats(self) -> Dict[str, int]:
        """Lấy thống kê về các gói tin đã xử lý"""
        return self.stats.copy()

    def reset_stats(self):
        """Reset tất cả bộ đếm thống kê về 0"""
        for key in self.stats:
            self.stats[key] = 0
