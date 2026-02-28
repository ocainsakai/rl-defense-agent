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
    """Trích xuất thông tin HTTP và xây dựng composite payload cho phân tích.

    Trách nhiệm:
    - Trích xuất HTTP request/response từ gói tin Scapy
    - Xây dựng composite payload [URI + User-Agent + Body] cho pattern matching

    Phân tách trách nhiệm:
    - Lớp này: Trích xuất thô (bytes, không biến đổi)
    - PayloadContextScorer: Chuẩn hóa cho pattern matching
    """

    # Các HTTP method cho fallback parse Raw layer
    _HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'PATCH', b'HEAD', b'OPTIONS'}

    @staticmethod
    def extract_http_info(packet, info: 'LayerInfo') -> bool:
        """Trích xuất HTTP request/response vào LayerInfo.

        Thử Scapy HTTPRequest/HTTPResponse layer trước.
        Fallback sang parse Raw layer dạng text HTTP nếu Scapy không tự phân tích.

        Returns:
            bool: True nếu tìm thấy và trích xuất được HTTP layer
        """
        found_http = False

        # HTTP Request (Scapy đã parse)
        if packet.haslayer(HTTPRequest):
            info.has_http = True
            http_req = packet[HTTPRequest]
            info.http_method = http_req.Method
            info.http_uri = http_req.Path
            info.http_host = http_req.Host
            info.http_user_agent = http_req.User_Agent

            # Trích xuất X-Real-IP và X-Request-ID từ headers (Nginx proxy headers)
            HttpPayloadExtractor._extract_proxy_headers(packet, info)
            found_http = True

        # HTTP Response (Scapy đã parse)
        if packet.haslayer(HTTPResponse):
            info.has_http = True
            http_resp = packet[HTTPResponse]
            try:
                info.http_status = int(http_resp.Status_Code) if http_resp.Status_Code else None
            except (ValueError, TypeError):
                info.http_status = None
            found_http = True

        # Fallback: parse Raw layer dạng text HTTP (cho gói tin tổng hợp / HTTP không được nhận diện)
        if not found_http and packet.haslayer(Raw):
            found_http = HttpPayloadExtractor._try_parse_raw_http(packet, info)

        # Xây dựng composite payload từ HTTP (URI + User-Agent + Body)
        # Bỏ qua nếu fallback đã xây dựng payload rồi
        if found_http and not info.has_payload:
            composite = HttpPayloadExtractor.build_composite_payload_from_packet(packet, info)
            if composite:
                info.has_payload = True
                info.payload_bytes = composite
                info.payload_length = len(composite)

        return found_http

    @staticmethod
    def _try_parse_raw_http(packet, info: 'LayerInfo') -> bool:
        """Fallback: parse Raw layer dạng text HTTP request.

        Xử lý các gói tin mà Scapy không tự phân tích HTTP
        (gói tin test tổng hợp, một số file PCAP).

        Xây dựng composite payload trực tiếp từ các thành phần đã parse
        (URI + User-Agent + Body) để tránh trùng lặp Raw layer.
        """
        try:
            raw_data = bytes(packet[Raw].load)
            # Kiểm tra nhanh: có bắt đầu bằng HTTP method không?
            first_space = raw_data.find(b' ')
            if first_space <= 0 or first_space > 7:
                return False
            method = raw_data[:first_space]
            if method not in HttpPayloadExtractor._HTTP_METHODS:
                return False

            text = raw_data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            if not lines:
                return False

            # Parse dòng request: "METHOD /path HTTP/1.1"
            request_line = lines[0]
            parts = request_line.split(' ', 2)
            if len(parts) < 2:
                return False

            info.has_http = True
            info.http_method = parts[0]
            info.http_uri = parts[1]

            # Parse headers và body
            header_end = False
            body_parts = []
            for line in lines[1:]:
                if header_end:
                    body_parts.append(line)
                    continue
                if line == '':
                    header_end = True
                    continue
                lower = line.lower()
                if lower.startswith('host:'):
                    info.http_host = line.split(':', 1)[1].strip()
                elif lower.startswith('user-agent:'):
                    info.http_user_agent = line.split(':', 1)[1].strip()
                elif lower.startswith('x-real-ip:'):
                    info.x_real_ip = line.split(':', 1)[1].strip()
                elif lower.startswith('x-request-id:'):
                    info.x_request_id = line.split(':', 1)[1].strip()

            # Build composite payload: [URI] + [User-Agent] + [Body]
            composite_parts = []
            if info.http_uri:
                uri = info.http_uri
                if isinstance(uri, str):
                    composite_parts.append(uri.encode('utf-8', errors='ignore'))
                else:
                    composite_parts.append(uri)
            if info.http_user_agent:
                ua = info.http_user_agent
                if isinstance(ua, str):
                    composite_parts.append(ua.encode('utf-8', errors='ignore'))
                else:
                    composite_parts.append(ua)
            body_text = '\r\n'.join(body_parts).strip()
            if body_text:
                composite_parts.append(body_text.encode('utf-8', errors='ignore'))

            if composite_parts:
                info.has_payload = True
                info.payload_bytes = b' '.join(composite_parts)
                info.payload_length = len(info.payload_bytes)

            return True
        except Exception:
            return False

    @staticmethod
    def _extract_proxy_headers(packet, info: 'LayerInfo'):
        """Trích xuất Nginx proxy headers (X-Real-IP, X-Request-ID) từ raw payload.

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
            pass  # Bỏ qua lỗi parse

    @staticmethod
    def build_composite_payload_from_packet(packet, info: 'LayerInfo') -> bytes:
        """Xây dựng composite payload từ HTTP packet: [URI] + [User-Agent] + [Body]

        Trích xuất body trực tiếp từ Scapy Raw layer (HTTP body).
        """
        parts = []

        # Phần 1: URI (quan trọng cho SQLi/XSS qua GET params)
        uri = info.http_uri
        if uri:
            if isinstance(uri, str):
                parts.append(uri.encode('utf-8', errors='ignore'))
            elif isinstance(uri, bytes):
                parts.append(uri)

        # Phần 2: User-Agent (vector tấn công phổ biến)
        ua = info.http_user_agent
        if ua:
            if isinstance(ua, str):
                parts.append(ua.encode('utf-8', errors='ignore'))
            elif isinstance(ua, bytes):
                parts.append(ua)

        # Phần 3: Body từ Raw layer (HTTP body cho POST requests)
        if packet.haslayer(Raw):
            body = bytes(packet[Raw].load)
            if body:
                parts.append(body)

        return b' '.join(parts) if parts else b''

    @staticmethod
    def build_composite_payload(pkt) -> bytes:
        """Xây dựng composite payload từ đối tượng LayerInfo: [URI] + [User-Agent] + [Body]

        Logic Fail-Fast:
        - Regex quét từ trái sang phải
        - Tấn công thường nằm ở URI (GET) hoặc User-Agent
        - Đặt Header trước Body → phát hiện sớm, tránh quét Body lớn

        Args:
            pkt: Đối tượng LayerInfo với các thuộc tính HTTP

        Returns:
            bytes: Composite payload cho phân tích
        """
        body = getattr(pkt, 'payload_bytes', None) or b''

        if not getattr(pkt, 'has_http', False):
            return body

        parts = []

        # Phần 1: URI
        uri = getattr(pkt, 'http_uri', None)
        if uri:
            if isinstance(uri, str):
                parts.append(uri.encode('utf-8', errors='ignore'))
            elif isinstance(uri, bytes):
                parts.append(uri)

        # Phần 2: User-Agent
        ua = getattr(pkt, 'http_user_agent', None)
        if ua:
            if isinstance(ua, str):
                parts.append(ua.encode('utf-8', errors='ignore'))
            elif isinstance(ua, bytes):
                parts.append(ua)

        # Body (chỉ thêm nếu không rỗng)
        if body:
            parts.append(body)

        return b' '.join(parts)


class PacketLayerExtractor:
    """Trích xuất tất cả layer từ gói tin trong MỘT lượt.

    Trách nhiệm:
    - Parse gói tin Scapy
    - Trích xuất thông tin IP + TCP + HTTP layer
    - Xây dựng HTTP composite payload cho feature extraction
    - Xử lý gói tin bị lỗi/hỏng một cách an toàn

    Hiệu năng: O(1) mỗi gói tin (single pass)

    LƯU Ý: HTTP parsing luôn được bật. Không hỗ trợ UDP/ICMP/raw payload.
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
