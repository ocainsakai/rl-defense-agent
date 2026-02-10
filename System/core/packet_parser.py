import time
from typing import Dict, List, Optional
from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS
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
            return True
        
        # HTTP Response
        if packet.haslayer(HTTPResponse):
            info.has_http = True
            http_resp = packet[HTTPResponse]
            try:
                info.http_status = int(http_resp.Status_Code) if http_resp.Status_Code else None
            except (ValueError, TypeError):
                info.http_status = None
            return True
        
        return False
    
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
                    # X-Forwarded-For có thể chứa nhiều IP, lấy IP đầu tiên
                    xff_value = line.split(':', 1)[-1].strip()
                    info.x_real_ip = xff_value.split(',')[0].strip()
                    
        except Exception:
            pass  # Ignore parse errors
    
    @staticmethod
    def build_composite_payload(pkt) -> bytes:
        """
        Build composite payload: [URI] + [User-Agent] + [Body]
        
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
        
        # Header 1: URI (quan trọng cho SQLi/XSS qua GET params)
        uri = getattr(pkt, 'http_uri', None)
        if uri:
            if isinstance(uri, str):
                parts.append(uri.encode('utf-8', errors='ignore'))
            elif isinstance(uri, bytes):
                parts.append(uri)
        
        # Header 2: User-Agent (vector tấn công phổ biến)
        ua = getattr(pkt, 'http_user_agent', None)
        if ua:
            if isinstance(ua, str):
                parts.append(ua.encode('utf-8', errors='ignore'))
            elif isinstance(ua, bytes):
                parts.append(ua)
        
        # Cuối cùng là Body
        parts.append(body)
        
        # Nối bằng space để regex \s hoạt động giữa các phần
        return b' '.join(parts)


class PacketLayerExtractor:
    """
    Extract all layers from packet in ONE pass
    
    Responsibilities:
    - Parse Scapy packet
    - Extract all layer information
    - Handle malformed packets gracefully
    
    Performance: O(1) per packet (single pass)
    
    GIẢI THÍCH:
    Class này chịu trách nhiệm trích xuất thông tin từ các gói tin mạng.
    - Phân tích gói tin Scapy chỉ trong 1 lần duyệt (hiệu suất cao)
    - Trích xuất thông tin từ tất cả các tầng (IP, TCP, UDP, ICMP, HTTP, DNS)
    - Xử lý an toàn các gói tin bị lỗi/hỏng
    """
    
    def __init__(self, enable_http_parsing: bool = False, use_packet_time: bool = False):
        """
        Hàm khởi tạo PacketLayerExtractor
        
        Args:
            enable_http_parsing: Bật/tắt phân tích HTTP headers (tốn thêm tài nguyên)
            use_packet_time: Dùng timestamp từ PCAP thay vì thời gian hiện tại
        
        CHỨC NĂNG:
        - Khởi tạo các cấu hình cho việc phân tích gói tin
        - Thiết lập bộ đếm thống kê để theo dõi các loại gói tin
        """
        self.enable_http_parsing = enable_http_parsing
        self.use_packet_time = use_packet_time
        
        # Thống kê: Đếm số lượng các loại gói tin đã xử lý
        self.stats = {
            'total_packets': 0,        # Tổng số gói tin
            'malformed_packets': 0,    # Số gói tin bị lỗi/hỏng
            'ip_packets': 0,           # Số gói tin IP
            'tcp_packets': 0,          # Số gói tin TCP
            'udp_packets': 0,          # Số gói tin UDP
            'icmp_packets': 0,         # Số gói tin ICMP
            'with_payload': 0,         # Số gói tin có payload/dữ liệu
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
        
        CHỨC NĂNG:
        - Đây là hàm chính để phân tích 1 gói tin
        - Trích xuất thông tin từ tất cả các tầng: IP, TCP, UDP, ICMP, Payload, HTTP, DNS
        - Xử lý an toàn nếu gói tin bị lỗi
        """
        self.stats['total_packets'] += 1
        
        # Lấy timestamp: Ưu tiên dùng thời gian từ PCAP, nếu không có thì dùng thời gian hiện tại
        if self.use_packet_time and hasattr(packet, 'time'):
            pkt_timestamp = float(packet.time)
        else:
            pkt_timestamp = time.time()
        
        # Khởi tạo đối tượng LayerInfo để lưu thông tin gói tin
        info = LayerInfo(
            timestamp=pkt_timestamp,
            packet_number=packet_number
        )
        
        try:
            # Bước 1: Trích xuất tầng IP (địa chỉ IP nguồn, đích, TTL, v.v.)
            self._extract_ip_layer(packet, info)
            
            # Bước 2: Trích xuất tầng Transport (TCP, UDP, ICMP)
            self._extract_tcp_layer(packet, info)   # TCP: port, flags, seq, ack
            self._extract_udp_layer(packet, info)   # UDP: port, length
            self._extract_icmp_layer(packet, info)  # ICMP: type, code
            
            # Bước 3: Trích xuất Payload (dữ liệu thô)
            self._extract_payload(packet, info)
            
            # Bước 4: Trích xuất tầng Application (HTTP) sử dụng Scapy layers
            if self.enable_http_parsing:
                self._extract_http_layer(packet, info)
            
            # Finalize: Sanitize data (decode bytes -> str)
            info.sanitize()
            
        except Exception as e:
            self.stats['malformed_packets'] += 1
            # Ghi log nhưng không crash chương trình (xử lý lỗi an toàn)
            # print(f"[!] Error extracting packet {packet_number}: {e}")
        
        return info
    
    def _extract_ip_layer(self, packet, info: LayerInfo):
        """
        Trích xuất thông tin tầng IP (Internet Protocol Layer)
        
        CHỨC NĂNG:
        - Lấy địa chỉ IP nguồn và đích
        - Lấy TTL (Time To Live) - số hop tối đa
        - Lấy version IP (IPv4 hoặc IPv6)
        - Lấy protocol (giao thức tầng trên: TCP=6, UDP=17, ICMP=1)
        """
        if packet.haslayer(IP):
            info.has_ip = True
            info.ip_version = packet[IP].version    # Phiên bản IP (4 hoặc 6)
            info.src_ip = packet[IP].src           # Địa chỉ IP nguồn
            info.dst_ip = packet[IP].dst           # Địa chỉ IP đích
            info.ttl = packet[IP].ttl              # Time To Live
            info.ip_len = packet[IP].len           # Độ dài gói tin IP
            info.protocol = packet[IP].proto       # Giao thức (6=TCP, 17=UDP, 1=ICMP)
            
            self.stats['ip_packets'] += 1
    
    def _extract_tcp_layer(self, packet, info: LayerInfo):
        """
        Trích xuất thông tin tầng TCP (Transmission Control Protocol)
        
        CHỨC NĂNG:
        - Lấy cổng nguồn và đích (source/destination port)
        - Lấy TCP flags (SYN, ACK, FIN, RST, PSH, URG) - quan trọng cho phân tích kết nối
        - Lấy sequence number và acknowledgment number
        - Lấy window size (kích thước cửa sổ nhận)
        """
        if packet.haslayer(TCP):
            info.has_tcp = True
            info.tcp_sport = packet[TCP].sport      # Cổng nguồn (source port)
            info.tcp_dport = packet[TCP].dport      # Cổng đích (destination port)
            info.tcp_flags = packet[TCP].flags      # Cờ TCP (SYN, ACK, FIN, etc.)
            info.tcp_seq = packet[TCP].seq          # Sequence number
            info.tcp_ack = packet[TCP].ack          # Acknowledgment number
            info.tcp_window = packet[TCP].window    # Window size
            
            self.stats['tcp_packets'] += 1
    
    def _extract_udp_layer(self, packet, info: LayerInfo):
        """
        Trích xuất tầng UDP - Chỉ lấy độ dài nếu cần
        """
        if packet.haslayer(UDP):
            info.has_udp = True
            info.udp_sport = packet[UDP].sport
            info.udp_dport = packet[UDP].dport
            info.udp_len = packet[UDP].len  

            self.stats['udp_packets'] += 1

    def _extract_icmp_layer(self, packet, info: LayerInfo):
        """
        ICMP Layer - Giữ tối giản
        """
        if packet.haslayer(ICMP):
            info.has_icmp = True
            info.icmp_type = packet[ICMP].type 
            info.icmp_code = packet[ICMP].code

            self.stats['icmp_packets'] += 1
    
    def _extract_payload(self, packet, info: LayerInfo):
        """
        Trích xuất Payload - Tối ưu hóa
        """
        if packet.haslayer(Raw):
            info.has_payload = True
            info.payload_bytes = bytes(packet[Raw].load)
            info.payload_length = len(info.payload_bytes)

            self.stats['with_payload'] += 1

    def _extract_http_layer(self, packet, info: LayerInfo):
        """
        Phân tích HTTP sử dụng HttpPayloadExtractor.
        Delegate logic extraction, chỉ giữ lại stats counting.
        """
        if HttpPayloadExtractor.extract_http_info(packet, info):
            self.stats['http_requests'] += 1

    
    def parse(self, packet, packet_number: int = 0) -> LayerInfo:
        """
        Bí danh (alias) cho hàm extract() - để tương thích ngược
        
        CHỨC NĂNG:
        - Gọi hàm extract() bên trong
        - Dùng để tương thích với code cũ
        """
        return self.extract(packet, packet_number)
    
    def extract_batch(self, packets: List) -> List[LayerInfo]:
        """
        Trích xuất nhiều gói tin cùng lúc (batch processing)
        
        Args:
            packets: Danh sách các gói tin Scapy
        
        Returns:
            Danh sách các đối tượng LayerInfo
        
        CHỨC NĂNG:
        - Xử lý nhiều gói tin một lúc, hiệu quả hơn xử lý từng gói
        - Dùng list comprehension để tối ưu tốc độ
        """
        return [self.extract(pkt, i) for i, pkt in enumerate(packets)]
    
    def get_stats(self) -> Dict[str, int]:
        """
        Lấy thống kê về các gói tin đã xử lý
        
        Returns:
            Dictionary chứa số liệu thống kê
        
        CHỨC NĂNG:
        - Trả về bản sao của thống kê (tránh thay đổi trực tiếp)
        - Hiển thị số lượng các loại gói tin: IP, TCP, UDP, HTTP, v.v.
        """
        return self.stats.copy()
    
    def reset_stats(self):
        """
        Reset (đặt lại) tất cả bộ đếm thống kê về 0
        
        CHỨC NĂNG:
        - Đặt lại tất cả các bộ đếm về 0
        - Dùng khi bắt đầu phân tích gói tin mới
        """
        for key in self.stats:
            self.stats[key] = 0
