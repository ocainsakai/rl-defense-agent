import time
from typing import Dict, List
from scapy.all import IP, TCP, UDP, ICMP, Raw, DNS

from core.layer_info import LayerInfo


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
            'http_requests': 0         # Số HTTP request
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
            
            # Bước 4: Trích xuất tầng Application (HTTP, DNS) nếu có payload
            if self.enable_http_parsing and info.has_payload:
                self._extract_http_layer(info)      # HTTP: method, URI, host, status
                self._extract_dns_layer(packet, info)  # DNS: query
            
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
        Trích xuất thông tin tầng UDP (User Datagram Protocol)
        
        CHỨC NĂNG:
        - Lấy cổng nguồn và đích
        - Lấy độ dài gói tin UDP
        - UDP không có connection (không giống TCP), đơn giản và nhanh hơn
        """
        if packet.haslayer(UDP):
            info.has_udp = True
            info.udp_sport = packet[UDP].sport      # Cổng nguồn
            info.udp_dport = packet[UDP].dport      # Cổng đích
            info.udp_len = packet[UDP].len          # Độ dài gói tin UDP
            
            self.stats['udp_packets'] += 1
    
    def _extract_icmp_layer(self, packet, info: LayerInfo):
        """
        Trích xuất thông tin tầng ICMP (Internet Control Message Protocol)
        
        CHỨC NĂNG:
        - ICMP dùng cho ping, traceroute, báo lỗi
        - Lấy ICMP type (8=Echo Request/Ping, 0=Echo Reply, 3=Destination Unreachable)
        - Lấy ICMP code (chi tiết thêm về type)
        """
        if packet.haslayer(ICMP):
            info.has_icmp = True
            info.icmp_type = packet[ICMP].type      # Loại ICMP (8=ping request, 0=ping reply)
            info.icmp_code = packet[ICMP].code      # Mã chi tiết
            
            self.stats['icmp_packets'] += 1
    
    def _extract_payload(self, packet, info: LayerInfo):
        """
        Trích xuất Payload - dữ liệu thô của gói tin
        
        CHỨC NĂNG:
        - Lấy dữ liệu thực tế được truyền trong gói tin (nội dung HTTP, DNS, v.v.)
        - Chuyển payload thành bytes để xử lý
        - Đếm độ dài payload
        """
        if packet.haslayer(Raw):
            info.has_payload = True
            info.payload_bytes = bytes(packet[Raw].load)   # Dữ liệu thô dạng bytes
            info.payload_length = len(info.payload_bytes)  # Độ dài payload
            
            self.stats['with_payload'] += 1

    ##################################################################
    def _extract_http_layer(self, info: LayerInfo):
        """
        Phân tích tầng HTTP từ payload (cả Request và Response)
        
        CHỨC NĂNG:
        - Phát hiện và trích xuất HTTP Request (GET, POST, PUT, DELETE, v.v.)
        - Phát hiện và trích xuất HTTP Response (Status Code: 200, 404, 500, v.v.)
        - Lấy thông tin HTTP headers (Host, User-Agent)
        - Lấy HTTP method, URI, và status code
        """
        if not info.payload_bytes:
            return
        
        try:
            # Chuyển payload bytes thành chuỗi UTF-8 (bỏ qua lỗi decode)
            payload_str = info.payload_bytes.decode('utf-8', errors='ignore')
            
            # 1. PHÁT HIỆN VÀ XỬ LÝ HTTP REQUEST (GET, POST, PUT, DELETE, v.v.)
            if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                info.has_http = True
                
                # Tách payload thành các dòng (HTTP dùng \r\n làm dấu phân cách)
                lines = payload_str.split('\r\n')
                
                # Phân tích dòng đầu tiên: "GET /index.html HTTP/1.1"
                request_line = lines[0]
                parts = request_line.split(' ')
                
                if len(parts) >= 2:
                    info.http_method = parts[0]   # Method: GET, POST, PUT, v.v.
                    info.http_uri = parts[1]      # URI: /index.html, /api/users, v.v.
                
                # Phân tích các HTTP headers (Host, User-Agent, v.v.)
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key == 'host':
                            info.http_host = value           # Host: www.example.com
                        elif key == 'user-agent':
                            info.http_user_agent = value     # User-Agent: Mozilla/5.0...
                
                self.stats['http_requests'] += 1

            # 2. PHÁT HIỆN VÀ XỬ LÝ HTTP RESPONSE (để lấy Status Code)
            elif payload_str.startswith('HTTP/'):
                # Ví dụ dòng đầu tiên: "HTTP/1.1 404 Not Found"
                first_line = payload_str.split('\r\n')[0]
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    try:
                        # parts[1] chính là HTTP Status Code (200=OK, 404=Not Found, 500=Server Error)
                        info.http_status = int(parts[1])
                    except ValueError:
                        pass  # Nếu không parse được thì bỏ qua
        except:
            pass  # Xử lý lỗi an toàn: nếu có lỗi thì bỏ qua
    
    def _extract_dns_layer(self, packet, info: LayerInfo):
        """
        Trích xuất thông tin DNS (Domain Name System)
        
        CHỨC NĂNG:
        - Lấy DNS query (tên miền được truy vấn)
        - Ví dụ: www.google.com, api.example.com
        - DNS dùng để chuyển tên miền thành địa chỉ IP
        """
        if packet.haslayer(DNS):
            info.has_dns = True
            dns_layer = packet[DNS]
            
            # Lấy DNS query (qd = question domain)
            if dns_layer.qd:
                info.dns_query = dns_layer.qd.qname.decode('utf-8', errors='ignore')
    
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
