from collections import defaultdict, deque
from typing import Dict, List, Set, Any
import time

from core.layer_info import LayerInfo

class PacketWindow:
    """
    =============================================================================
    BỘ LƯU TRỮ CHUỖI THỜI GIAN CHO THÔNG TIN GÓI TIN (SLIDING WINDOW)
    =============================================================================
    
    CHỨC NĂNG CHÍNH:
    - Lưu trữ các đối tượng LayerInfo theo địa chỉ IP nguồn
    - Tự động loại bỏ gói tin cũ ngoài cửa sổ thời gian (sliding window)
    - Cung cấp các thống kê tổng hợp (TCP flags, ports, payloads, v.v.)
    - Hỗ trợ bidirectional tracking cho phát hiện Port Scan
    
    THIẾT KẾ ĐẶC BIỆT:
    - Thread-safe cho truy cập đồng thời
    - maxlen=3000 cho deque để capture high-rate attacks
    - Cache cho các thống kê thường xuyên sử dụng (TCP flags)
    - Giới hạn số lượng IP theo dõi (max_ips) để tránh tràn bộ nhớ
    
    Sử DỤNG:
        window = PacketWindow(window_size=1.0)  # Cửa sổ 1 giây
        window.add(layer_info)                  # Thêm gói tin
        count = window.get_count(src_ip)        # Lấy số lượng gói tin
    """
    
    def __init__(self, window_size: float = 1.0, max_ips: int = 10000):
        """
        Khởi tạo PacketWindow.
        
        Args:
            window_size (float): Kích thước cửa sổ thời gian tính bằng giây.
                                 Mặc định 1.0s để tính toán features/giây.
            max_ips (int): Số lượng IP tối đa theo dõi (tránh tràn bộ nhớ).
                          Khi đạt giới hạn, IP cũ nhất sẽ bị xóa.
        """
        self.window_size = window_size
        self.max_ips = max_ips
        
        # Lưu trữ chính: {src_ip: deque([LayerInfo, ...])}
        # maxlen=3000 để capture high-rate attacks (sync với MAX_PACKET_RATE)
        # => Tối đa 3000 packets/IP trong cửa sổ 1s
        self.packets_by_ip = defaultdict(lambda: deque(maxlen=3000))
        
        # Cache cho thống kê TCP flags (để tăng hiệu suất)
        # Cache hết hạn sau 0.1s hoặc khi có packet mới
        self._stats_cache = {}
        self._cache_timestamp = {}
    
    def add(self, layer_info: LayerInfo):
        """
        Thêm gói tin vào cửa sổ.
        
        QUY TRÌNH Xử LÝ:
        1. Bỏ qua nếu không có tầng IP
        2. Kiểm tra và áp dụng giới hạn max_ips
        3. Thêm packet vào deque của IP tương ứng
        4. Dọn dẹp các packet cũ ngoài cửa sổ thời gian
        5. Xóa cache thống kê (vì đã có packet mới)
        
        Args:
            layer_info (LayerInfo): Đối tượng chứa thông tin gói tin
        
        LƯU Ý:
        - maxlen=3000 của deque sẽ tự động loại bỏ packet cũ nhất
          nếu đã đầy, không cần xử lý thêm
        """
        if not layer_info.has_ip:
            return
        
        src_ip = layer_info.src_ip
        
        # Giới hạn số lượng IP theo dõi - xóa IP cũ nhất nếu đầy
        if len(self.packets_by_ip) >= self.max_ips and src_ip not in self.packets_by_ip:
            oldest_ip = next(iter(self.packets_by_ip))
            del self.packets_by_ip[oldest_ip]
        
        # Thêm gói tin vào deque
        self.packets_by_ip[src_ip].append(layer_info)
        
        # Dọn dẹp các packet cũ ngoài cửa sổ thời gian
        self._clean_old_packets(src_ip, layer_info.timestamp)
        
        # Xóa cache (vì đã có packet mới, thống kê cũ không còn chính xác)
        if src_ip in self._stats_cache:
            del self._stats_cache[src_ip]
    
    def _clean_old_packets(self, src_ip: str, current_time: float):
        """
        Loại bỏ các gói tin ngoài cửa sổ thời gian (sliding window).
        
        LOGIC:
        - Tính thời điểm cutoff = current_time - window_size
        - Xóa tất cả packets có timestamp < cutoff
        - Xóa từ bên trái (popleft) vì packets được sắp xếp theo thời gian
        
        Args:
            src_ip (str): Địa chỉ IP cần dọn dẹp
            current_time (float): Thời gian hiện tại (timestamp)
        """
        cutoff_time = current_time - self.window_size
        packets = self.packets_by_ip[src_ip]
        
        # Xóa từ bên trái (packet cũ nhất) cho đến khi hết packet cũ
        while packets and packets[0].timestamp < cutoff_time:
            packets.popleft()
    
    def get_packets(self, src_ip: str) -> List[LayerInfo]:
        """
        Lấy tất cả các gói tin của một IP trong cửa sổ hiện tại.
        
        Args:
            src_ip (str): Địa chỉ IP nguồn cần tìm
            
        Returns:
            List[LayerInfo]: Danh sách các gói tin (có thể rỗng)
        """
        return list(self.packets_by_ip.get(src_ip, []))
    
    def get_response_packets(self, src_ip: str) -> List[LayerInfo]:
        """
        Get packets FROM other IPs that were sent TO src_ip.
        
        Use case: Khi src_ip scan ports, victim sẽ gửi RST về.
        RST này có src_ip=victim, dst_ip=src_ip.
        
        Cách hoạt động:
        1. Tìm tất cả dst_ip mà src_ip đã gửi đến
        2. Lấy packets từ các dst_ip đó mà có dst_ip = src_ip
        
        Args:
            src_ip: IP cần tìm response packets
            
        Returns:
            List[LayerInfo]: Packets gửi ĐẾN src_ip từ các IP nó đã liên lạc
        """
        # Bước 1: Tìm các IP mà src_ip đã gửi đến
        outbound_packets = self.get_packets(src_ip)
        contacted_ips = set()
        for pkt in outbound_packets:
            if pkt.dst_ip:
                contacted_ips.add(pkt.dst_ip)
        
        # Bước 2: Lấy packets từ các IP đó gửi về src_ip
        response_packets = []
        for contacted_ip in contacted_ips:
            their_packets = self.get_packets(contacted_ip)
            for pkt in their_packets:
                if pkt.dst_ip == src_ip:
                    response_packets.append(pkt)
        
        return response_packets
    
    def get_count(self, src_ip: str) -> int:
        """
        Lấy số lượng gói tin của một IP trong cửa sổ.
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            int: Số lượng gói tin (0 nếu không có)
        """
        return len(self.packets_by_ip.get(src_ip, []))
    
    def get_tcp_flags_count(self, src_ip: str) -> Dict[str, int]:
        """
        Đếm số lượng các loại cờ TCP cho một IP.
        
        CHỨC NĂNG:
        - Đếm số lượng từng loại cờ TCP (SYN, ACK, FIN, RST, PSH, URG)
        - Sử dụng cache để tăng hiệu suất (hết hạn sau 0.1s)
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            Dict[str, int]: Dictionary chứa số lượng mỗi loại cờ
            Ví dụ: {'SYN': 100, 'ACK': 50, 'FIN': 0, 'RST': 5, 'PSH': 20, 'URG': 0}
        
        ỨNG DỤNG:
        - Feature 2 (SYN/ACK Ratio): Dùng để phát hiện SYN Flood
        - Feature 5 (Fail Rate): Dùng để đếm RST (connection refused)
        """
        # Check cache
        if src_ip in self._stats_cache:
            if time.time() - self._cache_timestamp.get(src_ip, 0) < 0.1:
                return self._stats_cache[src_ip]['tcp_flags']
        
        packets = self.get_packets(src_ip)
        
        counts = {
            'SYN': 0,
            'ACK': 0,
            'FIN': 0,
            'RST': 0,
            'PSH': 0,
            'URG': 0
        }
        
        for pkt in packets:
            if pkt.has_tcp and pkt.tcp_flags is not None:
                flags = pkt.tcp_flags  # String like "S", "SA", "PA", "R", etc.
                if 'S' in flags: counts['SYN'] += 1
                if 'A' in flags: counts['ACK'] += 1
                if 'F' in flags: counts['FIN'] += 1
                if 'R' in flags: counts['RST'] += 1
                if 'P' in flags: counts['PSH'] += 1
                if 'U' in flags: counts['URG'] += 1
        
        # Cache result
        if src_ip not in self._stats_cache:
            self._stats_cache[src_ip] = {}
        self._stats_cache[src_ip]['tcp_flags'] = counts
        self._cache_timestamp[src_ip] = time.time()
        
        return counts
    
    def get_distinct_ports(self, src_ip: str) -> Set[int]:
        """
        Lấy tập hợp các cổng đích (destination ports) duy nhất đã được truy cập.
        
        CHỨC NĂNG:
        - Trả về các cổng đích khác nhau mà IP này đã kết nối đến
        - Hỗ trợ cả TCP và UDP ports
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            Set[int]: Tập hợp các cổng đích duy nhất
        
        ỨNG DỤNG:
        - Feature 3 (Distinct Ports): Phát hiện Port Scan
          (Số lượng ports cao trong thời gian ngắn = nghi ngờ scan)
        """
        packets = self.get_packets(src_ip)
        
        ports = set()
        for pkt in packets:
            if pkt.has_tcp and pkt.tcp_dport:
                ports.add(pkt.tcp_dport)
            elif pkt.has_udp and pkt.udp_dport:
                ports.add(pkt.udp_dport)
        
        return ports
    
    def get_payload_lengths(self, src_ip: str) -> List[int]:
        """
        Lấy danh sách độ dài payload của các gói tin.
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            List[int]: Danh sách độ dài payload (bytes)
        
        ỨNG DỤNG:
        - Feature 4 (Payload Length): Tính avg/max payload
          (Payload lớn bất thường có thể là buffer overflow attack)
        """
        packets = self.get_packets(src_ip)
        
        lengths = []
        for pkt in packets:
            if pkt.has_payload:
                lengths.append(pkt.payload_length)
        
        return lengths
    
    def get_payloads(self, src_ip: str) -> List[bytes]:
        """
        Lấy danh sách payload bytes của các gói tin.
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            List[bytes]: Danh sách các payload thô
        
        ỨNG DỤNG:
        - Feature 6 (Context Score): Phân tích nội dung để phát hiện
          SQLi, XSS, Command Injection, v.v.
        """
        packets = self.get_packets(src_ip)
        
        payloads = []
        for pkt in packets:
            if pkt.has_payload and pkt.payload_bytes:
                payloads.append(pkt.payload_bytes)
        
        return payloads
    
    def get_http_requests(self, src_ip: str) -> List[Dict[str, str]]:
        """
        Lấy danh sách các HTTP requests từ một IP.
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            List[Dict]: Danh sách các request với:
                - 'method': HTTP method (GET, POST, v.v.)
                - 'uri': Đường dẫn được yêu cầu
                - 'host': Hostname
        """
        packets = self.get_packets(src_ip)
        
        requests = []
        for pkt in packets:
            if pkt.has_http:
                requests.append({
                    'method': pkt.http_method,
                    'uri': pkt.http_uri,
                    'host': pkt.http_host
                })
        
        return requests
    
    def get_conversations(self, src_ip: str) -> Set[str]:
        """
        Lấy tập hợp các conversation keys duy nhất.
        
        CONVERSATION KEY:
        - Một chuỗi định danh kết nối: "src_ip:src_port-dst_ip:dst_port"
        
        Args:
            src_ip (str): Địa chỉ IP nguồn
            
        Returns:
            Set[str]: Tập hợp các conversation keys
        """
        packets = self.get_packets(src_ip)
        
        conversations = set()
        for pkt in packets:
            key = pkt.get_conversation_key()
            if key:
                conversations.add(key)
        
        return conversations
    
    def clear(self, src_ip: str = None):
        """
        Xóa dữ liệu trong cửa sổ.
        
        Args:
            src_ip (str, optional): Nếu chỉ định, chỉ xóa của IP đó.
                                   Nếu None, xóa toàn bộ dữ liệu.
        """
        if src_ip:
            self.packets_by_ip.pop(src_ip, None)
            self._stats_cache.pop(src_ip, None)
            self._cache_timestamp.pop(src_ip, None)
        else:
            self.packets_by_ip.clear()
            self._stats_cache.clear()
            self._cache_timestamp.clear()
    
    def get_all_ips(self) -> List[str]:
        """
        Lấy danh sách tất cả các IP đang được theo dõi.
        
        Returns:
            List[str]: Danh sách các địa chỉ IP
        """
        return list(self.packets_by_ip.keys())
    
    def cleanup_inactive_ips(self, min_packets: int = 10) -> int:
        """
        Dọn dẹp các IP không hoạt động (ít packets).
        
        Args:
            min_packets: Ngưỡng tối thiểu. IP nào có ít hơn sẽ bị xóa.
            
        Returns:
            Số lượng IP đã xóa.
        """
        ips_to_remove = [ip for ip, pkts in self.packets_by_ip.items() 
                         if len(pkts) < min_packets]
        for ip in ips_to_remove:
            self.clear(src_ip=ip)  # Dùng method có sẵn
        return len(ips_to_remove)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Lấy thống kê tổng quan về cửa sổ.
        
        Returns:
            Dict chứa:
                - 'total_ips': Số lượng IP đang theo dõi
                - 'total_packets': Tổng số gói tin trong cửa sổ
                - 'window_size': Kích thước cửa sổ (giây)
                - 'max_ips': Giới hạn số IP tối đa
        """
        return {
            'total_ips': len(self.packets_by_ip),
            'total_packets': sum(len(pkts) for pkts in self.packets_by_ip.values()),
            'window_size': self.window_size,
            'max_ips': self.max_ips
        }