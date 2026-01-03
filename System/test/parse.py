from scapy.all import IP, TCP, Raw
from core.packet_parser import PacketLayerExtractor

# 1. Tạo gói tin mẫu
pkt = IP(src="192.168.1.2", dst="8.8.8.8")/TCP(sport=12345, dport=80, flags="S")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

# 2. Khởi tạo extractor
extractor = PacketLayerExtractor(enable_http_parsing=True)

# 3. Phân tích gói tin
info = extractor.parse(pkt)

# 4. In kết quả
print(info.to_json())