import sys
import os
from scapy.all import conf, IP

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.sniffer import NetworkSniffer
from core.packet_parser import PacketLayerExtractor

# ==========================================
# CẤU HÌNH
# ==========================================
KALI_IP = "192.168.234.133" 
INTERFACE_NAME = "VMware Network Adapter VMnet8" 
# ==========================================

extractor = PacketLayerExtractor(enable_http_parsing=True)

# 1. Khởi tạo biến đếm toàn cục
GLOBAL_PACKET_COUNT = 0

def my_packet_callback(pkt):
    # 2. Phải có từ khóa global để Python cho phép sửa biến bên ngoài
    global GLOBAL_PACKET_COUNT
    
    try:
        # Lọc gói tin từ Kali
        if pkt.haslayer(IP) and pkt[IP].src == KALI_IP:
            
            # Phân tích trước
            info = extractor.parse(pkt)
            
            # --- [MẸO LỌC] ---
            # Chỉ in ra màn hình nếu gói tin CÓ PAYLOAD hoặc là ICMP
            # Các gói TCP bắt tay (SYN, ACK) rỗng sẽ bị ẩn đi cho đỡ rối mắt
            if info.has_payload or info.has_icmp:
                GLOBAL_PACKET_COUNT += 1
                info.packet_number = GLOBAL_PACKET_COUNT
                
                print(f"\n[!!!] PHÁT HIỆN DỮ LIỆU TỪ KALI")
                print(f"Packet #{info.packet_number} | Protocol: {info.protocol}")
                print(info.to_json())
                print("-" * 50)
            
    except Exception as e:
        pass

if __name__ == "__main__":
    sniffer = NetworkSniffer()
    
    if INTERFACE_NAME == "":
        iface = conf.iface
    else:
        iface = INTERFACE_NAME
    
    print(f"\n>>> Đang khởi động Sniffer trên: {iface}")
    print(f">>> CHẾ ĐỘ LỌC: TCP/ICMP từ IP {KALI_IP}")
    
    # Lọc cứng
    bpf_filter_str = f"host {KALI_IP} and (tcp or icmp)"
    
    sniffer.start_live(
        interface=iface, 
        callback=my_packet_callback,
        bpf_filter=bpf_filter_str 
    )