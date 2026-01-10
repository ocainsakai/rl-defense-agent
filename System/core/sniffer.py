"""
=============================================================================
NETWORK SNIFFER - Module bắt gói tin mạng
=============================================================================

CHỨC NĂNG:
- Wrapper cho Scapy sniff() function
- Hỗ trợ chế độ Live (Real-time) và Offline (PCAP file)
- Xử lý memory hiệu quả với store=0 (không lưu packets trong RAM)
- Tự động xử lý KeyboardInterrupt (Ctrl+C)

CHẾ ĐỘ HOẠT ĐỘNG:
1. Live Mode: Bắt gói tin trực tiếp từ network interface
2. Offline Mode: Đọc và xử lý file PCAP có sẵn

CÁCH SỬ DỤNG:
    from core.sniffer import NetworkSniffer
    
    # Khởi tạo sniffer
    sniffer = NetworkSniffer()
    
    # Callback xử lý mỗi packet
    def process_packet(pkt):
        print(f"Received: {pkt.summary()}")
    
    # Live capture (chạy với quyền Admin trên Windows)
    sniffer.start_live(
        interface="Ethernet",
        callback=process_packet,
        packet_count=100,       # None = unlimited
        bpf_filter="ip"         # BPF filter
    )
    
    # Hoặc đọc file PCAP
    sniffer.start_pcap(
        pcap_path="capture.pcap",
        callback=process_packet
    )

LƯU Ý:
- Trên Windows: Cần quyền Administrator và Npcap đã cài đặt
- Trên Linux: Cần quyền root hoặc CAP_NET_RAW capability
- store=0 là BẮT BUỘC để tránh tràn RAM khi chạy lâu dài
"""
    
import sys
from typing import Callable, Optional
from scapy.all import sniff

class NetworkSniffer:
    def __init__(self):
        self.is_running = False
        self.packet_count = 0

    # Cập nhật hàm start_live để hỗ trợ bộ lọc (filter)
    def start_live(self, interface: str, callback: Callable, 
                   packet_count: Optional[int] = None, 
                   bpf_filter: str = "ip"): # <--- THÊM THAM SỐ NÀY
        """
        Args:
            bpf_filter: Bộ lọc gói tin (VD: 'tcp port 80', 'ip', 'udp')
                        Mặc định là 'ip' để loại bỏ các gói tin lớp 2 (ARP) không cần thiết cho AI
        """
        print(f"\n[+] Đang lắng nghe trên giao diện: {interface}")
        print(f"[+] Bộ lọc BPF: {bpf_filter}") # In ra để debug
        self.is_running = True
        self.packet_count = 0
        
        def wrapped_callback(pkt):
            if self.is_running: # Kiểm tra cờ trước khi callback
                self.packet_count += 1
                callback(pkt)
        
        try:
            final_count = 0 if packet_count is None else packet_count
            # store=0 là BẮT BUỘC để tránh tràn RAM khi chạy lâu dài
            sniff(
                iface=interface, 
                prn=wrapped_callback, 
                filter=bpf_filter,  # Áp dụng bộ lọc BPF
                store=0,
                count=final_count  # Stop after N packets (None = unlimited)
            )
        except KeyboardInterrupt:
            print(f"\n[*] Dừng bởi người dùng (Đã xử lý {self.packet_count} gói)")
        except Exception as e:
            print(f"\n[!] Lỗi Sniffer: {e}")
        finally:
            self.stop()

    def start_pcap(self, pcap_path: str, callback: Callable, packet_count: Optional[int] = None):
        """
        Đọc file PCAP (Offline Mode)
        Args:
            pcap_path: Đường dẫn file .pcap
            callback: Hàm xử lý từng gói tin
            packet_count: Số lượng gói tin tối đa (None = đọc hết file)
        """
        print(f"\n[+] Đang đọc file PCAP: {pcap_path}")
        self.is_running = True
        self.packet_count = 0
        
        def wrapped_callback(pkt):
            self.packet_count += 1
            callback(pkt)
        
        try:
            import time
            start_time = time.time()
            
            # store=0 giúp đọc file lớn (vài GB) mà không tốn RAM
            sniff(
                offline=pcap_path, 
                prn=wrapped_callback, 
                store=0,
                count=packet_count  # Stop after N packets (None = read all)
            )
            
            elapsed = time.time() - start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            print(f"\n[✓] Hoàn thành: {self.packet_count:,} gói trong {elapsed:.1f}s ({rate:.0f} pkt/s)")
            
        except FileNotFoundError:
            print(f"\n[!] Lỗi: Không tìm thấy file {pcap_path}")
        except KeyboardInterrupt:
            print(f"\n[*] Dừng bởi người dùng (Đã xử lý {self.packet_count} gói)")
        except Exception as e:
            print(f"\n[!] Lỗi đọc PCAP: {e}")
        finally:
            self.stop()

    def stop(self):
        """Dừng quá trình bắt gói tin"""
        if self.is_running:
            self.is_running = False
    
    def get_stats(self) -> dict:
        """Lấy thống kê quá trình bắt gói"""
        return {
            'packet_count': self.packet_count,
            'is_running': self.is_running
        }