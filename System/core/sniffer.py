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
import logging
from typing import Callable, Optional
from scapy.all import sniff

logger = logging.getLogger(__name__)


class NetworkSniffer:
    def __init__(self):
        self.is_running = False
        self.packet_count = 0

    def start_live(self, interface: str, callback: Callable, 
                   packet_count: Optional[int] = None, 
                   bpf_filter: str = "ip") -> None:
        """
        Bắt gói tin trực tiếp từ network interface (Live Mode).

        Args:
            interface: Tên network interface (VD: 'Ethernet', 'eth0')
            callback: Hàm xử lý từng gói tin
            packet_count: Số lượng gói tin tối đa (None = unlimited)
            bpf_filter: Bộ lọc gói tin (VD: 'tcp port 80', 'ip', 'udp')
                        Mặc định là 'ip' để loại bỏ các gói tin lớp 2 (ARP) không cần thiết cho AI
        """
        logger.info(f"Đang lắng nghe trên giao diện: {interface}")
        logger.info(f"Bộ lọc BPF: {bpf_filter}")
        self.is_running = True
        self.packet_count = 0
        
        def wrapped_callback(pkt):
            if self.is_running:
                self.packet_count += 1
                callback(pkt)
        
        try:
            final_count = 0 if packet_count is None else packet_count
            # store=0 là BẮT BUỘC để tránh tràn RAM khi chạy lâu dài
            sniff(
                iface=interface, 
                prn=wrapped_callback, 
                filter=bpf_filter,
                store=0,
                count=final_count
            )
        except KeyboardInterrupt:
            logger.info(f"Dừng bởi người dùng (Đã xử lý {self.packet_count} gói)")
        except Exception as e:
            logger.error(f"Lỗi Sniffer: {e}", exc_info=True)
        finally:
            self.stop()

    def start_pcap(self, pcap_path: str, callback: Callable, packet_count: Optional[int] = None) -> None:
        """
        Đọc file PCAP (Offline Mode).

        Args:
            pcap_path: Đường dẫn file .pcap
            callback: Hàm xử lý từng gói tin
            packet_count: Số lượng gói tin tối đa (None = đọc hết file)
        """
        logger.info(f"Đang đọc file PCAP: {pcap_path}")
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
                count=packet_count
            )
            
            elapsed = time.time() - start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            logger.info(f"Hoàn thành: {self.packet_count:,} gói trong {elapsed:.1f}s ({rate:.0f} pkt/s)")
            
        except FileNotFoundError:
            logger.error(f"Không tìm thấy file {pcap_path}")
        except KeyboardInterrupt:
            logger.info(f"Dừng bởi người dùng (Đã xử lý {self.packet_count} gói)")
        except Exception as e:
            logger.error(f"Lỗi đọc PCAP: {e}", exc_info=True)
        finally:
            self.stop()

    def stop(self) -> None:
        """Dừng quá trình bắt gói tin."""
        if self.is_running:
            self.is_running = False
    
    def get_stats(self) -> dict:
        """Lấy thống kê quá trình bắt gói."""
        return {
            'packet_count': self.packet_count,
            'is_running': self.is_running
        }