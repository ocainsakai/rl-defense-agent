import threading
import time
import sys
import csv
import logging
from datetime import datetime
from collections import Counter
from scapy.all import sniff, conf

# TỐI ƯU HÓA SCAPY CORE
# 1. Tắt kiểm tra Checksum (Tốn CPU và không cần thiết cho Sniffer)
conf.checkIPaddr = False 
# 2. Tắt phân giải Promiscuous (nếu interface đã set)
# conf.sniff_promisc = False

# Import core modules
from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.packet_queue import PacketQueue
from core.sniffer import NetworkSniffer
from feature.calculator import FlowFeatureCalculator
# from config.data_params import WINDOW_SIZE_SECONDS
# from config import ai_config as config
WINDOW_SIZE_SECONDS = 1.0

from logging.handlers import RotatingFileHandler
import os

# ... imports ...

# Configure logging
# 1. Tạo thư mục logs nếu chưa có
if not os.path.exists("logs"):
    os.makedirs("logs")

# 2. Cấu hình Handler
log_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%H:%M:%S')

# File Handler: Ghi lại tất cả (DEBUG level), xoay vòng 10MB/file, giữ 5 file backup
file_handler = RotatingFileHandler("logs/nids.log", maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_formatter)

# Console Handler: Chỉ in INFO trở lên
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

# Setup Logger
logger = logging.getLogger("NIDS_Live")
logger.setLevel(logging.DEBUG) # Logger gốc bắt tất cả
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class RealTimeNIDS:
    """
    Hệ thống phát hiện xâm nhập thời gian thực (Real-time NIDS)
    Sử dụng kiến trúc Đa luồng (Multi-threading):
    - Thread 1 (Capture): Bắt gói tin -> Queue
    - Thread 2 (Analyze): Queue -> Phân tích -> Detection
    """
    
    def __init__(self, interface: str, window_size: float = 1.0, output_file: str = "live_features.csv"):
        self.interface = interface
        self.window_size = window_size
        self.output_file = output_file
        self.is_running = False
        
        # 0. Khởi tạo CSV file
        try:
            self.csv_file = open(self.output_file, mode='w', newline='', encoding='utf-8')
            self.csv_writer = csv.writer(self.csv_file)
            # Write Header
            feature_names = FlowFeatureCalculator.get_feature_names()
            feature_headers = [
                f"F{i+1:02d}_{name}_Raw" for i, name in enumerate(feature_names)
            ]
            headers = ["Timestamp", "SrcIP", "DstIP", "Protocol"] + feature_headers  # 20 RAW Features
            self.csv_writer.writerow(headers)
            self.csv_file.flush()
        except Exception as e:
            print(f"[!] Error opening CSV file: {e}")
            self.csv_file = None
            self.csv_writer = None
        
        # 1. Khởi tạo các thành phần cốt lõi
        self.packet_queue = PacketQueue(max_size=10000)  # Giới hạn 10k packets để bảo vệ RAM
        self.parser = PacketLayerExtractor()
        self.flow_manager = FlowManager(window_size=window_size)
        self.feature_calc = FlowFeatureCalculator()
        self.sniffer = NetworkSniffer() # Tách biệt logic sniffer
        
        # Thống kê hiệu năng (thread-safe Counter)
        self.stats = Counter(captured=0, processed=0, dropped=0, alerts=0)

    def _capture_loop(self):
        """
        Luồng Capture: Sử dụng NetworkSniffer để bắt gói tin.
        """
        logger.info(f"[Capture] Bắt đầu lắng nghe trên {self.interface}...")
        
        def capture_callback(pkt):
            if not self.is_running:
                return
            
            # Đẩy vào queue (non-blocking)
            success = self.packet_queue.put(pkt, block=False)
            
            if success:
                self.stats['captured'] += 1
            else:
                self.stats['dropped'] += 1
                if self.stats['dropped'] % 100 == 0:
                    logger.warning(f"[Capture] Queue đầy! Đã drop {self.stats['dropped']} gói tin.")

        # Gọi NetworkSniffer (block thread này cho đến khi stop)
        self.sniffer.start_live(
            interface=self.interface,
            callback=capture_callback,
            bpf_filter="ip and not broadcast and not multicast"
        )
        logger.info("[Capture] Đã dừng.")

    def stop(self):
        """Dừng hệ thống"""
        self.is_running = False
        self.sniffer.stop() # Dừng sniffer
        
        # Close CSV
        if hasattr(self, 'csv_file') and self.csv_file:
            self.csv_file.close()
            
        time.sleep(1)
        logger.info("Hệ thống đã tắt.")

    def _analysis_loop(self):
        """
        Luồng Analyze: Lấy từ Queue, parse, ghép luồng và phát hiện tấn công.
        """
        logger.info("[Analyze] Bắt đầu xử lý gói tin...")
        
        while self.is_running or not self.packet_queue.empty():
            # 1. Lấy gói tin từ Queue (timeout 1s để check is_running)
            pkt = self.packet_queue.get(block=True, timeout=1.0)
            
            if pkt is None:
                continue # Timeout, check lại is_running
            
            try:
                # 2. Parse gói tin (Fast-Path)
                # PacketLayerExtractor giờ đã tối ưu, chỉ lấy thông tin cần thiết
                layer_info = self.parser.extract(pkt)
                
                # 3. Quản lý luồng (Flow Reassembly)
                flow = self.flow_manager.process_packet(layer_info)
                
                self.stats['processed'] += 1
                
                # 4. Kiểm tra tấn công (Detection Logic) - Chỉ check khi Flow có update
                if flow:
                    self._check_threats(flow)
                    
            except Exception as e:
                logger.error(f"[Analyze] Lỗi xử lý: {e}")
                
        logger.info("[Analyze] Đã dừng.")

    def _check_threats(self, flow):
        """
        Kiểm tra các dấu hiệu tấn công dựa trên Feature.
        Đây là logic "Sơ khai" - sau này sẽ thay bằng AI Model.
        """
        # Chỉ check flows đã đủ lớn (ví dụ > 5 packets) để tránh false positive
        if flow.get_packet_count() < 5:
            return

        # Tính toán features (Trên 1 flow cụ thể)
        # IMPORTANT: Set window_size for F1 calculation
        flow.analysis_window_size = self.window_size
        
        # Raw Features (20 features) cho CSV export
        features_raw = self.feature_calc.calculate_all([flow])

        # Export CSV
        if self.csv_writer:
            try:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                src = flow.src_ip
                dst = flow.dst_ip
                proto = "TCP"

                row = [timestamp, src, dst, proto] + \
                      [f"{v:.4f}" for v in features_raw]

                self.csv_writer.writerow(row)
                if self.stats['processed'] % 10 == 0:
                    self.csv_file.flush()
            except Exception as e:
                logger.error(f"[CSV] Error writing row: {e}")

        # --- RULE-BASED DETECTION (DEMO) ---
        # Index theo FEATURE_ORDER (0-based):
        #   [0]  F1  packet_rate        [1]  F2  syn_ack_ratio
        #   [12] F13 crs_sqli_score     [17] F18 crs_xss_score
        f1_pkt_rate  = features_raw[0]   # packet_rate
        f2_syn_ratio = features_raw[1]   # syn_ack_ratio
        f13_sqli     = features_raw[12]  # crs_sqli_score  (F13)
        f18_xss      = features_raw[17]  # crs_xss_score   (F18)

        # 1. Phát hiện DoS/Flood (F1 > 2400 pkts/s = 80% of MAX_PACKET_RATE 3000)
        if f1_pkt_rate > 2400:
            self._alert(flow.src_ip, "High Packet Rate (Possible DoS)", f"Rate={f1_pkt_rate:.0f} pkt/s")

        # 2. Phát hiện SYN Flood (F2 > 0.9)
        if f2_syn_ratio > 0.9:
            self._alert(flow.src_ip, "SYN Flood Detected", f"SYN Ratio={f2_syn_ratio:.2f}")

        # 3. Phát hiện SQLi (F13 crs_sqli_score > 0)
        if f13_sqli > 0:
            self._alert(flow.src_ip, "SQLi Detected", f"CRS SQLi Score={f13_sqli:.0f}")

        # 4. Phát hiện XSS (F18 crs_xss_score > 0)
        if f18_xss > 0:
            self._alert(flow.src_ip, "XSS Detected", f"CRS XSS Score={f18_xss:.0f}")

    def _alert(self, src_ip, alert_type, details):
        """Ghi cảnh báo"""
        self.stats['alerts'] += 1
        logger.warning(f"🚨 [ALARM] {src_ip} | {alert_type} | {details}")

    def start(self):
        """Khởi động hệ thống"""
        self.is_running = True
        
        # Tạo threads
        self.capture_thread = threading.Thread(target=self._capture_loop, name="CaptureThread")
        self.analyze_thread = threading.Thread(target=self._analysis_loop, name="AnalysisThread")
        
        # Chạy threads (Daemon=True để chết theo main thread nếu crash)
        self.capture_thread.daemon = True
        self.analyze_thread.daemon = True
        
        self.capture_thread.start()
        self.analyze_thread.start()
        
        logger.info("🎬 HỆ THỐNG ĐANG CHẠY. Nhấn Ctrl+C để dừng.")
        logger.info(f"   - Interface: {self.interface}")
        logger.info(f"   - Window Size: {self.window_size}s")
        
        flow_timer = 0
        try:
            while self.is_running:
                time.sleep(1)
                
                # In thống kê mỗi 5 giây
                flow_timer += 1
                if flow_timer >= 5:
                    q_stats = self.packet_queue.get_stats()
                    logger.info(
                        f"[Stats] Cap: {self.stats['captured']} | "
                        f"Proc: {self.stats['processed']} | "
                        f"Drop: {self.stats['dropped']} | "
                        f"Queue: {q_stats['current_size']}/{q_stats['max_size']} | "
                        f"Flows: {len(self.flow_manager.flows)}"
                    )
                    flow_timer = 0
                    
        except KeyboardInterrupt:
            logger.info("🛑 Người dùng yêu cầu dừng hệ thống...")
            self.stop()


if __name__ == "__main__":
    import argparse
    
    # Lấy danh sách interface đê gợi ý (Optional)
    from scapy.all import get_if_list
    
    parser = argparse.ArgumentParser(description="Real-time NIDS (Scapy Multi-threaded)")
    parser.add_argument("-i", "--iface", type=str, required=False, help="Network Interface (ví dụ: 'Ethernet' hoặc 'eth0'). Nếu không nhập sẽ dùng default.")
    parser.add_argument("-w", "--window", type=float, default=1.0, help="Sliding Window Size (seconds)")
    parser.add_argument("-o", "--output", type=str, default="live_features.csv", help="Output CSV file (default: live_features.csv)")
    
    args = parser.parse_args()
    
    iface = args.iface
    if not iface:
        # Tự động chọn interface đầu tiên hoặc 'Ethernet' trên Windows
        # Đây chỉ là logic cơ bản, user nên nhập tay
        if sys.platform == "win32":
            iface = "Ethernet"
        else:
            iface = "eth0"
        print(f"[*] Chưa chọn interface, thử dùng mặc định: {iface}")
        print(f"[*] Danh sách interface khả dụng: {get_if_list()}")

    nids = RealTimeNIDS(interface=iface, window_size=args.window, output_file=args.output)
    nids.start()
