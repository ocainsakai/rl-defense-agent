#!/usr/bin/env python3
# main_live_sliding.py
"""
=============================================================================
REAL-TIME SLIDING WINDOW NIDS - JSON OUTPUT ONLY
=============================================================================

Captures live network traffic and outputs raw features to JSON/JSONL.
Features are AGGREGATED BY SOURCE IP.

USAGE:
    python main_live_sliding.py -i "Ethernet" -w 1.0 -o live_output.jsonl
    python main_live_sliding.py --iface "Wi-Fi" --window 5.0 --output output.json

OUTPUT FORMAT (JSONL - one JSON object per line):
    {
        "timestamp": <window_end_time>,
        "src_ip": "<source_ip>",
        "packet_rate": <F1>,
        "syn_ack_ratio": <F2>,
        "distinct_ports": <F3>,
        "payload_len": <F4>,
        "conn_fail_rate": <F5>,
        "context_score": <F6>
    }
=============================================================================
"""

import threading
import time
import sys
import json
import logging
import os
from scapy.all import conf

# Scapy optimization
conf.checkIPaddr = False

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.packet_queue import PacketQueue
from core.sniffer import NetworkSniffer
from feature.feature_flow import FlowFeatureCalculator

from logging.handlers import RotatingFileHandler

# ============================================================================
# LOGGING SETUP
# ============================================================================

if not os.path.exists("logs"):
    os.makedirs("logs")

log_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%H:%M:%S')

file_handler = RotatingFileHandler("logs/nids_sliding.log", maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

logger = logging.getLogger("NIDS_Live_Sliding")
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


def group_flows_by_src_ip(flows: list) -> dict:
    """Groups flows by source IP address."""
    flows_by_src = {}
    for flow in flows:
        src_ip = flow.src_ip
        if src_ip not in flows_by_src:
            flows_by_src[src_ip] = []
        flows_by_src[src_ip].append(flow)
    return flows_by_src


class RealTimeSlidingNIDS:
    """
    Real-time NIDS with Sliding Window and Source IP Aggregation.
    Outputs raw features to JSON/JSONL format only.
    """
    
    def __init__(self, interface: str, window_size: float = 1.0, slide_step: float = 0.5, output_file: str = "live_output.jsonl"):
        self.interface = interface
        self.window_size = window_size
        self.slide_step = slide_step  # True Sliding Window: slide by step, not window_size
        self.output_file = output_file
        self.is_running = False
        
        # Ensure JSON output extension
        if not (output_file.endswith('.json') or output_file.endswith('.jsonl')):
            self.output_file = output_file + '.jsonl'
            logger.warning(f"[Output] Added .jsonl extension: {self.output_file}")
        
        # Output file handle
        self.output_fd = None
        self._init_output()
        
        # Core components
        self.packet_queue = PacketQueue(max_size=10000)
        self.parser = PacketLayerExtractor(enable_http_parsing=True)
        # FlowManager: Quản lý packet-to-flow mapping
        # LƯU Ý: Cleanup được quản lý bởi slide_window_packets() trong _process_window()
        # Không dùng internal cleanup của FlowManager (để tránh xung đột logic)
        self.flow_manager = FlowManager(
            window_size=window_size,
            flow_timeout=120.0,        # Chỉ dùng cho trường hợp khẩn cấp (fallback)
            cleanup_interval=100000    # Vô hiệu hóa - slide_window_packets() làm việc này
        )

        self.feature_calc = FlowFeatureCalculator()
        self.sniffer = NetworkSniffer()
        
        # Thread synchronization
        self._flow_lock = threading.Lock()
        
        # Window tracking
        self.current_window_start = None
        self.current_window_end = None
        self.window_count = 0
        
        # Stats
        self.stats = {
            'captured': 0,
            'processed': 0,
            'dropped': 0,
            'rows_written': 0
        }
    
    def _init_output(self):
        """Initialize JSON output file."""
        try:
            self.output_fd = open(self.output_file, mode='w', encoding='utf-8')
            logger.info(f"[Output] JSON/JSONL: {self.output_file}")
        except Exception as e:
            logger.error(f"[Output] Error opening file: {e}")
            self.output_fd = None
    
    def _capture_loop(self):
        """Capture Thread: Captures packets and pushes to queue."""
        logger.info(f"[Capture] Listening on {self.interface}...")
        
        def capture_callback(pkt):
            if not self.is_running:
                return
            
            success = self.packet_queue.put(pkt, block=False)
            if success:
                self.stats['captured'] += 1
            else:
                self.stats['dropped'] += 1
                if self.stats['dropped'] % 100 == 0:
                    logger.warning(f"[Capture] Queue full! Dropped {self.stats['dropped']} packets.")
        
        self.sniffer.start_live(
            interface=self.interface,
            callback=capture_callback,
            bpf_filter="ip"
        )
        logger.info("[Capture] Stopped.")
    
    def _analysis_loop(self):
        """Analysis Thread: Parses packets and adds to FlowManager."""
        logger.info("[Analyze] Processing packets...")
        
        while self.is_running or not self.packet_queue.empty():
            pkt = self.packet_queue.get(block=True, timeout=0.5)
            
            if pkt is None:
                continue
            
            try:
                layer_info = self.parser.extract(pkt)
                
                if layer_info and layer_info.has_ip:
                    with self._flow_lock:
                        self.flow_manager.process_packet(layer_info)
                    self.stats['processed'] += 1
                    
            except Exception as e:
                logger.error(f"[Analyze] Error: {e}")
        
        logger.info("[Analyze] Stopped.")
    
    def _process_window(self):
        """Process current window: Aggregate by Source IP and export features."""
        self.window_count += 1
        
        with self._flow_lock:
            all_flows = self.flow_manager.get_all_flows()
            # TRUE SLIDING WINDOW: Thay vì xóa sạch (clear), ta chỉ xóa packets cũ
            self.flow_manager.slide_window_packets(self.current_window_end)
        
        flows_by_src = group_flows_by_src_ip(all_flows) if all_flows else {}
        
        if not flows_by_src:
            logger.info(f"[Window {self.window_count}] 0 source IPs, 0 flows")
            return
        
        logger.info(f"[Window {self.window_count}] {len(flows_by_src)} source IPs, {len(all_flows)} flows")
        
        for src_ip in sorted(flows_by_src.keys()):
            flows_list = flows_by_src[src_ip]
            self._export_features(src_ip, flows_list)
    
    def _export_features(self, src_ip: str, flows_list: list):
        """Export raw features for a Source IP to JSON."""
        # Set window_size for F1 calculation
        for flow in flows_list:
            flow.analysis_window_size = self.window_size
        
        # Calculate raw features
        features_raw = self.feature_calc.calculate_all_raw(flows_list)
        
        # FIX: Skip rows with packet_rate = 0 (empty windows / no actual data)
        packet_rate = float(features_raw[0])
        if packet_rate <= 0:
            return  # Skip this row - no data to report
        
        # Write JSON line
        if self.output_fd:
            json_row = {
                "timestamp": round(self.current_window_end, 6),
                "src_ip": src_ip,
                "packet_rate": round(packet_rate, 4),
                "syn_ack_ratio": round(float(features_raw[1]), 4),
                "distinct_ports": int(features_raw[2]),
                "payload_len": round(float(features_raw[3]), 4),
                "conn_fail_rate": round(float(features_raw[4]), 4),
                "context_score": round(float(features_raw[5]), 4)
            }
            self.output_fd.write(json.dumps(json_row) + "\n")
            self.output_fd.flush()
            self.stats['rows_written'] += 1
        
    def stop(self):
        """Stop the system."""
        self.is_running = False
        self.sniffer.stop()
        
        # Process remaining flows
        if self.flow_manager.get_all_flows():
            self._process_window()
        
        if self.output_fd:
            self.output_fd.close()
        
        time.sleep(1)
        logger.info("System stopped.")
    
    def start(self):
        """Start the system."""
        self.is_running = True
        self.current_window_start = time.time()
        self.current_window_end = self.current_window_start + self.window_size
        
        # Start threads
        self.capture_thread = threading.Thread(target=self._capture_loop, name="CaptureThread", daemon=True)
        self.analyze_thread = threading.Thread(target=self._analysis_loop, name="AnalysisThread", daemon=True)
        
        self.capture_thread.start()
        self.analyze_thread.start()
        
        logger.info("🎬 SYSTEM RUNNING. Press Ctrl+C to stop.")
        logger.info(f"   - Interface: {self.interface}")
        logger.info(f"   - Window Size: {self.window_size}s")
        logger.info(f"   - Slide Step: {self.slide_step}s (overlap: {self.window_size - self.slide_step}s)")
        logger.info(f"   - Output: {self.output_file}")
        
        try:
            while self.is_running:
                time.sleep(0.1)
                
                current_time = time.time()
                
                if current_time >= self.current_window_end:
                    self._process_window()
                    
                    # TRUE SLIDING WINDOW: Slide by step, not window_size
                    self.current_window_start += self.slide_step
                    self.current_window_end = self.current_window_start + self.window_size
                    
                    q_stats = self.packet_queue.get_stats()
                    logger.info(
                        f"[Stats] Cap: {self.stats['captured']} | "
                        f"Proc: {self.stats['processed']} | "
                        f"Drop: {self.stats['dropped']} | "
                        f"Queue: {q_stats['current_size']}/{q_stats['max_size']} | "
                        f"Rows: {self.stats['rows_written']}"
                    )
                    
        except KeyboardInterrupt:
            logger.info("🛑 User requested stop...")
            self.stop()


if __name__ == "__main__":
    import argparse
    from scapy.all import get_if_list
    
    parser = argparse.ArgumentParser(
        description="Real-time NIDS - JSON Output Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main_live_sliding.py -i "Ethernet" -w 1.0 -o live_output.jsonl
    python main_live_sliding.py -i "Wi-Fi" -w 5.0 -o output.json
        """
    )
    
    parser.add_argument("-i", "--iface", type=str, required=False, 
                        help="Network Interface (e.g., 'Ethernet', 'Wi-Fi')")
    parser.add_argument("-w", "--window", type=float, default=1.0,
                        help="Window size in seconds (default: 1.0)")
    parser.add_argument("-s", "--step", type=float, default=0.5,
                        help="Slide step in seconds (default: 0.5). Smaller = more overlap.")
    parser.add_argument("-o", "--output", type=str, default="live_output.jsonl",
                        help="Output file (default: live_output.jsonl)")
    
    args = parser.parse_args()
    
    # Validate step size
    if args.step <= 0:
        print("[!] Error: Step size must be > 0")
        sys.exit(1)
    if args.step > args.window:
        print(f"[!] Warning: Step ({args.step}s) > Window ({args.window}s). Setting step = window.")
        args.step = args.window
    
    iface = args.iface
    if not iface:
        if sys.platform == "win32":
            iface = "Ethernet"
        else:
            iface = "eth0"
        print(f"[*] No interface specified, using default: {iface}")
        print(f"[*] Available interfaces: {get_if_list()}")
    
    nids = RealTimeSlidingNIDS(interface=iface, window_size=args.window, slide_step=args.step, output_file=args.output)
    nids.start()
