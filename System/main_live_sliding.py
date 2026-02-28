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
        "inter_arrival_time": <F3>,
        "rst_ratio": <F4>,
        "distinct_ports": <F5>,
        "url_concentration": <F6>,
        "http_iat_uniformity": <F7>,
        "request_size_uniformity": <F8>,
        "avg_payload_size": <F9>,
        "fwd_bwd_ratio": <F10>,
        "packets_per_port": <F11>,
        "sql_special_char": <F12>,
        "crs_sqli_score": <F13>,
        "sql_union_select": <F14>,
        "sql_comment": <F15>,
        "sql_stacked_query": <F16>,
        "sql_select_count": <F17>,
        "crs_xss_score": <F18>,
        "js_function_call": <F19>,
        "html_event_handler": <F20>
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
from feature.calculator import FlowFeatureCalculator
from feature.wamm_classifier import WammClassifier

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


def group_flows_by_src_ip(flows: list, use_x_real_ip: bool = True) -> dict:
    """
    Groups flows by source IP address.
    
    Args:
        flows: List of FlowState objects
        use_x_real_ip: If True, prefer X-Real-IP header over packet src_ip
                       (useful when sniffing after Nginx proxy)
    """
    flows_by_src = {}
    for flow in flows:
        # Prefer effective_src_ip (X-Real-IP nếu có, fallback về src_ip)
        if use_x_real_ip and hasattr(flow, 'effective_src_ip'):
            src_ip = flow.effective_src_ip
        else:
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
    
    def __init__(self, interface: str, window_size: float = 1.0, slide_step: float = None, output_file: str = "live_output.jsonl"):
        self.interface = interface
        self.window_size = window_size
        # DISABLED OVERLAP: slide_step = window_size (no overlap for clearer testing)
        self.slide_step = slide_step if slide_step is not None else window_size
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
        self.parser = PacketLayerExtractor()
        # FlowManager: Quản lý packet-to-flow mapping
        # LƯU Ý: Cleanup được quản lý bởi slide_window_packets() trong _process_window()
        # Không dùng internal cleanup của FlowManager (để tránh xung đột logic)
        self.flow_manager = FlowManager(
            window_size=window_size,
            flow_timeout=120.0,        # Chỉ dùng cho trường hợp khẩn cấp (fallback)
            cleanup_interval=100000    # Vô hiệu hóa - slide_window_packets() làm việc này
        )

        wamm = WammClassifier()  # Auto-loads model if available
        self.feature_calc = FlowFeatureCalculator(wamm_classifier=wamm)
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
        """Export raw features for a Source IP to JSON.

        20 Features matching FEATURE_ORDER (F1-F20) from data_params.py.
        """
        # Set window_size for F1 calculation
        for flow in flows_list:
            flow.analysis_window_size = self.window_size

        # Calculate raw features (20 values)
        features_raw = self.feature_calc.calculate_all(flows_list)

        # Skip rows with packet_rate = 0 (empty windows / no actual data)
        packet_rate = float(features_raw[0])
        if packet_rate <= 0:
            return

        # Check if we have X-Real-IP (sniffing after Nginx)
        x_real_ip = None
        packet_src_ip = None
        for flow in flows_list:
            if hasattr(flow, 'x_real_ip') and flow.x_real_ip:
                x_real_ip = flow.x_real_ip
                packet_src_ip = flow.src_ip
                break

        # Write JSON line
        if self.output_fd:
            feature_names = FlowFeatureCalculator.get_feature_names()
            json_row = {
                "timestamp": round(self.current_window_end, 6),
                "src_ip": src_ip,
            }

            # Add all 20 features dynamically
            for idx, name in enumerate(feature_names):
                json_row[name] = round(float(features_raw[idx]), 4)

            # Add X-Real-IP info if present
            if x_real_ip:
                json_row["x_real_ip"] = x_real_ip
                json_row["proxy_ip"] = packet_src_ip

            self.output_fd.write(json.dumps(json_row) + "\n")
            self.output_fd.flush()
            self.stats['rows_written'] += 1
        
    def stop(self):
        """Stop the system."""
        self.is_running = False
        self.sniffer.stop()

        # Process remaining flows (thread-safe)
        with self._flow_lock:
            remaining = self.flow_manager.get_all_flows()
        if remaining:
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
        if self.slide_step < self.window_size:
            logger.info(f"   - Slide Step: {self.slide_step}s (overlap: {self.window_size - self.slide_step}s)")
        else:
            logger.info(f"   - Slide Step: {self.slide_step}s (NO OVERLAP - clean windows)")
        logger.info(f"   - Output: {self.output_file}")
        
        try:
            while self.is_running:
                time.sleep(0.1)
                
                current_time = time.time()
                
                while current_time >= self.current_window_end:
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
    parser.add_argument("-s", "--step", type=float, default=None,
                        help="Slide step in seconds (default: same as window = no overlap).")
    parser.add_argument("-o", "--output", type=str, default="live_output.jsonl",
                        help="Output file (default: live_output.jsonl)")
    
    args = parser.parse_args()
    
    # Validate step size
    if args.step is None:
        args.step = args.window  # No overlap by default
    elif args.step <= 0:
        print("[!] Error: Step size must be > 0")
        sys.exit(1)
    elif args.step > args.window:
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
