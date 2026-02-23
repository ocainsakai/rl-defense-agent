#!/usr/bin/env python3
# main_dual_sensor.py
"""
=============================================================================
DUAL-SOURCE NIDS - Network Capture + Nginx Log
=============================================================================

Kết hợp 2 nguồn dữ liệu:
- NetworkSensor: Scapy capture trước nginx (r-ext) → F1-F5, F15-F17
- NginxLogSensor: Parse nginx access.log → F6-F30

Merge theo (src_ip, time_window) → 30-feature vector → JSONL output.

USAGE:
    python main_dual_sensor.py -i r-ext -l /tmp/router-nginx/logs/access.log
    python main_dual_sensor.py -i r-ext -l /tmp/router-nginx/logs/access.log -w 1.0 -o dual_output.jsonl

OUTPUT FORMAT (JSONL):
    {
        "timestamp": <window_end>,
        "src_ip": "<source_ip>",
        "packet_count": <N>,
        "request_count": <N>,
        "pps": <F1>, "syn_ack_ratio": <F2>, ..., "xss_encoded_payload": <F30>
    }
=============================================================================
"""

import threading
import time
import sys
import json
import logging
import os
import argparse

from logging.handlers import RotatingFileHandler

# ============================================================================
# LOGGING SETUP
# ============================================================================

if not os.path.exists("logs"):
    os.makedirs("logs")

log_formatter = logging.Formatter(
    '%(asctime)s | %(levelname)s | %(message)s', datefmt='%H:%M:%S'
)

file_handler = RotatingFileHandler(
    "logs/nids_dual_sensor.log", maxBytes=10 * 1024 * 1024,
    backupCount=5, encoding='utf-8'
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)

logger = logging.getLogger("NIDS_DualSensor")
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


# ============================================================================
# DUAL SENSOR NIDS
# ============================================================================

class DualSensorNIDS:
    """
    Real-time NIDS with dual-source feature extraction.

    Threads:
    1. CaptureThread: Scapy packet capture on network interface
    2. AnalysisThread: Packet parsing → FlowManager
    3. LogReaderThread: Tail nginx access.log → entries buffer
    4. MainThread: Timer → merge → JSONL output
    """

    def __init__(self, capture_interface: str, log_path: str,
                 window_size: float = 1.0, slide_step: float = None,
                 output_file: str = "dual_output.jsonl"):
        self.capture_interface = capture_interface
        self.log_path = log_path
        self.window_size = window_size
        self.slide_step = slide_step if slide_step is not None else window_size
        self.output_file = output_file
        self.is_running = False

        # Ensure JSONL extension
        if not (output_file.endswith('.json') or output_file.endswith('.jsonl')):
            self.output_file = output_file + '.jsonl'

        # Output file handle
        self.output_fd = None

        # Import here to avoid circular imports at module level
        from core.network_sensor import NetworkSensor
        from core.nginx_log_sensor import NginxLogSensor
        from core.feature_merger import FeatureMerger

        # Network sensor (Scapy capture → F1-F5, F15-F17)
        self.net_sensor = NetworkSensor(
            window_size=window_size,
        )

        # Nginx log sensor (access.log → F6-F30)
        self.log_sensor = NginxLogSensor(
            log_path=log_path,
            window_size=window_size,
        )

        # Feature merger
        self.merger = FeatureMerger()

        # Window tracking
        self.current_window_start = None
        self.current_window_end = None
        self.window_count = 0

        # Stats
        self.stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'log_entries_read': 0,
            'rows_written': 0,
        }

    def _init_output(self):
        """Initialize JSONL output file."""
        try:
            self.output_fd = open(self.output_file, mode='w', encoding='utf-8')
            logger.info(f"[Output] JSONL: {self.output_file}")
        except Exception as e:
            logger.error(f"[Output] Error opening file: {e}")
            self.output_fd = None

    # ========================================================================
    # THREADS
    # ========================================================================

    def _capture_loop(self):
        """CaptureThread: Scapy packet capture → queue."""
        logger.info(f"[Capture] Listening on {self.capture_interface}...")

        self.net_sensor.sniffer.start_live(
            interface=self.capture_interface,
            callback=self.net_sensor.packet_callback,
            bpf_filter="ip",
        )
        logger.info("[Capture] Stopped.")

    def _analysis_loop(self):
        """AnalysisThread: Parse packets → FlowManager."""
        logger.info("[Analyze] Processing packets...")

        while self.is_running:
            count = self.net_sensor.process_packets()
            if count > 0:
                self.stats['packets_processed'] += count
            else:
                time.sleep(0.05)  # Avoid busy-wait

        # Drain remaining
        self.net_sensor.process_packets()
        logger.info("[Analyze] Stopped.")

    def _log_reader_loop(self):
        """LogReaderThread: Tail nginx access.log → buffer."""
        logger.info(f"[LogReader] Tailing {self.log_path}...")

        self.log_sensor.start_tail()

        while self.is_running:
            count = self.log_sensor.read_new_entries()
            if count > 0:
                self.stats['log_entries_read'] += count
            time.sleep(0.1)  # Poll interval

        # Final read
        self.log_sensor.read_new_entries()
        logger.info("[LogReader] Stopped.")

    # ========================================================================
    # WINDOW PROCESSING
    # ========================================================================

    def _process_window(self):
        """Process current window: merge both sensors → JSONL output."""
        self.window_count += 1

        # 1. Network features per src_ip
        net_results = self.net_sensor.compute_features(
            self.current_window_start,
            self.current_window_end,
        )

        # 2. Log features per src_ip
        log_results = self.log_sensor.flush_window(
            self.current_window_start,
            self.current_window_end,
        )

        # 3. Merge
        merged_vectors = self.merger.merge_all(
            network_results=net_results,
            log_results=log_results,
            window_end=self.current_window_end,
        )

        # Log summary
        net_ips = len(net_results)
        log_ips = len(log_results)
        total_ips = len(merged_vectors)

        if total_ips > 0:
            logger.info(
                f"[Window {self.window_count}] "
                f"{total_ips} IPs (net={net_ips}, log={log_ips})"
            )

        # 4. Export
        for vector in merged_vectors:
            self._export_vector(vector)

    def _export_vector(self, vector):
        """Write merged feature vector to JSONL."""
        if not self.output_fd:
            return

        row = self.merger.to_dict(vector)

        # Round floats for cleaner output
        for key, val in row.items():
            if isinstance(val, float):
                row[key] = round(val, 6)

        self.output_fd.write(json.dumps(row) + "\n")
        self.output_fd.flush()
        self.stats['rows_written'] += 1

    # ========================================================================
    # START / STOP
    # ========================================================================

    def stop(self):
        """Stop the system."""
        self.is_running = False
        self.net_sensor.sniffer.stop()

        # Process remaining data
        self._process_window()

        if self.output_fd:
            self.output_fd.close()

        time.sleep(1)
        logger.info("System stopped.")
        logger.info(f"  Packets captured: {self.stats['packets_captured']}")
        logger.info(f"  Packets processed: {self.stats['packets_processed']}")
        logger.info(f"  Log entries read: {self.stats['log_entries_read']}")
        logger.info(f"  Rows written: {self.stats['rows_written']}")

    def start(self):
        """Start the dual-sensor NIDS."""
        self.is_running = True
        self._init_output()

        self.current_window_start = time.time()
        self.current_window_end = self.current_window_start + self.window_size

        # Start threads
        capture_thread = threading.Thread(
            target=self._capture_loop, name="CaptureThread", daemon=True
        )
        analyze_thread = threading.Thread(
            target=self._analysis_loop, name="AnalysisThread", daemon=True
        )
        log_reader_thread = threading.Thread(
            target=self._log_reader_loop, name="LogReaderThread", daemon=True
        )

        capture_thread.start()
        analyze_thread.start()
        log_reader_thread.start()

        logger.info("DUAL-SENSOR NIDS RUNNING. Press Ctrl+C to stop.")
        logger.info(f"  Capture interface: {self.capture_interface}")
        logger.info(f"  Nginx log: {self.log_path}")
        logger.info(f"  Window size: {self.window_size}s")
        logger.info(f"  Output: {self.output_file}")

        try:
            while self.is_running:
                time.sleep(0.1)

                current_time = time.time()

                if current_time >= self.current_window_end:
                    self._process_window()

                    # Slide window
                    self.current_window_start += self.slide_step
                    self.current_window_end = (
                        self.current_window_start + self.window_size
                    )

                    # Log stats
                    net_stats = self.net_sensor.get_stats()
                    self.stats['packets_captured'] = net_stats['packets_captured']
                    log_buf = self.log_sensor.get_buffer_size()

                    logger.info(
                        f"[Stats] "
                        f"Pkts: {self.stats['packets_captured']} | "
                        f"Proc: {self.stats['packets_processed']} | "
                        f"Logs: {self.stats['log_entries_read']} | "
                        f"LogBuf: {log_buf} | "
                        f"Rows: {self.stats['rows_written']}"
                    )

        except KeyboardInterrupt:
            logger.info("User requested stop...")
            self.stop()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Dual-Source NIDS: Network Capture + Nginx Log",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main_dual_sensor.py -i r-ext -l /tmp/router-nginx/logs/access.log
    python main_dual_sensor.py -i r-ext -l /tmp/router-nginx/logs/access.log -w 1.0
    python main_dual_sensor.py -i eth0 -l /var/log/nginx/access.log -o output.jsonl
        """
    )

    parser.add_argument(
        "-i", "--iface", type=str, required=True,
        help="Network interface for packet capture (e.g., 'r-ext', 'eth0')"
    )
    parser.add_argument(
        "-l", "--log", type=str, required=True,
        help="Path to nginx access.log (lab_detail format)"
    )
    parser.add_argument(
        "-w", "--window", type=float, default=1.0,
        help="Window size in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-s", "--step", type=float, default=None,
        help="Slide step in seconds (default: same as window)"
    )
    parser.add_argument(
        "-o", "--output", type=str, default="dual_output.jsonl",
        help="Output file (default: dual_output.jsonl)"
    )

    args = parser.parse_args()

    # Validate
    if args.step is not None:
        if args.step <= 0:
            print("[!] Error: Step size must be > 0")
            sys.exit(1)
        if args.step > args.window:
            print(f"[!] Warning: Step ({args.step}s) > Window ({args.window}s). "
                  f"Setting step = window.")
            args.step = args.window

    if not os.path.exists(args.log):
        print(f"[!] Warning: Log file not found: {args.log}")
        print(f"    Sensor will wait for file to appear.")

    nids = DualSensorNIDS(
        capture_interface=args.iface,
        log_path=args.log,
        window_size=args.window,
        slide_step=args.step,
        output_file=args.output,
    )
    nids.start()
