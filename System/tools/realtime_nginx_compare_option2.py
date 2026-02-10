#!/usr/bin/env python3
"""
OPTION 2: Hybrid Approach - FlowManager + Custom HTTP Index
Sử dụng FlowManager cho flow tracking, thêm HTTP-based index để match
"""

import threading
import time
from typing import Dict, Optional, Tuple
from scapy.all import sniff

# ✅ TÁI SỬ DỤNG tất cả core modules
from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo


class NginxCompareManager:
    """
    Wrapper quanh FlowManager để support HTTP-based matching.

    Combines:
    - FlowManager: Flow tracking, memory safety, cleanup
    - HTTP Index: Custom index by IP|Path for nginx comparison
    """

    def __init__(self, window_size: float = 30.0):
        # ✅ Dùng FlowManager (memory safe, auto cleanup)
        self.flow_manager = FlowManager(
            window_size=window_size,
            flow_timeout=60.0,
            max_flows=10000
        )

        # ✅ Custom HTTP Index: IP|Path → flow_key
        self.http_index: Dict[str, tuple] = {}

        # Stats
        self.total_packets = 0
        self.http_requests = 0

    def process_packet(self, layer_info: LayerInfo) -> Optional[FlowState]:
        """
        Process packet qua FlowManager và index HTTP requests.
        """
        if not layer_info or not layer_info.has_ip:
            return None

        self.total_packets += 1

        # ✅ Process qua FlowManager (flow tracking)
        flow = self.flow_manager.process_packet(layer_info)

        # ✅ Index HTTP requests
        if flow and layer_info.http_path:
            self.http_requests += 1

            # Create HTTP index key
            # BEFORE: Use src_ip
            # AFTER: Use x_real_ip if available
            ip = layer_info.x_real_ip if layer_info.x_real_ip else layer_info.src_ip
            http_key = f"{ip}|{layer_info.http_path}"

            # Index: HTTP key → flow_key
            self.http_index[http_key] = flow.flow_key

        return flow

    def find_flow_by_http(self, ip: str, http_path: str) -> Optional[FlowState]:
        """
        Tìm flow bằng IP + HTTP Path (thay vì 5-tuple).
        """
        http_key = f"{ip}|{http_path}"

        if http_key in self.http_index:
            flow_key = self.http_index[http_key]
            return self.flow_manager.get_flow(flow_key)

        return None

    def cleanup_http_index(self):
        """
        Cleanup HTTP index for expired flows.
        """
        # Get active flow keys
        active_flow_keys = set(self.flow_manager.flows.keys())

        # Remove index entries for expired flows
        expired_keys = []
        for http_key, flow_key in self.http_index.items():
            if flow_key not in active_flow_keys:
                expired_keys.append(http_key)

        for key in expired_keys:
            del self.http_index[key]

    def get_stats(self) -> dict:
        """Get statistics."""
        flow_stats = self.flow_manager.get_stats()
        return {
            "total_packets": self.total_packets,
            "http_requests": self.http_requests,
            "total_flows": flow_stats["total_flows"],
            "http_index_size": len(self.http_index)
        }


# ============================================================================
# MAIN PROGRAM
# ============================================================================

# Setup
parser = PacketLayerExtractor(enable_http_parsing=True)
before_manager = NginxCompareManager(window_size=30.0)
after_manager = NginxCompareManager(window_size=30.0)

matched_count = 0


def sniffer_before(interface: str):
    """Sniffer BEFORE Nginx"""

    def packet_callback(pkt):
        # ✅ Parse với PacketLayerExtractor
        layer_info = parser.extract(pkt)

        if not layer_info:
            return

        # ✅ Process qua NginxCompareManager
        flow = before_manager.process_packet(layer_info)

        if flow and layer_info.http_path:
            print(f"[BEFORE] {layer_info.src_ip} {layer_info.http_method} {layer_info.http_path}")

    sniff(iface=interface, filter="ip", prn=packet_callback, store=False)


def sniffer_after(interface: str):
    """Sniffer AFTER Nginx"""
    global matched_count

    def packet_callback(pkt):
        global matched_count

        # ✅ Parse với PacketLayerExtractor
        layer_info = parser.extract(pkt)

        if not layer_info:
            return

        # ✅ Process qua NginxCompareManager
        after_flow = after_manager.process_packet(layer_info)

        if after_flow and layer_info.x_real_ip and layer_info.http_path:
            print(f"[AFTER ] {layer_info.x_real_ip} {layer_info.http_method} {layer_info.http_path}")

            # ✅ Try match by HTTP semantics
            before_flow = before_manager.find_flow_by_http(layer_info.x_real_ip, layer_info.http_path)

            if before_flow:
                matched_count += 1
                print(f"✅ MATCHED #{matched_count}:")
                print(f"   BEFORE Flow: {before_flow.src_ip}:{before_flow.flow_key[2]} → {before_flow.dst_ip}:{before_flow.flow_key[3]}")
                print(f"   AFTER  Flow: {after_flow.src_ip}:{after_flow.flow_key[2]} → {after_flow.dst_ip}:{after_flow.flow_key[3]}")
                print(f"   Forward packets: {before_flow.get_fwd_packet_count()} | {after_flow.get_fwd_packet_count()}")
                print(f"   Backward packets: {before_flow.get_bwd_packet_count()} | {after_flow.get_bwd_packet_count()}")

    sniff(iface=interface, filter="ip", prn=packet_callback, store=False)


def stats_printer():
    """Print stats every 5 seconds."""
    while True:
        time.sleep(5)

        before_stats = before_manager.get_stats()
        after_stats = after_manager.get_stats()

        print("\n" + "=" * 70)
        print("STATS:")
        print(f"  BEFORE: {before_stats['total_packets']} pkts | {before_stats['http_requests']} HTTP | {before_stats['total_flows']} flows")
        print(f"  AFTER:  {after_stats['total_packets']} pkts | {after_stats['http_requests']} HTTP | {after_stats['total_flows']} flows")
        print(f"  MATCHED: {matched_count}")
        print("=" * 70 + "\n")

        # Cleanup HTTP index
        before_manager.cleanup_http_index()
        after_manager.cleanup_http_index()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  OPTION 2: Hybrid Approach - FlowManager + HTTP Index           ║
╠══════════════════════════════════════════════════════════════════╣
║  Features:                                                       ║
║  ✅ FlowManager: Flow tracking, bidirectional, memory safe      ║
║  ✅ HTTP Index: Custom matching by IP|Path                      ║
║  ✅ Auto cleanup: Expired flows & index                         ║
╚══════════════════════════════════════════════════════════════════╝
    """)

    # Start sniffers
    before_thread = threading.Thread(target=sniffer_before, args=("r-ext",), daemon=True)
    after_thread = threading.Thread(target=sniffer_after, args=("r-web",), daemon=True)
    stats_thread = threading.Thread(target=stats_printer, daemon=True)

    before_thread.start()
    after_thread.start()
    stats_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopped.")