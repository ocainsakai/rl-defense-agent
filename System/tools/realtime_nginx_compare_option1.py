#!/usr/bin/env python3
"""
OPTION 1: Light Refactor - Chỉ dùng PacketLayerExtractor
Thay thế custom parsing bằng core module, vẫn giữ dict matching
"""

import threading
import time
from typing import Dict, Optional
from scapy.all import sniff

# ✅ TÁI SỬ DỤNG core modules
from core.packet_parser import PacketLayerExtractor
from core.layer_info import LayerInfo

# Setup parser
parser = PacketLayerExtractor()

# ✅ Dùng LayerInfo (consistent data structure)
before_buffer: Dict[str, LayerInfo] = {}  # IP|Path → LayerInfo
after_buffer: Dict[str, LayerInfo] = {}

before_packet_count = 0
after_packet_count = 0
matched_count = 0

# Stats
before_stats = {"total": 0, "http": 0}
after_stats = {"total": 0, "http": 0}


def sniffer_before(interface: str):
    """Sniffer BEFORE Nginx"""
    global before_packet_count

    def packet_callback(pkt):
        global before_packet_count

        # ✅ Dùng parser thay vì custom function
        layer_info = parser.extract(pkt)

        if not layer_info or not layer_info.has_ip:
            return

        before_packet_count += 1
        before_stats["total"] += 1

        # ✅ Vẫn dùng simple dict matching (fast!)
        if layer_info.http_path:
            key = f"{layer_info.src_ip}|{layer_info.http_path}"
            before_buffer[key] = layer_info
            before_stats["http"] += 1
            print(f"[BEFORE] #{before_packet_count} {layer_info.src_ip} → {layer_info.http_path}")

    sniff(iface=interface, filter="ip", prn=packet_callback, store=False)


def sniffer_after(interface: str):
    """Sniffer AFTER Nginx"""
    global after_packet_count, matched_count

    def packet_callback(pkt):
        global after_packet_count, matched_count

        # ✅ Dùng parser
        layer_info = parser.extract(pkt)

        if not layer_info or not layer_info.has_ip:
            return

        after_packet_count += 1
        after_stats["total"] += 1

        # ✅ Match by X-Real-IP (vẫn dùng dict)
        if layer_info.x_real_ip and layer_info.http_path:
            key = f"{layer_info.x_real_ip}|{layer_info.http_path}"
            after_buffer[key] = layer_info
            after_stats["http"] += 1

            # Try match
            if key in before_buffer:
                before_pkt = before_buffer[key]
                matched_count += 1
                print(f"✅ MATCHED #{matched_count}: {key}")
                print(f"   BEFORE: {before_pkt.src_ip}:{before_pkt.tcp_sport} → {before_pkt.dst_ip}:{before_pkt.tcp_dport}")
                print(f"   AFTER:  {layer_info.src_ip}:{layer_info.tcp_sport} → {layer_info.dst_ip}:{layer_info.tcp_dport}")
                del before_buffer[key]  # Cleanup after match

    sniff(iface=interface, filter="ip", prn=packet_callback, store=False)


if __name__ == "__main__":
    print("OPTION 1: Light Refactor - Using PacketLayerExtractor only")
    print("=" * 70)

    # Start sniffers
    before_thread = threading.Thread(target=sniffer_before, args=("r-ext",), daemon=True)
    after_thread = threading.Thread(target=sniffer_after, args=("r-web",), daemon=True)

    before_thread.start()
    after_thread.start()

    try:
        while True:
            time.sleep(5)
            print(f"\n[Stats] Before: {before_stats['total']} | After: {after_stats['total']} | Matched: {matched_count}")
    except KeyboardInterrupt:
        print("\nStopped.")