#!/usr/bin/env python3
"""
Dual Sniffer Comparison Tool
So sánh gói tin trước và sau Nginx để thấy sự khác biệt.

Usage:
    sudo python3 dual_sniffer_compare.py --before s1-eth1 --after s2-eth1
"""

import argparse
import threading
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from scapy.all import sniff, IP, TCP, Raw, Ether
import json


@dataclass
class PacketInfo:
    """Thông tin packet đã capture"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    tcp_flags: str
    seq: int
    ack: int
    payload: bytes
    payload_preview: str
    raw_packet: object = field(repr=False)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "seq": self.seq,
            "ack": self.ack,
            "payload_len": len(self.payload),
            "payload_preview": self.payload_preview[:200]
        }


class PacketCapture:
    """Capture packets trên một interface"""
    
    def __init__(self, interface: str, name: str):
        self.interface = interface
        self.name = name
        self.packets: List[PacketInfo] = []
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
    def _extract_tcp_flags(self, tcp_layer) -> str:
        """Trích xuất TCP flags thành string"""
        flags = []
        if tcp_layer.flags.S: flags.append("SYN")
        if tcp_layer.flags.A: flags.append("ACK")
        if tcp_layer.flags.F: flags.append("FIN")
        if tcp_layer.flags.R: flags.append("RST")
        if tcp_layer.flags.P: flags.append("PSH")
        return ",".join(flags) if flags else "NONE"
    
    def _process_packet(self, pkt):
        """Xử lý packet và lưu thông tin"""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
            
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        payload = bytes(tcp.payload) if tcp.payload else b""
        
        # Preview payload (decode nếu có thể)
        try:
            payload_preview = payload.decode('utf-8', errors='replace')
        except:
            payload_preview = payload.hex()[:100]
        
        info = PacketInfo(
            timestamp=time.time(),
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            tcp_flags=self._extract_tcp_flags(tcp),
            seq=tcp.seq,
            ack=tcp.ack,
            payload=payload,
            payload_preview=payload_preview,
            raw_packet=pkt
        )
        self.packets.append(info)
        
        # Print realtime
        print(f"[{self.name}] {info.src_ip}:{info.src_port} → {info.dst_ip}:{info.dst_port} "
              f"[{info.tcp_flags}] payload={len(payload)}B")
    
    def start(self, duration: int = 30, filter_expr: str = "tcp"):
        """Bắt đầu capture trong thread riêng"""
        def _capture():
            self.running = True
            print(f"\n{'='*60}")
            print(f"[{self.name}] Bắt đầu capture trên {self.interface}")
            print(f"{'='*60}\n")
            
            try:
                sniff(
                    iface=self.interface,
                    filter=filter_expr,
                    prn=self._process_packet,
                    timeout=duration,
                    store=False
                )
            except Exception as e:
                print(f"[{self.name}] Lỗi: {e}")
            finally:
                self.running = False
                print(f"\n[{self.name}] Kết thúc - Captured {len(self.packets)} packets")
        
        self._thread = threading.Thread(target=_capture, daemon=True)
        self._thread.start()
        
    def wait(self):
        """Đợi capture hoàn thành"""
        if self._thread:
            self._thread.join()


class PacketComparator:
    """So sánh packets từ 2 điểm capture"""
    
    def __init__(self, before_capture: PacketCapture, after_capture: PacketCapture):
        self.before = before_capture
        self.after = after_capture
        
    def find_matching_packets(self) -> List[tuple]:
        """
        Tìm các cặp packet tương ứng dựa trên payload.
        Packet sau Nginx sẽ có IP nguồn khác (là IP của Nginx).
        """
        matches = []
        
        for before_pkt in self.before.packets:
            if not before_pkt.payload:
                continue
                
            # Tìm packet sau Nginx có payload giống
            for after_pkt in self.after.packets:
                if before_pkt.payload == after_pkt.payload:
                    matches.append((before_pkt, after_pkt))
                    break
                    
        return matches
    
    def compare_and_report(self) -> str:
        """Tạo báo cáo so sánh chi tiết"""
        report = []
        report.append("\n" + "="*80)
        report.append("BÁO CÁO SO SÁNH PACKET TRƯỚC VÀ SAU NGINX")
        report.append("="*80)
        
        # Thống kê tổng quan
        report.append(f"\n📊 THỐNG KÊ TỔNG QUAN:")
        report.append(f"   - Packets trước Nginx: {len(self.before.packets)}")
        report.append(f"   - Packets sau Nginx:   {len(self.after.packets)}")
        
        matches = self.find_matching_packets()
        report.append(f"   - Cặp packet khớp:     {len(matches)}")
        
        # Chi tiết từng cặp
        report.append(f"\n📋 CHI TIẾT SO SÁNH:")
        report.append("-"*80)
        
        for i, (before, after) in enumerate(matches[:10], 1):  # Hiển thị 10 cặp đầu
            report.append(f"\n🔹 Cặp #{i}:")
            report.append(f"   ┌─ TRƯỚC NGINX:")
            report.append(f"   │  IP:    {before.src_ip} → {before.dst_ip}")
            report.append(f"   │  Port:  {before.src_port} → {before.dst_port}")
            report.append(f"   │  Flags: {before.tcp_flags}")
            report.append(f"   │  Seq:   {before.seq}")
            report.append(f"   │")
            report.append(f"   └─ SAU NGINX:")
            report.append(f"      IP:    {after.src_ip} → {after.dst_ip}")
            report.append(f"      Port:  {after.src_port} → {after.dst_port}")
            report.append(f"      Flags: {after.tcp_flags}")
            report.append(f"      Seq:   {after.seq}")
            
            # Highlight differences
            report.append(f"\n   ⚡ SỰ KHÁC BIỆT:")
            
            if before.src_ip != after.src_ip:
                report.append(f"      - IP nguồn: {before.src_ip} → {after.src_ip} (Nginx thay thế)")
                
            if before.src_port != after.src_port:
                report.append(f"      - Port nguồn: {before.src_port} → {after.src_port} (Nginx tạo mới)")
                
            if before.seq != after.seq:
                report.append(f"      - Seq number: {before.seq} → {after.seq} (TCP session mới)")
                
            if before.tcp_flags != after.tcp_flags:
                report.append(f"      - TCP flags: {before.tcp_flags} → {after.tcp_flags}")
                
            report.append("-"*80)
        
        # Kết luận
        report.append(f"\n📝 KẾT LUẬN:")
        report.append("""
   Khi traffic đi qua Nginx (reverse proxy):
   
   1. IP NGUỒN BỊ THAY ĐỔI:
      - Trước Nginx: IP của Attacker (10.0.10.10)
      - Sau Nginx:   IP của Nginx (192.168.10.1)
      → Mất thông tin IP thực của attacker!
   
   2. TCP SESSION MỚI:
      - Nginx tạo TCP connection mới tới WebServer
      - Seq/Ack numbers hoàn toàn khác
      → Không thể detect SYN Flood từ điểm này!
   
   3. PORT NGUỒN KHÁC:
      - Nginx sử dụng ephemeral port mới
      → Không thể detect Port Scan từ điểm này!
   
   4. PAYLOAD GIỮ NGUYÊN (HTTP):
      - Nội dung HTTP request không đổi
      → VẪN detect được SQLi, XSS từ điểm này!
   
   5. HTTPS ĐƯỢC GIẢI MÃ:
      - Trước Nginx: Payload encrypted (nếu HTTPS)
      - Sau Nginx:   Payload plaintext
      → CHỈ detect được SQLi, XSS từ điểm này nếu dùng HTTPS!
""")
        
        return "\n".join(report)
    
    def export_to_json(self, filepath: str):
        """Xuất kết quả ra file JSON"""
        data = {
            "capture_time": datetime.now().isoformat(),
            "before_nginx": {
                "interface": self.before.interface,
                "packet_count": len(self.before.packets),
                "packets": [p.to_dict() for p in self.before.packets[:50]]
            },
            "after_nginx": {
                "interface": self.after.interface,
                "packet_count": len(self.after.packets),
                "packets": [p.to_dict() for p in self.after.packets[:50]]
            },
            "matched_pairs": len(self.find_matching_packets())
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Đã lưu kết quả vào: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="So sánh packets trước và sau Nginx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
    # Capture 30 giây trên 2 interface
    sudo python3 dual_sniffer_compare.py --before s1-eth1 --after s2-eth1
    
    # Capture 60 giây, chỉ port 80
    sudo python3 dual_sniffer_compare.py --before s1-eth1 --after s2-eth1 -d 60 -f "tcp port 80"
    
    # Xuất kết quả ra JSON
    sudo python3 dual_sniffer_compare.py --before s1-eth1 --after s2-eth1 --output result.json
        """
    )
    
    parser.add_argument("--before", "-b", required=True,
                        help="Interface trước Nginx (VD: s1-eth1)")
    parser.add_argument("--after", "-a", required=True,
                        help="Interface sau Nginx (VD: s2-eth1)")
    parser.add_argument("--duration", "-d", type=int, default=30,
                        help="Thời gian capture (giây, mặc định: 30)")
    parser.add_argument("--filter", "-f", default="tcp",
                        help="BPF filter (mặc định: tcp)")
    parser.add_argument("--output", "-o",
                        help="File JSON output (optional)")
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║         DUAL SNIFFER - SO SÁNH TRƯỚC/SAU NGINX               ║
╠══════════════════════════════════════════════════════════════╣
║  Công cụ này capture packets tại 2 điểm đồng thời:           ║
║  1. Trước Nginx (traffic từ Attacker/Client)                 ║
║  2. Sau Nginx (traffic tới WebServer)                        ║
║                                                              ║
║  Mục đích: Hiểu rõ Nginx thay đổi gói tin như thế nào        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"📡 Interface trước Nginx: {args.before}")
    print(f"📡 Interface sau Nginx:   {args.after}")
    print(f"⏱️  Thời gian capture:     {args.duration} giây")
    print(f"🔍 Filter:                {args.filter}")
    print(f"\n⚠️  GỬI TRAFFIC ĐẾN WEBSERVER TRONG {args.duration} GIÂY!")
    print(f"   Ví dụ: curl http://10.0.10.254/test?id=1")
    print(f"\n")
    
    # Tạo 2 capture
    before_cap = PacketCapture(args.before, "TRƯỚC_NGINX")
    after_cap = PacketCapture(args.after, "SAU_NGINX")
    
    # Bắt đầu capture song song
    before_cap.start(duration=args.duration, filter_expr=args.filter)
    after_cap.start(duration=args.duration, filter_expr=args.filter)
    
    # Đợi hoàn thành
    before_cap.wait()
    after_cap.wait()
    
    # So sánh và báo cáo
    comparator = PacketComparator(before_cap, after_cap)
    report = comparator.compare_and_report()
    print(report)
    
    # Xuất JSON nếu yêu cầu
    if args.output:
        comparator.export_to_json(args.output)


if __name__ == "__main__":
    main()
