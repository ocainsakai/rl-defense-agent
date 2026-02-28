#!/usr/bin/env python3
"""
"""

import argparse
import logging
import os
from datetime import datetime
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Raw, Ether, ARP, DNS

# Global logger
logger = None


def format_tcp_flags(tcp):
    """Format TCP flags"""
    flags = []
    if tcp.flags.S: flags.append("SYN")
    if tcp.flags.A: flags.append("ACK")
    if tcp.flags.F: flags.append("FIN")
    if tcp.flags.R: flags.append("RST")
    if tcp.flags.P: flags.append("PSH")
    if tcp.flags.U: flags.append("URG")
    return "[" + ",".join(flags) + "]" if flags else "[]"


def setup_logging(log_file: str):
    """Thiết lập logging ra file"""
    global logger
    
    # Tạo thư mục nếu chưa có
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logger = logging.getLogger("PacketViewer")
    logger.setLevel(logging.DEBUG)
    
    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    
    logger.addHandler(file_handler)
    print(f"📝 Log file: {log_file}")
    return logger


def log_and_print(message: str):
    """In ra console và ghi log"""
    print(message)
    if logger:
        logger.info(message)


def print_packet(pkt, packet_num):
    """In thông tin packet giống Wireshark"""
    # Dùng timestamp thật của packet (từ PCAP hoặc capture time)
    pkt_time = getattr(pkt, 'time', None)
    if pkt_time:
        timestamp = datetime.fromtimestamp(float(pkt_time)).strftime("%H:%M:%S.%f")[:-3]
    else:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    # Header
    log_and_print(f"\n{'='*70}")
    log_and_print(f"Packet #{packet_num} | {timestamp}")
    log_and_print(f"{'='*70}")
    
    # Layer 2 - Ethernet
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        log_and_print(f"[Ethernet]")
        log_and_print(f"  Src MAC:  {eth.src}")
        log_and_print(f"  Dst MAC:  {eth.dst}")
        log_and_print(f"  Type:     {hex(eth.type)}")
    
    # ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        log_and_print(f"[ARP]")
        log_and_print(f"  Operation: {'Request' if arp.op == 1 else 'Reply'}")
        log_and_print(f"  Sender:    {arp.psrc} ({arp.hwsrc})")
        log_and_print(f"  Target:    {arp.pdst} ({arp.hwdst})")
        return
    
    # Layer 3 - IP
    if pkt.haslayer(IP):
        ip = pkt[IP]
        log_and_print(f"[IP]")
        log_and_print(f"  Src IP:   {ip.src}")
        log_and_print(f"  Dst IP:   {ip.dst}")
        log_and_print(f"  TTL:      {ip.ttl}")
        log_and_print(f"  Protocol: {ip.proto} ({'TCP' if ip.proto == 6 else 'UDP' if ip.proto == 17 else 'ICMP' if ip.proto == 1 else 'Other'})")
        log_and_print(f"  Length:   {ip.len} bytes")
    
    # Layer 4 - TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        log_and_print(f"[TCP]")
        log_and_print(f"  Src Port: {tcp.sport}")
        log_and_print(f"  Dst Port: {tcp.dport}")
        log_and_print(f"  Flags:    {format_tcp_flags(tcp)}")
        log_and_print(f"  Seq:      {tcp.seq}")
        log_and_print(f"  Ack:      {tcp.ack}")
        log_and_print(f"  Window:   {tcp.window}")
    
    # Layer 4 - UDP
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        log_and_print(f"[UDP]")
        log_and_print(f"  Src Port: {udp.sport}")
        log_and_print(f"  Dst Port: {udp.dport}")
        log_and_print(f"  Length:   {udp.len}")
    
    # Layer 4 - ICMP
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        log_and_print(f"[ICMP]")
        log_and_print(f"  Type:     {icmp.type} ({icmp_types.get(icmp.type, 'Other')})")
        log_and_print(f"  Code:     {icmp.code}")
    
    # DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        log_and_print(f"[DNS]")
        log_and_print(f"  QR:       {'Response' if dns.qr else 'Query'}")
        if dns.qd:
            log_and_print(f"  Query:    {dns.qd.qname.decode() if dns.qd.qname else 'N/A'}")
    
    # Payload
    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        log_and_print(f"[Payload] ({len(raw)} bytes)")
        
        # Thử decode UTF-8
        try:
            text = raw.decode('utf-8', errors='replace')
            # Hiển thị tối đa 500 ký tự
            if len(text) > 500:
                text = text[:500] + "..."
            # In từng dòng
            for line in text.split('\n')[:15]:
                log_and_print(f"  | {line.strip()}")
            if text.count('\n') > 15:
                log_and_print(f"  | ... (truncated)")
        except:
            # Hiển thị hex
            hex_str = raw[:100].hex()
            log_and_print(f"  HEX: {hex_str}")
            if len(raw) > 100:
                log_and_print(f"  ... ({len(raw) - 100} more bytes)")


def main():
    parser = argparse.ArgumentParser(
        description="Packet Viewer - Hiển thị packet như Wireshark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
    # Sniff trên interface eth0
    sudo python3 main_packet_viewer.py -i eth0
    
    # Chỉ xem TCP port 80
    sudo python3 main_packet_viewer.py -i eth0 -f "tcp port 80"
    
    # Đọc từ file PCAP
    sudo python3 main_packet_viewer.py -r capture.pcap
    
    # Giới hạn số packet
    sudo python3 main_packet_viewer.py -i eth0 -c 100
    
    # Ghi log ra file
    sudo python3 main_packet_viewer.py -i eth0 -l logs/packets.log
        """
    )
    
    parser.add_argument("-i", "--interface", help="Interface để sniff (VD: eth0, s1-eth1)")
    parser.add_argument("-r", "--read", help="Đọc từ file PCAP")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (VD: 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Số packet tối đa (0 = unlimited)")
    parser.add_argument("-l", "--log", help="Ghi log ra file (VD: logs/packets.log)")
    
    args = parser.parse_args()
    
    if not args.interface and not args.read:
        parser.error("Cần chỉ định -i INTERFACE hoặc -r PCAP_FILE")
    
    # Setup logging nếu có
    if args.log:
        setup_logging(args.log)
    
    packet_counter = [0]  # Dùng list để có thể modify trong closure
    
    def packet_handler(pkt):
        packet_counter[0] += 1
        print_packet(pkt, packet_counter[0])
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║              PACKET VIEWER - Xem packet như Wireshark        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if args.read:
        # Đọc từ file PCAP
        print(f"📁 Đọc file: {args.read}")
        packets = rdpcap(args.read)
        
        count = args.count if args.count > 0 else len(packets)
        for i, pkt in enumerate(packets[:count], 1):
            print_packet(pkt, i)
        
        print(f"\n✅ Đã hiển thị {min(count, len(packets))}/{len(packets)} packets")
    else:
        # Sniff live
        print(f"📡 Sniffing trên: {args.interface}")
        print(f"🔍 Filter: {args.filter if args.filter else '(none)'}")
        print(f"📊 Max packets: {args.count if args.count > 0 else 'unlimited'}")
        print(f"\n⌨️  Ctrl+C để dừng\n")
        
        try:
            sniff(
                iface=args.interface,
                filter=args.filter,
                prn=packet_handler,
                count=args.count if args.count > 0 else 0,
                store=False
            )
        except KeyboardInterrupt:
            print(f"\n\n✅ Đã capture {packet_counter[0]} packets")
        except PermissionError:
            print("❌ Lỗi: Cần quyền root. Chạy với sudo.")
        except OSError as e:
            print(f"❌ Lỗi interface: {e}")
            print("   Kiểm tra tên interface bằng: ip link show")


if __name__ == "__main__":
    main()
