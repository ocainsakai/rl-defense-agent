# main.py (Real-time Capture Version)
"""
=============================================================================
NIDS REAL-TIME FEATURE EXTRACTION TOOL
Công cụ trích xuất đặc trưng thời gian thực cho hệ thống phát hiện xâm nhập

CHỨC NĂNG CHÍNH:
- Bắt gói tin từ giao diện mạng (Ethernet, Wi-Fi)
- Trích xuất 6 đặc trưng (features) từ mỗi gói tin

⚠️ QUAN TRỌNG: Tất cả features trả về RAW VALUES (không normalize)
- Dùng để so sánh với CICFlowMeter
- Normalize riêng sau nếu cần cho AI training

CÁC CHẾ ĐỘ HOẠT ĐỘNG:
1. per-packet (mặc định): Mỗi gói tin = 1 dòng CSV (dùng cho IDS thời gian thực)
2. aggregate: Mỗi 1 giây = 1 dòng CSV (dùng cho huấn luyện AI)

CÁCH SỬ DỤNG:
    python main.py -i "Ethernet" -o output.csv
    python main.py --interface "Wi-Fi" --output features.csv
    python main.py -i "WiFi" --mode aggregate   # Cho huấn luyện AI (1s = 1 row)
    python main.py --help

LƯU Ý: Cần chạy với quyền Administrator trên Windows để bắt gói tin.
=============================================================================
"""

import argparse
import csv
import sys
import gc
import time
import numpy as np
from core.sniffer import NetworkSniffer
from core.packet_parser import PacketLayerExtractor
from core.processor import FeatureVectorBuilder


def realtime_capture(interface: str, output_csv: str, packet_count: int = None, mode: str = "per-packet"):
    """
    Bắt gói tin thời gian thực từ giao diện mạng và trích xuất đặc trưng.
    
    CHỨC NĂNG:
    - Khởi tạo các component: parser, builder, sniffer
    - Xử lý từng gói tin và trích xuất vector 6 features
    - Ghi kết quả ra file CSV theo mode được chọn
    
    Args:
        interface (str): Tên giao diện mạng (VD: "Ethernet", "Wi-Fi")
        output_csv (str): Đường dẫn file CSV đầu ra
        packet_count (int): Số gói tin tối đa cần bắt (None = không giới hạn)
        mode (str): Chế độ output:
            - "per-packet": Mỗi gói tin = 1 dòng (cho IDS thời gian thực)
            - "aggregate": Mỗi 1 giây = 1 dòng (cho huấn luyện AI)
    
    LƯU Ý QUAN TRỌNG:
    - Cần quyền Administrator để bắt gói tin
    - Memory cleanup tự động sau mỗi 100,000 packets
    - Nhấn Ctrl+C để dừng nếu không giới hạn số lượng
    """
    print(f"\n[>>>] REAL-TIME CAPTURE MODE")
    print(f"[+] Interface: {interface}")
    print(f"[+] Output: {output_csv}")
    print(f"[+] Mode: {mode}")
    if packet_count:
        print(f"[+] Max packets: {packet_count}")
    else:
        print(f"[+] Max packets: Unlimited (Press Ctrl+C to stop)")
    
    # ===========================================================
    # KHỞI TẠO CÁC THÀNH PHẦN CHÍNH
    # ===========================================================
    # parser: Phân tích gói tin Scapy thành LayerInfo
    # builder: Tính toán 6 features từ LayerInfo
    # sniffer: Bắt gói tin từ giao diện mạng
    # Live capture: use system wall-clock time for sliding-window correctness in real-time
    parser = PacketLayerExtractor(enable_http_parsing=False, use_packet_time=False)
    builder = FeatureVectorBuilder(window_size=1.0)
    sniffer = NetworkSniffer()
    
    processed_count = 0  # Bộ đếm số gói tin đã xử lý
    
    # === AGGREGATE MODE VARIABLES ===
    if mode == "aggregate":
        current_window_start = None
        window_vectors = []  # Collect vectors trong 1s
        window_tuple_info = []  # Collect 5-tuple info
        window_duration = 1.0  # 1 second per row
        rows_written = 0
    
    # Use context manager for proper file handling
    with open(output_csv, 'w', newline='', buffering=1) as csv_file:
        writer = csv.writer(csv_file)
        
        # Write header - 5-TUPLE + RAW FEATURES
        header = [
            "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol",
            "F1_PacketRate_RAW", "F2_SynRatio_RAW", "F3_DistinctPorts_RAW",
            "F4_PayloadLen_RAW", "F5_FailRate_RAW", "F6_ContextScore_RAW"
        ]
        writer.writerow(header)
        
        def write_aggregate_row(vectors, tuple_infos, writer_ref):
            """
            Gộp nhiều vector thành 1 dòng CSV (lấy MAX của mỗi feature).
            
            LOGIC:
            - Xếp chồng tất cả vectors trong cửa sổ 1 giây
            - Lấy giá trị MAX của mỗi feature (vì attack thường có giá trị cao hơn normal)
            
            Args:
                vectors (list): Danh sách các vector features trong cửa sổ
                tuple_infos (list): Danh sách 5-tuple info trong window
                writer_ref: Đối tượng csv.writer để ghi file
            
            LƯU Ý: 
            - Dùng MAX thay vì MEAN vì attack signatures có giá trị cao hơn normal
            - MEAN sẽ bị pha loãng bởi normal packets
            - Output là RAW VALUES (không normalize)
            - 5-tuple lấy từ packet đầu tiên trong window
            """
            nonlocal rows_written
            if not vectors:
                return
            
            # Lấy 5-tuple từ packet đầu tiên trong window (representative)
            if tuple_infos:
                tuple_row = tuple_infos[0]
            else:
                tuple_row = ["", "", 0, 0, ""]
            
            # Xếp chồng và lấy MAX của mỗi cột (mỗi feature)
            stacked = np.array(vectors)
            aggregated = np.max(stacked, axis=0)
            
            # Ghi ra CSV: 5-tuple + features
            feature_row = [f"{v:.4f}" for v in aggregated]
            row = tuple_row + feature_row
            writer_ref.writerow(row)
            rows_written += 1
        
        def process_packet(pkt):
            """
            Callback xử lý từng gói tin được bắt.
            
            PIPELINE XỬ LÝ:
            1. Memory cleanup (mỗi 100,000 packets)
            2. Parse gói tin thành LayerInfo
            3. Hiển thị tiến độ (mỗi 100 packets)
            4. Trích xuất vector 6 features
            5. Ghi ra CSV (theo mode per-packet hoặc aggregate)
            
            Args:
                pkt: Raw packet từ Scapy sniffer
            """
            nonlocal processed_count, current_window_start, window_vectors, window_tuple_info, rows_written
            processed_count += 1
            
            # Memory cleanup - ENCAPSULATED
            if processed_count % 100000 == 0:
                removed = builder.cleanup_inactive_flows()
                gc.collect()
                sys.stdout.write(f" [RAM: Cleaned {removed} flows] ")
            
            # A. Parse packet information
            info = parser.parse(pkt)
            if info is None or not info.src_ip:
                return
            
            # B. Progress display
            if processed_count % 100 == 0:
                if mode == "aggregate":
                    sys.stdout.write(f"\r[*] Packets: {processed_count} | Rows: {rows_written} | TS: {info.timestamp:.0f}")
                else:
                    sys.stdout.write(f"\r[*] Captured: {processed_count} | TS: {info.timestamp:.0f}")
                sys.stdout.flush()
            
            # C. Extract 5-tuple info
            src_port = info.tcp_sport or info.udp_sport or 0
            dst_port = info.tcp_dport or info.udp_dport or 0
            proto = "TCP" if info.has_tcp else ("UDP" if info.has_udp else "ICMP" if info.has_icmp else "OTHER")
            
            # D. Feature extraction
            vector = builder.process_layer_info(info)
            
            # E. Write to CSV based on mode
            if mode == "per-packet":
                # === PER-PACKET MODE ===
                # 5-tuple + features
                tuple_info = [info.src_ip, info.dst_ip, src_port, dst_port, proto]
                feature_values = [f"{v:.4f}" for v in vector]
                row = tuple_info + feature_values
                try:
                    writer.writerow(row)
                except IOError as e:
                    print(f"\n[!] CRITICAL: Disk write failed ({e})")
                    sys.exit(1)
            else:
                # === AGGREGATE MODE ===
                # Initialize window start time
                if current_window_start is None:
                    current_window_start = info.timestamp
                
                # Check if current packet is still in window
                if info.timestamp - current_window_start < window_duration:
                    # Still in same window, collect vector and 5-tuple
                    tuple_info = [info.src_ip, info.dst_ip, src_port, dst_port, proto]
                    window_vectors.append(vector)
                    window_tuple_info.append(tuple_info)
                else:
                    # Window ended, write aggregate row
                    write_aggregate_row(window_vectors, window_tuple_info, writer)
                    
                    # Start new window
                    current_window_start = info.timestamp
                    tuple_info = [info.src_ip, info.dst_ip, src_port, dst_port, proto]
                    window_vectors = [vector]
                    window_tuple_info = [tuple_info]
        
        # Use NetworkSniffer for REAL-TIME capture
        sniffer.start_live(
            interface=interface,
            callback=process_packet,
            packet_count=packet_count,
            bpf_filter="ip"
        )
        
        # Flush remaining vectors in aggregate mode
        if mode == "aggregate" and window_vectors:
            write_aggregate_row(window_vectors, window_tuple_info, writer)
    
    if mode == "aggregate":
        print(f"\n[DONE] Processed {processed_count} packets -> {rows_written} rows -> {output_csv}")
    else:
        print(f"\n[DONE] Captured {processed_count} packets -> {output_csv}")


def pcap_capture(pcap_file: str, output_csv: str, mode: str = "per-packet", verbose: bool = False):
    """
    Đọc file PCAP và trích xuất đặc trưng.
    
    Args:
        pcap_file (str): Đường dẫn file PCAP
        output_csv (str): Đường dẫn file CSV đầu ra
        mode (str): Chế độ output (per-packet hoặc aggregate)
        verbose (bool): In chi tiết flow tuple ra màn hình
    """
    from scapy.all import PcapReader
    import os
    from datetime import datetime
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: File không tồn tại: {pcap_file}")
        sys.exit(1)
    
    print(f"\n[>>>] PCAP FILE MODE")
    print(f"[+] Input: {pcap_file}")
    print(f"[+] Output: {output_csv}")
    print(f"[+] Mode: {mode}")
    print(f"[+] Verbose: {verbose}")
    
    # Khởi tạo components
    # PCAP/offline: preserve original capture timestamps
    parser = PacketLayerExtractor(enable_http_parsing=False, use_packet_time=True)
    builder = FeatureVectorBuilder(window_size=1.0)
    
    processed_count = 0
    first_timestamp = None
    
    # Aggregate mode variables
    window_vectors = []
    window_flow_info = []
    current_window_start = None
    window_duration = 1.0
    
    # Headers với flow info - RAW VALUES
    flow_headers = ['Timestamp', 'SrcIP', 'DstIP', 'SrcPort', 'DstPort', 'Protocol', 'Duration']
    feature_headers = ['F1_PacketRate_RAW', 'F2_SynRatio_RAW', 'F3_DistinctPorts_RAW', 
                       'F4_PayloadLen_RAW', 'F5_FailRate_RAW', 'F6_ContextScore_RAW']
    headers = flow_headers + feature_headers
    
    def format_timestamp(ts):
        try:
            return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        except:
            return str(ts)
    
    def write_aggregate_row(vectors, flow_infos, writer_ref, window_start):
        if not vectors:
            return
        stacked = np.array(vectors)
        aggregated = np.max(stacked, axis=0)
        
        # Lấy thông tin flow đại diện (first flow in window)
        if flow_infos:
            fi = flow_infos[0]
            duration = flow_infos[-1]['ts'] - flow_infos[0]['ts']
            flow_row = [format_timestamp(window_start), fi['src_ip'], fi['dst_ip'], 
                       fi['src_port'], fi['dst_port'], fi['proto'], f"{duration:.3f}"]
        else:
            flow_row = ['', '', '', '', '', '', '']
        
        feature_row = [f"{v:.4f}" for v in aggregated]
        writer_ref.writerow(flow_row + feature_row)
    
    if verbose:
        print(f"\n{'='*100}")
        print(f"{'Timestamp':<24} {'SrcIP':<16} {'DstIP':<16} {'Src:Dst':<12} {'Proto':<6} {'Flags':<6} Vector")
        print(f"{'='*100}")
    
    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for pkt in pcap_reader:
                    try:
                        info = parser.extract(pkt)
                        if info is None or not info.has_ip:
                            continue
                        
                        if first_timestamp is None:
                            first_timestamp = info.timestamp
                        
                        vector = builder.process_layer_info(info)
                        processed_count += 1
                        
                        # Flow info
                        src_port = info.tcp_sport or info.udp_sport or 0
                        dst_port = info.tcp_dport or info.udp_dport or 0
                        proto = "TCP" if info.has_tcp else ("UDP" if info.has_udp else "OTHER")
                        duration = info.timestamp - first_timestamp
                        
                        flow_info = {
                            'ts': info.timestamp,
                            'src_ip': info.src_ip,
                            'dst_ip': info.dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'proto': proto
                        }
                        
                        # Verbose output
                        if verbose and processed_count <= 50:
                            flags = info.tcp_flags or "-"
                            vec_str = "[" + ", ".join(f"{v:.2f}" for v in vector) + "]"
                            print(f"{format_timestamp(info.timestamp):<24} {info.src_ip:<16} {info.dst_ip:<16} "
                                  f"{src_port}:{dst_port:<6} {proto:<6} {flags:<6} {vec_str}")
                        
                        if mode == "aggregate":
                            if current_window_start is None:
                                current_window_start = info.timestamp
                            
                            if info.timestamp - current_window_start < window_duration:
                                window_vectors.append(vector)
                                window_flow_info.append(flow_info)
                            else:
                                write_aggregate_row(window_vectors, window_flow_info, writer, current_window_start)
                                current_window_start = info.timestamp
                                window_vectors = [vector]
                                window_flow_info = [flow_info]
                        else:
                            # Per-packet mode: write each row
                            flow_row = [format_timestamp(info.timestamp), info.src_ip, info.dst_ip,
                                       src_port, dst_port, proto, f"{duration:.3f}"]
                            feature_row = [f"{v:.4f}" for v in vector]
                            writer.writerow(flow_row + feature_row)
                        
                        if processed_count % 1000 == 0:
                            print(f"[*] Processed: {processed_count} packets...")
                            
                    except Exception as e:
                        continue
                
                # Write last window for aggregate mode
                if mode == "aggregate" and window_vectors:
                    write_aggregate_row(window_vectors, window_flow_info, writer, current_window_start)
                    
        except Exception as e:
            print(f"[!] Error reading PCAP: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    if verbose and processed_count > 50:
        print(f"... (hiển thị 50 packets đầu, còn {processed_count - 50} packets)")
    
    stats = builder.get_stats()
    print(f"\n{'='*60}")
    print(f"[+] Done!")
    print(f"[+] Total packets processed: {processed_count}")
    print(f"[+] Flows: {stats.get('total_flows', 0)}")
    print(f"[+] Hosts: {stats.get('total_hosts', 0)}")
    print(f"[+] Output saved: {output_csv}")
    print(f"{'='*60}")


def main():
    """
    Điểm vào chính của chương trình (CLI entry point).
    
    CHỨC NĂNG:
    - Parse các tham số dòng lệnh bằng argparse
    - Hỗ trợ 2 mode: live capture (-i) và đọc PCAP (-p)
    
    CÁC THAM SỐ HỖ TRỢ:
    - -i/--interface: Tên giao diện mạng (live capture)
    - -p/--pcap: Đường dẫn file PCAP (đọc file)
    - -o/--output: File CSV đầu ra (mặc định: realtime_features.csv)
    - -c/--count: Số lượng gói tin (mặc định: không giới hạn)
    - -m/--mode: Chế độ output (per-packet hoặc aggregate)
    """
    arg_parser = argparse.ArgumentParser(
        description="NIDS Feature Extraction - Capture from network or read PCAP file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Live capture
    python main.py -i "Ethernet" -o features.csv
    python main.py --interface "Wi-Fi" --count 1000
    
    # Read PCAP file
    python main.py -p capture.pcap -o features.csv
    python main.py --pcap data/sample.pcap --mode aggregate
    
Modes:
    per-packet (default): Each packet = 1 row (for real-time IDS)
    aggregate:            Each 1 second = 1 row (for AI training)

Note: Run as Administrator for live packet capture privileges.
        """
    )
    
    # Input source (mutually exclusive)
    input_group = arg_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i", "--interface",
        metavar="IFACE",
        help="Network interface name for live capture (e.g., 'Ethernet', 'Wi-Fi')"
    )
    input_group.add_argument(
        "-p", "--pcap",
        metavar="FILE",
        help="PCAP file path to read"
    )
    
    arg_parser.add_argument(
        "-o", "--output",
        default="realtime_features.csv",
        metavar="FILE",
        help="Output CSV file (default: realtime_features.csv)"
    )
    arg_parser.add_argument(
        "-c", "--count",
        type=int,
        default=None,
        metavar="N",
        help="Number of packets to capture (default: unlimited, only for live)"
    )
    arg_parser.add_argument(
        "-m", "--mode",
        choices=["per-packet", "aggregate"],
        default="per-packet",
        help="Output mode: 'per-packet' (1 packet = 1 row) or 'aggregate' (1s = 1 row)"
    )
    arg_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose: print flow tuple info (SrcIP, DstIP, Ports, etc.) to screen"
    )
    
    args = arg_parser.parse_args()
    
    if args.pcap:
        # PCAP file mode
        pcap_capture(args.pcap, args.output, args.mode, args.verbose)
    else:
        # Live capture mode
        realtime_capture(args.interface, args.output, args.count, args.mode)


if __name__ == "__main__":
    main()