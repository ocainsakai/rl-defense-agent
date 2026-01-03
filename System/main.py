# main.py (Real-time Capture Version)
"""
=============================================================================
NIDS REAL-TIME FEATURE EXTRACTION TOOL
Công cụ trích xuất đặc trưng thời gian thực cho hệ thống phát hiện xâm nhập

CHỨC NĂNG CHÍNH:
- Bắt gói tin từ giao diện mạng (Ethernet, Wi-Fi)
- Trích xuất 6 đặc trưng (features) từ mỗi gói tin
- Xuất kết quả ra file CSV để huấn luyện AI

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
    parser = PacketLayerExtractor(enable_http_parsing=False, use_packet_time=True)
    builder = FeatureVectorBuilder(window_size=1.0)
    sniffer = NetworkSniffer()
    
    processed_count = 0  # Bộ đếm số gói tin đã xử lý
    
    # === AGGREGATE MODE VARIABLES ===
    if mode == "aggregate":
        current_window_start = None
        window_vectors = []  # Collect vectors trong 1s
        window_duration = 1.0  # 1 second per row
        rows_written = 0
    
    # Use context manager for proper file handling
    with open(output_csv, 'w', newline='', buffering=1) as csv_file:
        writer = csv.writer(csv_file)
        
        # Write header
        header = [
            "f1_rate_norm", "f2_syn_norm", "f3_port_norm",
            "f4_len_norm", "f5_fail_norm", "f6_ctx_norm"
        ]
        writer.writerow(header)
        
        def write_aggregate_row(vectors, writer_ref):
            """
            Gộp nhiều vector thành 1 dòng CSV (lấy MAX của mỗi feature).
            
            LOGIC:
            - Xếp chồng tất cả vectors trong cửa sổ 1 giây
            - Lấy giá trị MAX của mỗi feature (vì attack thường có giá trị cao hơn normal)
            
            Args:
                vectors (list): Danh sách các vector features trong cửa sổ
                writer_ref: Đối tượng csv.writer để ghi file
            
            LƯU Ý: Dùng MAX thay vì MEAN vì:
            - Attack signatures có giá trị cao hơn normal traffic
            - MEAN sẽ bị pha loãng bởi normal packets
            """
            nonlocal rows_written
            if not vectors:
                return
            
            # Xếp chồng và lấy MAX của mỗi cột (mỗi feature)
            stacked = np.array(vectors)
            aggregated = np.max(stacked, axis=0)
            
            # Ghi ra CSV với 4 chữ số thập phân
            row = [f"{v:.4f}" for v in aggregated]
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
            nonlocal processed_count, current_window_start, window_vectors, rows_written
            processed_count += 1
            
            # Memory cleanup - ENCAPSULATED
            if processed_count % 100000 == 0:
                removed = builder.cleanup_inactive_ips(min_packets=10)
                gc.collect()
                sys.stdout.write(f" [RAM: Cleaned {removed} IPs] ")
            
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
            
            # C. Feature extraction
            vector = builder.process_layer_info(info)
            
            # D. Write to CSV based on mode
            if mode == "per-packet":
                # === PER-PACKET MODE ===
                row = [f"{v:.4f}" for v in vector]
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
                    # Still in same window, collect vector
                    window_vectors.append(vector)
                else:
                    # Window ended, write aggregate row
                    write_aggregate_row(window_vectors, writer)
                    
                    # Start new window
                    current_window_start = info.timestamp
                    window_vectors = [vector]
        
        # Use NetworkSniffer for REAL-TIME capture
        sniffer.start_live(
            interface=interface,
            callback=process_packet,
            packet_count=packet_count,
            bpf_filter="ip"
        )
        
        # Flush remaining vectors in aggregate mode
        if mode == "aggregate" and window_vectors:
            write_aggregate_row(window_vectors, writer)
    
    if mode == "aggregate":
        print(f"\n[DONE] Processed {processed_count} packets -> {rows_written} rows -> {output_csv}")
    else:
        print(f"\n[DONE] Captured {processed_count} packets -> {output_csv}")


def main():
    """
    Điểm vào chính của chương trình (CLI entry point).
    
    CHỨC NĂNG:
    - Parse các tham số dòng lệnh bằng argparse
    - Gọi hàm realtime_capture() với các tham số đã parse
    
    CÁC THAM SỐ HỖ TRỢ:
    - -i/--interface: Tên giao diện mạng (bắt buộc)
    - -o/--output: File CSV đầu ra (mặc định: realtime_features.csv)
    - -c/--count: Số lượng gói tin (mặc định: không giới hạn)
    - -m/--mode: Chế độ output (per-packet hoặc aggregate)
    """
    arg_parser = argparse.ArgumentParser(
        description="NIDS Real-time Feature Extraction - Capture from network interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py -i "Ethernet" -o features.csv
    python main.py --interface "Wi-Fi" --count 1000
    python main.py -i "WiFi" --mode aggregate -o training.csv
    
Modes:
    per-packet (default): Each packet = 1 row (for real-time IDS)
    aggregate:            Each 1 second = 1 row (for AI training)

Common Interface Names (Windows):
    - Ethernet
    - Wi-Fi
    - Loopback Pseudo-Interface 1

Note: Run as Administrator for packet capture privileges.
        """
    )
    arg_parser.add_argument(
        "-i", "--interface",
        required=True,
        metavar="IFACE",
        help="Network interface name (e.g., 'Ethernet', 'Wi-Fi')"
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
        help="Number of packets to capture (default: unlimited)"
    )
    arg_parser.add_argument(
        "-m", "--mode",
        choices=["per-packet", "aggregate"],
        default="per-packet",
        help="Output mode: 'per-packet' (1 packet = 1 row) or 'aggregate' (1s = 1 row)"
    )
    
    args = arg_parser.parse_args()
    realtime_capture(args.interface, args.output, args.count, args.mode)


if __name__ == "__main__":
    main()