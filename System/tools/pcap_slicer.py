#!/usr/bin/env python3
"""pcap_slicer.py — Cắt file PCAP/PCAPNG thành các file nhỏ hơn.

Hỗ trợ 2 chế độ:
  --mode time     : Cắt theo khoảng thời gian (giây)
  --mode packets  : Cắt theo số lượng packet

USAGE:
    # Cắt thành chunk 1 giờ (3600s)
    python tools/pcap_slicer.py -i file.pcapng -o output_dir/ --mode time --size 3600

    # Cắt thành chunk 10 phút (600s)
    python tools/pcap_slicer.py -i file.pcapng -o output_dir/ --mode time --size 600

    # Cắt thành chunk 100,000 packets
    python tools/pcap_slicer.py -i file.pcapng -o output_dir/ --mode packets --size 100000

    # Dry-run (chỉ xem thống kê, không ghi file)
    python tools/pcap_slicer.py -i file.pcapng --dry-run

OUTPUT:
    output_dir/
        <prefix>_001_<start>_<end>.pcapng
        <prefix>_002_<start>_<end>.pcapng
        ...
"""

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

# Silence scapy IPv6 warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import PcapReader, PcapWriter


# ============================================================================
# HELPER
# ============================================================================

def format_ts(epoch_float: float) -> str:
    """Float timestamp → chuỗi dễ đọc để đặt tên file."""
    return datetime.fromtimestamp(epoch_float).strftime("%Y%m%d_%H%M%S")


def open_writer(output_dir: Path, prefix: str, chunk_idx: int,
                first_ts: float, last_ts: float) -> PcapWriter:
    """Tạo PcapWriter cho chunk mới."""
    fname = f"{prefix}_{chunk_idx:04d}_{format_ts(first_ts)}_{format_ts(last_ts)}.pcapng"
    path = output_dir / fname
    return PcapWriter(str(path), append=False, sync=True), path


def progress_line(n_pkts: int, n_chunks: int, current_size: int,
                  mode: str, chunk_size: float):
    """In dòng progress."""
    if mode == "time":
        bar = f"chunk#{n_chunks} [{current_size:.1f}s / {chunk_size}s]"
    else:
        bar = f"chunk#{n_chunks} [{current_size:,} / {int(chunk_size):,} pkts]"
    sys.stdout.write(f"\r  pkts={n_pkts:>10,}  {bar}    ")
    sys.stdout.flush()


# ============================================================================
# DRY-RUN: chỉ thống kê, không ghi file
# ============================================================================

def dry_run(input_file: str):
    """Quét file và in thống kê để tư vấn cách cắt."""
    print(f"\n[Dry-run] Scanning: {input_file}")
    print("  (Chỉ đọc, không ghi file)\n")

    count = 0
    first_time = None
    last_time = None
    sizes = []

    with PcapReader(input_file) as reader:
        for pkt in reader:
            count += 1
            t = float(pkt.time)
            if first_time is None:
                first_time = t
            last_time = t
            sizes.append(len(pkt))
            if count % 50000 == 0:
                sys.stdout.write(f"\r  Scanned: {count:,} packets...")
                sys.stdout.flush()

    print(f"\r  Scanned: {count:,} packets      ")

    duration = last_time - first_time
    avg_pkt = sum(sizes) / len(sizes)

    print(f"\n{'='*55}")
    print(f"  File           : {input_file}")
    print(f"  Total packets  : {count:,}")
    print(f"  Duration       : {duration:.1f}s  ({duration/3600:.2f} hours)")
    print(f"  First packet   : {datetime.fromtimestamp(first_time)}")
    print(f"  Last  packet   : {datetime.fromtimestamp(last_time)}")
    print(f"  Avg pkt size   : {avg_pkt:.0f} bytes")
    print(f"  Avg rate       : {count/duration:.0f} pkt/s")
    print(f"{'='*55}")
    print("\n  GỢI Y CAT FILE:")
    print(f"  --mode time --size 3600   → ~{duration/3600:.0f} files (1h/file)")
    print(f"  --mode time --size 600    → ~{duration/600:.0f} files (10min/file)")
    print(f"  --mode time --size 60     → ~{duration/60:.0f} files (1min/file)")
    print(f"  --mode packets --size 100000  → ~{count//100000} files (100k pkts/file)")
    print(f"  --mode packets --size 50000   → ~{count//50000} files (50k pkts/file)")
    print()


# ============================================================================
# SLICE BY TIME
# ============================================================================

def slice_by_time(input_file: str, output_dir: Path, prefix: str,
                  chunk_seconds: float):
    """Cắt theo khoảng thời gian."""
    print(f"\n[Slice by time] chunk={chunk_seconds}s")

    output_dir.mkdir(parents=True, exist_ok=True)

    chunk_idx = 0
    total_pkts = 0
    chunk_first_ts = None
    chunk_last_ts = None
    writer = None
    out_path = None
    files_created = []

    chunk_start_ts = None  # epoch của chunk bắt đầu

    with PcapReader(input_file) as reader:
        for pkt in reader:
            t = float(pkt.time)

            # Khởi tạo chunk đầu tiên
            if chunk_start_ts is None:
                chunk_start_ts = t
                chunk_idx = 1
                chunk_first_ts = t
                # Tạo writer tạm (sẽ rename khi đóng)
                tmp_path = output_dir / f"{prefix}_{chunk_idx:04d}_TMP.pcapng"
                writer = PcapWriter(str(tmp_path), append=False, sync=True)
                out_path = tmp_path

            # Kiểm tra nếu đã vượt chunk_seconds → đóng chunk, mở chunk mới
            if t - chunk_start_ts >= chunk_seconds:
                writer.close()
                # Rename với timestamp thật
                final_name = (
                    f"{prefix}_{chunk_idx:04d}"
                    f"_{format_ts(chunk_first_ts)}"
                    f"_{format_ts(chunk_last_ts)}.pcapng"
                )
                final_path = output_dir / final_name
                out_path.rename(final_path)
                files_created.append(final_path.name)

                # Chunk mới
                chunk_idx += 1
                chunk_start_ts = t
                chunk_first_ts = t
                tmp_path = output_dir / f"{prefix}_{chunk_idx:04d}_TMP.pcapng"
                writer = PcapWriter(str(tmp_path), append=False, sync=True)
                out_path = tmp_path

            writer.write(pkt)
            chunk_last_ts = t
            total_pkts += 1

            if total_pkts % 50000 == 0:
                progress_line(total_pkts, chunk_idx,
                              t - chunk_start_ts, "time", chunk_seconds)

    # Đóng chunk cuối
    if writer:
        writer.close()
        final_name = (
            f"{prefix}_{chunk_idx:04d}"
            f"_{format_ts(chunk_first_ts)}"
            f"_{format_ts(chunk_last_ts)}.pcapng"
        )
        final_path = output_dir / final_name
        out_path.rename(final_path)
        files_created.append(final_path.name)

    print(f"\r  Done: {total_pkts:,} packets → {len(files_created)} files")
    print(f"  Output dir: {output_dir}")
    for f in files_created[:5]:
        print(f"    {f}")
    if len(files_created) > 5:
        print(f"    ... ({len(files_created)-5} more files)")


# ============================================================================
# SLICE BY PACKET COUNT
# ============================================================================

def slice_by_packets(input_file: str, output_dir: Path, prefix: str,
                     chunk_size: int):
    """Cắt theo số lượng packet."""
    print(f"\n[Slice by packets] chunk={chunk_size:,} pkts")

    output_dir.mkdir(parents=True, exist_ok=True)

    chunk_idx = 1
    pkt_in_chunk = 0
    total_pkts = 0
    chunk_first_ts = None
    chunk_last_ts = None
    files_created = []

    tmp_path = output_dir / f"{prefix}_{chunk_idx:04d}_TMP.pcapng"
    writer = PcapWriter(str(tmp_path), append=False, sync=True)
    out_path = tmp_path

    with PcapReader(input_file) as reader:
        for pkt in reader:
            t = float(pkt.time)

            if chunk_first_ts is None:
                chunk_first_ts = t

            writer.write(pkt)
            chunk_last_ts = t
            pkt_in_chunk += 1
            total_pkts += 1

            if total_pkts % 50000 == 0:
                progress_line(total_pkts, chunk_idx,
                              pkt_in_chunk, "packets", chunk_size)

            # Chunk đầy → đóng và mở chunk mới
            if pkt_in_chunk >= chunk_size:
                writer.close()
                final_name = (
                    f"{prefix}_{chunk_idx:04d}"
                    f"_{format_ts(chunk_first_ts)}"
                    f"_{format_ts(chunk_last_ts)}.pcapng"
                )
                final_path = output_dir / final_name
                out_path.rename(final_path)
                files_created.append(final_path.name)

                chunk_idx += 1
                pkt_in_chunk = 0
                chunk_first_ts = None
                tmp_path = output_dir / f"{prefix}_{chunk_idx:04d}_TMP.pcapng"
                writer = PcapWriter(str(tmp_path), append=False, sync=True)
                out_path = tmp_path

    # Đóng chunk cuối (có thể < chunk_size)
    writer.close()
    if pkt_in_chunk > 0:
        final_name = (
            f"{prefix}_{chunk_idx:04d}"
            f"_{format_ts(chunk_first_ts)}"
            f"_{format_ts(chunk_last_ts)}.pcapng"
        )
        final_path = output_dir / final_name
        out_path.rename(final_path)
        files_created.append(final_path.name)
    else:
        out_path.unlink(missing_ok=True)

    print(f"\r  Done: {total_pkts:,} packets → {len(files_created)} files")
    print(f"  Output dir: {output_dir}")
    for f in files_created[:5]:
        print(f"    {f}")
    if len(files_created) > 5:
        print(f"    ... ({len(files_created)-5} more files)")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PCAP/PCAPNG Slicer — cat file thanh cac chunk nho",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Xem thong ke truoc khi cat:
  python tools/pcap_slicer.py -i file.pcapng --dry-run

  # Cat theo thoi gian 1h/file:
  python tools/pcap_slicer.py -i file.pcapng -o slices/ --mode time --size 3600

  # Cat theo so packet 100k/file:
  python tools/pcap_slicer.py -i file.pcapng -o slices/ --mode packets --size 100000
        """
    )

    parser.add_argument("-i", "--input",  required=True,
                        help="Input PCAP/PCAPNG file")
    parser.add_argument("-o", "--output", default="slices/",
                        help="Output directory (default: slices/)")
    parser.add_argument("--mode", choices=["time", "packets"], default="time",
                        help="Slice mode: 'time' (seconds) or 'packets' (count)")
    parser.add_argument("--size", type=float, default=3600,
                        help="Chunk size: seconds (time mode) or packet count (packets mode). Default: 3600")
    parser.add_argument("--prefix", default=None,
                        help="Output filename prefix (default: input filename stem)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Only print stats, do not write any files")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    if args.dry_run:
        dry_run(args.input)
        return

    output_dir = Path(args.output)
    prefix = args.prefix or Path(args.input).stem

    if args.mode == "time":
        slice_by_time(args.input, output_dir, prefix, float(args.size))
    else:
        slice_by_packets(args.input, output_dir, prefix, int(args.size))


if __name__ == "__main__":
    main()
