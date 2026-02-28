#!/usr/bin/env python3
"""csv_slicer.py — Cắt file CSV thành các file nhỏ hơn.

Hỗ trợ 2 chế độ:
  --mode rows : Cắt theo số dòng
  --mode time : Cắt theo khoảng thời gian (giây)

USAGE:
    # Xem thống kê trước khi cắt:
    python tools/csv_slicer.py -i normal_data.csv --dry-run

    # Cắt thành chunk 10,000 dòng/file:
    python tools/csv_slicer.py -i normal_data.csv -o slices/ --mode rows --size 10000

    # Cắt thành chunk 60 giây/file:
    python tools/csv_slicer.py -i normal_data.csv -o slices/ --mode time --size 60

OUTPUT:
    slices/
        normal_data_0001.csv   <- có header
        normal_data_0002.csv   <- có header
        ...
"""

import argparse
import csv
import os
import sys
from pathlib import Path


# ============================================================================
# HELPER
# ============================================================================

def _parse_timestamp(row: dict) -> float:
    """Lấy timestamp từ row CSV.

    Ưu tiên: Frame Time (Epoch) + Time (relative) để giữ sub-second.
    - Nếu Frame Time (Epoch) là integer (không có '.') → cộng Time relative.
    - Fallback: dùng Time (relative) trực tiếp.
    """
    epoch_raw = row.get("Frame Time (Epoch)", "")
    time_raw  = row.get("Time", "")

    try:
        epoch = float(epoch_raw)
    except (ValueError, TypeError):
        epoch = None

    try:
        relative = float(time_raw)
    except (ValueError, TypeError):
        relative = None

    if epoch is not None:
        if "." not in str(epoch_raw) and relative is not None:
            return epoch + relative
        return epoch

    return relative  # None nếu cả hai đều không có


def _open_chunk(output_dir: Path, prefix: str, chunk_idx: int,
                fieldnames: list):
    """Mở file CSV mới cho chunk, trả về (file_handle, DictWriter, path)."""
    path   = output_dir / f"{prefix}_{chunk_idx:04d}.csv"
    fh     = open(path, "w", encoding="utf-8", newline="")
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    return fh, writer, path


def _progress(n_rows: int, n_chunks: int) -> None:
    sys.stdout.write(f"\r  rows={n_rows:>10,}  files={n_chunks}")
    sys.stdout.flush()


# ============================================================================
# DRY-RUN
# ============================================================================

def dry_run(input_file: str) -> None:
    """Quét toàn bộ file, in thống kê và gợi ý cách cắt."""
    print(f"\n[Dry-run] Scanning: {input_file}")
    print("  (Chi doc, khong ghi file)\n")

    total_rows = 0
    first_ts   = None
    last_ts    = None
    file_size  = os.path.getsize(input_file)

    with open(input_file, encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_rows += 1
            ts = _parse_timestamp(row)
            if ts is not None:
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
            if total_rows % 100_000 == 0:
                sys.stdout.write(f"\r  Scanned: {total_rows:,} rows...")
                sys.stdout.flush()

    print(f"\r  Scanned: {total_rows:,} rows      ")

    size_mb = file_size / 1_048_576
    print(f"\n{'='*55}")
    print(f"  File    : {input_file}")
    print(f"  Rows    : {total_rows:,}")
    print(f"  Size    : {size_mb:.1f} MB")

    if first_ts is not None and last_ts is not None:
        duration = last_ts - first_ts
        print(f"  Duration: {duration:.1f}s  ({duration / 3600:.2f} hours)")
    else:
        duration = None
        print(f"  Duration: N/A (khong doc duoc timestamp)")

    print(f"{'='*55}")
    print("\n  GOI Y CAT FILE:")
    if total_rows > 0:
        print(f"  --mode rows --size 5000    ->  ~{total_rows // 5000} files")
        print(f"  --mode rows --size 10000   ->  ~{total_rows // 10000} files")
        print(f"  --mode rows --size 50000   ->  ~{total_rows // 50000} files")
    if duration:
        print(f"  --mode time --size 60      ->  ~{int(duration // 60)} files  (1 min/file)")
        print(f"  --mode time --size 300     ->  ~{int(duration // 300)} files  (5 min/file)")
        print(f"  --mode time --size 3600    ->  ~{int(duration // 3600)} files  (1 hr/file)")
    print()


# ============================================================================
# SLICE BY ROWS
# ============================================================================

def slice_by_rows(input_file: str, output_dir: Path, prefix: str,
                  chunk_size: int) -> None:
    """Cắt theo số dòng — mỗi file có đúng chunk_size rows (file cuối có thể ít hơn)."""
    print(f"\n[Slice by rows] chunk={chunk_size:,} rows/file")
    output_dir.mkdir(parents=True, exist_ok=True)

    total_rows    = 0
    chunk_idx     = 1
    rows_in_chunk = 0
    files_created = []

    with open(input_file, encoding="utf-8", errors="ignore", newline="") as f:
        reader     = csv.DictReader(f)
        fieldnames = reader.fieldnames

        fh, writer, path = _open_chunk(output_dir, prefix, chunk_idx, fieldnames)

        for row in reader:
            writer.writerow(row)
            rows_in_chunk += 1
            total_rows    += 1

            if total_rows % 50_000 == 0:
                _progress(total_rows, chunk_idx)

            if rows_in_chunk >= chunk_size:
                fh.close()
                files_created.append(path.name)

                chunk_idx     += 1
                rows_in_chunk  = 0
                fh, writer, path = _open_chunk(output_dir, prefix, chunk_idx, fieldnames)

        # Đóng chunk cuối
        fh.close()
        if rows_in_chunk > 0:
            files_created.append(path.name)
        else:
            path.unlink(missing_ok=True)  # chunk rỗng

    print(f"\r  Done: {total_rows:,} rows -> {len(files_created)} files")
    print(f"  Output: {output_dir}")
    for name in files_created[:5]:
        print(f"    {name}")
    if len(files_created) > 5:
        print(f"    ... ({len(files_created) - 5} more files)")


# ============================================================================
# SLICE BY TIME
# ============================================================================

def slice_by_time(input_file: str, output_dir: Path, prefix: str,
                  chunk_seconds: float) -> None:
    """Cắt theo khoảng thời gian dựa trên timestamp."""
    print(f"\n[Slice by time] chunk={chunk_seconds}s/file")
    output_dir.mkdir(parents=True, exist_ok=True)

    total_rows     = 0
    chunk_idx      = 1
    chunk_start_ts = None
    files_created  = []
    rows_in_chunk  = 0

    with open(input_file, encoding="utf-8", errors="ignore", newline="") as f:
        reader     = csv.DictReader(f)
        fieldnames = reader.fieldnames

        fh, writer, path = _open_chunk(output_dir, prefix, chunk_idx, fieldnames)

        for row in reader:
            ts = _parse_timestamp(row)

            # Khởi tạo chunk_start khi gặp timestamp đầu tiên
            if ts is not None and chunk_start_ts is None:
                chunk_start_ts = ts

            # Sang chunk mới nếu vượt ngưỡng thời gian
            if ts is not None and chunk_start_ts is not None:
                if ts - chunk_start_ts >= chunk_seconds:
                    fh.close()
                    if rows_in_chunk > 0:
                        files_created.append(path.name)
                    else:
                        path.unlink(missing_ok=True)

                    chunk_idx      += 1
                    chunk_start_ts  = ts
                    rows_in_chunk   = 0
                    fh, writer, path = _open_chunk(output_dir, prefix, chunk_idx, fieldnames)

            writer.writerow(row)
            rows_in_chunk += 1
            total_rows    += 1

            if total_rows % 50_000 == 0:
                _progress(total_rows, chunk_idx)

        # Đóng chunk cuối
        fh.close()
        if rows_in_chunk > 0:
            files_created.append(path.name)
        else:
            path.unlink(missing_ok=True)

    print(f"\r  Done: {total_rows:,} rows -> {len(files_created)} files")
    print(f"  Output: {output_dir}")
    for name in files_created[:5]:
        print(f"    {name}")
    if len(files_created) > 5:
        print(f"    ... ({len(files_created) - 5} more files)")


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CSV Slicer — cat file CSV thanh cac chunk nho",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Xem thong ke truoc khi cat:
  python tools/csv_slicer.py -i normal_data.csv --dry-run

  # Cat 10,000 dong/file:
  python tools/csv_slicer.py -i normal_data.csv -o slices/ --mode rows --size 10000

  # Cat 60 giay/file:
  python tools/csv_slicer.py -i normal_data.csv -o slices/ --mode time --size 60
        """,
    )
    parser.add_argument("-i", "--input",  required=True,
                        help="Input CSV file")
    parser.add_argument("-o", "--output", default="slices/",
                        help="Output directory (default: slices/)")
    parser.add_argument("--mode", choices=["rows", "time"], default="rows",
                        help="Slice mode: 'rows' (so dong) or 'time' (giay). Default: rows")
    parser.add_argument("--size", type=float, default=10000,
                        help="Chunk size: rows (rows mode) or seconds (time mode). Default: 10000")
    parser.add_argument("--prefix", default=None,
                        help="Output filename prefix (default: input filename stem)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Chi in stats, khong ghi file")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    if args.dry_run:
        dry_run(args.input)
        return

    output_dir = Path(args.output)
    prefix     = args.prefix or Path(args.input).stem

    if args.mode == "rows":
        slice_by_rows(args.input, output_dir, prefix, int(args.size))
    else:
        slice_by_time(args.input, output_dir, prefix, float(args.size))


if __name__ == "__main__":
    main()
