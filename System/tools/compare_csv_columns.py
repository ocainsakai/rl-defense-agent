"""
So sánh các cột CSV giữa output của bạn và CICFlowMeter
"""

import os
import sys
import csv

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def compare_csv_columns(your_csv: str, cic_csv: str):
    """So sánh headers và một vài rows mẫu"""
    
    print("=" * 80)
    print("SO SÁNH CSV COLUMNS")
    print("=" * 80)
    
    # Read your CSV headers
    if os.path.exists(your_csv):
        with open(your_csv, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            your_headers = next(reader)
            your_sample_row = next(reader, None)
        print(f"✅ Your CSV: {your_csv}")
        print(f"   Columns: {len(your_headers)}")
    else:
        print(f"❌ Your CSV not found: {your_csv}")
        your_headers = []
        your_sample_row = None
    
    # Read CIC CSV headers
    if os.path.exists(cic_csv):
        with open(cic_csv, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            cic_headers = next(reader)
            cic_sample_row = next(reader, None)
        print(f"✅ CIC CSV: {cic_csv}")
        print(f"   Columns: {len(cic_headers)}")
    else:
        print(f"❌ CIC CSV not found: {cic_csv}")
        cic_headers = []
        cic_sample_row = None
    
    print("\n" + "=" * 80)
    print("YOUR CSV COLUMNS")
    print("=" * 80)
    for i, col in enumerate(your_headers, 1):
        print(f"{i:3d}. {col}")
    
    print("\n" + "=" * 80)
    print("CICFlowMeter CSV COLUMNS (first 30)")
    print("=" * 80)
    for i, col in enumerate(cic_headers[:30], 1):
        print(f"{i:3d}. {col}")
    
    if len(cic_headers) > 30:
        print(f"... và {len(cic_headers) - 30} cột nữa")
    
    # Mapping có thể so sánh
    print("\n" + "=" * 80)
    print("MAPPING CÓ THỂ SO SÁNH")
    print("=" * 80)
    
    mappings = [
        ("Src_IP", "Src IP"),
        ("Src_Port", "Src Port"),
        ("Dst_IP", "Dst IP"),
        ("Dst_Port", "Dst Port"),
        ("Protocol", "Protocol"),
        ("Fwd_Pkts", "TotLen Fwd Pkts" if "TotLen Fwd Pkts" in cic_headers else None),
        ("Bwd_Pkts", "TotLen Bwd Pkts" if "TotLen Bwd Pkts" in cic_headers else None),
        ("Fwd_Payload_Mean", "Fwd Pkt Len Mean"),
        ("Bwd_Payload_Mean", "Bwd Pkt Len Mean"),
        ("Total_SYN", "SYN Flag Cnt"),
        ("Total_RST", "RST Flag Cnt"),
        ("Total_ACK", "ACK Flag Cnt"),
    ]
    
    print(f"{'Your Column':<25} → {'CIC Column':<30} {'Match'}")
    print("-" * 80)
    for your_col, cic_col in mappings:
        if cic_col and cic_col in cic_headers:
            print(f"{your_col:<25} → {cic_col:<30} ✅")
        elif cic_col:
            print(f"{your_col:<25} → {cic_col:<30} ❌ (not found)")
        else:
            print(f"{your_col:<25} → {'(not applicable)':<30} ⚠️")
    
    # So sánh sample data nếu có
    if your_sample_row and cic_sample_row and your_headers and cic_headers:
        print("\n" + "=" * 80)
        print("SAMPLE DATA COMPARISON (Row 2)")
        print("=" * 80)
        
        # Find matching columns
        for your_col, cic_col in mappings[:8]:  # Chỉ show một vài cột
            if cic_col and cic_col in cic_headers:
                your_idx = your_headers.index(your_col) if your_col in your_headers else None
                cic_idx = cic_headers.index(cic_col)
                
                if your_idx is not None:
                    your_val = your_sample_row[your_idx] if your_idx < len(your_sample_row) else "N/A"
                    cic_val = cic_sample_row[cic_idx] if cic_idx < len(cic_sample_row) else "N/A"
                    
                    match = "✅" if your_val == cic_val else "⚠️"
                    print(f"{your_col:<20}: {your_val:<15} vs {cic_val:<15} {match}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-y", "--your-csv", required=True, help="Your CSV output")
    parser.add_argument("-c", "--cic-csv", required=True, help="CICFlowMeter CSV")
    args = parser.parse_args()
    
    compare_csv_columns(args.your_csv, args.cic_csv)
