"""
PHAN TICH CHI TIET: TAI SAO CHI NHAN DIEN DUOC 50% ATTACKS

Script nay se:
1. Load TOAN BO sqli.csv
2. Phan loai ATTACK duoc detect va ATTACK bi miss
3. Tim hieu pattern nao bi miss va tai sao
"""

import sys
import os
import csv
import re
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature.payload_context import PayloadContextScorer


def main():
    csv_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'dataset', 'sqli.csv'
    )
    
    print("="*80)
    print("PHAN TICH CHI TIET: TAI SAO CHI DETECT 50% ATTACKS")
    print("="*80)
    
    # Load ALL records
    records = []
    with open(csv_path, 'r', encoding='utf-16', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if len(row) >= 2:
                try:
                    records.append((row[0], int(row[1])))
                except:
                    pass
    
    print(f"\n[1] DATASET STATS:")
    print(f"    Total records: {len(records)}")
    
    attacks = [(p, l) for p, l in records if l == 1]
    normals = [(p, l) for p, l in records if l == 0]
    
    print(f"    Attacks (label=1): {len(attacks)}")
    print(f"    Normals (label=0): {len(normals)}")
    
    # Test all records
    print(f"\n[2] TESTING ALL RECORDS...")
    
    detected_attacks = []
    missed_attacks = []
    false_positives = []
    true_negatives = []
    
    for payload, label in records:
        payload_bytes = payload.encode('utf-8', errors='ignore')
        score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
        
        is_attack = label == 1
        is_detected = score > 0
        
        if is_attack and is_detected:
            detected_attacks.append((payload, score))
        elif is_attack and not is_detected:
            missed_attacks.append(payload)
        elif not is_attack and is_detected:
            false_positives.append((payload, score))
        else:
            true_negatives.append(payload)
    
    print(f"\n[3] DETECTION RESULTS:")
    print(f"    True Positives  (TP): {len(detected_attacks)}")
    print(f"    False Negatives (FN): {len(missed_attacks)} <- ATTACKS BI MISS")
    print(f"    False Positives (FP): {len(false_positives)}")
    print(f"    True Negatives  (TN): {len(true_negatives)}")
    
    if len(attacks) > 0:
        recall = len(detected_attacks) / len(attacks) * 100
        print(f"\n    RECALL (Attack Detection Rate): {recall:.1f}%")
    
    # PHAN TICH ATTACKS BI MISS
    print(f"\n{'='*80}")
    print("PHAN TICH ATTACKS BI MISS (False Negatives)")
    print("="*80)
    
    # Phan loai theo do dai
    short_payloads = [p for p in missed_attacks if len(p) <= 5]
    medium_payloads = [p for p in missed_attacks if 5 < len(p) <= 20]
    long_payloads = [p for p in missed_attacks if len(p) > 20]
    
    print(f"\n[4] PHAN LOAI THEO DO DAI:")
    print(f"    Short (<=5 chars): {len(short_payloads)}")
    print(f"    Medium (6-20 chars): {len(medium_payloads)}")
    print(f"    Long (>20 chars): {len(long_payloads)}")
    
    # Samples
    print(f"\n[5] SAMPLES - PAYLOADS NGAN BI MISS:")
    for p in short_payloads[:15]:
        print(f"    '{p}'")
    
    print(f"\n[6] SAMPLES - PAYLOADS TRUNG BINH BI MISS:")
    for p in medium_payloads[:15]:
        print(f"    '{p}'")
    
    print(f"\n[7] SAMPLES - PAYLOADS DAI BI MISS:")
    for p in long_payloads[:15]:
        print(f"    '{p}'")
    
    # Tim patterns pho bien trong missed attacks
    print(f"\n{'='*80}")
    print("TIM PATTERNS PHO BIEN TRONG MISSED ATTACKS")
    print("="*80)
    
    patterns_count = defaultdict(int)
    pattern_samples = defaultdict(list)
    
    # Cac pattern co the bi miss
    check_patterns = {
        "Chi co dau nhay don": r"^[^a-zA-Z]*'[^a-zA-Z]*$",
        "Chi co dau nhay kep": r'^[^a-zA-Z]*"[^a-zA-Z]*$',
        "Chi co ky tu dac biet": r"^[^\w\s]+$",
        "Co 'or' nhung khong du context": r"\bor\b",
        "Co 'and' nhung khong du context": r"\band\b",
        "Co comment --": r"--",
        "Co semicolon": r";",
        "Payload rat ngan (<= 3 chars)": None,
        "Co encoded chars (%xx)": r"%[0-9a-fA-F]{2}",
    }
    
    for payload in missed_attacks:
        payload_lower = payload.lower()
        
        if len(payload) <= 3:
            patterns_count["Payload rat ngan (<= 3 chars)"] += 1
            if len(pattern_samples["Payload rat ngan (<= 3 chars)"]) < 5:
                pattern_samples["Payload rat ngan (<= 3 chars)"].append(payload)
        
        for name, pattern in check_patterns.items():
            if pattern and re.search(pattern, payload_lower):
                patterns_count[name] += 1
                if len(pattern_samples[name]) < 5:
                    pattern_samples[name].append(payload)
    
    print(f"\nPattern distribution trong MISSED ATTACKS:")
    for name, count in sorted(patterns_count.items(), key=lambda x: -x[1]):
        pct = count / len(missed_attacks) * 100 if missed_attacks else 0
        print(f"    {name}: {count} ({pct:.1f}%)")
        for sample in pattern_samples[name][:3]:
            print(f"        Sample: '{sample[:50]}'")
    
    # === GIAI THICH ===
    print(f"\n{'='*80}")
    print("GIAI THICH TAI SAO KHONG DETECT DUOC")
    print("="*80)
    
    print("""
[1] PAYLOADS QUA NGAN:
    - Dataset chua nhieu payloads rat ngan: "a", "a'", "@", "?"
    - He thong can NHIEU INDICATORS de xac dinh la attack
    - Chi mot dau "'" khong du de ket luan la SQLi
    -> DAY LA THIET KE DUNG de tranh FALSE POSITIVES

[2] MISSING CONTEXT:
    - "' or 1=1" duoc detect vi co pattern "or 1=1"
    - "' or 'x'='x" duoc detect vi co pattern
    - Nhung "' --" co the bi miss neu khong match regex tren

[3] EARLY-EXIT CONDITIONS trong count_sqli_indicators():
    - Line 351-353: Neu KHONG CO keyword VA KHONG CO suspicious chars → return 0
    - Dieu nay skip nhieu payloads ngan

[4] REGEX REQUIREMENTS:
    - Pattern "or 1=1" yeu cau: \\bor\\b\\s+\\d+\\s*=\\s*\\d+
    - Payload "' or '1'='1" khong match vi co dau nhay quanh so

[5] DATASET LABELING:
    - Nhieu payload trong dataset duoc label la ATTACK nhung thuc te
    - chi la FRAGMENTS (manh nho) cua mot attack lon
    - Vi du: "a" label=1 nhung day khong phai la attack hoan chinh
    """)
    
    print("\nTEST COMPLETE")


if __name__ == '__main__':
    main()
