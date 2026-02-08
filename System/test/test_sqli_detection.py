"""
Test SQLi Detection - LOG CHI TIET PATTERN MATCHING
Su dung truc tiep code he thong co san
"""

import sys
import os
import csv
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature.payload_context import PayloadContextScorer


# Copy patterns tu PayloadContextScorer de log chi tiet
SQL_PATTERNS = {
    "UNION-SELECT": r"\bunion\b[\s\S]{0,50}\bselect\b",
    "OR-TAUTOLOGY": r"\bor\b\s+\d+\s*=\s*\d+",
    "OR-TRUE": r"\bor\b\s+true\b",
    "DROP-TABLE": r"\bdrop\b\s{1,10}\b(?:table|database|index)\b",
    "DELETE-FROM": r"\bdelete\b\s+\bfrom\b",
    "INSERT-INTO": r"\binsert\b\s+\binto\b",
    "SQL-COMMENT--": r"--\s",
    "SQL-COMMENT#": r"#(?![0-9a-fA-F]{3,6}\b)",
    "INLINE-COMMENT": r"/\*[\s\S]*?\*/",
    "SLEEP-FUNC": r"\b(?:benchmark|sleep|pg_sleep)\s*\(",
    "WAITFOR": r"\bwaitfor\b\s+\b(?:delay|time)\b",
    "CHAR-FUNC": r"\b(?:ascii|ord|char)\s*\(",
    "SUBSTRING": r"\b(?:substring|mid|left|right)\s*\(",
    "LOAD-FILE": r"\bload_file\s*\(",
    "INFO-SCHEMA": r"\binformation_schema\b",
    "STACKED-QUERY": r";\s*(?:drop|delete|insert|update|truncate|alter)\b",
}

SQL_KEYWORDS = ['select', 'union', 'insert', 'update', 'delete', 'drop',
                'truncate', 'alter', 'create', 'information_schema', 
                'load_file', 'benchmark', 'sleep', 'waitfor']


def analyze_payload(payload: str):
    """Phan tich chi tiet payload."""
    result = {
        'keywords': [],
        'patterns': [],
    }
    
    payload_lower = payload.lower()
    
    # Tim keywords
    for kw in SQL_KEYWORDS:
        if kw in payload_lower:
            result['keywords'].append(kw)
    
    # Tim patterns
    for name, pattern in SQL_PATTERNS.items():
        if re.search(pattern, payload_lower, re.IGNORECASE):
            result['patterns'].append(name)
    
    return result


def main():
    csv_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'dataset', 'sqli.csv'
    )
    
    print(f"[LOAD] {csv_path}")
    
    records = []
    with open(csv_path, 'r', encoding='utf-16', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for i, row in enumerate(reader):
            if i >= 50:  # Test 50 records
                break
            if len(row) >= 2:
                try:
                    records.append((row[0], int(row[1])))
                except:
                    pass
    
    print(f"[OK] Loaded {len(records)} records\n")
    
    print("="*80)
    print("CHI TIET PATTERN MATCHING - SU DUNG CODE HE THONG CO SAN")
    print("="*80)
    
    detected = 0
    not_detected = 0
    
    for i, (payload, label) in enumerate(records):
        # Goi code he thong
        payload_bytes = payload.encode('utf-8', errors='ignore')
        sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
        
        # Phan tich chi tiet
        analysis = analyze_payload(payload)
        
        is_detected = sqli_score > 0
        if is_detected:
            detected += 1
        else:
            not_detected += 1
        
        # Chi in cac record thu vi
        if is_detected or (not is_detected and label == 1 and i < 30):
            status = "DETECTED" if is_detected else "MISSED"
            label_str = "ATTACK" if label == 1 else "NORMAL"
            
            print(f"\n[{i+1:02d}] [{status}] [{label_str}]")
            print(f"    Payload: {payload[:70]}")
            print(f"    Score: {sqli_score}")
            if analysis['keywords']:
                print(f"    Keywords: {', '.join(analysis['keywords'])}")
            if analysis['patterns']:
                print(f"    Patterns: {', '.join(analysis['patterns'])}")
    
    print("\n" + "="*80)
    print("TONG KET")
    print("="*80)
    print(f"  Detected: {detected}/{len(records)}")
    print(f"  Not detected: {not_detected}/{len(records)}")
    
    print("\n" + "="*80)
    print("PATTERNS HE THONG HO TRO:")
    print("="*80)
    for name in SQL_PATTERNS.keys():
        print(f"  - {name}")
    
    print("\nTEST COMPLETE")


if __name__ == '__main__':
    main()
