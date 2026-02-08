"""
Test PayloadContextScorer với CSIC HTTP Dataset.

Script này load dữ liệu CSIC (CSV format) và test khả năng
phát hiện SQLi/XSS của PayloadContextScorer.

Cách dùng:
    python test/test_csic_dataset.py

Output:
    - Detection metrics (Accuracy, Precision, Recall, F1)
    - Confusion matrix
    - False Positives/Negatives samples
"""

import sys
import os

# Thêm root directory vào path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
from urllib.parse import urlparse, parse_qs, unquote_plus
from typing import List, Tuple, Dict
from dataclasses import dataclass
from collections import Counter

from feature.payload_context import PayloadContextScorer, CONTEXT_MALICIOUS


@dataclass
class CSICRecord:
    """Một record từ CSIC dataset."""
    label: str              # "Normal" hoặc "Anomaly" (tên cột đầu tiên)
    method: str             # GET hoặc POST
    url: str                # Full URL với query string
    content: str            # POST body (nếu có)
    
    @property
    def is_attack(self) -> bool:
        """Trả về True nếu là attack (Anomaly)."""
        return self.label.lower().strip() != "normal"
    
    def get_payload(self) -> str:
        """
        Lấy payload để test từ URL query string và POST body.
        
        Returns:
            str: Combined payload từ URL params và body
        """
        payloads = []
        
        # 1. Trích xuất từ URL query string  
        if '?' in self.url:
            try:
                # Lấy phần query string
                query_part = self.url.split('?', 1)[1].split(' ')[0]  # Bỏ phần "HTTP/1.1"
                params = parse_qs(query_part, keep_blank_values=True)
                for key, values in params.items():
                    payloads.append(unquote_plus(key))
                    for v in values:
                        payloads.append(unquote_plus(v))
            except Exception:
                pass
        
        # 2. Trích xuất từ POST body
        if self.content:
            try:
                # POST body thường dạng: key1=value1&key2=value2
                pairs = self.content.split('&')
                for pair in pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        payloads.append(unquote_plus(key))
                        payloads.append(unquote_plus(value))
                    else:
                        payloads.append(unquote_plus(pair))
            except Exception:
                pass
        
        return ' '.join(payloads)


def load_csic_csv(filepath: str, limit: int = None) -> List[CSICRecord]:
    """
    Load CSIC dataset từ CSV file.
    
    Args:
        filepath: Đường dẫn tới file CSV
        limit: Số records tối đa cần load (None = tất cả)
    
    Returns:
        List[CSICRecord]: Danh sách các records
    """
    records = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        headers = next(reader)  # Skip header row
        
        # Tìm index của các cột cần thiết
        # Cột đầu tiên không có tên (chứa label)
        method_idx = headers.index('Method') if 'Method' in headers else 1
        url_idx = headers.index('URL') if 'URL' in headers else -1
        content_idx = headers.index('content') if 'content' in headers else None
        
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            
            if len(row) < 2:
                continue
            
            try:
                record = CSICRecord(
                    label=row[0],  # Cột đầu tiên là label
                    method=row[method_idx] if method_idx < len(row) else 'GET',
                    url=row[url_idx] if url_idx >= 0 and abs(url_idx) < len(row) else '',
                    content=row[content_idx] if content_idx and content_idx < len(row) else ''
                )
                records.append(record)
            except Exception as e:
                continue
    
    return records


def test_detection(records: List[CSICRecord]) -> Dict:
    """
    Test PayloadContextScorer trên CSIC dataset.
    
    Returns:
        Dict chứa metrics và samples
    """
    # Counters
    true_positives = 0   # Attack đúng phát hiện
    true_negatives = 0   # Normal đúng không báo
    false_positives = 0  # Normal bị báo là attack
    false_negatives = 0  # Attack không phát hiện
    
    # Sample storage
    fp_samples = []  # False positive samples
    fn_samples = []  # False negative samples
    
    # Attack type counters (based on detected indicators)
    sqli_detected = 0
    xss_detected = 0
    
    for record in records:
        payload = record.get_payload()
        
        if not payload.strip():
            # Không có payload -> coi như normal
            if record.is_attack:
                false_negatives += 1
                fn_samples.append((record.label, record.url[:100], "Empty payload"))
            else:
                true_negatives += 1
            continue
        
        # Convert to bytes và score
        payload_bytes = payload.encode('utf-8', errors='ignore')
        score = PayloadContextScorer.score_payload(payload_bytes)
        
        # Count indicators
        sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
        xss_score = PayloadContextScorer.count_xss_indicators(payload_bytes)
        
        is_detected = (score == CONTEXT_MALICIOUS)
        
        if sqli_score > 0:
            sqli_detected += 1
        if xss_score > 0:
            xss_detected += 1
        
        # Classification
        if record.is_attack:
            if is_detected:
                true_positives += 1
            else:
                false_negatives += 1
                if len(fn_samples) < 20:
                    fn_samples.append((record.label, record.url[:100], payload[:200]))
        else:
            if is_detected:
                false_positives += 1
                if len(fp_samples) < 20:
                    fp_samples.append((record.label, record.url[:100], payload[:200]))
            else:
                true_negatives += 1
    
    # Calculate metrics
    total = true_positives + true_negatives + false_positives + false_negatives
    accuracy = (true_positives + true_negatives) / total if total > 0 else 0
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'total_records': total,
        'true_positives': true_positives,
        'true_negatives': true_negatives,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'sqli_detected': sqli_detected,
        'xss_detected': xss_detected,
        'fp_samples': fp_samples,
        'fn_samples': fn_samples,
    }


def print_results(results: Dict):
    """In kết quả test."""
    print("\n" + "="*60)
    print("CSIC DATASET - SQLi/XSS DETECTION TEST RESULTS")
    print("="*60)
    
    print(f"\n[STATS] Dataset Statistics:")
    print(f"   Total records tested: {results['total_records']:,}")
    
    print(f"\n[METRICS] Detection Metrics:")
    print(f"   Accuracy:  {results['accuracy']:.2%}")
    print(f"   Precision: {results['precision']:.2%}")
    print(f"   Recall:    {results['recall']:.2%}")
    print(f"   F1-Score:  {results['f1_score']:.2%}")
    
    print(f"\n[MATRIX] Confusion Matrix:")
    print(f"   ┌─────────────┬──────────────┬──────────────┐")
    print(f"   │             │ Predicted    │ Predicted    │")
    print(f"   │             │ Attack       │ Normal       │")
    print(f"   ├─────────────┼──────────────┼──────────────┤")
    print(f"   │ Actual      │              │              │")
    print(f"   │ Attack      │ TP: {results['true_positives']:>6,}   │ FN: {results['false_negatives']:>6,}   │")
    print(f"   ├─────────────┼──────────────┼──────────────┤")
    print(f"   │ Actual      │              │              │")
    print(f"   │ Normal      │ FP: {results['false_positives']:>6,}   │ TN: {results['true_negatives']:>6,}   │")
    print(f"   └─────────────┴──────────────┴──────────────┘")
    
    print(f"\n[TYPES] Attack Type Detection:")
    print(f"   SQLi indicators detected: {results['sqli_detected']:,} records")
    print(f"   XSS indicators detected:  {results['xss_detected']:,} records")
    
    if results['fp_samples']:
        print(f"\n[FP] False Positive Samples (Normal misclassified as Attack):")
        for i, (label, url, payload) in enumerate(results['fp_samples'][:5]):
            print(f"   [{i+1}] URL: {url}")
            print(f"       Payload: {payload[:100]}...")
    
    if results['fn_samples']:
        print(f"\n[FN] False Negative Samples (Attack not detected):")
        for i, (label, url, payload) in enumerate(results['fn_samples'][:5]):
            print(f"   [{i+1}] Label: {label}")
            print(f"       URL: {url}")
            print(f"       Payload: {payload[:100]}...")
    
    print("\n" + "="*60)


def main():
    """Main entry point."""
    # Đường dẫn mặc định tới CSIC dataset
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'dataset', 'csic_database.csv'
    )
    
    csv_path = sys.argv[1] if len(sys.argv) > 1 else default_path
    
    if not os.path.exists(csv_path):
        print(f"[ERROR] File not found: {csv_path}")
        sys.exit(1)
    
    print(f"[LOAD] Loading CSIC dataset: {csv_path}")
    
    # Load records (limit để test nhanh, bỏ limit để test full)
    records = load_csic_csv(csv_path, limit=None)
    
    print(f"[OK] Loaded {len(records):,} records")
    
    # Count labels
    label_counts = Counter(r.label for r in records)
    print(f"   - Normal: {label_counts.get('Normal', 0):,}")
    print(f"   - Anomaly/Attack: {sum(v for k,v in label_counts.items() if k != 'Normal'):,}")
    
    print(f"\n[TEST] Running detection test...")
    results = test_detection(records)
    
    print_results(results)


if __name__ == '__main__':
    main()
