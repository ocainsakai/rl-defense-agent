"""
Test SQLi Dataset qua FULL PIPELINE.

Pipeline: PacketLayerExtractor -> FlowManager -> FlowState -> Feature Calculators

Dataset: sqli.csv (Sentence, Label)
- Sentence: payload text
- Label: 1 = SQLi attack, 0 = normal

Chay: python test/test_sqli_full_pipeline.py
"""

import sys
import os
import csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo

from feature.feature_flow import (
    FlowFeatureCalculator,
    FlowFeature11_SqliKeyword,
    FlowFeature12_SqlSpecialChar,
    FlowFeature13_XssKeyword,
    FlowFeature14_XssSpecialChar,
)


def load_sqli_csv(filepath: str, limit: int = None):
    """
    Load SQLi CSV dataset.
    
    Format: Sentence,Label
    - Sentence: payload text 
    - Label: 1 = attack, 0 = normal
    
    Returns:
        List of (sentence, label) tuples
    """
    records = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        headers = next(reader)  # Skip header
        
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            
            if len(row) < 2:
                continue
            
            sentence = row[0]
            try:
                label = int(row[1])
            except ValueError:
                continue
                
            records.append((sentence, label))
    
    return records


def create_http_packet_from_payload(payload: str, seq_num: int):
    """
    Tao HTTP packet tu payload text.
    
    Payload duoc nhung vao HTTP GET request.
    """
    # Encode payload vao URL query string
    http_request = (
        f"GET /page?q={payload} HTTP/1.1\r\n"
        f"Host: target.com\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    ).encode('utf-8', errors='ignore')
    
    pkt = (
        Ether() / 
        IP(src="192.168.1.100", dst="10.0.0.1") / 
        TCP(sport=5000 + (seq_num % 1000), dport=80, flags="PA", seq=seq_num) / 
        Raw(load=http_request)
    )
    
    return pkt


def test_full_pipeline(records, verbose=False):
    """
    Test SQLi data qua FULL PIPELINE.
    
    Returns:
        Dict chua metrics
    """
    print("="*70)
    print("FULL PIPELINE TEST - SQLi DATASET")
    print("PacketLayerExtractor -> FlowManager -> FlowState -> Features")
    print("="*70)
    
    # 1. Khoi tao Pipeline
    print("\n[1] KHOI TAO PIPELINE COMPONENTS...")
    parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
    
    # 2. Counters
    true_positives = 0
    true_negatives = 0
    false_positives = 0
    false_negatives = 0
    
    sample_fp = []
    sample_fn = []
    
    attack_records = sum(1 for _, label in records if label == 1)
    normal_records = len(records) - attack_records
    
    print(f"    - Total records: {len(records)}")
    print(f"    - Attack (label=1): {attack_records}")
    print(f"    - Normal (label=0): {normal_records}")
    
    # 3. Process tung record
    print(f"\n[2] PROCESSING RECORDS...")
    
    f11_calc = FlowFeature11_SqliKeyword()
    
    for i, (sentence, label) in enumerate(records):
        # Tao FlowManager moi cho moi record (de tinh feature rieng)
        fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
        
        # Tao packet
        pkt = create_http_packet_from_payload(sentence, seq_num=i)
        
        # Extract va process
        info = parser.extract(pkt, packet_number=i)
        fm.process_packet(info)
        
        # Lay flows va tinh feature
        flows = fm.get_all_flows()
        sqli_score = f11_calc.calculate(flows)
        
        # Prediction: score > 0 = attack
        predicted_attack = sqli_score > 0
        actual_attack = label == 1
        
        # Count metrics
        if actual_attack and predicted_attack:
            true_positives += 1
        elif not actual_attack and not predicted_attack:
            true_negatives += 1
        elif not actual_attack and predicted_attack:
            false_positives += 1
            if len(sample_fp) < 5:
                sample_fp.append((sentence[:60], sqli_score))
        else:  # actual_attack and not predicted_attack
            false_negatives += 1
            if len(sample_fn) < 5:
                sample_fn.append((sentence[:60], sqli_score))
        
        # Progress
        if (i + 1) % 500 == 0:
            print(f"    Processed {i+1}/{len(records)} records...")
    
    # 4. Calculate metrics
    print(f"\n[3] TINH METRICS...")
    
    total = true_positives + true_negatives + false_positives + false_negatives
    accuracy = (true_positives + true_negatives) / total if total > 0 else 0
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n    CONFUSION MATRIX:")
    print(f"    {'='*40}")
    print(f"    True Positives  (TP): {true_positives}")
    print(f"    True Negatives  (TN): {true_negatives}")
    print(f"    False Positives (FP): {false_positives}")
    print(f"    False Negatives (FN): {false_negatives}")
    
    print(f"\n    METRICS:")
    print(f"    {'='*40}")
    print(f"    Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"    Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"    Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"    F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    
    if sample_fp:
        print(f"\n    SAMPLE FALSE POSITIVES (Normal -> Predicted Attack):")
        for payload, score in sample_fp:
            print(f"      Score={score:.1f}: {payload}...")
    
    if sample_fn:
        print(f"\n    SAMPLE FALSE NEGATIVES (Attack -> Predicted Normal):")
        for payload, score in sample_fn:
            print(f"      Score={score:.1f}: {payload}...")
    
    print("\n" + "="*70)
    print("PIPELINE TEST COMPLETE")
    print("="*70)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'tp': true_positives,
        'tn': true_negatives,
        'fp': false_positives,
        'fn': false_negatives,
    }


def main():
    # Default path
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'dataset', 'sqli.csv'
    )
    
    csv_path = sys.argv[1] if len(sys.argv) > 1 else default_path
    
    if not os.path.exists(csv_path):
        print(f"[ERROR] File not found: {csv_path}")
        sys.exit(1)
    
    print(f"[LOAD] Loading SQLi dataset: {csv_path}")
    
    # Load all records (or limit)
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
    records = load_sqli_csv(csv_path, limit=limit)
    print(f"[OK] Loaded {len(records)} records")
    
    # Test full pipeline
    metrics = test_full_pipeline(records, verbose=True)


if __name__ == '__main__':
    main()
