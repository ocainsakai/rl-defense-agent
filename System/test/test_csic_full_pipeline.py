"""
Test CSIC Dataset qua FULL PIPELINE có sẵn.

Pipeline: PacketLayerExtractor → FlowManager → FlowState → Feature Calculators

Script này:
1. Load CSIC CSV
2. Tái tạo Scapy HTTP packets từ CSV data
3. Đưa qua full pipeline của hệ thống
4. Tính features sử dụng FlowFeatureCalculator

Chạy: python test/test_csic_full_pipeline.py
"""

import sys
import os
import csv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import TOÀN BỘ pipeline từ core/
from scapy.all import IP, TCP, Raw, Ether

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.flow_state import FlowState
from core.layer_info import LayerInfo

# Import Feature Calculators
from feature.feature_flow import (
    FlowFeatureCalculator,
    FlowFeature11_SqliKeyword,
    FlowFeature12_SqlSpecialChar,
    FlowFeature13_XssKeyword,
    FlowFeature14_XssSpecialChar,
)


def load_csic_sample(filepath: str, limit: int = 100):
    """
    Load một số records từ CSIC CSV.
    
    Returns:
        List of (label, method, url, content) tuples
    """
    records = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        headers = next(reader)
        
        method_idx = headers.index('Method') if 'Method' in headers else 1
        url_idx = headers.index('URL') if 'URL' in headers else -1
        content_idx = headers.index('content') if 'content' in headers else None
        
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            
            if len(row) < 2:
                continue
            
            label = row[0]
            method = row[method_idx] if method_idx < len(row) else 'GET'
            url = row[url_idx] if url_idx >= 0 and abs(url_idx) < len(row) else '/'
            content = row[content_idx] if content_idx and content_idx < len(row) else ''
            
            records.append((label, method, url, content))
    
    return records


def reconstruct_http_packet(method: str, url: str, content: str, seq_num: int):
    """
    Tái tạo Scapy HTTP packet từ CSV data.
    
    Args:
        method: GET hoặc POST
        url: URL path với query string
        content: POST body
        seq_num: Sequence number cho packet
    
    Returns:
        Scapy packet object
    """
    # Xây dựng HTTP request
    if method.upper() == 'POST':
        http_request = (
            f"POST {url} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(content)}\r\n"
            f"\r\n"
            f"{content}"
        ).encode('utf-8', errors='ignore')
    else:
        http_request = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode('utf-8', errors='ignore')
    
    # Tạo Scapy packet
    pkt = (
        Ether() / 
        IP(src="192.168.1.100", dst="10.0.0.1") / 
        TCP(sport=5000 + (seq_num % 1000), dport=80, flags="PA", seq=seq_num) / 
        Raw(load=http_request)
    )
    
    return pkt


def test_full_pipeline(records, verbose=False):
    """
    Test CSIC data qua FULL PIPELINE.
    
    Pipeline: PacketLayerExtractor → FlowManager → FlowState → Features
    """
    print("="*70)
    print("FULL PIPELINE TEST - CSIC DATASET")
    print("PacketLayerExtractor -> FlowManager -> FlowState -> Features")
    print("="*70)
    
    # 1. Khởi tạo Pipeline Components (DÙNG CODE CÓ SẴN)
    print("\n[1] KHOI TAO PIPELINE COMPONENTS...")
    parser = PacketLayerExtractor(use_packet_time=False, enable_http_parsing=True)
    fm = FlowManager(window_size=60.0, flow_timeout=120.0, cleanup_interval=10000)
    
    print(f"    - PacketLayerExtractor: enable_http_parsing=True")
    print(f"    - FlowManager: window_size=60s, flow_timeout=120s")
    
    # 2. Counters
    attack_detected = 0
    normal_detected = 0
    sqli_count = 0
    xss_count = 0
    
    # 3. Process từng record qua pipeline
    print(f"\n[2] PROCESSING {len(records)} RECORDS QUA PIPELINE...")
    
    for i, (label, method, url, content) in enumerate(records):
        # Tái tạo packet
        pkt = reconstruct_http_packet(method, url, content, seq_num=i)
        
        # Step 1: PacketLayerExtractor.extract()
        info = parser.extract(pkt, packet_number=i)
        
        # Step 2: FlowManager.process_packet()
        fm.process_packet(info)
        
        if verbose and i < 5:
            print(f"\n    Record {i+1}: {label}")
            print(f"      Method: {method}, URL: {url[:50]}...")
            print(f"      LayerInfo: has_tcp={info.has_tcp}, payload_len={info.payload_length}")
    
    # 4. Lấy tất cả flows
    print(f"\n[3] LAY FLOWS TU FLOW MANAGER...")
    all_flows = fm.get_all_flows()
    print(f"    - Total flows: {len(all_flows)}")
    
    # 5. Tính Features bằng FlowFeatureCalculator
    print(f"\n[4] TINH FEATURES BANG FLOWFEATURECALCULATOR...")
    
    calc = FlowFeatureCalculator()
    features = calc.calculate_all(all_flows)
    feature_names = calc.get_feature_names()
    
    print(f"\n    FEATURE VALUES (14 features):")
    print(f"    {'='*50}")
    for name, value in zip(feature_names, features):
        print(f"    {name:25s}: {value:.4f}")
    
    # 6. Chi tiết SQLi/XSS detection
    print(f"\n[5] CHI TIET SQLi/XSS DETECTION...")
    
    f11_calc = FlowFeature11_SqliKeyword()
    f12_calc = FlowFeature12_SqlSpecialChar()
    f13_calc = FlowFeature13_XssKeyword()
    f14_calc = FlowFeature14_XssSpecialChar()
    
    sqli_keyword_score = f11_calc.calculate(all_flows)
    sqli_char_score = f12_calc.calculate(all_flows)
    xss_keyword_score = f13_calc.calculate(all_flows)
    xss_char_score = f14_calc.calculate(all_flows)
    
    print(f"    F11 SQLi Keyword Score:  {sqli_keyword_score}")
    print(f"    F12 SQLi Special Char:   {sqli_char_score}")
    print(f"    F13 XSS Keyword Score:   {xss_keyword_score}")
    print(f"    F14 XSS Special Char:    {xss_char_score}")
    
    # 7. Count results
    print(f"\n[6] KET QUA TONG HOP...")
    
    attack_count = sum(1 for label, _, _, _ in records if label.lower() != 'normal')
    normal_count = len(records) - attack_count
    
    print(f"    - Total records processed: {len(records)}")
    print(f"    - Normal records: {normal_count}")
    print(f"    - Attack records: {attack_count}")
    print(f"    - Total flows created: {len(all_flows)}")
    
    if sqli_keyword_score > 0 or sqli_char_score > 0:
        print(f"\n    [!] SQLi INDICATORS DETECTED in payload!")
    if xss_keyword_score > 0 or xss_char_score > 0:
        print(f"    [!] XSS INDICATORS DETECTED in payload!")
    
    print("\n" + "="*70)
    print("PIPELINE TEST COMPLETE")
    print("="*70)
    
    return features


def main():
    # Đường dẫn CSIC dataset
    default_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'dataset', 'csic_database.csv'
    )
    
    csv_path = sys.argv[1] if len(sys.argv) > 1 else default_path
    
    if not os.path.exists(csv_path):
        print(f"[ERROR] File not found: {csv_path}")
        sys.exit(1)
    
    print(f"[LOAD] Loading CSIC dataset: {csv_path}")
    
    # Load sample (100 records để test nhanh)
    records = load_csic_sample(csv_path, limit=100)
    print(f"[OK] Loaded {len(records)} sample records")
    
    # Test full pipeline
    features = test_full_pipeline(records, verbose=True)


if __name__ == '__main__':
    main()
