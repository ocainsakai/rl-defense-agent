"""
Test Behavioral Features Extraction.
Output JSON cho PPO/RL.
"""

import sys
import os
import csv
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature.behavioral_features import BehavioralFeatureExtractor


def main():
    print("="*70)
    print("TEST BEHAVIORAL FEATURES EXTRACTION")
    print("="*70)
    
    # Test payloads
    test_payloads = [
        ("' or 1=1--", "SQLi Tautology"),
        ("UNION SELECT * FROM users", "SQLi Union"),
        ("<script>alert(1)</script>", "XSS Script"),
        ("hello world", "Normal"),
        ("admin@email.com", "Normal Email"),
    ]
    
    print(f"\nFeature count: {len(BehavioralFeatureExtractor.get_feature_names())}\n")
    
    for payload, desc in test_payloads:
        print(f"\n{'='*50}")
        print(f"Payload: {payload}")
        print(f"Type: {desc}")
        print("-"*50)
        
        features = BehavioralFeatureExtractor.extract(payload)
        
        # Chi in features khac 0
        non_zero = {k: v for k, v in features.items() if v != 0}
        print("Non-zero features:")
        for k, v in non_zero.items():
            print(f"  {k}: {v}")
    
    # Test JSON output
    print(f"\n{'='*70}")
    print("JSON OUTPUT EXAMPLE:")
    print("="*70)
    
    json_output = BehavioralFeatureExtractor.extract_json("' or 1=1--")
    print(json.dumps(json.loads(json_output), indent=2))
    
    # Test voi sqli.csv
    print(f"\n{'='*70}")
    print("TEST VOI SQLI.CSV (10 mau):")
    print("="*70)
    
    csv_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'dataset', 'sqli.csv'
    )
    
    with open(csv_path, 'r', encoding='utf-16', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader)
        
        for i, row in enumerate(reader):
            if i >= 10:
                break
            if len(row) >= 2:
                payload = row[0]
                label = row[1]
                
                features = BehavioralFeatureExtractor.extract(payload)
                
                # Summary
                print(f"\n[{i+1}] Label={label} | SQL_kw={features['sql_keyword_count']} | "
                      f"Quotes={features['single_quote_count']} | "
                      f"Comment={features['has_comment']} | "
                      f"Entropy={features['entropy']:.2f}")
                print(f"    Payload: {payload[:50]}...")
    
    print("\nTEST COMPLETE")


if __name__ == '__main__':
    main()
