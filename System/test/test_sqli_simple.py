"""
Test SQLi Detection - CODE HE THONG CO SAN
Test truc tiep voi payload cu the
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature.payload_context import PayloadContextScorer


# PAYLOADS TEST TU FILE sqli.csv
TEST_PAYLOADS = [
    # SQLi attacks (label=1)
    ("a' or 1 = 1; --", 1),
    ("' and 1 = 0 )  union all", 1),
    ("x' and userid is NULL; --", 1),
    ("' or '1' = '1", 1),
    ("1 UNION SELECT username,password FROM users--", 1),
    ("admin' OR '1'='1'--", 1),
    ("'; DROP TABLE users;--", 1),
    ("1; SELECT * FROM passwords", 1),
    ("' OR 1=1#", 1),
    ("UNION SELECT NULL,version()--", 1),
    
    # Normal payloads (label=0)
    ("hello world", 0),
    ("user@email.com", 0),
    ("This is normal text", 0),
    ("Product name 123", 0),
    ("Search query here", 0),
]


def main():
    print("="*70)
    print("SQLi DETECTION TEST - CODE HE THONG CO SAN")
    print("Module: feature.payload_context.PayloadContextScorer")
    print("="*70)
    
    print("\nTesting PayloadContextScorer.count_sqli_indicators():")
    print("-"*70)
    
    for payload, expected_label in TEST_PAYLOADS:
        # Convert to bytes (nhu code he thong yeu cau)
        payload_bytes = payload.encode('utf-8')
        
        # Goi TRUC TIEP code he thong
        sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
        context_score = PayloadContextScorer.score_payload(payload_bytes)
        
        detected = "DETECTED" if sqli_score > 0 else "NOT DETECTED"
        label_str = "ATTACK" if expected_label == 1 else "NORMAL"
        
        print(f"\n[{label_str}] {payload}")
        print(f"  -> SQLi Score: {sqli_score}, Context: {context_score}")
        print(f"  -> Result: {detected}")
    
    print("\n" + "="*70)
    print("TEST COMPLETE")
    print("="*70)


if __name__ == '__main__':
    main()
