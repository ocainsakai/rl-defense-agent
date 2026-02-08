"""
Test SQLi Detection - Pattern Matching chi tiet
Su dung truc tiep code he thong co san
"""

import re

import pytest

from feature.payload_context import PayloadContextScorer


SQL_PATTERNS = {
    "UNION-SELECT": r"\bunion\b[\s\S]{0,50}\bselect\b",
    "OR-TAUTOLOGY": r"\bor\b\s+\d+\s*=\s*\d+",
    "DROP-TABLE": r"\bdrop\b\s{1,10}\b(?:table|database|index)\b",
    "STACKED-QUERY": r";\s*(?:drop|delete|insert|update|truncate|alter)\b",
}


@pytest.mark.sqli
@pytest.mark.dataset
class TestSqliDetection:
    """Test SQLi detection with sqli.csv dataset."""

    def test_detection_rate(self, sqli_csv_path):
        """Test detection rate on first 50 records."""
        from helpers import load_sqli_csv
        records = load_sqli_csv(sqli_csv_path, limit=50)

        assert len(records) > 0

        detected = 0
        total = len(records)

        for payload, label in records:
            payload_bytes = payload.encode('utf-8', errors='ignore')
            sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
            if sqli_score > 0:
                detected += 1

        # Should detect at least some payloads
        assert detected > 0, "No payloads detected at all"

    def test_pattern_matching(self):
        """Verify known patterns are matched."""
        test_cases = [
            ("1 UNION SELECT * FROM users", "UNION-SELECT"),
            ("' or 1 = 1", "OR-TAUTOLOGY"),
            ("; DROP TABLE users", "DROP-TABLE"),
            ("; drop table admin", "STACKED-QUERY"),
        ]

        for payload, expected_pattern in test_cases:
            pattern = SQL_PATTERNS[expected_pattern]
            assert re.search(pattern, payload.lower(), re.IGNORECASE), \
                f"Pattern {expected_pattern} should match: {payload}"
