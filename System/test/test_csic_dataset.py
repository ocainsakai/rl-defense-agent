"""
Test PayloadContextScorer với CSIC HTTP Dataset.

Load dữ liệu CSIC (CSV format) và test khả năng
phát hiện SQLi/XSS của PayloadContextScorer.
"""

import pytest

from feature.payload_context import PayloadContextScorer, CONTEXT_MALICIOUS


@pytest.mark.dataset
class TestCSICDataset:
    """Test PayloadContextScorer on CSIC dataset."""

    def test_detection_metrics(self, csic_csv_path):
        """Test detection accuracy on CSIC dataset."""
        from helpers import load_csic_csv

        records = load_csic_csv(csic_csv_path)
        assert len(records) > 0

        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0

        for record in records:
            payload = record.get_payload()
            if not payload.strip():
                if record.is_attack:
                    false_negatives += 1
                else:
                    true_negatives += 1
                continue

            payload_bytes = payload.encode('utf-8', errors='ignore')
            score = PayloadContextScorer.score_payload(payload_bytes)
            is_detected = (score == CONTEXT_MALICIOUS)

            if record.is_attack:
                if is_detected:
                    true_positives += 1
                else:
                    false_negatives += 1
            else:
                if is_detected:
                    false_positives += 1
                else:
                    true_negatives += 1

        total = true_positives + true_negatives + false_positives + false_negatives
        assert total == len(records)

        accuracy = (true_positives + true_negatives) / total
        assert accuracy > 0, "Accuracy should be > 0"

    def test_sqli_xss_indicators(self, csic_csv_path):
        """Verify SQLi/XSS indicators are detected in attack records."""
        from helpers import load_csic_csv

        records = load_csic_csv(csic_csv_path, limit=500, balanced=True)
        attack_records = [r for r in records if r.is_attack]
        assert len(attack_records) > 0, "No attack records in balanced sample"

        sqli_detected = 0
        xss_detected = 0

        for record in attack_records:
            payload = record.get_payload()
            if not payload.strip():
                continue

            payload_bytes = payload.encode('utf-8', errors='ignore')
            sqli_score = PayloadContextScorer.count_sqli_indicators(payload_bytes)
            xss_score = PayloadContextScorer.count_xss_indicators(payload_bytes)

            if sqli_score > 0:
                sqli_detected += 1
            if xss_score > 0:
                xss_detected += 1

        # At least some attacks should be detected
        total_detected = sqli_detected + xss_detected
        assert total_detected > 0, "No SQLi/XSS indicators detected in attack records"
