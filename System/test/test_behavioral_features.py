"""
Test Behavioral Features Extraction.
Output JSON cho PPO/RL.
"""

import json

import pytest

from feature.behavioral_features import BehavioralFeatureExtractor


@pytest.mark.unit
class TestBehavioralFeatures:
    """Test BehavioralFeatureExtractor."""

    @pytest.mark.parametrize("payload,desc,expect_sqli", [
        ("' or 1=1--", "SQLi Tautology", True),
        ("UNION SELECT * FROM users", "SQLi Union", True),
        ("<script>alert(1)</script>", "XSS Script", False),
        ("hello world", "Normal", False),
        ("admin@email.com", "Normal Email", False),
    ])
    def test_extract_features(self, payload, desc, expect_sqli):
        """Extract features from various payloads."""
        features = BehavioralFeatureExtractor.extract(payload)
        assert isinstance(features, dict)
        assert len(features) > 0
        if expect_sqli:
            assert features['sql_keyword_count'] > 0, f"{desc}: expected sql keywords"

    def test_feature_names(self):
        """get_feature_names() returns non-empty list."""
        names = BehavioralFeatureExtractor.get_feature_names()
        assert len(names) > 0

    def test_json_output(self):
        """extract_json() returns valid JSON."""
        json_output = BehavioralFeatureExtractor.extract_json("' or 1=1--")
        parsed = json.loads(json_output)
        assert isinstance(parsed, dict)
        assert 'sql_keyword_count' in parsed


@pytest.mark.dataset
@pytest.mark.unit
class TestBehavioralFeaturesDataset:
    """Test with sqli.csv dataset."""

    def test_with_sqli_csv(self, sqli_csv_path):
        """Extract features from first 10 sqli.csv records."""
        from helpers import load_sqli_csv
        records = load_sqli_csv(sqli_csv_path, limit=10, encoding='utf-16')

        assert len(records) > 0
        for payload, label in records:
            features = BehavioralFeatureExtractor.extract(payload)
            assert isinstance(features, dict)
            assert 'entropy' in features
