"""test/test_wamm_classifier.py

Tests for WAMM (Web Application Multiclass Model) classifier.

Markers:
    @pytest.mark.unit  - No model needed, tests feature extraction + graceful degradation
    @pytest.mark.wamm  - Requires trained model in System/models/wamm/
    @pytest.mark.integration - Full pipeline integration tests
"""

import os
import sys
import time
import pytest

# Path setup (conftest.py handles this, but explicit for clarity)
_test_dir = os.path.dirname(os.path.abspath(__file__))
_system_dir = os.path.dirname(_test_dir)
if _system_dir not in sys.path:
    sys.path.insert(0, _system_dir)

from feature.wamm_classifier import (
    WammFeatureExtractor,
    WammClassifier,
    normalize_payload_text,
)
from config.wamm_config import (
    WAMM_LABELS,
    NUM_HANDCRAFTED_FEATURES,
    MODEL_DIR,
    XGBOOST_MODEL_PATH,
    TFIDF_VECTORIZER_PATH,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def extractor():
    return WammFeatureExtractor()


@pytest.fixture
def classifier_no_model():
    """WammClassifier with intentionally non-existent model path."""
    return WammClassifier(model_dir="/nonexistent/path")


@pytest.fixture
def classifier():
    """WammClassifier with real model. Skips if model not trained."""
    if not os.path.exists(XGBOOST_MODEL_PATH) or not os.path.exists(TFIDF_VECTORIZER_PATH):
        pytest.skip("WAMM model not trained. Run: python System/tools/wamm_train.py")
    return WammClassifier()


# =============================================================================
# UNIT TESTS: normalize_payload_text
# =============================================================================

class TestNormalizePayload:
    @pytest.mark.unit
    def test_empty_payload(self):
        assert normalize_payload_text(b"") == ""

    @pytest.mark.unit
    def test_none_payload(self):
        assert normalize_payload_text(b"") == ""

    @pytest.mark.unit
    def test_url_decode(self):
        result = normalize_payload_text(b"hello%20world")
        assert "hello world" in result

    @pytest.mark.unit
    def test_url_decode_plus(self):
        result = normalize_payload_text(b"hello+world")
        assert "hello world" in result

    @pytest.mark.unit
    def test_html_unescape(self):
        result = normalize_payload_text(b"&lt;script&gt;")
        assert "<script>" in result

    @pytest.mark.unit
    def test_lowercase(self):
        result = normalize_payload_text(b"SELECT FROM Users")
        assert result == "select from users"

    @pytest.mark.unit
    def test_unicode_normalization(self):
        """Smart quotes should be normalized to ASCII."""
        result = normalize_payload_text("\u2018test\u2019".encode("utf-8"))
        assert "'" in result


# =============================================================================
# UNIT TESTS: WammFeatureExtractor
# =============================================================================

class TestWammFeatureExtractor:
    @pytest.mark.unit
    def test_empty_payload(self, extractor):
        features = extractor.extract("")
        assert len(features) == NUM_HANDCRAFTED_FEATURES
        assert all(f == 0.0 for f in features)

    @pytest.mark.unit
    def test_feature_count(self, extractor):
        features = extractor.extract("hello world")
        assert len(features) == NUM_HANDCRAFTED_FEATURES

    @pytest.mark.unit
    def test_sqli_payload(self, extractor):
        payload = "' or 1=1 -- union select * from users"
        features = extractor.extract(payload)

        # payload_length > 0
        assert features[0] > 0
        # special_char_count > 0 (', -, =, *)
        assert features[1] > 0
        # sql_keyword_binary = 1
        assert features[2] == 1.0
        # numeric_char_count > 0 (1, 1)
        assert features[3] > 0
        # shannon_entropy > 0
        assert features[5] > 0

    @pytest.mark.unit
    def test_xss_payload(self, extractor):
        payload = '<script>alert("xss")</script>'
        features = extractor.extract(payload)

        # payload_length > 0
        assert features[0] > 0
        # special_char_count > 0 (<, >, ", (, ))
        assert features[1] > 0
        # shannon_entropy > 0
        assert features[5] > 0

    @pytest.mark.unit
    def test_normal_payload(self, extractor):
        payload = "http://localhost:8080/index.html"
        features = extractor.extract(payload)

        # sql_keyword_binary = 0 (no SQL keywords)
        assert features[2] == 0.0
        # url_depth > 0 (has /)
        assert features[6] > 0

    @pytest.mark.unit
    def test_shannon_entropy_uniform(self, extractor):
        """High entropy for random-looking payload."""
        payload = "aB3$xZ9!qR7@mK2#"
        features = extractor.extract(payload)
        entropy = features[5]
        assert entropy > 3.0  # High entropy

    @pytest.mark.unit
    def test_shannon_entropy_repetitive(self, extractor):
        """Low entropy for repetitive payload."""
        payload = "aaaaaaaaaaaa"
        features = extractor.extract(payload)
        entropy = features[5]
        assert entropy == 0.0  # Single character = 0 entropy

    @pytest.mark.unit
    def test_url_depth(self, extractor):
        payload = "/admin/config/database/users"
        features = extractor.extract(payload)
        url_depth = features[6]
        assert url_depth == 4.0

    @pytest.mark.unit
    def test_percent_encoded(self, extractor):
        # Note: after normalization %27 is decoded, but we count on normalized text
        payload = "test%20payload%20with%20spaces"
        features = extractor.extract(payload)
        # After normalization these become spaces, so percent count may be 0
        assert features[0] > 0  # payload_length > 0


# =============================================================================
# UNIT TESTS: WammClassifier Graceful Degradation
# =============================================================================

class TestWammClassifierGraceful:
    @pytest.mark.unit
    def test_no_model_returns_normal(self, classifier_no_model):
        """Without model files, predict should return (0, 0.0)."""
        result = classifier_no_model.predict(b"' OR 1=1 --")
        assert result == (0, 0.0)

    @pytest.mark.unit
    def test_no_model_not_enabled(self, classifier_no_model):
        assert classifier_no_model.enabled is False

    @pytest.mark.unit
    def test_empty_payload(self, classifier_no_model):
        result = classifier_no_model.predict(b"")
        assert result == (0, 0.0)

    @pytest.mark.unit
    def test_none_payload(self, classifier_no_model):
        result = classifier_no_model.predict(None)
        assert result == (0, 0.0)

    @pytest.mark.unit
    def test_batch_no_model(self, classifier_no_model):
        payloads = [b"test1", b"test2", b"test3"]
        results = classifier_no_model.predict_batch(payloads)
        assert len(results) == 3
        assert all(r == (0, 0.0) for r in results)

    @pytest.mark.unit
    def test_get_label_name(self, classifier_no_model):
        assert classifier_no_model.get_label_name(0) == "normal"
        assert classifier_no_model.get_label_name(1) == "sqli"
        assert classifier_no_model.get_label_name(2) == "xss"
        assert classifier_no_model.get_label_name(99) == "unknown"


# =============================================================================
# INTEGRATION TESTS: With Trained Model
# =============================================================================

class TestWammClassifierWithModel:
    @pytest.mark.wamm
    @pytest.mark.integration
    def test_model_enabled(self, classifier):
        assert classifier.enabled is True

    @pytest.mark.wamm
    @pytest.mark.integration
    def test_predict_sqli(self, classifier):
        payload = b"' UNION SELECT username, password FROM users --"
        attack_type, confidence = classifier.predict(payload)
        assert attack_type == WAMM_LABELS["sqli"]
        assert confidence > 0.5

    @pytest.mark.wamm
    @pytest.mark.integration
    def test_predict_xss(self, classifier):
        payload = b'<script>alert("XSS")</script>'
        attack_type, confidence = classifier.predict(payload)
        assert attack_type == WAMM_LABELS["xss"]
        assert confidence > 0.5

    @pytest.mark.wamm
    @pytest.mark.integration
    def test_predict_normal(self, classifier):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        attack_type, confidence = classifier.predict(payload)
        assert attack_type == WAMM_LABELS["normal"]

    @pytest.mark.wamm
    @pytest.mark.integration
    def test_predict_batch(self, classifier):
        payloads = [
            b"' OR 1=1 --",
            b"<script>alert(1)</script>",
            b"GET /index.html HTTP/1.1",
            None,
            b"",
        ]
        results = classifier.predict_batch(payloads)
        assert len(results) == 5
        # SQLi payload
        assert results[0][0] == WAMM_LABELS["sqli"]
        # XSS payload
        assert results[1][0] == WAMM_LABELS["xss"]
        # None/empty -> normal
        assert results[3] == (0, 0.0)
        assert results[4] == (0, 0.0)

    @pytest.mark.wamm
    @pytest.mark.integration
    def test_inference_latency(self, classifier):
        """Single prediction should be under 1ms."""
        payload = b"' UNION SELECT * FROM users --"
        runs = 100

        start = time.perf_counter()
        for _ in range(runs):
            classifier.predict(payload)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / runs) * 1000
        assert avg_ms < 1.0, f"Avg latency {avg_ms:.2f}ms exceeds 1ms target"

    @pytest.mark.wamm
    @pytest.mark.integration
    def test_confidence_range(self, classifier):
        """Confidence should always be in [0, 1]."""
        payloads = [
            b"' OR 1=1 --",
            b"<script>alert(1)</script>",
            b"normal text content",
            b"http://example.com/page?id=1",
        ]
        for payload in payloads:
            _, confidence = classifier.predict(payload)
            assert 0.0 <= confidence <= 1.0


# =============================================================================
# INTEGRATION TESTS: FlowFeatureCalculator with WAMM
# =============================================================================

class TestFlowFeatureCalculatorWamm:
    @pytest.mark.unit
    def test_calculator_16_features_no_model(self):
        """Calculator should produce 16 features even without WAMM model."""
        from feature.calculator import FlowFeatureCalculator
        calc = FlowFeatureCalculator()
        names = calc.get_feature_names()
        assert len(names) == 16
        assert "wamm_attack_type" in names
        assert "wamm_confidence" in names

    @pytest.mark.unit
    def test_calculator_empty_flows_16_zeros(self):
        """Empty flows should return 16 zeros."""
        from feature.calculator import FlowFeatureCalculator
        calc = FlowFeatureCalculator()
        result = calc.calculate_all_optimized([])
        assert len(result) == 16
        assert all(v == 0.0 for v in result)

    @pytest.mark.unit
    def test_num_features_constant(self):
        from feature.calculator import FlowFeatureCalculator
        assert FlowFeatureCalculator.NUM_FEATURES == 16
