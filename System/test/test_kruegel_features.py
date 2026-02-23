"""
Test Kruegel-Vigna Web Anomaly Detection Features.

Verify all 6 models work correctly:
  1. Attribute Length (Chebyshev)
  2. Character Distribution (ICD + chi-squared)
  3. Structural Inference (pattern matching)
  4. Token Finder (enumeration detection)
  5. Attribute Presence/Absence
  6. Attribute Order
"""

import pytest

from feature._archive.kruegel_features import (
    KruegelFeatureExtractor,
    AttributeLengthModel,
    CharDistributionModel,
    StructuralModel,
    TokenFinderModel,
    AttributePresenceModel,
    AttributeOrderModel,
    parse_uri,
)


@pytest.mark.kruegel
class TestParseUri:
    """Test URI parser."""

    @pytest.mark.parametrize("uri,expected_path,expected_params", [
        ("/search?q=hello&lang=en", "/search", {"q": ["hello"], "lang": ["en"]}),
        ("/login?user=admin&pass=123", "/login", {"user": ["admin"], "pass": ["123"]}),
        ("/path", "/path", {}),
        ("/api?id=5", "/api", {"id": ["5"]}),
    ])
    def test_parse_uri(self, uri, expected_path, expected_params):
        path, params = parse_uri(uri)
        assert path == expected_path
        assert dict(params) == expected_params


@pytest.mark.kruegel
class TestAttributeLength:
    """Test Attribute Length Model (Chebyshev)."""

    @pytest.fixture
    def trained_model(self):
        model = AttributeLengthModel()
        for name in ["admin", "john", "alice", "bob", "charlie", "david", "frank", "grace"]:
            model.train("user", name)
        model.finalize()
        return model

    @pytest.mark.parametrize("value,expect_normal", [
        ("alice", True),
        ("a", False),
        ("A" * 200, False),
        ("bob", True),
    ])
    def test_length_detection(self, trained_model, value, expect_normal):
        p = trained_model.detect("user", value)
        is_normal = p > 0.1
        assert is_normal == expect_normal, f"len={len(value)}, prob={p:.4f}"


@pytest.mark.kruegel
class TestCharDistribution:
    """Test Character Distribution Model (ICD + Chi-squared)."""

    @pytest.fixture
    def trained_model(self):
        model = CharDistributionModel()
        normal_queries = [
            "hello world", "python programming", "web security",
            "machine learning", "data science", "neural networks",
            "computer vision", "natural language", "deep learning",
            "artificial intelligence",
        ]
        for q in normal_queries:
            model.train("q", q)
        model.finalize()
        return model

    @pytest.mark.parametrize("value,desc,expect_normal", [
        ("information retrieval", "Normal text", True),
        ("\x90" * 50, "NOP sled", False),
        ("aaaaaaaaaaaaaaa", "Repeated char", False),
    ])
    def test_char_distribution(self, trained_model, value, desc, expect_normal):
        p = trained_model.detect("q", value)
        is_normal = p > 0.05
        assert is_normal == expect_normal, f"{desc}: prob={p:.4f}"


@pytest.mark.kruegel
class TestStructuralModel:
    """Test Structural Inference Model."""

    @pytest.fixture
    def trained_model(self):
        model = StructuralModel()
        for v in ["123", "456", "789", "1001", "2048"]:
            model.train("id", v)
        for v in ["alice", "bob", "charlie"]:
            model.train("name", v)
        model.finalize()
        return model

    @pytest.mark.parametrize("param,value,desc,expect_normal", [
        ("id", "999", "Normal digit ID", True),
        ("id", "../../etc/passwd", "Directory traversal", False),
        ("id", "1 UNION SELECT", "SQLi in ID", False),
        ("name", "david", "Normal name", True),
        ("name", "<script>alert(1)</script>", "XSS in name", False),
    ])
    def test_structural_detection(self, trained_model, param, value, desc, expect_normal):
        p = trained_model.detect(param, value)
        is_normal = p > 0.5
        assert is_normal == expect_normal, f"{desc}: prob={p:.4f}"


@pytest.mark.kruegel
class TestTokenFinder:
    """Test Token Finder Model (Enumeration Detection)."""

    @pytest.fixture
    def trained_model(self):
        model = TokenFinderModel()
        for _ in range(10):
            for v in ["view", "edit", "delete"]:
                model.train("action", v)
        for v in ["hello", "world", "foo", "bar", "test", "abc", "xyz",
                   "python", "java", "rust", "go", "swift"]:
            model.train("q", v)
        model.finalize()
        return model

    @pytest.mark.parametrize("param,value,desc,expect_normal", [
        ("action", "view", "Known enum value", True),
        ("action", "drop_table", "Unknown enum value", False),
        ("q", "anything_goes", "Random param", True),
    ])
    def test_token_detection(self, trained_model, param, value, desc, expect_normal):
        p = trained_model.detect(param, value)
        is_normal = p > 0.5
        assert is_normal == expect_normal, f"{desc}: prob={p:.4f}"


@pytest.mark.kruegel
class TestPresenceAbsence:
    """Test Attribute Presence/Absence Model."""

    @pytest.fixture
    def trained_model(self):
        model = AttributePresenceModel()
        model.train("/login", frozenset(["user", "pass"]))
        model.train("/search", frozenset(["q"]))
        model.train("/search", frozenset(["q", "lang"]))
        model.finalize()
        return model

    @pytest.mark.parametrize("path,params,desc,expect_normal", [
        ("/login", frozenset(["user", "pass"]), "Normal login params", True),
        ("/login", frozenset(["user"]), "Missing 'pass' param", False),
        ("/login", frozenset(["user", "pass", "admin"]), "Extra param", False),
        ("/search", frozenset(["q"]), "Normal search", True),
        ("/search", frozenset(["q", "lang"]), "Search with lang", True),
    ])
    def test_presence_detection(self, trained_model, path, params, desc, expect_normal):
        p = trained_model.detect(path, params)
        is_normal = p > 0.5
        assert is_normal == expect_normal, f"{desc}: prob={p:.4f}"


@pytest.mark.kruegel
class TestAttributeOrder:
    """Test Attribute Order Model."""

    @pytest.fixture
    def trained_model(self):
        model = AttributeOrderModel()
        model.train("/login", ["user", "pass"])
        model.train("/login", ["user", "pass"])
        model.finalize()
        return model

    @pytest.mark.parametrize("path,params,desc,expect_normal", [
        ("/login", ["user", "pass"], "Correct order", True),
        ("/login", ["pass", "user"], "Reversed order", False),
    ])
    def test_order_detection(self, trained_model, path, params, desc, expect_normal):
        p = trained_model.detect(path, params)
        is_normal = p > 0.5
        assert is_normal == expect_normal, f"{desc}: prob={p:.4f}"


@pytest.mark.kruegel
class TestKruegelFullPipeline:
    """Test full Kruegel pipeline: train + detect."""

    @pytest.fixture
    def trained_extractor(self):
        extractor = KruegelFeatureExtractor()
        normal_uris = [
            "/search?q=python+tutorial&lang=en",
            "/search?q=machine+learning&lang=en",
            "/search?q=web+security&lang=fr",
            "/search?q=data+science&lang=en",
            "/search?q=neural+networks&lang=de",
            "/search?q=deep+learning&lang=en",
            "/search?q=computer+vision&lang=en",
            "/search?q=natural+language&lang=es",
            "/search?q=cloud+computing&lang=en",
            "/search?q=cyber+security&lang=en",
            "/login?user=alice&pass=secret123",
            "/login?user=bob&pass=mypass456",
            "/login?user=charlie&pass=pass789",
            "/login?user=david&pass=david2024",
            "/login?user=eve&pass=evepass00",
            "/api/item?id=1&action=view",
            "/api/item?id=2&action=edit",
            "/api/item?id=3&action=view",
            "/api/item?id=4&action=delete",
            "/api/item?id=5&action=view",
            "/api/item?id=10&action=view",
            "/api/item?id=15&action=edit",
            "/api/item?id=20&action=view",
            "/api/item?id=25&action=delete",
            "/api/item?id=30&action=view",
        ]
        for uri in normal_uris:
            extractor.train(uri)
        extractor.finalize_training()
        return extractor

    @pytest.mark.parametrize("uri,desc", [
        ("/search?q=artificial+intelligence&lang=en", "Normal search"),
        ("/login?user=frank&pass=frank2024", "Normal login"),
        ("/api/item?id=7&action=view", "Normal API call"),
    ])
    def test_normal_traffic(self, trained_extractor, uri, desc):
        """Normal traffic should not be flagged as anomalous."""
        scores = trained_extractor.detect(uri)
        assert not scores['is_anomalous'], f"{desc}: wrongly flagged, score={scores['anomaly_score']:.4f}"

    @pytest.mark.parametrize("uri,desc", [
        ("/search?q=' OR 1=1 --&lang=en", "SQLi: Tautology"),
        ("/search?q=' UNION SELECT username,password FROM users --&lang=en", "SQLi: UNION"),
        ("/login?user=admin'--&pass=x", "SQLi: Auth bypass"),
        ("/search?q=<script>alert(document.cookie)</script>&lang=en", "XSS: Script"),
        ("/search?q=<img src=x onerror=alert(1)>&lang=en", "XSS: Event handler"),
        ("/search?q=" + "A" * 500 + "&lang=en", "Buffer Overflow"),
        ("/api/item?id=../../../../etc/passwd&action=view", "Directory Traversal"),
        ("/api/item?id=1&action=drop_table", "Unknown enum value"),
        ("/login?user=admin", "Missing 'pass' parameter"),
        ("/login?pass=secret&user=admin", "Reversed parameter order"),
    ])
    def test_attack_traffic(self, trained_extractor, uri, desc):
        """Attack traffic should be flagged by at least one model."""
        scores = trained_extractor.detect(uri)
        any_flagged = any(
            scores[k] < 0.5
            for k in ['length_prob', 'char_dist_prob', 'structure_prob',
                       'token_prob', 'presence_prob', 'order_prob']
        )
        assert any_flagged or scores['is_anomalous'], \
            f"{desc}: not detected, score={scores['anomaly_score']:.4f}"


@pytest.mark.kruegel
class TestKruegelDetectionMatrix:
    """Detection matrix from paper Table 5."""

    def test_all_attack_classes_detected(self):
        """Each attack class should be detected by at least one model."""
        extractor = KruegelFeatureExtractor()

        for _ in range(5):
            for uri in [
                "/app?param=normalvalue&mode=view",
                "/app?param=teststring&mode=edit",
                "/app?param=userdata&mode=view",
                "/app?param=sampletext&mode=delete",
                "/app?param=inputdata&mode=view",
            ]:
                extractor.train(uri)
        extractor.finalize_training()

        attacks = {
            "Buffer Overflow": "/app?param=" + "A" * 300 + "&mode=view",
            "Directory Traversal": "/app?param=../../../etc/passwd&mode=view",
            "XSS": "/app?param=<script>alert(1)</script>&mode=view",
            "Input Validation": "/app?param=INVALID&mode=drop_database",
            "SQLi": "/app?param=' OR 1=1 --&mode=view",
        }

        for name, uri in attacks.items():
            s = extractor.detect(uri)
            any_detected = any(
                s[k] < 0.5
                for k in ['length_prob', 'char_dist_prob', 'structure_prob',
                           'token_prob', 'presence_prob', 'order_prob']
            )
            assert any_detected, f"{name} not detected by any model"
