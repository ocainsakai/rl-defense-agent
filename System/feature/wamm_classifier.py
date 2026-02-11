"""feature/wamm_classifier.py

WAMM - Web Application Multiclass Model
Based on: arxiv 2512.23610

Independent module for multiclass web attack classification using XGBoost + TF-IDF.
Runs alongside PayloadContextScorer (does NOT replace it).

Output:
    (attack_type: int, confidence: float)
    attack_type: 0=normal, 1=sqli, 2=xss
    confidence: 0.0 - 1.0

Graceful Degradation:
    - If model files not found -> returns (0, 0.0)
    - If xgboost/sklearn not installed -> module disabled
    - Never crashes the existing system
"""

from __future__ import annotations

import logging
import math
import os
import pickle
import re
from collections import Counter

logger = logging.getLogger("WAMM")

# Optional dependencies - graceful import
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from scipy.sparse import hstack as sparse_hstack, csr_matrix
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

# Config
from config.wamm_config import (
    WAMM_LABELS_INV,
    NUM_CLASSES,
    MAX_PAYLOAD_LENGTH,
    CONFIDENCE_THRESHOLD,
    XGBOOST_MODEL_PATH,
    TFIDF_VECTORIZER_PATH,
    MODEL_DIR,
    NUM_HANDCRAFTED_FEATURES,
)


# =============================================================================
# PAYLOAD NORMALIZATION - Delegate to PayloadNormalizer (single source of truth)
# =============================================================================

from feature.context import PayloadNormalizer


def normalize_payload_text(raw_bytes: bytes) -> str:
    """Normalize raw payload bytes to a clean string for analysis.

    Delegates to PayloadNormalizer.normalize() - nguồn duy nhất chân lý.
    """
    return PayloadNormalizer.normalize(raw_bytes)


# =============================================================================
# HANDCRAFTED FEATURE EXTRACTOR (Section III-B of paper)
# =============================================================================

# SQL keywords for binary indicator feature
_SQL_KEYWORDS = frozenset({
    "select", "union", "insert", "update", "delete", "drop",
    "truncate", "alter", "create", "replace", "information_schema",
    "load_file", "outfile", "dumpfile", "benchmark", "sleep",
    "waitfor", "pg_sleep", "concat", "group_concat",
    "extractvalue", "updatexml",
})

# Special characters relevant to web attacks
_SPECIAL_CHARS = frozenset('<>"\'`;(){}[]$&|\\/-=#,')

# Percent-encoded pattern
_PERCENT_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')


class WammFeatureExtractor:
    """Extract 8 handcrafted features from a normalized payload string.

    Features (per paper Section III-B):
        0. payload_length: len(payload)
        1. special_char_count: count of <>"';() etc.
        2. sql_keyword_binary: 1 if any SQL keyword present, else 0
        3. numeric_char_count: count of digit characters
        4. percent_encoded_count: count of %XX patterns
        5. shannon_entropy: information entropy of payload
        6. url_depth: count of '/' in payload
        7. unique_char_count: number of distinct characters
    """

    def extract(self, normalized_payload: str) -> list[float]:
        """Extract feature vector from normalized payload string.

        Args:
            normalized_payload: Lowercased, decoded payload string.

        Returns:
            List of 8 float values.
        """
        if not normalized_payload:
            return [0.0] * NUM_HANDCRAFTED_FEATURES

        length = float(len(normalized_payload))

        # 1. Special char count
        special_count = sum(1 for c in normalized_payload if c in _SPECIAL_CHARS)

        # 2. SQL keyword binary
        words = set(re.findall(r'[a-z_]+', normalized_payload))
        sql_binary = 1.0 if words & _SQL_KEYWORDS else 0.0

        # 3. Numeric char count
        numeric_count = sum(1 for c in normalized_payload if c.isdigit())

        # 4. Percent-encoded count (on original before full decode)
        percent_count = len(_PERCENT_PATTERN.findall(normalized_payload))

        # 5. Shannon entropy
        entropy = self._shannon_entropy(normalized_payload)

        # 6. URL depth
        url_depth = float(normalized_payload.count('/'))

        # 7. Unique char count
        unique_chars = float(len(set(normalized_payload)))

        return [
            length,
            float(special_count),
            sql_binary,
            float(numeric_count),
            float(percent_count),
            entropy,
            url_depth,
            unique_chars,
        ]

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        counter = Counter(text)
        total = len(text)
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy


# =============================================================================
# WAMM CLASSIFIER
# =============================================================================

class WammClassifier:
    """Multiclass web attack classifier using XGBoost + TF-IDF.

    Usage:
        classifier = WammClassifier()
        attack_type, confidence = classifier.predict(payload_bytes)

    If model files are not found or dependencies are missing,
    predict() returns (0, 0.0) = normal with zero confidence.
    """

    def __init__(self, model_dir: str | None = None):
        self._model = None
        self._vectorizer = None
        self._feature_extractor = WammFeatureExtractor()
        self._enabled = False

        if not all([HAS_NUMPY, HAS_SCIPY, HAS_XGBOOST, HAS_SKLEARN]):
            missing = []
            if not HAS_NUMPY:
                missing.append("numpy")
            if not HAS_SCIPY:
                missing.append("scipy")
            if not HAS_XGBOOST:
                missing.append("xgboost")
            if not HAS_SKLEARN:
                missing.append("scikit-learn")
            logger.warning("WAMM disabled: missing dependencies: %s", missing)
            return

        model_dir = model_dir or MODEL_DIR
        model_path = os.path.join(model_dir, "xgboost_model.pkl")
        vectorizer_path = os.path.join(model_dir, "tfidf_vectorizer.pkl")

        if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
            logger.warning(
                "WAMM disabled: model files not found in %s. "
                "Run 'python System/tools/wamm_train.py' to train.",
                model_dir,
            )
            return

        try:
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)
            with open(vectorizer_path, "rb") as f:
                self._vectorizer = pickle.load(f)
            self._enabled = True
            logger.info("WAMM classifier loaded from %s", model_dir)
        except Exception as e:
            logger.warning("WAMM disabled: failed to load model: %s", e)

    @property
    def enabled(self) -> bool:
        """Whether the classifier is ready for predictions."""
        return self._enabled

    def predict(self, payload_bytes: bytes | None) -> tuple[int, float]:
        """Classify a single HTTP payload.

        Args:
            payload_bytes: Raw HTTP payload bytes.

        Returns:
            (attack_type, confidence) where:
                attack_type: 0=normal, 1=sqli, 2=xss
                confidence: probability of predicted class [0.0, 1.0]
        """
        if not self._enabled or not payload_bytes:
            return (0, 0.0)

        payload_bytes = payload_bytes[:MAX_PAYLOAD_LENGTH]
        normalized = normalize_payload_text(payload_bytes)

        if not normalized:
            return (0, 0.0)

        try:
            # TF-IDF vectorization
            tfidf_vector = self._vectorizer.transform([normalized])

            # Handcrafted features
            handcrafted = self._feature_extractor.extract(normalized)
            handcrafted_matrix = csr_matrix([handcrafted])

            # Combine features
            combined = sparse_hstack([tfidf_vector, handcrafted_matrix])

            # Predict
            probas = self._model.predict_proba(combined)[0]
            predicted_class = int(np.argmax(probas))
            confidence = float(probas[predicted_class])

            # Apply confidence threshold
            if confidence < CONFIDENCE_THRESHOLD:
                return (0, confidence)

            return (predicted_class, confidence)

        except Exception as e:
            logger.debug("WAMM prediction error: %s", e)
            return (0, 0.0)

    def predict_batch(self, payloads: list[bytes | None]) -> list[tuple[int, float]]:
        """Classify multiple payloads at once for better throughput.

        Args:
            payloads: List of raw HTTP payload bytes.

        Returns:
            List of (attack_type, confidence) tuples.
        """
        if not self._enabled or not payloads:
            return [(0, 0.0)] * len(payloads)

        # Normalize all payloads
        normalized_texts = []
        valid_indices = []
        results = [(0, 0.0)] * len(payloads)

        for i, payload_bytes in enumerate(payloads):
            if not payload_bytes:
                continue
            text = normalize_payload_text(payload_bytes[:MAX_PAYLOAD_LENGTH])
            if text:
                normalized_texts.append(text)
                valid_indices.append(i)

        if not normalized_texts:
            return results

        try:
            # Batch TF-IDF
            tfidf_matrix = self._vectorizer.transform(normalized_texts)

            # Batch handcrafted features
            handcrafted_list = [
                self._feature_extractor.extract(text) for text in normalized_texts
            ]
            handcrafted_matrix = csr_matrix(handcrafted_list)

            # Combine
            combined = sparse_hstack([tfidf_matrix, handcrafted_matrix])

            # Batch predict
            all_probas = self._model.predict_proba(combined)

            for idx, probas in zip(valid_indices, all_probas):
                predicted_class = int(np.argmax(probas))
                confidence = float(probas[predicted_class])

                if confidence < CONFIDENCE_THRESHOLD:
                    results[idx] = (0, confidence)
                else:
                    results[idx] = (predicted_class, confidence)

            return results

        except Exception as e:
            logger.debug("WAMM batch prediction error: %s", e)
            return results

    def get_label_name(self, attack_type: int) -> str:
        """Convert attack type int to human-readable label."""
        return WAMM_LABELS_INV.get(attack_type, "unknown")
