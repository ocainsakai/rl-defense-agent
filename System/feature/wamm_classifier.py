"""feature/wamm_classifier.py

WAMM - Web Application Multiclass Model
Dựa trên: arxiv 2512.23610

Module độc lập phân loại tấn công web đa lớp sử dụng XGBoost + TF-IDF.
Chạy song song với PayloadContextScorer (KHÔNG thay thế nó).

Đầu ra:
    (attack_type: int, confidence: float)
    attack_type: 0=normal, 1=sqli, 2=xss
    confidence: 0.0 - 1.0

Xử lý lỗi nhẹ nhàng:
    - Nếu không tìm thấy file model → trả về (0, 0.0)
    - Nếu chưa cài xgboost/sklearn → module bị vô hiệu hóa
    - Không bao giờ làm crash hệ thống hiện có
"""

from __future__ import annotations

import logging
import math
import os
import pickle
import re
from collections import Counter

logger = logging.getLogger("WAMM")

# Dependency tùy chọn - import nhẹ nhàng
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
# CHUẨN HÓA PAYLOAD - Ủy quyền cho PayloadNormalizer (nguồn duy nhất chân lý)
# =============================================================================

from feature.context import PayloadNormalizer


def normalize_payload_text(raw_bytes: bytes) -> str:
    """Chuẩn hóa payload bytes thô thành chuỗi sạch để phân tích.

    Ủy quyền cho PayloadNormalizer.normalize() - nguồn duy nhất chân lý.
    """
    return PayloadNormalizer.normalize(raw_bytes)


# =============================================================================
# TRÍCH XUẤT ĐẶC TRƯNG THỦ CÔNG (Mục III-B của bài báo)
# =============================================================================

# Từ khóa SQL cho đặc trưng chỉ báo nhị phân
_SQL_KEYWORDS = frozenset({
    "select", "union", "insert", "update", "delete", "drop",
    "truncate", "alter", "create", "replace", "information_schema",
    "load_file", "outfile", "dumpfile", "benchmark", "sleep",
    "waitfor", "pg_sleep", "concat", "group_concat",
    "extractvalue", "updatexml",
})

# Ký tự đặc biệt liên quan đến tấn công web
_SPECIAL_CHARS = frozenset('<>"\'`;(){}[]$&|\\/-=#,')

# Pattern phần trăm mã hóa
_PERCENT_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')


class WammFeatureExtractor:
    """Trích xuất 8 đặc trưng thủ công từ chuỗi payload đã chuẩn hóa.

    Đặc trưng (theo Mục III-B của bài báo):
        0. payload_length: len(payload)
        1. special_char_count: số lượng <>"';() v.v.
        2. sql_keyword_binary: 1 nếu có từ khóa SQL, ngược lại 0
        3. numeric_char_count: số ký tự chữ số
        4. percent_encoded_count: số pattern %XX
        5. shannon_entropy: entropy thông tin của payload
        6. url_depth: số lần xuất hiện '/' trong payload
        7. unique_char_count: số ký tự duy nhất
    """

    def extract(self, normalized_payload: str) -> list[float]:
        """Trích xuất vector đặc trưng từ chuỗi payload đã chuẩn hóa.

        Args:
            normalized_payload: Chuỗi payload đã giải mã, chuyển thành chữ thường.

        Returns:
            Danh sách 8 giá trị float.
        """
        if not normalized_payload:
            return [0.0] * NUM_HANDCRAFTED_FEATURES

        length = float(len(normalized_payload))

        # 1. Số ký tự đặc biệt
        special_count = sum(1 for c in normalized_payload if c in _SPECIAL_CHARS)

        # 2. Nhị phân từ khóa SQL
        words = set(re.findall(r'[a-z_]+', normalized_payload))
        sql_binary = 1.0 if words & _SQL_KEYWORDS else 0.0

        # 3. Số ký tự chữ số
        numeric_count = sum(1 for c in normalized_payload if c.isdigit())

        # 4. Số lần mã hóa phần trăm (trên bản gốc trước khi giải mã đầy đủ)
        percent_count = len(_PERCENT_PATTERN.findall(normalized_payload))

        # 5. Entropy Shannon
        entropy = self._shannon_entropy(normalized_payload)

        # 6. Độ sâu URL
        url_depth = float(normalized_payload.count('/'))

        # 7. Số ký tự duy nhất
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
        """Tính entropy Shannon của một chuỗi."""
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
    """Bộ phân loại tấn công web đa lớp sử dụng XGBoost + TF-IDF.

    Sử dụng:
        classifier = WammClassifier()
        attack_type, confidence = classifier.predict(payload_bytes)

    Nếu không tìm thấy file model hoặc thiếu dependency,
    predict() trả về (0, 0.0) = normal với confidence bằng 0.
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
            logger.warning("WAMM bị vô hiệu hóa: thiếu dependency: %s", missing)
            return

        model_dir = model_dir or MODEL_DIR
        model_path = os.path.join(model_dir, "xgboost_model.pkl")
        vectorizer_path = os.path.join(model_dir, "tfidf_vectorizer.pkl")

        if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
            logger.warning(
                "WAMM bị vô hiệu hóa: không tìm thấy file model trong %s. "
                "Chạy 'python System/tools/wamm_train.py' để huấn luyện.",
                model_dir,
            )
            return

        try:
            with open(model_path, "rb") as f:
                self._model = pickle.load(f)
            with open(vectorizer_path, "rb") as f:
                self._vectorizer = pickle.load(f)
            self._enabled = True
            logger.info("WAMM classifier đã tải từ %s", model_dir)
        except Exception as e:
            logger.warning("WAMM bị vô hiệu hóa: không thể tải model: %s", e)

    @property
    def enabled(self) -> bool:
        """Trả về True nếu classifier sẵn sàng dự đoán."""
        return self._enabled

    def predict(self, payload_bytes: bytes | None) -> tuple[int, float]:
        """Phân loại một payload HTTP đơn lẻ.

        Args:
            payload_bytes: Payload HTTP bytes thô.

        Returns:
            (attack_type, confidence) trong đó:
                attack_type: 0=normal, 1=sqli, 2=xss
                confidence: xác suất của lớp dự đoán [0.0, 1.0]
        """
        if not self._enabled or not payload_bytes:
            return (0, 0.0)

        payload_bytes = payload_bytes[:MAX_PAYLOAD_LENGTH]
        normalized = normalize_payload_text(payload_bytes)

        if not normalized:
            return (0, 0.0)

        try:
            # Vector hóa TF-IDF
            tfidf_vector = self._vectorizer.transform([normalized])

            # Đặc trưng thủ công
            handcrafted = self._feature_extractor.extract(normalized)
            handcrafted_matrix = csr_matrix([handcrafted])

            # Kết hợp đặc trưng
            combined = sparse_hstack([tfidf_vector, handcrafted_matrix])

            # Dự đoán
            probas = self._model.predict_proba(combined)[0]
            predicted_class = int(np.argmax(probas))
            confidence = float(probas[predicted_class])

            # Áp dụng ngưỡng confidence
            if confidence < CONFIDENCE_THRESHOLD:
                return (0, confidence)

            return (predicted_class, confidence)

        except Exception as e:
            logger.debug("Lỗi dự đoán WAMM: %s", e)
            return (0, 0.0)

    def predict_batch(self, payloads: list[bytes | None]) -> list[tuple[int, float]]:
        """Phân loại nhiều payload cùng lúc để tăng throughput.

        Args:
            payloads: Danh sách payload HTTP bytes thô.

        Returns:
            Danh sách các tuple (attack_type, confidence).
        """
        if not self._enabled or not payloads:
            return [(0, 0.0)] * len(payloads)

        # Chuẩn hóa tất cả payload
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
            # TF-IDF theo batch
            tfidf_matrix = self._vectorizer.transform(normalized_texts)

            # Đặc trưng thủ công theo batch
            handcrafted_list = [
                self._feature_extractor.extract(text) for text in normalized_texts
            ]
            handcrafted_matrix = csr_matrix(handcrafted_list)

            # Kết hợp
            combined = sparse_hstack([tfidf_matrix, handcrafted_matrix])

            # Dự đoán theo batch
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
            logger.debug("Lỗi dự đoán batch WAMM: %s", e)
            return results

    def get_label_name(self, attack_type: int) -> str:
        """Chuyển đổi số loại tấn công thành nhãn dễ đọc."""
        return WAMM_LABELS_INV.get(attack_type, "unknown")
