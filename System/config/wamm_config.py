"""config/wamm_config.py

Cấu hình cho WAMM (Web Application Multiclass Model) classifier.
Dựa trên: arxiv 2512.23610 - Enhanced Web Payload Classification Using WAMM

Module này độc lập với cấu hình NIDS hiện có.
"""

import os

# =============================================================================
# MÃ HÓA LOẠI TẤN CÔNG
# =============================================================================
WAMM_LABELS = {"normal": 0, "sqli": 1, "xss": 2}
WAMM_LABELS_INV = {0: "normal", 1: "sqli", 2: "xss"}
NUM_CLASSES = 3

# =============================================================================
# CẤU HÌNH TF-IDF VECTORIZER (Mục III-B của bài báo)
# =============================================================================
TFIDF_MAX_FEATURES = 2000
TFIDF_ANALYZER = "char"
TFIDF_NGRAM_RANGE = (1, 2)

# =============================================================================
# SIÊU THAM SỐ XGBOOST
# =============================================================================
XGB_PARAMS = {
    "n_estimators": 300,
    "max_depth": 6,
    "learning_rate": 0.1,
    "objective": "multi:softprob",
    "num_class": NUM_CLASSES,
    "eval_metric": "mlogloss",
    "tree_method": "hist",
    "random_state": 42,
    "n_jobs": -1,
}

# =============================================================================
# ĐƯỜNG DẪN MODEL
# =============================================================================
_SYSTEM_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(_SYSTEM_DIR, "models", "wamm")
XGBOOST_MODEL_PATH = os.path.join(MODEL_DIR, "xgboost_model.pkl")
TFIDF_VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
TRAINING_REPORT_PATH = os.path.join(MODEL_DIR, "training_report.json")

# =============================================================================
# ĐƯỜNG DẪN DATASET
# =============================================================================
DATASET_DIR = os.path.join(_SYSTEM_DIR, "dataset")
SQLI_DATASET_PATH = os.path.join(DATASET_DIR, "sqli.csv")
XSS_DATASET_PATH = os.path.join(DATASET_DIR, "XSS_dataset.csv")
CSIC_DATASET_PATH = os.path.join(DATASET_DIR, "csic_database.csv")

# =============================================================================
# CẤU HÌNH SUY LUẬN
# =============================================================================
MAX_PAYLOAD_LENGTH = 65536      # Số byte tối đa để xử lý (khớp với PayloadContextScorer)
CONFIDENCE_THRESHOLD = 0.5      # Dưới ngưỡng này → phân loại là normal

# =============================================================================
# TÊN ĐẶC TRƯNG THỦ CÔNG (8 đặc trưng, Mục III-B)
# =============================================================================
HANDCRAFTED_FEATURE_NAMES = [
    "payload_length",
    "special_char_count",
    "sql_keyword_binary",
    "numeric_char_count",
    "percent_encoded_count",
    "shannon_entropy",
    "url_depth",
    "unique_char_count",
]
NUM_HANDCRAFTED_FEATURES = len(HANDCRAFTED_FEATURE_NAMES)
