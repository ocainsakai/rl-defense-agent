#!/usr/bin/env python3
"""tools/wamm_train.py

Training script for WAMM (Web Application Multiclass Model).
Based on: arxiv 2512.23610

Loads existing datasets, trains XGBoost + TF-IDF classifier,
and serializes model artifacts to System/models/wamm/.

Usage:
    python System/tools/wamm_train.py
    python System/tools/wamm_train.py --output-dir System/models/wamm

Datasets used:
    - sqli.csv (UTF-16): SQLi payloads (all attack, Label=1)
    - XSS_dataset.csv (UTF-8): XSS payloads + benign HTML (Label 0/1)
    - csic_database.csv: Normal HTTP traffic (classification=Normal)
"""

import argparse
import json
import logging
import os
import pickle
import sys
import time

# Add System/ to path for config imports
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_SYSTEM_DIR = os.path.dirname(_SCRIPT_DIR)
if _SYSTEM_DIR not in sys.path:
    sys.path.insert(0, _SYSTEM_DIR)

import numpy as np
import pandas as pd
from scipy.sparse import hstack as sparse_hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from config.wamm_config import (
    WAMM_LABELS,
    WAMM_LABELS_INV,
    NUM_CLASSES,
    TFIDF_MAX_FEATURES,
    TFIDF_ANALYZER,
    TFIDF_NGRAM_RANGE,
    XGB_PARAMS,
    MODEL_DIR,
    SQLI_DATASET_PATH,
    XSS_DATASET_PATH,
    CSIC_DATASET_PATH,
    TRAINING_REPORT_PATH,
)
from feature.wamm_classifier import WammFeatureExtractor, normalize_payload_text

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("WAMM_Train")


# =============================================================================
# DATA LOADING
# =============================================================================

def load_sqli_dataset(path: str) -> pd.DataFrame:
    """Load sqli.csv (UTF-16 encoded, columns: Sentence, Label).

    All rows are attack payloads (Label=1). We map them to label 'sqli'.
    """
    logger.info("Loading SQLi dataset: %s", path)
    df = pd.read_csv(path, encoding="utf-16", on_bad_lines="skip")
    df.columns = df.columns.str.strip()
    df = df.dropna(subset=["Sentence"])
    df["text"] = df["Sentence"].astype(str).str.strip()
    df["label"] = WAMM_LABELS["sqli"]
    logger.info("  SQLi samples: %d", len(df))
    return df[["text", "label"]]


def load_xss_dataset(path: str) -> pd.DataFrame:
    """Load XSS_dataset.csv (UTF-8 BOM, columns: index, Sentence, Label).

    Label=0 -> normal, Label=1 -> xss.
    """
    logger.info("Loading XSS dataset: %s", path)
    df = pd.read_csv(path, encoding="utf-8-sig", on_bad_lines="skip")
    df.columns = df.columns.str.strip()
    df = df.dropna(subset=["Sentence"])
    df["text"] = df["Sentence"].astype(str).str.strip()
    df["label"] = df["Label"].apply(
        lambda x: WAMM_LABELS["xss"] if int(x) == 1 else WAMM_LABELS["normal"]
    )
    logger.info("  XSS attack samples: %d", (df["label"] == WAMM_LABELS["xss"]).sum())
    logger.info("  XSS normal samples: %d", (df["label"] == WAMM_LABELS["normal"]).sum())
    return df[["text", "label"]]


def load_csic_normal(path: str, max_samples: int = 5000) -> pd.DataFrame:
    """Load normal HTTP traffic from csic_database.csv.

    Uses the URL column as payload text for normal samples.
    Limits to max_samples to balance the dataset.
    """
    logger.info("Loading CSIC normals: %s", path)
    df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    df.columns = df.columns.str.strip()

    # Filter only Normal traffic
    normal_df = df[df.iloc[:, 0].str.strip().str.lower() == "normal"].copy()

    # Combine URL + content for richer normal examples
    texts = []
    for _, row in normal_df.iterrows():
        parts = []
        url = str(row.get("URL", "")).strip()
        content = str(row.get("content", "")).strip()
        if url and url != "nan":
            parts.append(url)
        if content and content != "nan":
            parts.append(content)
        if parts:
            texts.append(" ".join(parts))

    normal_df = pd.DataFrame({"text": texts})

    if len(normal_df) > max_samples:
        normal_df = normal_df.sample(n=max_samples, random_state=42)

    normal_df["label"] = WAMM_LABELS["normal"]
    logger.info("  CSIC normal samples: %d", len(normal_df))
    return normal_df[["text", "label"]]


def load_all_datasets() -> pd.DataFrame:
    """Load and merge all datasets."""
    dfs = []

    if os.path.exists(SQLI_DATASET_PATH):
        dfs.append(load_sqli_dataset(SQLI_DATASET_PATH))
    else:
        logger.warning("SQLi dataset not found: %s", SQLI_DATASET_PATH)

    if os.path.exists(XSS_DATASET_PATH):
        dfs.append(load_xss_dataset(XSS_DATASET_PATH))
    else:
        logger.warning("XSS dataset not found: %s", XSS_DATASET_PATH)

    if os.path.exists(CSIC_DATASET_PATH):
        dfs.append(load_csic_normal(CSIC_DATASET_PATH))
    else:
        logger.warning("CSIC dataset not found: %s", CSIC_DATASET_PATH)

    if not dfs:
        raise FileNotFoundError("No datasets found. Check dataset paths in wamm_config.py")

    merged = pd.concat(dfs, ignore_index=True)
    merged = merged.dropna(subset=["text"])
    merged = merged[merged["text"].str.len() > 0]

    logger.info("Total merged samples: %d", len(merged))
    for label_int, label_name in WAMM_LABELS_INV.items():
        count = (merged["label"] == label_int).sum()
        logger.info("  %s (label=%d): %d samples", label_name, label_int, count)

    return merged


# =============================================================================
# TRAINING PIPELINE
# =============================================================================

def train_wamm(output_dir: str) -> dict:
    """Full training pipeline: load data -> train -> evaluate -> serialize.

    Returns:
        dict: Training report with metrics.
    """
    start_time = time.time()

    # 1. Load data
    logger.info("=" * 60)
    logger.info("STEP 1: Loading datasets")
    logger.info("=" * 60)
    df = load_all_datasets()

    # 2. Normalize text
    logger.info("=" * 60)
    logger.info("STEP 2: Normalizing payloads")
    logger.info("=" * 60)
    df["normalized"] = df["text"].apply(
        lambda t: normalize_payload_text(t.encode("utf-8", errors="ignore"))
    )
    df = df[df["normalized"].str.len() > 0]
    logger.info("After normalization: %d samples", len(df))

    # 3. Train/test split (80/20 stratified)
    logger.info("=" * 60)
    logger.info("STEP 3: Train/test split (80/20)")
    logger.info("=" * 60)
    X_text = df["normalized"].values
    y = df["label"].values

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, stratify=y, random_state=42
    )
    logger.info("Train: %d, Test: %d", len(X_train_text), len(X_test_text))

    # 4. TF-IDF vectorization
    logger.info("=" * 60)
    logger.info("STEP 4: TF-IDF vectorization")
    logger.info("=" * 60)
    tfidf = TfidfVectorizer(
        analyzer=TFIDF_ANALYZER,
        ngram_range=TFIDF_NGRAM_RANGE,
        max_features=TFIDF_MAX_FEATURES,
    )
    X_train_tfidf = tfidf.fit_transform(X_train_text)
    X_test_tfidf = tfidf.transform(X_test_text)
    logger.info("TF-IDF shape: %s", X_train_tfidf.shape)

    # 5. Handcrafted features
    logger.info("=" * 60)
    logger.info("STEP 5: Extracting handcrafted features")
    logger.info("=" * 60)
    extractor = WammFeatureExtractor()

    train_hc = [extractor.extract(text) for text in X_train_text]
    test_hc = [extractor.extract(text) for text in X_test_text]

    X_train_hc = csr_matrix(train_hc)
    X_test_hc = csr_matrix(test_hc)
    logger.info("Handcrafted features shape: %s", X_train_hc.shape)

    # 6. Combine features
    X_train_combined = sparse_hstack([X_train_tfidf, X_train_hc])
    X_test_combined = sparse_hstack([X_test_tfidf, X_test_hc])
    logger.info("Combined feature shape: %s", X_train_combined.shape)

    # 7. Class weighting
    logger.info("=" * 60)
    logger.info("STEP 6: Training XGBoost")
    logger.info("=" * 60)
    sample_weights = compute_sample_weight("balanced", y_train)

    # 8. Train XGBoost
    model = XGBClassifier(**XGB_PARAMS)
    model.fit(
        X_train_combined,
        y_train,
        sample_weight=sample_weights,
        eval_set=[(X_test_combined, y_test)],
        verbose=50,
    )

    # 9. Evaluate
    logger.info("=" * 60)
    logger.info("STEP 7: Evaluation")
    logger.info("=" * 60)
    y_pred = model.predict(X_test_combined)
    accuracy = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")

    target_names = [WAMM_LABELS_INV[i] for i in range(NUM_CLASSES)]
    report_str = classification_report(y_test, y_pred, target_names=target_names)
    cm = confusion_matrix(y_test, y_pred)

    logger.info("Accuracy: %.4f", accuracy)
    logger.info("Macro F1: %.4f", macro_f1)
    logger.info("\n%s", report_str)
    logger.info("Confusion Matrix:\n%s", cm)

    # 10. Inference latency test
    single_sample = X_test_combined[:1]
    latency_runs = 100
    t0 = time.time()
    for _ in range(latency_runs):
        model.predict_proba(single_sample)
    avg_latency_us = (time.time() - t0) / latency_runs * 1_000_000
    logger.info("Avg inference latency: %.1f us/sample", avg_latency_us)

    # 11. Serialize
    logger.info("=" * 60)
    logger.info("STEP 8: Saving model artifacts")
    logger.info("=" * 60)
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, "xgboost_model.pkl")
    vectorizer_path = os.path.join(output_dir, "tfidf_vectorizer.pkl")
    report_path = os.path.join(output_dir, "training_report.json")

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    logger.info("Model saved: %s", model_path)

    with open(vectorizer_path, "wb") as f:
        pickle.dump(tfidf, f)
    logger.info("Vectorizer saved: %s", vectorizer_path)

    # Training report
    elapsed = time.time() - start_time
    report = {
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "classification_report": classification_report(
            y_test, y_pred, target_names=target_names, output_dict=True
        ),
        "confusion_matrix": cm.tolist(),
        "train_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "tfidf_features": int(X_train_tfidf.shape[1]),
        "handcrafted_features": int(X_train_hc.shape[1]),
        "total_features": int(X_train_combined.shape[1]),
        "avg_inference_latency_us": float(avg_latency_us),
        "training_time_seconds": float(elapsed),
        "class_distribution": {
            WAMM_LABELS_INV[i]: int((y == i).sum()) for i in range(NUM_CLASSES)
        },
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("Report saved: %s", report_path)

    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE in %.1f seconds", elapsed)
    logger.info("=" * 60)

    return report


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Train WAMM classifier")
    parser.add_argument(
        "--output-dir",
        default=MODEL_DIR,
        help=f"Directory for model artifacts (default: {MODEL_DIR})",
    )
    args = parser.parse_args()

    train_wamm(args.output_dir)


if __name__ == "__main__":
    main()
