"""
train_classifier.py — Train + evaluate one classifier on one feature set.

Used by run_comparison.py to evaluate a single (feature_set, classifier, fold, seed)
combination. Computes 18+ metrics for downstream comparison.
"""

from __future__ import annotations

import time
from typing import Any, Dict

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

CLASS_ORDER = ["benign", "brute_force", "sqli", "xss"]


def get_classifier(name: str, seed: int) -> Any:
    """Instantiate classifier with consistent hyperparameters."""
    if name == "rf":
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            class_weight="balanced",
            random_state=seed,
            n_jobs=-1,
        )
    if name == "xgb":
        return XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            objective="multi:softprob",
            random_state=seed,
            tree_method="hist",
            n_jobs=-1,
            verbosity=0,
        )
    raise ValueError(f"Unknown classifier: {name}")


def evaluate_classifier(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    classifier_name: str,
    seed: int,
    label_encoder: LabelEncoder,
) -> Dict[str, Any]:
    """Train + evaluate, return metrics dict."""
    clf = get_classifier(classifier_name, seed)

    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0

    t0 = time.time()
    y_pred = clf.predict(X_test)
    predict_time = (time.time() - t0) / max(len(X_test), 1) * 1000  # ms per sample

    # Probabilities for ROC-AUC (multi-class one-vs-rest)
    try:
        y_proba = clf.predict_proba(X_test)
    except Exception:
        y_proba = None

    # Map class labels back for reports
    class_names = list(label_encoder.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=range(len(class_names)))
    report = classification_report(
        y_test, y_pred, labels=range(len(class_names)),
        target_names=class_names, output_dict=True, zero_division=0,
    )

    metrics: Dict[str, Any] = {
        "classifier": classifier_name,
        "seed": seed,
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_features": int(X_train.shape[1]),
        "train_time_sec": float(train_time),
        "predict_time_ms_per_sample": float(predict_time),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "accuracy": float(report["accuracy"]),
        "confusion_matrix": cm.tolist(),
        "class_names": class_names,
        "per_class": {c: report[c] for c in class_names if c in report},
    }

    if y_proba is not None and len(class_names) > 1:
        try:
            metrics["roc_auc_ovr_macro"] = float(
                roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro",
                              labels=range(len(class_names)))
            )
        except (ValueError, IndexError):
            metrics["roc_auc_ovr_macro"] = None

    # Feature importance (for one fold/seed only — averaged later)
    if hasattr(clf, "feature_importances_"):
        metrics["feature_importance"] = {
            col: float(imp)
            for col, imp in zip(X_train.columns, clf.feature_importances_)
        }

    return metrics


def main() -> None:
    """Smoke test: train RF on 20D dataset (single fold)."""
    from sklearn.model_selection import train_test_split

    from load_20d import load_20d_labeled, FEATURE_COLS_20D

    df = load_20d_labeled()
    X = df[FEATURE_COLS_20D]
    le = LabelEncoder()
    y = le.fit_transform(df["label"])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    print("Training Random Forest on 20D ...")
    metrics = evaluate_classifier(
        X_train, y_train, X_test, y_test,
        classifier_name="rf", seed=42, label_encoder=le,
    )

    print(f"\n  F1 (macro):     {metrics['f1_macro']:.4f}")
    print(f"  F1 (weighted):  {metrics['f1_weighted']:.4f}")
    print(f"  Precision:      {metrics['precision_macro']:.4f}")
    print(f"  Recall:         {metrics['recall_macro']:.4f}")
    print(f"  Accuracy:       {metrics['accuracy']:.4f}")
    if metrics.get("roc_auc_ovr_macro") is not None:
        print(f"  ROC-AUC:        {metrics['roc_auc_ovr_macro']:.4f}")
    print(f"  Train time:     {metrics['train_time_sec']:.2f}s")
    print(f"  Predict time:   {metrics['predict_time_ms_per_sample']:.4f} ms/sample")
    print(f"\n  Confusion matrix ({metrics['class_names']}):")
    for row in metrics["confusion_matrix"]:
        print(f"    {row}")


if __name__ == "__main__":
    main()
