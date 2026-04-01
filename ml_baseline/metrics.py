"""
metrics.py
Tất cả công thức benchmark: Detection / System / Redirect
"""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    confusion_matrix, classification_report,
)
from typing import Dict, List


# -------------------------------------------------------
# (A) DETECTION METRICS
# -------------------------------------------------------
def detection_metrics(y_true: List[str], y_pred: List[str]) -> Dict:
    """
    Accuracy, Precision, Recall, F1 (weighted)
    y_true / y_pred: list các label 'benign'|'suspicious'|'attack'
    """
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average='weighted', zero_division=0
    )
    return {
        'accuracy' : round(acc, 4),
        'precision': round(p,   4),
        'recall'   : round(r,   4),
        'f1_score' : round(f1,  4),
    }


# -------------------------------------------------------
# (B) SYSTEM / DECISION METRICS
# -------------------------------------------------------
# Trọng số chi phí false positive theo từng action
FP_WEIGHTS = {
    'block'    : 2.0,   # block benign = tệ nhất
    'rate-limit': 1.0,  # rate-limit benign = trung bình
    'redirect' : 0.5,   # redirect benign = nhẹ nhất (chỉ delay)
    'allow'    : 0.0,   # allow benign = đúng, không penalty
}

def system_metrics(results_df: pd.DataFrame) -> Dict:
    """
    results_df cần có columns: true_label, action

    Attack Mitigation Rate  = (attack bị block/rate-limit/redirect) / tổng attack+suspicious
                              redirect cũng là mitigation vì traffic bị chuyển sang honeypot
    False Positive Cost     = weighted FP / tổng benign
    Action Efficiency       = action khớp expected_action / tổng (nếu có cột expected_action)
                              hoặc action hợp lệ theo label / tổng
    """
    attacks    = results_df[results_df['true_label'] == 'attack']
    suspicious = results_df[results_df['true_label'] == 'suspicious']
    threats    = results_df[results_df['true_label'].isin(['attack', 'suspicious'])]
    benign     = results_df[results_df['true_label'] == 'benign']

    # Attack Mitigation Rate — block + rate-limit + redirect đều tính là mitigated
    # (redirect → honeypot = soft mitigation; block = hard mitigation)
    mitigated = threats[threats['action'].isin(['block', 'rate-limit', 'redirect'])]
    mitigation_rate = len(mitigated) / max(len(threats), 1)

    # False Positive Cost
    fp_rows  = benign[benign['action'] != 'allow']
    fp_cost  = sum(FP_WEIGHTS[row['action']] for _, row in fp_rows.iterrows())
    fp_cost_normalized = fp_cost / max(len(benign), 1)

    # Action Efficiency — dùng expected_action nếu có, fallback về label mapping
    if 'expected_action' in results_df.columns:
        correct = results_df['action'] == results_df['expected_action']
    else:
        correct = results_df.apply(
            lambda r: _correct_action(r['true_label'], r['action']), axis=1
        )
    action_efficiency = correct.mean()

    return {
        'mitigation_rate'  : round(mitigation_rate,    4),
        'fp_cost'          : round(fp_cost_normalized, 4),
        'action_efficiency': round(action_efficiency,  4),
    }


def _correct_action(true_label: str, action: str) -> bool:
    expected = {
        'benign'    : {'allow'},
        'suspicious': {'rate-limit', 'redirect'},
        'attack'    : {'block'},
    }
    return action in expected.get(true_label, set())


# -------------------------------------------------------
# (C) REDIRECT METRICS
# -------------------------------------------------------
def redirect_metrics(results_df: pd.DataFrame) -> Dict:
    """
    Redirect Usage Rate    = redirected / tổng traffic
    Redirect Effectiveness = redirect đúng (suspicious/attack) / tổng redirect
    Redirect FP Reduction  = suspicious được redirect thay vì block nhầm / tổng suspicious
    """
    total      = max(len(results_df), 1)
    suspicious = results_df[results_df['true_label'] == 'suspicious']
    redirected = results_df[results_df['action'] == 'redirect']

    redirect_usage_rate = len(redirected) / total

    # Redirect đúng mục tiêu (không phải benign bị redirect nhầm)
    correct_redirects   = redirected[redirected['true_label'].isin(['suspicious', 'attack'])]
    redirect_effectiveness = len(correct_redirects) / max(len(redirected), 1)

    # Suspicious được redirect thay vì block nhầm
    suspicious_redirected  = suspicious[suspicious['action'] == 'redirect']
    redirect_fp_reduction  = len(suspicious_redirected) / max(len(suspicious), 1)

    return {
        'redirect_usage_rate'   : round(redirect_usage_rate,    4),
        'redirect_effectiveness': round(redirect_effectiveness, 4),
        'redirect_fp_reduction' : round(redirect_fp_reduction,  4),
    }


# -------------------------------------------------------
# FULL REPORT
# -------------------------------------------------------
def full_report(results_df: pd.DataFrame, avg_response_ms: float = 0.0) -> Dict:
    """
    Tổng hợp tất cả metrics vào một dict.
    results_df: true_label, predicted_label, action
    """
    det  = detection_metrics(results_df['true_label'], results_df['predicted_label'])
    sys_ = system_metrics(results_df)
    red  = redirect_metrics(results_df)

    report = {
        **det,
        **sys_,
        **red,
        'avg_response_ms': round(avg_response_ms, 3),
    }

    print("\n" + "=" * 55)
    print("  BENCHMARK REPORT")
    print("=" * 55)
    groups = [
        ("DETECTION",  ['accuracy', 'precision', 'recall', 'f1_score']),
        ("SYSTEM",     ['mitigation_rate', 'fp_cost', 'action_efficiency', 'avg_response_ms']),
        ("REDIRECT",   ['redirect_usage_rate', 'redirect_effectiveness', 'redirect_fp_reduction']),
    ]
    for group_name, keys in groups:
        print(f"\n  [{group_name}]")
        for k in keys:
            print(f"    {k:<28} {report.get(k, 'N/A')}")
    print("=" * 55)

    return report
