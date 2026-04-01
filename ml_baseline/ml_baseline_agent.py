"""
ml_baseline_agent.py — Ngày 3
Decision engine: feature → model → label → action
"""

import numpy as np
import joblib
import time
from typing import Optional


# -------------------------------------------------------
# MAPPING: label + confidence → action
# -------------------------------------------------------
def map_to_action(label: str, confidence: float,
                  high_conf_threshold: float = 0.75) -> str:
    """
    label       : 'benign' | 'suspicious' | 'attack'
    confidence  : xác suất của predicted class [0, 1]
    returns     : 'allow' | 'block' | 'rate-limit' | 'redirect'

    Logic:
        benign                          → allow
        attack                          → block
        suspicious + conf >= threshold  → rate-limit  (khá chắc là nguy hiểm)
        suspicious + conf <  threshold  → redirect    (không chắc, cần phân tích thêm)
    """
    if label == 'benign':
        return 'allow'
    elif label == 'attack':
        return 'block'
    elif label == 'suspicious':
        if confidence >= high_conf_threshold:
            return 'rate-limit'
        else:
            return 'redirect'
    return 'allow'  # fallback


# -------------------------------------------------------
# AGENT CLASS
# -------------------------------------------------------
class MLBaselineAgent:
    """
    Wrapper bọc RF model thành interface giống RL agent.
    Dùng cho benchmark so sánh với PPO agent.
    """

    ACTIONS = ['allow', 'block', 'rate-limit', 'redirect']

    def __init__(self,
                 model_path: str = 'rf_baseline.pkl',
                 scaler_path: str = 'scaler.pkl',
                 feature_list_path: str = 'feature_list.pkl',
                 high_conf_threshold: float = 0.75):

        self.model     = joblib.load(model_path)
        self.scaler    = joblib.load(scaler_path)
        self.features  = joblib.load(feature_list_path)
        self.threshold = high_conf_threshold

        # Tracking
        self.action_counts  = {a: 0 for a in self.ACTIONS}
        self.decisions      = []
        self.response_times = []

    # --------------------------------------------------
    def decide(self, raw_features: list) -> dict:
        """
        Input : raw feature vector (list hoặc np.array)
        Output: dict {label, confidence, action, proba, response_time_ms}
        """
        t0 = time.perf_counter()

        x = np.array(raw_features, dtype=float).reshape(1, -1)
        x_scaled = self.scaler.transform(x)

        proba = self.model.predict_proba(x_scaled)[0]
        class_idx  = proba.argmax()
        label      = self.model.classes_[class_idx]
        confidence = float(proba[class_idx])

        action = map_to_action(label, confidence, self.threshold)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        self.action_counts[action] += 1
        self.response_times.append(elapsed_ms)

        record = {
            'label'          : label,
            'confidence'     : confidence,
            'action'         : action,
            'proba'          : dict(zip(self.model.classes_, proba.tolist())),
            'response_time_ms': elapsed_ms,
        }
        self.decisions.append(record)
        return record

    # --------------------------------------------------
    def reset_stats(self):
        self.action_counts  = {a: 0 for a in self.ACTIONS}
        self.decisions      = []
        self.response_times = []

    # --------------------------------------------------
    def get_stats(self) -> dict:
        total = sum(self.action_counts.values()) or 1
        return {
            'action_counts'   : self.action_counts,
            'total_decisions' : total,
            'allow_rate'      : self.action_counts['allow']      / total,
            'block_rate'      : self.action_counts['block']      / total,
            'rate_limit_rate' : self.action_counts['rate-limit'] / total,
            'redirect_rate'   : self.action_counts['redirect']   / total,
            'avg_response_ms' : float(np.mean(self.response_times)) if self.response_times else 0.0,
        }

    # --------------------------------------------------
    def __repr__(self):
        return (f"MLBaselineAgent(model={type(self.model).__name__}, "
                f"threshold={self.threshold}, "
                f"features={len(self.features)})")
