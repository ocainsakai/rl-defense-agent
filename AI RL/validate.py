"""
Validate AI RL agent — Confusion Matrix từ actions.log + expected.json.

Hai cách dùng:

1. Từ actions.log (live validation — infer.py đã chạy):
   python3 validate.py --actions actions.log --expected expected.json

2. Từ training_data.jsonl (offline — AI predict trực tiếp):
   python3 validate.py --training_data training_data.jsonl --model policy_model

Output: Confusion matrix + Accuracy / Precision / Recall per class.

Format expected.json:
    {"10.0.0.1": "syn_flood", "10.0.0.2": "normal", ...}
    (mapping src_ip → ground-truth label)

Format actions.log (ghi bởi infer.py):
    {"timestamp": ..., "src_ip": "10.0.0.1", "action": "Block", ...}
"""

import argparse
import json
import os
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'System'))

# Action names và expected action per label
ACTION_NAMES = {0: 'Allow', 1: 'RateLimit', 2: 'Redirect', 3: 'Block'}
ACTION_IDS   = {v: k for k, v in ACTION_NAMES.items()}

# Ground-truth: label → expected action
LABEL_TO_ACTION = {
    'normal':       0,  # Allow
    'benign':       0,  # Allow
    'noisy_normal': 1,  # RateLimit
    'scan':         3,  # Block
    'syn_flood':    3,  # Block
    'brute_force':  2,  # Redirect
    'sqli_xss':     2,  # Redirect (legacy combined label)
    'sqli':         2,  # Redirect
    'xss':          2,  # Redirect
}

LABELS = ['normal', 'noisy_normal', 'scan', 'syn_flood', 'brute_force', 'sqli_xss']


# ============================================================================
# MODE 1: Validate từ actions.log + expected.json
# ============================================================================

def validate_from_logs(actions_log: str, expected_json: str):
    """So sánh actions.log với expected.json → confusion matrix."""
    with open(expected_json) as f:
        expected = json.load(f)  # {src_ip: label}

    records = []
    with open(actions_log) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                records.append(rec)
            except Exception:
                continue

    y_true, y_pred = [], []
    for rec in records:
        src_ip = rec.get('src_ip', '')
        if src_ip not in expected:
            continue
        label = expected[src_ip]
        if label not in LABEL_TO_ACTION:
            continue
        action_name = rec.get('action', rec.get('action_name', ''))
        if action_name not in ACTION_IDS:
            continue
        y_true.append(LABEL_TO_ACTION[label])
        y_pred.append(ACTION_IDS[action_name])

    if not y_true:
        print("[ERROR] Không có records phù hợp giữa actions.log và expected.json")
        return

    _print_confusion_matrix(y_true, y_pred, title="Validation từ actions.log")


# ============================================================================
# MODE 2: Validate trực tiếp từ training_data.jsonl + model predict
# ============================================================================

def validate_from_training_data(training_data: str, model_path: str):
    """Load training_data.jsonl, chạy model predict, so sánh với expected action.

    Supports:
      - legacy 20D models: direct normalized feature vector
      - 30D models: 20D normalized feature vector + legacy temporal state
      - 34D models: 20D normalized feature vector + persistence temporal state + effect_prev_4d
    """
    from stable_baselines3 import PPO
    from env_ids import normalize_observation, compute_network_damage
    from infer import InferenceTemporalState, PersistenceTemporalState

    print(f"[*] Loading model: {model_path}")
    model = PPO.load(model_path)
    obs_dim = int(np.prod(model.observation_space.shape))
    print(f"[*] Model observation dim: {obs_dim}")

    records = []
    with open(training_data) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if 'features' in rec and 'label' in rec:
                    records.append(rec)
            except Exception:
                continue

    if not records:
        print(f"[ERROR] Không có records hợp lệ trong {training_data}")
        return

    records.sort(key=lambda rec: (
        float(rec.get('window_ts', rec.get('timestamp', 0.0))),
        float(rec.get('timestamp', 0.0)),
        str(rec.get('src_ip', 'unknown')),
    ))
    print(f"[*] {len(records)} records loaded from {training_data}")

    y_true, y_pred = [], []
    label_unknown = []
    temporal_states = defaultdict(InferenceTemporalState)
    persistence_states = defaultdict(PersistenceTemporalState)
    for rec in records:
        label = rec.get('label', '')
        if label not in LABEL_TO_ACTION:
            label_unknown.append(label)
            continue
        features = rec['features']
        if len(features) != 20:
            continue

        obs_20 = normalize_observation(features)
        if obs_dim == 34:
            src_ip = str(rec.get('src_ip', 'unknown'))
            effect_prev = rec.get('effect_prev_4d') or [0.0, 0.0, 0.0, 0.0]
            pstate = persistence_states[src_ip]
            pstate.observe_effect(effect_prev)
            obs = np.concatenate([
                obs_20,
                np.array(pstate.to_obs(), dtype=np.float32),
                np.array(effect_prev[:4], dtype=np.float32),
            ])
        elif obs_dim == 30:
            src_ip = str(rec.get('src_ip', 'unknown'))
            tstate = temporal_states[src_ip]
            obs = np.concatenate([obs_20, np.array(tstate.to_obs(), dtype=np.float32)])
        elif obs_dim == 20:
            obs = obs_20
        else:
            print(f"[ERROR] Unsupported observation dim: {obs_dim}")
            return

        action, _ = model.predict(obs.reshape(1, -1), deterministic=True)
        action = int(np.asarray(action).reshape(-1)[0])
        if obs_dim == 34:
            persistence_states[src_ip].stage_action(action)
        elif obs_dim == 30:
            damage = compute_network_damage(features)
            temporal_states[src_ip].update(action, damage)
        y_true.append(LABEL_TO_ACTION[label])
        y_pred.append(action)

    if label_unknown:
        unknown_set = set(label_unknown)
        print(f"[WARN] Bỏ qua {len(label_unknown)} records với label không rõ: {unknown_set}")

    if not y_true:
        print("[ERROR] Không có records hợp lệ để validate")
        return

    _print_confusion_matrix(y_true, y_pred, title=f"Validation từ {training_data}")


# ============================================================================
# CONFUSION MATRIX + METRICS
# ============================================================================

def _print_confusion_matrix(y_true: list, y_pred: list, title: str = ""):
    n = 4  # 4 actions
    action_labels = ['Allow', 'RateLimit', 'Redirect', 'Block']

    cm = np.zeros((n, n), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t][p] += 1

    total = len(y_true)
    correct = sum(t == p for t, p in zip(y_true, y_pred))
    accuracy = correct / total if total > 0 else 0.0

    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)
    print(f"  Total samples : {total}")
    print(f"  Correct       : {correct}")
    print(f"  Accuracy      : {accuracy*100:.1f}%")
    print()

    # Confusion matrix
    header = f"{'Predicted →':>14}" + "".join(f"{a:>12}" for a in action_labels)
    print(header)
    print("-" * (14 + 12 * n))
    for i, row_label in enumerate(action_labels):
        row = f"{'True '+row_label+' →':>14}" + "".join(f"{cm[i][j]:>12}" for j in range(n))
        print(row)
    print()

    # Per-class Precision / Recall / F1
    print(f"  {'Action':<12} {'Precision':>10} {'Recall':>10} {'F1':>8} {'Support':>9}")
    print("  " + "-" * 50)
    for i, a in enumerate(action_labels):
        tp = cm[i][i]
        fp = cm[:, i].sum() - tp
        fn = cm[i, :].sum() - tp
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        sup  = cm[i, :].sum()
        print(f"  {a:<12} {prec*100:>9.1f}% {rec*100:>9.1f}% {f1*100:>7.1f}% {sup:>9}")

    print("=" * 60)

    # Highlight critical errors
    ben_blocked = cm[0][3]  # Allow expected, Block predicted (false positive)
    att_allowed  = cm[2][0] + cm[3][0]  # syn_flood/brute_force allowed (false negative)
    if ben_blocked > 0:
        print(f"  [WARN] Normal traffic bị Block: {ben_blocked} lần (False Positive)")
    if att_allowed > 0:
        print(f"  [WARN] Attack traffic bị Allow: {att_allowed} lần (False Negative)")
    print()


# ============================================================================
# CLI
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description='Validate AI RL agent — Confusion Matrix',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Offline validation từ training_data.jsonl
  python3 validate.py --training_data training_data.jsonl --model policy_model

  # Live validation từ actions.log
  python3 validate.py --actions actions.log --expected expected.json
        """
    )
    parser.add_argument('--training_data', type=str, default=None,
                        help='Path to training_data.jsonl (offline validation)')
    parser.add_argument('--model', type=str, default='policy_model',
                        help='Path to model .zip (default: policy_model)')
    parser.add_argument('--actions', type=str, default=None,
                        help='Path to actions.log (live validation)')
    parser.add_argument('--expected', type=str, default=None,
                        help='Path to expected.json {src_ip: label} (for --actions mode)')
    return parser.parse_args()


def main():
    args = parse_args()

    if args.training_data:
        if not os.path.exists(args.training_data):
            print(f"[ERROR] File not found: {args.training_data}")
            sys.exit(1)
        validate_from_training_data(args.training_data, args.model)

    elif args.actions:
        if not args.expected:
            print("[ERROR] --actions requires --expected <expected.json>")
            sys.exit(1)
        if not os.path.exists(args.actions):
            print(f"[ERROR] File not found: {args.actions}")
            sys.exit(1)
        if not os.path.exists(args.expected):
            print(f"[ERROR] File not found: {args.expected}")
            sys.exit(1)
        validate_from_logs(args.actions, args.expected)

    else:
        print("[ERROR] Cần --training_data hoặc --actions")
        print("  python3 validate.py --training_data training_data.jsonl --model policy_model")
        print("  python3 validate.py --actions actions.log --expected expected.json")
        sys.exit(1)


if __name__ == '__main__':
    main()
