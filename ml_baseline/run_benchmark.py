"""
run_benchmark.py — Ngày 4-5
Chạy cả RL Agent và ML Baseline trên cùng eval_data.jsonl.
Xuất CSV + JSON để visualize.py vẽ biểu đồ.

Usage:
    cd /home/tringuyen/AIAGENT/rl-defense-agent
    python ml_baseline/run_benchmark.py
    python ml_baseline/run_benchmark.py --data ml_baseline/data/eval_data.jsonl --scenario 1
"""

import argparse
import json
import os
import sys
import time

import numpy as np
import pandas as pd
import joblib

# Import ML agent và metrics
sys.path.insert(0, os.path.dirname(__file__))
from ml_baseline_agent import MLBaselineAgent
from metrics import full_report

# Import RL
RL_DIR = os.path.join(os.path.dirname(__file__), '..', 'AI RL')
SYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'System')
sys.path.insert(0, RL_DIR)
sys.path.insert(0, SYS_DIR)


# Action mapping dùng chung
ACTION_NAMES = {0: 'Allow', 1: 'RateLimit', 2: 'Redirect', 3: 'Block'}

def _rl_action_to_label(action: str) -> str:
    """Suy ngược label từ action của RL để tính detection metrics."""
    return {
        'allow'    : 'benign',
        'block'    : 'attack',
        'rate-limit': 'suspicious',
        'redirect' : 'suspicious',
    }.get(action, 'benign')

# expected_action → action category cho metrics
def normalize_action(action_str: str) -> str:
    """Chuẩn hóa tên action về lowercase để so sánh."""
    mapping = {
        'Allow'    : 'allow',
        'RateLimit': 'rate-limit',
        'Redirect' : 'redirect',
        'Block'    : 'block',
    }
    return mapping.get(action_str, action_str.lower())


# -------------------------------------------------------
# Load eval data
# -------------------------------------------------------
def load_eval_data(path: str, n_samples: int = None, scenario: int = 1) -> list:
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    # Scenario filter
    if scenario == 1:
        # Chỉ lấy benign + attack thuần (không có suspicious) → attack cố định
        records = [r for r in records
                   if r['label_3class'] in ('benign', 'attack')]
    # scenario 2: giữ nguyên toàn bộ

    # Chỉ dùng TEST episodes (ep >= 400) để tránh data leakage với ML
    max_ep = max(r['episode'] for r in records)
    split_ep = int(max_ep * 0.8)
    records = [r for r in records if r['episode'] >= split_ep]
    print(f"    Using test episodes ({split_ep}–{max_ep}): {len(records)} records")

    if n_samples:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(records), size=min(n_samples, len(records)), replace=False)
        records = [records[i] for i in sorted(idx)]

    print(f"    Loaded {len(records):,} records (scenario {scenario})")
    from collections import Counter
    dist = Counter(r['label_3class'] for r in records)
    print(f"    Label dist: {dict(dist)}")
    return records


# -------------------------------------------------------
# Run ML Agent
# -------------------------------------------------------
def run_ml(records: list, agent: MLBaselineAgent) -> pd.DataFrame:
    rows = []
    for rec in records:
        obs = rec['obs']
        true_label = rec['label_3class']
        expected_action = normalize_action(rec['expected_action'])

        decision = agent.decide(obs)
        predicted_action = normalize_action(decision['action'])

        rows.append({
            'true_label'      : true_label,
            'predicted_label' : decision['label'],
            'confidence'      : decision['confidence'],
            'action'          : predicted_action,
            'expected_action' : expected_action,
            'response_time_ms': decision['response_time_ms'],
        })

    return pd.DataFrame(rows)


# -------------------------------------------------------
# Run RL Agent
# -------------------------------------------------------
def run_rl(records: list, model_path: str) -> pd.DataFrame:
    try:
        from stable_baselines3 import PPO
        from env_ids import normalize_observation
    except ImportError as e:
        print(f"[WARN] Không load được RL: {e}")
        return pd.DataFrame()

    print(f"    Loading RL model: {model_path}")
    model = PPO.load(model_path)

    rows = []
    for rec in records:
        obs = np.array(rec['obs'], dtype=np.float32)
        true_label = rec['label_3class']
        expected_action = normalize_action(rec['expected_action'])

        t0 = time.perf_counter()
        action_id, _ = model.predict(obs, deterministic=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        rl_action = normalize_action(ACTION_NAMES[int(action_id)])

        rows.append({
            'true_label'      : true_label,
            # RL không predict label — dùng action match để tính "accuracy"
            # predicted_label = 'benign' nếu action=allow, 'attack' nếu block, 'suspicious' nếu redirect/rate-limit
            'predicted_label' : _rl_action_to_label(rl_action),
            'action'          : rl_action,
            'expected_action' : expected_action,
            'response_time_ms': elapsed_ms,
        })

    return pd.DataFrame(rows)


# -------------------------------------------------------
# MAIN
# -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data',      default='ml_baseline/data/eval_data.jsonl')
    parser.add_argument('--ml_dir',    default='ml_baseline',
                        help='Thư mục chứa rf_baseline.pkl, scaler.pkl')
    parser.add_argument('--rl_model',  default='AI RL/policy_model',
                        help='Path tới PPO model (không cần .zip)')
    parser.add_argument('--threshold', type=float, default=0.75)
    parser.add_argument('--n_samples', type=int,   default=2000)
    parser.add_argument('--scenario',  type=int,   default=1, choices=[1, 2])
    parser.add_argument('--out_dir',   default='ml_baseline')
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    suffix = f"_s{args.scenario}"

    print(f"\n{'='*55}")
    print(f"  BENCHMARK — Scenario {args.scenario}")
    print(f"{'='*55}")

    # Load data
    print(f"\n[1] Loading eval data...")
    if not os.path.exists(args.data):
        print(f"[ERROR] {args.data} không tồn tại.")
        print("Chạy trước: python ml_baseline/generate_eval_data.py")
        sys.exit(1)

    records = load_eval_data(args.data, args.n_samples, args.scenario)

    # ── ML ──────────────────────────────────────────────
    print(f"\n[2] Running ML Baseline (Random Forest)...")
    ml_model_path   = os.path.join(args.ml_dir, 'rf_baseline.pkl')
    ml_scaler_path  = os.path.join(args.ml_dir, 'scaler.pkl')
    ml_feature_path = os.path.join(args.ml_dir, 'feature_list.pkl')

    if not os.path.exists(ml_model_path):
        print(f"[ERROR] {ml_model_path} không tồn tại.")
        print("Chạy trước: python ml_baseline/train_model.py")
        sys.exit(1)

    ml_agent = MLBaselineAgent(
        model_path=ml_model_path,
        scaler_path=ml_scaler_path,
        feature_list_path=ml_feature_path,
        high_conf_threshold=args.threshold,
    )
    ml_results = run_ml(records, ml_agent)
    ml_stats   = ml_agent.get_stats()

    print(f"\n  ML Results:")
    ml_report = full_report(ml_results, avg_response_ms=ml_stats['avg_response_ms'])

    # ── RL ──────────────────────────────────────────────
    print(f"\n[3] Running RL Agent (PPO)...")
    rl_model_path = args.rl_model
    if not os.path.exists(rl_model_path + '.zip') and not os.path.exists(rl_model_path):
        print(f"[WARN] RL model không tìm thấy tại: {rl_model_path}")
        print("       Bỏ qua RL benchmark, chỉ có ML results.")
        rl_report = None
    else:
        rl_results = run_rl(records, rl_model_path)
        if not rl_results.empty:
            rl_avg_rt = rl_results['response_time_ms'].mean()
            print(f"\n  RL Results:")
            rl_report = full_report(rl_results, avg_response_ms=rl_avg_rt)
        else:
            rl_report = None

    # ── So sánh ─────────────────────────────────────────
    if rl_report:
        print(f"\n{'='*55}")
        print(f"  COMPARISON — Scenario {args.scenario}")
        print(f"{'='*55}")
        print(f"  {'Metric':<28} {'ML':>8} {'RL':>8} {'Winner':>8}")
        print(f"  {'-'*52}")
        lower_is_better = {'fp_cost', 'avg_response_ms'}
        for k in ['accuracy', 'f1_score', 'mitigation_rate', 'fp_cost',
                  'action_efficiency', 'avg_response_ms',
                  'redirect_effectiveness', 'redirect_fp_reduction']:
            ml_v = ml_report.get(k, 0)
            rl_v = rl_report.get(k, 0)
            if k in lower_is_better:
                winner = 'ML' if ml_v < rl_v else 'RL'
            else:
                winner = 'ML' if ml_v > rl_v else 'RL'
            print(f"  {k:<28} {ml_v:>8.4f} {rl_v:>8.4f} {winner:>8}")

    # ── Save ────────────────────────────────────────────
    ml_csv  = os.path.join(args.out_dir, f'ml_results{suffix}.csv')
    ml_json = os.path.join(args.out_dir, f'ml_summary{suffix}.json')
    ml_results.to_csv(ml_csv, index=False)
    with open(ml_json, 'w') as f:
        json.dump(ml_report, f, indent=2)

    print(f"\n[OK] Saved: {ml_csv}")
    print(f"[OK] Saved: {ml_json}")

    if rl_report:
        rl_json = os.path.join(args.out_dir, f'rl_summary{suffix}.json')
        with open(rl_json, 'w') as f:
            json.dump(rl_report, f, indent=2)
        print(f"[OK] Saved: {rl_json}")
        print(f"\nBước tiếp theo:")
        print(f"  python ml_baseline/visualize.py "
              f"--ml_json {ml_json} --rl_json {rl_json}")


if __name__ == '__main__':
    main()
