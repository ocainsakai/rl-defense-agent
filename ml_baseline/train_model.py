"""
train_model.py — Ngày 1-2
Train Random Forest trên eval_data.jsonl (20D features từ RL Env).

Hai chế độ:
  1. --data eval_data.jsonl   ← KHUYÊN DÙNG (same feature space với RL)
  2. --data CICIDS2017.csv    ← backup nếu không sinh được JSONL

Usage:
    cd /home/tringuyen/AIAGENT/rl-defense-agent
    python ml_baseline/train_model.py
    python ml_baseline/train_model.py --data ml_baseline/data/eval_data.jsonl
"""

import argparse
import os
import sys
import json

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

RANDOM_SEED = 42
TEST_RATIO  = 0.2

# -------------------------------------------------------
# CICIDS2017 fallback features (nếu dùng CSV)
# -------------------------------------------------------
CICIDS_FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s',
    'Fwd Packet Length Max', 'Bwd Packet Length Max',
    'Flow IAT Mean', 'Flow IAT Std',
    'Fwd PSH Flags', 'SYN Flag Count', 'RST Flag Count',
    'Packet Length Mean', 'Packet Length Std',
    'Average Packet Size', 'Avg Fwd Segment Size',
]

SUSPICIOUS_LABELS_CICIDS = {
    'PORTSCAN', 'FTP-PATATOR', 'SSH-PATATOR',
    'INFILTRATION', 'BOT', 'HEARTBLEED',
}

def simplify_cicids_label(label: str) -> str:
    label = label.strip().upper()
    if label == 'BENIGN':
        return 'benign'
    elif label in SUSPICIOUS_LABELS_CICIDS:
        return 'suspicious'
    else:
        return 'attack'


# -------------------------------------------------------
# Load JSONL (từ generate_eval_data.py)
# -------------------------------------------------------
def load_jsonl(path: str):
    print(f"[*] Loading JSONL: {path}")
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    X = np.array([r['obs'] for r in records], dtype=float)
    y = np.array([r['label_3class'] for r in records])

    print(f"    {len(records):,} records, obs dim = {X.shape[1]}")
    from collections import Counter
    print(f"    Label dist: {dict(Counter(y))}")
    return X, y, [f'F{i+1}' for i in range(X.shape[1])]


# -------------------------------------------------------
# Load CSV (CICIDS2017 fallback)
# -------------------------------------------------------
def load_csv(path: str):
    print(f"[*] Loading CSV: {path}")
    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()

    available = [f for f in CICIDS_FEATURES if f in df.columns]
    missing   = [f for f in CICIDS_FEATURES if f not in df.columns]
    if missing:
        print(f"    [WARN] Thiếu {len(missing)} columns: {missing[:5]}...")
    print(f"    Sử dụng {len(available)} features")

    df['label_3class'] = df['Label'].apply(simplify_cicids_label)
    df[available] = df[available].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=available)
    print(f"    {len(df):,} rows sau dropna")
    print(f"    Label dist: {dict(df['label_3class'].value_counts())}")

    return df[available].values, df['label_3class'].values, available


# -------------------------------------------------------
# MAIN
# -------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data',    default='ml_baseline/data/eval_data.jsonl',
                        help='Path tới eval_data.jsonl hoặc CICIDS2017 CSV')
    parser.add_argument('--out_dir', default='ml_baseline',
                        help='Thư mục lưu model')
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    if not os.path.exists(args.data):
        print(f"[ERROR] Không tìm thấy: {args.data}")
        print("Hãy chạy trước: python ml_baseline/generate_eval_data.py")
        sys.exit(1)

    # Load
    if args.data.endswith('.jsonl'):
        X, y, feature_names = load_jsonl(args.data)
    else:
        X, y, feature_names = load_csv(args.data)

    print(f"\n[*] Scaling & splitting (episode-based, no leakage)...")
    scaler = StandardScaler()

    if args.data.endswith('.jsonl'):
        # Split theo episode: train ep 0–79%, test ep 80–100%
        # Đảm bảo RF không thấy bất kỳ obs nào từ test episodes
        import json as _json
        all_records = [_json.loads(l) for l in open(args.data)]
        max_ep = max(r['episode'] for r in all_records)
        split_ep = int(max_ep * 0.8)
        train_idx = [i for i, r in enumerate(all_records) if r['episode'] <  split_ep]
        test_idx  = [i for i, r in enumerate(all_records) if r['episode'] >= split_ep]
        X_train_raw = X[train_idx]
        X_test_raw  = X[test_idx]
        y_train = y[train_idx]
        y_test  = y[test_idx]
        print(f"    Episode split: train ep 0–{split_ep-1}, test ep {split_ep}–{max_ep}")
    else:
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X, y, test_size=TEST_RATIO, random_state=RANDOM_SEED, stratify=y,
        )

    # Fit scaler CHỈ trên train → không leak test distribution
    X_train = scaler.fit_transform(X_train_raw)
    X_test  = scaler.transform(X_test_raw)
    print(f"    Train: {len(X_train):,} | Test: {len(X_test):,}")

    print(f"\n[*] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        n_jobs=-1,
        random_state=RANDOM_SEED,
        class_weight='balanced',
    )
    model.fit(X_train, y_train)
    print("    Done.")

    print(f"\n[*] Evaluating on test set...")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
    print("Confusion Matrix (rows=true, cols=pred):")
    print(confusion_matrix(y_test, y_pred, labels=model.classes_))

    # Feature importance
    fi = pd.Series(model.feature_importances_, index=feature_names)
    print(f"\nTop 10 Feature Importances:")
    print(fi.sort_values(ascending=False).head(10).to_string())

    # Save
    model_path   = os.path.join(args.out_dir, 'rf_baseline.pkl')
    scaler_path  = os.path.join(args.out_dir, 'scaler.pkl')
    feature_path = os.path.join(args.out_dir, 'feature_list.pkl')
    test_path    = os.path.join(args.out_dir, 'test_split.pkl')

    joblib.dump(model,         model_path)
    joblib.dump(scaler,        scaler_path)
    joblib.dump(feature_names, feature_path)
    joblib.dump({'X_test': X_test, 'y_test': y_test}, test_path)

    print(f"\n[OK] Saved:")
    print(f"     {model_path}")
    print(f"     {scaler_path}")
    print(f"     {feature_path}")
    print(f"     {test_path}")
    print(f"\nBước tiếp theo:")
    print(f"  python ml_baseline/run_benchmark.py --data ml_baseline/data/eval_data.jsonl")


if __name__ == '__main__':
    main()
