"""
adapt_pipeline.py — Auto-labeling pipeline for collected NIDS data

Chuyển đổi output của `infer.py --collect` (label=null) sang training_data.jsonl
có nhãn để dùng với `train.py --mode replay`.

Cách hoạt động:
  --auto-label   : Dùng heuristic threshold từ feature values để gán nhãn tự động
  --action-map   : Admin chỉ định mapping ai_action → label thủ công

Usage:
  # Auto-label bằng heuristic:
  python3 adapt_pipeline.py \\
      --input /tmp/collect_$(date +%Y%m%d).jsonl \\
      --output training_data.jsonl \\
      --auto-label

  # Admin-guided: map Block→syn_flood, Redirect→brute_force:
  python3 adapt_pipeline.py \\
      --input /tmp/collect_$(date +%Y%m%d).jsonl \\
      --output training_data.jsonl \\
      --action-map Block=syn_flood Redirect=brute_force Allow=benign RateLimit=noisy_normal

  # Dry-run (không ghi file, chỉ in kết quả):
  python3 adapt_pipeline.py \\
      --input /tmp/collect_$(date +%Y%m%d).jsonl \\
      --auto-label --dry-run

  # Retrain sau khi có training_data.jsonl:
  python3 train.py \\
      --mode replay \\
      --training_data training_data.jsonl \\
      --resume_from runs/run_final_v4/best_model.zip \\
      --timesteps 50000
"""

import argparse
import json
import os
import sys
from collections import Counter

# ============================================================================
# Feature indices (theo NIDS_KEY_ORDER trong infer.py)
# ============================================================================
F1  = 0   # PacketRate       (packets/sec, raw)
F2  = 1   # SynAckRatio      (raw ratio)
F3  = 2   # InterArrivalTime (seconds)
F4  = 3   # RstRatio         (0–1)
F5  = 4   # DistinctPorts    (count, raw)
F6  = 5   # URLConcentration (0–1)
F7  = 6   # HttpIatUniformity (0–1)
F8  = 7   # RequestSizeUniformity (0–1)
F9  = 8   # AvgPayloadSize   (bytes)
F10 = 9   # FwdBwdRatio
F11 = 10  # PacketsPerPort
F12 = 11  # SqlSpecialChar
F13 = 12  # CrsSqliScore     (raw CRS score, max ~19)
F14 = 13  # SqlUnionSelect
F15 = 14  # SqlComment
F16 = 15  # SqlStackedQuery
F17 = 16  # SqlSelectCount
F18 = 17  # CrsXssScore      (raw CRS score, max ~4)
F19 = 18  # JsFunctionCall   (binary)
F20 = 19  # HtmlEventHandler (binary)

VALID_LABELS = {
    'benign', 'noisy_normal', 'scan', 'syn_flood',
    'brute_force', 'brute_force_ka',
    'sqli', 'xss', 'sqli_xss',
    'normal',
}

# ============================================================================
# Heuristic rules (thứ tự ưu tiên từ rõ ràng nhất đến mơ hồ nhất)
# Threshold dựa trên base_state của MockIPBehavior trong env_ids_harder.py
# ============================================================================

def _auto_label(features: list) -> tuple[str, float]:
    """Gán nhãn tự động từ raw feature vector (20D).

    Returns:
        (label, confidence)  confidence ∈ [0.0, 1.0]
    """
    if len(features) != 20:
        return 'noisy_normal', 0.0

    f1  = features[F1]   # PacketRate
    f2  = features[F2]   # SynAckRatio
    f4  = features[F4]   # RstRatio
    f5  = features[F5]   # DistinctPorts
    f6  = features[F6]   # URLConcentration
    f13 = features[F13]  # CrsSqliScore
    f18 = features[F18]  # CrsXssScore

    # Rule 1: SQLi / XSS — ưu tiên cao nhất vì có payload signature khá rõ
    if f13 > 0.5 and f18 > 0.5:
        conf = min(1.0, (f13 + f18) / 4.0)
        return 'sqli_xss', round(conf, 3)
    if f18 > 0.5:
        conf = min(1.0, f18 / 3.0)
        return 'xss', round(conf, 3)
    if f13 > 0.5:
        conf = min(1.0, f13 / 8.0)
        return 'sqli', round(conf, 3)

    # Rule 2: SYN Flood — SynAckRatio cao bất thường
    if f2 > 5.0:
        conf = min(1.0, f2 / 20.0)
        return 'syn_flood', round(conf, 3)

    # Rule 3: Port Scan — nhiều port phân biệt + RST cao
    if f5 > 50 and f4 > 0.2:
        conf = min(1.0, (f5 / 200.0 + f4 / 0.5) / 2.0)
        return 'scan', round(conf, 3)

    # Rule 4: Brute Force — tập trung URL + packet rate vừa cao
    if f6 > 0.90 and features[F7] > 0.70:
        conf = min(1.0, (f6 + features[F7]) / 2.0)
        return 'brute_force_ka', round(conf, 3)
    if f6 > 0.75 and f1 > 30:
        conf = min(1.0, (f6 + min(f1, 200) / 200.0) / 2.0)
        return 'brute_force', round(conf, 3)

    # Rule 5: Benign — tất cả indicator thấp, rate thấp
    if f1 < 15 and f2 < 0.5 and f6 < 0.3:
        conf = min(1.0, 1.0 - f1 / 30.0)
        return 'benign', round(conf, 3)

    # Fallback: không chắc chắn → noisy_normal (conservative)
    return 'noisy_normal', 0.5


def parse_action_map(action_map_args: list) -> dict:
    """Parse --action-map Block=syn_flood Redirect=brute_force ... → dict."""
    result = {}
    for item in action_map_args:
        if '=' not in item:
            print(f"[WARN] Bỏ qua --action-map entry không hợp lệ: {item!r}", file=sys.stderr)
            continue
        action, label = item.split('=', 1)
        action = action.strip()
        label = label.strip()
        if label not in VALID_LABELS:
            print(f"[WARN] Label không hợp lệ: {label!r} (bỏ qua)", file=sys.stderr)
            continue
        result[action] = label
    return result


def process(input_file: str, output_file: str,
            auto_label: bool, action_map: dict,
            min_confidence: float, dry_run: bool) -> None:

    if not os.path.exists(input_file):
        print(f"[ERROR] File không tồn tại: {input_file}", file=sys.stderr)
        sys.exit(1)

    stats = Counter()
    written = []

    with open(input_file, 'r') as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[WARN] Dòng {lineno}: JSON lỗi ({e}) — bỏ qua")
                stats['skip_json_error'] += 1
                continue

            features = rec.get('features')
            if not features or len(features) != 20:
                stats['skip_bad_features'] += 1
                continue

            ts  = rec.get('timestamp', 0.0)
            src = rec.get('src_ip', 'unknown')

            # -----------------------------------------------------------------
            # Gán nhãn
            # -----------------------------------------------------------------
            if auto_label:
                label, confidence = _auto_label(features)
            elif action_map:
                ai_action = rec.get('ai_action', '')
                label = action_map.get(ai_action)
                if label is None:
                    stats['skip_no_mapping'] += 1
                    continue
                confidence = 0.8  # admin-guided → tin cậy cao hơn
            else:
                print("[ERROR] Cần --auto-label hoặc --action-map", file=sys.stderr)
                sys.exit(1)

            if confidence < min_confidence:
                stats[f'skip_low_conf_{label}'] += 1
                continue

            train_record = {
                'timestamp': ts,
                'window_ts': rec.get('window_ts', ts),
                'src_ip':    src,
                'label':     label,
                'final_action': rec.get('final_action'),
                'features':  features,
                'effect_source': rec.get('effect_source'),
                'effect_prev_4d': rec.get('effect_prev_4d'),
                'effect_4d': rec.get('effect_4d'),
            }
            written.append((label, confidence, train_record))
            stats[f'label_{label}'] += 1

    # -------------------------------------------------------------------------
    # Ghi output
    # -------------------------------------------------------------------------
    if not dry_run and written:
        with open(output_file, 'a') as f:
            for _, _, rec in written:
                f.write(json.dumps(rec) + '\n')
        print(f"[+] Ghi {len(written)} records → {output_file} (append mode)")
    elif dry_run:
        print(f"[DRY-RUN] Sẽ ghi {len(written)} records → {output_file}")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print()
    print("=" * 52)
    print("  ADAPT PIPELINE — KẾT QUẢ")
    print("=" * 52)
    total_in = sum(stats.values())
    label_counts = {k.replace('label_', ''): v for k, v in stats.items() if k.startswith('label_')}
    skip_counts  = {k: v for k, v in stats.items() if k.startswith('skip_')}

    print(f"  Input:   {input_file}")
    print(f"  Output:  {output_file}{'  [DRY-RUN, không ghi]' if dry_run else ''}")
    print(f"  Records đã xử lý: {total_in}")
    print(f"  Records hợp lệ:   {len(written)}")
    print()

    if label_counts:
        print("  Phân phối nhãn:")
        for label in sorted(label_counts):
            count = label_counts[label]
            pct = count / len(written) * 100 if written else 0
            bar = '█' * int(pct / 5)
            print(f"    {label:15s} {count:4d}  ({pct:5.1f}%)  {bar}")

    if skip_counts:
        print()
        print("  Bị bỏ qua:")
        for reason, count in skip_counts.items():
            print(f"    {reason}: {count}")

    print()
    if written and not dry_run:
        print("  [Bước tiếp theo] Retrain với data thật:")
        print(f"    python3 train.py \\")
        print(f"        --mode replay \\")
        print(f"        --training_data {output_file} \\")
        print(f"        --resume_from runs/run_final_v4/best_model.zip \\")
        print(f"        --timesteps 50000")
    print("=" * 52)


def main():
    parser = argparse.ArgumentParser(
        description="Auto-labeling pipeline: collect JSONL → training_data.jsonl"
    )
    parser.add_argument('--input',  required=True,
                        help='Input: collect JSONL từ infer.py --collect')
    parser.add_argument('--output', default='training_data.jsonl',
                        help='Output: training_data.jsonl (append mode, default: training_data.jsonl)')
    parser.add_argument('--auto-label', action='store_true',
                        help='Dùng heuristic feature threshold để gán nhãn tự động')
    parser.add_argument('--action-map', nargs='+', metavar='ACTION=LABEL',
                        help='Admin mapping: Block=syn_flood Redirect=brute_force ...')
    parser.add_argument('--min-confidence', type=float, default=0.4,
                        help='Bỏ qua sample có confidence < threshold (default: 0.4)')
    parser.add_argument('--dry-run', action='store_true',
                        help='In kết quả dự đoán, không ghi file')

    args = parser.parse_args()

    if not args.auto_label and not args.action_map:
        parser.error("Cần ít nhất --auto-label hoặc --action-map")

    action_map = parse_action_map(args.action_map) if args.action_map else {}

    process(
        input_file=args.input,
        output_file=args.output,
        auto_label=args.auto_label,
        action_map=action_map,
        min_confidence=args.min_confidence,
        dry_run=args.dry_run,
    )


if __name__ == '__main__':
    main()
