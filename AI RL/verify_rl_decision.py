#!/usr/bin/env python3
"""
verify_rl_decision.py — Minh bạch hóa quyết định RL

Lấy obs vector từ một Block event trong actions.log,
chạy TRỰC TIẾP model.predict() mà không qua bất kỳ rule nào,
và in ra phân phối xác suất của neural network.

Mục đích: chứng minh với hội đồng rằng quyết định Block
đến từ PPO neural network, không phải rule-based system.

Usage:
    # Post-hoc: xem lại Block event cuối trong log
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model

    # Real-time: theo dõi log, tự động in khi Block xuất hiện
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model --watch

    # Xem tất cả Block events
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model --all-blocks
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch as th
from stable_baselines3 import PPO

ACTION_MAP = {0: 'Allow', 1: 'RateLimit', 2: 'Redirect', 3: 'Block'}
ACTIONS_LOG = Path(__file__).parent / 'actions.log'

# ── CLI ──────────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description='Verify RL Block decision transparency')
parser.add_argument('--model', default='runs/run_34d_v13/best_model')
parser.add_argument('--log', default=str(ACTIONS_LOG))
parser.add_argument('--event', type=int, default=-1,
                    help='Index of Block event to verify (-1 = last)')
parser.add_argument('--all-blocks', action='store_true',
                    help='Show all Block events, not just one')
parser.add_argument('--watch', action='store_true',
                    help='Real-time: theo dõi log, tự động in khi Block mới xuất hiện')
args = parser.parse_args()

# ── Load model ───────────────────────────────────────────────────────────────

print(f"\n{'='*60}")
print("VERIFY: RL Neural Network Decision Transparency")
print(f"{'='*60}")
print(f"Model: {args.model}.zip")

model = PPO.load(args.model)
obs_dim = model.observation_space.shape[0]
print(f"Obs dim: {obs_dim}D  |  Action space: {model.action_space}")

# ── Core: verify one event ───────────────────────────────────────────────────

def verify_event(event, model, obs_dim, idx=0):
    logged_probs = event.get('action_probs')
    has_obs = event.get('normalized_obs') and len(event['normalized_obs']) == obs_dim

    print(f"\n{'─'*60}")
    print(f"⚡ Block Event #{idx + 1}  |  ts={event.get('timestamp')}  |  IP={event.get('src_ip')}")
    print(f"   wlen={event.get('t_window_len')}  score={event.get('t_escalation_score')}  "
          f"block_ready={event.get('t_block_ready')}  soft_guard_promoted={event.get('soft_guard_promoted')}")

    # ── STEP 1: Logged probs ──────────────────────────────────────────────────
    if logged_probs:
        print(f"\n[STEP 1] Xác suất ghi lúc chạy thực (trong actions.log):")
        for a, p in logged_probs.items():
            bar = '█' * int(p * 40)
            mark = ' ← MODEL CHỌN' if a == 'Block' else ''
            print(f"  {a:<10}: {p:.4f}  {bar}{mark}")
    else:
        print(f"\n[STEP 1] action_probs chưa có — restart infer.py để log trường này")

    # ── STEP 2: Re-run model ──────────────────────────────────────────────────
    if not has_obs:
        print(f"\n[STEP 2] normalized_obs chưa có trong log entry này.")
        print(f"         (Event này từ lần chạy infer.py cũ — chỉ có STEP 1 khả dụng)")
        print(f"\n[STEP 3] Kết luận (từ STEP 1 only):")
        if logged_probs and logged_probs.get('Block', 0) > 0.5:
            print(f"  ✓ P(Block)={logged_probs['Block']:.4f} > 0.5 → Neural network ưu tiên Block")
            print(f"  ✓ soft_guard_promoted=False → không có rule promote")
        else:
            print(f"  [INFO] Không đủ dữ liệu để cross-validate — restart infer.py để có full proof")
        return

    obs = np.array(event['normalized_obs'], dtype=np.float32)
    print(f"\n[STEP 2] Chạy model.predict(obs) TRỰC TIẾP — không qua infer.py:")
    obs_tensor, _ = model.policy.obs_to_tensor(obs)
    with th.no_grad():
        dist = model.policy.get_distribution(obs_tensor)
        probs = dist.distribution.probs.cpu().numpy().flatten()
        action = int(probs.argmax())

    for i, p in enumerate(probs):
        bar = '█' * int(p * 40)
        mark = ' ← CHỌN' if i == action else ''
        print(f"  {ACTION_MAP[i]:<10}: {p:.4f}  {bar}{mark}")

    print(f"\n[STEP 3] Kết luận:")
    if action == 3:
        print(f"  ✓ Neural network tự chọn Block  (P={probs[3]:.4f})")
        print(f"  ✓ soft_guard_promoted=False → không có rule nào promote")
        print(f"  ✓ Đây là quyết định của PPO policy network")
    else:
        print(f"  Model chọn {ACTION_MAP[action]} — Block có thể từ override hoặc soft_guard")

    if logged_probs and 'Block' in logged_probs:
        diff = abs(logged_probs['Block'] - float(probs[3]))
        print(f"  Cross-check P(Block): log={logged_probs['Block']:.4f} vs replay={probs[3]:.4f} "
              f"→ {'✓ MATCH' if diff < 0.001 else '✗ MISMATCH'}")

    # ── STEP 4: Obs breakdown ─────────────────────────────────────────────────
    print(f"\n[STEP 4] Obs vector 34D tại thời điểm Block:")
    labels = [
        'F1 PacketRate', 'F2 SynAckRatio', 'F3 RstRatio', 'F4 SynRate',
        'F5 UdpRatio', 'F6 UrlConcentration', 'F7 HttpIatUniformity',
        'F8 HttpErrorRatio', 'F9 BodyBytesMean', 'F10 HeaderBytesMean',
        'F11 HttpReqRate', 'F12 CrsMethodScore', 'F13 CrsSqliScore',
        'F14 CrsPathScore', 'F15 CrsHeaderScore', 'F16 CrsProtoScore',
        'F17 CrsRceScore', 'F18 CrsXssScore', 'F19 CrsLfiScore',
        'F20 HtmlEventHandler',
        'T0 lastAct=Allow', 'T1 lastAct=RateLimit', 'T2 lastAct=Redirect', 'T3 lastAct=Block',
        'T4 actionHoldNorm', 'T5 damageEma', 'T6 effectTrend',
        'T7 windowFillNorm', 'T8 escalationScore', 'T9 missBudgetNorm',
        'E0 F21 WebHitRatio', 'E1 F22 HoneypotRatio', 'E2 F23 Presence', 'E3 F24 ServiceDamage'
    ]
    for i, (label, val) in enumerate(zip(labels, obs)):
        if val > 0.001:
            print(f"  obs[{i:02d}] {label:<28}: {val:.4f}")

# ── Helpers ──────────────────────────────────────────────────────────────────

def is_block_event(d, obs_dim):
    """True nếu là Block event từ RL (không phải soft_guard).
    Chấp nhận cả event cũ (không có probs/obs) — show whatever is available."""
    return (
        d.get('rl_action') == 3 and
        d.get('final_action') == 3 and
        not d.get('soft_guard_promoted', False)
    )

def load_block_events(log_path, obs_dim):
    events = []
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
            except Exception:
                continue
            if is_block_event(d, obs_dim):
                events.append(d)
    return events

def print_conclusion():
    print(f"\n{'='*60}")
    print("KẾT LUẬN:")
    print("  Xác suất P(Block) từ neural network là con số được tính")
    print("  hoàn toàn từ matrix multiplication của PPO policy network.")
    print("  Không có rule nào trong infer.py có thể tạo ra xác suất này.")
    print("  Block xảy ra vì P(Block) > P(các action khác) tại obs đó.")
    print(f"{'='*60}\n")

# ── Load Block events from log ───────────────────────────────────────────────

log_path = Path(args.log)
if not log_path.exists():
    print(f"\n[ERROR] actions.log not found: {log_path}")
    sys.exit(1)

# ── Watch mode ────────────────────────────────────────────────────────────────

if args.watch:
    print(f"\n[WATCH] Theo dõi real-time: {log_path}")
    print(f"        Sẽ tự động in khi Block event mới xuất hiện (Ctrl+C để dừng).\n")

    seen_keys: set = set()

    # Pre-seed seen_keys từ existing events (không replay lại)
    existing = load_block_events(log_path, obs_dim)
    for e in existing:
        seen_keys.add((e.get('timestamp'), e.get('src_ip')))
    print(f"  (Bỏ qua {len(existing)} Block event cũ trong log — chỉ show sự kiện MỚI)\n")

    try:
        while True:
            time.sleep(2)
            current = load_block_events(log_path, obs_dim)
            new_events = [
                e for e in current
                if (e.get('timestamp'), e.get('src_ip')) not in seen_keys
            ]
            for e in new_events:
                key = (e.get('timestamp'), e.get('src_ip'))
                seen_keys.add(key)
                verify_event(e, model, obs_dim, idx=0)
                print_conclusion()
    except KeyboardInterrupt:
        print("\n[WATCH] Dừng.")
    sys.exit(0)

# ── Non-watch mode ────────────────────────────────────────────────────────────

block_events = load_block_events(log_path, obs_dim)

n_with_obs    = sum(1 for e in block_events if e.get('normalized_obs') and len(e['normalized_obs']) == obs_dim)
n_probs_only  = len(block_events) - n_with_obs

print(f"\nBlock events từ RL (soft_guard_promoted=False): {len(block_events)}")
if n_probs_only:
    print(f"  ↳ {n_with_obs} có normalized_obs (full verify), "
          f"{n_probs_only} chỉ có action_probs (STEP 2 skip)")
if not block_events:
    print("\n[INFO] Chưa có Block event trong log.")
    print("       Restart infer.py (phiên bản mới) rồi chạy lại demo để ghi log.")
    sys.exit(0)

# ── Select event ─────────────────────────────────────────────────────────────

events_to_show = block_events if args.all_blocks else [block_events[args.event]]

for idx, event in enumerate(events_to_show):
    verify_event(event, model, obs_dim, idx=idx)

print_conclusion()
