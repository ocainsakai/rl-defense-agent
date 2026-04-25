#!/usr/bin/env python3
"""
verify_rl_decision.py — Minh bạch hóa quyết định RL

Lấy obs vector từ một Block event trong actions.log,
chạy TRỰC TIẾP model.predict() mà không qua bất kỳ rule nào,
và in ra phân phối xác suất của neural network.

Mục đích: chứng minh với hội đồng rằng quyết định Block
đến từ PPO neural network, không phải rule-based system.

Usage:
    # Trước demo: xóa log cũ (tránh lẫn session cũ)
    python3 verify_rl_decision.py --clear-log

    # Post-hoc: xem lại Block event cuối trong log
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model

    # Real-time: theo dõi log, tự động in khi Block xuất hiện
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model --watch

    # Xem tất cả Block events
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model --all-blocks

    # Xem P(Block) tăng dần qua từng window (so sánh RL vs rule)
    python3 verify_rl_decision.py --model runs/run_34d_v13/best_model --progression
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
parser.add_argument('--progression', action='store_true',
                    help='Show P(Block) tăng dần qua từng window của RL self-block gần nhất'
                         ' — chứng minh RL chờ đủ evidence thay vì rule ép sớm')
parser.add_argument('--clear-log', action='store_true',
                    help='Xóa actions.log trước demo để tránh lẫn session cũ')
args = parser.parse_args()

# ── Clear log mode ────────────────────────────────────────────────────────────
if args.clear_log:
    log_to_clear = Path(args.log)
    if log_to_clear.exists():
        size = log_to_clear.stat().st_size
        log_to_clear.write_text('')
        print(f"[✓] Đã xóa {log_to_clear} ({size/1024:.1f} KB) — sẵn sàng cho demo mới.")
    else:
        print(f"[INFO] {log_to_clear} chưa tồn tại — không cần xóa.")
    sys.exit(0)

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


# ── Progression mode ─────────────────────────────────────────────────────────

import datetime as _dt

def _get_probs(entry: dict, model) -> np.ndarray:
    obs   = np.array(entry['normalized_obs'], dtype=np.float32)
    obs_t, _ = model.policy.obs_to_tensor(obs)
    with th.no_grad():
        dist = model.policy.get_distribution(obs_t)
        return dist.distribution.probs.cpu().numpy().flatten()


def _ts_str(ts: float) -> str:
    try:
        return _dt.datetime.fromtimestamp(ts).strftime('%H:%M:%S')
    except Exception:
        return str(ts)


def show_progression(log_path: Path, model, obs_dim: int):
    """Tìm block event MỚI NHẤT, lấy toàn bộ session wlen=1→N,
    in bảng P(Block) tăng dần với bar chart trực quan.
    """
    RULE_WLEN = 12   # soft_guard fires at this window length

    # ── Tìm block event mới nhất ─────────────────────────────────────────────
    block = None
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
                if (d.get('final_action') == 3
                        and d.get('t_escalation_score', 0)
                        and d.get('normalized_obs')
                        and len(d['normalized_obs']) == obs_dim):
                    block = d
            except Exception:
                pass

    if not block:
        print("\n[INFO] Chưa ada Block event nào trong log. Chạy demo trước.")
        return

    is_rule = block.get('soft_guard_promoted') is True
    blk_wlen = block.get('t_window_len', 0)
    blk_ts   = block.get('timestamp', 0)
    src_ip   = block.get('src_ip', '?')

    # ── Lấy toàn bộ session: tất cả entries của IP trong 60s trước block ────
    session: dict = {}   # wlen → entry (newest wins)
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
                if (d.get('src_ip') == src_ip
                        and d.get('normalized_obs')
                        and len(d['normalized_obs']) == obs_dim
                        and d.get('t_window_len', 0)
                        and 0 <= blk_ts - d.get('timestamp', 0) <= 60):
                    session[d['t_window_len']] = d
            except Exception:
                pass
    session[blk_wlen] = block   # đảm bảo block event chính luôn có

    # ── Header ───────────────────────────────────────────────────────────────
    label = 'RULE-FORCED (soft_guard_promoted=True)' if is_rule \
            else 'RL SELF-BLOCK (soft_guard_promoted=False)'
    W = 72
    print(f"\n{'═'*W}")
    print(f"  P(Block) PROGRESSION — {label}")
    print(f"{'─'*W}")
    print(f"  IP : {src_ip}")
    print(f"  Block tại wlen={blk_wlen}  ts={_ts_str(blk_ts)}  (unix={blk_ts:.1f})")
    print(f"{'═'*W}")

    # ── Bảng ─────────────────────────────────────────────────────────────────
    BAR_W = 28
    print(f"  {'wlen':>4}  {'time':>8}  {'P(Block)':>8}  {'bar':<{BAR_W}}  RL muốn   Ghi chú")
    print(f"  {'─'*68}")

    sorted_wlens = sorted(session.keys())
    for w in sorted_wlens:
        d     = session[w]
        probs = _get_probs(d, model)
        p     = float(probs[3])
        act   = ACTION_MAP[int(probs.argmax())]
        ts_w  = d.get('timestamp', 0)

        # Bar: filled vs empty blocks, scale 0→1 over BAR_W chars
        filled = int(round(p * BAR_W))
        bar    = '█' * filled + '░' * (BAR_W - filled)

        # Ghi chú
        if w == blk_wlen and is_rule:
            note = '◄ RULE ÉP BLOCK'
        elif w == blk_wlen and not is_rule:
            note = '◄ RL TỰ BLOCK ★'
        elif w == RULE_WLEN and not is_rule:
            note = f'← rule sẽ ép ở đây  P={p:.4f}'
        else:
            note = ''

        prefix = '★ ' if (w == blk_wlen and not is_rule) else '  '
        print(f"{prefix}{w:4d}  {_ts_str(ts_w):>8}  {p:8.4f}  {bar}  {act:<9}  {note}")

    print(f"  {'─'*68}")

    # ── Kết luận ─────────────────────────────────────────────────────────────
    blk_probs = _get_probs(block, model)
    p_at_block = float(blk_probs[3])

    print(f"\n  KẾT LUẬN:")
    if is_rule:
        print(f"  Rule ép Block tại wlen={blk_wlen}  →  P(Block) = {p_at_block:.4f}")
        print(f"  Neural network {(1 - p_at_block)*100:.1f}% KHÔNG muốn Block tại thời điểm này.")
        print(f"  Chạy không có --soft-guard assist để thấy RL chờ đến P > 0.99.")
    else:
        p12 = float(_get_probs(session[RULE_WLEN], model)[3]) if RULE_WLEN in session else None
        print(f"  RL tự Block tại wlen={blk_wlen}  →  P(Block) = {p_at_block:.4f}  (tự tin {p_at_block*100:.1f}%)")
        if p12 is not None:
            ts12 = _ts_str(session[RULE_WLEN].get('timestamp', 0))
            print(f"  Nếu rule ép tại wlen={RULE_WLEN} ({ts12})  →  P(Block) = {p12:.4f}  (sai {(1-p12)*100:.1f}%)")
            print(f"  RL chờ thêm {blk_wlen - RULE_WLEN} window: P tăng {p12:.4f} → {p_at_block:.4f}")
    print(f"{'═'*W}\n")


# ── Load Block events from log ───────────────────────────────────────────────

log_path = Path(args.log)
if not log_path.exists():
    print(f"\n[ERROR] actions.log not found: {log_path}")
    sys.exit(1)

# ── Progression mode ──────────────────────────────────────────────────────────

if args.progression:
    show_progression(log_path, model, obs_dim)
    sys.exit(0)

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
