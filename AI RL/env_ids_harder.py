"""
IDSDefenseEnv — HARDER VARIANT for Algorithm Benchmark (PPO vs A2C vs DQN)

Same architecture as env_ids.py (34D obs, same reward, same IPs) but with
HARDER domain-randomization defaults:
  missing_prob = 0.08   (vs 0.01 default) — more missing features
  drift_max    = 0.35   (vs 0.12 default) — larger concept drift

Purpose: stress-test all algorithms under the same harder env so that
benchmark results reflect adaptation ability, not easy-env luck.

KEY DIFFERENCES FROM CLASSIFIER:
1. Reward = -network_damage (pps overflow, scan spread, payload anomaly, SQLi/XSS)
2. State transition driven by action (closed-loop control)
3. Cumulative damage tracking (episodic network health)
4. Domain randomization for robustness

OBSERVATION VECTOR (FROZEN ORDER — 20D, matches NIDS FEATURE_ORDER):
  Network (0-10):
    F1  PacketRate, F2  SynAckRatio, F3  InterArrivalTime,
    F4  RstRatio,   F5  DistinctPorts, F6  URLConcentration,
    F7  HttpIatUniformity, F8  RequestSizeUniformity, F9  AvgPayloadSize,
    F10 FwdBwdRatio, F11 PacketsPerPort
  SQLi (11-16):
    F12 SqlSpecialChar, F13 CrsSqliScore, F14 SqlUnionSelect,
    F15 SqlComment, F16 SqlStackedQuery, F17 SqlSelectCount
  XSS (17-19):
    F18 CrsXssScore, F19 JsFunctionCall, F20 HtmlEventHandler

ACTION → ATTACK TYPE MAPPING:
  - Normal user        → Allow     (action=0)
  - Noisy / suspicious → RateLimit (action=1) — user spam F5, click rapid
  - Brute Force / SQLi / XSS → Redirect (action=2) → Honeypot
  - DDoS / Port Scan   → Block     (action=3)

ATTACKER BEHAVIORAL ADAPTATION (không phải sniffer effect):
  Sniffer capture trên r-ext (TRƯỚC nginx reverse proxy) — không thấy firewall effect.
  Capture sau nginx mất toàn bộ L3/L4 features (F1,F2,F4,F5,F10,F11) vì nginx tạo TCP mới.
  Feedback qua attacker behavior thay đổi khi nhận response bất thường:
  - Allow (0):    Attacker tiếp tục / escalate attack
  - RateLimit (1): Scan attacker giảm tốc (timeout responses)
  - Redirect (2): L7 attacker giảm signal (honeypot responses khác real server)
  - Block (3):    Attacker không escalate thêm (last_action=3 trong step_forward)
"""

import math
import sys
import os
from collections import deque
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import random
from typing import Dict, List, Tuple, Any, Optional

# ============================================================================
# NORMALIZATION — single source of truth từ System/config/data_params.py
# ============================================================================
# Import trực tiếp để tránh duplicate và đảm bảo Training + Inference
# luôn dùng cùng một clip bounds / log-scale set.

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'System'))
from config.data_params import FEATURE_CLIP_BOUNDS, FEATURE_LOG_SCALE

_CLIP = FEATURE_CLIP_BOUNDS   # alias giữ backward-compat với code bên dưới
_LOG  = FEATURE_LOG_SCALE     # alias

# Feature order (20D) — FROZEN, matches NIDS FEATURE_ORDER
FEATURE_CODES = [
    'F1','F2','F3','F4','F5','F6','F7','F8','F9','F10',
    'F11','F12','F13','F14','F15','F16','F17','F18','F19','F20',
]

# Keep backward-compat anchors used by policy_guard/infer
PR_ANCHOR      = _CLIP['F1']   # 500.0
SA_ANCHOR      = _CLIP['F2']   # 100.0
DP_ANCHOR      = _CLIP['F5']   # 500.0
PAYLOAD_ANCHOR = _CLIP['F9']   # 1500.0
FAIL_ANCHOR    = 1.0           # F4 (RstRatio) is [0,1] pass-through

# Additional thresholds for damage formula
SYN_THRESHOLD = 2.0    # F2 > 2× → SYN flood indicator (normalized)
PORTS_OFFSET  = 5      # min ports before scan penalty kicks in
ACTION_HOLD_NORM_STEPS = 15.0
REDIRECT_PERSIST_STEPS = 15
HONEYPOT_STREAK_STEPS = 12
CLEAN_STREAK_NORM_STEPS = 10.0
HONEYPOT_RATIO_THRESHOLD = 0.60
PRESENCE_RATIO_THRESHOLD = 0.50
SERVICE_DAMAGE_CLEAN_THRESHOLD = 0.03
SOFT_SESSION_WINDOW = 15
MISS_BUDGET = 3
SESSION_START_L7_THRESHOLD = 0.35
ESCALATION_SCORE_BLOCK_THRESHOLD = 0.60  # lowered: 12R+3miss(score=0.647) now reaches block_ready at t=15
ESCALATION_SCORE_RAMP_THRESHOLD = 0.50   # kept below block threshold so ramp fires before block_ready
SESSION_RESET_CLEAN_STREAK = 2
SESSION_RESET_NO_PRESENCE_STREAK = 3
BLOCK_READY_MIN_WINDOW   = 12   # v13: 15→12 — fewer steps needed, reduces session timeout risk
BLOCK_READY_MIN_REDIRECT = 6    # v13: 8→6
BLOCK_READY_MIN_PRESENCE = 8    # v13: 10→8
BLOCK_READY_MIN_HONEYPOT = 5    # v13: 7→5


def _norm_one(code: str, raw: float) -> float:
    """Normalize a single feature value to [0,1] matching data_params logic."""
    cap = _CLIP.get(code)
    if cap is not None and cap > 0.0:
        clipped = min(raw, cap)
        if code in _LOG:
            return math.log1p(clipped) / math.log1p(cap)
        else:
            return clipped / cap
    else:
        return max(0.0, min(1.0, raw))


def normalize_observation(raw_vector: List[float]) -> np.ndarray:
    """
    Normalize 20D raw feature vector → [0,1]^20.

    Args:
        raw_vector: list of 20 raw feature values in FEATURE_CODES order
                    [F1, F2, ..., F20]

    Returns:
        np.ndarray shape (20,) dtype float32
    """
    assert len(raw_vector) == 20, f"Expected 20 features, got {len(raw_vector)}"
    return np.array(
        [_norm_one(code, float(v)) for code, v in zip(FEATURE_CODES, raw_vector)],
        dtype=np.float32
    )

# ============================================================================
# SMOOTH GATE HELPER
# ============================================================================

def soft_gate(x: float, center: float, width: float = 0.08) -> float:
    """
    Smooth sigmoid gate for graduated response.

    Returns value ∈ [0, 1]:
      - x << center → 0
      - x ≈ center → 0.5
      - x >> center → 1

    Args:
        x: Input value
        center: Midpoint of transition
        width: Transition sharpness (smaller = sharper)

    Returns:
        Gate activation ∈ [0, 1]
    """
    # Defensive check: prevent division by zero
    width = max(width, 1e-6)
    return 1.0 / (1.0 + np.exp(-(x - center) / width))
# = 1 / (1 + e^(-(x - center) / width))
#= 1 / (1 + e^(-(1/width)(x - center)))
#= L / (1 + e^(-k(x - x0)))      where k = 1/width, x0 = center, L = 1
#Source = https://en.wikipedia.org/wiki/Logistic_function

# ============================================================================
# NETWORK DAMAGE METRICS
# ============================================================================

def compute_network_damage(obs: List[float]) -> float:
    """
    Compute BOUNDED network damage score [0, 1] from 20D raw feature vector.

    Args:
        obs: list of 20 RAW (un-normalized) feature values in FEATURE_CODES order

    Returns:
        damage ∈ [0, 1]: 0=no damage, 1=critical damage
    """
    # Unpack relevant features (raw values)
    f1_pps    = obs[0]   # PacketRate (pps)
    f2_syn    = obs[1]   # SynAckRatio
    f4_rst    = obs[3]   # RstRatio [0,1]
    f5_ports  = obs[4]   # DistinctPorts (raw count)
    f9_plen   = obs[8]   # AvgPayloadSize (bytes)
    f11_ppp   = obs[10]  # PacketsPerPort

    # SQLi indicators (raw values)
    f12 = obs[11]  # SqlSpecialChar [0,1]
    f13 = obs[12]  # CrsSqliScore (0-20)
    f14 = obs[13]  # SqlUnionSelect [0,1]
    f15 = obs[14]  # SqlComment [0,1]
    f16 = obs[15]  # SqlStackedQuery [0,1]

    # XSS indicators (raw values)
    f18 = obs[17]  # CrsXssScore (0-4)
    f19 = obs[18]  # JsFunctionCall [0,1]
    f20 = obs[19]  # HtmlEventHandler [0,1]

    # 1. Packet rate overflow — logistic
    pps_norm = f1_pps / PR_ANCHOR
    pps_damage = 1.0 / (1.0 + np.exp(-5.0 * (pps_norm - 1.0)))

    # 2. RST ratio — tanh (replaces conn_fail_rate)
    rst_damage = np.tanh(f4_rst * 2.0)

    # 3. Port scan spread — log-sigmoid on raw port count
    ports_norm = np.log1p(max(0, f5_ports - PORTS_OFFSET)) / np.log1p(495)
    scan_damage = np.tanh(ports_norm * 2.0)

    # 4. Payload anomaly — benign upload pattern check uses f4_rst and f5_ports
    is_benign_upload = (f9_plen >= 3000 and f4_rst <= 0.05 and f5_ports <= 2)
    if is_benign_upload:
        payload_damage = 0.0
    else:
        payload_excess = max(0, (f9_plen - PAYLOAD_ANCHOR) / PAYLOAD_ANCHOR)
        payload_damage = 1.0 / (1.0 + np.exp(-3.0 * (payload_excess - 0.5)))

    # 5. SYN flood — tanh on normalized ratio
    syn_norm = f2_syn / SA_ANCHOR  # SA_ANCHOR=100, so this is small for normal traffic
    syn_excess = max(0, f2_syn - SYN_THRESHOLD)
    syn_damage = np.tanh(syn_excess / 5.0)

    # 6. SQLi damage — weighted combination of indicators
    sqli_norm_score = min(f13 / 20.0, 1.0)  # CRS score normalized
    sqli_damage = np.clip(
        0.4 * sqli_norm_score +
        0.2 * float(f14 > 0) +   # UNION SELECT binary
        0.2 * float(f16 > 0) +   # Stacked query binary
        0.1 * f12 +               # Special chars ratio
        0.1 * float(f15 > 0),    # Comment binary
        0.0, 1.0
    )

    # 7. XSS damage — weighted combination
    xss_norm_score = min(f18 / 4.0, 1.0)  # CRS XSS score normalized
    xss_damage = np.clip(
        0.5 * xss_norm_score +
        0.3 * float(f19 > 0) +   # JS function call binary
        0.2 * float(f20 > 0),    # HTML event handler binary
        0.0, 1.0
    )

    # Layer7 combined damage
    context_damage = np.clip((sqli_damage + xss_damage) / 2.0, 0.0, 1.0)

    # DAMAGE WEIGHTS — NIST 800-61r2 priority order
    total_damage = (
        0.25 * pps_damage +     # Capacity overflow (DDoS)
        0.15 * rst_damage +     # Connection failures (Brute Force / scan)
        0.15 * scan_damage +    # Port scan reconnaissance
        0.10 * payload_damage + # Large payload anomaly
        0.10 * syn_damage +     # SYN flood indicator
        0.25 * context_damage   # SQLi / XSS (Layer7 attack — high priority)
    )

    return float(np.clip(total_damage, 0.0, 1.0))


def compute_attack_signals(obs_raw: List[float]) -> Dict[str, float]:
    """Compute reusable attack-family signals from a 20D raw observation."""
    f1_pps    = obs_raw[0]   # PacketRate
    f2_syn    = obs_raw[1]   # SynAckRatio
    f5_ports  = obs_raw[4]   # DistinctPorts
    f6_url    = obs_raw[5]   # URLConcentration [0,1]
    f7_iat    = obs_raw[6]   # HttpIatUniformity [0,1]
    f8_size   = obs_raw[7]   # RequestSizeUniformity [0,1]
    f11_ppp   = obs_raw[10]  # PacketsPerPort

    # SQLi indicators
    f12_sqli  = obs_raw[11]  # SqlSpecialChar
    f13_crs   = obs_raw[12]  # CrsSqliScore
    f14_union = obs_raw[13]  # SqlUnionSelect
    f15_cmt   = obs_raw[14]  # SqlComment
    f16_stk   = obs_raw[15]  # SqlStackedQuery

    # XSS indicators
    f18_xss   = obs_raw[17]  # CrsXssScore
    f19_js    = obs_raw[18]  # JsFunctionCall
    f20_html  = obs_raw[19]  # HtmlEventHandler

    ddos_signal  = min(f1_pps / 200.0, 1.0)                    # high pps → DDoS
    syn_signal   = min(f2_syn / 10.0, 1.0)                     # SYN/ACK ratio spike
    scan_signal  = min(f5_ports / 50.0, 1.0) * min(f11_ppp / 50.0, 1.0)  # port scan
    brute_signal = (f6_url * 0.40 + f7_iat * 0.15 + f8_size * 0.15
                    + soft_gate(f13_crs, 0.5, 0.20) * 0.30)
    sqli_signal  = min((f12_sqli + f13_crs / 20.0 + float(f14_union > 0)
                        + float(f15_cmt > 0) + float(f16_stk > 0)) / 3.0, 1.0)
    xss_signal   = min((f18_xss / 4.0 + float(f19_js > 0) + float(f20_html > 0)) / 2.0, 1.0)

    return {
        'ddos': float(ddos_signal),
        'syn': float(syn_signal),
        'scan': float(scan_signal),
        'brute': float(brute_signal),
        'sqli': float(sqli_signal),
        'xss': float(xss_signal),
        'l7_presence': float(max(brute_signal, sqli_signal, xss_signal)),
    }


def compute_action_cost(action) -> float:
    """
    Action cost — creates "action ladder" discouraging lazy Block-all.

    Block zeroes all features (damage_after≈0) so base_reward is only -action_cost.
    Setting Block cost high (0.15) prevents the model from always preferring Block
    over Redirect/RateLimit for all traffic types.

    - Allow: free (no intervention)
    - RateLimit: very cheap (light throttle — good for noisy users)
    - Redirect: moderate (honeypot setup overhead)
    - Block: expensive (false positive risk + service disruption)
    """
    action = int(action)  # Handle numpy array from model.predict()
    cost_map = {
        0: 0.00,  # Allow
        1: 0.01,  # RateLimit — very cheap to encourage for noisy traffic
        2: 0.04,  # Redirect
        3: 0.15   # Block — expensive to prevent lazy Block-all
    }
    return cost_map.get(action, 0.0)

def compute_action_bonus(action: int, obs_raw: List[float], damage: float) -> float:
    """
    Compute graduated response bonus based on attack-type detection (20D obs).

    4-zone mapping (thesis scope):
      - DDoS / Port Scan   → Block     (action=3) — F1/F2 high OR F5/F11 high
      - Brute / SQLi / XSS → Redirect  (action=2) — F6/F7/F8 OR F12-F20
      - Noisy / unclear    → RateLimit (action=1) — ambiguous moderate signals
      - Normal             → Allow     (action=0) — no attack signal

    Args:
        action: Action ID (0=Allow, 1=RateLimit, 2=Redirect, 3=Block)
        obs_raw: 20D RAW feature vector (un-normalized)
        damage: Network damage [0, 1]

    Returns:
        bonus ∈ [-0.60, +0.25]
    """
    # ── Attack signal detection from raw 20D vector ──────────────────────────
    signals = compute_attack_signals(obs_raw)
    ddos_signal  = signals['ddos']
    syn_signal   = signals['syn']
    scan_signal  = signals['scan']
    brute_signal = signals['brute']
    sqli_signal  = signals['sqli']
    xss_signal   = signals['xss']
    f1_pps       = obs_raw[0]   # PacketRate (reused below for noisy-normal shaping)
    f6_url       = obs_raw[5]   # URLConcentration [0,1]
    f8_size      = obs_raw[7]   # RequestSizeUniformity [0,1]
    # Noise signal: elevated pps (20-60 pps) with low attack signals → noisy user (spam F5, rapid clicks)
    # Trapezoidal: ramp up from 0→1 over 15-30pps, ramp down 1→0 over 50-80pps
    # Benign F1≈8 → noise_pps≈0 (below 15 pps floor); noisy_normal F1≈30 → noise_pps≈1.0
    noise_rise   = float(np.clip((f1_pps - 15.0) / 15.0, 0.0, 1.0))   # 0→1 at 15→30 pps
    noise_fall   = float(np.clip(1.0 - (f1_pps - 50.0) / 30.0, 0.0, 1.0))  # 1→0 at 50→80 pps
    noise_pps    = noise_rise * noise_fall
    # Spam-reload is characterized by:
    #   - medium packet rate bursts
    #   - repeated URL/response size patterns
    # but without the stronger signatures of DDoS or L7 exploitation.
    repetition_hint = float(np.clip(0.6 * f8_size + 0.4 * f6_url, 0.0, 1.0))
    burst_hint = soft_gate(noise_pps, 0.55, 0.10)
    reload_hint = soft_gate(repetition_hint, 0.18, 0.06)
    ddos_suppress = 1.0 - soft_gate(max(ddos_signal, syn_signal, scan_signal), 0.45, 0.08)
    layer7_suppress = 1.0 - soft_gate(max(brute_signal, sqli_signal, xss_signal), 0.42, 0.08)
    noise_signal = float(np.clip(
        (0.70 * burst_hint + 0.30 * reload_hint) * ddos_suppress * layer7_suppress,
        0.0, 1.0
    ))

    # Zone classification (soft gates, 4 zones)
    # L7 suppressor: khi brute/sqli/xss signal mạnh → triệt is_ddos.
    # Lý do: brute_force có F1 cao (120pps) giống DDoS, nhưng có F6/F7/F8 đặc trưng L7.
    # scan/syn_flood không có L7 signal → suppressor = 0 → is_ddos không bị ảnh hưởng.
    l7_presence = signals['l7_presence']
    l7_ddos_suppress = soft_gate(l7_presence, 0.35, 0.08)  # gần 1 khi L7 mạnh
    raw_ddos_gate = soft_gate(max(ddos_signal, syn_signal, scan_signal), 0.40, 0.10)
    is_ddos   = raw_ddos_gate * (1.0 - l7_ddos_suppress)
    is_layer7 = soft_gate(max(brute_signal, sqli_signal, xss_signal), 0.35, 0.10)
    noise_presence = max(noise_signal, 0.60 * burst_hint + 0.40 * reload_hint)
    is_noise  = float(np.clip(
        soft_gate(noise_presence, 0.45, 0.10) * (1.0 - is_ddos) * (1.0 - is_layer7),
        0.0, 1.0
    ))
    normal_clean = (1.0 - soft_gate(damage, 0.08, 0.04)) * (1.0 - is_ddos) * (1.0 - is_layer7)
    is_normal = float(np.clip(
        normal_clean
        * (1.0 - is_noise)
        * (1.0 - 0.75 * burst_hint)
        * (1.0 - 0.35 * reload_hint),
        0.0, 1.0
    ))

    # Damage gates
    high_damage = soft_gate(damage, 0.50, 0.10)
    low_damage  = 1.0 - soft_gate(damage, 0.15, 0.05)

    bonus = 0.0

    # ── DDoS / Port Scan → Block ──────────────────────────────────────────────
    if action == 3:   # Block (correct)
        bonus += is_ddos * 0.30
    elif action == 0: # Allow (very wrong)
        bonus -= is_ddos * high_damage * 0.50
    elif action == 2: # Redirect (suboptimal for DDoS)
        bonus -= is_ddos * 0.10

    # ── Brute Force / SQLi / XSS → Redirect ──────────────────────────────────
    if action == 2:   # Redirect (correct — honeypot capture)
        bonus += is_layer7 * 0.35    # Increased from 0.25 — must beat Block
    elif action == 0: # Allow (wrong)
        bonus -= is_layer7 * high_damage * 0.40
    elif action == 3: # Block (suboptimal — attacker evades honeypot)
        # Block is usually worse than Redirect for L7, but the penalty should fade
        # once service-side damage is already low and persistence logic takes over.
        bonus -= is_layer7 * high_damage * 0.20

    # ── Noisy / Suspicious → RateLimit ───────────────────────────────────────
    if action == 1:   # RateLimit (correct — graduated response)
        bonus += is_noise * 0.46    # Strong enough for spam-reload bursts, still below hard-attack zones
    elif action == 3: # Block (over-response for ambiguous traffic)
        bonus -= is_noise * 0.50
    elif action == 2: # Redirect (over-response for noise)
        bonus -= is_noise * 0.25
    elif action == 0: # Allow (risky — noisy user may be probing)
        bonus -= is_noise * 0.20   # Encourage gentle mitigation for persistent spam-reload traffic

    # ── Normal → Allow ────────────────────────────────────────────────────────
    # Give Allow a small positive anchor so PPO does not drift toward "always mitigate a bit".
    if action == 0: # Allow (correct)
        bonus += is_normal * low_damage * 0.12
    if action == 3: # Block (false positive — very bad for UX)
        bonus -= is_normal * low_damage * 0.60
    elif action == 1: # RateLimit (mild over-response for clean traffic)
        bonus -= is_normal * low_damage * 0.32
    elif action == 2: # Redirect (over-response for clean traffic)
        bonus -= is_normal * low_damage * 0.45

    return float(np.clip(bonus, -0.60, 0.35))

# ============================================================================
# IP MOCK BEHAVIOR WITH DOMAIN RANDOMIZATION
# ============================================================================

class MockIPBehavior:
    """Simulates per-IP traffic with domain randomization and closed-loop effects.

    PHASE 2: Added persistence state tracking (persistence_score, burst_window)."""

    def __init__(self, ip_type: str, rng: np.random.Generator = None):
        self.ip_type = ip_type
        self.rng = rng if rng is not None else np.random.default_rng()
        self.step_counter = 0

        # Base state (mean values)
        self.base_state = {}

        # Current state (with noise)
        self.state = {}

        # Closed-loop tracking
        self.block_ttl = 0  # Steps remaining in block
        self.last_action = 0  # Last action applied

        # PHASE 2: Persistence state (temporal tracking)
        self.persistence_score = 0.0  # Accumulates suspicion over time [0, 1]
        self.burst_window = 0  # Burst counter (0 = inactive, >0 = steps remaining)
        self.last_phase = None  # Track episode phase for phase transitions

        self._init_base_state()
        self._apply_domain_randomization()

    def _init_base_state(self):
        """Initialize baseline state means for each IP type (20D feature vector).

        Keys in base_state:
          F1..F20: mean values (raw, un-normalized)
          F1_sigma, F9_sigma: std-dev for Gaussian features
          F2_sigma: for log-normal F2
          F5_lam: Poisson lambda for distinct ports (F5)
          F11_lam: Poisson lambda for PacketsPerPort (F11)
          F4_alpha/F4_beta: Beta params for RstRatio (F4)
        """
        if self.ip_type == 'benign':
            self.base_state = {
                'F1': 8.0,   'F1_sigma': 5.0,        # PacketRate — normal browsing is 1-15 pps
                'F2': 1.0,   'F2_sigma': 0.15,       # SynAckRatio (log-normal)
                'F3': 0.3,                             # InterArrivalTime (seconds)
                'F4': 0.02,  'F4_alpha': 1.0, 'F4_beta': 48.0,   # RstRatio ~ Beta
                'F5': 2,     'F5_lam': 2,             # DistinctPorts (Poisson)
                'F6': 0.05,                            # URLConcentration — diverse URLs
                # Low F7/F8: benign users browse randomly, timing/size non-uniform
                # → brute_signal low → noise_signal suppressed → Allow zone
                'F7': 0.08,                            # HttpIatUniformity — random timing
                'F8': 0.10,                            # RequestSizeUniformity — varied
                'F9': 180.0, 'F9_sigma': 60.0,        # AvgPayloadSize
                'F10': 1.5,                            # FwdBwdRatio
                'F11': 30.0, 'F11_lam': 30,           # PacketsPerPort
                # SQLi: all zero
                'F12': 0.0, 'F13': 0.0, 'F14': 0.0,
                'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                # XSS: all zero
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
            }
        elif self.ip_type == 'scan':
            self.base_state = {
                'F1': 160.0, 'F1_sigma': 30.0,  # High pps → always > 80 pps → outside noise zone
                'F2': 2.0,   'F2_sigma': 0.30,
                'F3': 0.1,
                'F4': 0.60,  'F4_alpha': 30.0, 'F4_beta': 20.0,  # High RST (failed conns)
                'F5': 10,    'F5_lam': 10,
                'F6': 0.05,
                'F7': 0.3,
                'F8': 0.2,
                'F9': 140.0, 'F9_sigma': 30.0,
                'F10': 3.0,
                'F11': 10.0, 'F11_lam': 10,
                'F12': 0.0, 'F13': 0.0, 'F14': 0.0,
                'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
            }
        elif self.ip_type == 'syn_flood':
            self.base_state = {
                'F1': 350.0, 'F1_sigma': 80.0,   # High packet rate
                'F2': 10.0,  'F2_sigma': 2.0,    # SYN/ACK flood
                'F3': 0.003,                       # Very fast IAT
                'F4': 0.35,  'F4_alpha': 17.5, 'F4_beta': 32.5,
                'F5': 2,     'F5_lam': 2,
                'F6': 0.05,
                'F7': 0.2,
                'F8': 0.2,   # SYN flood — not uniform HTTP size (no HTTP payload)
                'F9': 70.0,  'F9_sigma': 15.0,   # Tiny payload (SYN has no data)
                'F10': 8.0,  # Highly asymmetric (all SYN, no ACK back)
                'F11': 200.0,'F11_lam': 200,
                'F12': 0.0, 'F13': 0.0, 'F14': 0.0,
                'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
            }
        elif self.ip_type == 'brute_force':
            # Standard HTTP brute force (no keep-alive).
            # Calibrated from CIC-IDS2018: F1≈5-10 pps, F7≈0, F8≈0, F13≈1.0
            self.base_state = {
                'F1': 25.0,  'F1_sigma': 15.0,
                'F2': 1.1,   'F2_sigma': 0.15,
                'F3': 0.10,
                'F4': 0.65,  'F4_alpha': 32.5, 'F4_beta': 17.5,
                'F5': 1,     'F5_lam': 1,
                'F6': 0.95,
                'F7': 0.12,  # Standard HTTP (not keep-alive)
                'F8': 0.12,
                'F9': 100.0, 'F9_sigma': 40.0,
                'F10': 1.5,
                'F11': 8.0,  'F11_lam': 8,
                'F12': 0.02,
                'F13': 0.8,  # CRS fires on POST URL-encoded params
                'F14': 0.0, 'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
            }
        elif self.ip_type == 'brute_force_ka':
            # Keep-alive brute force bot (brute_keepalive.py demo scenario).
            # Calibrated from live test: F7≈0.85, F8≈0.90, F13≈0 (no CRS on POST).
            self.base_state = {
                'F1': 30.0,  'F1_sigma': 10.0,  # ~20-40 pps (50ms delay × pkts/request)
                'F2': 1.1,   'F2_sigma': 0.15,
                'F3': 0.05,  # Fast IAT (keep-alive, 50ms)
                'F4': 0.70,  'F4_alpha': 35.0, 'F4_beta': 15.0,
                'F5': 1,     'F5_lam': 1,
                'F6': 0.98,  # 100% requests to /login
                'F7': 0.85,  # Keep-alive → very uniform IAT → F7 high
                'F8': 0.88,  # Same POST form → uniform payload size
                'F9': 180.0, 'F9_sigma': 30.0,
                'F10': 1.5,
                'F11': 30.0, 'F11_lam': 30,
                'F12': 0.0,
                'F13': 0.0,  # Simple password list → no CRS SQLi trigger
                'F14': 0.0, 'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
            }
        elif self.ip_type == 'sqli':
            # SQL Injection only — calibrated from CIC-IDS2018 SQL Injection attack window.
            # CIC averages: F1≈6, F6≈0.69, F7≈0, F8≈0, F9≈30, F13≈6.5, F14≈0.4, F15≈0.6
            self.base_state = {
                'F1': 12.0,  'F1_sigma': 8.0,   # slow/low-rate SQLi tool (sqlmap)
                'F2': 1.05,  'F2_sigma': 0.15,
                'F3': 0.05,
                'F4': 0.01,  'F4_alpha': 0.5, 'F4_beta': 49.5,  # Low RST (sessions work)
                'F5': 2,     'F5_lam': 2,
                'F6': 0.70,  # Concentrated on exploit URLs (CIC: 0.694)
                'F7': 0.04,  # Standard HTTP (CIC: ~0)
                'F8': 0.04,  # Variable payload (SQL query strings vary)
                'F9': 40.0,  'F9_sigma': 20.0,  # CIC: ~30 bytes avg (short queries)
                'F10': 1.6,
                'F11': 5.0,  'F11_lam': 5,
                'F12': 0.02,                      # Special chars (CIC: 0.017)
                'F13': 5.5,  # CRS SQLi score (CIC: 6.49 avg)
                'F14': 0.4,  # UNION SELECT (CIC: 0.408)
                'F15': 0.6,  # SQL comments (CIC: 0.571)
                'F16': 0.0,  # Stacked queries (CIC: ~0)
                'F17': 0.4,  # SELECT count
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,  # No XSS signals
            }
        elif self.ip_type == 'xss':
            # XSS only — calibrated from CIC-IDS2018 Brute Force-XSS attack window.
            # CIC averages: F1≈6, F6≈0.995, F7≈0, F8≈0, F9≈92, F13≈2.7, F18≈2.2, F19≈0.89
            self.base_state = {
                'F1': 12.0,  'F1_sigma': 8.0,   # slow/low-rate XSS tool
                'F2': 1.0,   'F2_sigma': 0.15,
                'F3': 0.06,
                'F4': 0.01,  'F4_alpha': 0.5, 'F4_beta': 49.5,
                'F5': 1,     'F5_lam': 1,
                'F6': 0.95,  # Very concentrated URLs (CIC: 0.995)
                'F7': 0.05,  # Standard HTTP (CIC: ~0)
                'F8': 0.05,  # Variable payload (XSS payloads vary)
                'F9': 90.0,  'F9_sigma': 30.0,  # CIC: ~92 bytes avg
                'F10': 2.0,
                'F11': 4.0,  'F11_lam': 4,
                'F12': 0.02,
                'F13': 2.5,  # CRS SQLi also fires on XSS payloads (CIC: 2.672)
                'F14': 0.0, 'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 2.2,  # CRS XSS score (CIC: 2.227)
                'F19': 0.9,  # JS function calls (alert/eval) (CIC: 0.892)
                'F20': 0.0,  # HTML event handlers (CIC: ~0)
            }
        elif self.ip_type == 'noisy_normal':
            # Legit user but reloads / clicks repeatedly in short bursts.
            # Goal: stay clearly above benign browsing, but below attack zones.
            self.base_state = {
                'F1': 24.0,  'F1_sigma': 5.0,    # Typical spam-reload baseline before burst
                'F2': 1.1,   'F2_sigma': 0.30,
                'F3': 0.18,
                'F4': 0.04,  'F4_alpha': 2.0, 'F4_beta': 48.0,
                'F5': 2,     'F5_lam': 2,
                'F6': 0.18,  # Some URL repetition from refreshing the same page
                'F7': 0.14,  # More regular than benign, but far from bot-like uniformity
                'F8': 0.28,  # Repeated requests make size more uniform
                'F9': 240.0, 'F9_sigma': 60.0,
                'F10': 1.8,
                'F11': 18.0, 'F11_lam': 18,
                'F12': 0.0, 'F13': 0.0, 'F14': 0.0,
                'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,
            }
        else:
            raise ValueError(f"Unknown ip_type: {self.ip_type}")

    def _apply_domain_randomization(self):
        """Apply domain randomization with realistic noise distributions (20D)."""
        b = self.base_state

        # F1 PacketRate ~ Normal
        self.state['F1'] = max(0.0, self.rng.normal(b['F1'], b['F1_sigma']))

        # F2 SynAckRatio ~ LogNormal
        mu = np.log(max(b['F2'], 0.5))
        sigma = b['F2_sigma'] / max(b['F2'], 0.5)
        self.state['F2'] = max(0.5, self.rng.lognormal(mu, sigma))

        # F3 InterArrivalTime ~ Exponential (IAT always > 0)
        self.state['F3'] = max(0.001, self.rng.exponential(b['F3']))

        # F4 RstRatio ~ Beta
        alpha = max(0.1, b['F4_alpha'])
        beta  = max(0.1, b['F4_beta'])
        self.state['F4'] = float(self.rng.beta(alpha, beta))

        # F5 DistinctPorts ~ Poisson
        self.state['F5'] = max(1, int(self.rng.poisson(max(1, b['F5_lam']))))

        # F6 URLConcentration [0,1] — Beta noise around mean
        f6_mean = float(np.clip(b['F6'], 0.01, 0.99))
        f6_a = f6_mean * 20.0
        f6_b = (1.0 - f6_mean) * 20.0
        self.state['F6'] = float(self.rng.beta(max(0.1, f6_a), max(0.1, f6_b)))

        # F7 HttpIatUniformity [0,1] — Beta
        f7_mean = float(np.clip(b['F7'], 0.01, 0.99))
        f7_a = f7_mean * 15.0
        f7_b = (1.0 - f7_mean) * 15.0
        self.state['F7'] = float(self.rng.beta(max(0.1, f7_a), max(0.1, f7_b)))

        # F8 RequestSizeUniformity [0,1] — Beta
        f8_mean = float(np.clip(b['F8'], 0.01, 0.99))
        f8_a = f8_mean * 15.0
        f8_b = (1.0 - f8_mean) * 15.0
        self.state['F8'] = float(self.rng.beta(max(0.1, f8_a), max(0.1, f8_b)))

        # F9 AvgPayloadSize ~ Normal
        self.state['F9'] = max(40.0, self.rng.normal(b['F9'], b['F9_sigma']))

        # F10 FwdBwdRatio ~ LogNormal
        f10 = max(b.get('F10', 1.5), 0.5)
        self.state['F10'] = max(0.5, self.rng.lognormal(np.log(f10), 0.3))

        # F11 PacketsPerPort ~ Poisson
        self.state['F11'] = float(max(1, int(self.rng.poisson(max(1, b['F11_lam'])))))

        # F12 SqlSpecialChar [0,1] — noise only when base > 0
        # FIX: benign base=0 → no noise (real NIDS: no SQLi pattern = score 0 exactly)
        if b['F12'] > 0:
            self.state['F12'] = float(np.clip(b['F12'] + self.rng.normal(0, 0.01), 0.0, 1.0))
        else:
            self.state['F12'] = 0.0

        # F13 CrsSqliScore (0-20) — noise only when base > 0
        # FIX: Normal(0, 0.1) when base=0 → 50% false positive rate for benign
        if b['F13'] > 0:
            self.state['F13'] = float(max(0.0, self.rng.normal(b['F13'], max(0.1, b['F13'] * 0.15))))
        else:
            self.state['F13'] = 0.0

        # F14-F16: Binary/normalized indicators — noise only when base > 0
        # FIX: clip(0 + Normal(0,0.05)) → ~50% chance >0 → float(f14>0)=1.0 for benign
        for code in ('F14', 'F15', 'F16'):
            if b[code] > 0:
                self.state[code] = float(np.clip(b[code] + self.rng.normal(0, 0.05), 0.0, 1.0))
            else:
                self.state[code] = 0.0

        # F17 SqlSelectCount — noise only when base > 0
        if b['F17'] > 0:
            self.state['F17'] = float(max(0.0, self.rng.normal(b['F17'], max(0.1, b['F17'] * 0.15))))
        else:
            self.state['F17'] = 0.0

        # F18 CrsXssScore (0-4) — noise only when base > 0
        if b['F18'] > 0:
            self.state['F18'] = float(max(0.0, self.rng.normal(b['F18'], max(0.1, b['F18'] * 0.15 + 0.05))))
        else:
            self.state['F18'] = 0.0

        # F19-F20: Binary XSS indicators — noise only when base > 0
        for code in ('F19', 'F20'):
            if b[code] > 0:
                self.state[code] = float(np.clip(b[code] + self.rng.normal(0, 0.05), 0.0, 1.0))
            else:
                self.state[code] = 0.0

    def apply_closed_loop_effect(self, action: int):
        """
        Record last action for attacker behavioral adaptation in step_forward().

        Kiến trúc thực tế: Sniffer capture trên r-ext (TRƯỚC nginx reverse proxy).
        Lý do bắt buộc: nginx tạo TCP connection mới → capture sau nginx (r-web) chỉ
        thấy nginx IP, mất toàn bộ L3/L4 features của attacker thật:
          F1 PacketRate, F2 SynAckRatio, F4 RstRatio, F5 DistinctPorts,
          F10 FwdBwdRatio, F11 PacketsPerPort → Port Scan và DDoS detection thất bại.
        r-ext là điểm capture duy nhất giữ đủ 20 features.

        Hệ quả: firewall effects (iptables DROP/hashlimit/DNAT) không phản ánh
        trên r-ext capture. Feedback loop được mô phỏng qua attacker behavioral
        adaptation — attacker thay đổi pattern khi nhận response bất thường.
        step_forward() dùng last_action để điều chỉnh base_state của attacker.
        """
        self.block_ttl = 0  # unused
        self.last_action = action

    def step_forward(self):
        """Evolve behavior for next step with closed-loop awareness (20D)."""
        self.step_counter += 1

        # block_ttl không còn dùng — sniffer luôn thấy raw traffic
        # (kiến trúc: sniffer trước firewall, không bị ảnh hưởng bởi iptables DROP)

        b = self.base_state

        if self.ip_type == 'benign':
            # Mean-reverting browsing traffic: casual users should not drift into noisy zone
            b['F1'] = float(np.clip(0.35 * b['F1'] + self.rng.normal(5, 2.5), 1.0, 18.0))
            b['F9'] = float(np.clip(0.30 * b['F9'] + self.rng.normal(165, 30), 40.0, 900.0))
            if self.rng.random() < 0.1:
                b['F9'] = min(1200.0, b['F9'] + 150.0)  # occasional spike (file upload)

        elif self.ip_type == 'scan':
            if self.last_action == 0:  # Allowed → escalate scan
                b['F5'] = min(200, b['F5'] + int(self.rng.integers(3, 12)))
                b['F5_lam'] = b['F5']
                b['F11'] = min(500, b['F11'] + self.rng.normal(5, 10))
                b['F11_lam'] = int(b['F11'])
            elif self.last_action in (1, 2):  # Throttled → slow scan
                b['F5'] = max(5, b['F5'] + int(self.rng.integers(-2, 2)))
                b['F5_lam'] = b['F5']

        elif self.ip_type == 'syn_flood':
            if self.last_action == 0:
                b['F1'] += self.rng.normal(50, 80)
                b['F2'] += self.rng.normal(1.0, 1.5)
            elif self.last_action == 1:
                b['F1'] += self.rng.normal(10, 30)

        elif self.ip_type in ('brute_force', 'brute_force_ka'):
            if self.last_action == 0:
                # Allowed traffic gives the bot confidence to push retries harder.
                b['F1'] = float(np.clip(b['F1'] + self.rng.normal(3.0, 2.0), 10.0, 60.0))
                b['F6'] = float(np.clip(b['F6'] + self.rng.normal(0.01, 0.01), 0.70, 1.0))
                b['F7'] = float(np.clip(b['F7'] + self.rng.normal(0.02, 0.01), 0.05, 0.98))
                b['F8'] = float(np.clip(b['F8'] + self.rng.normal(0.02, 0.01), 0.05, 0.98))
                b['F4'] = float(np.clip(0.75 + self.rng.beta(8, 2) * 0.23, 0.0, 1.0))
                b['F4_alpha'] = b['F4'] * 50
                b['F4_beta'] = (1.0 - b['F4']) * 50
            elif self.last_action == 2:
                # Redirect should keep the bot talking to the honeypot; sensor stays attack-like.
                b['F1'] = float(np.clip(0.92 * b['F1'] + self.rng.normal(2.0, 1.5), 10.0, 55.0))
                b['F6'] = float(np.clip(0.98 * b['F6'] + self.rng.normal(0.0, 0.01), 0.65, 1.0))
                b['F7'] = float(np.clip(0.97 * b['F7'] + self.rng.normal(0.0, 0.01), 0.05, 0.98))
                b['F8'] = float(np.clip(0.97 * b['F8'] + self.rng.normal(0.0, 0.01), 0.05, 0.98))
            elif self.last_action == 3:  # Blocked
                b['F1'] = float(np.clip(0.78 * b['F1'] + self.rng.normal(-2.0, 2.0), 5.0, 45.0))
                b['F6'] = float(np.clip(0.90 * b['F6'], 0.25, 0.98))
                b['F7'] = float(np.clip(0.88 * b['F7'], 0.05, 0.95))
                b['F8'] = float(np.clip(0.88 * b['F8'], 0.05, 0.95))

        elif self.ip_type == 'sqli':
            if self.last_action == 0:
                # SQLi tool escalates queries over time (more complex payloads)
                b['F13'] = min(20.0, b['F13'] + self.rng.normal(0.3, 0.15))
                b['F14'] = min(1.0,  b['F14'] + 0.03)
                b['F15'] = min(1.0,  b['F15'] + 0.03)
            elif self.last_action == 2:  # Redirected to honeypot
                # Honeypot keeps the SQLi tool engaged; payloads stay malicious instead of vanishing.
                b['F1'] = float(np.clip(0.95 * b['F1'] + self.rng.normal(1.0, 1.0), 6.0, 30.0))
                b['F13'] = float(np.clip(0.98 * b['F13'] + self.rng.normal(0.05, 0.10), 3.5, 20.0))
                b['F14'] = float(np.clip(0.98 * b['F14'] + self.rng.normal(0.01, 0.02), 0.20, 1.0))
                b['F15'] = float(np.clip(0.98 * b['F15'] + self.rng.normal(0.01, 0.02), 0.20, 1.0))
            elif self.last_action == 3:
                b['F1'] = float(np.clip(0.80 * b['F1'] + self.rng.normal(-1.0, 1.0), 3.0, 20.0))
                b['F13'] = float(np.clip(0.90 * b['F13'], 1.0, 20.0))
                b['F14'] = float(np.clip(0.92 * b['F14'], 0.10, 1.0))
                b['F15'] = float(np.clip(0.92 * b['F15'], 0.10, 1.0))
            b['F9'] = max(20.0, b['F9'])

        elif self.ip_type == 'xss':
            if self.last_action == 0:
                # XSS tool escalates payload complexity
                b['F18'] = min(4.0, b['F18'] + self.rng.normal(0.1, 0.05))
                b['F19'] = min(1.0, b['F19'] + 0.01)
            elif self.last_action == 2:  # Redirected to honeypot
                b['F1'] = float(np.clip(0.95 * b['F1'] + self.rng.normal(1.0, 1.0), 6.0, 28.0))
                b['F18'] = float(np.clip(0.98 * b['F18'] + self.rng.normal(0.03, 0.06), 1.5, 4.0))
                b['F19'] = float(np.clip(0.99 * b['F19'] + self.rng.normal(0.0, 0.02), 0.35, 1.0))
            elif self.last_action == 3:
                b['F1'] = float(np.clip(0.82 * b['F1'] + self.rng.normal(-1.0, 1.0), 3.0, 20.0))
                b['F18'] = float(np.clip(0.90 * b['F18'], 0.8, 4.0))
                b['F19'] = float(np.clip(0.92 * b['F19'], 0.20, 1.0))
            b['F9'] = max(40.0, b['F9'])

        elif self.ip_type == 'noisy_normal':
            # Spam-reload is modeled as short repeated bursts, not runaway exponential traffic.
            if self.last_action == 1:
                # RateLimit should calm the user-visible burst down within a few windows.
                self.burst_window = max(0, self.burst_window - 2)
                b['F1'] = float(np.clip(0.45 * b['F1'] + self.rng.normal(7, 2), 8.0, 30.0))
                b['F6'] = float(np.clip(0.85 * b['F6'], 0.08, 0.30))
                b['F7'] = float(np.clip(0.85 * b['F7'], 0.06, 0.25))
                b['F8'] = float(np.clip(0.88 * b['F8'], 0.12, 0.35))
                b['F11'] = float(np.clip(0.70 * b['F11'] + self.rng.normal(6, 2), 6.0, 28.0))
                b['F11_lam'] = int(max(1, round(b['F11'])))
                self.persistence_score *= 0.75
            else:
                if self.burst_window <= 0 and self.rng.random() < 0.22:
                    self.burst_window = int(self.rng.integers(2, 5))

                if self.burst_window > 0:
                    self.burst_window -= 1
                    b['F1'] = float(np.clip(self.rng.normal(42, 7), 24.0, 62.0))
                    b['F6'] = float(np.clip(self.rng.normal(0.24, 0.05), 0.10, 0.40))
                    b['F7'] = float(np.clip(self.rng.normal(0.18, 0.04), 0.08, 0.32))
                    b['F8'] = float(np.clip(self.rng.normal(0.34, 0.05), 0.18, 0.48))
                    b['F11'] = float(np.clip(self.rng.normal(24, 5), 12.0, 36.0))
                    b['F11_lam'] = int(max(1, round(b['F11'])))
                    self.persistence_score = min(1.0, self.persistence_score + 0.15)
                else:
                    b['F1'] = float(np.clip(0.50 * b['F1'] + self.rng.normal(12, 3), 8.0, 34.0))
                    b['F6'] = float(np.clip(0.85 * b['F6'] + self.rng.normal(0.02, 0.02), 0.08, 0.28))
                    b['F7'] = float(np.clip(0.85 * b['F7'] + self.rng.normal(0.01, 0.02), 0.05, 0.24))
                    b['F8'] = float(np.clip(0.85 * b['F8'] + self.rng.normal(0.02, 0.03), 0.10, 0.38))
                    b['F11'] = float(np.clip(0.75 * b['F11'] + self.rng.normal(12, 3), 6.0, 26.0))
                    b['F11_lam'] = int(max(1, round(b['F11'])))
                    self.persistence_score *= 0.90

            b['F9'] = float(np.clip(0.80 * b['F9'] + self.rng.normal(230, 45), 80.0, 800.0))

        # Clip base F1, F2, F5, F9 to physical bounds
        b['F1'] = max(0.0, b['F1'])
        b['F2'] = max(0.5, b.get('F2', 1.0))
        b['F5'] = max(1, min(65535, b['F5']))
        b['F5_lam'] = max(1, b['F5_lam'])
        b['F9'] = max(40.0, b['F9'])

        self._apply_domain_randomization()

    def get_features(self, enable_phase2: bool = True, missing_prob: float = 0.01) -> List[float]:
        """Return current raw feature vector (20D list, FEATURE_CODES order).

        Args:
            enable_phase2: unused (kept for API compat)
            missing_prob: unused (kept for API compat)

        Returns:
            list of 20 raw float values: [F1, F2, ..., F20]
        """
        s = self.state
        return [
            s['F1'],  s['F2'],  s['F3'],  s['F4'],  s['F5'],
            s['F6'],  s['F7'],  s['F8'],  s['F9'],  s['F10'],
            s['F11'], s['F12'], s['F13'], s['F14'], s['F15'],
            s['F16'], s['F17'], s['F18'], s['F19'], s['F20'],
        ]

# ============================================================================
# PER-IP TEMPORAL STATE — memory features for 30D observation
# ============================================================================

class PerIPTemporalState:
    """Per-IP temporal state for the 34D soft-escalation observation.

    Temporal slice:
      [20..23] last_action one-hot (4D)
      [24]     action_hold_norm     — consecutive current-action steps / 15
      [25]     effect_damage_ema    — EMA(F24)
      [26]     effect_trend         — sigmoid(EMA(F24_t - F24_{t-1}))
      [27]     soft_window_fill_norm— len(window_flags) / 15
      [28]     escalation_score_norm— soft evidence score in [0,1]
      [29]     miss_budget_used_norm— miss_count / 3

    Soft session semantics:
      - first Redirect with valid L7 signal starts an escalation session
      - the session accumulates evidence over a 15-window rolling buffer
      - a few non-Redirect windows are tolerated before Block becomes ready
    """

    def __init__(self):
        self.last_action: int = 0
        self.action_hold_steps: int = 0
        self.cumulative_damage: float = 0.0
        self.damage_ema: float = 0.0
        self.damage_trend: float = 0.0
        self.clean_streak: int = 0
        self.effect_prev: float = 0.0
        self.session_active: bool = False
        self.session_age: int = 0
        self.window_len: int = 0
        self.window_flags = deque(maxlen=SOFT_SESSION_WINDOW)
        self.redirect_hits: int = 0
        self.presence_hits: int = 0
        self.honeypot_hits: int = 0
        self.miss_count: int = 0
        self.pressure_mean: float = 0.0
        self.escalation_score: float = 0.0
        self.block_ready_latched: bool = False
        self.no_presence_streak: int = 0
        self._staged_l7_signal: float = 0.0

    def _reset_soft_session(self):
        self.session_active = False
        self.session_age = 0
        self.window_len = 0
        self.window_flags.clear()
        self.redirect_hits = 0
        self.presence_hits = 0
        self.honeypot_hits = 0
        self.miss_count = 0
        self.pressure_mean = 0.0
        self.escalation_score = 0.0
        self.block_ready_latched = False
        self.no_presence_streak = 0

    def _recompute_soft_session(self):
        self.window_len = len(self.window_flags)
        if self.window_len <= 0:
            self.redirect_hits = 0
            self.presence_hits = 0
            self.honeypot_hits = 0
            self.miss_count = 0
            self.pressure_mean = 0.0
            self.escalation_score = 0.0
            return

        self.redirect_hits = int(sum(1 for w in self.window_flags if w['is_redirect']))
        self.presence_hits = int(sum(1 for w in self.window_flags if w['has_presence']))
        self.honeypot_hits = int(sum(1 for w in self.window_flags if w['has_honeypot']))
        self.miss_count = int(sum(1 for w in self.window_flags if w['is_miss']))
        self.pressure_mean = float(np.clip(
            np.mean([float(w['pressure']) for w in self.window_flags]),
            0.0, 1.0
        ))

        redirect_ratio = self.redirect_hits / self.window_len
        presence_ratio = self.presence_hits / self.window_len
        honeypot_ratio = self.honeypot_hits / self.window_len
        miss_ratio = self.miss_count / MISS_BUDGET
        score = (
            0.30 * redirect_ratio +
            0.30 * honeypot_ratio +
            0.25 * presence_ratio +
            0.15 * self.pressure_mean -
            0.15 * miss_ratio
        )
        self.escalation_score = float(np.clip(score, 0.0, 1.0))

    def _maybe_latch_block_ready(self, has_presence: bool):
        if not self.session_active or self.block_ready_latched:
            return
        if (
            self.window_len >= BLOCK_READY_MIN_WINDOW and
            self.redirect_hits >= BLOCK_READY_MIN_REDIRECT and
            self.presence_hits >= BLOCK_READY_MIN_PRESENCE and
            self.honeypot_hits >= BLOCK_READY_MIN_HONEYPOT and
            self.miss_count <= MISS_BUDGET and
            has_presence and
            self.escalation_score >= ESCALATION_SCORE_BLOCK_THRESHOLD
        ):
            self.block_ready_latched = True

    def stage_action(self, action: int, l7_signal: float = 0.0):
        """Record the chosen action so the next observation knows what is being held."""
        if action == self.last_action:
            self.action_hold_steps += 1
        else:
            self.action_hold_steps = 1
        self.last_action = int(action)
        self._staged_l7_signal = float(np.clip(l7_signal, 0.0, 1.0))
        if (
            self.last_action == 2 and
            self._staged_l7_signal >= SESSION_START_L7_THRESHOLD and
            not self.session_active
        ):
            self.session_active = True
            self.session_age = 0
            self.window_flags.clear()
            self.window_len = 0
            self.redirect_hits = 0
            self.presence_hits = 0
            self.honeypot_hits = 0
            self.miss_count = 0
            self.pressure_mean = 0.0
            self.escalation_score = 0.0
            self.block_ready_latched = False
            self.no_presence_streak = 0

    def observe_effect(self, effect: Optional[List[float]], ema_alpha: float = 0.3):
        """Update effect-driven counters from [F21, F22, F23, F24]."""
        effect = list(effect or [0.0, 0.0, 0.0, 0.0])
        if len(effect) < 4:
            effect = (effect + [0.0, 0.0, 0.0, 0.0])[:4]
        f21, f22, f23, f24 = [float(np.clip(v, 0.0, 1.0)) for v in effect[:4]]
        delta = f24 - self.effect_prev
        self.damage_ema = ema_alpha * f24 + (1 - ema_alpha) * self.damage_ema
        self.damage_trend = ema_alpha * delta + (1 - ema_alpha) * self.damage_trend
        self.effect_prev = f24
        self.cumulative_damage += f24

        has_presence = bool(f23 >= PRESENCE_RATIO_THRESHOLD)
        has_honeypot = bool(f22 >= HONEYPOT_RATIO_THRESHOLD and has_presence)
        is_clean = bool(
            f23 < PRESENCE_RATIO_THRESHOLD or
            (f24 <= SERVICE_DAMAGE_CLEAN_THRESHOLD and f21 <= 0.10 and f22 <= 0.10)
        )
        if is_clean:
            self.clean_streak += 1
        else:
            self.clean_streak = 0

        if self.session_active:
            if self.last_action == 3:
                if self.block_ready_latched:
                    # Block at the right time → session completed, reset cleanly
                    self._reset_soft_session()
                    return
                # v13: Premature Block → record as heavy miss, do NOT reset session.
                # Resetting was causing a death loop: model tries Block early →
                # session resets → block_ready never fires → model never sees late reward
                # → learns "Redirect forever". Now premature Block just costs a miss slot.

            # v13: When premature Block is active, attacker traffic drops (iptables effect)
            # → F23 falls below PRESENCE_RATIO_THRESHOLD → is_clean=True → clean_streak++
            # This causes session to reset via clean_streak path, defeating Fix A.
            # Suppress clean_streak here: "clean" appearance was caused by us, not attacker.
            if self.last_action == 3 and not self.block_ready_latched:
                self.clean_streak = 0

            pressure = float(np.clip(max(f24, self.damage_ema), 0.0, 1.0))
            self.window_flags.append({
                'is_redirect': bool(self.last_action == 2),
                'has_presence': has_presence,
                'has_honeypot': has_honeypot,
                # v13: premature Block counts as miss (same as Allow/RateLimit during session)
                'is_miss': bool(self.last_action in (0, 1, 3) and has_presence and not self.block_ready_latched),
                'pressure': pressure,
            })
            self.session_age += 1
            self._recompute_soft_session()
            self._maybe_latch_block_ready(has_presence)

            if (not has_presence) and self._staged_l7_signal < SESSION_START_L7_THRESHOLD:
                self.no_presence_streak += 1
            else:
                self.no_presence_streak = 0

            if (
                self.clean_streak >= SESSION_RESET_CLEAN_STREAK or
                self.no_presence_streak >= SESSION_RESET_NO_PRESENCE_STREAK
            ):
                self._reset_soft_session()

    def update(self, action: int, effect: Any,
               attack_threshold: float = 0.15, ema_alpha: float = 0.3,
               l7_signal: float = 0.0):
        """Backward-compatible wrapper: stage action, then observe effect/damage."""
        self.stage_action(action, l7_signal=l7_signal)
        if isinstance(effect, (list, tuple, np.ndarray)):
            self.observe_effect(list(effect), ema_alpha=ema_alpha)
            return
        # Legacy callers may still pass a scalar damage; approximate a present-service effect.
        f24 = float(np.clip(effect, 0.0, 1.0))
        presence = 1.0 if f24 > SERVICE_DAMAGE_CLEAN_THRESHOLD else 0.0
        self.observe_effect([0.0, 0.0, presence, f24], ema_alpha=ema_alpha)

    def to_obs(self) -> list:
        """Return 10D normalized temporal feature vector, all in [0,1]."""
        one_hot = [0.0, 0.0, 0.0, 0.0]
        one_hot[self.last_action] = 1.0

        return one_hot + [
            min(self.action_hold_steps / ACTION_HOLD_NORM_STEPS, 1.0),
            min(self.damage_ema, 1.0),
            1.0 / (1.0 + np.exp(-10.0 * self.damage_trend)),
            min(self.window_len / SOFT_SESSION_WINDOW, 1.0),
            min(self.escalation_score, 1.0),
            min(self.miss_count / MISS_BUDGET, 1.0),
        ]

    def reset(self):
        """Reset to initial state (new episode)."""
        self.__init__()


# ============================================================================
# EFFECT DYNAMICS SIMULATION (4D closed-loop feedback)
# ============================================================================

def simulate_effect(action: int, sensor_raw: List[float],
                    rng: np.random.Generator) -> List[float]:
    """
    Simulate 4D effect features [F21, F22, F23, F24] for given (action, sensor).

    Mirrors real nginx topology behavior (delayed 1 step — effect_t used at obs_{t+1}):
      Allow:    webserver reachable  → F21↑ F22↓ F23=1 F24↑
      Redirect: honeypot absorbs     → F21↓ F22↑ F23=1 F24↓
      Block:    iptables DROP pre-nginx → F21=0 F22=0 F23=0 F24≈0
      RateLimit: throttled, web still up → F23 partial, F24 reduced

    F21 = WebHitRatio       fraction of hits reaching real webserver
    F22 = HoneypotHitRatio  fraction of hits reaching honeypot
    F23 = PresenceRatio     1.0 if any hit in window, else 0.0
    F24 = ServiceDamage     composite: attack_conf × web exposure
    """
    f1   = sensor_raw[0];  f2  = sensor_raw[1]
    f5   = sensor_raw[4];  f11 = sensor_raw[10]
    sqli = max(sensor_raw[11:17]); xss = max(sensor_raw[17:20])
    attack_conf = float(min(max(
        min(f1 / 200.0, 1.0), min(f2 / 10.0, 1.0),
        min(f5 / 50.0, 1.0) * min(f11 / 50.0, 1.0),
        min((sqli + xss) / 2.0, 1.0),
    ), 1.0))

    if action == 0:    # Allow — webserver gets all traffic
        f21 = float(np.clip(rng.normal(0.92, 0.05), 0.80, 1.0))
        f22 = float(np.clip(rng.normal(0.03, 0.02), 0.0,  0.10))
        f23 = 1.0
    elif action == 1:  # RateLimit — web still up, fewer requests get through
        f21 = float(np.clip(rng.normal(0.65, 0.10), 0.40, 0.85))
        f22 = float(np.clip(rng.normal(0.05, 0.03), 0.0,  0.15))
        f23 = float(np.clip(rng.normal(0.65, 0.10), 0.40, 0.90))
    elif action == 2:  # Redirect — traffic diverted to honeypot
        f21 = float(np.clip(rng.normal(0.05, 0.03), 0.0,  0.15))
        f22 = float(np.clip(rng.normal(0.88, 0.06), 0.70, 1.0))
        f23 = 1.0
    else:              # Block — iptables DROP, nginx sees nothing
        f21 = 0.0; f22 = 0.0; f23 = 0.0

    f24 = float(min(0.7 * attack_conf * f21 + 0.3 * attack_conf * f23 * (1.0 - f22), 1.0))
    return [round(f21, 4), round(f22, 4), round(f23, 4), round(f24, 4)]


# ============================================================================
# REPLAY BEHAVIOR — reads real NIDS data from training_data.jsonl
# ============================================================================

import json as _json
REPLAY_MAX_GAP_SECONDS = 2.5


def _normalize_effect_4d(value: Any) -> Optional[List[float]]:
    """Normalize stored effect vectors to a clipped 4D float list."""
    if not isinstance(value, (list, tuple, np.ndarray)) or len(value) < 4:
        return None
    return [float(np.clip(v, 0.0, 1.0)) for v in list(value[:4])]


def _build_replay_sequences(records: List[dict]) -> List[List[dict]]:
    """Group records by src_ip/session and keep temporal order inside each sequence."""
    grouped: Dict[str, List[dict]] = {}
    for rec in records:
        session_key = str(rec.get('session_id') or rec.get('src_ip') or 'unknown')
        grouped.setdefault(session_key, []).append(rec)

    sequences: List[List[dict]] = []
    for recs in grouped.values():
        recs.sort(
            key=lambda rec: (
                float(rec.get('window_ts', rec.get('timestamp', 0.0))),
                float(rec.get('timestamp', 0.0)),
            )
        )
        current_seq: List[dict] = []
        prev_ts: Optional[float] = None
        prev_label: Optional[str] = None
        for rec in recs:
            current_ts = float(rec.get('window_ts', rec.get('timestamp', 0.0)))
            label = str(rec.get('label', 'normal'))
            split_here = (
                prev_ts is not None and (
                    (current_ts - prev_ts) > REPLAY_MAX_GAP_SECONDS or
                    label != prev_label
                )
            )
            if split_here and current_seq:
                sequences.append(current_seq)
                current_seq = []
            current_seq.append(rec)
            prev_ts = current_ts
            prev_label = label
        if current_seq:
            sequences.append(current_seq)

    sequences.sort(
        key=lambda seq: (
            float(seq[0].get('window_ts', seq[0].get('timestamp', 0.0))),
            str(seq[0].get('src_ip', 'unknown')),
        )
    )
    return sequences

class ReplayBehavior:
    """Replay real NIDS features thay cho MockIPBehavior.

    Đọc training_data.jsonl (được thu thập bằng infer.py --label),
    cung cấp cùng interface với MockIPBehavior để IDSDefenseEnv
    có thể swap sang mode="replay" mà không cần thay đổi logic khác.

    Interface:
        get_features()             → List[float] (20D raw)
        apply_closed_loop_effect() → (no-op trong replay — features đến từ data thật)
        step_forward()             → advance to next record
        persistence_score          → float (luôn = 0.0 trong replay)
        burst_window               → int (luôn = 0 trong replay)
    """

    # Reward signal mặc định theo label (dùng khi train với ReplayBehavior)
    LABEL_DAMAGE = {
        'normal':       0.0,
        'benign':       0.0,
        'noisy_normal': 0.1,
        'scan':          0.7,
        'syn_flood':     0.9,
        'brute_force':   0.6,
        'brute_force_ka': 0.6,
        'sqli':          0.8,
        'xss':           0.8,
    }

    def __init__(self, sequences: list, rng: np.random.Generator = None):
        """
        Args:
            sequences: list of ordered replay sequences, each sequence is a list of
                       {features, label, src_ip, window_ts, effect_4d, final_action, ...}
            rng: numpy RNG (dùng để shuffle)
        """
        if not sequences:
            raise ValueError("ReplayBehavior cần ít nhất 1 replay sequence")
        self.sequences = sequences
        self.rng = rng if rng is not None else np.random.default_rng()
        self.seq_order = list(range(len(self.sequences)))
        self.seq_idx = 0
        self.step_idx = 0
        self.persistence_score = 0.0
        self.burst_window = 0
        self._shuffle_sequences()

    def _shuffle_sequences(self):
        self.rng.shuffle(self.seq_order)
        self.seq_idx = 0
        self.step_idx = 0

    @property
    def current_record(self) -> dict:
        seq = self.sequences[self.seq_order[self.seq_idx]]
        return seq[self.step_idx]

    @property
    def ip_type(self) -> str:
        return str(self.current_record.get('label', 'normal'))

    @property
    def src_ip(self) -> str:
        return str(self.current_record.get('src_ip', 'replay_ip'))

    def get_features(self) -> list:
        feats = self.current_record.get('features', [0.0] * 20)
        if len(feats) != 20:
            feats = (list(feats) + [0.0] * 20)[:20]
        return list(feats)

    def get_effect_prev(self) -> Optional[List[float]]:
        return _normalize_effect_4d(self.current_record.get('effect_prev_4d'))

    def get_effect(self) -> Optional[List[float]]:
        return _normalize_effect_4d(self.current_record.get('effect_4d'))

    def get_final_action(self) -> Optional[int]:
        action = self.current_record.get('final_action')
        try:
            action = int(action)
        except (TypeError, ValueError):
            return None
        return action if 0 <= action <= 3 else None

    def get_effect_source(self) -> str:
        return str(self.current_record.get('effect_source', 'legacy'))

    def apply_closed_loop_effect(self, action: int):
        # No-op: features đến từ data thật, không simulate closed-loop
        pass

    def step_forward(self):
        seq = self.sequences[self.seq_order[self.seq_idx]]
        self.step_idx += 1
        if self.step_idx < len(seq):
            return
        self.step_idx = 0
        self.seq_idx += 1
        if self.seq_idx >= len(self.seq_order):
            self._shuffle_sequences()


def _load_replay_records(training_data_file: str) -> list:
    """Load training_data.jsonl → ordered replay sequences."""
    records = []
    with open(training_data_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = _json.loads(line)
                feats = rec.get('features')
                if not isinstance(feats, list) or len(feats) != 20:
                    continue
                ts = float(rec.get('timestamp', 0.0) or 0.0)
                window_ts = rec.get('window_ts', ts)
                try:
                    window_ts = float(window_ts)
                except (TypeError, ValueError):
                    window_ts = ts
                records.append({
                    **rec,
                    'timestamp': ts,
                    'window_ts': window_ts,
                    'effect_prev_4d': _normalize_effect_4d(rec.get('effect_prev_4d')),
                    'effect_4d': _normalize_effect_4d(rec.get('effect_4d')),
                })
            except Exception:
                continue
    if not records:
        raise ValueError(f"Không có record hợp lệ trong {training_data_file}")
    sequences = _build_replay_sequences(records)
    if not sequences:
        raise ValueError(f"Không build được replay sequence hợp lệ từ {training_data_file}")
    return sequences


# ============================================================================
# GYMNASIUM ENVIRONMENT WITH CLOSED-LOOP CONTROL
# ============================================================================

class IDSDefenseEnv(gym.Env):
    """
    TRUE RL CONTROL SYSTEM for IDS Defense.

    Reward = -(network_damage + action_cost)
    State transition driven by action (closed-loop)

    Observation: [PR, SA, DP, PL, FR, CS] (frozen order)
    Action: Discrete(4) - [0=Allow, 1=RateLimit, 2=Redirect, 3=Block]
    Episode: 120 steps
    """

    metadata = {'render_modes': []}

    def __init__(self, seed=None, enable_phase2=True, missing_prob=0.08, drift_max=0.35,
                 mode='mock', training_data=None, session_block_size: int = 0):
        """Initialize IDS Defense Environment (20D observation).

        Args:
            seed: Random seed
            enable_phase2: Enable concept drift / missing data simulation
            missing_prob: Probability of missing feature (PHASE 2)
            drift_max: Max concept drift factor (PHASE 2)
            mode: 'mock' (default) | 'replay' — use real NIDS data for fine-tuning
            training_data: Path to training_data.jsonl (required when mode='replay')
            session_block_size: If >0, keep same IP for N consecutive steps before
                advancing (session scheduling). 0=round-robin (default).
                With 16 IPs and session_block_size=20, one episode covers each IP
                exactly 20 steps (16×20=320 = episode_length).
        """
        super().__init__()

        self.rng = np.random.default_rng(seed)
        self.mode = mode

        # 34D observation space — 20D NIDS features + 10D per-IP temporal + 4D effect
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(34,), dtype=np.float32)
        self.action_space = spaces.Discrete(4)

        # Episode config
        # 320 steps: 16 IPs × 20 steps/IP → redirect_age can exceed REDIRECT_PERSIST_STEPS=15
        # Previously 120 → 7.5 steps/IP → escalation never triggered during training
        self.episode_length = 320
        self.current_step = 0
        self.cumulative_damage = 0.0  # Track episodic damage

        # Session-block scheduling — keep same IP for N consecutive steps.
        # 0 = round-robin (default). With 16 IPs and session_block_size=20,
        # one episode covers each IP exactly 20 steps (16×20=320=episode_length).
        self.session_block_size = session_block_size
        self.current_session_step = 0

        # PHASE 2: Config flags
        self.enable_phase2 = enable_phase2
        self.missing_prob = missing_prob
        self.drift_max = drift_max

        if mode == 'replay':
            if training_data is None:
                raise ValueError("mode='replay' requires training_data path")
            records = _load_replay_records(training_data)
            # Single ReplayBehavior that cycles through all real records
            self._replay = ReplayBehavior(records, rng=self.rng)
            self.ip_list = ['replay_ip']
            self.ip_types = [self._replay.ip_type]
            self.ip_behaviors = {'replay_ip': self._replay}
            self.current_ip_idx = 0
        else:
            # IP configuration — increased L7 persistence mix:
            #   Allow: benign (25%) | RateLimit: noisy_normal (12.5%)
            #   Redirect: brute_force×2 + brute_force_ka×2 + sqli×2 + xss×2 = 50%
            #   Block: scan (6.25%) + syn_flood (6.25%) = 12.5%
            # Rationale: L7 IPs doubled so agent sees more long-running Redirect episodes
            # → more gradient signal for Redirect→Block phase transition.
            self.ip_list = [
                '192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.15',  # benign (4)
                '192.168.1.13', '192.168.1.14',                                   # noisy_normal (2)
                '10.0.0.100',                                                       # scan (1)
                '10.0.0.102',                                                       # syn_flood (1)
                '10.0.0.103', '10.0.0.107',                                        # brute_force std HTTP (2)
                '10.0.0.104', '10.0.0.108',                                        # brute_force keep-alive (2)
                '10.0.0.105', '10.0.0.109',                                        # sqli (2)
                '10.0.0.106', '10.0.0.110',                                        # xss (2)
            ]
            self.ip_types = [
                'benign', 'benign', 'benign', 'benign',  # 25% → Allow
                'noisy_normal', 'noisy_normal',           # 12.5% → RateLimit
                'scan',                                   # 6.25% → Block
                'syn_flood',                              # 6.25% → Block
                'brute_force',    'brute_force',          # 12.5% → Redirect (standard HTTP)
                'brute_force_ka', 'brute_force_ka',       # 12.5% → Redirect (keep-alive)
                'sqli',           'sqli',                 # 12.5% → Redirect
                'xss',            'xss',                  # 12.5% → Redirect
            ]

            # Create IP behaviors
            self.ip_behaviors = {}
            self.current_ip_idx = 0

            self._init_behaviors()

        # Per-IP temporal state (10D memory features)
        self.ip_temporal_state: Dict[str, PerIPTemporalState] = {
            ip: PerIPTemporalState() for ip in self.ip_list
        }

        # Per-IP effect state — 4D effect_{t-1}, used in obs_t (delayed 1 step)
        self.ip_effect_state: Dict[str, List[float]] = {
            ip: [0.0, 0.0, 0.0, 0.0] for ip in self.ip_list
        }

    def _init_behaviors(self):
        """Initialize all IP behaviors.

        PHASE 2 FIX: Spawn per-IP RNG using integers() to avoid private API and excessive synchronization.
        """
        # Generate independent seeds for each IP behavior
        per_ip_seeds = self.rng.integers(0, 2**32 - 1, size=len(self.ip_list), dtype=np.uint32)

        self.ip_behaviors = {
            ip: MockIPBehavior(ip_type, rng=np.random.default_rng(int(seed)))
            for ip, ip_type, seed in zip(self.ip_list, self.ip_types, per_ip_seeds)
        }

    def reset(self, seed=None, options=None):
        """Reset environment."""
        if seed is not None:
            self.rng = np.random.default_rng(seed)

        super().reset(seed=seed)

        self.current_step = 0
        self.current_ip_idx = 0
        self.current_session_step = 0
        self.cumulative_damage = 0.0

        if self.mode == 'replay':
            # Replay: just update ip_type from current record
            self.ip_types = [self._replay.ip_type]
        else:
            # Mock: re-initialize all MockIPBehaviors with fresh RNG seeds
            self._init_behaviors()

        # Reset per-IP temporal state (fresh memory each episode)
        self.ip_temporal_state = {
            ip: PerIPTemporalState() for ip in self.ip_list
        }

        # Reset effect state — episode starts with no prior effect
        self.ip_effect_state = {
            ip: [0.0, 0.0, 0.0, 0.0] for ip in self.ip_list
        }

        # Get initial observation
        obs, _ = self._get_obs_and_info()
        return obs, {}

    def _normalize_features(self, features: List[float]) -> np.ndarray:
        """Normalize 20D raw feature list → [0,1]^20 ndarray."""
        return normalize_observation(features)

    def _apply_concept_drift(self, features: List[float], ip_type: str) -> List[float]:
        """Apply concept drift to F1 (PacketRate) and F9 (AvgPayloadSize) in final 20% of episode.

        Only affects benign traffic types.
        """
        if not self.enable_phase2:
            return features

        if ip_type not in ('benign', 'noisy_normal'):
            return features

        drift_start_step = int(self.episode_length * 0.80)
        if self.current_step < drift_start_step:
            return features

        drift_duration = self.episode_length - drift_start_step
        if drift_duration <= 0:
            drift_progress = 1.0
        else:
            drift_progress = (self.current_step - drift_start_step) / drift_duration
        drift_progress = float(np.clip(drift_progress, 0.0, 1.0))
        drift_factor = 1.0 + (drift_progress * self.drift_max)

        features = list(features)  # copy
        features[0] *= drift_factor   # F1 PacketRate
        features[8] *= drift_factor   # F9 AvgPayloadSize
        return features

    def _resolve_prev_effect(self, current_ip: str, behavior) -> List[float]:
        """Return the delayed effect vector used in the current observation."""
        if self.mode == 'replay':
            replay_prev = behavior.get_effect_prev()
            if replay_prev is not None:
                self.ip_effect_state[current_ip] = replay_prev
        return list(self.ip_effect_state[current_ip])

    def _resolve_effect_after_action(self, action: int, sensor_before: List[float], behavior) -> List[float]:
        """Return effect_t for reward/state update after taking `action`."""
        if self.mode == 'replay':
            replay_effect = behavior.get_effect()
            replay_action = behavior.get_final_action()
            replay_source = behavior.get_effect_source()
            if replay_effect is not None and replay_action == action and replay_source == 'post_action':
                return replay_effect
        return simulate_effect(action, sensor_before, self.rng)

    def _get_obs_and_info(self) -> Tuple[np.ndarray, Dict]:
        """Get 34D observation for current IP: 20D sensor + 10D temporal + 4D effect_{t-1}."""
        current_ip = self.ip_list[self.current_ip_idx]
        behavior = self.ip_behaviors[current_ip]
        # In replay mode, ip_type comes from the current record dynamically
        ip_type = behavior.ip_type if self.mode == 'replay' else self.ip_types[self.current_ip_idx]

        raw_features = behavior.get_features()
        raw_features = self._apply_concept_drift(raw_features, ip_type)

        # Normalize 20D sensor features for agent observation
        obs_base = self._normalize_features(raw_features)

        # Apply missing_prob as observation noise on 20D sensor features only.
        # missing_prob masks random sensor indices to 0 — simulates dropped/corrupt packets.
        # Does NOT affect raw_features used for reward/damage calculation.
        if self.missing_prob > 0.0:
            mask = self.rng.random(20) >= self.missing_prob
            obs_base = obs_base * mask.astype(np.float32)

        # 10D temporal state
        temporal = self.ip_temporal_state[current_ip].to_obs()

        # 4D effect_{t-1} — delayed feedback from previous step's action
        effect = self._resolve_prev_effect(current_ip, behavior)

        obs = np.concatenate([
            obs_base,
            np.array(temporal, dtype=np.float32),
            np.array(effect,   dtype=np.float32),
        ])

        if self.current_step < 48:
            phase = 'baseline'
        elif self.current_step < 96:
            phase = 'mid'
        else:
            phase = 'drift'

        info = {
            'ip': current_ip,
            'ip_type': ip_type,
            'features': raw_features,
            'normalized': obs,
            'temporal_state': temporal,
            'effect_state': effect,
            'persistence_score': behavior.persistence_score,
            'burst_window': behavior.burst_window,
            'phase': phase,
            'scenario': f"{ip_type}_{phase}",
        }
        return obs, info

    def _compute_reward(self, action: int, features_before: List[float], current_ip: str,
                        effect_prev: Optional[List[float]] = None,
                        effect_after: Optional[List[float]] = None) -> float:
        """
        Persistence-aware reward:
          base_reward = action_bonus - action_cost - 0.12 * F24_t
          + stability / anti-oscillation shaping
          + persistent honeybot escalation shaping
        """
        damage_before = compute_network_damage(features_before)
        action_cost = compute_action_cost(action)
        f24_after = (
            float(effect_after[3])
            if (effect_after is not None and len(effect_after) >= 4)
            else damage_before
        )
        action_bonus = compute_action_bonus(action, features_before, damage_before)
        base_reward = action_bonus - action_cost - 0.12 * f24_after

        ts = self.ip_temporal_state[current_ip]
        _prev_presence = float(effect_prev[2]) if (effect_prev and len(effect_prev) >= 3) else 0.0
        attack_signals = compute_attack_signals(features_before)
        l7_signal = attack_signals['l7_presence']
        session_active = bool(ts.session_active)
        window_len = int(ts.window_len)
        block_ready = bool(ts.block_ready_latched)

        oscillation_penalty = 0.0
        stability_bonus = 0.0
        if action != ts.last_action and action < ts.last_action:
            # Penalize backing off while service still shows live pressure.
            if ts.damage_ema > SERVICE_DAMAGE_CLEAN_THRESHOLD and _prev_presence >= PRESENCE_RATIO_THRESHOLD:
                oscillation_penalty = -0.05

        # Context-aware stability bonus: keep legacy shaping for non-escalation behavior.
        if ts.action_hold_steps >= 1:
            if action == 0 and ts.damage_ema <= SERVICE_DAMAGE_CLEAN_THRESHOLD:
                stability_bonus = 0.01
            elif action == 1 and ts.damage_ema < 0.15:
                stability_bonus = 0.01
            elif action == 3 and ts.damage_ema > SERVICE_DAMAGE_CLEAN_THRESHOLD:
                stability_bonus = 0.01

        if session_active and not block_ready and action == 2:
            stability_bonus = max(stability_bonus, 0.05)  # v13: 0.02→0.05 — stronger incentive to hold Redirect

        if (
            session_active and
            _prev_presence >= PRESENCE_RATIO_THRESHOLD and
            action in (0, 1)
        ):
            oscillation_penalty += -0.15 if window_len >= 12 else -0.10

        ramp_bonus = 0.0
        if (
            session_active and
            not block_ready and
            window_len >= 12 and
            ts.escalation_score >= ESCALATION_SCORE_RAMP_THRESHOLD
        ):
            if window_len in (12, 13):
                ramp_block, ramp_redirect = 0.08, -0.03
            elif window_len == 14:
                ramp_block, ramp_redirect = 0.15, -0.06
            else:
                ramp_block = ramp_redirect = 0.0

            if action == 3:
                ramp_bonus = ramp_block
            elif action == 2:
                ramp_bonus = ramp_redirect

        persistent_bonus = 0.0
        if block_ready and _prev_presence >= PRESENCE_RATIO_THRESHOLD:
            if action == 3:
                persistent_bonus += 0.45
            elif action == 2:
                persistent_bonus -= 0.35
            else:
                persistent_bonus -= 0.40

        # Premature Block penalty: discourage blocking before evidence is sufficient.
        # Only skip when already in the ramp zone (window 12-14 + score >= threshold),
        # where ramp_bonus already guides the agent toward Block.
        premature_block_penalty = 0.0
        in_ramp_zone = (
            session_active and not block_ready and
            window_len >= 12 and
            ts.escalation_score >= ESCALATION_SCORE_RAMP_THRESHOLD
        )
        if session_active and not block_ready and action == 3 and not in_ramp_zone:
            premature_block_penalty = -0.20

        total_reward = base_reward + oscillation_penalty + stability_bonus + ramp_bonus + persistent_bonus + premature_block_penalty
        return float(np.clip(total_reward, -1.0, 1.0))

    def step(self, action) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """Execute one step with delayed closed-loop effects (34D obs)."""
        action = int(action)
        current_ip = self.ip_list[self.current_ip_idx]
        behavior   = self.ip_behaviors[current_ip]
        ip_type    = behavior.ip_type if self.mode == 'replay' else self.ip_types[self.current_ip_idx]

        prev_effect = self._resolve_prev_effect(current_ip, behavior)

        # Raw 20D features BEFORE action
        raw_before = behavior.get_features()
        raw_before = self._apply_concept_drift(raw_before, ip_type)

        # Apply closed-loop effect
        behavior.apply_closed_loop_effect(action)

        # Raw 20D features AFTER action
        raw_after = behavior.get_features()
        raw_after = self._apply_concept_drift(raw_after, ip_type)

        # Simulate effect_t (delayed — stored for obs_{t+1})
        effect_t = self._resolve_effect_after_action(action, raw_before, behavior)
        self.ip_effect_state[current_ip] = effect_t

        reward = self._compute_reward(
            action,
            raw_before,
            current_ip,
            effect_prev=prev_effect,
            effect_after=effect_t,
        )

        sensor_damage = compute_network_damage(raw_after)
        service_damage = float(effect_t[3])
        self.cumulative_damage += service_damage

        # Snapshot temporal state BEFORE stage_action mutates it — used for dynamic metrics.
        _ts_before = self.ip_temporal_state[current_ip]
        temporal_snapshot = {
            'block_ready_before':      bool(_ts_before.block_ready_latched),
            'session_active_before':   bool(_ts_before.session_active),
            'escalation_score_before': float(_ts_before.escalation_score),
            'window_len_before':       int(_ts_before.window_len),
            'action_hold_steps_before':int(_ts_before.action_hold_steps),
        }

        # Temporal state now tracks the soft escalation session directly.
        l7_signal_before = compute_attack_signals(raw_before)['l7_presence']
        self.ip_temporal_state[current_ip].stage_action(action, l7_signal=l7_signal_before)
        self.ip_temporal_state[current_ip].observe_effect(effect_t)

        behavior.step_forward()

        if self.session_block_size > 0:
            self.current_session_step += 1
            if self.current_session_step >= self.session_block_size:
                self.current_session_step = 0
                self.current_ip_idx = (self.current_ip_idx + 1) % len(self.ip_list)
        else:
            self.current_ip_idx = (self.current_ip_idx + 1) % len(self.ip_list)
        self.current_step  += 1

        done = self.current_step >= self.episode_length
        obs, info = self._get_obs_and_info()

        # Step info must describe the IP that was just acted on, not the next IP.
        info['acted_ip'] = current_ip
        info['acted_ip_type'] = ip_type
        info['acted_features_before'] = raw_before
        info.update(temporal_snapshot)
        info['acted_features_after'] = raw_after
        info['step_damage'] = service_damage
        info['sensor_damage'] = sensor_damage
        info['effect_prev'] = prev_effect
        info['effect'] = effect_t
        info['cumulative_damage'] = self.cumulative_damage
        info['reward_breakdown'] = {
            'service_damage': -service_damage,
            'action_cost': -compute_action_cost(action),
            'total': reward,
        }
        return obs, reward, done, False, info

    def render(self):
        pass

    def close(self):
        pass


# ============================================================================
# SELF-TEST: Verify bounds before training
# ============================================================================

def run_self_test(n_samples: int = 500, verbose: bool = True) -> bool:
    """Quick self-test to verify 30D env bounds before training."""
    if verbose:
        print("\n" + "="*60)
        print("ENV_IDS SELF-TEST (34D): Verifying Bounds")
        print("="*60)

    env = IDSDefenseEnv(seed=42)
    all_passed = True

    # Test 1: observation_space is 34D (20D sensor + 10D temporal + 4D effect)
    obs_dim = env.observation_space.shape[0]
    if verbose:
        print(f"[TEST 1] Observation dim: {obs_dim}", end=" ")
        print("[PASS]" if obs_dim == 34 else "[FAIL]")
    if obs_dim != 34:
        all_passed = False

    # Test 2: Damage bounds [0, 1] for all IP types
    damages = []
    for ip in env.ip_list:
        raw = env.ip_behaviors[ip].get_features()
        assert len(raw) == 20, f"Expected 20 features, got {len(raw)}"
        d = compute_network_damage(raw)
        damages.append(d)
        if not (0.0 <= d <= 1.0):
            if verbose:
                print(f"[FAIL] Damage OOB for {ip}: {d}")
            all_passed = False

    if verbose:
        print(f"[TEST 2] Damage bounds: [{min(damages):.4f}, {max(damages):.4f}]", end=" ")
        print("[PASS]" if 0 <= min(damages) and max(damages) <= 1 else "[FAIL]")

    # Test 3: Reward bounds [-1, +1]  (FIX: was [-1,0], now allows positive rewards)
    rewards = []
    for _ in range(n_samples):
        obs, _ = env.reset()
        assert obs.shape == (34,), f"obs shape {obs.shape}"
        action = env.action_space.sample()
        _, r, _, _, _ = env.step(action)
        rewards.append(r)
        if not (-1.0 <= r <= 1.0):
            if verbose:
                print(f"[FAIL] Reward OOB: {r}")
            all_passed = False

    if verbose:
        print(f"[TEST 3] Reward bounds: [{min(rewards):.4f}, {max(rewards):.4f}]", end=" ")
        print("[PASS]" if -1 <= min(rewards) and max(rewards) <= 1 else "[FAIL]")

    # Test 4: No NaN/inf
    has_nan_inf = any(np.isnan(r) or np.isinf(r) for r in rewards)
    if verbose:
        print(f"[TEST 4] No NaN/Inf in rewards", end=" ")
        print("[PASS]" if not has_nan_inf else "[FAIL]")
    if has_nan_inf:
        all_passed = False

    # Test 5: Observation bounds [0, 1]
    obs_vals = []
    for _ in range(100):
        obs, _ = env.reset()
        for _ in range(10):
            obs, _, done, _, _ = env.step(env.action_space.sample())
            obs_vals.extend(obs.tolist())
            if done:
                break
    o_min, o_max = min(obs_vals), max(obs_vals)
    obs_valid = (0.0 <= o_min) and (o_max <= 1.0)
    if verbose:
        print(f"[TEST 5] Obs bounds: [{o_min:.4f}, {o_max:.4f}]", end=" ")
        print("[PASS]" if obs_valid else "[FAIL]")
    if not obs_valid:
        all_passed = False

    # Test 6: Noisy normal 20D — burst F1, no SQLi/XSS → low-moderate damage (not high)
    noisy_20d = [
        200.0, 1.4, 0.25, 0.05, 3,
        0.15,  0.45, 0.25, 250.0, 1.8,
        22.0,  0.0,  0.0,  0.0,  0.0,
        0.0,   0.0,  0.0,  0.0,  0.0,
    ]
    d_noisy = compute_network_damage(noisy_20d)
    if verbose:
        print(f"[TEST 6] Noisy normal damage: {d_noisy:.4f}", end=" ")
        print("[PASS]" if d_noisy < 0.50 else "[FAIL]")
    if d_noisy >= 0.50:
        all_passed = False

    # Test 7: Brute force 20D — high F6, F13 moderate, low F7/F8 (realistic) → medium damage
    brute_20d = [
        25.0, 1.1, 0.10, 0.65, 1,
        0.95, 0.12, 0.12, 100.0, 1.5,
        8.0,  0.02, 0.8, 0.0, 0.0,
        0.0,  0.0,  0.0, 0.0, 0.0,
    ]
    d_brute = compute_network_damage(brute_20d)
    if verbose:
        print(f"[TEST 7] Brute force damage: {d_brute:.4f}", end=" ")
        print("[PASS]" if d_brute > 0.08 else "[FAIL]")
    if d_brute <= 0.08:
        all_passed = False

    # Test 8a: SQLi 20D — high F13, F14/F15 present, no XSS → high damage
    sqli_20d = [
        12.0, 1.05, 0.05, 0.01, 2,
        0.70, 0.04, 0.04, 40.0, 1.6,
        5.0,  0.02, 5.5, 0.4, 0.6,
        0.0,  0.4,  0.0, 0.0, 0.0,
    ]
    d_sqli = compute_network_damage(sqli_20d)
    if verbose:
        print(f"[TEST 8a] SQLi damage:     {d_sqli:.4f}", end=" ")
        print("[PASS]" if d_sqli > 0.05 else "[FAIL]")
    if d_sqli <= 0.05:
        all_passed = False

    # Test 8b: XSS 20D — high F18/F19, no SQL flags → medium-high damage
    xss_20d = [
        12.0, 1.0, 0.06, 0.01, 1,
        0.95, 0.05, 0.05, 90.0, 2.0,
        4.0,  0.02, 2.5, 0.0, 0.0,
        0.0,  0.0,  2.2, 1.0, 0.0,
    ]
    d_xss = compute_network_damage(xss_20d)
    if verbose:
        print(f"[TEST 8b] XSS damage:      {d_xss:.4f}", end=" ")
        print("[PASS]" if d_xss > 0.05 else "[FAIL]")
    if d_xss <= 0.05:
        all_passed = False

    # Test 9: Soft session counters — first Redirect starts session, evidence accumulates
    ts = PerIPTemporalState()
    ts.stage_action(2, l7_signal=0.8)
    ts.observe_effect([0.05, 0.90, 1.0, 0.05])
    ts.stage_action(2, l7_signal=0.8)
    ts.observe_effect([0.04, 0.92, 1.0, 0.04])
    temporal_ok = (
        ts.session_active and
        ts.window_len == 2 and
        ts.redirect_hits == 2 and
        ts.presence_hits == 2 and
        ts.honeypot_hits == 2 and
        ts.miss_count == 0 and
        ts.action_hold_steps == 2
    )
    if verbose:
        print(f"[TEST 9] Soft session counters", end=" ")
        print("[PASS]" if temporal_ok else "[FAIL]")
    if not temporal_ok:
        all_passed = False

    # Test 10: Two clean/no-presence windows should reset the soft session
    ts.stage_action(0, l7_signal=0.0)
    ts.observe_effect([0.0, 0.0, 0.0, 0.0])
    ts.stage_action(0, l7_signal=0.0)
    ts.observe_effect([0.0, 0.0, 0.0, 0.0])
    clean_ok = (not ts.session_active and ts.window_len == 0 and ts.clean_streak >= 2)
    if verbose:
        print(f"[TEST 10] Soft session reset on clean/no-presence", end=" ")
        print("[PASS]" if clean_ok else "[FAIL]")
    if not clean_ok:
        all_passed = False

    # Test 11: Redirect should win early, Block should win after a soft 15-window session
    env_p = IDSDefenseEnv(seed=42, mode='mock')
    env_p.reset()
    target_ip = [ip for ip, ip_type in zip(env_p.ip_list, env_p.ip_types) if ip_type == 'sqli'][0]

    def _advance_to_target_ip():
        while env_p.ip_list[env_p.current_ip_idx] != target_ip:
            env_p.step(0)

    _advance_to_target_ip()
    early_redirect = early_block = 0.0
    session_actions = [2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2]
    for idx, soft_action in enumerate(session_actions):
        env_p.step(soft_action)
        _advance_to_target_ip()
        if idx == 4:
            raw_mid = env_p.ip_behaviors[target_ip].get_features()
            effect_mid = env_p.ip_effect_state[target_ip]
            early_redirect = env_p._compute_reward(
                2, raw_mid, target_ip,
                effect_prev=effect_mid,
                effect_after=simulate_effect(2, raw_mid, env_p.rng),
            )
            early_block = env_p._compute_reward(
                3, raw_mid, target_ip,
                effect_prev=effect_mid,
                effect_after=simulate_effect(3, raw_mid, env_p.rng),
            )

    raw_late = env_p.ip_behaviors[target_ip].get_features()
    effect_late = env_p.ip_effect_state[target_ip]
    late_redirect = env_p._compute_reward(
        2, raw_late, target_ip,
        effect_prev=effect_late,
        effect_after=simulate_effect(2, raw_late, env_p.rng),
    )
    late_block = env_p._compute_reward(
        3, raw_late, target_ip,
        effect_prev=effect_late,
        effect_after=simulate_effect(3, raw_late, env_p.rng),
    )
    persistence_ok = (early_redirect > early_block and late_block > late_redirect)
    if verbose:
        print(
            f"[TEST 11] Redirect early / Block late: "
            f"early R={early_redirect:.3f} B={early_block:.3f} | "
            f"late R={late_redirect:.3f} B={late_block:.3f}",
            end=" "
        )
        print("[PASS]" if persistence_ok else "[FAIL]")
    if not persistence_ok:
        all_passed = False

    # Test 12: Concept drift — F1 increases in final 20% for benign
    env_d = IDSDefenseEnv(seed=42, enable_phase2=True, drift_max=0.12)
    env_d.reset()
    ep_len = env_d.episode_length
    drift_start = int(ep_len * 0.80)
    with_drift, without_drift = [], []
    for step in range(ep_len):
        ip = env_d.ip_list[env_d.current_ip_idx]
        ip_type = env_d.ip_types[env_d.current_ip_idx]
        behavior = env_d.ip_behaviors[ip]
        if step >= drift_start and ip_type in ('benign', 'noisy_normal'):
            if behavior.block_ttl == 0:
                raw = behavior.get_features()
                drifted = env_d._apply_concept_drift(list(raw), ip_type)
                if raw[0] > 10:
                    without_drift.append(raw[0])
                    with_drift.append(drifted[0])
        env_d.step(0)

    if len(without_drift) > 5:
        drift_ratio = np.mean(with_drift) / np.mean(without_drift) - 1.0
    else:
        drift_ratio = 0.0

    if verbose:
        print(f"[TEST 12] Concept drift: {100*drift_ratio:.1f}% F1 increase", end=" ")
        print("[PASS]" if 0.02 <= drift_ratio <= 0.15 else "[FAIL]")
    if not (0.02 <= drift_ratio <= 0.15):
        all_passed = False

    if verbose:
        print("="*60)
        print("[SUCCESS] All tests passed!" if all_passed else "[FAILURE] Some tests failed!")
        print("="*60 + "\n")

    return all_passed


if __name__ == '__main__':
    # Run self-test when executed directly
    import sys
    success = run_self_test(n_samples=500)
    sys.exit(0 if success else 1)
