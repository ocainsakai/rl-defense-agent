"""
IDSDefenseEnv - TRUE RL CONTROL SYSTEM (not a classifier)

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

CLOSED-LOOP EFFECTS:
  - Allow (0):    No mitigation
  - RateLimit (1): F1 *= 0.4, F11 *= 0.5
  - Redirect (2): F6,F7,F8 *= 0.3 + F12-F20 *= 0.2 (honeypot absorbs L7)
  - Block (3):    All features → 0 for TTL steps
"""

import math
import sys
import os
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import random
from typing import Dict, List, Tuple, Any

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

    # Composite signals (normalized to [0,1])
    ddos_signal  = min(f1_pps / 200.0, 1.0)                    # high pps → DDoS
    syn_signal   = min(f2_syn / 10.0, 1.0)                     # SYN/ACK ratio spike
    scan_signal  = min(f5_ports / 50.0, 1.0) * min(f11_ppp / 50.0, 1.0)  # port scan
    brute_signal = (f6_url * 0.4 + f7_iat * 0.3 + f8_size * 0.3)         # brute force bot
    sqli_signal  = min((f12_sqli + f13_crs / 20.0 + float(f14_union > 0)
                        + float(f15_cmt > 0) + float(f16_stk > 0)) / 3.0, 1.0)
    xss_signal   = min((f18_xss / 4.0 + float(f19_js > 0) + float(f20_html > 0)) / 2.0, 1.0)
    # Noise signal: elevated pps (20-60 pps) with low attack signals → noisy user (spam F5, rapid clicks)
    # Trapezoidal: ramp up from 0→1 over 15-30pps, ramp down 1→0 over 50-80pps
    # Benign F1≈8 → noise_pps≈0 (below 15 pps floor); noisy_normal F1≈30 → noise_pps≈1.0
    noise_rise   = float(np.clip((f1_pps - 15.0) / 15.0, 0.0, 1.0))   # 0→1 at 15→30 pps
    noise_fall   = float(np.clip(1.0 - (f1_pps - 50.0) / 30.0, 0.0, 1.0))  # 1→0 at 50→80 pps
    noise_pps    = noise_rise * noise_fall
    # Suppress noise only if strong attack signals present (thresholds match is_layer7/is_ddos gates)
    noise_signal = noise_pps * max(0.0, 1.0 - brute_signal / 0.35) * max(0.0, 1.0 - ddos_signal / 0.40)

    # Zone classification (soft gates, 4 zones)
    is_ddos   = soft_gate(max(ddos_signal, syn_signal, scan_signal), 0.40, 0.10)
    is_layer7 = soft_gate(max(brute_signal, sqli_signal, xss_signal), 0.35, 0.10)
    is_noise  = float(np.clip(noise_signal * (1.0 - is_ddos) * (1.0 - is_layer7), 0.0, 1.0))
    is_normal = float(np.clip((1.0 - soft_gate(damage, 0.10, 0.05)) * (1.0 - is_ddos) * (1.0 - is_layer7) * (1.0 - is_noise), 0.0, 1.0))

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
        bonus -= is_layer7 * 0.20   # Increased from 0.05 — discourage Block for L7

    # ── Noisy / Suspicious → RateLimit ───────────────────────────────────────
    if action == 1:   # RateLimit (correct — graduated response)
        bonus += is_noise * 0.50    # Strong signal — must clearly beat Allow in noise zone
    elif action == 3: # Block (over-response for ambiguous traffic)
        bonus -= is_noise * 0.50
    elif action == 2: # Redirect (over-response for noise)
        bonus -= is_noise * 0.25
    elif action == 0: # Allow (risky — noisy user may be probing)
        bonus -= is_noise * 0.30   # Stronger penalty — discourage Allow for noise

    # ── Normal → Allow ────────────────────────────────────────────────────────
    # Allow is the zero-cost default — no positive bonus, only penalties for wrong actions
    if action == 3: # Block (false positive — very bad for UX)
        bonus -= is_normal * low_damage * 0.60
    elif action == 1: # RateLimit (mild over-response for clean traffic)
        bonus -= is_normal * low_damage * 0.20
    elif action == 2: # Redirect (over-response for clean traffic)
        bonus -= is_normal * low_damage * 0.30

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
            # Calibrated from live test: F6=1.0, F8≈1.0 (curl loop), F7=0.85 (keep-alive bot)
            self.base_state = {
                'F1': 120.0, 'F1_sigma': 30.0,
                'F2': 1.2,   'F2_sigma': 0.20,
                'F3': 0.05,  # Fast IAT between requests
                'F4': 0.82,  'F4_alpha': 41.0, 'F4_beta': 9.0,   # High RST (failed logins)
                'F5': 1,     'F5_lam': 1,       # Single port (443/login)
                'F6': 0.95,  # All requests to /login → URL concentration high
                'F7': 0.85,  # Keep-alive bot → uniform IAT → F7 high
                'F8': 0.90,  # Uniform POST payload size
                'F9': 180.0, 'F9_sigma': 40.0,
                'F10': 1.5,
                'F11': 120.0,'F11_lam': 120,    # All pkts to single port
                'F12': 0.0, 'F13': 0.0, 'F14': 0.0,   # No SQLi
                'F15': 0.0, 'F16': 0.0, 'F17': 0.0,
                'F18': 0.0, 'F19': 0.0, 'F20': 0.0,   # No XSS
            }
        elif self.ip_type == 'sqli_xss':
            # Calibrated from live SQLmap+XSSer test results
            self.base_state = {
                'F1': 55.0,  'F1_sigma': 15.0,
                'F2': 1.05,  'F2_sigma': 0.10,
                'F3': 0.2,
                'F4': 0.05,  'F4_alpha': 2.5, 'F4_beta': 47.5,
                'F5': 2,     'F5_lam': 2,
                'F6': 0.8,   # Requests concentrated on exploit URLs
                'F7': 0.4,   # Semi-automated, not perfectly uniform
                'F8': 0.3,   # Variable payload sizes (SQLi payloads vary)
                'F9': 750.0, 'F9_sigma': 200.0,  # Large payloads (SQL query strings)
                'F10': 2.0,
                'F11': 55.0, 'F11_lam': 55,
                # SQLi features (from live test)
                'F12': 0.04, # Special chars ratio (', ;, --)
                'F13': 5.0,  # CRS SQLi score (live test: 4.8 avg)
                'F14': 1.0,  # UNION SELECT detected
                'F15': 1.0,  # SQL comments detected
                'F16': 1.0,  # Stacked queries
                'F17': 2.0,  # SELECT count
                # XSS features
                'F18': 1.6,  # CRS XSS score (live test avg)
                'F19': 1.0,  # JS function calls (alert/eval)
                'F20': 1.0,  # HTML event handlers
            }
        elif self.ip_type == 'noisy_normal':
            # Benign user with moderate noise (spam F5, rapid clicks)
            # Tuned so noise_signal stays in 0.3-0.7 range for reliable RateLimit zone:
            #   F1=30 pps avg (low sigma=8) → ddos_signal≈0.15 → noise_pps≈0.92
            #   F7=0.10 (low IAT uniformity) → brute_signal≈0.10 → not suppressed
            self.base_state = {
                'F1': 30.0,  'F1_sigma': 8.0,    # Low sigma → stays 15-45 pps range
                'F2': 1.1,   'F2_sigma': 0.30,
                'F3': 0.25,
                'F4': 0.04,  'F4_alpha': 2.0, 'F4_beta': 48.0,
                'F5': 2,     'F5_lam': 2,
                'F6': 0.10,
                'F7': 0.10,  # Low IAT uniformity → brute_signal low
                'F8': 0.15,
                'F9': 250.0, 'F9_sigma': 80.0,
                'F10': 1.8,
                'F11': 15.0, 'F11_lam': 15,
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
        Apply closed-loop effect based on last action (20D state).

        Action effects:
          0 (Allow): No effect (damage accumulates)
          1 (RateLimit): Throttle F1 (pps), F11 (ppp), slow port scan
          2 (Redirect): Honeypot absorbs L7 — reduce F6/F7/F8 + F12-F20
          3 (Block): Complete silence — all features → 0/neutral
        """
        if action == 0:  # Allow
            pass

        elif action == 1:  # RateLimit
            self.state['F1']  *= 0.4   # PacketRate throttled
            self.state['F11'] *= 0.5   # PacketsPerPort throttled
            self.state['F4']  *= 0.7   # Fewer RST (less probing)
            if self.state['F5'] > 5:
                self.state['F5'] = max(1, int(self.state['F5'] * 0.8))  # Slow scan

        elif action == 2:  # Redirect → Honeypot
            self.state['F1']  *= 0.6   # Partial traffic reduction
            # Honeypot absorbs brute-force patterns
            self.state['F6']  *= 0.3
            self.state['F7']  *= 0.3
            self.state['F8']  *= 0.3
            # Honeypot absorbs SQLi/XSS payload
            for k in ('F12','F13','F14','F15','F16','F17','F18','F19','F20'):
                self.state[k] *= 0.2
            # Reduce large payloads going to honeypot
            if self.state['F9'] > PAYLOAD_ANCHOR:
                self.state['F9'] = PAYLOAD_ANCHOR + (self.state['F9'] - PAYLOAD_ANCHOR) * 0.4

        elif action == 3:  # Block — complete silence
            self.block_ttl = int(self.rng.integers(5, 11))
            for k in ('F1','F2','F3','F4','F6','F7','F8','F9','F10','F11',
                      'F12','F13','F14','F15','F16','F17','F18','F19','F20'):
                self.state[k] = 0.0
            self.state['F2'] = 1.0   # Normal SYN/ACK ratio (no traffic)
            self.state['F5'] = 1     # Minimal port activity

        self.last_action = action

    def step_forward(self):
        """Evolve behavior for next step with closed-loop awareness (20D)."""
        self.step_counter += 1

        # During block TTL: keep all features silent
        if self.block_ttl > 0:
            self.block_ttl -= 1
            for k in self.state:
                self.state[k] = 0.0
            self.state['F2'] = 1.0
            self.state['F5'] = 1
            return

        b = self.base_state

        if self.ip_type == 'benign':
            b['F1'] += self.rng.normal(0, 5)
            b['F9'] += self.rng.normal(0, 20)
            if self.rng.random() < 0.1:
                b['F9'] += 150  # occasional spike (file upload)

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

        elif self.ip_type == 'brute_force':
            if self.last_action == 0:
                # Sustained brute force: keep high RST ratio and URL concentration
                b['F4'] = float(np.clip(0.75 + self.rng.beta(8, 2) * 0.23, 0.0, 1.0))
                b['F4_alpha'] = b['F4'] * 50
                b['F4_beta'] = (1.0 - b['F4']) * 50
            elif self.last_action in (2, 3):  # Redirected/blocked
                b['F6'] = max(0.1, b['F6'] * 0.85)
                b['F7'] = max(0.1, b['F7'] * 0.85)

        elif self.ip_type == 'sqli_xss':
            if self.last_action == 0:
                b['F9'] += self.rng.normal(50, 100)
                # Escalate SQLi/XSS
                b['F13'] = min(20.0, b['F13'] + self.rng.normal(0.2, 0.1))
                b['F18'] = min(4.0,  b['F18'] + self.rng.normal(0.1, 0.05))
            elif self.last_action == 2:  # Redirected to honeypot
                b['F13'] = max(0.0, b['F13'] * 0.9)
                b['F18'] = max(0.0, b['F18'] * 0.9)
            b['F9'] = max(450.0, b['F9'])

        elif self.ip_type == 'noisy_normal':
            b['F1'] += self.rng.normal(0, 10)
            b['F9'] += self.rng.normal(0, 30)
            if self.rng.random() < 0.10:
                b['F1'] *= self.rng.uniform(1.5, 2.5)
                self.persistence_score = min(1.0, self.persistence_score + 0.1)
            else:
                self.persistence_score *= 0.98

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
# REPLAY BEHAVIOR — reads real NIDS data from training_data.jsonl
# ============================================================================

import json as _json

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
        'scan':         0.7,
        'syn_flood':    0.9,
        'brute_force':  0.6,
        'sqli_xss':     0.8,
    }

    def __init__(self, records: list, rng: np.random.Generator = None):
        """
        Args:
            records: list of dicts {features: [20 floats], label: str, src_ip: str, ...}
            rng: numpy RNG (dùng để shuffle)
        """
        if not records:
            raise ValueError("ReplayBehavior cần ít nhất 1 record")
        self.records = records
        self.rng = rng if rng is not None else np.random.default_rng()
        self.idx = 0
        self.persistence_score = 0.0
        self.burst_window = 0
        self._shuffle()

    def _shuffle(self):
        self.rng.shuffle(self.records)
        self.idx = 0

    @property
    def ip_type(self) -> str:
        return self.records[self.idx % len(self.records)].get('label', 'normal')

    def get_features(self) -> list:
        rec = self.records[self.idx % len(self.records)]
        feats = rec.get('features', [0.0] * 20)
        if len(feats) != 20:
            feats = (list(feats) + [0.0] * 20)[:20]
        return list(feats)

    def apply_closed_loop_effect(self, action: int):
        # No-op: features đến từ data thật, không simulate closed-loop
        pass

    def step_forward(self):
        self.idx += 1
        if self.idx >= len(self.records):
            self._shuffle()


def _load_replay_records(training_data_file: str) -> list:
    """Load training_data.jsonl → list of records."""
    records = []
    with open(training_data_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = _json.loads(line)
                if 'features' in rec and len(rec['features']) == 20:
                    records.append(rec)
            except Exception:
                continue
    if not records:
        raise ValueError(f"Không có record hợp lệ trong {training_data_file}")
    return records


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

    def __init__(self, seed=None, enable_phase2=True, missing_prob=0.01, drift_max=0.12,
                 mode='mock', training_data=None):
        """Initialize IDS Defense Environment (20D observation).

        Args:
            seed: Random seed
            enable_phase2: Enable concept drift / missing data simulation
            missing_prob: Probability of missing feature (PHASE 2)
            drift_max: Max concept drift factor (PHASE 2)
            mode: 'mock' (default) | 'replay' — use real NIDS data for fine-tuning
            training_data: Path to training_data.jsonl (required when mode='replay')
        """
        super().__init__()

        self.rng = np.random.default_rng(seed)
        self.mode = mode

        # 20D observation space — matches NIDS FEATURE_ORDER
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(20,), dtype=np.float32)
        self.action_space = spaces.Discrete(4)

        # Episode config
        self.episode_length = 120
        self.current_step = 0
        self.cumulative_damage = 0.0  # Track episodic damage

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
            # IP configuration — 5 types matching thesis demo scope:
            #   Allow: benign (25%) | RateLimit: noisy_normal (16.7%)
            #   Redirect: brute_force (16.7%) + sqli_xss (16.7%) = 33.3%
            #   Block: scan (16.7%) + syn_flood (8.3%) = 25%
            self.ip_list = [
                '192.168.1.10', '192.168.1.11', '192.168.1.12',  # benign (3)
                '192.168.1.13', '192.168.1.14',                   # noisy_normal (2)
                '10.0.0.100', '10.0.0.101',                       # scan (2)
                '10.0.0.102',                                       # syn_flood (1)
                '10.0.0.103', '10.0.0.104',                       # brute_force (2)
                '10.0.0.105', '10.0.0.106',                       # sqli_xss (2)
            ]
            self.ip_types = [
                'benign', 'benign', 'benign',            # 25% → Allow
                'noisy_normal', 'noisy_normal',          # 16.7% → RateLimit
                'scan', 'scan',                          # 16.7% → Block
                'syn_flood',                             # 8.3% → Block
                'brute_force', 'brute_force',            # 16.7% → Redirect
                'sqli_xss', 'sqli_xss',                 # 16.7% → Redirect
            ]

            # Create IP behaviors
            self.ip_behaviors = {}
            self.current_ip_idx = 0

            self._init_behaviors()

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
        self.cumulative_damage = 0.0

        if self.mode == 'replay':
            # Replay: just update ip_type from current record
            self.ip_types = [self._replay.ip_type]
        else:
            # Mock: re-initialize all MockIPBehaviors with fresh RNG seeds
            self._init_behaviors()

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

    def _get_obs_and_info(self) -> Tuple[np.ndarray, Dict]:
        """Get 20D observation for current IP with concept drift applied."""
        current_ip = self.ip_list[self.current_ip_idx]
        behavior = self.ip_behaviors[current_ip]
        # In replay mode, ip_type comes from the current record dynamically
        ip_type = behavior.ip_type if self.mode == 'replay' else self.ip_types[self.current_ip_idx]

        raw_features = behavior.get_features()
        raw_features = self._apply_concept_drift(raw_features, ip_type)
        obs = self._normalize_features(raw_features)

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
            'persistence_score': behavior.persistence_score,
            'burst_window': behavior.burst_window,
            'phase': phase,
            'scenario': f"{ip_type}_{phase}",
        }
        return obs, info

    def _compute_reward(self, action: int, features_before: List[float], features_after: List[float]) -> float:
        """
        Reward = -(damage_after + action_cost) + action_bonus

        Args:
            action: Action taken
            features_before: 20D raw list before action
            features_after:  20D raw list after closed-loop effect

        Returns:
            reward ∈ [-1, +1]
        """
        damage_before = compute_network_damage(features_before)
        damage_after  = compute_network_damage(features_after)
        action_cost   = compute_action_cost(action)

        base_reward = -(damage_after + action_cost)

        # Damage reduction bonus
        damage_reduction = damage_before - damage_after
        reduction_bonus  = damage_reduction * 0.5
        if action == 3:
            reduction_bonus = min(reduction_bonus, 0.05)  # Cap Block bonus

        # Attack-type based action bonus (uses 20D raw obs)
        action_bonus = compute_action_bonus(action, features_before, damage_before)

        total_reward = base_reward + reduction_bonus + action_bonus
        # FIX: Clip [-1,+1] not [-1,0] — positive rewards are needed for gradient signal
        # Old clip to 0 caused BOTH correct and wrong actions to return 0.0 → no learning
        return float(np.clip(total_reward, -1.0, 1.0))

    def step(self, action) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """Execute one step with closed-loop effects (20D)."""
        action = int(action)
        current_ip = self.ip_list[self.current_ip_idx]
        behavior   = self.ip_behaviors[current_ip]
        ip_type    = behavior.ip_type if self.mode == 'replay' else self.ip_types[self.current_ip_idx]

        # Raw 20D features BEFORE action
        raw_before = behavior.get_features()
        raw_before = self._apply_concept_drift(raw_before, ip_type)

        # Apply closed-loop effect
        behavior.apply_closed_loop_effect(action)

        # Raw 20D features AFTER action
        raw_after = behavior.get_features()
        raw_after = self._apply_concept_drift(raw_after, ip_type)

        reward = self._compute_reward(action, raw_before, raw_after)

        damage = compute_network_damage(raw_after)
        self.cumulative_damage += damage

        behavior.step_forward()

        self.current_ip_idx = (self.current_ip_idx + 1) % len(self.ip_list)
        self.current_step  += 1

        done = self.current_step >= self.episode_length
        obs, info = self._get_obs_and_info()

        info['step_damage'] = damage
        info['cumulative_damage'] = self.cumulative_damage
        info['reward_breakdown'] = {
            'damage': -damage,
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
    """Quick self-test to verify 20D env bounds before training."""
    if verbose:
        print("\n" + "="*60)
        print("ENV_IDS SELF-TEST (20D): Verifying Bounds")
        print("="*60)

    env = IDSDefenseEnv(seed=42)
    all_passed = True

    # Test 1: observation_space is 20D
    obs_dim = env.observation_space.shape[0]
    if verbose:
        print(f"[TEST 1] Observation dim: {obs_dim}", end=" ")
        print("[PASS]" if obs_dim == 20 else "[FAIL]")
    if obs_dim != 20:
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
        assert obs.shape == (20,), f"obs shape {obs.shape}"
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

    # Test 7: Brute force 20D — high F6/F7/F8, no SQLi/XSS → medium-high damage
    brute_20d = [
        120.0, 1.2, 0.05, 0.82, 1,
        0.95,  0.85, 0.90, 180.0, 1.5,
        120.0, 0.0, 0.0, 0.0, 0.0,
        0.0,   0.0, 0.0, 0.0, 0.0,
    ]
    d_brute = compute_network_damage(brute_20d)
    if verbose:
        print(f"[TEST 7] Brute force damage: {d_brute:.4f}", end=" ")
        print("[PASS]" if d_brute > 0.10 else "[FAIL]")
    if d_brute <= 0.10:
        all_passed = False

    # Test 8: SQLi/XSS 20D — high F13/F18 → high damage
    sqli_20d = [
        55.0, 1.05, 0.2, 0.05, 2,
        0.8,  0.4,  0.3, 750.0, 2.0,
        55.0, 0.04, 5.0, 1.0, 1.0,
        1.0,  2.0,  1.6, 1.0, 1.0,
    ]
    d_sqli = compute_network_damage(sqli_20d)
    if verbose:
        print(f"[TEST 8] SQLi/XSS damage: {d_sqli:.4f}", end=" ")
        print("[PASS]" if d_sqli > 0.15 else "[FAIL]")
    if d_sqli <= 0.15:
        all_passed = False

    # Test 9: Concept drift — F1 increases in final 20% for benign
    env_d = IDSDefenseEnv(seed=42, enable_phase2=True, drift_max=0.12)
    env_d.reset()
    with_drift, without_drift = [], []
    for step in range(120):
        ip = env_d.ip_list[env_d.current_ip_idx]
        ip_type = env_d.ip_types[env_d.current_ip_idx]
        behavior = env_d.ip_behaviors[ip]
        if step >= 96 and ip_type in ('benign', 'noisy_normal'):
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
        print(f"[TEST 9] Concept drift: {100*drift_ratio:.1f}% F1 increase", end=" ")
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
