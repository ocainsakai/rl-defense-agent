"""
PPO Agent Inference Script - Real-time NIDS JSONL Processing

Reads sniffer_output.jsonl (produced by System/main.py) in real-time,
normalizes 20D feature vector, runs PPO model, and applies iptables actions
on the router namespace via nsenter.

OBSERVATION VECTOR (20D, matches NIDS FEATURE_ORDER):
  [F1-PacketRate, F2-SynAckRatio, ..., F20-HtmlEventHandler]

ACTION MAPPING (attack-type driven):
  0 = Allow      — normal traffic
  1 = RateLimit  — noisy/suspicious user (spam F5, rapid clicks)
  2 = Redirect   — Brute Force / SQLi / XSS → Honeypot (escalates to Block after TTL)
  3 = Block      — DDoS / Port Scan

Usage:
  python3 infer.py --watch /tmp/sniffer_output.jsonl
  python3 infer.py --watch /tmp/sniffer_output.jsonl --from-begin
  python3 infer.py --no-enforce   # dry-run (print actions only, no iptables)
"""

import json
import math as _math
import numpy as np
import argparse
import sys
import time
import os
import subprocess
from typing import Dict, List, Optional, Tuple
from stable_baselines3 import PPO
from env_ids import (
    normalize_observation, compute_network_damage, compute_attack_signals,
    PerIPTemporalState,
    SOFT_SESSION_WINDOW, MISS_BUDGET, SESSION_START_L7_THRESHOLD,
    PRESENCE_RATIO_THRESHOLD as _ENV_PRESENCE_THRESHOLD,
)

# ============================================================================
# NIDS FEATURE KEY ORDER (matches System/main.py FlowFeatureCalculator labels)
# ============================================================================

NIDS_KEY_ORDER: List[str] = [
    'F1 - PacketRate',
    'F2 - SynAckRatio',
    'F3 - InterArrivalTime',
    'F4 - RstRatio',
    'F5 - DistinctPorts',
    'F6 - URLConcentration',
    'F7 - HttpIatUniformity',
    'F8 - RequestSizeUniformity',
    'F9 - AvgPayloadSize',
    'F10 - FwdBwdRatio',
    'F11 - PacketsPerPort',
    'F12 - SqlSpecialChar',
    'F13 - CrsSqliScore',
    'F14 - SqlUnionSelect',
    'F15 - SqlComment',
    'F16 - SqlStackedQuery',
    'F17 - SqlSelectCount',
    'F18 - CrsXssScore',
    'F19 - JsFunctionCall',
    'F20 - HtmlEventHandler',
]

ACTION_MAP = {0: 'Allow', 1: 'RateLimit', 2: 'Redirect', 3: 'Block'}

# ============================================================================
# NETWORK TOPOLOGY CONFIG
# ============================================================================

ROUTER_IFACE_EXT = 'r-ext'      # Router external interface (faces attackers)
SERVER_IP        = '192.168.10.10'
SERVER_PORT      = 443
HONEYPOT_PORT    = 4443           # Redirect destination on same router IP

# IPs that should NEVER be blocked — internal infrastructure
WHITELIST_IPS = {
    '192.168.10.10',   # Web server
    '192.168.10.1',    # Server subnet gateway
    '10.0.10.254',     # Router nginx proxy
    '10.0.10.1',       # Router/gateway
    '127.0.0.1',
}

# ============================================================================
# NIDS ROW PARSER
# ============================================================================

def parse_nids_row(row: dict) -> np.ndarray:
    """
    Parse NIDS JSONL row → normalized 20D obs vector.

    Accepts both NIDS format  {'F1 - PacketRate': 120.0, ...}
    and test/legacy format    {'F1': 120.0, ...}

    Missing keys → 0.0 (safe default).
    """
    raw = []
    for key in NIDS_KEY_ORDER:
        val = row.get(key)
        if val is None:
            # Try short key (F1, F2, ...) as fallback
            short = key.split(' - ')[0]
            val = row.get(short, 0.0)
        try:
            raw.append(float(val))
        except (TypeError, ValueError):
            raw.append(0.0)

    norm = normalize_observation(raw)
    return norm, raw   # return both: obs for model, raw for action executor


# ============================================================================
# ACTION EXECUTOR (iptables via nsenter into router namespace)
# ============================================================================

def _find_router_pid() -> Optional[int]:
    """Find PID of the Mininet router process (r-ext interface owner)."""
    try:
        result = subprocess.run(
            ['ip', 'link', 'show', ROUTER_IFACE_EXT],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            # Already in router namespace — use PID 1 (self)
            return None  # No nsenter needed
    except Exception:
        pass

    # Try to find router by searching for its namespace
    try:
        out = subprocess.run(
            ['ps', 'aux'], capture_output=True, text=True
        ).stdout
        for line in out.splitlines():
            if 'mininet' in line.lower() and ('-r ' in line or 'router' in line.lower()):
                parts = line.split()
                if len(parts) > 1:
                    try:
                        return int(parts[1])
                    except ValueError:
                        pass
    except Exception:
        pass
    return None


_ROUTER_PID: Optional[int] = None  # Lazy-initialized


def _run_router(cmd: str, enforce: bool = True) -> bool:
    """Run iptables command in router network namespace."""
    global _ROUTER_PID

    if not enforce:
        print(f"    [DRY-RUN] {cmd}")
        return True

    if _ROUTER_PID is None:
        _ROUTER_PID = _find_router_pid()

    try:
        if _ROUTER_PID is not None:
            full_cmd = ['nsenter', '-n', '-t', str(_ROUTER_PID), 'bash', '-c', cmd]
        else:
            full_cmd = ['bash', '-c', cmd]

        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"    [WARN] iptables: {result.stderr.strip()}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"    [ERROR] iptables timeout")
        return False
    except Exception as e:
        print(f"    [ERROR] nsenter: {e}")
        return False


def _del_rule(src_ip: str, enforce: bool = True):
    """Remove ALL existing rules for this IP (batched into single shell call).

    Rules are applied to both FORWARD and INPUT chains because traffic from the
    attacker is DNAT'd to the local nginx proxy (10.0.10.254:443) → INPUT chain.
    FORWARD chain alone is insufficient.
    """
    name = src_ip.replace('.', '_')
    # Batch all deletes into a single bash command (instead of 40 separate nsenter calls)
    parts = []
    for _ in range(3):  # 3 iterations to clear stacked duplicates
        for chain in ('FORWARD', 'INPUT'):
            parts.append(
                f"iptables -D {chain} -s {src_ip} -j DROP 2>/dev/null"
            )
            parts.append(
                f"iptables -D {chain} -s {src_ip} -m hashlimit "
                f"--hashlimit-name rl_{name} "
                f"--hashlimit-above 2/sec --hashlimit-burst 5 -j DROP 2>/dev/null"
            )
        parts.append(
            f"iptables -t nat -D PREROUTING -i {ROUTER_IFACE_EXT} -s {src_ip} "
            f"-d {SERVER_IP} -p tcp --dport {SERVER_PORT} "
            f"-j REDIRECT --to-ports {HONEYPOT_PORT} 2>/dev/null"
        )
    _run_router("; ".join(parts) + "; true", enforce)


def apply_action(src_ip: str, action: int, enforce: bool = True):
    """Apply firewall action for a given source IP."""
    _del_rule(src_ip, enforce)

    if action == 0:   # Allow — rules already deleted above
        pass

    elif action == 1:  # RateLimit — throttle at 2 pps
        # Apply to both INPUT (DNAT'd traffic to local nginx) and FORWARD
        # Shared hashlimit-name means both chains share the same token bucket
        for chain in ('INPUT', 'FORWARD'):
            _run_router(
                f"iptables -I {chain} 1 -s {src_ip} "
                f"-m hashlimit --hashlimit-name rl_{src_ip.replace('.','_')} "
                f"--hashlimit-above 2/sec --hashlimit-burst 5 -j DROP",
                enforce
            )

    elif action == 2:  # Redirect → Honeypot
        _run_router(
            f"iptables -t nat -I PREROUTING 1 "
            f"-i {ROUTER_IFACE_EXT} -s {src_ip} "
            f"-d {SERVER_IP} -p tcp --dport {SERVER_PORT} "
            f"-j REDIRECT --to-ports {HONEYPOT_PORT}",
            enforce
        )

    elif action == 3:  # Block
        # Apply to both INPUT (DNAT'd traffic to local nginx) and FORWARD
        for chain in ('INPUT', 'FORWARD'):
            _run_router(
                f"iptables -I {chain} 1 -s {src_ip} -j DROP",
                enforce
            )


# ============================================================================
# INFERENCE TEMPORAL STATE (mirrors PerIPTemporalState from env_ids.py)
# ============================================================================

ACTION_HOLD_NORM_STEPS = 15.0
CLEAN_STREAK_NORM_STEPS = 10.0
HONEYPOT_RATIO_THRESHOLD = 0.60
PRESENCE_RATIO_THRESHOLD = 0.50
SERVICE_DAMAGE_CLEAN_THRESHOLD = 0.03


class InferenceTemporalState:
    """Legacy 30D temporal state kept for old v2 models.

    New 34D models use PersistenceTemporalState below.
    """

    def __init__(self):
        self.last_action: int = 0
        self.action_hold_steps: int = 0
        self.cumulative_damage: float = 0.0
        self.damage_ema: float = 0.0
        self.damage_trend: float = 0.0
        self.escalation_count: int = 0
        self.steps_since_attack: int = 0
        self.prev_damage: float = 0.0
        self.step_count: int = 0

    def update(self, action: int, step_damage: float,
               attack_threshold: float = 0.15, ema_alpha: float = 0.3):
        """Update state after action decision for this IP."""
        if action > self.last_action:
            self.escalation_count += 1

        if action == self.last_action:
            self.action_hold_steps += 1
        else:
            self.action_hold_steps = 0

        self.last_action = action
        self.step_count += 1

        self.cumulative_damage += step_damage
        delta = step_damage - self.prev_damage
        self.damage_ema = ema_alpha * step_damage + (1 - ema_alpha) * self.damage_ema
        self.damage_trend = ema_alpha * delta + (1 - ema_alpha) * self.damage_trend
        self.prev_damage = step_damage

        if step_damage > attack_threshold:
            self.steps_since_attack = 0
        else:
            self.steps_since_attack += 1

    def to_obs(self) -> list:
        """Return 10D normalized temporal feature vector, all in [0,1]."""
        one_hot = [0.0, 0.0, 0.0, 0.0]
        one_hot[self.last_action] = 1.0

        return one_hot + [
            min(self.action_hold_steps / 10.0, 1.0),
            min(self.damage_ema * 5.0, 1.0),           # recent_intensity_norm — khớp env_ids.py (không tích lũy)
            1.0 / (1.0 + np.exp(-10.0 * self.damage_trend)),
            min(self.escalation_count / 5.0, 1.0),
            min(self.steps_since_attack / 10.0, 1.0),
            min(self.damage_ema, 1.0),
        ]


class PersistenceTemporalState(PerIPTemporalState):
    """34D temporal state for inference — exact mirror of PerIPTemporalState in env_ids.py.

    Inherits all fields and logic directly so obs [20..29] always matches training exactly:
      [20..23] last_action one-hot
      [24]     action_hold_norm
      [25]     damage_ema
      [26]     effect_trend
      [27]     soft_window_fill_norm  = window_len / 15
      [28]     escalation_score_norm  = escalation_score ∈ [0,1]
      [29]     miss_budget_used_norm  = miss_count / 3

    Do NOT add extra fields here — any divergence from PerIPTemporalState breaks the 34D obs.
    """
    pass


# ============================================================================
# SAFETY NET (thin wrapper — replaces old IPStateTracker state machine)
# ============================================================================

BLOCK_IDLE_TTL        = 60.0   # Auto-unblock Block after this many seconds of silence
RATELIMIT_IDLE_TTL    = 15.0   # Auto-clear RateLimit after 15s silence
EXPIRE_CHECK_INTERVAL = 5.0    # How often to scan for idle blocked IPs (seconds)


class SafetyNet:
    """Thin safety net — only handles infrastructure concerns, NOT temporal policy.

    What it does (Category B+C):
      - Track last applied action per IP (for iptables change detection)
      - XSS/SQLi → Redirect override (honeypot intel gathering)
      - Block hold when damage_ema is high (prevent premature unblock)
      - expire_stale() for auto-unblocking after prolonged silence

    What it does NOT do (model handles via temporal obs):
      - Escalation timing (was REDIRECT_TTL_SECONDS)
      - Downgrade logic (was CLEAN_WINDOWS_TO_DOWNGRADE)
      - Attack signal detection (was _is_attack_signal)
      - Hold gates (was MIN_ESCALATE_HOLD)
    """

    def __init__(self, override0: bool = True):
        self._state: Dict[str, dict] = {}   # ip → {action, ts}
        self.override0 = override0

    def apply_safety_overrides(self, src_ip: str, rl_action: int,
                                raw: list, tstate) -> int:
        """Apply safety overrides to model decision. Returns final action."""
        final_action = rl_action

        # Override 0: L7 attack detected but model says Allow/RateLimit → force Redirect.
        # Root cause: model v7 damage_ema is driven by network-level damage (F1/F2).
        # HTTP brute force / SQLi / XSS have low F1 (~6 pps) → damage_ema never rises →
        # model sees "low damage, no prior escalation" → Allow. Override corrects this.
        if self.override0 and final_action < 2 and len(raw) >= 20:
            sqli_score = max(raw[11:17])   # F12-F17
            xss_score  = max(raw[17:20])   # F18-F20
            f6 = raw[5]   # URLConcentration — high = requests concentrated on 1 URL (brute force)
            f7 = raw[6]   # HttpIatUniformity — high = bot-like uniform timing
            brute_signal = f6 * 0.5 + f7 * 0.5
            if sqli_score > 0.08 or xss_score > 0.08 or brute_signal > 0.6:
                final_action = 2  # Allow/RateLimit → Redirect

        # Override 1: Layer-7 attacks (SQLi/XSS) → always Redirect first, never Block directly.
        # Rationale: honeypot captures attacker payloads; attacker doesn't know they're detected.
        # Real-world evidence (CIC-IDS2018): high F13/F18 with low F1 → model outputs Block
        # incorrectly because it conflates high-signal L7 with DDoS. This override corrects it.
        # EXCEPTION: skip when block_ready_latched=True — sufficient evidence collected, let
        # the RL model make the Block decision independently. This restores the training-inference
        # alignment: env_ids.py has no Override 1, so the model learned "high escalation_score
        # → Block"; keeping this override active after latch prevents that learned behavior
        # from ever executing. soft_guard assist remains as backup if model outputs Redirect.
        if final_action == 3 and len(raw) >= 20 and not tstate.block_ready_latched:
            sqli_score  = max(raw[11:17])   # F12-F17
            xss_score   = max(raw[17:20])   # F18-F20
            f1_pps      = raw[0]             # PacketRate raw pps (unnormalized)
            f2_syn      = raw[1]             # SynAckRatio raw
            ddos_signal = (f1_pps > 80 or f2_syn > 5)
            if not ddos_signal:
                # L7 session: downgrade Block→Redirect regardless of current L7 signal.
                # Gap windows (sqlmap --delay=1) have SQLi=0 between requests but temporal
                # state still high → model fires Block → iptables drop → session reset loop.
                # DDoS (F1>80 pps) is network-level and doesn't need L7 evidence to Block.
                final_action = 2  # Block → Redirect

        # Override 2: Block hold when damage is still high
        if (tstate.last_action == 3 and final_action < 3
                and tstate.damage_ema > 0.3):
            final_action = 3

        return final_action

    def update(self, src_ip: str, action: int, ts: float) -> bool:
        """Track action and return True if iptables needs to change."""
        s = self._state.get(src_ip)
        if s is None:
            if action == 0:
                return False  # No need to track Allow for new IPs
            self._state[src_ip] = {'action': action, 'ts': ts}
            return True

        # Block-hold: once Block is correctly applied (block_ready_latched path or any Block),
        # prevent downgrading to a less-restrictive action until the attacker goes silent.
        # Without this, the PersistenceTemporalState session reset after correct Block causes
        # Redirect to be re-applied to iptables 1 second later, cycling Block→Redirect→Block
        # every ~12 windows while the attacker is still sending traffic.
        if s.get('action') == 3 and action < 3:
            idle = ts - s.get('ts', ts)
            if idle < BLOCK_IDLE_TTL:
                s['ts'] = ts  # refresh idle timer so expire_stale keeps it alive
                return False  # suppress iptables downgrade while block is hot

        changed = (action != s['action'])
        s['action'] = action
        s['ts'] = ts
        return changed

    def get(self, src_ip: str) -> dict:
        return self._state.get(src_ip, {})

    def expire_stale(self, now: float, enforce: bool = True):
        """Auto-unblock IPs that have been silent for too long."""
        for ip, s in list(self._state.items()):
            action = s.get('action', 0)
            if action == 0:
                continue
            last_seen = s.get('ts', now)
            idle_secs = now - last_seen
            ttl = RATELIMIT_IDLE_TTL if action == 1 else BLOCK_IDLE_TTL
            if idle_secs >= ttl:
                print(f"\n    [AUTO-UNBLOCK] {ip}: {ACTION_MAP[action]} expired "
                      f"(silent {idle_secs:.0f}s >= {ttl:.0f}s) → Allow")
                apply_action(ip, 0, enforce)
                del self._state[ip]


# ============================================================================
# LEGACY STATE TRACKER (kept for --model-version v1 compatibility)
# ============================================================================

REDIRECT_TTL_SECONDS  = 15.0
MIN_ESCALATE_HOLD     = 10.0
CLEAN_WINDOWS_TO_DOWNGRADE = {
    3: -1,
    2: 10,
    1: 2,
}

ACTION_SEVERITY = {0: 0, 1: 1, 2: 2, 3: 3}
L7_BENIGN_MEMORY_SECONDS = 8.0


class IPStateTracker:
    """LEGACY: Track per-IP action state with hysteresis and escalation logic.

    Key design:
      - Escalation (Allow→Block): immediate if signal is strong, short hold if weak
      - Same severity: no iptables change, but still tracks redirect escalation timer
      - Downgrade (Block→Allow): requires CLEAN_WINDOWS_TO_DOWNGRADE consecutive
        clean 1s NIDS windows (not just one lucky window with no payload)
      - Always updates s['ts'] so expire_stale knows the IP is still active
    """

    def __init__(self):
        self._state: Dict[str, dict] = {}

    @staticmethod
    def _is_attack_signal(obs_raw: list) -> bool:
        """Check if current NIDS window shows attack indicators."""
        if len(obs_raw) < 20:
            return False
        f1  = obs_raw[0]                        # PacketRate
        f2  = obs_raw[1]                        # SynAckRatio
        f6  = obs_raw[5]                        # URLConcentration
        sqli = max(obs_raw[11:17])              # F12-F17
        xss  = max(obs_raw[17:20])              # F18-F20
        return (f1 > 100 or f2 > 5 or f6 > 0.5 or sqli > 0.1 or xss > 0.1)

    @staticmethod
    def _has_clear_layer7_signal(obs_raw: list) -> bool:
        """Require stronger evidence before escalating noisy RateLimit traffic to Redirect.

        Purpose:
          - Keep spam-reload/noisy users at RateLimit
          - Only allow Redirect when there is clear L7 evidence
            (SQLi/XSS or a strong brute-force bot pattern)
        """
        if len(obs_raw) < 20:
            return False

        f4_rst  = obs_raw[3]                    # RstRatio
        f6_url  = obs_raw[5]                    # URLConcentration
        f7_iat  = obs_raw[6]                    # HttpIatUniformity
        f8_size = obs_raw[7]                    # RequestSizeUniformity
        sqli = max(obs_raw[11:17])              # F12-F17
        xss  = max(obs_raw[17:20])              # F18-F20

        # SQLi/XSS payload indicators are clear enough on their own.
        if sqli > 0.08 or xss > 0.08:
            return True

        # Brute-force bot pattern: same endpoint, highly regular timing/size,
        # and at least some failed-connection/abnormality signal.
        brute_pattern = (
            f6_url > 0.85 and
            f7_iat > 0.75 and
            f8_size > 0.75 and
            f4_rst > 0.05
        )
        return brute_pattern

    def _check_redirect_escalation(self, s: dict, ts: float,
                                    obs_raw: list, src_ip: str) -> Optional[int]:
        """Check if Redirect should escalate to Block. Returns 3 or None."""
        if 'redirect_since' not in s:
            s['redirect_since'] = ts
            return None

        age = ts - s['redirect_since']
        if age <= REDIRECT_TTL_SECONDS:
            return None

        # IP already confirmed as attacker (that's why it's in Redirect).
        # After TTL, escalate unconditionally — don't re-check attack signal
        # because slow tools (sqlmap --delay=1) have low F1 and tshark may not
        # decrypt every window, making _is_attack_signal() return False even
        # while the attack is ongoing.
        print(f"\n    [ESCALATE] {src_ip}: Redirect → Block "
              f"(persisted {age:.0f}s > {REDIRECT_TTL_SECONDS:.0f}s)")
        s.pop('redirect_since', None)
        return 3

    def update(self, src_ip: str, action: int, ts: float,
               obs_raw: List[float], force_downgrade: bool = False) -> Tuple[int, bool]:
        """
        Returns (final_action, changed).
        changed=True means iptables rule needs to be applied.
        """
        s = self._state.get(src_ip, {})
        current_action = s.get('action', 0)
        action_since   = s.get('action_since', ts)

        # FIX Bug#1: ALWAYS update last-seen timestamp
        s['ts'] = ts

        # FIX Bug#2: Track consecutive clean windows for downgrade decisions
        is_attack = self._is_attack_signal(obs_raw)
        if is_attack:
            s['clean_streak'] = 0
        else:
            s['clean_streak'] = s.get('clean_streak', 0) + 1

        new_sev = ACTION_SEVERITY[action]
        cur_sev = ACTION_SEVERITY[current_action]

        if force_downgrade and new_sev < cur_sev:
            s['action_since'] = ts
            s['action'] = action
            s['clean_streak'] = max(s.get('clean_streak', 0), 1)
            s.pop('redirect_since', None)
            self._state[src_ip] = s
            return action, (action != current_action)

        if new_sev > cur_sev:
            # --- ESCALATION ---
            if cur_sev > 0:   # already restricted
                hold_age = ts - action_since
                strong = is_attack  # any attack signal → immediate escalation
                if current_action == 1 and action == 2 and not self._has_clear_layer7_signal(obs_raw):
                    print(f"\n    [HOLD-ESC] {src_ip}: keep RateLimit "
                          f"(no clear Layer7 signal for Redirect)")
                    self._state[src_ip] = s
                    return current_action, False
                if hold_age < MIN_ESCALATE_HOLD and not strong:
                    print(f"\n    [HOLD-ESC] {src_ip}: keep {ACTION_MAP[current_action]} "
                          f"(hold {hold_age:.0f}s/{MIN_ESCALATE_HOLD:.0f}s)")
                    self._state[src_ip] = s
                    return current_action, False
            s['action_since'] = ts

        elif new_sev == cur_sev:
            # --- SAME SEVERITY ---
            # FIX Bug#3: Still check redirect escalation timer
            if current_action == 2:
                esc = self._check_redirect_escalation(s, ts, obs_raw, src_ip)
                if esc is not None:
                    s['action'] = esc
                    s['action_since'] = ts
                    s.pop('redirect_since', None)
                    self._state[src_ip] = s
                    return esc, True  # changed!
            # No iptables change needed
            self._state[src_ip] = s
            return current_action, False

        else:
            # --- DOWNGRADE ---
            required = CLEAN_WINDOWS_TO_DOWNGRADE.get(cur_sev, 5)
            if required < 0:
                # Block: NEVER downgrade while traffic is still present.
                # If attacker truly stops, expire_stale handles it after 60s silence.
                print(f"\n    [HOLD] {src_ip}: keep Block (traffic still arriving, "
                      f"auto-expires after {BLOCK_IDLE_TTL:.0f}s silence)")
                self._state[src_ip] = s
                return current_action, False

            clean_streak = s.get('clean_streak', 0)
            if clean_streak < required:
                print(f"\n    [HOLD] {src_ip}: keep {ACTION_MAP[current_action]} "
                      f"(clean {clean_streak}/{required})")
                self._state[src_ip] = s
                return current_action, False
            # Enough consecutive clean windows → allow downgrade
            s['action_since'] = ts

        # --- Redirect escalation (for newly set Redirect) ---
        if action == 2:
            esc = self._check_redirect_escalation(s, ts, obs_raw, src_ip)
            if esc is not None:
                action = esc
                s['action_since'] = ts
        elif current_action != 2:
            # Only clear redirect_since if we weren't previously in Redirect.
            # When downgrading FROM Redirect → Allow, keep redirect_since so the
            # escalation timer persists across Redirect→Allow→Redirect cycles
            # (e.g. slow sqlmap with --delay=1 causing intermittent clean windows).
            s.pop('redirect_since', None)

        s['action'] = action
        self._state[src_ip] = s
        return action, True  # changed

    def get(self, src_ip: str) -> dict:
        return self._state.get(src_ip, {})

    def expire_stale(self, now: float, enforce: bool = True):
        """Auto-unblock IPs that have been silent (no new NIDS windows)."""
        for ip, s in list(self._state.items()):
            action = s.get('action', 0)
            if action == 0:
                continue
            last_seen = s.get('ts', now)
            idle_secs = now - last_seen
            # RateLimit: short idle TTL — benign users stop sending → auto-clear quickly
            ttl = RATELIMIT_IDLE_TTL if action == 1 else BLOCK_IDLE_TTL
            if idle_secs >= ttl:
                print(f"\n    [AUTO-UNBLOCK] {ip}: {ACTION_MAP[action]} expired "
                      f"(silent {idle_secs:.0f}s >= {ttl:.0f}s) → Allow")
                apply_action(ip, 0, enforce)
                del self._state[ip]


# ============================================================================
# NGINX EFFECT COLLECTOR (4D effect-side feedback from nginx access.log)
# ============================================================================

import re as _re

_RE_ADDR   = _re.compile(r'^(\S+)')
_RE_TIME   = _re.compile(r'\[([^\]]+)\]')
_RE_UADDR  = _re.compile(r'uaddr="([^"]*)"')
_MONTHS    = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
              'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
NGINX_LOG_PATH   = '/tmp/router-nginx/logs/access.log'
NGINX_WEB_UP     = '192.168.10.10:8080'
NGINX_HONEY_UP   = '192.168.30.10:8081'


def _parse_nginx_ts(ts_str: str) -> float:
    try:
        ts_str = ts_str.split(' ')[0]
        day, mon, rest = ts_str.split('/')
        year, h, m, s  = rest.split(':')
        from datetime import datetime
        return datetime(int(year), _MONTHS[mon], int(day),
                        int(h), int(m), int(s)).timestamp()
    except Exception:
        return time.time()


class NginxEffectCollector:
    """Incrementally reads nginx access.log → 4D effect features per (src_ip, window_ts).

    F21 WebHitRatio, F22 HoneypotHitRatio, F23 PresenceRatio, F24 ServiceDamage.
    All features represent effect of the PREVIOUS step (delayed 1 step causal contract).
    """

    def __init__(self, log_path: str = NGINX_LOG_PATH, window: float = 1.0):
        self._path   = log_path
        self._win    = window
        self._offset = 0
        self._inode  = None
        self._buckets: Dict[Tuple[str, float], dict] = {}

    def ingest(self) -> int:
        """Read new log lines since last call. Returns count of new entries."""
        try:
            st = os.stat(self._path)
        except FileNotFoundError:
            return 0
        if st.st_ino != self._inode or st.st_size < self._offset:
            self._offset = 0
            self._inode  = st.st_ino
        if st.st_size == self._offset:
            return 0
        count = 0
        try:
            with open(self._path, 'r', errors='replace') as f:
                f.seek(self._offset)
                for line in f:
                    m_a = _RE_ADDR.search(line)
                    m_t = _RE_TIME.search(line)
                    m_u = _RE_UADDR.search(line)
                    if not m_a:
                        continue
                    ip  = m_a.group(1)
                    ts  = _parse_nginx_ts(m_t.group(1)) if m_t else time.time()
                    ua  = m_u.group(1) if m_u else '-'
                    dest = ('web' if NGINX_WEB_UP in ua else
                            'honeypot' if NGINX_HONEY_UP in ua else 'none')
                    wts = _math.floor(ts / self._win) * self._win
                    key = (ip, wts)
                    b   = self._buckets.setdefault(key, {'t':0,'w':0,'h':0})
                    b['t'] += 1
                    if dest == 'web':      b['w'] += 1
                    elif dest == 'honeypot': b['h'] += 1
                    count += 1
                self._offset = f.tell()
        except OSError:
            pass
        return count

    def get_effect(self, src_ip: str, window_ts: float,
                   sensor_20d: Optional[List[float]] = None) -> List[float]:
        """Return [F21, F22, F23, F24] for (src_ip, window_ts). Zeros if no data."""
        b = self._buckets.get((src_ip, window_ts), {'t':0,'w':0,'h':0})
        if b['t'] == 0:
            return [0.0, 0.0, 0.0, 0.0]
        f21 = b['w'] / b['t']
        f22 = b['h'] / b['t']
        f23 = 1.0
        if sensor_20d and len(sensor_20d) >= 20:
            f1 = sensor_20d[0]; f2 = sensor_20d[1]; f5 = sensor_20d[4]
            f11 = sensor_20d[10]
            sqli = max(sensor_20d[11:17]); xss = max(sensor_20d[17:20])
            ac = float(min(max(min(f1/200,1), min(f2/10,1),
                              min(f5/50,1)*min(f11/50,1),
                              min((sqli+xss)/2,1)), 1))
        else:
            ac = 1.0
        f24 = float(min(0.7*ac*f21 + 0.3*ac*f23*(1-f22), 1.0))
        return [round(f21,4), round(f22,4), round(f23,4), round(f24,4)]

    def current_wts(self) -> float:
        return _math.floor(time.time() / self._win) * self._win

    def prune(self, max_age: float = 60.0):
        cutoff = self.current_wts() - max_age
        for k in [k for k in self._buckets if k[1] < cutoff]:
            del self._buckets[k]


# ============================================================================
# INFERENCE AGENT
# ============================================================================

class IDSDefenseAgent:
    """PPO agent with 34D input (20D NIDS + 10D temporal + 4D effect) and iptables executor."""

    def __init__(self, model_path: str = './policy_model', enforce: bool = True,
                 demo_safe: bool = False, soft_guard_mode: str = 'off',
                 override0: bool = True):
        try:
            self.model = PPO.load(model_path)
            print(f"[+] Model loaded from {model_path}.zip")
        except FileNotFoundError:
            print(f"[ERROR] Model not found at {model_path}.zip")
            print(f"[HINT]  Run 'python3 train.py' first to train the model.")
            sys.exit(1)

        self.enforce = enforce
        self.demo_safe = demo_safe
        self.override0 = override0
        self.soft_guard_mode = soft_guard_mode if soft_guard_mode in ('off', 'assist') else 'off'
        self.l7_memory: Dict[str, dict] = {}

        # Detect model version from observation space
        obs_dim = self.model.observation_space.shape[0]
        if obs_dim == 34:
            self.model_version = 'v3'
        elif obs_dim == 30:
            self.model_version = 'v2'
        else:
            self.model_version = 'v1'
        print(f"[+] Model version: {self.model_version} ({obs_dim}D observation)")

        if self.model_version == 'v3':
            self.temporal_states: Dict[str, PersistenceTemporalState] = {}
            self.safety_net = SafetyNet(override0=self.override0)
            self.effect_collector = NginxEffectCollector()
            print(f"[+] Effect collector: ON (nginx log → 4D feedback)")
        elif self.model_version == 'v2':
            self.temporal_states: Dict[str, InferenceTemporalState] = {}
            self.safety_net = SafetyNet(override0=self.override0)
            self.guard_tracker = IPStateTracker()
        else:
            self.tracker = IPStateTracker()

        if enforce:
            print("[+] Action enforcement: ON (iptables via nsenter)")
        else:
            print("[+] Action enforcement: OFF (dry-run mode)")
        if demo_safe:
            print("[+] Demo-safe overrides: ON (benign HTTPS decrypt-miss protection)")
        print(f"[+] Soft-guard mode: {self.soft_guard_mode.upper()} "
              f"({'promote to Block when block_ready_latched' if self.soft_guard_mode == 'assist' else 'model decides alone'})")

    @staticmethod
    def _extract_l7_meta(row: dict) -> dict:
        """Read optional L7 confidence metadata emitted by System/main.py."""
        def _to_int(key: str) -> int:
            try:
                return int(row.get(key, 0) or 0)
            except (TypeError, ValueError):
                return 0

        raw_conf = row.get('meta_l7_confident', False)
        if isinstance(raw_conf, str):
            l7_confident = raw_conf.strip().lower() in ('1', 'true', 'yes')
        else:
            l7_confident = bool(raw_conf)

        return {
            'https_data_packets': _to_int('meta_https_data_packets'),
            'https_unenriched_packets': _to_int('meta_https_unenriched_packets'),
            'http_enriched_packets': _to_int('meta_http_enriched_packets'),
            'l7_confident': l7_confident,
        }

    @staticmethod
    def _is_benign_l7_profile(raw: list) -> bool:
        """True when the window lacks both attack signals and strong network abuse."""
        if len(raw) < 20:
            return False

        f1 = raw[0]
        f2 = raw[1]
        f5 = raw[4]
        f6 = raw[5]
        f7 = raw[6]
        f8 = raw[7]
        f11 = raw[10]
        sqli = max(raw[11:17])
        xss = max(raw[17:20])

        has_layer7_attack = (sqli > 0.08 or xss > 0.08)
        has_brute_pattern = (f6 > 0.85 and f7 > 0.75 and f8 > 0.75)
        has_network_attack = (f1 >= 30.0 or f2 >= 3.0 or f5 >= 10.0 or f11 >= 20.0)
        return (not has_layer7_attack and not has_brute_pattern and not has_network_attack)

    def _remember_l7_context(self, src_ip: str, ts: float, raw: list, meta: dict) -> None:
        """Cache recent trustworthy L7 observations to help identify decrypt gaps."""
        if len(raw) < 20 or not meta.get('l7_confident'):
            return

        f6 = raw[5]
        f7 = raw[6]
        f8 = raw[7]
        f9 = raw[8]
        if f6 <= 0.0 and f9 <= 0.0:
            return

        self.l7_memory[src_ip] = {
            'ts': ts,
            'f6': f6,
            'f7': f7,
            'f8': f8,
            'f9': f9,
            'benign_like': self._is_benign_l7_profile(raw),
        }

    def _apply_decrypt_miss_guard(self, src_ip: str, action: int, raw: list, row: dict,
                                  current_action: int = 0) -> Tuple[int, bool, Optional[str]]:
        """Downgrade false restrictions caused by delayed tshark TLS decryption."""
        if len(raw) < 20:
            return action, False, None

        ts = float(row.get('timestamp', time.time()))
        meta = self._extract_l7_meta(row)
        self._remember_l7_context(src_ip, ts, raw, meta)

        likely_decrypt_miss = (
            meta['https_data_packets'] > 0 and
            meta['https_unenriched_packets'] > 0 and
            not meta['l7_confident'] and
            raw[5] <= 0.05 and
            raw[8] <= 0.05
        )
        if not likely_decrypt_miss:
            return action, False, None

        if not self._is_benign_l7_profile(raw):
            return action, False, None

        cached = self.l7_memory.get(src_ip)
        has_recent_benign_memory = (
            cached is not None and
            cached.get('benign_like') and
            (ts - float(cached.get('ts', 0.0))) <= L7_BENIGN_MEMORY_SECONDS
        )

        if action == 0:
            return action, False, None

        if current_action >= 2 and not has_recent_benign_memory:
            return action, False, None

        reason = (
            f"L7 decrypt miss (https={meta['https_data_packets']}, "
            f"unenriched={meta['https_unenriched_packets']}, "
            f"cached_benign={has_recent_benign_memory})"
        )
        print(f"\n    [L7-GUARD] {src_ip}: {reason} → Allow")
        return 0, (current_action >= 2), reason

    def _apply_benign_browse_guard(self, src_ip: str, action: int, raw: list,
                                   row: dict, current_action: int = 0) -> Tuple[int, bool, Optional[str]]:
        """Keep simple benign page browsing at Allow instead of Redirect.

        Narrow scope:
          - only downgrades Redirect
          - requires no SQLi/XSS, no scan/flood signals
          - only for small HTTPS page-fetch windows typical of demo menu option 1
        """
        if action != 2 or len(raw) < 20:
            return action, False, None

        meta = self._extract_l7_meta(row)
        f1 = raw[0]
        f2 = raw[1]
        f4 = raw[3]
        f5 = raw[4]
        f6 = raw[5]
        f8 = raw[7]
        f11 = raw[10]
        sqli = max(raw[11:17])
        xss = max(raw[17:20])

        no_attack_payload = (sqli <= 0.01 and xss <= 0.01)
        no_network_attack = (f2 <= 1.5 and f4 <= 0.10 and f5 <= 2.0 and f11 <= 12.0)
        looks_like_small_browse = (
            meta['https_data_packets'] <= 4 and
            meta['http_enriched_packets'] <= 1 and
            f1 <= 25.0 and
            f8 <= 0.20
        )
        likely_single_page_fetch = (
            f6 >= 0.95 and
            no_attack_payload and
            no_network_attack and
            looks_like_small_browse
        )

        if not likely_single_page_fetch:
            return action, False, None

        reason = (
            f"benign page fetch (F1={f1:.1f}, F6={f6:.2f}, "
            f"https={meta['https_data_packets']}, http={meta['http_enriched_packets']})"
        )
        print(f"\n    [BROWSE-GUARD] {src_ip}: {reason} → Allow")
        return 0, (current_action >= 2), reason

    def _apply_demo_safe_override(self, src_ip: str, action: int, raw: list,
                                  current_action: int = 0) -> int:
        """Fallback heuristic when metadata is unavailable and demo-safe is enabled."""
        if not self.demo_safe or action not in (1, 2) or len(raw) < 20:
            return action

        f1 = raw[0]   # PacketRate
        f6 = raw[5]   # URLConcentration
        f9 = raw[8]   # AvgPayloadSize
        likely_decrypt_miss = (f6 <= 0.05 and f9 <= 0.05)

        if self._is_benign_l7_profile(raw) and likely_decrypt_miss and current_action < 2:
            print(f"\n    [DEMO-SAFE] {src_ip}: benign HTTPS decrypt miss "
                  f"(F1={f1:.1f}, F6={f6:.2f}, F9={f9:.2f}) → Allow")
            return 0

        return action

    def predict(self, row: dict) -> Tuple[int, str, dict]:
        """
        Parse NIDS JSONL row → RL action → apply iptables.

        v2 (30D): Model has temporal memory, SafetyNet only for overrides.
        v1 (20D): Legacy IPStateTracker handles all temporal logic.

        Returns:
            (action_id, action_name, info_dict)
        """
        ts     = float(row.get('timestamp', time.time()))
        src_ip = str(row.get('src_ip', 'unknown'))

        # Skip whitelisted IPs (server, router, internal infra)
        if src_ip in WHITELIST_IPS or src_ip.startswith('192.168.10.'):
            return 0, 'Allow', {'rl_action': 0, 'rl_action_name': 'Allow',
                                'final_action': 0, 'final_action_name': 'Allow',
                                'normalized_obs': [], 'src_ip': src_ip, 'timestamp': ts,
                                'whitelisted': True}

        obs_20d, raw = parse_nids_row(row)

        if self.model_version == 'v3':
            return self._predict_v3(obs_20d, raw, src_ip, ts, row)
        elif self.model_version == 'v2':
            return self._predict_v2(obs_20d, raw, src_ip, ts, row)
        else:
            return self._predict_v1(obs_20d, raw, src_ip, ts, row)

    def _predict_v2(self, obs_20d: np.ndarray, raw: list,
                     src_ip: str, ts: float, row: dict) -> Tuple[int, str, dict]:
        """30D model with temporal memory — model makes temporal decisions."""
        # Get or create temporal state for this IP
        if src_ip not in self.temporal_states:
            self.temporal_states[src_ip] = InferenceTemporalState()
        tstate = self.temporal_states[src_ip]

        # Build 30D observation: 20D base + 10D temporal
        temporal_10d = tstate.to_obs()
        obs_30d = np.concatenate([obs_20d, np.array(temporal_10d, dtype=np.float32)])

        # Model prediction on full 30D observation
        rl_action, _ = self.model.predict(obs_30d, deterministic=True)
        rl_action = int(rl_action)
        current_action = self.guard_tracker.get(src_ip).get('action', 0)
        forced_downgrade = False
        decrypt_miss_reason = None
        rl_action, forced_downgrade, decrypt_miss_reason = self._apply_decrypt_miss_guard(
            src_ip, rl_action, raw, row, current_action
        )
        browse_guard_reason = None
        rl_action, browse_forced, browse_guard_reason = self._apply_benign_browse_guard(
            src_ip, rl_action, raw, row, current_action
        )
        forced_downgrade = forced_downgrade or browse_forced
        rl_action = self._apply_demo_safe_override(src_ip, rl_action, raw, current_action)

        # Safety net overrides (thin guardrails only)
        guarded_action = self.safety_net.apply_safety_overrides(
            src_ip, rl_action, raw, tstate)

        # Reuse legacy hysteresis/hold logic to make v2 behavior easier to explain/demo:
        # Redirect hold/escalation, downgrade streaks, and "don't jump Block -> Allow".
        final_action, changed = self.guard_tracker.update(
            src_ip, guarded_action, ts, raw, force_downgrade=forced_downgrade
        )

        # Compute step damage for temporal state update
        step_damage = compute_network_damage(raw)

        # Update temporal state with final action
        tstate.update(final_action, step_damage)

        # Apply iptables only when action changes
        if changed:
            apply_action(src_ip, final_action, enforce=self.enforce)

        action_name = ACTION_MAP[final_action]
        info = {
            'rl_action': rl_action,
            'rl_action_name': ACTION_MAP[rl_action],
            'final_action': final_action,
            'final_action_name': action_name,
            'normalized_obs': obs_30d.tolist(),
            'src_ip': src_ip,
            'timestamp': ts,
            'model_version': self.model_version,
            't_last_action': tstate.last_action,
            't_last_action_name': ACTION_MAP[tstate.last_action],
            't_action_hold_steps': tstate.action_hold_steps,
            't_damage_ema': tstate.damage_ema,
            't_damage_trend': tstate.damage_trend,
            't_escalation_count': tstate.escalation_count,
            't_steps_since_attack': tstate.steps_since_attack,
            't_step_damage': step_damage,
            'decrypt_miss_guard': decrypt_miss_reason,
            'browse_guard': browse_guard_reason,
        }
        return final_action, action_name, info

    def _predict_v3(self, obs_20d: np.ndarray, raw: list,
                     src_ip: str, ts: float, row: dict) -> Tuple[int, str, dict]:
        """34D model: 20D sensor + 10D temporal + 4D effect (nginx feedback).

        Temporal obs [20..29] mirrors PerIPTemporalState.to_obs() exactly:
          [20..23] last_action one-hot
          [24]     action_hold_norm
          [25]     damage_ema
          [26]     effect_trend
          [27]     soft_window_fill_norm  (window_len / 15)
          [28]     escalation_score_norm
          [29]     miss_budget_used_norm  (miss_count / 3)
        """
        # Temporal state — PersistenceTemporalState inherits PerIPTemporalState exactly
        if src_ip not in self.temporal_states:
            self.temporal_states[src_ip] = PersistenceTemporalState()
        tstate = self.temporal_states[src_ip]

        # Read nginx effect window aligned with the current sensor row.
        # Use previous second (current_wts - 1.0): nginx entries for second S are only
        # guaranteed to be written AFTER ingest() runs at S+0.115s. Requests arriving
        # after 0.115s into second S are logged after ingest() → bucket (ip, S) missed.
        # Looking up S-1 ensures all entries are fully written before we read them.
        self.effect_collector.ingest()
        current_wts = _math.floor(ts / 1.0) * 1.0
        effect_prev = self.effect_collector.get_effect(src_ip, current_wts - 1.0, raw)

        # observe_effect must be called BEFORE stage_action to mirror env step() order:
        # env: observe_effect uses last_action (previous step) → then stage_action updates it
        tstate.observe_effect(effect_prev)
        temporal_10d = tstate.to_obs()

        # Build 34D obs: [20D sensor | 10D temporal | 4D effect_{t-1}]
        obs_34d = np.concatenate([
            obs_20d,
            np.array(temporal_10d, dtype=np.float32),
            np.array(effect_prev,  dtype=np.float32),
        ])

        # Model prediction — also capture action probability distribution for transparency
        rl_action, _ = self.model.predict(obs_34d, deterministic=True)
        rl_action = int(rl_action)
        try:
            import torch as _th
            _obs_t, _ = self.model.policy.obs_to_tensor(obs_34d)
            with _th.no_grad():
                _dist = self.model.policy.get_distribution(_obs_t)
                _probs = _dist.distribution.probs.cpu().numpy().flatten()
            action_probs = {ACTION_MAP[i]: round(float(p), 4) for i, p in enumerate(_probs)}
        except Exception:
            action_probs = None
        current_action = self.safety_net.get(src_ip).get('action', 0)

        # Safety guards (infrastructure-level overrides, not temporal policy)
        rl_action, _, decrypt_miss_reason = self._apply_decrypt_miss_guard(
            src_ip, rl_action, raw, row, current_action)
        rl_action, browse_forced, browse_guard_reason = self._apply_benign_browse_guard(
            src_ip, rl_action, raw, row, current_action)
        rl_action = self._apply_demo_safe_override(src_ip, rl_action, raw, current_action)
        guarded_action = self.safety_net.apply_safety_overrides(src_ip, rl_action, raw, tstate)
        final_action = guarded_action

        # soft_guard_mode=assist: promote to Block if session evidence is complete.
        # Fires when block_ready_latched=True — no F23 presence check needed because
        # block_ready_latched already encodes multi-window honeypot+presence evidence.
        # Removing the F23 condition fixes a timing gap: at the exact window when
        # escalation_score crosses 0.60, nginx may return F23=0 for that 1s bucket
        # (due to log flush timing), causing soft_guard to miss even though it should fire.
        # Does NOT intervene for benign/noisy/scan/syn_flood — only for L7 session IPs
        # (block_ready_latched requires redirect_hits≥6, honeypot_hits≥5, presence_hits≥8).
        soft_guard_promoted = False
        if (self.soft_guard_mode == 'assist'
                and final_action < 3
                and tstate.block_ready_latched):
            final_action = 3
            soft_guard_promoted = True

        # l7_signal for session start/continuation — must be computed from raw (pre-action)
        l7_signal = float(compute_attack_signals(raw)['l7_presence']) if len(raw) >= 20 else 0.0

        # stage_action AFTER all overrides so temporal state reflects the actual applied action
        tstate.stage_action(final_action, l7_signal=l7_signal)
        changed = self.safety_net.update(src_ip, final_action, ts)

        # Prune old nginx log buckets periodically
        if int(ts) % 30 == 0:
            self.effect_collector.prune()

        if changed:
            apply_action(src_ip, final_action, enforce=self.enforce)

        action_name = ACTION_MAP[final_action]
        info = {
            'rl_action': rl_action,
            'rl_action_name': ACTION_MAP[rl_action],
            'final_action': final_action,
            'final_action_name': action_name,
            'normalized_obs': obs_34d.tolist(),
            'src_ip': src_ip,
            'timestamp': ts,
            'window_ts': current_wts,
            'model_version': self.model_version,
            'effect_prev': effect_prev,
            'effect': effect_prev,
            # Soft-session temporal state fields (mirrors plan.md §5 log fields)
            't_last_action': tstate.last_action,
            't_last_action_name': ACTION_MAP[tstate.last_action],
            't_action_hold_steps': tstate.action_hold_steps,
            't_damage_ema': round(tstate.damage_ema, 4),
            't_damage_trend': round(tstate.damage_trend, 4),
            't_session_active': tstate.session_active,
            't_soft_window_len': tstate.window_len,
            't_redirect_hits': tstate.redirect_hits,
            't_presence_hits': tstate.presence_hits,
            't_honeypot_hits': tstate.honeypot_hits,
            't_miss_count': tstate.miss_count,
            't_escalation_score': round(tstate.escalation_score, 4),
            't_block_ready': tstate.block_ready_latched,
            't_clean_streak': tstate.clean_streak,
            # Guard metadata
            'soft_guard_promoted': soft_guard_promoted,
            'decrypt_miss_guard': decrypt_miss_reason,
            'browse_guard': browse_guard_reason,
            'browse_forced': browse_forced,
            # Transparency: raw neural network output — proves RL made the decision
            'action_probs': action_probs,
            'normalized_obs': obs_34d.tolist(),
        }
        return final_action, action_name, info

    def _predict_v1(self, obs: np.ndarray, raw: list,
                     src_ip: str, ts: float, row: dict) -> Tuple[int, str, dict]:
        """Legacy 20D model — full IPStateTracker handles temporal logic."""
        rl_action, _ = self.model.predict(obs, deterministic=True)
        rl_action = int(rl_action)

        # Legacy policy overrides
        if rl_action == 3 and len(raw) >= 20:
            xss_score   = max(raw[17:20])
            sqli_score  = max(raw[11:17])
            brute_score = max(raw[5], raw[6], raw[7])
            if xss_score > 0.1 or sqli_score > 0.1 or brute_score > 0.5:
                rl_action = 2

        current_action = self.tracker.get(src_ip).get('action', 0)
        forced_downgrade = False
        decrypt_miss_reason = None
        rl_action, forced_downgrade, decrypt_miss_reason = self._apply_decrypt_miss_guard(
            src_ip, rl_action, raw, row, current_action
        )
        browse_guard_reason = None
        rl_action, browse_forced, browse_guard_reason = self._apply_benign_browse_guard(
            src_ip, rl_action, raw, row, current_action
        )
        forced_downgrade = forced_downgrade or browse_forced
        rl_action = self._apply_demo_safe_override(src_ip, rl_action, raw, current_action)

        final_action, changed = self.tracker.update(
            src_ip, rl_action, ts, raw, force_downgrade=forced_downgrade
        )

        if changed:
            apply_action(src_ip, final_action, enforce=self.enforce)

        action_name = ACTION_MAP[final_action]
        info = {
            'rl_action': rl_action,
            'rl_action_name': ACTION_MAP[rl_action],
            'final_action': final_action,
            'final_action_name': action_name,
            'normalized_obs': obs.tolist(),
            'src_ip': src_ip,
            'timestamp': ts,
            'model_version': self.model_version,
            'decrypt_miss_guard': decrypt_miss_reason,
            'browse_guard': browse_guard_reason,
        }
        return final_action, action_name, info


# ============================================================================
# REAL-TIME JSONL WATCHER
# ============================================================================

VALID_LABELS = [
    'normal', 'benign', 'noisy_normal',
    'scan', 'syn_flood',
    'brute_force', 'brute_force_ka',
    'sqli', 'xss', 'sqli_xss',
    'grayzone',
    'slowloris',
]


def _build_wazuh_log(action_log: dict) -> dict:
    """Return a flat action event that Wazuh Indexer can map consistently."""
    return {
        key: value
        for key, value in action_log.items()
        if key not in {'action_probs', 'normalized_obs'}
    }


def watch_jsonl(agent: IDSDefenseAgent, input_file: str,
                output_file: str = 'actions.log', from_begin: bool = False,
                label: Optional[str] = None, training_data_file: str = 'training_data.jsonl',
                collect_file: Optional[str] = None,
                wazuh_output_file: Optional[str] = 'actions_wazuh.log'):
    """Tail sniffer_output.jsonl and write actions.log.

    If --label is provided, also appends labeled feature records to training_data.jsonl
    for future fine-tuning.

    If --collect is provided, continuously logs ALL raw features + AI action (no label)
    to the specified file. Admin can review later and add labels for retraining — this
    allows passive data collection without interrupting production inference.
    """

    if not os.path.exists(input_file):
        print(f"[*] Creating empty {input_file} (waiting for NIDS sniffer)...")
        open(input_file, 'w').close()

    print(f"[*] Watching {input_file}")
    print(f"[*] Writing actions to {output_file}")
    if wazuh_output_file:
        print(f"[*] Writing Wazuh-safe actions to {wazuh_output_file}")
    if label:
        print(f"[*] Collecting training data — label: '{label}' → {training_data_file}")
    if collect_file:
        print(f"[*] Passive collection ON — all raw features → {collect_file}")
        print(f"[*]   (review & label later with: label_traffic.py --input {collect_file})")
    print(f"[*] Mode: {'from-begin' if from_begin else 'tail'}\n")

    file_pos  = 0
    cur_inode = None
    last_expire_check = time.time()
    _waiting_shown = False  # Print "Waiting..." only once
    train_f = None
    collect_f = None
    wazuh_f = None

    try:
        train_f   = open(training_data_file, 'a') if label else None
        collect_f = open(collect_file, 'a') if collect_file else None
        wazuh_f   = (
            open(wazuh_output_file, 'a')
            if wazuh_output_file and wazuh_output_file != output_file
            else None
        )
        with open(output_file, 'a') as out_f:
            while True:
                try:
                    st = os.stat(input_file)
                    new_inode = st.st_ino
                    file_size = st.st_size
                except (OSError, FileNotFoundError):
                    time.sleep(0.2)
                    continue

                # Rotation / truncation detection
                if cur_inode is not None and (new_inode != cur_inode or file_size < file_pos):
                    print("\n[*] File rotated/truncated, resetting...")
                    file_pos = 0
                    _waiting_shown = False
                cur_inode = new_inode

                try:
                    with open(input_file, 'r') as in_f:
                        if file_pos == 0:
                            if not from_begin:
                                in_f.seek(0, 2)   # Tail: jump to end
                                file_pos = in_f.tell()
                                if not _waiting_shown:
                                    print("[*] Waiting for new NIDS data...")
                                    _waiting_shown = True
                                time.sleep(0.5)
                                continue
                            # from_begin: read from start
                        else:
                            in_f.seek(file_pos)

                        new_data = False
                        while True:
                            line = in_f.readline()
                            if not line:
                                file_pos = in_f.tell()
                                break
                            line = line.strip()
                            if not line:
                                continue
                            new_data = True

                            try:
                                row = json.loads(line)
                                ts  = row.get('timestamp', time.time())
                                src = row.get('src_ip', 'unknown')

                                final_action, action_name, info = agent.predict(row)

                                log = {
                                    'timestamp': ts,
                                    'window_ts': info.get('window_ts', ts),
                                    'src_ip': src,
                                    'rl_action': info['rl_action'],
                                    'rl_action_name': info['rl_action_name'],
                                    'final_action': final_action,
                                    'final_action_name': action_name,
                                }
                                if 't_last_action' in info:
                                    log.update({
                                        'model_version': info['model_version'],
                                        't_last_action': info['t_last_action'],
                                        't_last_action_name': info['t_last_action_name'],
                                        't_action_hold_steps': info['t_action_hold_steps'],
                                        't_damage_ema': info['t_damage_ema'],
                                        't_damage_trend': info['t_damage_trend'],
                                        't_clean_streak': info.get('t_clean_streak'),
                                        # v3 escalation fields
                                        't_window_len': info.get('t_soft_window_len'),
                                        't_redirect_hits': info.get('t_redirect_hits'),
                                        't_presence_hits': info.get('t_presence_hits'),
                                        't_honeypot_hits': info.get('t_honeypot_hits'),
                                        't_escalation_score': info.get('t_escalation_score'),
                                        't_block_ready': info.get('t_block_ready'),
                                        'soft_guard_promoted': info.get('soft_guard_promoted'),
                                        # Neural network transparency fields
                                        'action_probs': info.get('action_probs'),
                                        'normalized_obs': info.get('normalized_obs'),
                                    })
                                elif 'model_version' in info:
                                    log['model_version'] = info['model_version']
                                if not info.get('whitelisted', False):
                                    out_f.write(json.dumps(log) + '\n')
                                    out_f.flush()
                                    if wazuh_f is not None:
                                        wazuh_f.write(json.dumps(_build_wazuh_log(log)) + '\n')
                                        wazuh_f.flush()

                                raw_features = [float(row.get(k, 0.0)) for k in NIDS_KEY_ORDER]

                                if train_f is not None and not src.startswith('192.168.'):
                                    # Labeled collection (--label mode)
                                    train_record = {
                                        'timestamp': ts,
                                        'window_ts': info.get('window_ts', ts),
                                        'src_ip': src,
                                        'label': label,
                                        'final_action': final_action,
                                        'features': raw_features,
                                        'effect_source': 'observed_prev_window',
                                        'effect_prev_4d': info.get('effect_prev'),
                                        'effect_4d': info.get('effect'),
                                    }
                                    train_f.write(json.dumps(train_record) + '\n')
                                    train_f.flush()

                                if collect_f is not None and not src.startswith('192.168.'):
                                    # Passive collection (--collect mode): no label, review later
                                    collect_record = {
                                        'timestamp': ts,
                                        'window_ts': info.get('window_ts', ts),
                                        'src_ip': src,
                                        'label': None,   # to be filled by admin later
                                        'ai_action': action_name,
                                        'final_action': final_action,
                                        'features': raw_features,
                                        'effect_source': 'observed_prev_window',
                                        'effect_prev_4d': info.get('effect_prev'),
                                        'effect_4d': info.get('effect'),
                                    }
                                    collect_f.write(json.dumps(collect_record) + '\n')
                                    collect_f.flush()

                                # Skip display for whitelisted IPs — their Allow would
                                # overwrite attacker's Block on screen via \r
                                if not info.get('whitelisted', False):
                                    escalated = ''
                                    if final_action != info['rl_action']:
                                        escalated = f" [ESC from {info['rl_action_name']}]"
                                    line_out = (
                                        f"\r[{ts:.1f}] {src:15s} | "
                                        f"RL:{info['rl_action_name']:10s} → "
                                        f"FINAL:{action_name:10s}{escalated:<25}"
                                    )
                                    # Action line: overwrite in-place (no scroll spam)
                                    # HOLD/ESCALATE/ERROR messages are on their own lines above
                                    print(line_out, end='', flush=True)

                            except json.JSONDecodeError as e:
                                print(f"\n[WARN] Bad JSON: {line[:60]}... ({e})")
                            except Exception as e:
                                print(f"\n[ERROR] {e}")

                        if not new_data:
                            time.sleep(0.1)

                        # Periodically auto-unblock idle IPs
                        now = time.time()
                        if now - last_expire_check >= EXPIRE_CHECK_INTERVAL:
                            if agent.model_version == 'v3':
                                agent.safety_net.expire_stale(now, enforce=agent.enforce)
                            elif agent.model_version == 'v2':
                                agent.guard_tracker.expire_stale(now, enforce=agent.enforce)
                            else:
                                agent.tracker.expire_stale(now, enforce=agent.enforce)
                            last_expire_check = now

                except FileNotFoundError:
                    time.sleep(0.3)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        if wazuh_f is not None:
            wazuh_f.close()
        if train_f is not None:
            train_f.close()
        if collect_f is not None:
            collect_f.close()


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_mode(agent: IDSDefenseAgent):
    """Manual testing with NIDS-format JSON input."""
    print("[*] Interactive Mode — paste NIDS JSON row (or 'quit')\n")
    print("Example:")
    print('  {"src_ip": "10.0.0.100", "F1 - PacketRate": 350, "F2 - SynAckRatio": 10,')
    print('   "F5 - DistinctPorts": 1, "F6 - URLConcentration": 0, "F18 - CrsXssScore": 0}')
    print()

    try:
        while True:
            line = input("> ").strip()
            if line.lower() in ('quit', 'exit', 'q'):
                break
            try:
                row = json.loads(line)
                final_action, action_name, info = agent.predict(row)
                print(f"  RL: {info['rl_action_name']} → Final: {action_name}")
                print(f"  Obs[0..4]: {[f'{x:.3f}' for x in info['normalized_obs'][:5]]}")
                print()
            except json.JSONDecodeError:
                print("[ERROR] Invalid JSON\n")
            except Exception as e:
                print(f"[ERROR] {e}\n")
    except KeyboardInterrupt:
        print("\n[*] Exiting.")


# ============================================================================
# MAIN CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='IDS Defense Agent — Real-time NIDS 20D Inference + iptables Enforcement',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Watch NIDS sniffer output (tail mode)
  python3 infer.py --watch /tmp/sniffer_output.jsonl

  # Process from beginning
  python3 infer.py --watch /tmp/sniffer_output.jsonl --from-begin

  # Dry-run (no iptables)
  python3 infer.py --watch /tmp/sniffer_output.jsonl --no-enforce

  # Demo-safe mode (benign HTTPS decrypt-miss protection)
  python3 infer.py --watch /tmp/sniffer_output.jsonl --demo-safe

  # Interactive
  python3 infer.py --interactive
        """
    )
    parser.add_argument('--watch', type=str, help='Watch NIDS JSONL file in real-time')
    parser.add_argument('--from-begin', action='store_true', help='Process entire file from start')
    parser.add_argument('--interactive', action='store_true', help='Interactive testing mode')
    parser.add_argument('--no-enforce', action='store_true', help='Dry-run: print actions, no iptables')
    parser.add_argument('--demo-safe', action='store_true',
                        help='Demo-only guardrail: downgrade false benign HTTPS RateLimit caused by delayed tshark decrypt')
    parser.add_argument('--no-override0', action='store_true',
                        help='Disable Override 0 (L7 cold-start Redirect forcing). Default: ON')
    parser.add_argument('--soft-guard', type=str, default='off', choices=['off', 'assist'],
                        help='Soft-guard mode (default: off). '
                             '"assist": promote to Block when block_ready_latched=True and attacker still present')
    parser.add_argument('--model', type=str, default='./policy_model', help='Model path (without .zip)')
    parser.add_argument('--output', type=str, default='actions.log', help='Output log file')
    parser.add_argument('--wazuh-output', type=str, default='actions_wazuh.log',
                        help='Flat Wazuh-safe action log file (default: actions_wazuh.log)')
    parser.add_argument('--no-wazuh-output', action='store_true',
                        help='Disable the separate Wazuh-safe action log')
    parser.add_argument('--label', type=str, choices=VALID_LABELS, default=None,
                        help='Label current traffic for training data collection '
                             f'(choices: {", ".join(VALID_LABELS)})')
    parser.add_argument('--training-data', type=str, default='training_data.jsonl',
                        help='Output file for labeled training data (default: training_data.jsonl)')
    parser.add_argument('--collect', type=str, default=None, metavar='FILE',
                        help='Passive collection: log ALL raw features + AI action to FILE '
                             'without label, for admin review and future retraining')
    args = parser.parse_args()

    print("\n" + "="*70)
    print("IDS DEFENSE AGENT — NIDS 20D INFERENCE ENGINE")
    print("="*70 + "\n")

    agent = IDSDefenseAgent(
        model_path=args.model,
        enforce=not args.no_enforce,
        demo_safe=args.demo_safe,
        soft_guard_mode=args.soft_guard,
        override0=not args.no_override0,
    )

    if args.watch:
        watch_jsonl(agent, args.watch, output_file=args.output, from_begin=args.from_begin,
                    label=args.label, training_data_file=args.training_data,
                    collect_file=args.collect,
                    wazuh_output_file=None if args.no_wazuh_output else args.wazuh_output)
    elif args.interactive:
        interactive_mode(agent)
    else:
        print("[!] No mode specified. Use --watch or --interactive")
        parser.print_help()


if __name__ == '__main__':
    main()
