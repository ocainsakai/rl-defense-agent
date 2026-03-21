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
import numpy as np
import argparse
import sys
import time
import os
import subprocess
from typing import Dict, List, Optional, Tuple
from stable_baselines3 import PPO
from env_ids import normalize_observation

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
# STATE TRACKER (per-IP action + redirect escalation)
# ============================================================================

REDIRECT_TTL_SECONDS  = 15.0   # Escalate Redirect → Block after this time
MIN_ESCALATE_HOLD     = 10.0   # Min time before escalating (e.g. RateLimit→Redirect)
CLEAN_WINDOWS_TO_DOWNGRADE = {  # Per-severity: how many clean 1s windows before downgrading
    3: -1,  # Block: NEVER downgrade via clean_streak (only expire_stale after 60s silence)
    2: 10,  # Redirect: 10 consecutive clean windows (10s)
    1: 2,   # RateLimit: 2 consecutive clean windows (2s) — fast recovery for benign traffic
}
BLOCK_IDLE_TTL        = 60.0   # Auto-unblock Block after this many seconds of silence
RATELIMIT_IDLE_TTL    = 8.0    # Auto-clear RateLimit after 8s silence (no NIDS windows emitted)
EXPIRE_CHECK_INTERVAL = 5.0    # How often to scan for idle blocked IPs (seconds)

# Severity order: Allow(0) < RateLimit(1) < Redirect(2) < Block(3)
ACTION_SEVERITY = {0: 0, 1: 1, 2: 2, 3: 3}


class IPStateTracker:
    """Track per-IP action state with hysteresis and escalation logic.

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
               obs_raw: List[float]) -> Tuple[int, bool]:
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

        if new_sev > cur_sev:
            # --- ESCALATION ---
            if cur_sev > 0:   # already restricted
                hold_age = ts - action_since
                strong = is_attack  # any attack signal → immediate escalation
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
# INFERENCE AGENT
# ============================================================================

class IDSDefenseAgent:
    """PPO agent with NIDS 20D input and iptables action executor."""

    def __init__(self, model_path: str = './policy_model', enforce: bool = True):
        try:
            self.model = PPO.load(model_path)
            print(f"[+] Model loaded from {model_path}.zip")
        except FileNotFoundError:
            print(f"[ERROR] Model not found at {model_path}.zip")
            print(f"[HINT]  Run 'python3 train.py' first to train the model.")
            sys.exit(1)

        self.enforce = enforce
        self.tracker = IPStateTracker()

        if enforce:
            print("[+] Action enforcement: ON (iptables via nsenter)")
        else:
            print("[+] Action enforcement: OFF (dry-run mode)")

    def predict(self, row: dict) -> Tuple[int, str, dict]:
        """
        Parse NIDS JSONL row → RL action → apply iptables.

        Args:
            row: NIDS JSONL dict with keys like 'F1 - PacketRate', 'src_ip', etc.

        Returns:
            (action_id, action_name, info_dict)
        """
        ts     = float(row.get('timestamp', time.time()))
        src_ip = str(row.get('src_ip', 'unknown'))

        # Skip whitelisted IPs (server, router, internal infra) — no display, no iptables
        if src_ip in WHITELIST_IPS or src_ip.startswith('192.168.10.'):
            return 0, 'Allow', {'rl_action': 0, 'rl_action_name': 'Allow',
                                'final_action': 0, 'final_action_name': 'Allow',
                                'normalized_obs': [], 'src_ip': src_ip, 'timestamp': ts,
                                'whitelisted': True}

        obs, raw = parse_nids_row(row)

        rl_action, _ = self.model.predict(obs, deterministic=True)
        rl_action = int(rl_action)

        # Attack-type policy override:
        # Layer-7 attacks (XSS/SQLi) → always Redirect to honeypot FIRST.
        # Rationale: honeypot gathers attacker payloads + attacker doesn't know
        # they've been detected. Block escalation happens after REDIRECT_TTL_SECONDS.
        # DDoS/SYN flood (high F1/F2, no payload) → Block is correct.
        if rl_action == 3 and len(raw) >= 20:
            xss_score  = max(raw[17:20])   # F18-F20
            sqli_score = max(raw[11:17])   # F12-F17
            if xss_score > 0.1 or sqli_score > 0.1:
                rl_action = 2  # XSS/SQLi → Redirect (not Block)

        # Apply escalation logic
        final_action, changed = self.tracker.update(src_ip, rl_action, ts, raw)

        # FIX Bug#4: Only touch iptables when action actually changes
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
        }
        return final_action, action_name, info


# ============================================================================
# REAL-TIME JSONL WATCHER
# ============================================================================

VALID_LABELS = ['normal', 'scan', 'syn_flood', 'brute_force', 'sqli_xss', 'grayzone']


def watch_jsonl(agent: IDSDefenseAgent, input_file: str,
                output_file: str = 'actions.log', from_begin: bool = False,
                label: Optional[str] = None, training_data_file: str = 'training_data.jsonl',
                collect_file: Optional[str] = None):
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

    try:
        train_f   = open(training_data_file, 'a') if label else None
        collect_f = open(collect_file, 'a') if collect_file else None
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
                                    'src_ip': src,
                                    'rl_action': info['rl_action'],
                                    'rl_action_name': info['rl_action_name'],
                                    'final_action': final_action,
                                    'final_action_name': action_name,
                                }
                                out_f.write(json.dumps(log) + '\n')
                                out_f.flush()

                                raw_features = [float(row.get(k, 0.0)) for k in NIDS_KEY_ORDER]

                                if train_f is not None:
                                    # Labeled collection (--label mode)
                                    train_record = {
                                        'timestamp': ts,
                                        'src_ip': src,
                                        'label': label,
                                        'features': raw_features,
                                    }
                                    train_f.write(json.dumps(train_record) + '\n')
                                    train_f.flush()

                                if collect_f is not None:
                                    # Passive collection (--collect mode): no label, review later
                                    collect_record = {
                                        'timestamp': ts,
                                        'src_ip': src,
                                        'label': None,   # to be filled by admin later
                                        'ai_action': action_name,
                                        'features': raw_features,
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
                            agent.tracker.expire_stale(now, enforce=agent.enforce)
                            last_expire_check = now

                except FileNotFoundError:
                    time.sleep(0.3)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
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

  # Interactive
  python3 infer.py --interactive
        """
    )
    parser.add_argument('--watch', type=str, help='Watch NIDS JSONL file in real-time')
    parser.add_argument('--from-begin', action='store_true', help='Process entire file from start')
    parser.add_argument('--interactive', action='store_true', help='Interactive testing mode')
    parser.add_argument('--no-enforce', action='store_true', help='Dry-run: print actions, no iptables')
    parser.add_argument('--model', type=str, default='./policy_model', help='Model path (without .zip)')
    parser.add_argument('--output', type=str, default='actions.log', help='Output log file')
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
        enforce=not args.no_enforce
    )

    if args.watch:
        watch_jsonl(agent, args.watch, output_file=args.output, from_begin=args.from_begin,
                    label=args.label, training_data_file=args.training_data,
                    collect_file=args.collect)
    elif args.interactive:
        interactive_mode(agent)
    else:
        print("[!] No mode specified. Use --watch or --interactive")
        parser.print_help()


if __name__ == '__main__':
    main()
