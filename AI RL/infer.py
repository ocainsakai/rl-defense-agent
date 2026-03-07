"""
PPO Agent Inference Script - Real-time NIDS JSONL Processing

Reads sniffer_output.jsonl (produced by System/main.py) in real-time,
normalizes 20D feature vector, runs PPO model, and applies iptables actions
on the router namespace via nsenter.

OBSERVATION VECTOR (20D, matches NIDS FEATURE_ORDER):
  [F1-PacketRate, F2-SynAckRatio, ..., F20-HtmlEventHandler]

ACTION MAPPING (attack-type driven):
  0 = Allow      — normal traffic
  1 = RateLimit  — noise / grayzone
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
    """Remove all existing rules for this IP (idempotent cleanup)."""
    # Remove FORWARD DROP rule
    _run_router(
        f"iptables -D FORWARD -s {src_ip} -j DROP 2>/dev/null; true",
        enforce
    )
    # Remove FORWARD hashlimit rule
    _run_router(
        f"iptables -D FORWARD -s {src_ip} -m hashlimit "
        f"--hashlimit-name rl_{src_ip.replace('.','_')} "
        f"--hashlimit-above 10/sec --hashlimit-burst 20 -j DROP 2>/dev/null; true",
        enforce
    )
    # Remove NAT redirect rule
    _run_router(
        f"iptables -t nat -D PREROUTING -i {ROUTER_IFACE_EXT} -s {src_ip} "
        f"-d {SERVER_IP} -p tcp --dport {SERVER_PORT} "
        f"-j REDIRECT --to-ports {HONEYPOT_PORT} 2>/dev/null; true",
        enforce
    )


def apply_action(src_ip: str, action: int, enforce: bool = True):
    """Apply firewall action for a given source IP."""
    _del_rule(src_ip, enforce)

    if action == 0:   # Allow — rules already deleted above
        pass

    elif action == 1:  # RateLimit — throttle at 10 pps
        _run_router(
            f"iptables -I FORWARD 1 -s {src_ip} "
            f"-m hashlimit --hashlimit-name rl_{src_ip.replace('.','_')} "
            f"--hashlimit-above 10/sec --hashlimit-burst 20 -j DROP",
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
        _run_router(
            f"iptables -I FORWARD 1 -s {src_ip} -j DROP",
            enforce
        )


# ============================================================================
# STATE TRACKER (per-IP action + redirect escalation)
# ============================================================================

REDIRECT_TTL_SECONDS = 60.0   # Escalate Redirect → Block after this time

class IPStateTracker:
    """Track per-IP action state for escalation logic."""

    def __init__(self):
        self._state: Dict[str, dict] = {}

    def update(self, src_ip: str, action: int, ts: float, obs_raw: List[float]) -> int:
        """
        Update state for src_ip and apply escalation:
          - If Redirect and attacker persists > REDIRECT_TTL_SECONDS → Block
        Returns final action (possibly escalated).
        """
        s = self._state.get(src_ip, {})

        if action == 2:  # Redirect
            if 'redirect_since' not in s:
                s['redirect_since'] = ts
            else:
                # Check escalation: still attacking after TTL?
                age = ts - s['redirect_since']
                if age > REDIRECT_TTL_SECONDS:
                    # Check if still showing attack signals
                    f6 = obs_raw[5]; f7 = obs_raw[6]; f8 = obs_raw[7]
                    sqli = max(obs_raw[11], obs_raw[12]/20, float(obs_raw[13]>0))
                    xss  = max(obs_raw[17]/4, float(obs_raw[18]>0))
                    still_attacking = (f6 > 0.5 or f7 > 0.6 or f8 > 0.6
                                       or sqli > 0.2 or xss > 0.2)
                    if still_attacking:
                        print(f"    [ESCALATE] {src_ip}: Redirect → Block "
                              f"(persisted {age:.0f}s > {REDIRECT_TTL_SECONDS:.0f}s)")
                        action = 3
                        s.pop('redirect_since', None)
        else:
            s.pop('redirect_since', None)

        s['action'] = action
        s['ts'] = ts
        self._state[src_ip] = s
        return action

    def get(self, src_ip: str) -> dict:
        return self._state.get(src_ip, {})


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

        obs, raw = parse_nids_row(row)

        rl_action, _ = self.model.predict(obs, deterministic=True)
        rl_action = int(rl_action)

        # Apply escalation logic
        final_action = self.tracker.update(src_ip, rl_action, ts, raw)

        # Apply iptables
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

def watch_jsonl(agent: IDSDefenseAgent, input_file: str,
                output_file: str = 'actions.log', from_begin: bool = False):
    """Tail sniffer_output.jsonl and write actions.log."""

    if not os.path.exists(input_file):
        print(f"[*] Creating empty {input_file} (waiting for NIDS sniffer)...")
        open(input_file, 'w').close()

    print(f"[*] Watching {input_file}")
    print(f"[*] Writing actions to {output_file}")
    print(f"[*] Mode: {'from-begin' if from_begin else 'tail'}\n")

    file_pos  = 0
    cur_inode = None

    try:
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
                    print("[*] File rotated/truncated, resetting...")
                    file_pos = 0
                cur_inode = new_inode

                try:
                    with open(input_file, 'r') as in_f:
                        if file_pos == 0:
                            if not from_begin:
                                in_f.seek(0, 2)   # Tail: jump to end
                                file_pos = in_f.tell()
                                print("[*] Waiting for new NIDS data...\n")
                                time.sleep(0.1)
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

                                escalated = ''
                                if final_action != info['rl_action']:
                                    escalated = f" [ESCALATED from {info['rl_action_name']}]"
                                print(f"[{ts:.1f}] {src:15s} | "
                                      f"RL:{info['rl_action_name']:10s} → "
                                      f"{action_name:10s}{escalated}")
                                sys.stdout.flush()

                            except json.JSONDecodeError as e:
                                print(f"[WARN] Bad JSON: {line[:60]}... ({e})")
                            except Exception as e:
                                print(f"[ERROR] {e}")

                        if not new_data:
                            time.sleep(0.1)

                except FileNotFoundError:
                    time.sleep(0.3)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")


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
    args = parser.parse_args()

    print("\n" + "="*70)
    print("IDS DEFENSE AGENT — NIDS 20D INFERENCE ENGINE")
    print("="*70 + "\n")

    agent = IDSDefenseAgent(
        model_path=args.model,
        enforce=not args.no_enforce
    )

    if args.watch:
        watch_jsonl(agent, args.watch, output_file=args.output, from_begin=args.from_begin)
    elif args.interactive:
        interactive_mode(agent)
    else:
        print("[!] No mode specified. Use --watch or --interactive")
        parser.print_help()


if __name__ == '__main__':
    main()
