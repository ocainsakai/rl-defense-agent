"""
pcap_benchmark.py — Full PCAP-based benchmark for the current RL defense model.

Pipeline:
  1. Filter large PCAPs by attacker IPs + time windows (tshark) → mini-PCAPs
  2. Extract 20D NIDS features via System's FlowFeatureCalculator
     - F1-F11 (network): Scapy packet parsing
     - F6-F20 (L7):  tshark offline HTTP extraction + enrich_flows_with_tshark
  3. Label each 1s window by timestamp + src_ip
  4. Run IDSDefenseAgent chronologically on the extracted NIDS windows
  5. Verify + report: accuracy, confusion matrix, per-class metrics

Timezone note: CIC-IDS2018 recorded in Halifax, Nova Scotia = AST = UTC-4 (winter).
All attack times from dataset metadata are in AST, converted to UTC epoch below.

Usage:
  cd /home/binhhl/Downloads/rl-defense-agent
  python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py [--model runs/run_34d_v13/best_model]
  python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py --skip-extract  # reuse cached JSONL
  python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py --verify-only   # verify cache only
"""

from __future__ import annotations

import argparse
import calendar
import datetime
import json
import os
import subprocess
import sys
import time

import numpy as np
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ─── Path setup ───────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parents[2]
SYSTEM_DIR = REPO_ROOT / "System"
AIRL_DIR   = REPO_ROOT / "AI RL"
CACHE_DIR  = Path(__file__).parent / "pcap_cache"

for p in (str(SYSTEM_DIR), str(AIRL_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# ─── Timezone helper ──────────────────────────────────────────────────────────
def _ast(date_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' AST (UTC-4) string to Unix epoch."""
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return float(calendar.timegm(dt.timetuple())) + 4 * 3600

# ─── Attack metadata (times in AST = UTC-4, Halifax) ─────────────────────────
DDOS_ATTACKERS = [
    "18.218.115.60", "18.219.9.1",    "18.219.32.43",  "18.218.55.126",
    "52.14.136.135", "18.219.5.43",   "18.216.200.189", "18.218.229.235",
    "18.218.11.51",  "18.216.24.42",
]

ATTACK_DAYS = [
    {
        "day":        "Thursday-22-02-2018",
        "pcap":       "/mnt/hgfs/Dataset/Thursday-22-02-2018_pcap/pcap/UCAP172.31.69.28",
        "pcap_large": False,
        "attackers":  ["18.218.115.60"],
        "windows": [
            (_ast("2018-02-22 10:17:00"), _ast("2018-02-22 11:24:00"),
             "brute_force", "Redirect", "Brute Force-Web"),
            (_ast("2018-02-22 13:50:00"), _ast("2018-02-22 14:29:00"),
             "xss",         "Redirect", "Brute Force-XSS"),
            (_ast("2018-02-22 16:15:00"), _ast("2018-02-22 16:29:00"),
             "sqli",        "Redirect", "SQL Injection"),
        ],
        "benign_cap": 500,
    },
    {
        "day":        "Tuesday-20-02-2018",
        "pcap":       "/mnt/hgfs/Dataset/Tuesday/pcap/UCAP172.31.69.25",
        "pcap_large": True,
        "attackers":  DDOS_ATTACKERS,
        "windows": [
            (_ast("2018-02-20 10:12:00"), _ast("2018-02-20 11:17:00"),
             "syn_flood", "Block", "DDoS-LOIC-HTTP"),
            (_ast("2018-02-20 13:13:00"), _ast("2018-02-20 13:32:00"),
             "syn_flood", "Block", "DDoS-LOIC-UDP"),
        ],
        "benign_cap": 300,
    },
    {
        "day":        "Wednesday-21-02-2018",
        "pcap":       "/mnt/hgfs/Dataset/Wednesday/pcap/UCAP172.31.69.28 part 1",
        "pcap_extra": "/mnt/hgfs/Dataset/Wednesday/pcap/UCAP172.31.69.28 part 2",
        "pcap_large": True,
        "attackers":  DDOS_ATTACKERS,
        "windows": [
            (_ast("2018-02-21 10:09:00"), _ast("2018-02-21 10:43:00"),
             "syn_flood", "Block", "DDOS-LOIC-UDP"),
            (_ast("2018-02-21 14:05:00"), _ast("2018-02-21 15:05:00"),
             "syn_flood", "Block", "DDOS-HOIC"),
        ],
        "benign_cap": 300,
    },
]

# ─── Step 1: tshark filter → mini-PCAP ────────────────────────────────────────
def create_filtered_pcap(src_pcap: str, dst_pcap: str, attacker_ips: List[str],
                         time_start: float, time_end: float) -> bool:
    if Path(dst_pcap).exists() and Path(dst_pcap).stat().st_size > 1000:
        print(f"    [cache] {Path(dst_pcap).name} already exists")
        return True
    ip_filter   = " or ".join(f"ip.addr == {ip}" for ip in attacker_ips)
    time_filter = f"frame.time_epoch >= {time_start - 60} and frame.time_epoch <= {time_end + 60}"
    full_filter = f"({ip_filter}) and ({time_filter})"
    print(f"    tshark: {Path(src_pcap).name} → {Path(dst_pcap).name}")
    cmd = ["tshark", "-r", src_pcap, "-Y", full_filter, "-w", dst_pcap]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0:
        print(f"    [ERROR] tshark: {r.stderr.decode()[:200]}")
        return False
    size_mb = Path(dst_pcap).stat().st_size / (1024 * 1024)
    print(f"    [✓] {size_mb:.1f} MB filtered")
    return True

# ─── Step 2a: tshark offline HTTP events ─────────────────────────────────────
_SEP = "\x01"

def load_tshark_http_events(pcap_file: str) -> Dict[Tuple[str, int], List[dict]]:
    """
    Run tshark -r to extract all HTTP request events from a PCAP file.
    Returns dict keyed by (src_ip, sport) — same format as TsharkL7Reader.drain_events().
    """
    print(f"    tshark L7: reading HTTP events from {Path(pcap_file).name} ...")
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "http.request.method",
        "-e", "http.request.uri",
        "-e", "http.user_agent",
        "-e", "http.file_data",
        "-E", f"separator={_SEP}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    events: Dict[Tuple[str, int], List[dict]] = {}
    n_parsed = 0
    for line in result.stdout.splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split(_SEP)
        if len(parts) < 6:
            continue
        try:
            ts_str, src_ip, sport_str, dst_ip, dport_str, method = parts[:6]
            uri        = parts[6] if len(parts) > 6 else ""
            user_agent = parts[7] if len(parts) > 7 else ""
            file_data  = parts[8] if len(parts) > 8 else ""
            if not src_ip or not method:
                continue
            sport = int(sport_str) if sport_str else 0
            dport = int(dport_str) if dport_str else 80
            ts    = float(ts_str)  if ts_str    else 0.0
            composite = uri
            if user_agent:
                composite += " " + user_agent
            if file_data:
                composite += " " + file_data
            event = {
                "timestamp":       ts,
                "src_ip":          src_ip,
                "sport":           sport,
                "dst_ip":          dst_ip,
                "dport":           dport,
                "http_method":     method,
                "http_uri":        uri,
                "http_user_agent": user_agent,
                "payload":         composite.encode("utf-8", errors="ignore"),
            }
            events.setdefault((src_ip, sport), []).append(event)
            n_parsed += 1
        except Exception:
            continue
    print(f"    [✓] tshark L7: {n_parsed} HTTP events, {len(events)} unique (src_ip, sport) keys")
    return events


def _filter_events_for_window(all_events: dict, win_start: float,
                               win_end: float) -> dict:
    """Return subset of tshark events whose timestamp overlaps [win_start-0.5, win_end+0.5]."""
    result = {}
    lo, hi = win_start - 0.5, win_end + 0.5
    for key, evts in all_events.items():
        win_evts = [e for e in evts if lo <= e["timestamp"] <= hi]
        if win_evts:
            result[key] = win_evts
    return result


# ─── Step 2b: PCAP → 20D NIDS JSONL (with L7 enrichment) ────────────────────
def extract_nids_features(pcap_file: str, output_jsonl: str,
                          window_size: float = 1.0) -> int:
    """
    Process PCAP → NIDS JSONL with full 20D features.
    F1-F11: Scapy network stats.
    F6-F20: tshark offline HTTP events → enrich_flows_with_tshark.
    """
    if Path(output_jsonl).exists():
        rows = sum(1 for _ in open(output_jsonl))
        print(f"    [cache] {Path(output_jsonl).name}: {rows} rows")
        return rows

    from scapy.all import PcapReader
    from config.data_params import normalize_feature_vector
    from core.flow_manager import FlowManager
    from core.packet_parser import PacketLayerExtractor
    from core.tshark_l7 import enrich_flows_with_tshark
    from feature.calculator import FlowFeatureCalculator

    # Pre-load ALL tshark HTTP events from PCAP
    all_http_events = load_tshark_http_events(pcap_file)

    parser   = PacketLayerExtractor(use_packet_time=True)
    calc     = FlowFeatureCalculator()
    f_labels = FlowFeatureCalculator.get_feature_labels()

    total_pkts = rows = enriched_total = 0
    win_start = win_end = None
    fm: Optional[FlowManager] = None

    def _export(out_fd):
        nonlocal rows, enriched_total
        if fm is None:
            return
        all_flows = fm.get_all_flows()
        if not all_flows:
            return

        # Enrich flows with tshark L7 data for this window
        window_http = _filter_events_for_window(all_http_events, win_start, win_end)
        if window_http:
            enriched_total += enrich_flows_with_tshark(all_flows, window_http)

        # Group by src_ip, compute features
        flows_by_src: Dict[str, list] = defaultdict(list)
        for fl in all_flows:
            flows_by_src[fl.src_ip].append(fl)

        for src_ip, flows_list in flows_by_src.items():
            for fl in flows_list:
                fl.analysis_window_size = window_size
            features = calc.calculate_all(flows_list)
            if features is None:
                continue
            row = {"src_ip": src_ip, "timestamp": win_start}
            for i, label in enumerate(f_labels):
                row[label] = round(float(features[i]), 6)
            out_fd.write(json.dumps(row) + "\n")
            rows += 1

    with open(output_jsonl, "w") as out_fd:
        print(f"    reading packets: {Path(pcap_file).name}")
        try:
            with PcapReader(pcap_file) as reader:
                for pkt in reader:
                    info = parser.extract(pkt, total_pkts)
                    if info is None or not info.has_ip or not info.has_tcp:
                        continue
                    pkt_time = info.timestamp
                    if win_start is None:
                        win_start = pkt_time
                        win_end   = win_start + window_size
                        fm = FlowManager(window_size=window_size)
                    while pkt_time >= win_end:
                        _export(out_fd)
                        fm.slide_window_packets(win_end)
                        win_start = win_end
                        win_end   = win_start + window_size
                    fm.process_packet(info)
                    total_pkts += 1
                    if total_pkts % 5000 == 0:
                        print(f"\r    pkts={total_pkts} rows={rows}...", end="", flush=True)
            _export(out_fd)
        except Exception as e:
            print(f"\n    [ERROR] {e}")
            import traceback; traceback.print_exc()
            return rows

    print(f"\n    [✓] {total_pkts} pkts → {rows} rows | L7 enriched: {enriched_total} pkts")
    return rows


# ─── Step 3: Label rows ────────────────────────────────────────────────────────
def label_rows(jsonl_file: str, attacker_ips: List[str],
               attack_windows: list, benign_cap: int) -> List[dict]:
    labeled: List[dict] = []
    benign_count = 0
    with open(jsonl_file) as f:
        for line in f:
            row = json.loads(line.strip())
            ts     = float(row["timestamp"])
            src_ip = row["src_ip"]
            gt_label = gt_action = None

            if src_ip in attacker_ips:
                for idx, (t_start, t_end, label, action, name) in enumerate(attack_windows):
                    if t_start <= ts <= t_end:
                        gt_label  = label
                        gt_action = action
                        row["attack_name"] = name
                        row["window_id"]   = idx
                        row["window_t0"]   = t_start
                        break
                if gt_label is None:
                    continue   # attacker outside window → ambiguous, skip
            else:
                in_any_window = any(t_s <= ts <= t_e for (t_s, t_e, *_) in attack_windows)
                if in_any_window:
                    continue   # victim reply traffic during attack → skip
                if benign_count >= benign_cap:
                    continue
                gt_label  = "benign"
                gt_action = "Allow"
                benign_count += 1

            row["gt_label"]  = gt_label
            row["gt_action"] = gt_action
            labeled.append(row)
    return labeled


# ─── Step 4: Verify features before running model ────────────────────────────
def verify_features(labeled: List[dict], day: str) -> bool:
    """
    Sanity-check 20D features of labeled rows.
    Fails if F6-F20 are all zero for attack traffic (L7 enrichment missing).
    """
    print(f"\n  [VERIFY] Feature sanity check — {day}")
    by_label: Dict[str, List[dict]] = defaultdict(list)
    for r in labeled:
        by_label[r["gt_label"]].append(r)

    ok = True
    f_keys = {
        "F1 - PacketRate": "F1",
        "F6 - URLConcentration": "F6",
        "F7 - HttpIatUniformity": "F7",
        "F12 - SqlSpecialChar": "F12",
        "F13 - CrsSqliScore": "F13",
        "F18 - CrsXssScore": "F18",
    }

    for label, rows in sorted(by_label.items()):
        sample = rows[:50]
        means = {}
        for k, short in f_keys.items():
            vals = [r.get(k, 0.0) for r in sample]
            means[short] = sum(vals) / len(vals) if vals else 0.0
        line = "  ".join(f"{s}={v:.3f}" for s, v in means.items())
        print(f"    {label:15s} (n={len(rows):4d}): {line}")

        # Warn if L7 features are 0 for attack traffic
        if label == "brute_force" and means["F6"] < 0.01 and means["F7"] < 0.01:
            print(f"    [WARN] brute_force: F6/F7 both ~0 — L7 enrichment may have failed")
            ok = False
        if label in ("sqli_xss", "sqli"):
            if means["F12"] < 0.001 and means["F13"] < 0.001:
                print(f"    [WARN] {label}: F12/F13 all ~0 — SQLi payload features missing")
                ok = False
        if label in ("sqli_xss", "xss"):
            if means["F18"] < 0.001:
                print(f"    [WARN] {label}: F18 ~0 — XSS payload features missing")
                ok = False
        if label == "benign" and means["F1"] < 0.01:
            print(f"    [WARN] benign: F1 very low — check timing/traffic")

    return ok


# ─── Step 5: Run model ────────────────────────────────────────────────────────
class OfflineEffectCollector:
    """Benchmark-only fallback for 34D models when no nginx access log exists.

    Public CIC PCAPs do not include the router/nginx side-channel used by the
    closed-loop 34D model. To keep offline benchmarking closer to the training
    contract, we carry forward a simulated effect vector per IP using the same
    `simulate_effect()` helper as the environment.
    """

    def __init__(self, simulate_effect_fn, seed: int = 42):
        self._simulate_effect = simulate_effect_fn
        self._rng = np.random.default_rng(seed)
        self._prev_effect_by_ip: Dict[str, List[float]] = {}

    def ingest(self) -> int:
        return 0

    def get_effect(self, src_ip: str, window_ts: float,
                   sensor_20d: Optional[List[float]] = None) -> List[float]:
        return list(self._prev_effect_by_ip.get(src_ip, [0.0, 0.0, 0.0, 0.0]))

    def remember(self, src_ip: str, action: int, sensor_20d: List[float]) -> None:
        if sensor_20d is None or len(sensor_20d) < 20:
            self._prev_effect_by_ip[src_ip] = [0.0, 0.0, 0.0, 0.0]
            return
        self._prev_effect_by_ip[src_ip] = list(
            self._simulate_effect(int(action), list(sensor_20d), self._rng)
        )

    def reset_ip(self, src_ip: str) -> None:
        self._prev_effect_by_ip.pop(src_ip, None)

    def clear(self) -> None:
        self._prev_effect_by_ip.clear()

    def prune(self, max_age: float = 60.0) -> None:
        return


def run_model_on_labeled(labeled: List[dict], model_path: str,
                          demo_safe: bool = False,
                          eval_mode: str = 'stateful') -> Tuple[List[dict], dict]:
    """
    eval_mode:
      'stateful'     — production simulation: state accumulates across all rows.
                       Redirect escalates to Block after REDIRECT_TTL_SECONDS.
      'stateless'    — per-window AI agent accuracy: fresh state before every predict().
                       Measures classification accuracy of PPO + policy guard combined.
      'window-reset' — system response timeline: state reset at start of each attack
                       window. Shows Redirect→Block escalation from t=0 per attacker.
      'raw-ppo'      — Layer 1: pure PPO model output only.
                       No policy override (Block→Redirect for SQLi/XSS), no tracker.
                       Use to measure raw model capability vs AI agent capability.

    Returns (results, audit) where audit = {raw_ppo_diff_count, safety_net_override_count, total_rows}.
    """
    os.chdir(str(AIRL_DIR))
    import infer as infer_mod
    from infer import (
        IDSDefenseAgent, BLOCK_IDLE_TTL, parse_nids_row, ACTION_MAP,
        InferenceTemporalState, PersistenceTemporalState,
    )
    from env_ids import simulate_effect

    # Benchmarks run offline; suppress iptables dry-run spam while preserving agent logic.
    original_run_router = infer_mod._run_router
    infer_mod._run_router = lambda cmd, enforce=True: True if not enforce else original_run_router(cmd, enforce)

    try:
        agent = IDSDefenseAgent(model_path=model_path, enforce=False, demo_safe=demo_safe)
        raw_model = agent.model   # direct PPO model access for raw prediction + override audit

        # Detect model obs dimension and build the correct "fresh IP" observation shape.
        _obs_dim = int(np.prod(raw_model.observation_space.shape))
        _default_state_cls = PersistenceTemporalState if _obs_dim == 34 else InferenceTemporalState
        _default_tstate = _default_state_cls()
        _default_temporal_obs = np.array(_default_tstate.to_obs(), dtype=np.float32)
        _effect_pad = np.zeros(4, dtype=np.float32) if _obs_dim == 34 else np.zeros(0, dtype=np.float32)

        offline_effect = None
        if _obs_dim == 34:
            offline_effect = OfflineEffectCollector(simulate_effect_fn=simulate_effect, seed=42)
            agent.effect_collector = offline_effect

        labeled_sorted = sorted(labeled, key=lambda r: float(r["timestamp"]))

        results  = []
        prev_ts: float = 0.0
        seen_windows: set = set()   # for window-reset mode
        raw_ppo_diff_count       = 0   # rows where raw PPO (default temporal) ≠ info['rl_action']
        safety_net_override_count = 0  # rows where safety_net/tracker changed action: info['rl_action'] → final

        for i, row in enumerate(labeled_sorted):
            try:
                ts     = float(row["timestamp"])
                src_ip = row.get("src_ip", "unknown")

                # ── Layer 1: Raw PPO — no override, no tracker, no state ──────────
                if eval_mode == 'raw-ppo':
                    obs20, raw = parse_nids_row(row)
                    obs30 = np.concatenate([obs20, _default_temporal_obs, _effect_pad])
                    raw_int, _ = raw_model.predict(obs30, deterministic=True)
                    raw_action = int(raw_int)
                    row["pred_action"]      = raw_action
                    row["pred_action_name"] = ACTION_MAP[raw_action]
                    row["raw_ppo_action"]   = ACTION_MAP[raw_action]
                    results.append(row)
                    if (i + 1) % 200 == 0:
                        print(f"\r  evaluated {i+1}/{len(labeled_sorted)}...", end="", flush=True)
                    continue

                # ── State management (stateless / window-reset / stateful) ────────
                if eval_mode == 'stateless':
                    if hasattr(agent, 'temporal_states'):
                        agent.temporal_states.pop(src_ip, None)
                    if hasattr(agent, 'guard_tracker'):
                        agent.guard_tracker._state.pop(src_ip, None)
                    if hasattr(agent, 'tracker'):
                        agent.tracker._state.pop(src_ip, None)
                    if offline_effect is not None:
                        offline_effect.reset_ip(src_ip)

                elif eval_mode == 'window-reset':
                    wid = row.get("window_id")
                    if wid is not None:
                        key = (src_ip, wid)
                        if key not in seen_windows:
                            seen_windows.add(key)
                            if hasattr(agent, 'temporal_states'):
                                agent.temporal_states.pop(src_ip, None)
                            if hasattr(agent, 'guard_tracker'):
                                agent.guard_tracker._state.pop(src_ip, None)
                            if hasattr(agent, 'tracker'):
                                agent.tracker._state.pop(src_ip, None)
                            if offline_effect is not None:
                                offline_effect.reset_ip(src_ip)

                else:  # stateful (default)
                    if prev_ts > 0 and (ts - prev_ts) >= BLOCK_IDLE_TTL:
                        tracker = getattr(agent, 'guard_tracker', None) or getattr(agent, 'tracker', None)
                        if tracker is not None:
                            tracker.expire_stale(ts, enforce=False)
                        if offline_effect is not None:
                            offline_effect.clear()

                prev_ts = ts

                # ── Override audit: get raw PPO action before any rule-based logic ─
                # Use 30D/34D obs with default temporal (fresh IP: last_action=Allow, no damage)
                obs20, raw = parse_nids_row(row)
                obs30 = np.concatenate([obs20, _default_temporal_obs, _effect_pad])
                raw_int, _ = raw_model.predict(obs30, deterministic=True)
                raw_ppo_name = ACTION_MAP[int(raw_int)]

                # ── Full AI agent prediction (policy override + tracker) ───────────
                pred_action, action_name, info = agent.predict(row)
                agent_action_name = ACTION_MAP[info['rl_action']]  # after override, before tracker

                # Track raw PPO vs post-guard divergence (temporal context effects / browse guard)
                if raw_ppo_name != agent_action_name:
                    raw_ppo_diff_count += 1
                # Track safety_net + tracker changes: info['rl_action'] → final action
                if agent_action_name != action_name:
                    safety_net_override_count += 1

                if offline_effect is not None:
                    offline_effect.remember(src_ip, pred_action, raw)

                row["pred_action"]        = pred_action
                row["pred_action_name"]   = action_name
                row["raw_ppo_action"]     = raw_ppo_name       # pure PPO output
                row["agent_action"]       = agent_action_name  # after override, before tracker
                results.append(row)
            except Exception as e:
                print(f"  [WARN] row {i}: {e}")
            if (i + 1) % 200 == 0:
                print(f"\r  evaluated {i+1}/{len(labeled_sorted)}...", end="", flush=True)

        audit = {
            "raw_ppo_diff_count":        raw_ppo_diff_count,
            "safety_net_override_count": safety_net_override_count,
            "total_rows":                len(results),
        }
        print(f"\r  [✓] evaluated {len(results)} rows")
        if eval_mode != 'raw-ppo':
            print(f"  Override audit: raw_ppo_diff={raw_ppo_diff_count} "
                  f"| safety_net_overrides={safety_net_override_count}")
        return results, audit
    finally:
        infer_mod._run_router = original_run_router


# ─── Step 6: Metrics + Report ─────────────────────────────────────────────────
LABEL_EXPECTED = {
    "benign":      "Allow",
    "brute_force": "Redirect",
    "sqli_xss":    "Redirect",   # legacy — kept for old caches
    "sqli":        "Redirect",
    "xss":         "Redirect",
    "syn_flood":   "Block",
    "scan":        "Block",
}


TIMELINE_BUCKETS = [
    (0,   15,  "0-15s   (initial)"),
    (15,  60,  "15-60s  (escalate)"),
    (60,  300, "60-300s (sustained)"),
    (300, None,"300s+   (long-run)"),
]


def compute_metrics(results: List[dict]) -> dict:
    per_label: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    per_label_raw: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    confusion:  Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    confusion_raw: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # Timeline: {label: {bucket_label: {pred_action: count}}}
    timeline: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    correct = total = correct_raw = 0
    has_raw_ppo = any("raw_ppo_action" in r and "agent_action" not in r
                      # raw-ppo mode: raw_ppo_action == pred_action_name
                      # stateless mode: raw_ppo_action is separate from pred_action_name
                      for r in results[:5])
    # Detect if rows have separate raw_ppo_action vs pred_action_name
    has_raw_audit = any("raw_ppo_action" in r for r in results[:5])

    for row in results:
        gt     = row["gt_action"]
        pred   = row["pred_action_name"]
        label  = row["gt_label"]
        per_label[label]["total"]         += 1
        per_label[label][f"pred_{pred}"]  += 1
        confusion[gt][pred]               += 1
        if pred == gt:
            per_label[label]["correct"] += 1
            correct += 1
        if label != "benign" and pred != "Allow":
            per_label[label]["mitigated"] += 1
        total += 1

        # Raw PPO tracking (for stateless/window-reset modes that include override audit)
        if has_raw_audit and "raw_ppo_action" in row:
            raw = row["raw_ppo_action"]
            per_label_raw[label]["total"]         += 1
            per_label_raw[label][f"pred_{raw}"]   += 1
            confusion_raw[gt][raw]                += 1
            if raw == gt:
                per_label_raw[label]["correct"] += 1
                correct_raw += 1
            if label != "benign" and raw != "Allow":
                per_label_raw[label]["mitigated"] += 1

        # Timeline bucketing (only for attack rows with window timing info)
        if label != "benign" and "window_t0" in row:
            rel_t = float(row["timestamp"]) - float(row["window_t0"])
            for (lo, hi, bname) in TIMELINE_BUCKETS:
                if rel_t >= lo and (hi is None or rel_t < hi):
                    timeline[label][bname][pred] += 1
                    break

    per_class = {}
    for label, counts in per_label.items():
        n = counts["total"]
        c = counts.get("correct", 0)
        exp = LABEL_EXPECTED.get(label, "?")
        tp  = counts.get(f"pred_{exp}", 0)
        mit = counts.get("mitigated", 0)
        entry = {
            "total":           n,
            "correct":         c,
            "accuracy":        round(c / n, 4) if n > 0 else 0.0,
            "recall":          round(tp / n, 4) if n > 0 else 0.0,
            "mitigate_rate":   round(mit / n, 4) if n > 0 and label != "benign" else None,
            "expected_action": exp,
            "pred_dist":       {k.replace("pred_", ""): v
                                 for k, v in counts.items() if k.startswith("pred_")},
            "timeline":        {b: dict(d) for b, d in timeline.get(label, {}).items()},
        }
        # Embed raw PPO sub-metrics if available
        if label in per_label_raw:
            rcounts = per_label_raw[label]
            rn = rcounts["total"]
            rc = rcounts.get("correct", 0)
            rtp = rcounts.get(f"pred_{exp}", 0)
            rmit = rcounts.get("mitigated", 0)
            entry["raw_ppo"] = {
                "accuracy":      round(rc / rn, 4) if rn > 0 else 0.0,
                "recall":        round(rtp / rn, 4) if rn > 0 else 0.0,
                "mitigate_rate": round(rmit / rn, 4) if rn > 0 and label != "benign" else None,
                "pred_dist":     {k.replace("pred_", ""): v
                                   for k, v in rcounts.items() if k.startswith("pred_")},
            }
        per_class[label] = entry

    metrics = {
        "overall_accuracy": round(correct / total, 4) if total else 0.0,
        "total_rows":       total,
        "correct_rows":     correct,
        "per_class":        per_class,
        "confusion_matrix": {gt: dict(p) for gt, p in confusion.items()},
    }
    if has_raw_audit and correct_raw > 0:
        metrics["raw_ppo_overall_accuracy"] = round(correct_raw / total, 4)
        metrics["confusion_matrix_raw_ppo"] = {gt: dict(p) for gt, p in confusion_raw.items()}
    return metrics


def print_report(metrics: dict, day: str = "", eval_mode: str = "stateful",
                 audit: Optional[dict] = None):
    mode_desc = {
        "stateful":     "stateful (production simulation)",
        "stateless":    "stateless — per-window AI agent capability (Layer 2)",
        "window-reset": "window-reset — system response timeline (Layer 3)",
        "raw-ppo":      "raw-ppo — pure PPO model output, no override/tracker (Layer 1)",
    }.get(eval_mode, eval_mode)
    print(f"\n{'='*70}")
    print(f"  BENCHMARK RESULTS — {day}")
    print(f"  Eval mode : {mode_desc}")
    print(f"{'='*70}")
    print(f"  Overall accuracy : {metrics['overall_accuracy']*100:.1f}%"
          f"  ({metrics['correct_rows']}/{metrics['total_rows']} rows)")
    if "raw_ppo_overall_accuracy" in metrics:
        print(f"  Raw PPO accuracy : {metrics['raw_ppo_overall_accuracy']*100:.1f}%  (Layer 1 baseline)")

    # Per-class table
    has_raw = any("raw_ppo" in m for m in metrics["per_class"].values())
    print(f"\n  Per-class (AI Agent / Raw PPO):" if has_raw else f"\n  Per-class:")
    hdr = f"  {'Label':15s} {'Expected':10s} {'N':5s} {'Acc%':6s} {'Recall%':8s} {'Mitigate%':10s}  Pred distribution"
    if has_raw:
        hdr += "  |  Raw-PPO Acc%  Recall%"
    print(hdr)
    print(f"  {'-'*95}")
    has_timeline = False
    for label, m in sorted(metrics["per_class"].items()):
        dist = ", ".join(f"{a}:{n}" for a, n in sorted(m["pred_dist"].items()))
        mit = m.get("mitigate_rate")
        mit_str = f"{mit*100:7.1f}%" if mit is not None else f"{'N/A':>7s}"
        line = (f"  {label:15s} {m['expected_action']:10s} {m['total']:5d} "
                f"{m['accuracy']*100:5.1f}%  {m['recall']*100:6.1f}%  {mit_str}   {dist}")
        if has_raw and "raw_ppo" in m:
            rp = m["raw_ppo"]
            rmit = rp.get("mitigate_rate")
            rmit_str = f"{rmit*100:.1f}%" if rmit is not None else "N/A"
            line += f"  |  {rp['accuracy']*100:5.1f}%  {rp['recall']*100:5.1f}%  {rmit_str}"
        print(line)
        if m.get("timeline"):
            has_timeline = True

    # Timeline section (only if window_t0 was available — window-reset or stateful mode)
    if has_timeline:
        print(f"\n  Response timeline (action distribution by time since attack start):")
        for label, m in sorted(metrics["per_class"].items()):
            tl = m.get("timeline", {})
            if not tl:
                continue
            print(f"    {label}:")
            for bname, dist in sorted(tl.items()):
                total_b = sum(dist.values())
                dist_str = "  ".join(f"{a}:{n}" for a, n in sorted(dist.items(), key=lambda x: -x[1]))
                print(f"      {bname}  (n={total_b:4d}): {dist_str}")

    # Audit summary
    if audit and eval_mode not in ('raw-ppo',):
        n = audit.get('total_rows', 1) or 1
        raw_diff   = audit.get('raw_ppo_diff_count', 0)
        safety_ovr = audit.get('safety_net_override_count', 0)
        print(f"\n  Override audit:")
        print(f"    raw_ppo vs info['rl_action'] diff : {raw_diff:4d}  "
              f"({raw_diff/n*100:.1f}%)  ← temporal context or browse_guard changes")
        print(f"    safety_net + tracker overrides   : {safety_ovr:4d}  "
              f"({safety_ovr/n*100:.1f}%)  ← info['rl_action']→final (e.g. Allow→Redirect, Redirect→Block)")

    print(f"\n  Confusion matrix  (GT \\ Pred):")
    acts = ["Allow", "RateLimit", "Redirect", "Block"]
    print("  {:12s}".format("") + "".join(f"{a:10s}" for a in acts))
    for gt in acts:
        row = f"  {gt:12s}"
        for pred in acts:
            row += f"{metrics['confusion_matrix'].get(gt, {}).get(pred, 0):10d}"
        print(row)


# ─── Step 7: Verify-only mode ─────────────────────────────────────────────────
def verify_cached_jsonl(day_cfg: dict, safe_day: str):
    """Quick check: print feature stats for cached JSONL."""
    jsonl = CACHE_DIR / f"{safe_day}_nids.jsonl"
    if not jsonl.exists():
        print(f"  [SKIP] cache not found: {jsonl}")
        return
    rows = []
    with open(jsonl) as f:
        for line in f:
            rows.append(json.loads(line))
    print(f"\n  {day_cfg['day']}: {len(rows)} total NIDS rows in cache")

    # Show attack window coverage
    for (ts, te, label, action, name) in day_cfg["windows"]:
        attackers = set(day_cfg["attackers"])
        window_rows = [r for r in rows
                       if r["src_ip"] in attackers and ts <= r["timestamp"] <= te]
        ts_str = datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M")
        te_str = datetime.datetime.utcfromtimestamp(te).strftime("%H:%M")
        if window_rows:
            f6  = sum(r.get("F6 - URLConcentration", 0) for r in window_rows) / len(window_rows)
            f13 = sum(r.get("F13 - CrsSqliScore", 0)    for r in window_rows) / len(window_rows)
            f18 = sum(r.get("F18 - CrsXssScore", 0)     for r in window_rows) / len(window_rows)
            f1  = sum(r.get("F1 - PacketRate", 0)        for r in window_rows) / len(window_rows)
            print(f"    [{name}] {ts_str}-{te_str} UTC: {len(window_rows)} rows | "
                  f"F1={f1:.1f} F6={f6:.3f} F13={f13:.3f} F18={f18:.3f}")
        else:
            print(f"    [{name}] {ts_str}-{te_str} UTC: 0 rows  ← MISSING (timezone/IP issue?)")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="CIC-IDS2018 PCAP benchmark for the current RL defense model.\n"
                    "3-layer evaluation: raw-ppo (L1) | stateless (L2) | window-reset (L3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--model", default="runs/run_34d_v13/best_model")
    ap.add_argument("--skip-extract", action="store_true")
    ap.add_argument("--verify-only", action="store_true",
                    help="Only verify cached JSONL, no model run")
    ap.add_argument("--demo-safe", action="store_true")
    ap.add_argument("--eval-mode", default="stateless",
                    choices=["stateful", "stateless", "window-reset", "raw-ppo", "all"],
                    help="raw-ppo: pure PPO (L1) | stateless: AI agent per-window (L2) | "
                         "window-reset: system timeline (L3) | stateful: production sim | "
                         "all: run L1+L2+L3 in sequence")
    ap.add_argument("--output", default=None,
                    help="Output JSON filename. Default: benchmark_results_{eval_mode}.json")
    ap.add_argument("--day", default=None,
                    help="Run only one day (substring match, e.g. 'Thursday')")
    ap.add_argument("--benign-cap", type=int, default=None,
                    help="Override per-day benign_cap (default: use per-day config, usually 500)")
    args = ap.parse_args()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    model_path = str(AIRL_DIR / args.model)

    # ── Verify-only mode ──────────────────────────────────────────────────────
    if args.verify_only:
        print("\n=== VERIFY MODE: checking cached JSONL feature coverage ===")
        for day_cfg in ATTACK_DAYS:
            safe_day = day_cfg["day"].replace("-", "_").replace(" ", "_")
            verify_cached_jsonl(day_cfg, safe_day)
        return

    # Determine which eval modes to run
    if args.eval_mode == "all":
        eval_modes = ["raw-ppo", "stateless", "window-reset"]
    else:
        eval_modes = [args.eval_mode]

    combined_results: Dict[str, dict] = {}  # day → {mode → metrics}

    for day_cfg in ATTACK_DAYS:
        day       = day_cfg["day"]
        if args.day and args.day.lower() not in day.lower():
            continue

        pcap      = day_cfg["pcap"]
        large     = day_cfg["pcap_large"]
        attackers = day_cfg["attackers"]
        windows   = day_cfg["windows"]
        benign_cap = args.benign_cap if args.benign_cap is not None else day_cfg.get("benign_cap", 300)
        safe_day  = day.replace("-", "_").replace(" ", "_")

        print(f"\n{'─'*70}")
        print(f"  Processing: {day}  (benign_cap={benign_cap})")
        print(f"{'─'*70}")

        jsonl_path = CACHE_DIR / f"{safe_day}_nids.jsonl"

        if not args.skip_extract:
            # Step 1: filter large PCAPs
            if large:
                t_min = min(w[0] for w in windows) - 300
                t_max = max(w[1] for w in windows) + 300
                filtered = str(CACHE_DIR / f"{safe_day}_filtered.pcap")
                if not create_filtered_pcap(pcap, filtered, attackers, t_min, t_max):
                    print(f"  [SKIP] tshark filter failed for {day}")
                    continue
                if "pcap_extra" in day_cfg:
                    filtered2 = str(CACHE_DIR / f"{safe_day}_filtered_p2.pcap")
                    create_filtered_pcap(day_cfg["pcap_extra"], filtered2,
                                         attackers, t_min, t_max)
                    merged = str(CACHE_DIR / f"{safe_day}_merged.pcap")
                    if not Path(merged).exists():
                        print(f"    mergecap: merging parts ...")
                        subprocess.run(["mergecap", "-w", merged, filtered, filtered2],
                                       capture_output=True)
                    pcap_to_use = merged
                else:
                    pcap_to_use = filtered
            else:
                pcap_to_use = pcap

            # Step 2: extract 20D features (with L7)
            extract_nids_features(pcap_to_use, str(jsonl_path))

        if not jsonl_path.exists():
            print(f"  [SKIP] {jsonl_path} not found — run without --skip-extract first")
            continue

        # Step 3: label (shared across all eval modes for this day)
        labeled = label_rows(str(jsonl_path), attackers, windows, benign_cap)
        dist    = defaultdict(int)
        for r in labeled:
            dist[r["gt_label"]] += 1
        print(f"  Labeled: {len(labeled)} rows | {dict(dist)}")

        if not labeled:
            print(f"  [WARN] 0 labeled rows — check timezone or PCAP coverage")
            continue

        # Step 4: verify features (once per day)
        feat_ok = verify_features(labeled, day)
        if not feat_ok:
            print(f"  [WARN] Feature verification warnings above — results may be unreliable")

        day_combined: Dict[str, dict] = {}

        for eval_mode in eval_modes:
            # Deep-copy labeled rows so each mode gets clean rows without prev mode's fields
            import copy
            labeled_copy = copy.deepcopy(labeled)

            print(f"\n  ── Eval mode: {eval_mode} ──")
            results, audit = run_model_on_labeled(labeled_copy, model_path, args.demo_safe,
                                                  eval_mode=eval_mode)
            metrics = compute_metrics(results)
            print_report(metrics, day, eval_mode=eval_mode, audit=audit)
            day_combined[eval_mode] = {**metrics, "_audit": audit}

        combined_results[day] = day_combined

    # ── Summary across all modes (only when --eval-mode all) ──────────────────
    if args.eval_mode == "all" and combined_results:
        print(f"\n{'='*70}")
        print("  3-LAYER SUMMARY")
        print(f"{'='*70}")
        for day, modes in combined_results.items():
            print(f"\n  {day}:")
            print(f"  {'Layer':20s} {'Benign Acc%':12s} {'BruteForce':12s} {'XSS':10s} {'SQLi':10s} {'Mitigate%':12s}")
            print(f"  {'-'*75}")
            for mode_lbl, mode_key in [("L1 Raw PPO", "raw-ppo"),
                                        ("L2 AI Agent", "stateless"),
                                        ("L3 Window-Reset", "window-reset")]:
                if mode_key not in modes:
                    continue
                m = modes[mode_key]
                pc = m.get("per_class", {})
                def _acc(lbl):
                    return f"{pc[lbl]['accuracy']*100:.1f}%" if lbl in pc else "N/A"
                def _mit(lbl):
                    v = pc.get(lbl, {}).get("mitigate_rate")
                    return f"{v*100:.1f}%" if v is not None else "N/A"
                ben_acc  = _acc("benign")
                bf_acc   = _acc("brute_force")
                xss_acc  = _acc("xss")
                sqli_acc = _acc("sqli")
                # mitigate_rate: average across attack classes
                mits = [pc[lbl].get("mitigate_rate") for lbl in ("brute_force","xss","sqli")
                        if lbl in pc and pc[lbl].get("mitigate_rate") is not None]
                avg_mit = f"{sum(mits)/len(mits)*100:.1f}%" if mits else "N/A"
                print(f"  {mode_lbl:20s} {ben_acc:12s} {bf_acc:12s} {xss_acc:10s} {sqli_acc:10s} {avg_mit:12s}")

    # ── Save results ──────────────────────────────────────────────────────────
    if args.eval_mode == "all":
        out_name = args.output or "benchmark_results_all_modes.json"
    else:
        out_name = args.output or f"benchmark_results_{args.eval_mode.replace('-','_')}.json"
    out_path = CACHE_DIR / out_name
    with open(out_path, "w") as f:
        json.dump(combined_results, f, indent=2)
    print(f"\n  [✓] Results saved: {out_path}")


if __name__ == "__main__":
    main()
