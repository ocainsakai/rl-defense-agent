"""
pcap_benchmark_ids2017.py — PCAP-based benchmark for CIC-IDS2017 dataset.

Pipeline (giống IDS2018):
  1. Filter large PCAPs by attacker IP + time windows (tshark) → mini-PCAPs
  2. Extract 34D NIDS features via System's FlowFeatureCalculator
  3. Label mỗi 1s window theo timestamp + src_ip
  4. Run IDSDefenseAgent chronologically
  5. Report: accuracy, confusion matrix, per-class metrics (3-layer)

Network topology (từ https://www.unb.ca/cic/datasets/ids-2017.html):
  Attacker:  205.174.165.73  (Kali Linux 2)
  Victims:   192.168.10.x    (Windows/Ubuntu/Mac)
  Router/FW: 205.174.165.68

Timezone: Halifax, Nova Scotia, July 2017 → ADT = UTC-3.
Tất cả giờ tấn công trong metadata là ADT, được convert sang UTC epoch.

Attacks phù hợp scope (5-class model):
  Tuesday   : FTP-Patator, SSH-Patator                → brute_force → Redirect
  Wednesday : DoS Slowloris/Slowhttptest/Hulk/GoldenEye → syn_flood  → Block
  Thursday  : Web Brute Force, XSS, SQL Injection      → brute_force / xss / sqli → Redirect
  Friday    : PortScan, DDoS LOIT                       → scan / syn_flood → Block

Attacks NGOÀI scope (bỏ qua):
  Wednesday : Heartbleed (không map được hành động rõ ràng)
  Thursday  : Infiltration
  Friday    : Botnet ARES

Usage:
  cd /home/vytny/Documents/IAP491/rl-defense-agent-full-project-2
  python3 datasets/CIC-IDS2017/pcap_benchmark_ids2017.py --verify-only
  python3 datasets/CIC-IDS2017/pcap_benchmark_ids2017.py --eval-mode all
  python3 datasets/CIC-IDS2017/pcap_benchmark_ids2017.py --skip-extract --eval-mode stateless
  python3 datasets/CIC-IDS2017/pcap_benchmark_ids2017.py --day Thursday --eval-mode all
"""

from __future__ import annotations

import argparse
import calendar
import copy
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
REPO_ROOT  = Path(__file__).resolve().parents[3]
SYSTEM_DIR = REPO_ROOT / "System"
AIRL_DIR   = REPO_ROOT / "AI RL"
CACHE_DIR  = Path(__file__).parent / "pcap_cache"

for p in (str(SYSTEM_DIR), str(AIRL_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# ─── Path PCAP ───────────────────────────────────────────────────────────────
# Pre-sliced per-attack files (local disk, avoid hgfs freeze):
#   ~/Downloads/pcap_slices_2017/Thursday_All.pcap         (BruteForce+XSS+SQLi+Benign merged)
#   ~/Downloads/pcap_slices_2017/Friday_PortScan_merged.pcap (PortScan+Benign merged)
#   ~/Downloads/pcap_slices_2017/Friday_DDoS_SYN.pcap      (DDoS SYN only)
SLICES = "/home/vytny/Downloads/pcap_slices_2017"

# ─── Timezone helper ──────────────────────────────────────────────────────────
TIMEZONE_OFFSET = 3  # ADT = UTC-3 (Halifax, mùa hè July 2017)

def _adt(date_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' ADT (UTC-3) string to Unix epoch."""
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return float(calendar.timegm(dt.timetuple())) + TIMEZONE_OFFSET * 3600

# ─── Network topology ─────────────────────────────────────────────────────────
# Toàn bộ attack traffic đều qua NAT firewall:
#   Kali 205.174.165.73  → FW 205.174.165.80 → 172.16.0.1 → 192.168.10.50
#   DDoS 205.174.165.69-71 → FW 205.174.165.80 → 172.16.0.1
# Nên IP attacker visible trong PCAP là 172.16.0.1 (internal FW interface).
ATTACKER_IP  = "172.16.0.1"
VICTIM_IP    = "192.168.10.50"   # Ubuntu16 web server (NAT'd from 205.174.165.68)
INTERNAL_IPS = {
    "192.168.10.3",  "192.168.10.5",  "192.168.10.6",  "192.168.10.7",
    "192.168.10.8",  "192.168.10.9",  "192.168.10.10", "192.168.10.11",
    "192.168.10.12", "192.168.10.14", "192.168.10.15", "192.168.10.16",
    "192.168.10.17", "192.168.10.19", "192.168.10.20", "192.168.10.21",
    "192.168.10.25", "192.168.10.50", "205.174.165.68",
}

# ─── Attack metadata (times in ADT = UTC-3, Halifax) ─────────────────────────
# Tuesday  bị loại: FTP/SSH Patator không có HTTP → F6-F18 = 0.
# Wednesday bị loại: Slowloris/Hulk là HTTP app-layer flood (tầng 7),
#   không phải TCP SYN flood — ngoài scope bài toán.
ATTACK_DAYS = [
    {
        "day":        "Thursday-06-07-2017",
        "pcap":       f"{SLICES}/Thursday_All.pcap",
        "pcap_large": True,
        "attackers":  [ATTACKER_IP],
        "windows": [
            (_adt("2017-07-06 09:20:00"), _adt("2017-07-06 10:00:00"),
             "brute_force", "Redirect", "Web-BruteForce"),
            (_adt("2017-07-06 10:15:00"), _adt("2017-07-06 10:35:00"),
             "xss",         "Redirect", "Web-XSS"),
            (_adt("2017-07-06 10:40:00"), _adt("2017-07-06 10:42:00"),
             "sqli",        "Redirect", "Web-SQLi"),
        ],
        # benign window: 10:50-11:15 ADT (after all attacks, before afternoon infiltration)
        "benign_window": (_adt("2017-07-06 10:50:00"), _adt("2017-07-06 11:15:00")),
        "benign_cap": 500,
    },
    {
        # Friday PortScan: FW-On (13:55-14:35) + FW-Off (14:51-15:29)
        "day":        "Friday-07-07-2017-PortScan",
        "pcap":       f"{SLICES}/Friday_PortScan_merged.pcap",
        "pcap_large": True,
        "attackers":  [ATTACKER_IP],
        "windows": [
            (_adt("2017-07-07 13:55:00"), _adt("2017-07-07 14:35:00"),
             "scan_fw_on", "Block", "PortScan-FW-On"),
            (_adt("2017-07-07 14:51:00"), _adt("2017-07-07 15:29:00"),
             "scan_fw_off", "Block", "PortScan-FW-Off"),
        ],
        # benign window: 09:00-09:15 ADT (before Botnet starts at 10:02)
        "benign_window": (_adt("2017-07-07 09:00:00"), _adt("2017-07-07 09:15:00")),
        "benign_cap": 500,
    },
    {
        # Friday DDoS LOIT: attackers 205.174.165.69-71 → NAT → 172.16.0.1.
        # proto_filter: chỉ lấy TCP SYN (L3/L4), bỏ HTTP flood (L7).
        "day":        "Friday-07-07-2017-DDoS",
        "pcap":       f"{SLICES}/Friday_DDoS_SYN.pcap",
        "pcap_large": True,
        "attackers":  [ATTACKER_IP],
        "proto_filter": "tcp.flags.syn == 1 and tcp.flags.ack == 0",
        "windows": [
            (_adt("2017-07-07 15:56:00"), _adt("2017-07-07 16:16:00"),
             "syn_flood", "Block", "DDoS-LOIT-SYN"),
        ],
        "benign_cap": 0,
    },
]

# ─── Step 1: tshark filter → mini-PCAP ────────────────────────────────────────
def create_filtered_pcap(src_pcap: str, dst_pcap: str, attacker_ips: List[str],
                         time_start: float, time_end: float,
                         proto_filter: Optional[str] = None,
                         benign_window: Optional[Tuple[float, float]] = None) -> bool:
    dst = Path(dst_pcap)
    if dst.exists() and dst.stat().st_size > 1000:
        print(f"    [cache] {dst.name} already exists")
        return True
    ip_filter   = " or ".join(f"ip.addr == {ip}" for ip in attacker_ips)
    time_filter = f"frame.time_epoch >= {time_start - 60} and frame.time_epoch <= {time_end + 60}"
    attack_clause = f"({ip_filter}) and ({time_filter})"
    if proto_filter:
        attack_clause += f" and ({proto_filter})"
    if benign_window:
        b_start, b_end = benign_window
        benign_clause = f"(frame.time_epoch >= {b_start} and frame.time_epoch <= {b_end})"
        full_filter = f"({attack_clause}) or ({benign_clause})"
    else:
        full_filter = attack_clause
    print(f"    tshark: {Path(src_pcap).name} → {dst.name}")
    # -F pcap: force classic pcap output (src may be pcapng — IDS2017 files are pcapng)
    # stdin=DEVNULL: prevent tshark waiting on stdin in non-interactive mode
    cmd = ["tshark", "-r", src_pcap, "-F", "pcap", "-Y", full_filter, "-w", dst_pcap]
    r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL)
    stderr_txt = r.stderr.decode(errors="replace").strip()
    # tshark sometimes exits non-zero for non-fatal warnings (e.g. pcapng interface blocks).
    # Check output file size instead of relying solely on returncode.
    if not dst.exists() or dst.stat().st_size < 24:   # <24 = no PCAP header written
        err = stderr_txt or r.stdout.decode(errors="replace").strip() or f"exit {r.returncode}"
        print(f"    [ERROR] tshark exit={r.returncode}: {err[:300] or '(no output)'}")
        return False
    if r.returncode != 0 and stderr_txt:
        print(f"    [WARN] tshark exit={r.returncode}: {stderr_txt[:200]}")
    size_mb = dst.stat().st_size / (1024 * 1024)
    print(f"    [✓] {size_mb:.1f} MB filtered")
    return True

# ─── Step 2a: tshark offline HTTP events ─────────────────────────────────────
_SEP = "\x01"

def load_tshark_http_events(pcap_file: str) -> Dict[Tuple[str, int], List[dict]]:
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
    result = {}
    lo, hi = win_start - 0.5, win_end + 0.5
    for key, evts in all_events.items():
        win_evts = [e for e in evts if lo <= e["timestamp"] <= hi]
        if win_evts:
            result[key] = win_evts
    return result


# ─── Step 2b: PCAP → NIDS JSONL (with L7 enrichment) ────────────────────────
def extract_nids_features(pcap_file: str, output_jsonl: str,
                          window_size: float = 1.0) -> int:
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

        window_http = _filter_events_for_window(all_http_events, win_start, win_end)
        if window_http:
            enriched_total += enrich_flows_with_tshark(all_flows, window_http)

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


# ─── Step 4: Verify features ─────────────────────────────────────────────────
def verify_features(labeled: List[dict], day: str) -> bool:
    print(f"\n  [VERIFY] Feature sanity check — {day}")
    by_label: Dict[str, List[dict]] = defaultdict(list)
    for r in labeled:
        by_label[r["gt_label"]].append(r)

    ok = True
    f_keys = {
        "F1 - PacketRate":       "F1",
        "F6 - URLConcentration": "F6",
        "F7 - HttpIatUniformity":"F7",
        "F12 - SqlSpecialChar":  "F12",
        "F13 - CrsSqliScore":    "F13",
        "F18 - CrsXssScore":     "F18",
    }

    for label, rows in sorted(by_label.items()):
        sample = rows[:50]
        means = {}
        for k, short in f_keys.items():
            vals = [r.get(k, 0.0) for r in sample]
            means[short] = sum(vals) / len(vals) if vals else 0.0
        line = "  ".join(f"{s}={v:.3f}" for s, v in means.items())
        print(f"    {label:15s} (n={len(rows):4d}): {line}")

        if label == "brute_force" and means["F6"] < 0.01 and means["F7"] < 0.01:
            print(f"    [WARN] brute_force: F6/F7 ~0 — L7 enrichment may have failed")
            ok = False
        if label == "sqli" and means["F12"] < 0.001 and means["F13"] < 0.001:
            print(f"    [WARN] sqli: F12/F13 ~0 — SQLi payload features missing")
            ok = False
        if label == "xss" and means["F18"] < 0.001:
            print(f"    [WARN] xss: F18 ~0 — XSS payload features missing")
            ok = False
        if label == "benign" and means["F1"] < 0.01:
            print(f"    [WARN] benign: F1 very low — check timing/traffic")

    return ok


# ─── Step 5: Run model ────────────────────────────────────────────────────────
class OfflineEffectCollector:
    """Fallback cho 34D model khi không có nginx log (offline benchmark)."""

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
      'stateful'     — production simulation
      'stateless'    — per-window AI agent accuracy (Layer 2)
      'window-reset' — system response timeline (Layer 3)
      'raw-ppo'      — pure PPO output only (Layer 1)
    """
    os.chdir(str(AIRL_DIR))
    import infer as infer_mod
    from infer import (
        IDSDefenseAgent, BLOCK_IDLE_TTL, parse_nids_row, ACTION_MAP,
        InferenceTemporalState, PersistenceTemporalState,
    )
    from env_ids import simulate_effect

    original_run_router = infer_mod._run_router
    infer_mod._run_router = lambda cmd, enforce=True: True if not enforce else original_run_router(cmd, enforce)

    try:
        agent = IDSDefenseAgent(model_path=model_path, enforce=False, demo_safe=demo_safe)
        raw_model = agent.model

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
        seen_windows: set = set()
        raw_ppo_diff_count        = 0
        safety_net_override_count = 0

        for i, row in enumerate(labeled_sorted):
            try:
                ts     = float(row["timestamp"])
                src_ip = row.get("src_ip", "unknown")

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

                else:  # stateful
                    if prev_ts > 0 and (ts - prev_ts) >= BLOCK_IDLE_TTL:
                        tracker = getattr(agent, 'guard_tracker', None) or getattr(agent, 'tracker', None)
                        if tracker is not None:
                            tracker.expire_stale(ts, enforce=False)
                        if offline_effect is not None:
                            offline_effect.clear()

                prev_ts = ts

                obs20, raw = parse_nids_row(row)
                obs30 = np.concatenate([obs20, _default_temporal_obs, _effect_pad])
                raw_int, _ = raw_model.predict(obs30, deterministic=True)
                raw_ppo_name = ACTION_MAP[int(raw_int)]

                pred_action, action_name, info = agent.predict(row)
                agent_action_name = ACTION_MAP[info['rl_action']]

                if raw_ppo_name != agent_action_name:
                    raw_ppo_diff_count += 1
                if agent_action_name != action_name:
                    safety_net_override_count += 1

                if offline_effect is not None:
                    offline_effect.remember(src_ip, pred_action, raw)

                row["pred_action"]        = pred_action
                row["pred_action_name"]   = action_name
                row["raw_ppo_action"]     = raw_ppo_name
                row["agent_action"]       = agent_action_name
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
    "xss":         "Redirect",
    "sqli":        "Redirect",
    "syn_flood":   "Block",
    "scan":        "Block",
    "scan_fw_on":  "Block",
    "scan_fw_off": "Block",
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
    timeline: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    correct = total = correct_raw = 0
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

    if audit and eval_mode not in ('raw-ppo',):
        n = audit.get('total_rows', 1) or 1
        raw_diff   = audit.get('raw_ppo_diff_count', 0)
        safety_ovr = audit.get('safety_net_override_count', 0)
        print(f"\n  Override audit:")
        print(f"    raw_ppo vs info['rl_action'] diff : {raw_diff:4d}  "
              f"({raw_diff/n*100:.1f}%)  ← temporal context or browse_guard changes")
        print(f"    safety_net + tracker overrides   : {safety_ovr:4d}  "
              f"({safety_ovr/n*100:.1f}%)  ← info['rl_action']→final")

    print(f"\n  Confusion matrix  (GT \\ Pred):")
    acts = ["Allow", "RateLimit", "Redirect", "Block"]
    print("  {:12s}".format("") + "".join(f"{a:10s}" for a in acts))
    for gt in acts:
        row = f"  {gt:12s}"
        for pred in acts:
            row += f"{metrics['confusion_matrix'].get(gt, {}).get(pred, 0):10d}"
        print(row)


# ─── Verify-only mode ─────────────────────────────────────────────────────────
def verify_cached_jsonl(day_cfg: dict, safe_day: str):
    jsonl = CACHE_DIR / f"{safe_day}_nids.jsonl"
    if not jsonl.exists():
        print(f"  [SKIP] cache not found: {jsonl}")
        return
    rows = []
    with open(jsonl) as f:
        for line in f:
            rows.append(json.loads(line))
    print(f"\n  {day_cfg['day']}: {len(rows)} total NIDS rows in cache")

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
        description="CIC-IDS2017 PCAP benchmark for the current RL defense model.\n"
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
                    help="Output JSON filename")
    ap.add_argument("--day", default=None,
                    help="Run only one day (substring match, e.g. 'Thursday')")
    ap.add_argument("--benign-cap", type=int, default=None,
                    help="Override per-day benign_cap")
    args = ap.parse_args()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    model_path = str(AIRL_DIR / args.model)

    if args.verify_only:
        print("\n=== VERIFY MODE: checking cached JSONL feature coverage ===")
        for day_cfg in ATTACK_DAYS:
            safe_day = day_cfg["day"].replace("-", "_").replace(" ", "_")
            verify_cached_jsonl(day_cfg, safe_day)
        return

    if args.eval_mode == "all":
        eval_modes = ["raw-ppo", "stateless", "window-reset"]
    else:
        eval_modes = [args.eval_mode]

    combined_results: Dict[str, dict] = {}

    # Pre-pass: large PCAPs used by multiple day configs are read only once.
    # A shared mini-PCAP (merged time range, no proto_filter) is created first,
    # then each day re-filters from that small file — avoiding multiple GB-scale reads.
    shared_filtered: Dict[str, str] = {}  # src_pcap → shared mini-pcap path
    if not args.skip_extract:
        pcap_usage: Dict[str, List[dict]] = defaultdict(list)
        for dc in ATTACK_DAYS:
            if not dc.get("pcap_large") or not dc.get("attackers"):
                continue
            if args.day and args.day.lower() not in dc["day"].lower():
                continue
            pcap_usage[dc["pcap"]].append(dc)

        for src_pcap, days_using in pcap_usage.items():
            if len(days_using) <= 1:
                continue
            all_windows   = [w for dc in days_using for w in dc["windows"]]
            t_min         = min(w[0] for w in all_windows) - 300
            t_max         = max(w[1] for w in all_windows) + 300
            all_attackers = list({ip for dc in days_using for ip in dc["attackers"]})
            safe_name     = Path(src_pcap).stem.replace(" ", "_").replace("-", "_")
            shared_dst    = str(CACHE_DIR / f"shared_{safe_name}_filtered.pcap")
            print(f"\n  [shared filter] {Path(src_pcap).name} → {Path(shared_dst).name}")
            print(f"    merging {len(days_using)} day-configs, "
                  f"window {datetime.datetime.utcfromtimestamp(t_min).strftime('%H:%M')}"
                  f"–{datetime.datetime.utcfromtimestamp(t_max).strftime('%H:%M')} UTC")
            if create_filtered_pcap(src_pcap, shared_dst, all_attackers, t_min, t_max):
                shared_filtered[src_pcap] = shared_dst

    for day_cfg in ATTACK_DAYS:
        day = day_cfg["day"]
        if args.day and args.day.lower() not in day.lower():
            continue

        pcap      = day_cfg["pcap"]
        large     = day_cfg["pcap_large"]
        attackers = day_cfg["attackers"]
        windows   = day_cfg["windows"]
        benign_cap = args.benign_cap if args.benign_cap is not None else day_cfg.get("benign_cap", 500)
        safe_day  = day.replace("-", "_").replace(" ", "_")

        print(f"\n{'─'*70}")
        print(f"  Processing: {day}  (benign_cap={benign_cap})")
        print(f"{'─'*70}")

        jsonl_path = CACHE_DIR / f"{safe_day}_nids.jsonl"

        proto_filter = day_cfg.get("proto_filter", None)

        if not args.skip_extract:
            if large:
                t_min = min(w[0] for w in windows) - 300
                t_max = max(w[1] for w in windows) + 300
                filtered = str(CACHE_DIR / f"{safe_day}_filtered.pcap")
                # If a shared mini-PCAP exists for this source, filter from it
                # (already a small file) instead of re-reading the original large PCAP.
                filter_src = shared_filtered.get(pcap, pcap)
                benign_window = day_cfg.get("benign_window", None)
                if not create_filtered_pcap(filter_src, filtered, attackers, t_min, t_max,
                                            proto_filter=proto_filter,
                                            benign_window=benign_window):
                    print(f"  [SKIP] tshark filter failed for {day}")
                    continue
                pcap_to_use = filtered
            else:
                pcap_to_use = pcap

            extract_nids_features(pcap_to_use, str(jsonl_path))

        if not jsonl_path.exists():
            print(f"  [SKIP] {jsonl_path} not found — run without --skip-extract first")
            continue

        labeled = label_rows(str(jsonl_path), attackers, windows, benign_cap)
        dist    = defaultdict(int)
        for r in labeled:
            dist[r["gt_label"]] += 1
        print(f"  Labeled: {len(labeled)} rows | {dict(dist)}")

        if not labeled:
            print(f"  [WARN] 0 labeled rows — check timezone or PCAP coverage")
            continue

        feat_ok = verify_features(labeled, day)
        if not feat_ok:
            print(f"  [WARN] Feature verification warnings — results may be unreliable")

        day_combined: Dict[str, dict] = {}

        for eval_mode in eval_modes:
            labeled_copy = copy.deepcopy(labeled)
            print(f"\n  ── Eval mode: {eval_mode} ──")
            results, audit = run_model_on_labeled(labeled_copy, model_path, args.demo_safe,
                                                  eval_mode=eval_mode)
            metrics = compute_metrics(results)
            print_report(metrics, day, eval_mode=eval_mode, audit=audit)
            day_combined[eval_mode] = {**metrics, "_audit": audit}

        combined_results[day] = day_combined

    # ── Summary (--eval-mode all) ─────────────────────────────────────────────
    if args.eval_mode == "all" and combined_results:
        print(f"\n{'='*70}")
        print("  3-LAYER SUMMARY  (CIC-IDS2017)")
        print(f"{'='*70}")
        for day, modes in combined_results.items():
            print(f"\n  {day}:")
            print(f"  {'Layer':20s} {'Benign Acc%':12s} {'BruteForce':12s} {'XSS':10s} "
                  f"{'SQLi':10s} {'SynFlood':10s} {'Scan':10s} {'Mitigate%':12s}")
            print(f"  {'-'*90}")
            for mode_lbl, mode_key in [("L1 Raw PPO",     "raw-ppo"),
                                        ("L2 AI Agent",    "stateless"),
                                        ("L3 Window-Reset","window-reset")]:
                if mode_key not in modes:
                    continue
                m = modes[mode_key]
                pc = m.get("per_class", {})
                def _acc(lbl):
                    return f"{pc[lbl]['accuracy']*100:.1f}%" if lbl in pc else "N/A"
                mits = [pc[lbl].get("mitigate_rate")
                        for lbl in ("brute_force","xss","sqli","syn_flood","scan","scan_fw_on","scan_fw_off")
                        if lbl in pc and pc[lbl].get("mitigate_rate") is not None]
                avg_mit = f"{sum(mits)/len(mits)*100:.1f}%" if mits else "N/A"
                scan_col = _acc('scan_fw_on') + '/' + _acc('scan_fw_off') if 'scan_fw_on' in pc else _acc('scan')
                print(f"  {mode_lbl:20s} {_acc('benign'):12s} {_acc('brute_force'):12s} "
                      f"{_acc('xss'):10s} {_acc('sqli'):10s} {_acc('syn_flood'):10s} "
                      f"{scan_col:20s} {avg_mit:12s}")

    if args.eval_mode == "all":
        out_name = args.output or "benchmark_results_all_modes.json"
    else:
        out_name = args.output or f"benchmark_results_{args.eval_mode.replace('-','_')}.json"
    out_path = CACHE_DIR / out_name
    # Merge với kết quả cũ để không ghi đè khi chạy từng ngày riêng
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text())
            existing.update(combined_results)
            combined_results = existing
        except Exception:
            pass
    with open(out_path, "w") as f:
        json.dump(combined_results, f, indent=2)
    print(f"\n  [✓] Results saved: {out_path}")


if __name__ == "__main__":
    main()
