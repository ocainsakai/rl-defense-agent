"""
pcap_benchmark_ddos2019.py — PCAP-based benchmark for CIC-DDoS2019 dataset.

Pipeline (giống IDS2018 nhưng label theo victim IP thay vì attacker IP):
  1. Filter large PCAPs by victim IP + time windows (tshark) → mini-PCAPs
  2. Extract 20D NIDS features via System's FlowFeatureCalculator
  3. Label mỗi 1s window:
       - src_ip ∈ BENIGN_CLIENTS + ngoài attack window → benign (Allow)
       - src_ip KHÔNG ∈ nội bộ + trong attack window    → attack (Block)
  4. Run IDSDefenseAgent chronologically
  5. Report: accuracy, confusion matrix, per-class metrics

Network topology (từ https://www.unb.ca/cic/datasets/ddos-2019.html):
  Victim Day 1:  192.168.50.1  (Ubuntu 16.04 Web Server)
  Victim Day 2:  192.168.50.4  (Ubuntu 16.04 Web Server)
  Benign Day 1:  192.168.50.5, .6, .7, .8  (Windows PCs)
  Benign Day 2:  192.168.50.6, .7, .8, .9  (Windows PCs)
  Firewall:      205.174.165.81

Attacks phù hợp bài toán (trong scope 5 loại):
  syn_flood → Block   (Day 1: 11:28-17:35, Day 2: 13:29-13:34)
  port_scan → Block   (Day 2: thời gian xác nhận từ PCAP metadata)

Attacks NGOÀI scope (có trong dataset nhưng không dùng):
  PortMap, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, NTP, DNS, SNMP, SSDP, WebDDoS, TFTP

Usage:
  python3 datasets/CIC-DDoS2019/pcap_benchmark_ddos2019.py --verify-only
  python3 datasets/CIC-DDoS2019/pcap_benchmark_ddos2019.py --eval-mode all --day Day2
  python3 datasets/CIC-DDoS2019/pcap_benchmark_ddos2019.py --skip-extract --eval-mode all
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

# ─── TODO: Điền thông tin sau khi chạy capinfos ──────────────────────────────
# Chạy: capinfos <file.pcap> | grep "First packet"
# Ví dụ output: "First packet time: 2019-01-12 09:41:23.123456"
#
# Sau đó điền:
#   DAY1_DATE = "2019-01-12"   ← ngày Day 1 (Training)
#   DAY2_DATE = "2019-01-11"   ← ngày Day 2 (Testing)  (thay bằng ngày thực tế)
#   TIMEZONE_OFFSET = 5        ← EST = UTC-5 (mùa đông Canada)
#                                hoặc 4 nếu EDT = UTC-4 (mùa hè)
#
DAY1_DATE        = "2019-01-12"   # TODO: xác nhận từ capinfos
DAY2_DATE        = "2019-01-11"   # TODO: xác nhận từ capinfos
TIMEZONE_OFFSET  = 5              # EST = UTC-5

# ─── TODO: Điền path PCAP trên máy của bạn ───────────────────────────────────
# Ví dụ: "/home/vytny/Downloads/CIC-DDoS2019/Day1/SAT-01-12-2019_0"
#         "/home/vytny/Downloads/CIC-DDoS2019/Day2/SAT-01-11-2019_0"
#
PCAP_DAY1 = "/TODO/path/to/CIC-DDoS2019/Day1/pcap_file"
PCAP_DAY2 = "/TODO/path/to/CIC-DDoS2019/Day2/pcap_file"

# ─── Timezone helper ──────────────────────────────────────────────────────────
def _local(date_str: str) -> float:
    """Convert 'YYYY-MM-DD HH:MM:SS' local time → Unix epoch (dùng TIMEZONE_OFFSET)."""
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return float(calendar.timegm(dt.timetuple())) + TIMEZONE_OFFSET * 3600

# ─── Network topology ─────────────────────────────────────────────────────────
VICTIM_DAY1   = "192.168.50.1"
VICTIM_DAY2   = "192.168.50.4"

BENIGN_DAY1   = {"192.168.50.5", "192.168.50.6", "192.168.50.7", "192.168.50.8"}
BENIGN_DAY2   = {"192.168.50.6", "192.168.50.7", "192.168.50.8", "192.168.50.9"}

INTERNAL_IPS  = {
    VICTIM_DAY1, VICTIM_DAY2, "205.174.165.81",
    "192.168.50.5", "192.168.50.6", "192.168.50.7",
    "192.168.50.8", "192.168.50.9",
}

# ─── Attack metadata ──────────────────────────────────────────────────────────
ATTACK_DAYS = [
    {
        "day":        "Day1-Training",
        "pcap":       PCAP_DAY1,
        "pcap_large": True,
        "victim_ip":  VICTIM_DAY1,
        "benign_ips": BENIGN_DAY1,
        "windows": [
            (_local(f"{DAY1_DATE} 11:28:00"), _local(f"{DAY1_DATE} 17:35:00"),
             "syn_flood", "Block", "SYN-Flood"),
        ],
        "benign_cap": 500,
        "attack_cap": 500,
    },
    {
        "day":        "Day2-Testing",
        "pcap":       PCAP_DAY2,
        "pcap_large": True,
        "victim_ip":  VICTIM_DAY2,
        "benign_ips": BENIGN_DAY2,
        "windows": [
            (_local(f"{DAY2_DATE} 13:29:00"), _local(f"{DAY2_DATE} 13:34:00"),
             "syn_flood", "Block", "SYN-Flood"),
            # TODO: Thêm PortScan window sau khi xác nhận từ PCAP/metadata
            # (_local(f"{DAY2_DATE} HH:MM:00"), _local(f"{DAY2_DATE} HH:MM:00"),
            #  "port_scan", "Block", "PortScan"),
        ],
        "benign_cap": 500,
        "attack_cap": 500,
    },
]

# ─── Step 1: tshark filter → mini-PCAP ────────────────────────────────────────
def create_filtered_pcap(src_pcap: str, dst_pcap: str, victim_ip: str,
                         time_start: float, time_end: float) -> bool:
    """Filter PCAP by victim IP + time window (DDoS2019 dùng victim thay attacker)."""
    if Path(dst_pcap).exists() and Path(dst_pcap).stat().st_size > 1000:
        print(f"    [cache] {Path(dst_pcap).name} already exists")
        return True
    ip_filter   = f"ip.addr == {victim_ip}"
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


# ─── Step 2: tshark HTTP events (reused, L7 features sẽ gần 0 với DDoS) ───────
_SEP = "\x01"

def load_tshark_http_events(pcap_file: str) -> Dict[Tuple[str, int], List[dict]]:
    print(f"    tshark L7: reading HTTP events from {Path(pcap_file).name} ...")
    cmd = [
        "tshark", "-r", pcap_file,
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src",    "-e", "tcp.srcport",
        "-e", "ip.dst",           "-e", "tcp.dstport","-e", "http.request.method",
        "-e", "http.request.uri", "-e", "http.user_agent", "-e", "http.file_data",
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
                "timestamp": ts, "src_ip": src_ip, "sport": sport,
                "dst_ip": dst_ip, "dport": dport, "http_method": method,
                "http_uri": uri, "http_user_agent": user_agent,
                "payload": composite.encode("utf-8", errors="ignore"),
            }
            events.setdefault((src_ip, sport), []).append(event)
            n_parsed += 1
        except Exception:
            continue
    print(f"    [✓] tshark L7: {n_parsed} HTTP events, {len(events)} unique (src_ip, sport) keys")
    return events


def _filter_events_for_window(all_events: dict, win_start: float, win_end: float) -> dict:
    result = {}
    lo, hi = win_start - 0.5, win_end + 0.5
    for key, evts in all_events.items():
        win_evts = [e for e in evts if lo <= e["timestamp"] <= hi]
        if win_evts:
            result[key] = win_evts
    return result


# ─── Step 3: PCAP → 20D NIDS JSONL ────────────────────────────────────────────
def extract_nids_features(pcap_file: str, output_jsonl: str,
                          window_size: float = 1.0) -> int:
    if Path(output_jsonl).exists():
        rows = sum(1 for _ in open(output_jsonl))
        print(f"    [cache] {Path(output_jsonl).name}: {rows} rows")
        return rows

    from scapy.all import PcapReader
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
        if fm is None or win_start is None or win_end is None:
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


# ─── Step 4: Label rows (victim-based, khác IDS2018) ─────────────────────────
def label_rows(jsonl_file: str, victim_ip: str, benign_ips: set,
               attack_windows: list, benign_cap: int, attack_cap: int) -> List[dict]:
    """
    Label logic cho DDoS2019:
      - src_ip ∈ benign_ips + ngoài attack window → benign (Allow)
      - src_ip ∉ internal_ips + trong attack window → attack
      - Các trường hợp còn lại → bỏ qua (ambiguous)

    attack_cap: giới hạn số rows mỗi attack window (SYN Day 1 = 21,600 rows nếu không cap)
    """
    labeled: List[dict] = []
    benign_count = 0
    attack_count_per_window: Dict[int, int] = defaultdict(int)

    with open(jsonl_file) as f:
        for line in f:
            row = json.loads(line.strip())
            ts     = float(row["timestamp"])
            src_ip = row["src_ip"]

            # ── Kiểm tra có trong attack window không ────────────────────────
            in_window_idx = None
            for idx, (t_start, t_end, *_) in enumerate(attack_windows):
                if t_start <= ts <= t_end:
                    in_window_idx = idx
                    break

            # ── Attack: src_ip ngoài mạng nội bộ + trong attack window ───────
            if src_ip not in INTERNAL_IPS and in_window_idx is not None:
                if attack_count_per_window[in_window_idx] >= attack_cap:
                    continue
                _, _, label, action, name = attack_windows[in_window_idx]
                row["gt_label"]    = label
                row["gt_action"]   = action
                row["attack_name"] = name
                row["window_id"]   = in_window_idx
                row["window_t0"]   = attack_windows[in_window_idx][0]
                labeled.append(row)
                attack_count_per_window[in_window_idx] += 1

            # ── Benign: src_ip là PC nội bộ + ngoài attack window ────────────
            elif src_ip in benign_ips and in_window_idx is None:
                if benign_count >= benign_cap:
                    continue
                row["gt_label"]  = "benign"
                row["gt_action"] = "Allow"
                labeled.append(row)
                benign_count += 1

    return labeled


# ─── Step 5: Verify features ──────────────────────────────────────────────────
def verify_features(labeled: List[dict], day: str) -> bool:
    """
    Sanity check cho DDoS/PortScan:
    - syn_flood:  F1 (PacketRate) cao, F4 (RstRatio) có thể cao
    - port_scan:  F5 (DistinctPorts) cao
    - benign:     F1 thấp, F5 thấp
    """
    print(f"\n  [VERIFY] Feature sanity check — {day}")
    by_label: Dict[str, List[dict]] = defaultdict(list)
    for r in labeled:
        by_label[r["gt_label"]].append(r)

    ok = True
    f_keys = {
        "F1 - PacketRate":    "F1",
        "F4 - RstRatio":      "F4",
        "F5 - DistinctPorts": "F5",
        "F2 - SynAckRatio":   "F2",
    }

    for label, rows in sorted(by_label.items()):
        sample = rows[:50]
        means = {}
        for k, short in f_keys.items():
            vals = [r.get(k, 0.0) for r in sample]
            means[short] = sum(vals) / len(vals) if vals else 0.0
        line = "  ".join(f"{s}={v:.3f}" for s, v in means.items())
        print(f"    {label:15s} (n={len(rows):4d}): {line}")

        if label == "syn_flood" and means["F1"] < 1.0:
            print(f"    [WARN] syn_flood: F1 (PacketRate) rất thấp — kiểm tra time window hoặc victim IP")
            ok = False
        if label == "port_scan" and means["F5"] < 1.0:
            print(f"    [WARN] port_scan: F5 (DistinctPorts) rất thấp — PortScan phải có nhiều port")
            ok = False
        if label == "benign" and means["F1"] < 0.01:
            print(f"    [WARN] benign: F1 rất thấp — kiểm tra benign_ips hoặc timing")

    return ok


# ─── Step 6: Run model (reused hoàn toàn từ IDS2018) ─────────────────────────
class OfflineEffectCollector:
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
                         eval_mode: str = "stateless") -> Tuple[List[dict], dict]:
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
        agent     = IDSDefenseAgent(model_path=model_path, enforce=False, demo_safe=demo_safe)
        raw_model = agent.model

        _obs_dim          = int(np.prod(raw_model.observation_space.shape))
        _default_state_cls = PersistenceTemporalState if _obs_dim == 34 else InferenceTemporalState
        _default_tstate   = _default_state_cls()
        _default_temporal_obs = np.array(_default_tstate.to_obs(), dtype=np.float32)
        _effect_pad       = np.zeros(4, dtype=np.float32) if _obs_dim == 34 else np.zeros(0, dtype=np.float32)

        offline_effect = None
        if _obs_dim == 34:
            offline_effect = OfflineEffectCollector(simulate_effect_fn=simulate_effect, seed=42)
            agent.effect_collector = offline_effect

        labeled_sorted = sorted(labeled, key=lambda r: float(r["timestamp"]))
        results: List[dict] = []
        prev_ts: float = 0.0
        seen_windows: set = set()
        raw_ppo_diff_count = safety_net_override_count = 0

        for i, row in enumerate(labeled_sorted):
            try:
                ts     = float(row["timestamp"])
                src_ip = row.get("src_ip", "unknown")

                if eval_mode == "raw-ppo":
                    obs20, raw = parse_nids_row(row)
                    obs30 = np.concatenate([obs20, _default_temporal_obs, _effect_pad])
                    raw_int, _ = raw_model.predict(obs30, deterministic=True)
                    row["pred_action"]      = int(raw_int)
                    row["pred_action_name"] = ACTION_MAP[int(raw_int)]
                    row["raw_ppo_action"]   = ACTION_MAP[int(raw_int)]
                    results.append(row)
                    if (i + 1) % 200 == 0:
                        print(f"\r  evaluated {i+1}/{len(labeled_sorted)}...", end="", flush=True)
                    continue

                if eval_mode == "stateless":
                    for attr in ("temporal_states", "guard_tracker", "tracker"):
                        state = getattr(agent, attr, None)
                        if state is not None and hasattr(state, "_state"):
                            state._state.pop(src_ip, None)
                        elif isinstance(state, dict):
                            state.pop(src_ip, None)
                    if offline_effect is not None:
                        offline_effect.reset_ip(src_ip)

                elif eval_mode == "window-reset":
                    wid = row.get("window_id")
                    if wid is not None:
                        key = (src_ip, wid)
                        if key not in seen_windows:
                            seen_windows.add(key)
                            for attr in ("temporal_states", "guard_tracker", "tracker"):
                                state = getattr(agent, attr, None)
                                if state is not None and hasattr(state, "_state"):
                                    state._state.pop(src_ip, None)
                                elif isinstance(state, dict):
                                    state.pop(src_ip, None)
                            if offline_effect is not None:
                                offline_effect.reset_ip(src_ip)

                else:  # stateful
                    if prev_ts > 0 and (ts - prev_ts) >= BLOCK_IDLE_TTL:
                        tracker = getattr(agent, "guard_tracker", None) or getattr(agent, "tracker", None)
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
                agent_action_name = ACTION_MAP[info["rl_action"]]

                if raw_ppo_name != agent_action_name:
                    raw_ppo_diff_count += 1
                if agent_action_name != action_name:
                    safety_net_override_count += 1

                if offline_effect is not None:
                    offline_effect.remember(src_ip, pred_action, raw)

                row["pred_action"]      = pred_action
                row["pred_action_name"] = action_name
                row["raw_ppo_action"]   = raw_ppo_name
                row["agent_action"]     = agent_action_name
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
        if eval_mode != "raw-ppo":
            print(f"  Override audit: raw_ppo_diff={raw_ppo_diff_count} "
                  f"| safety_net_overrides={safety_net_override_count}")
        return results, audit
    finally:
        infer_mod._run_router = original_run_router


# ─── Step 7: Metrics + Report (reused từ IDS2018) ────────────────────────────
LABEL_EXPECTED = {
    "benign":    "Allow",
    "syn_flood": "Block",
    "port_scan": "Block",
}

TIMELINE_BUCKETS = [
    (0,   15,  "0-15s   (initial)"),
    (15,  60,  "15-60s  (escalate)"),
    (60,  300, "60-300s (sustained)"),
    (300, None,"300s+   (long-run)"),
]


def compute_metrics(results: List[dict]) -> dict:
    per_label: Dict[str, Dict[str, int]]     = defaultdict(lambda: defaultdict(int))
    per_label_raw: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    confusion: Dict[str, Dict[str, int]]     = defaultdict(lambda: defaultdict(int))
    confusion_raw: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    timeline: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    correct = total = correct_raw = 0
    has_raw_audit = any("raw_ppo_action" in r for r in results[:5])

    for row in results:
        gt    = row["gt_action"]
        pred  = row["pred_action_name"]
        label = row["gt_label"]
        per_label[label]["total"]        += 1
        per_label[label][f"pred_{pred}"] += 1
        confusion[gt][pred]              += 1
        if pred == gt:
            per_label[label]["correct"] += 1
            correct += 1
        if label != "benign" and pred != "Allow":
            per_label[label]["mitigated"] += 1
        total += 1

        if has_raw_audit and "raw_ppo_action" in row:
            raw = row["raw_ppo_action"]
            per_label_raw[label]["total"]        += 1
            per_label_raw[label][f"pred_{raw}"]  += 1
            confusion_raw[gt][raw]               += 1
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
        n   = counts["total"]
        c   = counts.get("correct", 0)
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
            rn  = rcounts["total"]
            rc  = rcounts.get("correct", 0)
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
        "stateless":    "stateless — per-window AI agent (Layer 2)",
        "window-reset": "window-reset — system response timeline (Layer 3)",
        "raw-ppo":      "raw-ppo — pure PPO, no override/tracker (Layer 1)",
    }.get(eval_mode, eval_mode)
    print(f"\n{'='*70}")
    print(f"  BENCHMARK RESULTS — {day}  [CIC-DDoS2019]")
    print(f"  Eval mode : {mode_desc}")
    print(f"{'='*70}")
    print(f"  Overall accuracy : {metrics['overall_accuracy']*100:.1f}%"
          f"  ({metrics['correct_rows']}/{metrics['total_rows']} rows)")
    if "raw_ppo_overall_accuracy" in metrics:
        print(f"  Raw PPO accuracy : {metrics['raw_ppo_overall_accuracy']*100:.1f}%")

    has_raw = any("raw_ppo" in m for m in metrics["per_class"].values())
    print(f"\n  Per-class:")
    hdr = f"  {'Label':15s} {'Expected':10s} {'N':5s} {'Acc%':6s} {'Recall%':8s} {'Mitigate%':10s}  Pred distribution"
    if has_raw:
        hdr += "  |  Raw-PPO Acc%  Recall%"
    print(hdr)
    print(f"  {'-'*95}")
    has_timeline = False
    for label, m in sorted(metrics["per_class"].items()):
        dist    = ", ".join(f"{a}:{n}" for a, n in sorted(m["pred_dist"].items()))
        mit     = m.get("mitigate_rate")
        mit_str = f"{mit*100:7.1f}%" if mit is not None else f"{'N/A':>7s}"
        line    = (f"  {label:15s} {m['expected_action']:10s} {m['total']:5d} "
                   f"{m['accuracy']*100:5.1f}%  {m['recall']*100:6.1f}%  {mit_str}   {dist}")
        if has_raw and "raw_ppo" in m:
            rp      = m["raw_ppo"]
            rmit    = rp.get("mitigate_rate")
            rmit_str = f"{rmit*100:.1f}%" if rmit is not None else "N/A"
            line   += f"  |  {rp['accuracy']*100:5.1f}%  {rp['recall']*100:5.1f}%  {rmit_str}"
        print(line)
        if m.get("timeline"):
            has_timeline = True

    if has_timeline:
        print(f"\n  Response timeline:")
        for label, m in sorted(metrics["per_class"].items()):
            tl = m.get("timeline", {})
            if not tl:
                continue
            print(f"    {label}:")
            for bname, dist in sorted(tl.items()):
                total_b  = sum(dist.values())
                dist_str = "  ".join(f"{a}:{n}" for a, n in sorted(dist.items(), key=lambda x: -x[1]))
                print(f"      {bname}  (n={total_b:4d}): {dist_str}")

    if audit and eval_mode not in ("raw-ppo",):
        n = audit.get("total_rows", 1) or 1
        print(f"\n  Override audit:")
        print(f"    raw_ppo_diff       : {audit['raw_ppo_diff_count']:4d}  ({audit['raw_ppo_diff_count']/n*100:.1f}%)")
        print(f"    safety_net_override: {audit['safety_net_override_count']:4d}  ({audit['safety_net_override_count']/n*100:.1f}%)")

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
        victim = day_cfg["victim_ip"]
        window_rows = [r for r in rows if r["src_ip"] != victim and ts <= r["timestamp"] <= te]
        ts_str = datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M")
        te_str = datetime.datetime.utcfromtimestamp(te).strftime("%H:%M")
        if window_rows:
            f1 = sum(r.get("F1 - PacketRate", 0) for r in window_rows) / len(window_rows)
            f5 = sum(r.get("F5 - DistinctPorts", 0) for r in window_rows) / len(window_rows)
            print(f"    [{name}] {ts_str}-{te_str} UTC: {len(window_rows)} rows | F1={f1:.1f} F5={f5:.3f}")
        else:
            print(f"    [{name}] {ts_str}-{te_str} UTC: 0 rows  ← MISSING (timezone/path issue?)")


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    # Kiểm tra TODO placeholders
    if "TODO" in PCAP_DAY1 or "TODO" in PCAP_DAY2:
        print("[WARN] PCAP paths chưa được cấu hình. Sửa PCAP_DAY1/PCAP_DAY2 ở đầu file.")
        print("       Chạy: capinfos <file.pcap> | grep 'First packet'  để lấy ngày + timezone")
        print()

    ap = argparse.ArgumentParser(
        description="CIC-DDoS2019 PCAP benchmark — SYN Flood + PortScan.\n"
                    "3-layer evaluation: raw-ppo (L1) | stateless (L2) | window-reset (L3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--model",       default="runs/run_34d_v13/best_model")
    ap.add_argument("--skip-extract",action="store_true")
    ap.add_argument("--verify-only", action="store_true")
    ap.add_argument("--demo-safe",   action="store_true")
    ap.add_argument("--eval-mode",   default="stateless",
                    choices=["stateful", "stateless", "window-reset", "raw-ppo", "all"])
    ap.add_argument("--output",      default=None)
    ap.add_argument("--day",         default=None, help="Substring match, e.g. 'Day2'")
    ap.add_argument("--benign-cap",  type=int, default=None)
    ap.add_argument("--attack-cap",  type=int, default=None)
    args = ap.parse_args()

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    model_path = str(AIRL_DIR / args.model)

    if args.verify_only:
        print("\n=== VERIFY MODE: checking cached JSONL feature coverage ===")
        for day_cfg in ATTACK_DAYS:
            safe_day = day_cfg["day"].replace("-", "_").replace(" ", "_")
            verify_cached_jsonl(day_cfg, safe_day)
        return

    eval_modes = ["raw-ppo", "stateless", "window-reset"] if args.eval_mode == "all" else [args.eval_mode]
    combined_results: Dict[str, dict] = {}

    for day_cfg in ATTACK_DAYS:
        day = day_cfg["day"]
        if args.day and args.day.lower() not in day.lower():
            continue

        pcap       = day_cfg["pcap"]
        large      = day_cfg["pcap_large"]
        victim_ip  = day_cfg["victim_ip"]
        benign_ips = day_cfg["benign_ips"]
        windows    = day_cfg["windows"]
        benign_cap = args.benign_cap if args.benign_cap is not None else day_cfg.get("benign_cap", 500)
        attack_cap = args.attack_cap if args.attack_cap is not None else day_cfg.get("attack_cap", 500)
        safe_day   = day.replace("-", "_").replace(" ", "_")

        print(f"\n{'─'*70}")
        print(f"  Processing: {day}  (benign_cap={benign_cap}, attack_cap={attack_cap})")
        print(f"{'─'*70}")

        jsonl_path = CACHE_DIR / f"{safe_day}_nids.jsonl"

        if not args.skip_extract:
            if large:
                t_min    = min(w[0] for w in windows) - 300
                t_max    = max(w[1] for w in windows) + 300
                filtered = str(CACHE_DIR / f"{safe_day}_filtered.pcap")
                if not create_filtered_pcap(pcap, filtered, victim_ip, t_min, t_max):
                    print(f"  [SKIP] tshark filter failed for {day}")
                    continue
                pcap_to_use = filtered
            else:
                pcap_to_use = pcap
            extract_nids_features(pcap_to_use, str(jsonl_path))

        if not jsonl_path.exists():
            print(f"  [SKIP] {jsonl_path} not found — run without --skip-extract first")
            continue

        labeled = label_rows(str(jsonl_path), victim_ip, benign_ips,
                             windows, benign_cap, attack_cap)
        dist = defaultdict(int)
        for r in labeled:
            dist[r["gt_label"]] += 1
        print(f"  Labeled: {len(labeled)} rows | {dict(dist)}")

        if not labeled:
            print(f"  [WARN] 0 labeled rows — kiểm tra DAY1_DATE/DAY2_DATE và TIMEZONE_OFFSET")
            continue

        feat_ok = verify_features(labeled, day)
        if not feat_ok:
            print(f"  [WARN] Feature verification warnings above — kết quả có thể không đáng tin")

        day_combined: Dict[str, dict] = {}
        for eval_mode in eval_modes:
            labeled_copy = copy.deepcopy(labeled)
            print(f"\n  ── Eval mode: {eval_mode} ──")
            results, audit = run_model_on_labeled(labeled_copy, model_path,
                                                  args.demo_safe, eval_mode=eval_mode)
            metrics = compute_metrics(results)
            print_report(metrics, day, eval_mode=eval_mode, audit=audit)
            day_combined[eval_mode] = {**metrics, "_audit": audit}

        combined_results[day] = day_combined

    if args.eval_mode == "all" and combined_results:
        print(f"\n{'='*70}")
        print("  3-LAYER SUMMARY  [CIC-DDoS2019]")
        print(f"{'='*70}")
        for day, modes in combined_results.items():
            print(f"\n  {day}:")
            print(f"  {'Layer':20s} {'Benign Acc%':12s} {'SYN Flood':12s} {'PortScan':12s}")
            print(f"  {'-'*58}")
            for mode_lbl, mode_key in [("L1 Raw PPO", "raw-ppo"),
                                        ("L2 AI Agent", "stateless"),
                                        ("L3 Window-Reset", "window-reset")]:
                if mode_key not in modes:
                    continue
                pc = modes[mode_key].get("per_class", {})
                def _acc(lbl):
                    return f"{pc[lbl]['accuracy']*100:.1f}%" if lbl in pc else "N/A"
                print(f"  {mode_lbl:20s} {_acc('benign'):12s} {_acc('syn_flood'):12s} {_acc('port_scan'):12s}")

    out_name = args.output or (
        "benchmark_results_all_modes.json" if args.eval_mode == "all"
        else f"benchmark_results_{args.eval_mode.replace('-','_')}.json"
    )
    out_path = CACHE_DIR / out_name
    with open(out_path, "w") as f:
        json.dump(combined_results, f, indent=2)
    print(f"\n  [✓] Results saved: {out_path}")


if __name__ == "__main__":
    main()
