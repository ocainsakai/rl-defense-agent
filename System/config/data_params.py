"""Shared data/windowing parameters.

This module exists to ensure Train and Inference use the exact same
windowing constants.

Per review (2026-01): WINDOW_SIZE_SECONDS must be fixed to 1.0s.
"""

from __future__ import annotations

import hashlib


# Sliding/window duration used across the system (seconds)
WINDOW_SIZE_SECONDS: float = 1.0


# Indirect label-leakage mitigation
# - If you export Src_IP for training datasets, anonymize it by default.
ANONYMIZE_SRC_IP_FOR_TRAINING: bool = True
SRC_IP_ANON_SALT: str = "IAP491"


def anonymize_src_ip(src_ip: str) -> str:
    """Return a stable, non-reversible identifier for a source IP."""
    if not src_ip:
        return ""
    digest = hashlib.sha256((SRC_IP_ANON_SALT + src_ip).encode("utf-8")).hexdigest()
    return digest[:12]


# =============================================================================
# RL OBSERVATION VECTOR — Canonical feature ordering (dim=20)
# =============================================================================
#
# Maps feature class codes → sequential observation index [0..19]
# Used by RL environment to build obs vector consistently.
#
# Rule:  FEATURE_ORDER[i] = feature code at observation index i
#        obs_vector[i]     = feature_values[FEATURE_ORDER[i]]
#
# Group layout:
#   [0 -10]  Network layer  (11 features) — detect DDoS, SYN flood, Port scan
#   [11-16]  SQLi layer     ( 6 features) — detect SQL Injection → redirect
#   [17-19]  XSS layer      ( 3 features) — detect XSS           → redirect
# =============================================================================

FEATURE_ORDER: list = [
    # ── Network (indices 0-10) ────────────────────────────────────────────────
    'F1',   #  0  PacketRate        — packets/sec,        DDoS / Flood
    'F2',   #  1  SynAckRatio       — SYN/ACK ratio,      SYN Flood
    'F3',   #  2  InterArrivalTime  — avg pkt gap,         Automated attack
    'F4',   #  3  RstRatio          — RST/total,           Port Scan
    'F5',   #  4  DistinctPorts     — unique dst ports,    Port Scan
    'F6',   #  5  URLConcentration  — max_url/total,       Brute Force / L7 DDoS
    'F7',   #  6  AuthFailureRate   — 401+403/total,       Brute Force login
    'F8',   #  7  ServerErrorRate   — 5xx/total,           Server crash / DoS
    'F9',   #  8  AvgPayloadSize    — avg bytes/pkt,       SYN flood (no payload)
    'F10',  #  9  FwdBwdRatio       — fwd/bwd pkts,        Traffic asymmetry
    'F11',  # 10  PacketsPerPort    — pkts/port,           Port Scan density

    # ── SQLi (indices 11-16) ─────────────────────────────────────────────────
    'F12',  # 11  SqlSpecialChar    — char ratio (', ;, --),   F1=0.919
    'F13',  # 12  CrsSquliScore     — CRS 942 score (0→N),     F1=0.722
    'F14',  # 13  SqlUnionSelect    — UNION SELECT,             FPR=0.0%
    'F15',  # 14  SqlComment        — --, #, /**/,              F1=0.662
    'F16',  # 15  SqlStackedQuery   — ; DROP/DELETE,            FPR=0.0%
    'F17',  # 16  SqlSelectCount    — SELECT count,             F1=0.766

    # ── XSS (indices 17-19) ──────────────────────────────────────────────────
    'F18',  # 17  CrsXssScore       — CRS 941 score (0→N),      F1=0.944
    'F19',  # 18  JsFunctionCall    — alert()/eval()/...,       F1=0.995
    'F20',  # 19  HtmlEventHandler  — onerror=/onload=/...,     F1=0.755
]

# Convenience: dimension of observation vector
OBS_DIM: int = len(FEATURE_ORDER)  # = 20

# Feature group slices (for reward shaping / action masking)
NETWORK_SLICE = slice(0, 11)   # indices 0-10
SQLI_SLICE    = slice(11, 17)  # indices 11-16
XSS_SLICE     = slice(17, 20)  # indices 17-19

# =============================================================================
# NORMALIZATION CLIP BOUNDS — upper bounds for unbounded features
# =============================================================================
# Features không có trong dict đã là [0,1] hoặc binary — dùng trực tiếp.
# Logic: normalized = min(raw_value, cap) / cap  → [0.0, 1.0]
FEATURE_CLIP_BOUNDS: dict = {
    'F1':  500.0,   # packets/sec   — DDoS traffic ~100-500 pkt/s
    'F2':  100.0,   # SYN/ACK ratio — SYN flood
    'F3':    5.0,   # seconds       — max inter-arrival time
    'F5':  500.0,   # distinct ports — port scan upper bound
    'F9':  1500.0,  # bytes         — MTU ceiling
    'F10': 100.0,   # fwd/bwd ratio — unidirectional flood
    'F11': 500.0,   # pkts/port     — concentrated flood
    'F13':  20.0,   # CRS SQLi rules — PL1 max ~19
    'F17':  10.0,   # SELECT count  — multiple SELECTs rare in legit traffic
    'F18':  32.0,   # CRS XSS rules — PL1 max ~31
}
