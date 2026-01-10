"""Scenario-based feature validation (SAFE, offline).

This script does NOT send real network traffic.
It builds synthetic LayerInfo objects and feeds them through the same
FlowManager/FlowState + feature_flow pipeline used by main.py.

Use it to sanity-check that F1–F6 react as expected for common scenarios.

Run:
  python tools/scenario_validator.py
"""

from __future__ import annotations

import os
import sys
from typing import List, Tuple

# Allow running as: python tools/scenario_validator.py
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.layer_info import LayerInfo
from core.processor import FeatureVectorBuilder


def _tcp_packet(
    *,
    ts: float,
    n: int,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    flags: str = "S",
    payload: bytes | None = None,
    http_status: int | None = None,
) -> LayerInfo:
    info = LayerInfo(timestamp=ts, packet_number=n)
    info.has_ip = True
    info.ip_version = 4
    info.src_ip = src_ip
    info.dst_ip = dst_ip
    info.protocol = 6

    info.has_tcp = True
    info.tcp_sport = sport
    info.tcp_dport = dport
    info.tcp_flags = flags

    if payload is not None:
        info.has_payload = True
        info.payload_bytes = payload
        info.payload_length = len(payload)

    if http_status is not None:
        # Note: main.py currently disables HTTP parsing. We still support
        # injecting http_status for offline validation.
        info.http_status = http_status

    return info


def _udp_packet(
    *,
    ts: float,
    n: int,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload_len: int = 0,
) -> LayerInfo:
    info = LayerInfo(timestamp=ts, packet_number=n)
    info.has_ip = True
    info.ip_version = 4
    info.src_ip = src_ip
    info.dst_ip = dst_ip
    info.protocol = 17

    info.has_udp = True
    info.udp_sport = sport
    info.udp_dport = dport
    info.udp_len = payload_len

    if payload_len > 0:
        payload = b"A" * payload_len
        info.has_payload = True
        info.payload_bytes = payload
        info.payload_length = payload_len

    return info


def _run_scenario(name: str, builder: FeatureVectorBuilder, packets: List[LayerInfo]) -> Tuple[str, List[float]]:
    last_vec = None
    for p in packets:
        last_vec = builder.process_layer_info(p)
    if last_vec is None:
        last_vec = builder.process_layer_info(LayerInfo(timestamp=0.0, packet_number=0))
    return name, [float(x) for x in last_vec]


def scenario_syn_flood(attacker: str, victim: str, base_ts: float = 1_000.0) -> List[LayerInfo]:
    # Many SYNs to one port within 1s
    packets: List[LayerInfo] = []
    n = 1
    for i in range(400):
        ts = base_ts + (i / 400.0) * 0.9
        sport = 20000 + (i % 2000)
        packets.append(_tcp_packet(ts=ts, n=n, src_ip=attacker, dst_ip=victim, sport=sport, dport=80, flags="S"))
        n += 1
    return packets


def scenario_udp_flood(attacker: str, victim: str, base_ts: float = 2_000.0) -> List[LayerInfo]:
    packets: List[LayerInfo] = []
    n = 1
    for i in range(500):
        ts = base_ts + (i / 500.0) * 0.9
        sport = 30000 + (i % 2000)
        packets.append(_udp_packet(ts=ts, n=n, src_ip=attacker, dst_ip=victim, sport=sport, dport=53, payload_len=0))
        n += 1
    return packets


def scenario_port_scan_with_rst(attacker: str, victim: str, base_ts: float = 3_000.0) -> List[LayerInfo]:
    # SYN to many ports + victim replies with RST (backward)
    packets: List[LayerInfo] = []
    n = 1
    ports = list(range(20, 80))  # 60 distinct ports
    for i, dport in enumerate(ports):
        ts = base_ts + (i / len(ports)) * 0.9
        sport = 40000 + (i % 2000)
        # forward SYN
        packets.append(_tcp_packet(ts=ts, n=n, src_ip=attacker, dst_ip=victim, sport=sport, dport=dport, flags="S"))
        n += 1
        # backward RST: src=victim, dst=attacker, src_port=dport, dst_port=sport
        packets.append(_tcp_packet(ts=ts + 0.0005, n=n, src_ip=victim, dst_ip=attacker, sport=dport, dport=sport, flags="RA"))
        n += 1
    return packets


def scenario_payload_outlier(attacker: str, victim: str, base_ts: float = 4_000.0) -> List[LayerInfo]:
    packets: List[LayerInfo] = []
    n = 1
    # Many small payloads
    for i in range(40):
        ts = base_ts + (i / 40.0) * 0.5
        packets.append(
            _tcp_packet(
                ts=ts,
                n=n,
                src_ip=attacker,
                dst_ip=victim,
                sport=50000 + i,
                dport=80,
                flags="PA",
                payload=b"hello-world",  # small
            )
        )
        n += 1
    # One large outlier payload (>500 bytes)
    packets.append(
        _tcp_packet(
            ts=base_ts + 0.6,
            n=n,
            src_ip=attacker,
            dst_ip=victim,
            sport=50100,
            dport=80,
            flags="PA",
            payload=b"A" * 1200,
        )
    )
    return packets


def scenario_web_sqli(attacker: str, victim: str, base_ts: float = 5_000.0) -> List[LayerInfo]:
    payload = (
        b"GET /search?q=' OR '1'='1 HTTP/1.1\r\n"
        b"Host: test.local\r\n"
        b"User-Agent: validator\r\n\r\n"
    )
    return [
        _tcp_packet(
            ts=base_ts,
            n=1,
            src_ip=attacker,
            dst_ip=victim,
            sport=52000,
            dport=80,
            flags="PA",
            payload=payload,
        )
    ]


def scenario_web_xss(attacker: str, victim: str, base_ts: float = 6_000.0) -> List[LayerInfo]:
    payload = (
        b"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\n"
        b"Host: test.local\r\n\r\n"
    )
    return [
        _tcp_packet(
            ts=base_ts,
            n=1,
            src_ip=attacker,
            dst_ip=victim,
            sport=53000,
            dport=80,
            flags="PA",
            payload=payload,
        )
    ]


def scenario_safe_upload(attacker: str, victim: str, base_ts: float = 7_000.0) -> List[LayerInfo]:
    payload = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: test.local\r\n"
        b"Content-Type: image/png\r\n\r\n"
        b"...binary..."
    )
    return [
        _tcp_packet(
            ts=base_ts,
            n=1,
            src_ip=attacker,
            dst_ip=victim,
            sport=54000,
            dport=80,
            flags="PA",
            payload=payload,
        )
    ]


def main() -> None:
    attacker = "10.0.0.10"
    victim = "10.0.0.20"

    scenarios = [
        ("SYN flood", scenario_syn_flood(attacker, victim)),
        ("UDP flood", scenario_udp_flood(attacker, victim)),
        ("Port scan + RST", scenario_port_scan_with_rst(attacker, victim)),
        ("Payload outlier", scenario_payload_outlier(attacker, victim)),
        ("Web SQLi signature", scenario_web_sqli(attacker, victim)),
        ("Web XSS signature", scenario_web_xss(attacker, victim)),
        ("Safe upload signature", scenario_safe_upload(attacker, victim)),
    ]

    print("\nScenario validator (offline)\n")
    print("Vector order: [f1_rate_norm, f2_syn_norm, f3_port_norm, f4_len_norm, f5_fail_norm, f6_ctx_score]")
    print("Note: f6_ctx_score is discrete in {-1, 0, 1}\n")

    for name, pkts in scenarios:
        builder = FeatureVectorBuilder(window_size=1.0)
        scen_name, vec = _run_scenario(name, builder, pkts)
        f1, f2, f3, f4, f5, f6 = vec
        print(f"- {scen_name}:")
        print(f"  f1={f1:.4f}  f2={f2:.4f}  f3={f3:.4f}  f4={f4:.4f}  f5={f5:.4f}  f6={f6:.1f}")


if __name__ == "__main__":
    main()
