"""Feature benchmarks for network-traffic -> feature pipeline (SAFE, offline).

Goal
- Provide numeric, repeatable PASS/FAIL checks to detect when features are wrong or drift.
- Uses synthetic LayerInfo sequences (no real traffic is generated).

Run
  python -m tools.feature_benchmark

Notes
- Vector order follows config.FEATURE_NAMES:
  [f1_rate_norm, f2_syn_norm, f3_port_norm, f4_len_norm, f5_fail_norm, f6_ctx_score]
- f6_ctx_score is discrete in {-1, 0, 1} by design.
"""

from __future__ import annotations

import math
import os
import sys
from dataclasses import dataclass
from typing import Callable, List, Sequence, Tuple

# Allow running as: python -m tools.feature_benchmark
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import ai_config as config
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


def _run(builder: FeatureVectorBuilder, packets: Sequence[LayerInfo]) -> List[float]:
    last_vec = None
    for p in packets:
        last_vec = builder.process_layer_info(p)
    if last_vec is None:
        last_vec = builder.process_layer_info(LayerInfo(timestamp=0.0, packet_number=0))
    return [float(x) for x in last_vec]


@dataclass(frozen=True)
class Check:
    name: str
    fn: Callable[[List[float]], Tuple[bool, str]]


def _close(a: float, b: float, tol: float) -> bool:
    return abs(a - b) <= tol


def _check_close(idx: int, expected: float, tol: float, label: str) -> Check:
    def _fn(vec: List[float]) -> Tuple[bool, str]:
        got = vec[idx]
        ok = _close(got, expected, tol)
        msg = f"{label}: got={got:.6f} expected={expected:.6f} tol=±{tol:.6f}"
        return ok, msg

    return Check(name=label, fn=_fn)


def _check_between(idx: int, lo: float, hi: float, label: str) -> Check:
    def _fn(vec: List[float]) -> Tuple[bool, str]:
        got = vec[idx]
        ok = (got >= lo) and (got <= hi)
        msg = f"{label}: got={got:.6f} expected in [{lo:.6f}, {hi:.6f}]"
        return ok, msg

    return Check(name=label, fn=_fn)


def _check_in_set(idx: int, allowed: Sequence[float], label: str) -> Check:
    allowed_set = set(float(x) for x in allowed)

    def _fn(vec: List[float]) -> Tuple[bool, str]:
        got = float(vec[idx])
        ok = got in allowed_set
        msg = f"{label}: got={got:.6f} expected one of {sorted(allowed_set)}"
        return ok, msg

    return Check(name=label, fn=_fn)


# Indices by contract
F1, F2, F3, F4, F5, F6 = 0, 1, 2, 3, 4, 5


def scenario_syn_flood(attacker: str, victim: str, base_ts: float = 1_000.0) -> List[LayerInfo]:
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
    packets: List[LayerInfo] = []
    n = 1
    ports = list(range(20, 80))  # 60 distinct ports
    for i, dport in enumerate(ports):
        ts = base_ts + (i / len(ports)) * 0.9
        sport = 40000 + (i % 2000)
        packets.append(_tcp_packet(ts=ts, n=n, src_ip=attacker, dst_ip=victim, sport=sport, dport=dport, flags="S"))
        n += 1
        packets.append(_tcp_packet(ts=ts + 0.0005, n=n, src_ip=victim, dst_ip=attacker, sport=dport, dport=sport, flags="RA"))
        n += 1
    return packets


def scenario_payload_outlier(attacker: str, victim: str, base_ts: float = 4_000.0) -> List[LayerInfo]:
    packets: List[LayerInfo] = []
    n = 1
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
                payload=b"hello-world",
            )
        )
        n += 1
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


def scenario_tcp_normal_handshake(attacker: str, victim: str, base_ts: float = 8_000.0) -> List[LayerInfo]:
    # SYN (fwd), SYN-ACK (bwd), ACK (fwd)
    return [
        _tcp_packet(ts=base_ts + 0.00, n=1, src_ip=attacker, dst_ip=victim, sport=60000, dport=80, flags="S"),
        _tcp_packet(ts=base_ts + 0.01, n=2, src_ip=victim, dst_ip=attacker, sport=80, dport=60000, flags="SA"),
        _tcp_packet(ts=base_ts + 0.02, n=3, src_ip=attacker, dst_ip=victim, sport=60000, dport=80, flags="A"),
    ]


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


def scenario_web_xss_urlencoded(attacker: str, victim: str, base_ts: float = 6_000.0) -> List[LayerInfo]:
    # Current FlowFeature6 checks for <SCRIPT etc (not URL-decoding), so this is expected neutral (0.0)
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


def _expected_for_syn_flood() -> List[Check]:
    # 400 pkts within ~1s => packet_rate_raw=400, norm=400/3000
    f1 = config.normalize(400.0 / 1.0, config.MAX_PACKET_RATE)
    return [
        _check_close(F1, f1, tol=1e-6, label="F1 packet rate"),
        _check_close(F2, 1.0, tol=1e-6, label="F2 SYN/(SYN+ACK)"),
        _check_between(F3, 0.0, 0.05, label="F3 distinct ports low"),
        _check_in_set(F6, [0.0, 1.0, -1.0], label="F6 discrete domain"),
    ]


def _expected_for_udp_flood() -> List[Check]:
    f1 = config.normalize(500.0 / 1.0, config.MAX_PACKET_RATE)
    return [
        _check_close(F1, f1, tol=1e-6, label="F1 packet rate"),
        _check_close(F2, 0.0, tol=1e-6, label="F2 SYN/(SYN+ACK)"),
        _check_between(F3, 0.0, 0.05, label="F3 distinct ports low"),
        _check_close(F5, 0.0, tol=1e-6, label="F5 fail rate"),
        _check_close(F6, 0.0, tol=1e-6, label="F6 context"),
    ]


def _expected_for_port_scan_with_rst() -> List[Check]:
    # 60 ports, 2 packets per port => 120 packets total => F1=120/3000
    f1 = config.normalize(120.0 / 1.0, config.MAX_PACKET_RATE)
    # Distinct ports clipped to 1.0 since 60 > MAX_DISTINCT_PORTS=50
    f3 = 1.0
    # RST from backward: 60 / 120 => 0.5
    f5 = 0.5
    return [
        _check_close(F1, f1, tol=1e-6, label="F1 packet rate"),
        _check_close(F2, 1.0, tol=1e-6, label="F2 SYN/(SYN+ACK)"),
        _check_close(F3, f3, tol=1e-6, label="F3 distinct ports"),
        _check_close(F5, f5, tol=1e-3, label="F5 fail rate"),
        _check_in_set(F6, [-1.0, 0.0, 1.0], label="F6 discrete domain"),
    ]


def _expected_for_payload_outlier() -> List[Check]:
    # Should detect outlier max_len=1200 => norm=1200/1500=0.8
    f4 = config.normalize(1200.0, config.MAX_PAYLOAD_LEN)
    return [
        _check_between(F4, f4 - 1e-6, f4 + 1e-6, label="F4 payload outlier"),
        _check_in_set(F6, [-1.0, 0.0, 1.0], label="F6 discrete domain"),
    ]


def _expected_for_tcp_handshake() -> List[Check]:
    # Forward SYN=1, forward ACK=1 => SYN/(SYN+ACK)=0.5
    return [
        _check_close(F2, 0.5, tol=1e-6, label="F2 SYN/(SYN+ACK)"),
        _check_close(F5, 0.0, tol=1e-6, label="F5 fail rate"),
    ]


def _expected_for_sqli() -> List[Check]:
    return [
        _check_close(F6, 1.0, tol=1e-6, label="F6 malicious signature"),
    ]


def _expected_for_xss_urlencoded_current() -> List[Check]:
    # With multi-layer decoding enabled, URL-encoded XSS should be detected.
    return [
        _check_close(F6, 1.0, tol=1e-6, label="F6 urlencoded xss"),
    ]


def _expected_for_safe_upload() -> List[Check]:
    return [
        _check_close(F6, -1.0, tol=1e-6, label="F6 safe upload"),
    ]


def main() -> int:
    attacker = "10.0.0.10"
    victim = "10.0.0.20"

    suites: List[Tuple[str, List[LayerInfo], List[Check]]] = [
        ("SYN flood", scenario_syn_flood(attacker, victim), _expected_for_syn_flood()),
        ("UDP flood", scenario_udp_flood(attacker, victim), _expected_for_udp_flood()),
        ("Port scan + RST", scenario_port_scan_with_rst(attacker, victim), _expected_for_port_scan_with_rst()),
        ("Payload outlier", scenario_payload_outlier(attacker, victim), _expected_for_payload_outlier()),
        ("TCP normal handshake", scenario_tcp_normal_handshake(attacker, victim), _expected_for_tcp_handshake()),
        ("Web SQLi signature", scenario_web_sqli(attacker, victim), _expected_for_sqli()),
        ("Web XSS urlencoded", scenario_web_xss_urlencoded(attacker, victim), _expected_for_xss_urlencoded_current()),
        ("Safe upload signature", scenario_safe_upload(attacker, victim), _expected_for_safe_upload()),
    ]

    print("\nFeature benchmark (offline)\n")
    print(f"Vector order: {config.FEATURE_NAMES}")
    print("Note: f6_ctx_score is discrete in {-1, 0, 1}\n")

    total_checks = 0
    failed_checks: List[str] = []

    for name, packets, checks in suites:
        builder = FeatureVectorBuilder(window_size=1.0)
        vec = _run(builder, packets)
        print(f"[{name}] vec={vec}")

        for check in checks:
            total_checks += 1
            ok, msg = check.fn(vec)
            if not ok:
                failed_checks.append(f"[{name}] {msg}")

    print("\n--- Summary ---")
    print(f"Checks: {total_checks} | Failed: {len(failed_checks)}")
    if failed_checks:
        for line in failed_checks:
            print("FAIL", line)
        return 1

    print("PASS: All benchmarks satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
