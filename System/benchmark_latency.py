"""
Latency Benchmark — đo độ trễ từng thành phần xử lý payload HTTPS

Đo 3 nguồn độc lập:
  A. PayloadNormalizer (9 bước, offline)
  B. CRS regex matching — SQLi 942 + XSS 941 (offline)
  C. tshark enrichment delay — wire timestamp vs event timestamp (live/PCAP)

Chạy:
  python3 System/benchmark_latency.py            # A + B (offline, không cần interface)
  python3 System/benchmark_latency.py --tshark   # A + B + C (cần SSLKEYLOGFILE hoặc plain HTTP)
  python3 System/benchmark_latency.py --pcap /path/to/capture.pcap  # C qua PCAP replay
"""

import argparse
import os
import re
import subprocess
import sys
import time
import threading
import statistics
from pathlib import Path

# Đảm bảo có thể import từ System/
_SYSTEM_DIR = Path(__file__).resolve().parent
if str(_SYSTEM_DIR) not in sys.path:
    sys.path.insert(0, str(_SYSTEM_DIR))

from feature.context import PayloadNormalizer
from core.crs_loader import load_rx_patterns, CRS_SQLI_CONF, CRS_XSS_CONF

# ─── Payload mẫu theo kích thước ──────────────────────────────────────────────

_SAMPLES = {
    "tiny_100B": (
        b"GET /login HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n"
        b"X-Attack: SELECT * FROM users WHERE id=1"
    ),
    "small_1KB": (
        b"POST /search HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
        + b"q=" + b"SELECT%20*%20FROM%20information_schema.tables%20WHERE%20table_schema%3D%27public%27" * 11
    ),
    "medium_10KB": (
        b"POST /api/data HTTP/1.1\r\n\r\n"
        + b"data=" + b"<script>alert(document.cookie)</script>" * 256
    ),
    "large_64KB": (
        b"POST /upload HTTP/1.1\r\n\r\n"
        + b"payload=" + b"A" * 1000 + b"' OR '1'='1" + b"B" * 500
    ) * 50,
    "double_encoded": (
        b"GET /path?id=%2527%2520OR%25201%253D1%2520--%2520 HTTP/1.1\r\n"
        b"User-Agent: sqlmap/1.7\r\n"
    ),
    "xss_obfuscated": (
        b"GET /?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\n"
        b"User-Agent: <img src=x onerror=eval(atob('YWxlcnQoMSk='))>\r\n"
    ),
}

# Cắt về 64KB để không vi phạm giới hạn normalizer
_SAMPLES = {k: v[:65536] for k, v in _SAMPLES.items()}


# ─── A. Benchmark PayloadNormalizer ───────────────────────────────────────────

def bench_normalizer(n_runs: int = 1000) -> dict:
    """Đo thời gian PayloadNormalizer.normalize() trên từng payload mẫu."""
    results = {}
    for name, payload in _SAMPLES.items():
        times = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            PayloadNormalizer.normalize(payload)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)  # ms

        results[name] = {
            "size_bytes": len(payload),
            "mean_ms":    round(statistics.mean(times), 4),
            "median_ms":  round(statistics.median(times), 4),
            "p95_ms":     round(sorted(times)[int(0.95 * n_runs)], 4),
            "max_ms":     round(max(times), 4),
        }
    return results


# ─── B. Benchmark CRS Regex Matching ─────────────────────────────────────────

def bench_crs(n_runs: int = 500) -> dict:
    """Đo thời gian quét toàn bộ ruleset CRS 942 (SQLi) và 941 (XSS)."""
    sqli_patterns = load_rx_patterns(CRS_SQLI_CONF, paranoia_level=2)
    xss_patterns  = load_rx_patterns(CRS_XSS_CONF,  paranoia_level=2)

    results = {}
    for name, payload in _SAMPLES.items():
        normalized = PayloadNormalizer.normalize(payload)

        # SQLi scan
        sqli_times = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            for _, _, pat in sqli_patterns:
                pat.search(normalized)
            sqli_times.append((time.perf_counter() - t0) * 1000)

        # XSS scan
        xss_times = []
        for _ in range(n_runs):
            t0 = time.perf_counter()
            for _, _, pat in xss_patterns:
                pat.search(normalized)
            xss_times.append((time.perf_counter() - t0) * 1000)

        results[name] = {
            "sqli_rules":    len(sqli_patterns),
            "xss_rules":     len(xss_patterns),
            "sqli_mean_ms":  round(statistics.mean(sqli_times), 4),
            "sqli_p95_ms":   round(sorted(sqli_times)[int(0.95 * n_runs)], 4),
            "sqli_max_ms":   round(max(sqli_times), 4),
            "xss_mean_ms":   round(statistics.mean(xss_times), 4),
            "xss_p95_ms":    round(sorted(xss_times)[int(0.95 * n_runs)], 4),
            "xss_max_ms":    round(max(xss_times), 4),
            "total_mean_ms": round(statistics.mean(sqli_times) + statistics.mean(xss_times), 4),
        }
    return results


# ─── C. Benchmark tshark enrichment delay ────────────────────────────────────

def bench_tshark_pcap(pcap_path: str, keylog: str = None, n_packets: int = 200) -> dict:
    """
    Đo độ trễ tshark qua PCAP replay.

    Phương pháp:
    1. Chạy tshark -r <pcap> với output field frame.time_epoch + http.*
    2. Ghi lại thời điểm tshark output từng dòng (time.perf_counter())
    3. So sánh với frame.time_epoch (wire timestamp)
    4. Độ trễ = wall_time_output - wire_timestamp_of_last_packet
       → phản ánh tshark processing + line-buffered stdout flush

    Lưu ý: Với PCAP replay, tshark xử lý nhanh hơn live vì không có
    kernel packet capture overhead. Kết quả là lower bound của live latency.
    """
    cmd = [
        'tshark', '-r', pcap_path,
        '-Y', 'http.request',
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'tcp.srcport',
        '-e', 'http.request.method',
        '-e', 'http.request.uri',
        '-E', 'separator=\x01',
        '-l',
    ]
    if keylog:
        cmd += ['-o', f'tls.keylog_file:{keylog}']

    delays = []
    first_output_latency = None

    try:
        t_start = time.perf_counter()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        count = 0
        for line in proc.stdout:
            t_got = time.perf_counter()
            line = line.strip()
            if not line:
                continue
            parts = line.split('\x01')
            if not parts[0]:
                continue
            try:
                wire_ts = float(parts[0])
            except ValueError:
                continue

            if first_output_latency is None:
                first_output_latency = (t_got - t_start) * 1000  # ms — startup + first parse

            delays.append((t_got - t_start) * 1000)  # ms from proc start
            count += 1
            if count >= n_packets:
                break

        proc.terminate()
        proc.wait(timeout=3)

    except FileNotFoundError:
        return {"error": "tshark not found — install wireshark-common"}
    except Exception as e:
        return {"error": str(e)}

    if not delays:
        return {"error": "No HTTP packets found in PCAP (need plain HTTP or TLS keylog)"}

    return {
        "n_events":              len(delays),
        "startup_first_event_ms": round(first_output_latency, 2),
        "mean_cumulative_ms":    round(statistics.mean(delays), 2),
        "median_ms":             round(statistics.median(delays), 2),
        "p95_ms":                round(sorted(delays)[int(0.95 * len(delays))], 2),
        "throughput_events_sec": round(len(delays) / (max(delays) / 1000), 1) if delays else 0,
        "note": (
            "Giá trị này là thời gian tích lũy từ lúc tshark khởi động đến khi nhận event. "
            "Với live capture, cộng thêm ~5-20ms kernel capture overhead."
        ),
    }


def bench_tshark_live(interface: str, keylog: str, duration_sec: int = 10) -> dict:
    """
    Đo độ trễ tshark trên live traffic.

    Phương pháp:
    1. Ghi lại t_wire = thời điểm Scapy nhận packet (thực tế là t_start + offset)
    2. Ghi lại t_tshark = khi tshark output dòng tương ứng
    3. Delay = t_tshark - t_wire  ← IPC latency thực tế

    Để có kết quả chính xác: cần có HTTP traffic trên interface trong duration_sec.
    Gợi ý: chạy `curl http://target/` trong khi benchmark này đang chạy.
    """
    _SEP = '\x01'
    events = []
    t_start = time.perf_counter()

    cmd = [
        'tshark', '-i', interface,
        '-Y', 'http.request',
        '-T', 'fields',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'http.request.method',
        '-E', f'separator={_SEP}',
        '-l',
    ]
    if keylog:
        cmd += ['-o', f'tls.keylog_file:{keylog}']

    delays = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        def _reader():
            for line in proc.stdout:
                t_got = time.perf_counter()
                line = line.strip()
                if not line:
                    continue
                parts = line.split(_SEP)
                if not parts[0]:
                    continue
                try:
                    wire_ts = float(parts[0])
                    # Convert wire timestamp (epoch) to offset từ t_start
                    # Để so sánh đồng hồ: lấy epoch hiện tại khi tshark start
                    delays.append({
                        "wire_epoch":   wire_ts,
                        "got_perf":     t_got,
                        "got_epoch":    time.time(),
                    })
                except ValueError:
                    pass

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        time.sleep(duration_sec)
        proc.terminate()
        proc.wait(timeout=3)
        t.join(timeout=2)

    except FileNotFoundError:
        return {"error": "tshark not found"}
    except Exception as e:
        return {"error": str(e)}

    if not delays:
        return {"error": f"Không có HTTP event nào trong {duration_sec}s — hãy generate traffic (curl) trong lúc benchmark chạy"}

    # Ước tính delay: got_epoch - wire_epoch
    real_delays_ms = [(d["got_epoch"] - d["wire_epoch"]) * 1000 for d in delays]
    # Loại bỏ outlier âm (clock skew)
    real_delays_ms = [d for d in real_delays_ms if 0 < d < 5000]

    if not real_delays_ms:
        return {"error": "Clock skew quá lớn — không thể tính delay chính xác từ live capture"}

    return {
        "n_events":    len(real_delays_ms),
        "mean_ms":     round(statistics.mean(real_delays_ms), 2),
        "median_ms":   round(statistics.median(real_delays_ms), 2),
        "p95_ms":      round(sorted(real_delays_ms)[int(0.95 * len(real_delays_ms))], 2),
        "max_ms":      round(max(real_delays_ms), 2),
        "note": (
            "Đo từ frame.time_epoch (wire) đến khi Python nhận được dòng stdout của tshark. "
            "Bao gồm: tshark dissection + line-buffer flush + subprocess IPC."
        ),
    }


# ─── Report ───────────────────────────────────────────────────────────────────

def _print_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def _print_table(data: dict):
    col_w = 22
    for name, row in data.items():
        if "error" in row:
            print(f"  {name}: ERROR — {row['error']}")
            continue
        size = row.get("size_bytes", "")
        size_str = f"({size:,}B)" if size else ""
        print(f"\n  [{name}] {size_str}")
        for k, v in row.items():
            if k in ("size_bytes",):
                continue
            print(f"    {k:<30} {v}")


def main():
    parser = argparse.ArgumentParser(description="Latency benchmark cho HTTPS NIDS pipeline")
    parser.add_argument("--tshark",    action="store_true",  help="Kích hoạt đo tshark live")
    parser.add_argument("--pcap",      type=str, default="", help="Đo tshark qua PCAP file")
    parser.add_argument("--iface",     type=str, default="",  help="Interface cho tshark live")
    parser.add_argument("--keylog",    type=str, default="",  help="SSLKEYLOGFILE path")
    parser.add_argument("--runs",      type=int, default=500, help="Số lần lặp mỗi benchmark (mặc định 500)")
    parser.add_argument("--duration",  type=int, default=10,  help="Thời gian live capture (giây)")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  NIDS Latency Benchmark")
    print("  Môi trường: HTTPS toàn bộ traffic")
    print("="*60)

    # A. PayloadNormalizer
    _print_section("A. PayloadNormalizer (8 bước) — thời gian normalize() per payload")
    print(f"  Số lần lặp: {args.runs}")
    norm_results = bench_normalizer(n_runs=args.runs)
    _print_table(norm_results)

    # Tổng hợp A
    means = [r["mean_ms"] for r in norm_results.values()]
    print(f"\n  → Trung bình trên tất cả payload: {round(sum(means)/len(means), 4)} ms")
    print(f"  → Worst-case (max_ms): {round(max(r['max_ms'] for r in norm_results.values()), 4)} ms")

    # B. CRS Regex
    _print_section("B. CRS Regex Matching — toàn bộ ruleset (SQLi 942 PL2 + XSS 941 PL2)")
    print(f"  Số lần lặp: {args.runs}")
    crs_results = bench_crs(n_runs=args.runs)
    _print_table(crs_results)

    # Tổng hợp B
    total_means = [r["total_mean_ms"] for r in crs_results.values()]
    print(f"\n  → Trung bình tổng (SQLi + XSS): {round(sum(total_means)/len(total_means), 4)} ms")
    print(f"  → Worst-case p95: {round(max(r['sqli_p95_ms'] + r['xss_p95_ms'] for r in crs_results.values()), 4)} ms")

    # Tổng hợp A+B
    _print_section("Tổng hợp A+B — Normalizer + CRS (không tính tshark)")
    for name in norm_results:
        a = norm_results[name]["mean_ms"]
        b = crs_results[name]["total_mean_ms"]
        print(f"  {name:<25} normalizer={a} ms + CRS={b} ms = total={round(a+b,4)} ms")

    # C. tshark
    if args.pcap:
        _print_section(f"C. tshark enrichment delay — PCAP: {args.pcap}")
        result = bench_tshark_pcap(args.pcap, keylog=args.keylog or None)
        if "error" in result:
            print(f"  ERROR: {result['error']}")
        else:
            for k, v in result.items():
                print(f"  {k:<35} {v}")

    elif args.tshark:
        if not args.iface:
            print("\n  [C] --tshark cần --iface <interface>. Ví dụ: --iface eth0")
            print("      Trong khi benchmark chạy, generate traffic: curl http://target/")
        else:
            _print_section(f"C. tshark enrichment delay — live {args.iface} ({args.duration}s)")
            if args.keylog:
                print(f"  SSLKEYLOGFILE: {args.keylog}")
            else:
                print("  Không có SSLKEYLOGFILE — chỉ plain HTTP được decode")
            result = bench_tshark_live(args.iface, args.keylog or None, duration_sec=args.duration)
            if "error" in result:
                print(f"  ERROR: {result['error']}")
            else:
                for k, v in result.items():
                    print(f"  {k:<35} {v}")

    else:
        print("\n  [C] tshark chưa được đo. Để đo:")
        print("      PCAP:  python3 benchmark_latency.py --pcap capture.pcap [--keylog /tmp/tls.log]")
        print("      Live:  python3 benchmark_latency.py --tshark --iface eth0 --keylog /tmp/tls.log --duration 10")

    print("\n" + "="*60)
    print("  Xong. Xem kết quả ở trên.")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
