"""
Benchmark throughput của PayloadNormalizer pipeline.
Chạy từ thư mục System/:
    python benchmark_payload.py
"""
import sys, time, statistics

sys.path.insert(0, ".")
from feature.context import PayloadNormalizer

# --------------------------------------------------------------------------
# Test payloads: mix normal + SQLi + XSS + double-encoded evasion
# --------------------------------------------------------------------------
PAYLOADS_RAW = [
    # Normal
    b"GET /index.html HTTP/1.1",
    b"search=hello+world&page=1",
    b"user=admin&action=view_profile",
    b"q=reinforcement+learning+network+defense",
    b"filename=report_2024.pdf&download=1",

    # SQLi
    b"SELECT * FROM users WHERE id=1 UNION SELECT null,null--",
    b"'; DROP TABLE users; --",
    b"1' OR '1'='1",
    b"admin'--",
    b"1; EXEC xp_cmdshell('whoami')--",

    # XSS
    b"<script>alert(document.cookie)</script>",
    b"<img src=x onerror=alert(1)>",
    b"javascript:eval(atob('YWxlcnQoMSk='))",
    b"<svg onload=alert('xss')>",

    # Double-encoded SQLi (evasion)
    b"%2527%20OR%20%25271%2527%253D%25271",   # %27 → ' double-encoded
    b"%253CSCRIPT%253Ealert(1)%253C%252FSCRIPT%253E",

    # Base64-encoded payload
    b"dW5pb24gc2VsZWN0IHVzZXJuYW1lLCBwYXNzd29yZCBmcm9tIHVzZXJz",

    # Long normal payload
    b"name=John+Doe&email=john@example.com&message=Hello+this+is+a+test+message+with+normal+content",
]

# Replicate to get N=5000 samples
PAYLOADS = (PAYLOADS_RAW * 278)[:5000]  # ~5000 calls

# --------------------------------------------------------------------------
# Warmup
# --------------------------------------------------------------------------
for p in PAYLOADS[:100]:
    PayloadNormalizer.normalize(p)

# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------
times_us = []
for payload in PAYLOADS:
    t0 = time.perf_counter()
    PayloadNormalizer.normalize(payload)
    elapsed = (time.perf_counter() - t0) * 1e6  # microseconds
    times_us.append(elapsed)

times_us.sort()
n = len(times_us)
mean_us = statistics.mean(times_us)
median_us = statistics.median(times_us)
p95_us = times_us[int(0.95 * n)]
p99_us = times_us[int(0.99 * n)]
throughput = 1_000_000 / mean_us

print(f"\n{'='*50}")
print(f"PayloadNormalizer Throughput Benchmark  (N={n})")
print(f"{'='*50}")
print(f"Mean:        {mean_us:8.2f} µs/call")
print(f"Median:      {median_us:8.2f} µs/call")
print(f"P95:         {p95_us:8.2f} µs/call")
print(f"P99:         {p99_us:8.2f} µs/call")
print(f"Throughput:  {throughput:,.0f} calls/sec")
print(f"{'='*50}")
print(f"\nFor paper:")
print(f"  mean={mean_us:.2f}µs/call, P99={p99_us:.1f}µs, throughput={throughput:,.0f} calls/sec")
