"""
payload_inspection.py — Investigate F20 hypothesis bằng cách inspect raw HTTP
payloads từ CIC-IDS2018 PCAP gốc trong attack window XSS.

Mục đích: Verify F20=0 trên CIC-IDS2018 LÀ EXPECTED (data limitation), không
phải code bug.

Pipeline:
  1. Run tshark trên PCAP gốc filter: HTTP requests từ attacker IP trong
     attack window XSS (13:50-14:29 AST = 17:50-18:29 UTC)
  2. Extract URI + Body của 30 requests
  3. Search F20 patterns: regex r"\\bon(?:error|load|click|...)\\s*="
  4. Search F18/F19 patterns: script tag, alert/eval
  5. Report:
     - N requests total
     - N có script tag
     - N có event handler (should be ≈ 0 if hypothesis correct)
     - Sample 10 raw payloads để hội đồng inspect

Output: results/correctness_payload_inspection.json
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SYSTEM_DIR = REPO_ROOT / "System"
sys.path.insert(0, str(SYSTEM_DIR))

PCAP_PATH = "/mnt/hgfs/Dataset/Thursday-22-02-2018_pcap/pcap/UCAP172.31.69.28"
ATTACKER_IP = "18.218.115.60"
RESULTS_DIR = Path(__file__).parent / "results"
OUTPUT_FILE = RESULTS_DIR / "correctness_payload_inspection.json"

# XSS attack window (UTC epoch — converted from AST 13:50-14:29)
import calendar, datetime
def _ast(date_str: str) -> float:
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return float(calendar.timegm(dt.timetuple())) + 4 * 3600

XSS_WINDOW_START = _ast("2018-02-22 13:50:00")
XSS_WINDOW_END = _ast("2018-02-22 14:29:00")

# Patterns from System/feature/calculators/xss_features.py
EVENT_HANDLER_REGEX = re.compile(
    r"\bon(?:error|load|click|mouse(?:over|out|down|up)|focus|blur"
    r"|change|submit|reset|select|input|invalid"
    r"|key(?:down|up|press)|dblclick|contextmenu"
    r"|toggle|animationstart|animationend|transitionend"
    r"|pointer(?:down|up|move|enter|leave)|wheel"
    r"|touch(?:start|end|move|cancel)|loadstart"
    r"|drag(?:start|end|over|leave|enter)?|drop|paste|copy|cut)\s*=",
    re.IGNORECASE,
)

SCRIPT_TAG_REGEX = re.compile(r"<\s*script\b", re.IGNORECASE)
JS_FUNC_REGEX = re.compile(r"\b(?:alert|eval|prompt|confirm)\s*\(", re.IGNORECASE)


def extract_http_requests_in_window(pcap: str, attacker_ip: str,
                                     t_start: float, t_end: float) -> list[dict]:
    """Run tshark on PCAP, extract HTTP requests from attacker in window.

    Note: PCAP may have truncation warning — we post-filter timestamps in Python
    rather than relying on tshark filter expression (which fails on truncated PCAP).
    """
    # Use tab separator (default) to avoid issues when --E separator= conflicts
    cmd = [
        "tshark", "-r", pcap,
        "-Y", f"http.request and ip.src == {attacker_ip}",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "http.request.method",
        "-e", "http.request.uri",
        "-e", "http.user_agent",
        "-e", "http.file_data",
    ]
    print(f"  Running tshark on {Path(pcap).name} (filter attacker only, window post-filtered) ...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    # tshark may return non-zero on truncation but still output data — proceed

    rows = []
    parsed = 0
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 5:
            parts.append("")
        try:
            ts = float(parts[0])
        except ValueError:
            continue
        parsed += 1
        if not (t_start <= ts <= t_end):
            continue
        rows.append({
            "ts": ts,
            "method": parts[1],
            "uri": parts[2],
            "ua": parts[3],
            "body": parts[4],
        })
    print(f"  Parsed {parsed} total attacker HTTP requests, {len(rows)} in window")
    return rows


def search_patterns(rows: list[dict]) -> dict:
    """Count requests matching each pattern.

    Note: CIC-IDS2018 attacker payloads are URL-encoded (e.g., %3Cscript%3E
    instead of <script>). We URL-decode before regex search to match the
    actual semantic content. This mirrors what System/feature/calculators
    does via FeatureContext.get_normalized().
    """
    from urllib.parse import unquote_plus
    n_total = len(rows)
    n_script = 0
    n_event_handler = 0
    n_js_func = 0
    matched_event_handler = []
    matched_script = []

    for r in rows:
        # URL-decode URI + body before pattern search
        uri_decoded = unquote_plus(r["uri"])
        body_decoded = unquote_plus(r["body"])
        text = f"{uri_decoded} {body_decoded}"
        if SCRIPT_TAG_REGEX.search(text):
            n_script += 1
            if len(matched_script) < 10:
                matched_script.append(r)
        if EVENT_HANDLER_REGEX.search(text):
            n_event_handler += 1
            if len(matched_event_handler) < 10:
                matched_event_handler.append(r)
        if JS_FUNC_REGEX.search(text):
            n_js_func += 1

    return {
        "n_total": n_total,
        "n_script_tag": n_script,
        "n_event_handler": n_event_handler,
        "n_js_function_call": n_js_func,
        "matched_event_handler": matched_event_handler,
        "matched_script": matched_script,
    }


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if not Path(PCAP_PATH).exists():
        print(f"  ERROR: PCAP not found at {PCAP_PATH}")
        print(f"  Mount /mnt/hgfs/ first")
        return

    print(f"Inspecting XSS window {XSS_WINDOW_START} to {XSS_WINDOW_END}")
    print(f"  AST: 13:50:00 to 14:29:00 (UTC: 17:50:00 to 18:29:00)")
    print(f"  Attacker IP: {ATTACKER_IP}")

    rows = extract_http_requests_in_window(
        PCAP_PATH, ATTACKER_IP, XSS_WINDOW_START, XSS_WINDOW_END
    )
    print(f"\nExtracted {len(rows)} HTTP requests")

    patterns = search_patterns(rows)
    print()
    print(f"Pattern search results:")
    print(f"  Script tag (<script>):       {patterns['n_script_tag']:>4} / {patterns['n_total']}")
    print(f"  Event handler (onerror=...): {patterns['n_event_handler']:>4} / {patterns['n_total']}")
    print(f"  JS function call (alert()):  {patterns['n_js_function_call']:>4} / {patterns['n_total']}")

    print(f"\nSample matched event handler payloads (first 5):")
    if patterns["matched_event_handler"]:
        for i, r in enumerate(patterns["matched_event_handler"][:5], start=1):
            uri_short = r["uri"][:120] + "..." if len(r["uri"]) > 120 else r["uri"]
            print(f"  {i}. URI: {uri_short}")
    else:
        print("  → ZERO event handler patterns found in CIC XSS attack window")
        print("  → CONFIRMED: F20=0 trên CIC LÀ EXPECTED (CIC XSS không inject event handlers)")

    print(f"\nSample matched script tag payloads (first 5):")
    for i, r in enumerate(patterns["matched_script"][:5], start=1):
        uri_short = r["uri"][:120] + "..." if len(r["uri"]) > 120 else r["uri"]
        print(f"  {i}. URI: {uri_short}")

    # Sample 10 random payloads cho hội đồng inspect
    sample_payloads = rows[::max(len(rows) // 10, 1)][:10] if rows else []
    print(f"\nSample 10 random XSS payloads (URI):")
    for i, r in enumerate(sample_payloads, start=1):
        uri_short = r["uri"][:140] + "..." if len(r["uri"]) > 140 else r["uri"]
        print(f"  {i}. ts={r['ts']:.0f}  {r['method']}  {uri_short}")

    output = {
        "metadata": {
            "purpose": "Verify F20=0 hypothesis on CIC-IDS2018 — inspect raw payloads",
            "pcap": PCAP_PATH,
            "attacker_ip": ATTACKER_IP,
            "window_ast": "2018-02-22 13:50:00 to 14:29:00 (XSS attack)",
            "n_requests": patterns["n_total"],
        },
        "pattern_counts": {
            "script_tag": patterns["n_script_tag"],
            "event_handler": patterns["n_event_handler"],
            "js_function_call": patterns["n_js_function_call"],
        },
        "interpretation": {
            "f20_expected_zero": patterns["n_event_handler"] == 0,
            "verdict": (
                "CONFIRMED: CIC XSS không inject event handlers, F20=0 LÀ EXPECTED, "
                "không phải code bug (boundary_test verified F20 code path active)"
                if patterns["n_event_handler"] == 0
                else f"UNEXPECTED: found {patterns['n_event_handler']} event handlers, "
                     f"F20 should fire — investigate why F20=0 in dataset"
            ),
        },
        "sample_event_handlers": patterns["matched_event_handler"][:5],
        "sample_script_tags": patterns["matched_script"][:5],
        "sample_random_uris": [r["uri"] for r in sample_payloads],
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {OUTPUT_FILE.name}")


if __name__ == "__main__":
    main()
