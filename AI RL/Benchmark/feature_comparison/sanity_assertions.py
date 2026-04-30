"""
sanity_assertions.py — Automated assertions kiểm tra design intent của F1-F20.

Đối với mỗi assertion, kiểm tra:
  - Feature value có khớp design intent không (dựa trên comments + code trong
    System/feature/calculators/*.py).

Severity:
  - REQUIRED:  PASS bắt buộc. FAIL → CRITICAL (feature broken hoặc dataset wrong)
  - EXPECTED:  thường PASS. FAIL → WARNING (investigate)
  - OPTIONAL:  có thể FAIL nếu data limit (vd F20 trên CIC). Document trong README.

Output:
  - results/correctness_report.json
  - results/plots/25_sanity_pass_fail.png
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from load_20d import load_20d_labeled
from load_2017 import load_2017_labeled

RESULTS_DIR = Path(__file__).parent / "results"
PLOTS_DIR = RESULTS_DIR / "plots"
OUTPUT_FILE = RESULTS_DIR / "correctness_assertions.json"


# Format: (feature_short, class, op, threshold_or_other_class, severity, design_rationale)
# op: ">", "<", ">>", "<<"  (>> means "much greater" — diff > 5x)
ASSERTIONS_2018 = [
    # F4 trên 2018 chỉ có L7 attacks → expected ≈ 0 ở attack rows
    ("F4",  "brute_force", "<", 0.1, "REQUIRED",
     "L7 brute force connections complete → ít RST"),
    ("F4",  "sqli",        "<", 0.1, "REQUIRED",
     "L7 SQLi connections complete → ít RST"),
    ("F4",  "xss",         "<", 0.1, "REQUIRED",
     "L7 XSS connections complete → ít RST"),

    # Application-level
    ("F6",  "brute_force", ">", 0.5, "REQUIRED",
     "Brute force concentrate trên 1 URL → URLConcentration cao"),
    ("F7",  "brute_force", ">", 0.3, "OPTIONAL",
     "Bot timing uniformity — depends on attacker tool"),

    # SQLi rules
    ("F12", "sqli",        ">", "benign", "REQUIRED",
     "SQLi payload có nhiều SQL special chars"),
    ("F13", "sqli",        ">", 1.0, "REQUIRED",
     "CRS-942 score >1 cho SQLi class (design threshold)"),
    ("F13", "sqli",        ">", "brute_force", "REQUIRED",
     "SQLi class phải có CRS-942 cao nhất"),
    ("F13", "benign",      "<", 0.1, "REQUIRED",
     "Benign requests không nên trigger CRS-942"),
    ("F14", "sqli",        ">", 0, "OPTIONAL",
     "UNION SELECT — depends on attacker payloads"),

    # XSS rules
    ("F18", "xss",         ">", "benign", "REQUIRED",
     "XSS class phải có CRS-941 score cao hơn benign"),
    ("F18", "xss",         ">", 1.0, "REQUIRED",
     "CRS-941 score >1 cho XSS class"),
    ("F18", "benign",      "<", 0.1, "REQUIRED",
     "Benign không nên trigger CRS-941"),
    ("F19", "xss",         ">", 0, "REQUIRED",
     "JS function call (alert/eval) phải fire ≥1 trong window XSS"),
    ("F20", "xss",         ">", 0, "OPTIONAL",
     "HTML event handler — data-dependent: CIC XSS có thể không inject"),
]

ASSERTIONS_2017 = [
    # Network features — 2017 có port scan + DDoS
    ("F1",  "scan_fw_off", ">", "benign", "REQUIRED",
     "Fast port scan có packet rate cao"),
    ("F1",  "syn_flood",   ">", "benign", "REQUIRED",
     "SYN flood có high pps"),
    ("F4",  "scan_fw_on",  ">", 0.3, "REQUIRED",
     "Port scan: F4 ≥ 0.3 (design)"),
    ("F4",  "scan_fw_off", ">", 0.3, "REQUIRED",
     "Port scan F4 ≥ 0.3 (design)"),
    ("F5",  "scan_fw_off", ">", 50, "REQUIRED",
     "DistinctPorts > 50 cho fast port scan (design)"),
    ("F4",  "syn_flood",   "<", 0.1, "EXPECTED",
     "Spoofed SYN không nhận response RST"),

    # L7 attacks không tạo RST
    ("F4",  "brute_force", "<", 0.1, "REQUIRED", "L7 connections complete"),
    ("F4",  "sqli",        "<", 0.1, "REQUIRED", "L7 connections complete"),
    ("F4",  "xss",         "<", 0.1, "REQUIRED", "L7 connections complete"),

    # F18/F19 cho XSS 2017
    ("F18", "xss",         ">", "benign", "REQUIRED", "CRS-941 cao cho XSS"),
    ("F19", "xss",         ">", 0,       "REQUIRED", "JS function call cho XSS"),

    # F13 cho SQLi 2017
    ("F13", "sqli",        ">", "benign", "REQUIRED", "CRS-942 cao cho SQLi"),
]


def _full_feature_name(short: str) -> str:
    """Map 'F4' to full column name 'F4 - RstRatio'."""
    name_map = {
        "F1": "F1 - PacketRate", "F2": "F2 - SynAckRatio",
        "F3": "F3 - InterArrivalTime", "F4": "F4 - RstRatio",
        "F5": "F5 - DistinctPorts", "F6": "F6 - URLConcentration",
        "F7": "F7 - HttpIatUniformity", "F8": "F8 - RequestSizeUniformity",
        "F9": "F9 - AvgPayloadSize", "F10": "F10 - FwdBwdRatio",
        "F11": "F11 - PacketsPerPort", "F12": "F12 - SqlSpecialChar",
        "F13": "F13 - CrsSqliScore", "F14": "F14 - SqlUnionSelect",
        "F15": "F15 - SqlComment", "F16": "F16 - SqlStackedQuery",
        "F17": "F17 - SqlSelectCount", "F18": "F18 - CrsXssScore",
        "F19": "F19 - JsFunctionCall", "F20": "F20 - HtmlEventHandler",
    }
    return name_map.get(short, short)


def evaluate_assertion(
    df: pd.DataFrame, feat_short: str, target_class: str,
    op: str, ref: Any,
) -> Tuple[bool, dict]:
    """Evaluate a single assertion. Returns (passed, info)."""
    feat_full = _full_feature_name(feat_short)
    if feat_full not in df.columns:
        return False, {"error": f"Feature {feat_full} not in data"}
    target_df = df[df["label"] == target_class]
    if len(target_df) == 0:
        return False, {"error": f"Class {target_class} not in dataset"}

    target_mean = float(target_df[feat_full].mean())

    if isinstance(ref, str):  # comparison with another class
        ref_df = df[df["label"] == ref]
        if len(ref_df) == 0:
            return False, {"error": f"Reference class {ref} not in dataset"}
        ref_mean = float(ref_df[feat_full].mean())
        info = {
            "target_mean": target_mean, "ref_class": ref,
            "ref_mean": ref_mean, "diff": target_mean - ref_mean,
        }
        if op == ">":
            return target_mean > ref_mean, info
        if op == "<":
            return target_mean < ref_mean, info
        if op == ">>":
            return target_mean > 5 * ref_mean, info
        if op == "<<":
            return ref_mean > 5 * target_mean, info
    else:  # comparison with absolute threshold
        info = {"target_mean": target_mean, "threshold": ref}
        if op == ">":
            return target_mean > ref, info
        if op == "<":
            return target_mean < ref, info

    return False, {"error": f"Unknown op: {op}"}


def run_assertions(df: pd.DataFrame, assertions: list, dataset_name: str) -> list:
    """Run all assertions, return list of result dicts."""
    results = []
    for feat, cls, op, ref, severity, rationale in assertions:
        passed, info = evaluate_assertion(df, feat, cls, op, ref)
        result = {
            "dataset": dataset_name,
            "feature": feat,
            "class": cls,
            "op": op,
            "ref": ref,
            "severity": severity,
            "rationale": rationale,
            "passed": bool(passed),
            **info,
        }
        results.append(result)
    return results


def plot_assertion_table(results: list, out_path: Path) -> None:
    """Render assertions as colored table image."""
    rows = []
    for r in results:
        if "error" in r:
            outcome = "ERROR"
        else:
            outcome = "PASS" if r["passed"] else "FAIL"
        op_str = f"{r['op']} {r['ref']}"
        if "ref_mean" in r:
            details = f"target={r['target_mean']:.3f}, ref={r['ref_mean']:.3f}"
        elif "target_mean" in r:
            details = f"target={r['target_mean']:.3f}"
        else:
            details = r.get("error", "—")
        rows.append([r["dataset"], r["feature"], r["class"], op_str,
                     r["severity"], outcome, details, r["rationale"]])

    columns = ["Dataset", "Feature", "Class", "Condition", "Severity",
               "Outcome", "Details", "Rationale"]

    fig, ax = plt.subplots(figsize=(20, 0.4 * len(rows) + 1.5))
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=columns,
                      loc="center", cellLoc="left")
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.7)

    # Set cell width per column proportionally
    col_widths = [0.06, 0.06, 0.10, 0.10, 0.08, 0.07, 0.18, 0.35]
    for i, w in enumerate(col_widths):
        for r_idx in range(len(rows) + 1):
            table[(r_idx, i)].set_width(w)

    # Header
    for j in range(len(columns)):
        table[(0, j)].set_facecolor("#2E2E2E")
        table[(0, j)].set_text_props(color="white", weight="bold")

    # Color code rows by outcome
    for i, r in enumerate(rows, start=1):
        outcome = r[5]
        severity = r[4]
        if outcome == "PASS":
            color = "#C8E6C9"  # green
        elif outcome == "ERROR":
            color = "#FFE0B2"  # orange
        else:
            if severity == "OPTIONAL":
                color = "#FFF9C4"  # yellow (acceptable failure)
            elif severity == "EXPECTED":
                color = "#FFCDD2"  # light red
            else:  # REQUIRED
                color = "#EF9A9A"  # red
        for j in range(len(columns)):
            table[(i, j)].set_facecolor(color)

    pass_count = sum(1 for r in rows if r[5] == "PASS")
    plt.title(
        f"Sanity Assertions — Direct Feature Correctness Validation\n"
        f"Pass: {pass_count}/{len(rows)}  |  "
        f"Each row = 1 design-intent assertion vs actual data\n"
        f"REQUIRED FAIL = CRITICAL  |  EXPECTED FAIL = INVESTIGATE  |  "
        f"OPTIONAL FAIL = data-dependent (acceptable)",
        fontsize=11, pad=15,
    )
    plt.tight_layout()
    plt.savefig(out_path, dpi=110, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {out_path.name}")


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading datasets ...")
    df_2018 = load_20d_labeled(benign_cap=500)
    df_2017 = load_2017_labeled()

    print("\nRunning 2018 assertions ...")
    results_2018 = run_assertions(df_2018, ASSERTIONS_2018, "2018")
    print("Running 2017 assertions ...")
    results_2017 = run_assertions(df_2017, ASSERTIONS_2017, "2017")

    all_results = results_2018 + results_2017

    # Summary
    n_pass = sum(1 for r in all_results if r.get("passed"))
    n_fail = sum(1 for r in all_results if not r.get("passed") and "error" not in r)
    n_err = sum(1 for r in all_results if "error" in r)
    n_required_fail = sum(1 for r in all_results
                          if not r.get("passed") and r.get("severity") == "REQUIRED")
    n_optional_fail = sum(1 for r in all_results
                          if not r.get("passed") and r.get("severity") == "OPTIONAL")

    output = {
        "metadata": {
            "purpose": "Direct feature correctness validation — verify design intent",
            "n_total": len(all_results),
            "n_pass": n_pass,
            "n_fail": n_fail,
            "n_error": n_err,
            "n_required_fail": n_required_fail,
            "n_optional_fail": n_optional_fail,
        },
        "results": all_results,
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved: {OUTPUT_FILE.name}")

    print("\n=== SUMMARY ===")
    print(f"Total assertions: {len(all_results)}")
    print(f"  PASS: {n_pass}")
    print(f"  FAIL: {n_fail} (REQUIRED: {n_required_fail}, OPTIONAL/EXPECTED: {n_fail - n_required_fail})")
    print(f"  ERROR: {n_err}")

    print("\n=== FAILED ASSERTIONS ===")
    for r in all_results:
        if not r.get("passed") and "error" not in r:
            tgt = r.get("target_mean", "?")
            ref = r.get("ref_mean", r.get("threshold", "?"))
            print(f"  [{r['severity']:8s}] {r['dataset']} {r['feature']:5s} "
                  f"{r['class']:14s} {r['op']} {r['ref']}  "
                  f"actual: target={tgt}, ref={ref}")

    plot_assertion_table(all_results, PLOTS_DIR / "25_sanity_pass_fail.png")


if __name__ == "__main__":
    main()
