"""
Benchmark CRS-941 (XSS) trên LSNM2024 XSS subset.

Kết quả dùng để điền vào Table CRS XSS trong paper_draft.tex.

Chạy từ thư mục System/:
    python benchmark_crs_xss.py
"""
import csv
import sys
import re
from pathlib import Path

sys.path.insert(0, ".")
from core.crs_loader import CRS_XSS_CONF, load_rx_patterns, load_pm_phrases
from feature.context import PayloadNormalizer

# ── Đường dẫn dataset ────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).parent.parent
DATASET_DIR = _REPO_ROOT / "System/dataset/LSNM2024 Dataset/Dataset-Ready (Use This)"

XSS_FILES = [
    DATASET_DIR / "Malicious/XSS/XSS-1.csv",
    DATASET_DIR / "Malicious/XSS/9.csv",
    DATASET_DIR / "Malicious/XSS/XSS-2.csv",
]
BENIGN_FILE = DATASET_DIR / "Benign/normal_data.csv"

URI_COL = "HTTP Request URI"
N_NORMAL = 3000  # Số URI bình thường dùng để đo FP (khớp với SQLi benchmark)

# ── Trích xuất URI từ CSV ─────────────────────────────────────────────────────

# XSS attack URI indicators — chỉ các pattern thực sự là XSS payload
# KHÔNG dùng %3c/%3e trần vì chúng là probe traffic (bare angle brackets)
_XSS_INDICATORS = [
    "<script", "</script",
    "onerror=", "onload=", "onclick=", "onmouseover=",
    "onpointerenter", "onpointermove", "onfocus=", "onblur=",
    "alert(", "prompt(", "eval(",
    "javascript:",
    "document.cookie", "document.write",
    "&#x3c;script", "&#60;script",  # HTML entity script tag
    # URL-encoded variants chứa full tag/event (không phải bare bracket)
    "%3cscript", "%3c/script",
    "%3csvg", "%3cimg", "%3ciframe",
    "onpointer", "onmouse",
]

def is_xss_uri(uri: str) -> bool:
    """True nếu URI chứa XSS payload thực sự (không phải bare probe)."""
    lower = uri.lower()
    return any(ind in lower for ind in _XSS_INDICATORS)


def extract_uris(csv_path: Path, max_rows: int = None,
                 attack_only: bool = False) -> list[str]:
    """Đọc CSV, trả về URI từ cột HTTP Request URI.

    Args:
        attack_only: nếu True, chỉ trả về URI chứa XSS payload indicator.
    """
    uris = []
    try:
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uri = row.get(URI_COL, "").strip()
                if not uri or uri in ("", "-"):
                    continue
                if attack_only and not is_xss_uri(uri):
                    continue
                uris.append(uri)
                if max_rows and len(uris) >= max_rows:
                    break
    except Exception as e:
        print(f"  [!] Lỗi đọc {csv_path.name}: {e}")
    return uris


# ── Hàm kiểm tra một URI qua CRS-941 ─────────────────────────────────────────

def score_uri(uri: str, rx_patterns, pm_phrases: list[str]) -> int:
    """Trả về số rule CRS-941 khớp với URI (sau normalize). 0 = không phát hiện."""
    normalized = PayloadNormalizer.normalize(uri.encode("utf-8", errors="replace"))
    score = 0
    for _rid, _msg, pattern in rx_patterns:
        if pattern.search(normalized):
            score += 1
    # phrase match
    lower_norm = normalized.lower()
    for phrase in pm_phrases:
        if phrase in lower_norm:
            score += 1
            break  # chỉ tính 1 lần cho pm
    return score


# ── Chạy benchmark cho một mức PL ────────────────────────────────────────────

def run_benchmark(pl: int, xss_uris: list[str], normal_uris: list[str]):
    rx_patterns = load_rx_patterns(CRS_XSS_CONF, paranoia_level=pl)
    pm_phrases  = load_pm_phrases(CRS_XSS_CONF)
    n_rules     = len(rx_patterns)

    # True Positives: XSS được phát hiện
    tp = sum(1 for u in xss_uris if score_uri(u, rx_patterns, pm_phrases) > 0)
    fn = len(xss_uris) - tp

    # False Positives: Normal bị flag nhầm
    fp = sum(1 for u in normal_uris if score_uri(u, rx_patterns, pm_phrases) > 0)
    tn = len(normal_uris) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "pl": pl,
        "rules": n_rules,
        "tp": tp,
        "fp": fp,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 1. Load XSS attack URIs (chỉ lấy URI chứa XSS payload indicator)
    print("Đang tải XSS attack URIs (filter attack_only=True)...")
    xss_uris = []
    for xss_file in XSS_FILES:
        if not xss_file.exists():
            print(f"  [!] Không tìm thấy: {xss_file}")
            continue
        batch = extract_uris(xss_file, attack_only=True)
        print(f"  {xss_file.name}: {len(batch)} attack URI")
        xss_uris.extend(batch)

    if not xss_uris:
        print("Không tìm thấy URI XSS nào. Kiểm tra đường dẫn dataset.")
        sys.exit(1)

    print(f"  Tổng XSS attack URI: {len(xss_uris)}")

    # 2. Load Normal URIs
    print("\nĐang tải Normal URIs...")
    normal_uris = extract_uris(BENIGN_FILE, max_rows=N_NORMAL * 10)
    normal_uris = normal_uris[:N_NORMAL]
    print(f"  Đã lấy {len(normal_uris)} URI bình thường (mục tiêu: {N_NORMAL})")

    # 3. Không cần sample thêm — dùng toàn bộ attack URIs tìm được
    n_xss = len(xss_uris)
    n_normal = len(normal_uris)
    n_total = n_xss + n_normal

    print(f"\nDataset benchmark: n_XSS={n_xss}, n_Normal={n_normal}, n_Total={n_total}")

    # 4. Chạy PL1, PL2, PL3
    print("\nĐang benchmark CRS-941 (XSS) theo từng Paranoia Level...")
    results = []
    for pl in [1, 2, 3]:
        print(f"  PL{pl}...", end="", flush=True)
        r = run_benchmark(pl, xss_uris, normal_uris)
        results.append(r)
        print(f" TP={r['tp']}/{n_xss}, FP={r['fp']}/{n_normal}, "
              f"F1={r['f1']:.3f}, Recall={r['recall']:.3f}, FPR={r['fpr']:.1%}")

    # 5. In kết quả cho paper
    print("\n" + "=" * 65)
    print(f"CRS-941 (XSS) Benchmark — LSNM2024 XSS Subset (n={n_total})")
    print("=" * 65)
    print(f"{'PL':<5} {'Rules':<8} {'TP':<8} {'FP':<8} {'Recall':<10} {'Prec':<10} {'F1':<8} {'FPR':<8}")
    print("-" * 65)
    for r in results:
        print(f"PL{r['pl']:<4} {r['rules']:<8} {r['tp']:<8} {r['fp']:<8} "
              f"{r['recall']:<10.3f} {r['precision']:<10.3f} {r['f1']:<8.3f} {r['fpr']:.1%}")
    print("=" * 65)

    # Gợi ý PL tốt nhất
    best = max(results, key=lambda x: x["f1"])
    print(f"\n→ PL được chọn: PL{best['pl']} "
          f"(F1={best['f1']:.3f}, Recall={best['recall']:.3f}, "
          f"FPR={best['fpr']:.1%})")

    print("\n=== Dữ liệu LaTeX cho paper ===")
    for r in results:
        selected = " & \\textbf{Selected}" if r == best else " &"
        print(f"PL{r['pl']} & {r['rules']} & {r['tp']:,} & {r['fp']:,} "
              f"& {r['f1']:.3f}{selected} \\\\")
