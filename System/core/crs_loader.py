"""CRS Rule Loader — Parse file .conf OWASP CRS thành regex Python.

Phân tích chỉ thị SecRule từ file cấu hình ModSecurity CRS và trả về
các đối tượng re.Pattern đã biên dịch để dùng trong feature calculators.

Toán tử hỗ trợ:
  @rx PATTERN   → biên dịch thành re.compile(PATTERN, IGNORECASE)
  @pm phrase... → trả về danh sách chuỗi viết thường

Không hỗ trợ (cần thư viện C libinjection):
  @detectSQLi, @detectXSS → bỏ qua

Cách sử dụng:
    from core.crs_loader import load_rx_patterns, load_pm_phrases

    sqli_patterns = load_rx_patterns(CRS_SQLI_CONF)
    # sqli_patterns = [(rule_id, msg, compiled_pattern), ...]

    xss_patterns  = load_rx_patterns(CRS_XSS_CONF)
"""

import re
import logging
from pathlib import Path
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

# ── Đường dẫn mặc định (file CRS conf nằm ở thư mục gốc repo) ──
_REPO_ROOT   = Path(__file__).parent.parent.parent
CRS_SQLI_CONF = _REPO_ROOT / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
CRS_XSS_CONF  = _REPO_ROOT / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"

# ── Regex trích xuất từ định dạng SecRule ──────────────────────────────────────
_RX_RE  = re.compile(r'"@rx\s+((?:[^"\\]|\\.)*?)"',  re.DOTALL)
_PM_RE  = re.compile(r'"@pm\s+((?:[^"\\]|\\.)*?)"',  re.DOTALL)
_ID_RE  = re.compile(r'\bid:(\d+)')
_MSG_RE = re.compile(r"msg:'([^']*)'")


def load_rx_patterns(
    conf_path: Path = None,
    paranoia_level: int = 1,
) -> List[Tuple[int, str, re.Pattern]]:
    """Phân tích các rule @rx từ file .conf CRS.

    Args:
        conf_path:      Đường dẫn file .conf. Mặc định CRS_SQLI_CONF.
        paranoia_level: Mức paranoia tối đa (1-4).
                        Level 1 = chỉ các rule mặc định/khuyến nghị.

    Returns:
        Danh sách tuple (rule_id, msg_snippet, compiled_pattern).
        Các rule không biên dịch được sẽ bị bỏ qua với cảnh báo.
    """
    if conf_path is None:
        conf_path = CRS_SQLI_CONF

    conf_path = Path(conf_path)
    if not conf_path.exists():
        logger.error(f"Không tìm thấy file CRS conf: {conf_path}")
        return []

    text = conf_path.read_text(encoding='utf-8')

    # Tách thành các khối rule (mỗi SecRule có thể kéo dài nhiều dòng)
    blocks = _split_into_blocks(text)

    results: List[Tuple[int, str, re.Pattern]] = []
    skipped_libinject = 0
    skipped_compile   = 0
    skipped_paranoia  = 0

    current_pl = 1  # theo dõi mức paranoia từ comment section

    for block in blocks:
        # Cập nhật mức paranoia từ comment tiêu đề section
        pl_match = re.search(r'Paranoia Level (\d)', block)
        if pl_match:
            current_pl = int(pl_match.group(1))
            continue

        if current_pl > paranoia_level:
            skipped_paranoia += 1
            continue

        # Bỏ qua rule libinjection
        if '@detectSQLi' in block or '@detectXSS' in block:
            skipped_libinject += 1
            continue

        # Trích xuất pattern @rx
        rx_match = _RX_RE.search(block)
        if not rx_match:
            continue

        raw_pattern = rx_match.group(1)

        # Trích xuất rule ID
        id_match = _ID_RE.search(block)
        rule_id  = int(id_match.group(1)) if id_match else 0

        # Trích xuất mô tả ngắn
        msg_match = _MSG_RE.search(block)
        msg = msg_match.group(1)[:60] if msg_match else f"rule_{rule_id}"

        # Biên dịch pattern
        try:
            compiled = re.compile(raw_pattern, re.IGNORECASE | re.DOTALL)
            results.append((rule_id, msg, compiled))
        except re.error as exc:
            logger.warning(f"CRS rule {rule_id} pattern biên dịch thất bại: {exc}")
            skipped_compile += 1

    logger.info(
        f"CRS loader [{conf_path.name}]: "
        f"{len(results)} patterns đã tải | "
        f"{skipped_libinject} libinjection bỏ qua | "
        f"{skipped_compile} lỗi biên dịch | "
        f"{skipped_paranoia} paranoia>{paranoia_level} bỏ qua"
    )
    return results


def load_pm_phrases(conf_path: Path = None) -> List[str]:
    """Phân tích các rule @pm (phrase match) từ file .conf CRS.

    Args:
        conf_path: Đường dẫn file .conf.

    Returns:
        Danh sách chuỗi viết thường (tách từ tất cả rule @pm).
    """
    if conf_path is None:
        conf_path = CRS_SQLI_CONF

    conf_path = Path(conf_path)
    if not conf_path.exists():
        return []

    text  = conf_path.read_text(encoding='utf-8')
    phrases: List[str] = []

    for pm_match in _PM_RE.finditer(text):
        raw = pm_match.group(1).strip()
        phrases.extend(p.lower() for p in raw.split() if p)

    return phrases


# ── Hàm nội bộ ────────────────────────────────────────────────────────────────

def _split_into_blocks(text: str) -> List[str]:
    """Tách nội dung file CRS conf thành các khối logic.

    Mỗi khối là:
    - Comment tiêu đề section (chứa 'Paranoia Level N')
    - Một SecRule hoàn chỉnh (có thể kéo dài nhiều dòng qua dấu \\)
    """
    blocks: List[str] = []
    current: List[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        # Comment tiêu đề section → flush + tạo khối riêng
        if stripped.startswith('#') and 'Paranoia Level' in stripped:
            if current:
                blocks.append('\n'.join(current))
                current = []
            blocks.append(stripped)
            continue

        # Bỏ qua dòng comment thuần và dòng trống (trừ khi đang trong rule)
        if not current and (stripped.startswith('#') or not stripped):
            continue

        current.append(line)

        # Rule kết thúc khi dòng KHÔNG kết thúc bằng dấu \\
        if current and not stripped.endswith('\\'):
            blocks.append('\n'.join(current))
            current = []

    if current:
        blocks.append('\n'.join(current))

    return blocks


# ── Kiểm tra nhanh ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    print("\n=== SQLI (CRS 942) ===")
    sqli = load_rx_patterns(CRS_SQLI_CONF, paranoia_level=1)
    print(f"Đã tải: {len(sqli)} patterns")
    for rid, msg, _ in sqli[:5]:
        print(f"  [{rid}] {msg}")

    print("\n=== XSS (CRS 941) ===")
    xss = load_rx_patterns(CRS_XSS_CONF, paranoia_level=1)
    print(f"Đã tải: {len(xss)} patterns")
    for rid, msg, _ in xss[:5]:
        print(f"  [{rid}] {msg}")

    print("\n=== XSS @pm phrases ===")
    phrases = load_pm_phrases(CRS_XSS_CONF)
    print(f"Đã tải: {len(phrases)} phrases: {phrases}")
