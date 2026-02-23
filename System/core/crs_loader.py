"""CRS Rule Loader — Parse OWASP CRS .conf files into Python regex patterns.

Parses SecRule directives from ModSecurity CRS config files and returns
compiled Python re.Pattern objects usable by feature calculators.

Supported operators:
  @rx PATTERN   → compiled as re.compile(PATTERN, IGNORECASE)
  @pm phrase... → returned as list of lowercase strings

NOT supported (requires libinjection C library):
  @detectSQLi, @detectXSS → skipped silently

Typical usage:
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

# ── Default paths (CRS conf files sit at repo root, one level above System/) ──
_REPO_ROOT   = Path(__file__).parent.parent.parent
CRS_SQLI_CONF = _REPO_ROOT / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
CRS_XSS_CONF  = _REPO_ROOT / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"

# ── Extraction regexes for SecRule format ──────────────────────────────────────
# SecRule VARS "@rx PATTERN" \
#     "id:XXXX,...,msg:'TEXT',...
_RX_RE  = re.compile(r'"@rx\s+((?:[^"\\]|\\.)*?)"',  re.DOTALL)
_PM_RE  = re.compile(r'"@pm\s+((?:[^"\\]|\\.)*?)"',  re.DOTALL)
_ID_RE  = re.compile(r'\bid:(\d+)')
_MSG_RE = re.compile(r"msg:'([^']*)'")


def load_rx_patterns(
    conf_path: Path = None,
    paranoia_level: int = 1,
) -> List[Tuple[int, str, re.Pattern]]:
    """Parse @rx rules from a CRS .conf file.

    Args:
        conf_path:      Path to .conf file. Defaults to CRS_SQLI_CONF.
        paranoia_level: Maximum paranoia level to include (1-4).
                        Level 1 = default/recommended rules only.

    Returns:
        List of (rule_id, msg_snippet, compiled_pattern) tuples.
        Rules that fail to compile as Python regex are skipped with a warning.
    """
    if conf_path is None:
        conf_path = CRS_SQLI_CONF

    conf_path = Path(conf_path)
    if not conf_path.exists():
        logger.error(f"CRS conf not found: {conf_path}")
        return []

    text = conf_path.read_text(encoding='utf-8')

    # Split into per-rule blocks (each SecRule block ends before next SecRule or EOF)
    # We process line by line: collect consecutive lines per rule block
    blocks = _split_into_blocks(text)

    results: List[Tuple[int, str, re.Pattern]] = []
    skipped_libinject = 0
    skipped_compile   = 0
    skipped_paranoia  = 0

    current_pl = 1  # track paranoia level from section comments

    for block in blocks:
        # Update paranoia level from section header comments
        pl_match = re.search(r'Paranoia Level (\d)', block)
        if pl_match:
            current_pl = int(pl_match.group(1))
            continue

        if current_pl > paranoia_level:
            skipped_paranoia += 1
            continue

        # Skip libinjection rules
        if '@detectSQLi' in block or '@detectXSS' in block:
            skipped_libinject += 1
            continue

        # Extract @rx pattern
        rx_match = _RX_RE.search(block)
        if not rx_match:
            continue

        raw_pattern = rx_match.group(1)

        # Extract rule ID
        id_match = _ID_RE.search(block)
        rule_id  = int(id_match.group(1)) if id_match else 0

        # Extract short message
        msg_match = _MSG_RE.search(block)
        msg = msg_match.group(1)[:60] if msg_match else f"rule_{rule_id}"

        # Compile pattern
        try:
            compiled = re.compile(raw_pattern, re.IGNORECASE | re.DOTALL)
            results.append((rule_id, msg, compiled))
        except re.error as exc:
            logger.warning(f"CRS rule {rule_id} pattern failed to compile: {exc}")
            skipped_compile += 1

    logger.info(
        f"CRS loader [{conf_path.name}]: "
        f"{len(results)} patterns loaded | "
        f"{skipped_libinject} libinjection skipped | "
        f"{skipped_compile} compile errors | "
        f"{skipped_paranoia} paranoia>{paranoia_level} skipped"
    )
    return results


def load_pm_phrases(conf_path: Path = None) -> List[str]:
    """Parse @pm (phrase match) rules from a CRS .conf file.

    Args:
        conf_path: Path to .conf file.

    Returns:
        Flat list of lowercase phrases (space-separated from all @pm rules).
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


# ── Internal helper ────────────────────────────────────────────────────────────

def _split_into_blocks(text: str) -> List[str]:
    """Split CRS conf text into logical blocks.

    Each block is either:
    - A section-header comment line (containing 'Paranoia Level N')
    - A complete SecRule (which may span multiple lines via backslash continuation)
    """
    blocks: List[str] = []
    current: List[str] = []

    for line in text.splitlines():
        stripped = line.strip()

        # Section header comment → flush + emit as its own block
        if stripped.startswith('#') and 'Paranoia Level' in stripped:
            if current:
                blocks.append('\n'.join(current))
                current = []
            blocks.append(stripped)
            continue

        # Skip pure comment lines and blank lines (but NOT within a rule)
        if not current and (stripped.startswith('#') or not stripped):
            continue

        current.append(line)

        # Rule ends when a line does NOT end with backslash continuation
        if current and not stripped.endswith('\\'):
            blocks.append('\n'.join(current))
            current = []

    if current:
        blocks.append('\n'.join(current))

    return blocks


# ── Quick self-test ────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    print("\n=== SQLI (CRS 942) ===")
    sqli = load_rx_patterns(CRS_SQLI_CONF, paranoia_level=1)
    print(f"Loaded: {len(sqli)} patterns")
    for rid, msg, _ in sqli[:5]:
        print(f"  [{rid}] {msg}")

    print("\n=== XSS (CRS 941) ===")
    xss = load_rx_patterns(CRS_XSS_CONF, paranoia_level=1)
    print(f"Loaded: {len(xss)} patterns")
    for rid, msg, _ in xss[:5]:
        print(f"  [{rid}] {msg}")

    print("\n=== XSS @pm phrases ===")
    phrases = load_pm_phrases(CRS_XSS_CONF)
    print(f"Loaded: {len(phrases)} phrases: {phrases}")
