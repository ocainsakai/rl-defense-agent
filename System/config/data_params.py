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
