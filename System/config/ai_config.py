# SHARED CONFIGURATION & NORMALIZATION CONTRACT
# (Dùng chung cho cả Module Extractor và Module AI Training)

import numpy as np

# 1. FEATURE INDICES (Thứ tự bắt buộc trong mảng Vector)
# =============================================================================
IDX_PACKET_RATE      = 0  # Tốc độ gói tin
IDX_SYN_RATIO        = 1  # Tỷ lệ SYN/Total
IDX_DISTINCT_PORTS   = 2  # Số lượng cổng đích khác nhau
IDX_PAYLOAD_LEN      = 3  # Kích thước trung bình payload
IDX_FAIL_RATE        = 4  # Tỷ lệ kết nối lỗi (RST + ICMP + HTTP Error)
IDX_CONTEXT_SCORE    = 5  # Điểm ngữ cảnh (Signature base)

# Tên cột dùng cho Header CSV
FEATURE_NAMES = [
    "f1_rate_norm",
    "f2_syn_norm",
    "f3_port_norm",
    "f4_len_norm",
    "f5_fail_norm",
    "f6_ctx_score"
]

# =============================================================================
# 2. NORMALIZATION THRESHOLDS (Ngưỡng chuẩn hóa)
# Công thức chung: Norm_Value = Raw_Value / MAX_VALUE
# Nếu > 1.0 sẽ bị cắt (clip) về 1.0
# =============================================================================

# Feature 1: Packet Rate
# Sync với maxlen=2000 trong window_packet.py
# Normalized: packets/s / MAX_PACKET_RATE
MAX_PACKET_RATE = 3000.0

# Feature 2: SYN Ratio
# Công thức: SYN / Total_Packets. Giá trị tự nhiên là 0->1.
MAX_SYN_RATIO = 1.0

# Feature 3: Distinct Ports
MAX_DISTINCT_PORTS = 50.0

# Feature 4: Payload Length
# Quy ước: MTU chuẩn của Ethernet là 1500 bytes
MAX_PAYLOAD_LEN = 1500.0

# Feature 5: Fail Rate
# Công thức: Failed / Total. Giá trị tự nhiên là 0->1 (0% -> 100%)
MAX_FAIL_RATE = 1.0

# Feature 6: Context Score
# Điểm số rời rạc quy định cho AI
CONTEXT_SAFE      = -1.0  # Mẫu an toàn (VD: Upload ảnh, Static files)
CONTEXT_NEUTRAL   = 0.0   # Không xác định
CONTEXT_MALICIOUS = 1.0   # Mẫu độc hại (SQLi, XSS, Shell)

# =============================================================================
# 3. HELPER FUNCTIONS (Hàm hỗ trợ tính toán)
# =============================================================================

def clamp(value: float, min_val: float, max_val: float) -> float:
    """Giới hạn giá trị trong khoảng [min, max]"""
    return float(np.clip(value, min_val, max_val))

def normalize(value: float, max_val: float) -> float:
    """Chuẩn hóa về [0, 1] dựa trên ngưỡng Max"""
    if max_val == 0: 
        return 0.0
    norm = value / max_val
    return clamp(norm, 0.0, 1.0)

def normalize_range(value: float, min_val: float, max_val: float) -> float:
    """Chuẩn hóa value từ [min_val, max_val] về [0, 1] (có clamp)."""
    rng = max_val - min_val
    if rng == 0:
        return 0.0
    return clamp((value - min_val) / rng, 0.0, 1.0)

def normalize_context_score(value: float) -> float:
    """Chuẩn hóa Context Score từ [-1, 1] (SAFE/NEUTRAL/MALICIOUS) về [0, 1]."""
    return normalize_range(value, CONTEXT_SAFE, CONTEXT_MALICIOUS)


# =============================================================================
# 4. WAMM CLASSIFIER NORMALIZATION
# =============================================================================

# Feature 15: WAMM Attack Type (0=normal, 1=sqli, 2=xss)
MAX_WAMM_ATTACK_TYPE = 2.0

# Feature 16: WAMM Confidence (already [0, 1])
MAX_WAMM_CONFIDENCE = 1.0