"""
experiment_config.py
Cấu hình thực nghiệm — đảm bảo RL và ML chạy trong cùng điều kiện.
"""

import numpy as np
import random

# -------------------------------------------------------
# GLOBAL CONFIG
# -------------------------------------------------------
RANDOM_SEED  = 42
N_SAMPLES    = 10_000   # số lượng traffic samples cho benchmark
TEST_RATIO   = 0.2
CONF_THRESHOLD = 0.75   # ngưỡng confident cho mapping suspicious → rate-limit

# -------------------------------------------------------
# SCENARIOS
# -------------------------------------------------------
SCENARIOS = {
    1: {
        'name'        : 'Fixed Attack Pattern',
        'description' : 'Attack type cố định (DDoS) — test detection cơ bản',
        'attack_types': ['DDoS'],
        'data_filter' : lambda df: df[df['Label'].str.upper().isin(['BENIGN', 'DDOS'])],
    },
    2: {
        'name'        : 'Adaptive Attack',
        'description' : 'Attack type thay đổi theo thời gian — test adaptability',
        'attack_types': ['DDoS', 'PortScan', 'Web Attack'],
        'data_filter' : None,   # dùng toàn bộ dataset
    },
}

# -------------------------------------------------------
# FAIRNESS CONSTRAINTS
# -------------------------------------------------------
FAIRNESS_RULES = """
Đảm bảo công bằng khi so sánh RL vs ML:
1. Cùng file test CSV (không re-shuffle khác nhau)
2. Cùng feature columns
3. Cùng N_SAMPLES và RANDOM_SEED
4. Ghi response time thực tế (không bỏ qua)
5. Cùng label mapping (benign/suspicious/attack)
"""

# -------------------------------------------------------
def set_global_seed():
    """Gọi hàm này ở đầu mỗi script benchmark."""
    np.random.seed(RANDOM_SEED)
    random.seed(RANDOM_SEED)
    print(f"[Config] Global seed set to {RANDOM_SEED}")


def print_config():
    print("\n" + "=" * 45)
    print("  EXPERIMENT CONFIGURATION")
    print("=" * 45)
    print(f"  Random seed   : {RANDOM_SEED}")
    print(f"  N samples     : {N_SAMPLES:,}")
    print(f"  Test ratio    : {TEST_RATIO}")
    print(f"  Conf threshold: {CONF_THRESHOLD}")
    print(f"  Scenarios     : {list(SCENARIOS.keys())}")
    print("=" * 45 + "\n")
