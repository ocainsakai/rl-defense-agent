"""
generate_eval_data.py
Sinh evaluation dataset từ RL Env (env_ids.py).

- Chạy nhiều episodes trong IDSDefenseEnv
- Ghi obs (20D), ip_type, expected_action ra JSONL
- Cả RL và ML đều dùng cùng file này → so sánh CÔNG BẰNG

Usage:
    cd /home/tringuyen/AIAGENT/rl-defense-agent
    python ml_baseline/generate_eval_data.py
    python ml_baseline/generate_eval_data.py --episodes 50 --out ml_baseline/data/eval_data.jsonl
"""

import sys
import os
import json
import argparse
import numpy as np

# Thêm path để import RL env
RL_DIR = os.path.join(os.path.dirname(__file__), '..', 'AI RL')
sys.path.insert(0, RL_DIR)
SYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'System')
sys.path.insert(0, SYS_DIR)

from env_ids import IDSDefenseEnv

# -------------------------------------------------------
# Label mapping — từ ip_type của env → 3 class cho ML
# -------------------------------------------------------
IP_TYPE_TO_3CLASS = {
    'normal'       : 'benign',
    'benign'       : 'benign',
    'benign_upload': 'benign',
    'noisy_normal' : 'suspicious',
    'scan'         : 'attack',
    'syn_flood'    : 'attack',
    'brute_force'  : 'suspicious',
    'sqli_xss'     : 'suspicious',
}

# ip_type → expected RL action (dùng để đánh giá cả hai hệ thống)
IP_TYPE_TO_ACTION = {
    'normal'       : 'Allow',
    'benign'       : 'Allow',
    'benign_upload': 'Allow',
    'noisy_normal' : 'RateLimit',
    'scan'         : 'Block',
    'syn_flood'    : 'Block',
    'brute_force'  : 'Redirect',
    'sqli_xss'     : 'Redirect',
}


def run_episodes(env: IDSDefenseEnv, n_episodes: int,
                 steps_per_episode: int, seed: int,
                 rl_model=None) -> list:
    """
    Sinh eval data SẠCH: dùng env._get_obs_and_info() trực tiếp.

    Tại sao không dùng env.step()?
    - step() áp dụng closed-loop effect → làm thay đổi features của IP
    - Sau khi RL block IP, obs của IP đó về gần 0 → cả RL lẫn RF không nhận ra
    - Cần obs "chưa bị can thiệp" để đánh giá quyết định SINGLE-STEP

    Cách hoạt động:
    - Reset env với seed khác nhau → behavior objects được khởi tạo lại với RNG mới
    - Duyệt từng ip_idx → _get_obs_and_info() → lấy obs sạch cho ip_type đó
    - Không gọi step() → không có closed-loop contamination
    """
    records = []
    n_ips = len(env.ip_list)
    rng = np.random.default_rng(seed)

    for ep in range(n_episodes):
        # Reset → khởi tạo MockIPBehavior với seed mới → obs đa dạng
        env.reset(seed=seed + ep)

        for ip_idx in range(n_ips):
            env.current_ip_idx = ip_idx
            # Tạm thời set step để tránh drift (chỉ lấy phase baseline)
            env.current_step = 0

            obs, info = env._get_obs_and_info()
            ip_type = info['ip_type']
            label_3class  = IP_TYPE_TO_3CLASS.get(ip_type, 'benign')
            expected_action = IP_TYPE_TO_ACTION.get(ip_type, 'Allow')

            # Thêm Gaussian noise để simulate real-world variability
            # σ=0.06: đủ để tạo overlap giữa các class, không làm mất tín hiệu
            noise = rng.normal(0, 0.06, size=len(obs))
            obs_noisy = np.clip(obs + noise, 0.0, 1.0)

            records.append({
                'episode'        : ep,
                'ip_idx'         : ip_idx,
                'obs'            : obs_noisy.tolist(),
                'ip_type'        : ip_type,
                'label_3class'   : label_3class,
                'expected_action': expected_action,
            })

        if (ep + 1) % 100 == 0:
            print(f"  {ep+1}/{n_episodes} episodes done ({len(records)} records)")

    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--episodes',   type=int, default=30,
                        help='Số episodes cần sinh')
    parser.add_argument('--steps',      type=int, default=200,
                        help='Steps mỗi episode')
    parser.add_argument('--seed',       type=int, default=42)
    parser.add_argument('--out',        default='ml_baseline/data/eval_data.jsonl')
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    print(f"[*] Khởi tạo IDSDefenseEnv...")
    env = IDSDefenseEnv()

    # Load RL model nếu có
    rl_model = None
    rl_model_path = os.path.join(os.path.dirname(__file__), '..', 'AI RL', 'policy_model')
    try:
        from stable_baselines3 import PPO
        if os.path.exists(rl_model_path + '.zip') or os.path.exists(rl_model_path):
            rl_model = PPO.load(rl_model_path)
            print(f"[*] Dùng RL policy để sinh data (cleaner obs)")
        else:
            print(f"[*] Không tìm thấy RL model → dùng oracle action (expected action theo ip_type)")
    except ImportError:
        print(f"[*] stable_baselines3 không có → dùng oracle action")

    print(f"[*] Sinh {args.episodes} episodes × {args.steps} steps = "
          f"{args.episodes * args.steps:,} samples max")
    print(f"    seed={args.seed}, output={args.out}")

    records = run_episodes(env, args.episodes, args.steps, args.seed, rl_model=rl_model)
    env.close()

    # Thống kê
    from collections import Counter
    label_dist = Counter(r['label_3class'] for r in records)
    action_dist = Counter(r['expected_action'] for r in records)
    print(f"\n[*] Tổng: {len(records):,} records")
    print(f"    Label dist   : {dict(label_dist)}")
    print(f"    Action dist  : {dict(action_dist)}")
    print(f"    Obs dim      : {len(records[0]['obs'])}D")

    # Ghi JSONL
    with open(args.out, 'w') as f:
        for rec in records:
            f.write(json.dumps(rec) + '\n')

    print(f"\n[OK] Saved: {args.out}")
    print(f"\nBước tiếp theo:")
    print(f"  python ml_baseline/train_model.py --data {args.out}")


if __name__ == '__main__':
    main()
