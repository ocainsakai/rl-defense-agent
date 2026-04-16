"""
A2C Baseline Training Script — v2 (30D Temporal Observation)

Train on standard env (env_ids.py, 30D obs) for fair comparison with PPO-Tuned v2.
SB3 recommended defaults — no tuning (same hyperparams as train_a2c.py).

Usage:
  python3 train_a2c_v2.py --seed 42
  for seed in 42 123 456 789 1337; do python3 train_a2c_v2.py --seed $seed; done
"""

import os
import sys
import argparse
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids import IDSDefenseEnv   # v2: standard 30D env (not harder)

from stable_baselines3 import A2C
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

ALGO = "a2c_v2"
TOTAL_TIMESTEPS = 500_000

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True, help="Random seed")
    return parser.parse_args()

def main():
    args = parse_args()
    seed = args.seed

    random.seed(seed)
    np.random.seed(seed)

    models_dir = os.path.join(os.path.dirname(__file__), "models_v2")
    os.makedirs(models_dir, exist_ok=True)

    output_path = os.path.join(models_dir, f"{ALGO}_seed{seed}")

    print(f"[*] Training A2C-v2 (30D) | seed={seed} | {TOTAL_TIMESTEPS} steps")
    print(f"    Env: env_ids.py (standard, 30D temporal obs)")

    env = make_vec_env(IDSDefenseEnv, n_envs=4, seed=seed)
    eval_env = Monitor(IDSDefenseEnv(seed=seed))

    tb_log_dir = os.path.join(os.path.dirname(__file__), "tb_v2", f"{ALGO}_seed{seed}")
    best_model_path = os.path.join(models_dir, f"{ALGO}_seed{seed}_best")
    eval_callback = EvalCallback(
        eval_env,
        best_model_save_path=best_model_path,
        log_path=None,
        eval_freq=10_000,
        n_eval_episodes=5,
        deterministic=True,
        render=False,
        verbose=0,
    )

    # SB3 A2C defaults — no tuning, wider first layer for 30D input
    model = A2C(
        "MlpPolicy",
        env,
        learning_rate=7e-4,       # SB3 A2C default
        n_steps=5,                # SB3 A2C default
        gamma=0.99,               # SB3 default
        gae_lambda=1.0,           # SB3 A2C default (no GAE)
        ent_coef=0.0,             # SB3 default
        vf_coef=0.5,              # SB3 default
        max_grad_norm=0.5,        # SB3 default
        seed=seed,
        verbose=1,
        tensorboard_log=tb_log_dir,
        policy_kwargs=dict(net_arch=dict(pi=[256, 128], vf=[256, 128])),  # wider for 30D
    )

    model.learn(
        total_timesteps=TOTAL_TIMESTEPS,
        callback=eval_callback,
        progress_bar=True,
        reset_num_timesteps=True,
    )

    model.save(output_path)
    best_zip = os.path.join(best_model_path, "best_model.zip")
    if os.path.exists(best_zip):
        import shutil
        shutil.copy2(best_zip, output_path + ".zip")
        print(f"[+] Saved best_model → {output_path}.zip")
    else:
        print(f"[+] Saved final_model → {output_path}.zip")

if __name__ == "__main__":
    main()
