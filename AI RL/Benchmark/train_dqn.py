"""
DQN Baseline Training Script (34D Harder Env)

Train on env_ids_harder.py (34D obs, missing_prob=0.08, drift_max=0.35).
SB3 strict defaults — no hyperparameter tuning, single env (off-policy).
  learning_rate=1e-4, buffer_size=1_000_000, learning_starts=100
  batch_size=32, gamma=0.99, exploration_fraction=0.1
  exploration_final_eps=0.05, train_freq=4, target_update_interval=10_000
  max_grad_norm=10, net_arch=[64,64] (SB3 MlpPolicy default)

Checkpoint policy: final model primary (not best).
n_envs=1 — off-policy algorithm, single env only.

Usage:
  python3 train_dqn.py --seed 42
  for seed in 42 123 456 789 1337; do python3 train_dqn.py --seed $seed; done
"""

import os
import sys
import argparse
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids_harder import IDSDefenseEnv   # 34D harder env

from stable_baselines3 import DQN
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

ALGO = "dqn"
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

    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    output_path = os.path.join(models_dir, f"{ALGO}_seed{seed}")

    print(f"[*] Training DQN (34D harder env) | seed={seed} | {TOTAL_TIMESTEPS} steps")
    print(f"    Env: env_ids_harder.py (34D, missing_prob=0.08, drift_max=0.35)")
    print(f"    Track: sb3_strict_default | n_envs=1 | checkpoint=final_primary")
    print(f"    SB3 defaults: lr=1e-4, buffer=1M, learning_starts=100, net_arch=[64,64]")

    env = IDSDefenseEnv(seed=seed)
    eval_env = Monitor(IDSDefenseEnv(seed=seed))

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

    # SB3 DQN — 100% strict default hyperparameters (no adjustments)
    model = DQN(
        "MlpPolicy",
        env,
        seed=seed,
        verbose=1,
        tensorboard_log=None,
    )

    model.learn(
        total_timesteps=TOTAL_TIMESTEPS,
        callback=eval_callback,
        progress_bar=True,
        reset_num_timesteps=True,
    )

    # Final model is primary — do NOT overwrite with best model
    model.save(output_path)
    print(f"[+] Saved final_model (primary) → {output_path}.zip")

if __name__ == "__main__":
    main()
