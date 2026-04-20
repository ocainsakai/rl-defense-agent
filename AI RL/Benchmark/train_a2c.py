"""
A2C Baseline Training Script (34D Harder Env)

Train on env_ids_harder.py (34D obs, missing_prob=0.08, drift_max=0.35).
SB3 strict defaults — no hyperparameter tuning, single env for fair comparison.
  learning_rate=7e-4, n_steps=5, gamma=0.99, gae_lambda=1.0
  ent_coef=0.0, vf_coef=0.5, max_grad_norm=0.5
  net_arch=pi=[64,64] vf=[64,64] (SB3 MlpPolicy default)

Checkpoint policy: final model primary (not best).
n_envs=1 — single env, same as DQN/PPO, for fair comparison.

Usage:
  python3 train_a2c.py --seed 42
  for seed in 42 123 456 789 1337; do python3 train_a2c.py --seed $seed; done
"""

import os
import sys
import argparse
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids_harder import IDSDefenseEnv   # 34D harder env

from stable_baselines3 import A2C
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

ALGO = "a2c"
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

    print(f"[*] Training A2C (34D harder env) | seed={seed} | {TOTAL_TIMESTEPS} steps")
    print(f"    Env: env_ids_harder.py (34D, missing_prob=0.08, drift_max=0.35)")
    print(f"    Track: sb3_strict_default | n_envs=1 | checkpoint=final_primary")
    print(f"    SB3 defaults: lr=7e-4, n_steps=5, gae_lambda=1.0, net_arch=[64,64]")

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

    # SB3 A2C — 100% strict default hyperparameters
    model = A2C(
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
