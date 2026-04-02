"""
PPO Tuned Training Script (Benchmark)

Hyperparameter-optimized variant (thesis config v4).
- All 5 seeds trained from scratch on harder env (drift_max=0.35, missing_prob=0.08)
- 500k timesteps (vs 300k for baselines) — justified by entropy regularization
  (ent_coef=0.02 requires more steps to converge vs default ent_coef=0.0)

Usage:
  python3 train_ppo_tuned.py --seed 42
  for seed in 42 123 456 789 1337; do python3 train_ppo_tuned.py --seed $seed; done
"""

import os
import sys
import argparse
import random
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids_harder import IDSDefenseEnv

# Phase 2 harder env config — same for all algos (fair benchmark)
HARDER_ENV = {'drift_max': 0.35, 'missing_prob': 0.08}

from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

ALGO = "ppo_tuned"
TOTAL_TIMESTEPS = 500_000

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True, help="Random seed")
    return parser.parse_args()

def linear_schedule(initial_lr: float, floor_fraction: float = 0.33):
    """Linear LR decay from initial_lr to initial_lr*floor_fraction."""
    def schedule(progress_remaining: float) -> float:
        return initial_lr * max(progress_remaining, floor_fraction)
    return schedule

def main():
    args = parse_args()
    seed = args.seed

    random.seed(seed)
    np.random.seed(seed)

    models_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(models_dir, exist_ok=True)

    output_path = os.path.join(models_dir, f"{ALGO}_seed{seed}")

    # NOTE: seed42 is retrained from scratch on harder env (drift_max=0.35, missing_prob=0.08)
    # The original run_final_v4/best_model.zip was trained on easy env — NOT reused here.
    if os.path.exists(output_path + ".zip"):
        print(f"[*] {output_path}.zip already exists — skipping")
        return

    print(f"[*] Training PPO-Tuned | seed={seed} | {TOTAL_TIMESTEPS} steps")

    env = make_vec_env(IDSDefenseEnv, n_envs=4, seed=seed, env_kwargs=HARDER_ENV)
    eval_env = Monitor(IDSDefenseEnv(seed=seed, **HARDER_ENV))

    tb_log_dir = os.path.join(os.path.dirname(__file__), "tb", f"{ALGO}_seed{seed}")
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

    # PPO-Tuned hyperparams (thesis v4 config)
    model = PPO(
        "MlpPolicy",
        env,
        learning_rate=linear_schedule(3e-4, floor_fraction=0.1),   # 3e-4 → 3e-5
        n_steps=2048,
        batch_size=64,
        n_epochs=10,
        gamma=0.99,
        gae_lambda=0.95,
        clip_range=0.2,
        clip_range_vf=None,
        ent_coef=0.005,  # Tuned: mild entropy for exploration (SB3 default is 0.0)
        vf_coef=1.0,     # Tuned: double critic gradient (SB3 default is 0.5)
        max_grad_norm=0.5,
        seed=seed,
        verbose=1,
        tensorboard_log=tb_log_dir,
        policy_kwargs=dict(
            net_arch=dict(
                pi=[128, 128],  # Wider actor
                vf=[128, 128],  # Wider critic
            )
        ),
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
