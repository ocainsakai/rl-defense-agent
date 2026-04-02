"""
PPO Default Baseline Training Script (Benchmark)

SB3 recommended defaults — no tuning.
Train 300k steps, save to models/ppo_default_seed{N}.zip

Usage:
  python3 train_ppo_default.py --seed 42
  for seed in 42 123 456 789 1337; do python3 train_ppo_default.py --seed $seed; done
"""

import os
import sys
import argparse
import random
import numpy as np

# Add parent dir so we can import IDSDefenseEnv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids_harder import IDSDefenseEnv

# Phase 2 harder env config — same for all algos (fair benchmark)
HARDER_ENV = {'drift_max': 0.35, 'missing_prob': 0.08}

from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback
from stable_baselines3.common.monitor import Monitor

ALGO = "ppo_default"
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

    print(f"[*] Training PPO-Default | seed={seed} | {TOTAL_TIMESTEPS} steps")

    env = make_vec_env(IDSDefenseEnv, n_envs=4, seed=seed, env_kwargs=HARDER_ENV)
    eval_env = Monitor(IDSDefenseEnv(seed=seed, **HARDER_ENV))

    tb_log_dir = os.path.join(os.path.dirname(__file__), "tb", f"{ALGO}_seed{seed}")
    # Save best model (peak eval reward) — consistent with PPO-Tuned seed42 methodology
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

    # SB3 PPO defaults — no tuning
    model = PPO(
        "MlpPolicy",
        env,
        learning_rate=3e-4,       # SB3 default
        n_steps=2048,             # SB3 default
        batch_size=64,            # SB3 default
        n_epochs=10,              # SB3 default
        gamma=0.99,               # SB3 default
        gae_lambda=0.95,          # SB3 default
        clip_range=0.2,           # SB3 default
        ent_coef=0.0,             # SB3 default
        vf_coef=0.5,              # SB3 default
        max_grad_norm=0.5,        # SB3 default
        seed=seed,
        verbose=1,
        tensorboard_log=tb_log_dir,
        policy_kwargs=dict(net_arch=[64, 64]),  # SB3 default arch
    )

    model.learn(
        total_timesteps=TOTAL_TIMESTEPS,
        callback=eval_callback,
        progress_bar=True,
        reset_num_timesteps=True,
    )

    model.save(output_path)
    # Also load and re-save best model as the canonical eval file
    best_zip = os.path.join(best_model_path, "best_model.zip")
    if os.path.exists(best_zip):
        import shutil
        shutil.copy2(best_zip, output_path + ".zip")
        print(f"[+] Saved best_model → {output_path}.zip")
    else:
        print(f"[+] Saved final_model → {output_path}.zip")

if __name__ == "__main__":
    main()
