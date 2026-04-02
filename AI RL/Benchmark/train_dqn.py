"""
DQN Baseline Training Script (Benchmark)

SB3 recommended defaults — no tuning.
Train 300k steps, save to models/dqn_seed{N}.zip

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
from env_ids_harder import IDSDefenseEnv

HARDER_ENV = {'drift_max': 0.35, 'missing_prob': 0.08}

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

    print(f"[*] Training DQN-Default | seed={seed} | {TOTAL_TIMESTEPS} steps")

    # DQN uses single env (off-policy, replay buffer)
    env = IDSDefenseEnv(seed=seed, **HARDER_ENV)
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

    # SB3 DQN defaults — no tuning
    model = DQN(
        "MlpPolicy",
        env,
        learning_rate=1e-4,          # SB3 DQN default
        buffer_size=100_000,          # SB3 default
        learning_starts=1_000,        # SB3 default
        batch_size=32,               # SB3 default
        tau=1.0,                     # SB3 default (hard update)
        gamma=0.99,                  # SB3 default
        train_freq=4,                # SB3 default
        gradient_steps=1,            # SB3 default
        target_update_interval=1_000, # SB3 default
        exploration_fraction=0.1,    # SB3 default
        exploration_initial_eps=1.0, # SB3 default
        exploration_final_eps=0.05,  # SB3 default
        max_grad_norm=10,            # SB3 default
        seed=seed,
        verbose=1,
        tensorboard_log=tb_log_dir,
        policy_kwargs=dict(net_arch=[128, 128]),
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
