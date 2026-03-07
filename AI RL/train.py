"""
PPO Agent Training Script using Stable-Baselines3

Trains a PPO agent on IDSDefenseEnv with run management and checkpointing.
Saves trained model to 'policy_model.zip'.
Evaluates and logs reward progression.

Usage:
  pip install gymnasium stable-baselines3 numpy
  python train.py
"""

import os
import sys
import argparse
import random
from datetime import datetime
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback, CheckpointCallback
from env_ids import IDSDefenseEnv, run_self_test

# ============================================================================
# CLI ARGUMENT PARSING
# ============================================================================

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Train PPO agent on IDS Defense Environment')

    parser.add_argument('--run_id', type=str, default=None,
                        help='Run ID for organizing logs/models (default: auto-generated timestamp+seed)')
    parser.add_argument('--seed', type=int, default=42,
                        help='Random seed for reproducibility (default: 42)')
    parser.add_argument('--timesteps', type=int, default=300000,
                        help='Total training timesteps (default: 300000)')
    parser.add_argument('--resume_from', type=str, default=None,
                        help='Path to model checkpoint to resume training from (e.g., runs/run_X/checkpoints/model_50000.zip)')
    parser.add_argument('--n_envs', type=int, default=4,
                        help='Number of parallel environments (default: 4)')
    parser.add_argument('--eval_freq', type=int, default=5000,
                        help='Evaluate every N timesteps (default: 5000)')
    parser.add_argument('--checkpoint_freq', type=int, default=10000,
                        help='Save checkpoint every N timesteps (default: 10000)')
    parser.add_argument('--eval_episodes', type=int, default=10,
                        help='Number of episodes for evaluation (default: 10)')
    parser.add_argument('--skip_self_test', action='store_true',
                        help='Skip environment self-test (not recommended)')

    return parser.parse_args()

# ============================================================================
# SEED MANAGEMENT
# ============================================================================

def set_global_seed(seed: int):
    """Set random seed for reproducibility across all libraries."""
    random.seed(seed)
    np.random.seed(seed)
    # Note: Gymnasium/Stable-Baselines3 env seeds are set separately via env creation

# ============================================================================
# MAIN TRAINING
# ============================================================================

def train():
    """Train PPO agent on IDS Defense environment with run management."""

    # Parse arguments
    args = parse_args()

    # Set global seeds FIRST
    set_global_seed(args.seed)

    # Generate run_id if not provided
    if args.run_id is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.run_id = f"run_{timestamp}_seed{args.seed}"

    # Setup directories
    run_dir = os.path.join('runs', args.run_id)
    tb_dir = os.path.join(run_dir, 'tb')
    checkpoint_dir = os.path.join(run_dir, 'checkpoints')
    best_model_path = os.path.join(run_dir, 'best_model')

    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(tb_dir, exist_ok=True)
    os.makedirs(checkpoint_dir, exist_ok=True)

    print("\n" + "="*80)
    print("RL-BASED IDS DEFENSE AGENT - PPO TRAINING")
    print("="*80 + "\n")
    print(f"[*] Run ID: {args.run_id}")
    print(f"[*] Seed: {args.seed}")
    print(f"[*] Total timesteps: {args.timesteps}")
    print(f"[*] Run directory: {run_dir}")
    if args.resume_from:
        print(f"[*] Resuming from: {args.resume_from}")
    print()

    # ========================================================================
    # SELF-TEST: Verify environment bounds before training
    # ========================================================================

    if not args.skip_self_test:
        print("[*] Running environment self-test...")
        test_passed = run_self_test(n_samples=500, verbose=True)

        if not test_passed:
            print("\n" + "="*80)
            print("[CRITICAL ERROR] Environment self-test FAILED!")
            print("Training aborted. Please fix the issues above before training.")
            print("="*80 + "\n")
            sys.exit(1)

        print("[+] Self-test passed! Environment is ready for training.\n")
    else:
        print("[WARNING] Skipping self-test (not recommended)\n")

    # ========================================================================
    # CREATE ENVIRONMENT
    # ========================================================================

    print(f"[*] Creating IDSDefenseEnv with {args.n_envs} parallel environments...")
    print(f"    Seeding: make_vec_env(seed={args.seed}) with per-rank offsets; constructor seed not forced.")
    env = make_vec_env(
        IDSDefenseEnv,
        n_envs=args.n_envs,
        seed=args.seed
        # Note: Do NOT pass env_kwargs={'seed': ...} - SB3 handles per-rank seeding automatically
    )

    print(f"[*] Environment created.")
    print(f"    Observation space: {env.observation_space}")
    print(f"    Action space: {env.action_space}")
    print(f"    Episode length: 120 steps\n")

    # Create evaluation environment (single env, same seed for reproducibility)
    eval_env = IDSDefenseEnv(seed=args.seed)

    # Define evaluation callback
    eval_callback = EvalCallback(
        eval_env,
        best_model_save_path=run_dir,  # Will save as best_model.zip
        log_path=run_dir,
        eval_freq=args.eval_freq,
        n_eval_episodes=args.eval_episodes,
        deterministic=True,
        render=False
    )

    # Define checkpoint callback
    checkpoint_callback = CheckpointCallback(
        save_freq=args.checkpoint_freq,
        save_path=checkpoint_dir,
        name_prefix='model',
        save_replay_buffer=False,
        save_vecnormalize=True
    )

    # ========================================================================
    # CREATE OR LOAD PPO AGENT
    # ========================================================================

    if args.resume_from:
        print(f"[*] Loading model from {args.resume_from}...")
        if not os.path.exists(args.resume_from):
            print(f"[ERROR] Resume path not found: {args.resume_from}")
            sys.exit(1)
        model = PPO.load(
            args.resume_from,
            env=env,
            tensorboard_log=tb_dir
        )
        print(f"[*] Model loaded successfully. Resuming training...\n")
    else:
        print(f"[*] Initializing new PPO agent...")

        # =====================================================================
        # PPO HYPERPARAMETERS (Stable-Baselines3 v1.x defaults, tuned)
        # =====================================================================
        # Reference: Raffin et al. (2021) "Stable-Baselines3: Reliable Distributed
        #            Deep Reinforcement Learning Implementations" + empirical tuning
        #
        # Key parameters for IDS defense (4-action graduated response):
        #   - learning_rate=3e-4: Standard PPO LR (from SB3 docs)
        #   - gamma=0.99: High discount (long-horizon 120-step episodes)
        #   - n_steps=2048: Rollout buffer for gradient estimation
        #   - ent_coef=0.02: Increased from SB3 default (0.01) to encourage
        #                    exploration across Allow/RateLimit/Redirect/Block
        #   - gae_lambda=0.95: Generalized Advantage Estimation parameter
        #   - clip_range=0.2: PPO surrogate clipping (standard value)
        #
        # Reference papers:
        #   - Schulman et al. (2017): PPO algorithm (arxiv.org/abs/1707.06347)
        #   - Raffin et al. (2021): SB3 implementation details

        model = PPO(
            'MlpPolicy',
            env,
            learning_rate=3e-4,
            n_steps=2048,
            batch_size=64,
            n_epochs=10,
            gamma=0.99,
            gae_lambda=0.95,
            clip_range=0.2,
            clip_range_vf=None,
            ent_coef=0.02,  # Increased from 0.01 for graduated response exploration
            vf_coef=0.5,
            max_grad_norm=0.5,
            use_sde=False,
            seed=args.seed,
            verbose=1,
            tensorboard_log=tb_dir
        )
        print(f"[*] PPO agent initialized with policy type: MlpPolicy\n")

    # ========================================================================
    # TRAIN
    # ========================================================================

    print(f"[*] Starting training for {args.timesteps} timesteps...")
    print(f"    (This may take 10-30 minutes depending on your hardware)\n")

    model.learn(
        total_timesteps=args.timesteps,
        callback=[eval_callback, checkpoint_callback],
        log_interval=100,
        progress_bar=True,
        reset_num_timesteps=False if args.resume_from else True
    )

    # ========================================================================
    # SAVE FINAL MODEL
    # ========================================================================

    print(f"\n[*] Training complete!")
    final_model_path = os.path.join(run_dir, 'final_model')
    print(f"[*] Saving final model to {final_model_path}.zip...")
    model.save(final_model_path)
    print(f"[+] Model saved successfully.\n")

    # ========================================================================
    # FINAL EVALUATION
    # ========================================================================

    print(f"[*] Running final evaluation ({args.eval_episodes} episodes)...")
    
    # Statistics containers
    total_reward = 0
    n_eval = 0
    action_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    step_damages = []
    episode_end_damages = []
    
    # Traffic group stats: {group_name: {'total': 0, 'block': 0, 'mitigate': 0}}
    group_stats = {
        'attacker': {'total': 0, 'block': 0, 'mitigate': 0},
        'benign': {'total': 0, 'block': 0, 'mitigate': 0},
        'grayzone': {'total': 0, 'block': 0, 'mitigate': 0}
    }
    
    attacker_types = {"scan", "syn_flood", "brute_force", "sqli_xss", "layer7_stealth", "mimicry_attackers", "app_attacker", "apt_attacker"}
    benign_types = {"benign", "benign_upload", "noisy_normal"}

    for _ in range(args.eval_episodes):
        obs, _ = eval_env.reset()
        done = False
        episode_reward = 0
        last_info = {}

        while not done:
            action, _ = model.predict(obs, deterministic=True)
            action = int(action)
            obs, reward, done, truncated, info = eval_env.step(action)
            
            episode_reward += reward
            last_info = info
            
            # 1. Track Action Counts
            if action in action_counts:
                action_counts[action] += 1
            
            # 2. Track Step Damage
            if 'step_damage' in info:
                step_damages.append(info['step_damage'])
            
            # 3. Track Group Stats by IP Type
            ip_type = info.get('ip_type', 'unknown')
            
            target_group = None
            if ip_type in attacker_types or 'attacker' in ip_type: 
                target_group = 'attacker'
            elif ip_type in benign_types:
                target_group = 'benign'
            elif ip_type == 'gray_zone_users' or 'gray' in ip_type:
                target_group = 'grayzone'
            
            if target_group:
                group_stats[target_group]['total'] += 1
                if action == 3: # Block
                    group_stats[target_group]['block'] += 1
                if action in [1, 2, 3]: # Mitigate (RateLimit, Redirect, Block)
                    group_stats[target_group]['mitigate'] += 1

            done = done or truncated

        # End of episode
        total_reward += episode_reward
        n_eval += 1
        
        # Track Cumulative Damage at end of episode
        if 'cumulative_damage' in last_info:
            episode_end_damages.append(last_info['cumulative_damage'])
        elif 'damage' in last_info:
            episode_end_damages.append(last_info['damage'])

    # --- Compute Metrics ---
    avg_reward = total_reward / n_eval
    
    mean_step_damage = np.mean(step_damages) if step_damages else 0.0
    mean_ep_damage = np.mean(episode_end_damages) if episode_end_damages else 0.0
    
    total_actions = sum(action_counts.values())
    action_rates = {k: (v/total_actions)*100 if total_actions else 0 for k, v in action_counts.items()}
    
    def get_rates(stats):
        total = stats['total']
        if total == 0: return 0.0, 0.0
        return (stats['block']/total)*100, (stats['mitigate']/total)*100

    att_block, att_mit = get_rates(group_stats['attacker'])
    ben_block, ben_mit = get_rates(group_stats['benign'])
    gray_block, gray_mit = get_rates(group_stats['grayzone'])

    print(f"[+] Final Evaluation Results:")
    print("="*50)
    print("EVALUATION RESULTS")
    print("="*50)
    print(f"1. Mean Episode Reward: {avg_reward:.4f}")
    print(f"2. Mean Step Damage: {mean_step_damage:.4f}")
    print(f"3. Mean Episode End Cumulative Damage: {mean_ep_damage:.4f}")
    print(f"4. Action Rates: Allow={action_rates[0]:.1f}% | RateLimit={action_rates[1]:.1f}% | Redirect={action_rates[2]:.1f}% | Block={action_rates[3]:.1f}%")
    print(f"5. Attacker: block_rate={att_block:.1f}% | mitigate_rate={att_mit:.1f}%")
    print(f"6. Benign:   block_rate={ben_block:.1f}% | mitigate_rate={ben_mit:.1f}%")
    print(f"7. Grayzone: mitigate_rate={gray_mit:.1f}%")
    print("="*50)
    print(f"    Total Episodes: {n_eval}\n")

    print("="*80)
    print("TRAINING COMPLETE")
    print("="*80 + "\n")
    print(f"Saved files:")
    print(f"  - Best model: {run_dir}/best_model.zip")
    print(f"  - Final model: {run_dir}/final_model.zip")
    print(f"  - Checkpoints: {checkpoint_dir}/model_*.zip")
    print(f"  - TensorBoard logs: {tb_dir}/")
    print()
    print(f"View training progress:")
    print(f"  tensorboard --logdir {tb_dir}")
    print()

if __name__ == '__main__':
    train()
