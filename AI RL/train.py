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
from collections import defaultdict
from datetime import datetime
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import BaseCallback, EvalCallback, CheckpointCallback
from stable_baselines3.common.monitor import Monitor
from env_ids import IDSDefenseEnv, run_self_test, simulate_effect

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
    parser.add_argument('--timesteps', type=int, default=500000,
                        help='Total training timesteps (default: 500000, increased for 30D temporal obs)')
    parser.add_argument('--resume_from', type=str, default=None,
                        help='Path to model checkpoint to resume training from (e.g., runs/run_X/checkpoints/model_50000.zip)')
    parser.add_argument('--n_envs', type=int, default=4,
                        help='Number of parallel environments (default: 4)')
    parser.add_argument('--eval_freq', type=int, default=5000,
                        help='Evaluate every N timesteps (default: 5000)')
    parser.add_argument('--checkpoint_freq', type=int, default=10000,
                        help='Save checkpoint every N timesteps (default: 10000)')
    parser.add_argument('--eval_episodes', type=int, default=100,
                        help='Number of episodes for evaluation (default: 100)')
    parser.add_argument('--skip_self_test', action='store_true',
                        help='Skip environment self-test (not recommended)')
    parser.add_argument('--mode', type=str, default='mock', choices=['mock', 'replay'],
                        help='Training mode: mock (simulation) or replay (real NIDS data). Default: mock')
    parser.add_argument('--training_data', type=str, default=None,
                        help='Path to training_data.jsonl (required when --mode replay)')
    parser.add_argument('--session_block_size', type=int, default=0,
                        help='Session-block scheduling: keep same IP for N consecutive steps before '
                             'advancing. 0=round-robin (default). Recommended: 20 (= episode_length/n_ips).')
    parser.add_argument('--target_kl', type=float, default=None,
                        help='Target KL divergence for early stopping per update (e.g. 0.015). '
                             'Prevents large policy shifts during fine-tuning. Default: None (disabled).')
    return parser.parse_args()

# ============================================================================
# SEED MANAGEMENT
# ============================================================================

def set_global_seed(seed: int):
    """Set random seed for reproducibility across all libraries."""
    random.seed(seed)
    np.random.seed(seed)
    # Note: Gymnasium/Stable-Baselines3 env seeds are set separately via env creation


def evaluate_persistent_honeypot_acceptance(seed: int = 42) -> dict:
    """Check the intended reward ordering for redirect-group traffic.

    Expectation:
      - before block_ready (early session, window ~5): Redirect reward > Block reward
      - once block_ready_latched = True:               Block reward > Redirect reward
    """
    targets = ['brute_force', 'brute_force_ka', 'sqli', 'xss']
    results = {}

    for target in targets:
        env = IDSDefenseEnv(seed=seed, mode='mock')
        env.reset()
        target_ip = next(ip for ip, ip_type in zip(env.ip_list, env.ip_types) if ip_type == target)

        def _advance_to_target():
            while env.ip_list[env.current_ip_idx] != target_ip:
                env.step(0)

        _advance_to_target()
        early_redirect = early_block = 0.0
        late_redirect = late_block = 0.0

        ts = env.ip_temporal_state.get(target_ip)
        max_steps = 80  # safety cap to avoid infinite loop
        for step_i in range(max_steps):
            if ts is None:
                ts = env.ip_temporal_state.get(target_ip)

            # Capture early reward at window_len == 5 (session just started)
            if (ts is not None and ts.window_len == 5
                    and early_redirect == 0.0):
                raw_mid = env.ip_behaviors[target_ip].get_features()
                effect_mid = env.ip_effect_state[target_ip]
                early_redirect = env._compute_reward(
                    2, raw_mid, target_ip,
                    effect_prev=effect_mid,
                    effect_after=simulate_effect(2, raw_mid, env.rng),
                )
                early_block = env._compute_reward(
                    3, raw_mid, target_ip,
                    effect_prev=effect_mid,
                    effect_after=simulate_effect(3, raw_mid, env.rng),
                )

            env.step(2)
            _advance_to_target()
            ts = env.ip_temporal_state.get(target_ip)

            # Capture late reward once block_ready_latched fires
            if ts is not None and ts.block_ready_latched and late_redirect == 0.0:
                raw_late = env.ip_behaviors[target_ip].get_features()
                effect_late = env.ip_effect_state[target_ip]
                late_redirect = env._compute_reward(
                    2, raw_late, target_ip,
                    effect_prev=effect_late,
                    effect_after=simulate_effect(2, raw_late, env.rng),
                )
                late_block = env._compute_reward(
                    3, raw_late, target_ip,
                    effect_prev=effect_late,
                    effect_after=simulate_effect(3, raw_late, env.rng),
                )
                break

        results[target] = {
            'early_redirect': float(early_redirect),
            'early_block': float(early_block),
            'late_redirect': float(late_redirect),
            'late_block': float(late_block),
            'redirect_wins_early': bool(early_redirect > early_block),
            'block_wins_late': bool(late_block > late_redirect),
        }

    return results

# ============================================================================
# PERSISTENT EVAL CALLBACK
# ============================================================================

class PersistentEvalCallback(BaseCallback):
    """Custom evaluation callback that monitors Redirect→Block escalation quality.

    Runs every eval_freq steps on a held-out eval env, tracking:
      - escalation_rate: fraction of L7-type IPs that escalate Redirect→Block
      - premature_block_rate: fraction of L7-type IPs blocked without block_ready_latched
      - benign_false_block_rate: fraction of benign/noisy steps where Block is chosen

    Escalation semantics: soft-session based (block_ready_latched from env temporal state).
    A Block is "on-time" when block_ready_latched was True at the moment Block was chosen.
    A Block is "premature" when block_ready_latched was False at the moment Block was chosen.

    Logs all metrics to TensorBoard under 'persistent/' prefix.
    Saves best_model_persistent.zip when escalation quality improves AND
    premature_block and benign_false_block are below their thresholds.
    """

    L7_TYPES  = frozenset({'brute_force', 'brute_force_ka', 'sqli', 'xss'})
    SAFE_TYPES = frozenset({'benign', 'noisy_normal'})

    def __init__(
        self,
        eval_env,
        eval_freq: int = 5000,
        n_eval_episodes: int = 20,
        save_path: str = '.',
        premature_block_threshold: float = 0.20,
        benign_false_block_threshold: float = 0.10,
        verbose: int = 0,
    ):
        super().__init__(verbose)
        self.eval_env = eval_env
        self.eval_freq = eval_freq
        self.n_eval_episodes = n_eval_episodes
        self.save_path = save_path
        self.premature_block_threshold = premature_block_threshold
        self.benign_false_block_threshold = benign_false_block_threshold
        self.best_escalation_rate = -1.0
        self._last_eval_timestep = 0

    def _on_step(self) -> bool:
        if (self.num_timesteps - self._last_eval_timestep) < self.eval_freq:
            return True
        self._last_eval_timestep = self.num_timesteps

        l7_escalated   = 0
        l7_total        = 0
        premature_count = 0
        benign_block    = 0
        benign_total    = 0
        per_type_esc    = {t: 0 for t in self.L7_TYPES}
        per_type_tot    = {t: 0 for t in self.L7_TYPES}

        for _ in range(self.n_eval_episodes):
            obs, _ = self.eval_env.reset()
            done   = False
            # {acted_ip: {'type': str, 'escalated': bool, 'premature': bool, 'done': bool}}
            ep_ip_status: dict = {}

            while not done:
                # Capture block_ready_latched BEFORE step — temporal state resets after Block
                cur_ip = self.eval_env.ip_list[self.eval_env.current_ip_idx]
                ts = self.eval_env.ip_temporal_state.get(cur_ip)
                block_ready_before = ts.block_ready_latched if ts is not None else False

                action, _ = self.model.predict(obs, deterministic=True)
                action = int(action)
                obs, _, done, truncated, info = self.eval_env.step(action)
                done = done or truncated

                ip_type  = info.get('acted_ip_type', info.get('ip_type', 'unknown'))
                acted_ip = info.get('acted_ip', '')

                if ip_type in self.SAFE_TYPES:
                    benign_total += 1
                    if action == 3:
                        benign_block += 1

                if ip_type in self.L7_TYPES:
                    if acted_ip not in ep_ip_status:
                        ep_ip_status[acted_ip] = {
                            'type': ip_type,
                            'escalated': False,
                            'premature': False,
                            'done': False,
                        }
                    s = ep_ip_status[acted_ip]
                    # Only count the first Block per IP per episode
                    if not s['done'] and action == 3:
                        if block_ready_before:
                            s['escalated'] = True
                        else:
                            s['premature'] = True
                        s['done'] = True

            # Per-IP post-episode tally
            for ip_data in ep_ip_status.values():
                ip_type = ip_data['type']
                l7_total += 1
                per_type_tot[ip_type] += 1
                if ip_data['escalated']:
                    l7_escalated += 1
                    per_type_esc[ip_type] += 1
                if ip_data['premature']:
                    premature_count += 1

        # Compute rates
        esc_rate      = l7_escalated    / l7_total      if l7_total      > 0 else 0.0
        premature_rate = premature_count / l7_total      if l7_total      > 0 else 0.0
        benign_fp_rate = benign_block    / benign_total  if benign_total  > 0 else 0.0

        # Log to TensorBoard
        self.logger.record("persistent/escalation_rate_mean",  esc_rate)
        self.logger.record("persistent/premature_block_rate",  premature_rate)
        self.logger.record("persistent/benign_false_block_rate", benign_fp_rate)
        for t in self.L7_TYPES:
            rate = per_type_esc[t] / per_type_tot[t] if per_type_tot[t] > 0 else 0.0
            self.logger.record(f"persistent/esc_{t}", rate)

        if self.verbose >= 1:
            print(
                f"[PersistentEval @{self.num_timesteps}] "
                f"esc={esc_rate:.3f}  premature={premature_rate:.3f}  "
                f"benign_fp={benign_fp_rate:.3f}"
            )

        # Save best_model_persistent.zip if quality improved and thresholds met
        if (
            esc_rate > self.best_escalation_rate
            and premature_rate  < self.premature_block_threshold
            and benign_fp_rate < self.benign_false_block_threshold
        ):
            self.best_escalation_rate = esc_rate
            path = os.path.join(self.save_path, 'best_model_persistent')
            self.model.save(path)
            if self.verbose >= 1:
                print(
                    f"[PersistentEval] New best → esc={esc_rate:.3f}  "
                    f"premature={premature_rate:.3f}  benign_fp={benign_fp_rate:.3f}  "
                    f"→ saved {path}.zip"
                )
        return True


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
    print(f"[*] Mode: {args.mode}")
    if args.resume_from:
        print(f"[*] Resuming from: {args.resume_from}")
    if args.mode == 'replay':
        if not args.training_data:
            print("[ERROR] --mode replay requires --training_data <path>")
            sys.exit(1)
        if not os.path.exists(args.training_data):
            print(f"[ERROR] training_data not found: {args.training_data}")
            sys.exit(1)
        print(f"[*] Training data: {args.training_data}")
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

    print(f"[*] Creating IDSDefenseEnv ({args.mode} mode) with {args.n_envs} parallel environments...")
    env_kwargs = {}
    if args.mode == 'replay':
        env_kwargs = {'mode': 'replay', 'training_data': args.training_data}
    if args.session_block_size > 0:
        env_kwargs['session_block_size'] = args.session_block_size

    env = make_vec_env(
        IDSDefenseEnv,
        n_envs=args.n_envs,
        seed=args.seed,
        env_kwargs=env_kwargs if env_kwargs else None
    )

    print(f"[*] Environment created.")
    print(f"    Observation space: {env.observation_space}")
    print(f"    Action space: {env.action_space}")
    from env_ids import IDSDefenseEnv as _E; _ep = _E().episode_length; del _E
    print(f"    Episode length: {_ep} steps")
    if args.session_block_size > 0:
        print(f"    Session-block size: {args.session_block_size} steps/IP")
    print()

    # Create evaluation environment — wrapped with Monitor so EvalCallback
    # measures episode reward correctly (no UserWarning, accurate best_model saving)
    eval_env = Monitor(IDSDefenseEnv(seed=args.seed, **env_kwargs))

    # Separate env for PersistentEvalCallback (unmonitored — we compute our own metrics)
    persistent_eval_env = IDSDefenseEnv(seed=args.seed + 1, **env_kwargs)

    # Define evaluation callback
    # n_eval_episodes=10 during training (fast checkpoint evals every eval_freq steps)
    # The full 100-episode eval runs at the end via args.eval_episodes
    eval_callback = EvalCallback(
        eval_env,
        best_model_save_path=run_dir,  # Will save as best_model.zip
        log_path=run_dir,
        eval_freq=args.eval_freq,
        n_eval_episodes=10,
        deterministic=True,
        render=False
    )

    # PersistentEvalCallback: monitors Redirect→Block escalation quality
    # Runs every eval_freq steps; saves best_model_persistent.zip when escalation is best.
    persistent_eval_callback = PersistentEvalCallback(
        eval_env=persistent_eval_env,
        eval_freq=args.eval_freq,
        n_eval_episodes=50,   # was 20 — more episodes → less noisy escalation estimate
        save_path=run_dir,
        premature_block_threshold=0.20,
        benign_false_block_threshold=0.10,
        verbose=1,
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
        custom_objs = {}
        if args.target_kl is not None:
            custom_objs["target_kl"] = args.target_kl
        model = PPO.load(
            args.resume_from,
            env=env,
            tensorboard_log=tb_dir,
            custom_objects=custom_objs if custom_objs else None,
        )
        if args.target_kl is not None:
            print(f"[*] target_kl overridden → {args.target_kl}")
        print(f"[*] Model loaded successfully. Resuming training...\n")
    else:
        print(f"[*] Initializing new PPO agent...")

        # =====================================================================
        # PPO HYPERPARAMETERS (Stable-Baselines3, tuned for thesis demo)
        # =====================================================================
        # Reference: Raffin et al. (2021) "Stable-Baselines3: Reliable Distributed
        #            Deep Reinforcement Learning Implementations" + empirical tuning
        #
        # Key parameters for IDS defense (4-action graduated response):
        #   - learning_rate=3e-4: Standard PPO LR (from SB3 docs)
        #   - gamma=0.99: High discount (long-horizon 120-step episodes)
        #   - n_steps=2048: Rollout buffer for gradient estimation
        #   - ent_coef=0.01: SB3 default — 5-type scope is clear, less exploration needed
        #   - gae_lambda=0.95: Generalized Advantage Estimation parameter
        #   - clip_range=0.2: PPO surrogate clipping (standard value)
        #   - net_arch=[128,128]: Wider network → better critic (higher explained_variance)
        #                         → cleaner TensorBoard curves for thesis report
        #
        # Reference papers:
        #   - Schulman et al. (2017): PPO algorithm (arxiv.org/abs/1707.06347)
        #   - Raffin et al. (2021): SB3 implementation details

        # =====================================================================
        # PPO HYPERPARAMETERS v6 — Anti-collapse tuning
        # =====================================================================
        # v5 context: gamma=0.995, gae_lambda=0.97, batch=128, LR floor=1.5e-4
        #
        # v6 addresses premature-Block local optimum collapse:
        #   Root cause: without env-side premature_block_penalty, agent learned
        #   "Block early = avoids miss penalty" (both ≈ -0.15). PPO's large updates
        #   (n_epochs=10, clip=0.2) caused one-shot overshoot into this local optimum.
        #   Env fix: added -0.20 premature_block_penalty in env_ids.py.
        #   PPO fix: reduce update aggressiveness to prevent overshoot.
        #
        #   1. n_epochs: 10→6 — fewer gradient passes per rollout batch
        #      (prevents policy from fully committing to a sub-optimal path in one update)
        #   2. clip_range: 0.2→0.15 — tighter surrogate clipping
        #      (limits max policy change per step → smoother convergence)
        #   3. ent_coef: 0.01→0.02 — more entropy (exploration)
        #      (helps escape premature-block local optimum by maintaining action diversity)
        #
        # Unchanged from v5:
        #   - gamma=0.995, gae_lambda=0.97 (credit horizon for 15-window escalation)
        #   - batch_size=128 (stable gradient)
        #   - clip_range_vf=0.2, vf_coef=0.5 (critic stability)
        #   - net_arch: pi=[256,128], vf=[256,256,128]
        # =====================================================================

        def linear_schedule(initial_lr: float, floor_fraction: float = 0.33):
            """Linear LR decay from initial_lr to initial_lr*floor_fraction."""
            def schedule(progress_remaining: float) -> float:
                return initial_lr * max(progress_remaining, floor_fraction)
            return schedule

        model = PPO(
            'MlpPolicy',
            env,
            learning_rate=linear_schedule(3e-4, floor_fraction=0.20),  # v13: floor 0.50→0.20 (1.5e-4→6e-5) — less aggressive decay, more room to learn late
            n_steps=2048,
            batch_size=128,      # v5: 64→128 — more stable gradient for sparse escalation
            n_epochs=6,          # v6: 10→6 — fewer update passes/batch prevents overshoot into premature-block local optimum
            gamma=0.995,         # v5: 0.99→0.995 — longer credit horizon for escalation
            gae_lambda=0.97,     # v5: 0.95→0.97 — consistent with higher gamma
            clip_range=0.15,     # v6: 0.2→0.15 — tighter clipping prevents large policy swings that cause collapse
            clip_range_vf=0.2,   # prevents value_loss runaway
            ent_coef=0.05,       # v13: 0.02→0.05 — entropy collapse at 200k needs stronger exploration push
            vf_coef=0.5,
            max_grad_norm=0.5,
            use_sde=False,
            seed=args.seed,
            verbose=1,
            tensorboard_log=tb_dir,
            policy_kwargs=dict(
                net_arch=dict(
                    pi=[256, 128],      # Actor: 2-layer
                    vf=[256, 256, 128]  # Critic deeper — 3-layer for sparse escalation reward
                )
            )
        )
        print(f"[*] PPO agent initialized with policy type: MlpPolicy")

    # ========================================================================
    # TRAIN
    # ========================================================================

    print(f"[*] Starting training for {args.timesteps} timesteps...")
    print(f"    (This may take 10-30 minutes depending on your hardware)\n")

    model.learn(
        total_timesteps=args.timesteps,
        callback=[eval_callback, persistent_eval_callback, checkpoint_callback],
        log_interval=100,
        progress_bar=True,
        reset_num_timesteps=False if args.resume_from else True
    )

    # ========================================================================
    # SAVE FINAL MODEL
    # ========================================================================

    print(f"\n[*] Training complete!")
    model_name = 'final_model_finetuned' if args.mode == 'replay' else 'final_model'
    final_model_path = os.path.join(run_dir, model_name)
    print(f"[*] Saving final model to {final_model_path}.zip...")
    model.save(final_model_path)
    # Also save to root dir for easy access
    root_name = 'policy_model_finetuned' if args.mode == 'replay' else 'policy_model'
    model.save(root_name)
    print(f"[*] Also saved to ./{root_name}.zip")
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
        'benign':   {'total': 0, 'block': 0, 'mitigate': 0},
        'noisy':    {'total': 0, 'block': 0, 'mitigate': 0},
    }
    per_type_stats = defaultdict(lambda: {
        'total': 0,
        'block': 0,
        'mitigate': 0,
        'actions': {0: 0, 1: 0, 2: 0, 3: 0},
    })
    # Redirect→Block transition tracking per L7 episode
    # An episode "escalates" if the agent switched from Redirect to Block at least once
    l7_types = {'brute_force', 'brute_force_ka', 'sqli', 'xss'}
    l7_escalation_stats = {t: {'episodes': 0, 'escalated': 0} for t in l7_types}
    # Per-episode per-IP action history for transition detection
    _ep_ip_actions: dict = {}
    
    attacker_types = {"scan", "syn_flood", "brute_force", "brute_force_ka", "sqli", "xss"}
    benign_types = {"benign", "noisy_normal"}

    _raw_eval_env = eval_env.unwrapped  # unwrap Monitor to access IDSDefenseEnv attributes

    for _ in range(args.eval_episodes):
        obs, _ = eval_env.reset()
        done = False
        episode_reward = 0
        last_info = {}
        _ep_ip_actions = {}

        while not done:
            # Capture block_ready_latched BEFORE step — temporal state resets after Block
            cur_ip = _raw_eval_env.ip_list[_raw_eval_env.current_ip_idx]
            _ts = _raw_eval_env.ip_temporal_state.get(cur_ip)
            _block_ready_before = _ts.block_ready_latched if _ts is not None else False

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

            # 3. Track Group Stats by IP Type — read from info (set by env.step)
            ip_type = info.get('acted_ip_type', info.get('ip_type', 'unknown'))
            type_stat = per_type_stats[ip_type]
            type_stat['total'] += 1
            type_stat['actions'][action] += 1
            if action == 3:
                type_stat['block'] += 1
            if action in [1, 2, 3]:
                type_stat['mitigate'] += 1
            
            target_group = None
            if ip_type in attacker_types:
                target_group = 'attacker'
            elif ip_type == 'noisy_normal':
                target_group = 'noisy'
            elif ip_type in benign_types:
                target_group = 'benign'
            
            if target_group:
                group_stats[target_group]['total'] += 1
                if action == 3: # Block
                    group_stats[target_group]['block'] += 1
                if action in [1, 2, 3]: # Mitigate (RateLimit, Redirect, Block)
                    group_stats[target_group]['mitigate'] += 1

            # Track per-IP soft-session escalation using block_ready_latched
            acted_ip = info.get('acted_ip', '')
            if ip_type in l7_types and action == 3:
                if acted_ip not in _ep_ip_actions:
                    _ep_ip_actions[acted_ip] = {'type': ip_type, 'escalated': False}
                if not _ep_ip_actions[acted_ip].get('done'):
                    _ep_ip_actions[acted_ip]['escalated'] = _block_ready_before
                    _ep_ip_actions[acted_ip]['done'] = True

            done = done or truncated

        # End of episode — tally soft-session escalation per L7 IP
        for ip, ip_data in _ep_ip_actions.items():
            ip_type_ep = ip_data.get('type', '')
            if ip_type_ep not in l7_types:
                continue
            l7_escalation_stats[ip_type_ep]['episodes'] += 1
            if ip_data.get('escalated'):
                l7_escalation_stats[ip_type_ep]['escalated'] += 1

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

    att_block, att_mit   = get_rates(group_stats['attacker'])
    ben_block, ben_mit   = get_rates(group_stats['benign'])
    noisy_block, noisy_mit = get_rates(group_stats['noisy'])
    persistence_acceptance = evaluate_persistent_honeypot_acceptance(seed=args.seed)

    print(f"[+] Final Evaluation Results:")
    print("="*50)
    print("EVALUATION RESULTS")
    print("="*50)
    print(f"1. Mean Episode Reward: {avg_reward:.4f}")
    print(f"2. Mean Step Damage: {mean_step_damage:.4f}")
    print(f"3. Mean Episode End Cumulative Damage: {mean_ep_damage:.4f}")
    print(f"4. Action Rates: Allow={action_rates[0]:.1f}% | RateLimit={action_rates[1]:.1f}% | Redirect={action_rates[2]:.1f}% | Block={action_rates[3]:.1f}%")
    print(f"5. Attacker:     block_rate={att_block:.1f}% | mitigate_rate={att_mit:.1f}%")
    print(f"6. Benign:       block_rate={ben_block:.1f}% | mitigate_rate={ben_mit:.1f}%")
    print(f"7. Noisy normal: block_rate={noisy_block:.1f}% | mitigate_rate={noisy_mit:.1f}%")
    print("8. Persistence acceptance (Redirect early, Block after 15s persistence):")
    for ip_type in ['brute_force', 'brute_force_ka', 'sqli', 'xss']:
        metrics = persistence_acceptance[ip_type]
        print(
            f"   {ip_type:12s}: early Redirect={metrics['early_redirect']:.3f} vs Block={metrics['early_block']:.3f} | "
            f"late Redirect={metrics['late_redirect']:.3f} vs Block={metrics['late_block']:.3f}"
        )
    print("9. Per-type action distribution:")
    for ip_type in sorted(per_type_stats):
        stats = per_type_stats[ip_type]
        total = stats['total']
        if total == 0:
            continue
        action_line = " | ".join(
            f"{name}={stats['actions'][idx] / total * 100:.1f}%"
            for idx, name in enumerate(["Allow", "RateLimit", "Redirect", "Block"])
        )
        print(f"   {ip_type:12s}: {action_line}")
    print("10. Soft-session escalation rate (Block when block_ready_latched=True, L7 types):")
    for ip_type in ['brute_force', 'brute_force_ka', 'sqli', 'xss']:
        stats = l7_escalation_stats[ip_type]
        eps = stats['episodes']
        esc = stats['escalated']
        rate = (esc / eps * 100) if eps > 0 else 0.0
        print(f"   {ip_type:12s}: {esc}/{eps} episodes escalated ({rate:.1f}%)")
    print("="*50)
    print(f"    Total Episodes: {n_eval}\n")

    print("="*80)
    print("TRAINING COMPLETE")
    print("="*80 + "\n")
    print(f"Saved files:")
    print(f"  - Best model (reward):      {run_dir}/best_model.zip")
    print(f"  - Best model (escalation):  {run_dir}/best_model_persistent.zip  (if threshold met)")
    print(f"  - Final model: {run_dir}/final_model.zip")
    print(f"  - Checkpoints: {checkpoint_dir}/model_*.zip")
    print(f"  - TensorBoard logs: {tb_dir}/")
    print()
    print(f"View training progress:")
    print(f"  tensorboard --logdir {tb_dir}")
    print()

if __name__ == '__main__':
    train()
