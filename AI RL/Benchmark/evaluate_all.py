"""
Unified Benchmark Evaluation Pipeline

Evaluates all 5 algorithms × 5 seeds under identical conditions:
- Same IDSDefenseEnv (shared MDP)
- 30 episodes per (algo, seed) pair
- deterministic=True
- Fixed eval env seed for cross-algo comparability

Outputs: results/benchmark_results.json

Usage:
  cd "AI RL/Benchmark"
  python3 evaluate_all.py

Methodology:
  Henderson et al. (2018) "Deep Reinforcement Learning That Matters"
  → multiple seeds, unified evaluation protocol, documented tuning
"""

import os
import sys
import json
import numpy as np
from scipy import stats as scipy_stats

# Add parent dir so we can import IDSDefenseEnv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids_harder import IDSDefenseEnv

# Must match training config — all algos evaluated on same harder env
HARDER_ENV = {'drift_max': 0.35, 'missing_prob': 0.08}

from stable_baselines3 import PPO, A2C, DQN

# ============================================================================
# CONFIG
# ============================================================================

EVAL_EPISODES    = 30
EVAL_DETERMINISTIC = True
EVAL_ENV_SEED    = 999   # Fixed seed for eval env — same across all algos
SEEDS            = [42, 123, 456, 789, 1337]
ALGOS            = ["ppo_tuned", "ppo_default", "a2c", "dqn", "rule_based"]

MODELS_DIR  = os.path.join(os.path.dirname(__file__), "models")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# IP type → ground truth label (optimal action index for detection metric)
# Attackers: scan/syn_flood → Block(3); brute_force/sqli_xss → Redirect(2)
# Non-attackers: benign → Allow(0); noisy_normal → RateLimit(1)
ATTACK_TYPES   = {"scan", "syn_flood", "brute_force", "sqli_xss"}
BENIGN_TYPES   = {"benign"}
NOISY_TYPES    = {"noisy_normal"}

ALGO_CLASS = {
    "ppo_tuned":   PPO,
    "ppo_default": PPO,
    "a2c":         A2C,
    "dqn":         DQN,
}

# ============================================================================
# RULE-BASED POLICY
# ============================================================================

def rule_based_action(obs: np.ndarray) -> int:
    """
    Deterministic rule-based IDS policy.

    Thresholds based on feature semantics (20D normalized obs):
      F1(0)  PacketRate: high → Block (DDoS indicator)
      F2(1)  SynAckRatio: high → Block (SYN flood)
      F5(4)  DistinctPorts: many → Block (port scan)
      F13(12) CrsSqliScore: high → Redirect (SQLi)
      F18(17) CrsXssScore: high → Redirect (XSS)
      F6(5)  URLConcentration: high brute force → Redirect
      F1 moderate → RateLimit (noisy user)
      Otherwise → Allow
    """
    f1_pps    = obs[0]   # PacketRate (normalized)
    f2_syn    = obs[1]   # SynAckRatio (normalized)
    f5_ports  = obs[4]   # DistinctPorts (normalized)
    f6_url    = obs[5]   # URLConcentration
    f13_sqli  = obs[12]  # CrsSqliScore (normalized)
    f18_xss   = obs[17]  # CrsXssScore (normalized)

    # Block: DDoS / Port Scan thresholds
    if f1_pps > 0.6 or f2_syn > 0.4 or f5_ports > 0.3:
        return 3  # Block

    # Redirect: Brute Force / SQLi / XSS thresholds
    if f13_sqli > 0.1 or f18_xss > 0.1 or f6_url > 0.7:
        return 2  # Redirect

    # RateLimit: moderately elevated traffic
    if f1_pps > 0.15:
        return 1  # RateLimit

    return 0  # Allow

# ============================================================================
# SINGLE (ALGO, SEED) EVALUATION
# ============================================================================

def evaluate_one(algo: str, seed: int) -> dict:
    """Evaluate one (algo, seed) combination for EVAL_EPISODES episodes."""
    print(f"  [{algo}][seed={seed}] evaluating {EVAL_EPISODES} episodes...")

    env = IDSDefenseEnv(seed=EVAL_ENV_SEED, **HARDER_ENV)

    # Load model (skip for rule_based)
    model = None
    if algo != "rule_based":
        model_path = os.path.join(MODELS_DIR, f"{algo}_seed{seed}.zip")
        if not os.path.exists(model_path):
            print(f"    [SKIP] Model not found: {model_path}")
            return None
        cls = ALGO_CLASS[algo]
        model = cls.load(model_path, env=env)

    # Storage
    episode_rewards   = []
    action_counts_all = []   # per episode, list of 4 counts
    ip_type_actions   = []   # list of (ip_type, action) per step

    for ep in range(EVAL_EPISODES):
        obs, _ = env.reset(seed=EVAL_ENV_SEED + ep)  # vary episode start but deterministic
        done = False
        ep_reward = 0.0
        ep_actions = [0, 0, 0, 0]

        while not done:
            # Save observation BEFORE action — needed for active threat detection
            obs_before = obs.copy()

            if algo == "rule_based":
                action = rule_based_action(obs)
            else:
                action, _ = model.predict(obs, deterministic=EVAL_DETERMINISTIC)
                action = int(action)

            obs, reward, done, truncated, info = env.step(action)
            ep_reward += reward
            ep_actions[action] += 1

            ip_type = info.get("ip_type", "unknown")

            # Is this attacker currently an active threat? (features not suppressed)
            # After Block, all features → 0 for block_ttl steps.
            # F1 (PacketRate) > 0.03 normalized means traffic is still flowing
            # → only count as detection opportunity when attacker is active
            is_active = float(obs_before[0]) > 0.03

            ip_type_actions.append((ip_type, action, is_active))

            done = done or truncated

        episode_rewards.append(ep_reward)
        action_counts_all.append(ep_actions)

    env.close()

    # ---- Compute metrics ----

    # 1. Reward statistics
    rewards_arr = np.array(episode_rewards)
    mean_reward = float(np.mean(rewards_arr))
    std_reward  = float(np.std(rewards_arr))

    # 2. Action distribution (% across all steps)
    total_ac = np.array(action_counts_all).sum(axis=0)  # shape (4,)
    total_steps = int(total_ac.sum())
    action_dist = (total_ac / total_steps * 100).tolist() if total_steps > 0 else [0.0]*4

    # 3. Detection rate — correct mitigation action per attack type
    #
    # Why NOT use action>=1 as detection:
    #   - Closed-loop effect: after Block, attacker features drop to ~0
    #     → model sees "clean" obs → Allow on next cycle → counted as miss
    #     even though model already correctly blocked that attacker.
    #   - RateLimit for DDoS/PortScan is NOT correct mitigation.
    #
    # Definition used here (strict, security-relevant):
    #   scan/syn_flood    → correct iff action == 3 (Block)
    #   brute_force/sqli_xss → correct iff action in {2,3} (Redirect or Block)
    #   noisy_normal      → correct iff action in {1,2,3} (any mitigation)
    #
    # This measures "did the model apply a meaningful security response"
    # rather than "did it not Allow".
    CORRECT_ACTIONS = {
        "scan":        {3},      # Block only
        "syn_flood":   {3},      # Block only
        "brute_force": {2, 3},   # Redirect or Block
        "sqli_xss":    {2, 3},   # Redirect or Block
    }

    # --- Active-threat detection (PRIMARY metric for paper) ---
    # Only count steps where attacker features are NOT suppressed by prior Block.
    # After Block, all features → 0 for block_ttl (5-11) steps → model correctly
    # Allows "silent" attacker → should NOT be counted as miss.
    # Threshold: F1 (PacketRate) normalized > 0.03 means traffic still flowing.
    attack_active  = [(ipt, a) for ipt, a, active in ip_type_actions
                      if ipt in ATTACK_TYPES and active]
    detected_active = [(ipt, a) for ipt, a in attack_active
                       if a in CORRECT_ACTIONS.get(ipt, set())]
    detection_rate  = len(detected_active) / len(attack_active) * 100 if attack_active else 0.0

    # --- Raw detection rates (ALL steps, for reference/transparency) ---
    attack_all       = [(ipt, a) for ipt, a, _ in ip_type_actions if ipt in ATTACK_TYPES]
    detected_strict  = [(ipt, a) for ipt, a in attack_all
                        if a in CORRECT_ACTIONS.get(ipt, set())]
    detected_loose   = [a for _, a in attack_all if a >= 1]
    detection_rate_raw_strict = len(detected_strict) / len(attack_all) * 100 if attack_all else 0.0
    detection_rate_raw_loose  = len(detected_loose)  / len(attack_all) * 100 if attack_all else 0.0

    # 4. False positive rate — benign/noisy traffic that got Blocked (action=3)
    #    Only count active benign steps (not suppressed)
    benign_active = [(ipt, a) for ipt, a, active in ip_type_actions
                     if ipt in BENIGN_TYPES | NOISY_TYPES and active]
    fp_blocked    = [a for _, a in benign_active if a == 3]
    fp_rate       = len(fp_blocked) / len(benign_active) * 100 if benign_active else 0.0

    # 5. Confusion matrix 4×4 (true_action × predicted_action)
    #    Only count ACTIVE steps (no post-suppression noise)
    OPTIMAL = {
        "benign":      0,  # Allow
        "noisy_normal": 1, # RateLimit
        "brute_force":  2, # Redirect
        "sqli_xss":     2, # Redirect
        "scan":         3, # Block
        "syn_flood":    3, # Block
    }
    cm = np.zeros((4, 4), dtype=int)
    for ipt, a, active in ip_type_actions:
        if not active:
            continue
        gt = OPTIMAL.get(ipt, 0)
        cm[gt][a] += 1

    return {
        "mean_reward":              mean_reward,
        "std_reward":               std_reward,
        "action_dist":              action_dist,
        "detection_rate":           detection_rate,            # active-threat, correct action
        "detection_rate_raw_strict": detection_rate_raw_strict, # all steps, correct action
        "detection_rate_raw_loose":  detection_rate_raw_loose,  # all steps, any action>=1
        "fp_rate":                  fp_rate,
        "confusion_matrix":         cm.tolist(),
        "total_steps":              total_steps,
        "n_active_attack_steps":    len(attack_active),
        "n_total_attack_steps":     len(attack_all),
        "episode_rewards":          episode_rewards,
    }

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*70)
    print("BENCHMARK EVALUATION — Unified Pipeline")
    print(f"  Algos:    {ALGOS}")
    print(f"  Seeds:    {SEEDS}")
    print(f"  Episodes: {EVAL_EPISODES} per (algo × seed)")
    print("="*70)

    results = {}

    for algo in ALGOS:
        print(f"\n[{algo.upper()}]")
        results[algo] = {}
        for seed in SEEDS:
            seed_result = evaluate_one(algo, seed)
            if seed_result is not None:
                results[algo][str(seed)] = seed_result

        # Aggregate across seeds
        seed_keys = [k for k in results[algo]]
        if seed_keys:
            mean_rewards    = [results[algo][k]["mean_reward"] for k in seed_keys]
            det_rates       = [results[algo][k]["detection_rate"] for k in seed_keys]
            det_raw_strict  = [results[algo][k]["detection_rate_raw_strict"] for k in seed_keys]
            det_raw_loose   = [results[algo][k]["detection_rate_raw_loose"] for k in seed_keys]
            fp_rates        = [results[algo][k]["fp_rate"] for k in seed_keys]
            act_dists       = np.array([results[algo][k]["action_dist"] for k in seed_keys])
            cms             = np.array([results[algo][k]["confusion_matrix"] for k in seed_keys])

            results[algo]["_aggregate"] = {
                "mean_reward":              float(np.mean(mean_rewards)),
                "std_reward":               float(np.std(mean_rewards)),
                "ci95":                     float(1.96 * np.std(mean_rewards) / np.sqrt(len(mean_rewards))),
                "detection_rate":           float(np.mean(det_rates)),         # active-threat only
                "detection_rate_raw_strict": float(np.mean(det_raw_strict)),   # all steps, correct action
                "detection_rate_raw_loose":  float(np.mean(det_raw_loose)),    # all steps, action>=1
                "fp_rate":                  float(np.mean(fp_rates)),
                "action_dist_mean":         act_dists.mean(axis=0).tolist(),
                "confusion_matrix_mean":    cms.mean(axis=0).tolist(),
                "n_seeds":                  len(seed_keys),
            }

            agg = results[algo]["_aggregate"]
            print(f"  [AGGREGATE] mean_reward={agg['mean_reward']:.4f} ± {agg['std_reward']:.4f}"
                  f"  (95% CI ±{agg['ci95']:.4f})")
            print(f"              detection_rate={agg['detection_rate']:.1f}%  "
                  f"fp_rate={agg['fp_rate']:.1f}%")
            ad = agg["action_dist_mean"]
            print(f"              actions: Allow={ad[0]:.1f}% RL={ad[1]:.1f}% "
                  f"Redirect={ad[2]:.1f}% Block={ad[3]:.1f}%")

    # ---- Statistical comparison: PPO-Tuned vs PPO-Default ----
    try:
        tuned_seeds   = [k for k in results.get("ppo_tuned", {}) if not k.startswith("_")]
        default_seeds = [k for k in results.get("ppo_default", {}) if not k.startswith("_")]
        if tuned_seeds and default_seeds:
            tuned_rewards   = [results["ppo_tuned"][k]["mean_reward"]   for k in tuned_seeds]
            default_rewards = [results["ppo_default"][k]["mean_reward"] for k in default_seeds]

            t_stat, p_val = scipy_stats.ttest_ind(tuned_rewards, default_rewards)
            pooled_std = float(np.sqrt(
                (np.std(tuned_rewards, ddof=1)**2 + np.std(default_rewards, ddof=1)**2) / 2
            ))
            cohen_d = (np.mean(tuned_rewards) - np.mean(default_rewards)) / pooled_std if pooled_std > 0 else 0.0
            effect_label = "large" if abs(cohen_d) >= 0.8 else "medium" if abs(cohen_d) >= 0.5 else "small"

            results["_statistics"] = {
                "ppo_tuned_vs_default_tstat":  float(t_stat),
                "ppo_tuned_vs_default_pvalue": float(p_val),
                "cohen_d":                     float(cohen_d),
                "effect_size_label":           effect_label,
                "tuned_mean":                  float(np.mean(tuned_rewards)),
                "default_mean":                float(np.mean(default_rewards)),
                "tuned_std":                   float(np.std(tuned_rewards, ddof=1)),
                "default_std":                 float(np.std(default_rewards, ddof=1)),
            }

            print("\n" + "="*70)
            print("STATISTICAL ANALYSIS: PPO-Tuned vs PPO-Default")
            print(f"  PPO-Tuned  : {np.mean(tuned_rewards):.4f} ± {np.std(tuned_rewards, ddof=1):.4f}")
            print(f"  PPO-Default: {np.mean(default_rewards):.4f} ± {np.std(default_rewards, ddof=1):.4f}")
            print(f"  Cohen's d  : {cohen_d:.3f} ({effect_label} effect)")
            print(f"  t-statistic: {t_stat:.3f},  p-value: {p_val:.4f}")
            print("="*70)
    except Exception as e:
        print(f"[WARN] Statistical analysis failed: {e}")

    # Save results
    output_path = os.path.join(RESULTS_DIR, "benchmark_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Results saved to: {output_path}")
    print("="*70)

if __name__ == "__main__":
    main()
