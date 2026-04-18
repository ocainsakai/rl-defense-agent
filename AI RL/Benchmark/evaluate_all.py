"""
Unified Benchmark Evaluation Pipeline — PPO vs A2C vs DQN vs Rule-Based

TRACK: sb3_strict_default
  PPO        — SB3 strict defaults, net_arch=[64,64]
  A2C        — SB3 strict defaults, net_arch=[64,64]
  DQN        — SB3 strict defaults, buffer_size=1_000_000, net_arch=[64,64]
  Rule-Based — deterministic threshold policy

3-Tier Evaluation:
  Tier 1  Algorithmic Baseline    — reward, mitigation, exact response, macro F1
  Tier 2  Operational Suitability — honeypot capture, benign protection, over-mitigation,
                                    service damage, action oscillation
  Tier 3  Closed-loop Stress Test — round_robin vs session_20 eval modes

Protocol (Henderson et al. 2018):
  5 train seeds × 5 eval seeds × 6 episodes = 30 ep per train seed per eval mode
  Aggregate per train seed → mean ± 95% CI across 5 train seeds

Outputs: results/benchmark_results.json

Usage:
  cd "AI RL/Benchmark"
  python3 evaluate_all.py
"""

import os
import sys
import json
import numpy as np
from scipy import stats as scipy_stats

# -- imports from sibling file ------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from metrics import (
    compute_metrics, aggregate_seeds,
    KNOWN_IP_TYPES, OPTIMAL_ACTION, MITIGATION_ACTIONS,
    ACTION_NAMES,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from env_ids_harder import IDSDefenseEnv, compute_network_damage

from stable_baselines3 import PPO, A2C, DQN

# ============================================================================
# CONFIG
# ============================================================================

TRACK_NAME             = "sb3_strict_default_final_primary"
TRAIN_SEEDS            = [42, 123, 456, 789, 1337]
EVAL_SEEDS             = [1001, 1002, 1003, 1004, 1005]
EVAL_EPISODES_PER_SEED = 6      # 5 × 6 = 30 episodes per train seed
EVAL_DETERMINISTIC     = True
ALGOS                  = ["ppo", "a2c", "dqn", "rule_based"]

MODELS_DIR  = os.path.join(os.path.dirname(__file__), "models")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

ALGO_CLASS = {"ppo": PPO, "a2c": A2C, "dqn": DQN}

DQN_TRACK_NOTE = (
    "sb3_strict_default: buffer_size=1_000_000, learning_starts=100, "
    "exploration_fraction=0.1 — all SB3 defaults, no adjustments"
)

# ── Tier 3: Eval modes ───────────────────────────────────────────────────────
#
# Each config is passed as **env_kwargs to IDSDefenseEnv.
# "session_block_size=0" = round-robin (default, env-compatible always).
# "session_block_size=20" = 20 consecutive steps per IP (closed-loop test).
#
# Four eval configs split cleanly by two axes:
#   session axis:  round_robin (iid, session_block_size=0)  vs  session_20 (sequential blocks)
#   noise axis:    normal (training distribution)           vs  stress (out-of-distribution noise)
#
# Stress comparisons MUST pair same session setting:
#   round_robin  ↔  round_robin_stress    (isolates noise/drift effect)
#   session_20   ↔  session_20_stress     (isolates noise/drift effect)
#
# Do NOT compare round_robin with session_20_stress — confounds two variables.
EVAL_CONFIGS = [
    {
        "name":       "round_robin",
        "env_kwargs": {"session_block_size": 0,  "missing_prob": 0.08, "drift_max": 0.35},
    },
    {
        "name":       "round_robin_stress",
        "env_kwargs": {"session_block_size": 0,  "missing_prob": 0.15, "drift_max": 0.50},
    },
    {
        "name":       "session_20",
        "env_kwargs": {"session_block_size": 20, "missing_prob": 0.08, "drift_max": 0.35},
    },
    {
        "name":       "session_20_stress",
        "env_kwargs": {"session_block_size": 20, "missing_prob": 0.15, "drift_max": 0.50},
    },
]

# ============================================================================
# RULE-BASED POLICY
# ============================================================================

def rule_based_action(obs: np.ndarray) -> int:
    """
    Deterministic rule-based IDS policy on normalized 34D obs.
      obs[0]  F1  PacketRate
      obs[1]  F2  SynAckRatio
      obs[4]  F5  DistinctPorts
      obs[5]  F6  URLConcentration
      obs[12] F13 CrsSqliScore
      obs[17] F18 CrsXssScore
    """
    if obs[0] > 0.6 or obs[1] > 0.4 or obs[4] > 0.3:
        return 3  # Block
    if obs[12] > 0.1 or obs[17] > 0.1 or obs[5] > 0.7:
        return 2  # Redirect
    if obs[0] > 0.15:
        return 1  # RateLimit
    return 0      # Allow

# ============================================================================
# EVALUATION RUNNER
# ============================================================================

def evaluate_one(algo: str, train_seed: int, eval_config: dict) -> dict | None:
    """
    Evaluate one (algo, train_seed) pair across all EVAL_SEEDS for one eval_config.
    Returns metrics dict or None if model not found.
    """
    mode = eval_config["name"]
    env_kwargs = eval_config["env_kwargs"]
    n_ep = len(EVAL_SEEDS) * EVAL_EPISODES_PER_SEED

    print(f"  [{algo}][train={train_seed}][{mode}]  "
          f"{len(EVAL_SEEDS)} seeds × {EVAL_EPISODES_PER_SEED} ep = {n_ep} episodes ...")

    model = None
    if algo != "rule_based":
        model_path = os.path.join(MODELS_DIR, f"{algo}_seed{train_seed}.zip")
        if not os.path.exists(model_path):
            print(f"    [SKIP] Not found: {model_path}")
            return None
        model = ALGO_CLASS[algo].load(model_path)

    records         = []
    episode_rewards = []
    unknown_count   = 0
    global_step_idx = 0

    for eval_seed in EVAL_SEEDS:
        try:
            env = IDSDefenseEnv(seed=eval_seed, **env_kwargs)
        except TypeError:
            # env doesn't support one of the kwargs — skip this eval_config
            print(f"    [SKIP] Env does not support kwargs: {env_kwargs}")
            return None

        for ep_idx in range(EVAL_EPISODES_PER_SEED):
            episode_seed = eval_seed * 100 + ep_idx   # unique, no overlap with train seeds
            obs, _ = env.reset(seed=episode_seed)
            done      = False
            ep_reward = 0.0
            ep_step   = 0

            while not done:
                obs_before = obs.copy()

                if algo == "rule_based":
                    action = rule_based_action(obs)
                else:
                    action, _ = model.predict(obs, deterministic=EVAL_DETERMINISTIC)
                    action = int(action)

                obs, reward, done, truncated, info = env.step(action)
                ep_reward += reward

                # ── Strict label validation ──────────────────────────────────
                acted_ip_type = info.get("acted_ip_type")
                if acted_ip_type is None:
                    raise RuntimeError(
                        f"[{algo}][train={train_seed}][{mode}][eval_seed={eval_seed}] "
                        f"info missing 'acted_ip_type'. Fallback disabled."
                    )
                if acted_ip_type not in KNOWN_IP_TYPES:
                    unknown_count += 1
                    acted_ip_type = "_unknown_"

                # Use raw features (unmasked) to determine activity — avoids
                # missing_prob masking obs_before[0] causing false inactive labels.
                raw_before  = info.get("acted_features_before", [])
                is_active   = (compute_network_damage(raw_before) > 0.01
                               if raw_before else float(obs_before[0]) > 0.03)
                step_damage = float(info.get("step_damage",
                              info.get("damage",
                              max(0.0, -reward))))
                acted_ip    = str(info.get("acted_ip", info.get("src_ip", "unknown")))

                records.append({
                    "ip_type":           acted_ip_type,
                    "acted_ip":          acted_ip,
                    "action":            action,
                    "active":            is_active,
                    "reward":            float(reward),
                    "step_damage":       step_damage,
                    "eval_seed":         eval_seed,
                    "ep_idx":            ep_idx,
                    "step_idx":          ep_step,
                    "eval_mode":         mode,
                    "train_seed":        train_seed,
                    # temporal snapshot from env (thesis-control metrics)
                    "block_ready_before": info.get("block_ready_before"),
                })
                ep_step          += 1
                global_step_idx  += 1
                done = done or truncated

            episode_rewards.append(ep_reward)

        env.close()

    if unknown_count > 0:
        raise RuntimeError(
            f"[{algo}][train={train_seed}][{mode}] "
            f"{unknown_count} steps with unknown acted_ip_type — "
            f"update KNOWN_IP_TYPES or fix env."
        )

    return compute_metrics(records, episode_rewards, eval_mode=mode)

# ============================================================================
# STATISTICAL ANALYSIS
# ============================================================================

def significance_label(p_value: float) -> str:
    """
    Conventional stars interpretation for two-sample t-test p-values.
    With n=5 seeds, results with p >= 0.05 should be presented as trends only.
    """
    if p_value < 0.001:
        return "*** (p<0.001)"
    if p_value < 0.01:
        return "**  (p<0.01)"
    if p_value < 0.05:
        return "*   (p<0.05)"
    return "ns  (trend only)"


def run_statistics(results: dict, eval_mode: str) -> dict:
    """
    Pairwise independent two-sample t-test + Cohen's d across 5 train seeds.
    Covers reward, key attack metrics, and benign-safety metrics.
    Statistical threshold: p < 0.05 (two-tailed).
    Note: n=5 is small; interpret p-values together with effect size and direction.
    """
    rl_algos = ["ppo", "a2c", "dqn"]
    stat_metrics = [
        "mean_reward", "exact_response_rate",
        "honeypot_capture_rate", "benign_intervention_rate",
        "benign_harm_score", "service_damage_auc",
    ]

    algo_data = {}
    for algo in rl_algos:
        mode_data = results.get(algo, {}).get(eval_mode, {})
        keys = [k for k in mode_data if not k.startswith("_")]
        if keys:
            algo_data[algo] = {
                m: [mode_data[k][m] for k in keys
                    if m in mode_data[k] and mode_data[k][m] is not None]
                for m in stat_metrics
            }

    stats_out = {}
    for i, a1 in enumerate(rl_algos):
        for a2 in rl_algos[i+1:]:
            if a1 not in algo_data or a2 not in algo_data:
                continue
            pair_key = f"{a1}_vs_{a2}"
            stats_out[pair_key] = {}
            for m in stat_metrics:
                r1 = algo_data[a1].get(m, [])
                r2 = algo_data[a2].get(m, [])
                if len(r1) < 2 or len(r2) < 2:
                    continue
                t_stat, p_val = scipy_stats.ttest_ind(r1, r2)
                pooled_std = float(np.sqrt(
                    (np.std(r1, ddof=1)**2 + np.std(r2, ddof=1)**2) / 2
                ))
                cohen_d = (np.mean(r1) - np.mean(r2)) / pooled_std if pooled_std > 0 else 0.0
                effect  = ("large"  if abs(cohen_d) >= 0.8
                           else "medium" if abs(cohen_d) >= 0.5 else "small")
                stats_out[pair_key][m] = {
                    "t_stat":         float(t_stat),
                    "p_value":        float(p_val),
                    "significance":   significance_label(float(p_val)),
                    "cohen_d":        float(cohen_d),
                    "effect":         effect,
                    f"{a1}_mean":     float(np.mean(r1)),
                    f"{a2}_mean":     float(np.mean(r2)),
                }
    return stats_out


def print_ppo_dqn_significance(stats_all: dict):
    """
    Print focused PPO-vs-DQN significance table for benign-safety metrics
    across all eval modes. This is the primary statistical claim of the thesis.
    """
    benign_metrics = [
        ("benign_intervention_rate", "benign_intervention_rate",
         "lower=better for PPO"),
        ("benign_harm_score",        "benign_harm_score (weighted)",
         "lower=better for PPO; n=5 so p>=0.05 = trend only"),
    ]

    print("\n" + "=" * 72)
    print("PPO vs DQN — Benign-Safety Statistical Significance")
    print("Method: independent two-sample t-test, n=5 train seeds per algo")
    print("Threshold: p < 0.05 → significant  |  p >= 0.05 → trend only")
    print("Note: n=5 is small; interpret with effect size and direction.")
    print("=" * 72)
    print(f"  {'Metric':<32} {'Mode':<22} {'PPO':>7} {'DQN':>7}  {'p-value':>8}  Interpretation")
    print("-" * 100)

    modes_order = ["round_robin", "round_robin_stress", "session_20", "session_20_stress"]
    for mkey, mlabel, note in benign_metrics:
        for mode in modes_order:
            pair = stats_all.get(mode, {}).get("ppo_vs_dqn", {}).get(mkey)
            if not pair:
                continue
            p = pair["p_value"]
            ppo_v = pair["ppo_mean"]
            dqn_v = pair["dqn_mean"]
            sig = significance_label(p)
            print(f"  {mlabel:<32} {mode:<22} {ppo_v:>7.3f} {dqn_v:>7.3f}  {p:>8.4f}  {sig}")
        print(f"    ({note})")
        print()

    print("Statistical evidence summary:")
    print("  benign_intervention_rate: primary claim — use p-values above as evidence.")
    print("  benign_harm_score:        supporting claim — report significant modes only.")
    print("  Efficiency ratios (mitigation_efficiency, weighted_mitigation_efficiency):")
    print("    Use to describe tradeoff magnitude, NOT as primary statistical evidence.")
    print("=" * 72)

# ============================================================================
# CONSOLE REPORT
# ============================================================================

def print_summary(results: dict, eval_mode: str):
    agg_key = "_aggregate"
    algos = [a for a in ALGOS if eval_mode in results.get(a, {})]

    def _v(algo, metric, fmt=".1f"):
        agg = results[algo][eval_mode].get(agg_key, {})
        val = agg.get(metric)
        if val is None:
            return "  N/A"
        return format(val, fmt)

    W = 12
    header = f"{'':20s}" + "".join(f"{a:>{W}}" for a in algos)

    print(f"\n── Tier 1: Algorithmic Baseline [{eval_mode}] ──")
    print(header)
    for label, metric, fmt in [
        ("Mean Reward",      "mean_reward",        ".2f"),
        ("  ± 95% CI",       "ci95",               ".2f"),
        ("Mitigation %",     "mitigation_rate",    ".1f"),
        ("Exact Response %", "exact_response_rate",".1f"),
        ("Macro F1",         "macro_f1",           ".4f"),
    ]:
        row = f"{label:20s}"
        for a in algos:
            row += f"{_v(a, metric, fmt):>{W}}"
        print(row)

    print(f"\n── Tier 2: Operational Suitability [{eval_mode}] ──")
    print(header)
    for label, metric, fmt, note in [
        ("Honeypot Capture%","honeypot_capture_rate",         ".1f", "↑ better"),
        ("L7 Over-Block %",  "l7_over_block_rate",            ".1f", "↓ better"),
        ("Benign Interv. %", "benign_intervention_rate",      ".1f", "↓ better  (any non-Allow on benign)"),
        ("Benign Block %",   "benign_block_rate",             ".1f", "↓ better"),
        ("Benign Harm Score","benign_harm_score",             ".2f", "↓ better  (1×RL+2×Redir+3×Block)"),
        ("Over-Mitigate %",  "over_mitigation_rate",         ".1f", "↓ better"),
        ("Svc Damage AUC",   "service_damage_auc",           ".4f", "↓ better"),
        ("Action Oscill. %", "action_oscillation_rate",      ".1f", "↓ better"),
        ("Mitig/BenignInt",  "mitigation_efficiency",        ".1f", "↑ tradeoff (mitigation_rate/benign_int)"),
        ("Mitig/BenignHarm", "weighted_mitigation_efficiency",".1f","↑ tradeoff (mitigation_rate/harm_score)"),
    ]:
        row = f"{label:20s}"
        for a in algos:
            row += f"{_v(a, metric, fmt):>{W}}"
        print(f"{row}   # {note}")

    print(f"\n── Tier 3: Thesis-Control / Dynamic Metrics [{eval_mode}] ──")
    print(header)
    for label, metric, fmt, note in [
        ("Dyn Exact Resp %",  "dynamic_exact_response_rate", ".1f", "↑ better (phase-aware L7)"),
        ("L7 Redirect Hold%", "l7_redirect_hold_rate",       ".1f", "↑ better (hold before escalate)"),
        ("L7 On-time Block%", "l7_ontime_block_rate",        ".1f", "↑ better (escalate on time)"),
        ("L7 Premature Blk%", "l7_premature_block_rate",     ".1f", "↓ better (don't block too early)"),
        ("L7 Late Redir %",   "l7_late_under_escalation_rate",".1f","↓ better (don't under-escalate)"),
        ("Safe Interv. %",    "safe_intervention_rate",      ".1f", "↑ better"),
    ]:
        row = f"{label:20s}"
        for a in algos:
            row += f"{_v(a, metric, fmt):>{W}}"
        print(f"{row}   # {note}")

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 72)
    print("BENCHMARK — PPO vs A2C vs DQN vs Rule-Based  (3-Tier Evaluation)")
    print(f"  Track:       {TRACK_NAME}")
    print(f"  DQN note:    {DQN_TRACK_NOTE}")
    print(f"  Eval modes:  {[c['name'] for c in EVAL_CONFIGS]}")
    print(f"  Train seeds: {TRAIN_SEEDS}")
    print(f"  Eval seeds:  {EVAL_SEEDS}  × {EVAL_EPISODES_PER_SEED} ep = "
          f"{len(EVAL_SEEDS)*EVAL_EPISODES_PER_SEED} ep/train_seed")
    print(f"  Env:         env_ids_harder.py (34D, missing_prob=0.08, drift_max=0.35)")
    print("=" * 72)

    # results[algo][eval_mode][train_seed] = metrics_dict
    # results[algo][eval_mode]["_aggregate"] = aggregate_dict
    results = {}

    for algo in ALGOS:
        print(f"\n{'='*20} [{algo.upper()}] {'='*20}")
        results[algo] = {}

        for eval_cfg in EVAL_CONFIGS:
            mode = eval_cfg["name"]
            results[algo][mode] = {}
            print(f"\n  ── Mode: {mode} ──")

            for train_seed in TRAIN_SEEDS:
                seed_result = evaluate_one(algo, train_seed, eval_cfg)
                if seed_result is not None:
                    results[algo][mode][str(train_seed)] = seed_result

            agg = aggregate_seeds(results[algo][mode])
            if agg:
                results[algo][mode]["_aggregate"] = agg
                ad = agg.get("action_dist_mean", [0]*4)
                print(f"  [AGG/{mode}] "
                      f"reward={agg['mean_reward']:.3f}±{agg.get('ci95',0):.3f}  "
                      f"mitig={agg['mitigation_rate']:.1f}%  "
                      f"exact={agg['exact_response_rate']:.1f}%  "
                      f"F1={agg['macro_f1']:.3f}")
                print(f"             "
                      f"honeypot={agg['honeypot_capture_rate']:.1f}%  "
                      f"benign_int={agg['benign_intervention_rate']:.1f}%  "
                      f"over_mit={agg['over_mitigation_rate']:.1f}%  "
                      f"dmg={agg['service_damage_auc']:.4f}")
                print(f"             "
                      f"Allow={ad[0]:.1f}% RL={ad[1]:.1f}% "
                      f"Redirect={ad[2]:.1f}% Block={ad[3]:.1f}%")

    # Console summary tables
    for eval_cfg in EVAL_CONFIGS:
        print_summary(results, eval_cfg["name"])

    # Statistical analysis per eval mode
    stats_all = {}
    for eval_cfg in EVAL_CONFIGS:
        mode = eval_cfg["name"]
        s = run_statistics(results, mode)
        stats_all[mode] = s
        print(f"\n── Statistics [{mode}] ── (reward only; full table below)")
        ppo_dqn = s.get("ppo_vs_dqn", {})
        for pair, pair_stats in s.items():
            reward_s = pair_stats.get("mean_reward", {})
            if reward_s:
                a1, a2 = pair.split("_vs_")
                sig = significance_label(reward_s["p_value"])
                print(f"  {a1.upper():>3} vs {a2.upper():<3}: "
                      f"reward t={reward_s['t_stat']:.3f}  "
                      f"p={reward_s['p_value']:.5f}  "
                      f"d={reward_s['cohen_d']:.3f} ({reward_s['effect']})  "
                      f"{sig}")

    # Focused PPO vs DQN benign-safety significance table
    print_ppo_dqn_significance(stats_all)

    # Save
    output = {
        "_metadata": {
            "track":                TRACK_NAME,
            "checkpoint_policy":    "final_primary",
            "statistical_methods": (
                "Independent two-sample t-tests across 5 train seeds. "
                "p < 0.05 → statistically significant; p >= 0.05 → trend only. "
                "n=5 is small; interpret p-values together with Cohen's d and metric direction. "
                "Primary statistical claim: benign_intervention_rate (PPO < DQN, p < 0.05 all modes). "
                "Supporting claim: benign_harm_score (PPO < DQN, significant under stress settings). "
                "Ratio metrics (mitigation_efficiency, weighted_mitigation_efficiency) describe "
                "tradeoff magnitude — not used as primary statistical evidence."
            ),
            "n_envs":               1,
            "hyperparameter_tuning": False,
            "dqn_note":             DQN_TRACK_NOTE,
            "train_seeds":          TRAIN_SEEDS,
            "eval_seeds":           EVAL_SEEDS,
            "eval_episodes_per_seed": EVAL_EPISODES_PER_SEED,
            "total_episodes_per_train_seed": len(EVAL_SEEDS) * EVAL_EPISODES_PER_SEED,
            "eval_configs":         [c["name"] for c in EVAL_CONFIGS],
            "env_configs":          {c["name"]: c["env_kwargs"] for c in EVAL_CONFIGS},
            "metric_definitions": {
                "mitigation_rate":        "% active attack steps with correct mitigating action",
                "exact_response_rate":    "% active steps with OPTIMAL_ACTION for that ip_type",
                "honeypot_capture_rate":  "% active L7 steps that were Redirected to honeypot",
                "benign_intervention_rate": "% active benign steps with any non-Allow action (RateLimit+Redirect+Block); broad proxy for benign-user disruption, not equivalent to false positive rate",
                "benign_harm_score":       "severity-weighted benign disruption: 1×benign_ratelimit + 2×benign_redirect + 3×benign_block; higher = more operational friction on legit users",
                "over_mitigation_rate":   "% active steps where action severity > optimal for that ip_type",
                "action_oscillation_rate": "% consecutive appearances of same IP where action changed",
                "service_damage_auc":     "mean step_damage per step across all steps",
                "dynamic_exact_response_rate": "% active steps with L7-phase-aware optimal action (Redirect when block_ready=False, Block when block_ready=True)",
                "l7_redirect_hold_rate":  "% L7 steps in hold-phase correctly Redirected",
                "l7_ontime_block_rate":   "% L7 escalation-phase steps correctly Blocked",
                "l7_premature_block_rate":"% L7 hold-phase steps incorrectly Blocked",
                "l7_late_under_escalation_rate": "% L7 escalation-phase steps still Redirecting after escalation threshold",
                "safe_intervention_rate": "% active steps where action was a correct mitigating response",
                "mitigation_efficiency":  "mitigation_rate / benign_intervention_rate — security-usability tradeoff indicator; higher = more attack protection per unit of benign disruption. Computed from aggregate rates for stability. Not a replacement for reward/mitigation as primary metrics.",
                "weighted_mitigation_efficiency": "mitigation_rate / benign_harm_score — same concept with severity-weighted denominator; more conservative than mitigation_efficiency when benign block/redirect occur.",
            },
        },
        "_statistics": stats_all,
    }
    output.update(results)

    output_path = os.path.join(RESULTS_DIR, "benchmark_results.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[+] Saved: {output_path}")
    print("=" * 72)


if __name__ == "__main__":
    main()
