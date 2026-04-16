"""
Preflight evaluator for 30D PPO IDS models.

Purpose:
  - Evaluate a model/checkpoint on the current 30D environment
  - Report per-type action distribution with correct acted_ip_type semantics
  - Apply simple thesis-oriented health checks before keeping or deploying a run

Examples:
  python3 preflight_eval.py --model runs/run_v6_30d/best_model.zip
  python3 preflight_eval.py --model runs/run_v6_30d/checkpoints/model_200000_steps.zip --episodes 50
"""

import argparse
import json
import os
from collections import Counter, defaultdict

import numpy as np
from stable_baselines3 import PPO

from env_ids import IDSDefenseEnv


ACTION_NAMES = {0: "Allow", 1: "RateLimit", 2: "Redirect", 3: "Block"}
ATTACKER_TYPES = {"scan", "syn_flood", "brute_force", "sqli_xss"}


def evaluate_model(model_path: str, episodes: int = 50, seed: int = 42) -> dict:
    env = IDSDefenseEnv(seed=seed)
    model = PPO.load(model_path)

    action_counts = Counter()
    per_type = defaultdict(lambda: {
        "total": 0,
        "reward_sum": 0.0,
        "damage_sum": 0.0,
        "actions": Counter(),
    })
    episode_rewards = []
    episode_damages = []

    for ep in range(episodes):
        obs, _ = env.reset(seed=seed + ep)
        done = False
        episode_reward = 0.0
        last_cumulative_damage = 0.0

        while not done:
            action, _ = model.predict(obs, deterministic=True)
            action = int(np.asarray(action).reshape(-1)[0])

            obs, reward, done, truncated, info = env.step(action)
            done = done or truncated

            acted_type = info["acted_ip_type"]
            action_counts[action] += 1

            s = per_type[acted_type]
            s["total"] += 1
            s["reward_sum"] += reward
            s["damage_sum"] += info.get("step_damage", 0.0)
            s["actions"][action] += 1

            episode_reward += reward
            last_cumulative_damage = info.get("cumulative_damage", last_cumulative_damage)

        episode_rewards.append(episode_reward)
        episode_damages.append(last_cumulative_damage)

    total_steps = sum(action_counts.values())
    summary = {
        "model": model_path,
        "episodes": episodes,
        "mean_episode_reward": float(np.mean(episode_rewards)),
        "std_episode_reward": float(np.std(episode_rewards)),
        "mean_episode_damage": float(np.mean(episode_damages)),
        "action_rates": {
            ACTION_NAMES[a]: (100.0 * action_counts[a] / total_steps if total_steps else 0.0)
            for a in range(4)
        },
        "per_type": {},
    }

    groups = {
        "attacker": {"total": 0, "mitigate": 0, "block": 0},
        "benign": {"total": 0, "mitigate": 0, "block": 0},
        "noisy": {"total": 0, "mitigate": 0, "block": 0, "ratelimit": 0},
    }

    for ip_type in sorted(per_type):
        s = per_type[ip_type]
        total = s["total"]
        actions_pct = {
            ACTION_NAMES[a]: (100.0 * s["actions"][a] / total if total else 0.0)
            for a in range(4)
        }
        mitigate_rate = 100.0 * sum(s["actions"][a] for a in (1, 2, 3)) / total if total else 0.0
        block_rate = 100.0 * s["actions"][3] / total if total else 0.0
        summary["per_type"][ip_type] = {
            "total": total,
            "mean_reward": s["reward_sum"] / total if total else 0.0,
            "mean_damage": s["damage_sum"] / total if total else 0.0,
            "actions": actions_pct,
            "mitigate_rate": mitigate_rate,
            "block_rate": block_rate,
        }

        if ip_type in ATTACKER_TYPES:
            g = groups["attacker"]
            g["total"] += total
            g["mitigate"] += sum(s["actions"][a] for a in (1, 2, 3))
            g["block"] += s["actions"][3]
        elif ip_type == "benign":
            g = groups["benign"]
            g["total"] += total
            g["mitigate"] += sum(s["actions"][a] for a in (1, 2, 3))
            g["block"] += s["actions"][3]
        elif ip_type == "noisy_normal":
            g = groups["noisy"]
            g["total"] += total
            g["mitigate"] += sum(s["actions"][a] for a in (1, 2, 3))
            g["block"] += s["actions"][3]
            g["ratelimit"] += s["actions"][1]

    summary["groups"] = {
        "attacker": {
            "mitigate_rate": (100.0 * groups["attacker"]["mitigate"] / groups["attacker"]["total"]
                              if groups["attacker"]["total"] else 0.0),
            "block_rate": (100.0 * groups["attacker"]["block"] / groups["attacker"]["total"]
                           if groups["attacker"]["total"] else 0.0),
            "total": groups["attacker"]["total"],
        },
        "benign": {
            "mitigate_rate": (100.0 * groups["benign"]["mitigate"] / groups["benign"]["total"]
                              if groups["benign"]["total"] else 0.0),
            "block_rate": (100.0 * groups["benign"]["block"] / groups["benign"]["total"]
                           if groups["benign"]["total"] else 0.0),
            "total": groups["benign"]["total"],
        },
        "noisy": {
            "mitigate_rate": (100.0 * groups["noisy"]["mitigate"] / groups["noisy"]["total"]
                              if groups["noisy"]["total"] else 0.0),
            "block_rate": (100.0 * groups["noisy"]["block"] / groups["noisy"]["total"]
                           if groups["noisy"]["total"] else 0.0),
            "ratelimit_rate": (100.0 * groups["noisy"]["ratelimit"] / groups["noisy"]["total"]
                               if groups["noisy"]["total"] else 0.0),
            "total": groups["noisy"]["total"],
        },
    }

    return summary


def judge_summary(summary: dict) -> list:
    """Return flat findings list with severity-like prefixes."""
    findings = []
    groups = summary["groups"]
    per_type = summary["per_type"]

    attacker_mit = groups["attacker"]["mitigate_rate"]
    benign_mit = groups["benign"]["mitigate_rate"]
    benign_block = groups["benign"]["block_rate"]
    noisy_rl = groups["noisy"]["ratelimit_rate"]
    noisy_block = groups["noisy"]["block_rate"]

    if attacker_mit < 95.0:
        findings.append(f"FAIL attacker mitigate_rate too low: {attacker_mit:.1f}% < 95%")
    else:
        findings.append(f"PASS attacker mitigate_rate: {attacker_mit:.1f}%")

    if benign_block > 0.0:
        findings.append(f"FAIL benign block_rate must be 0%, got {benign_block:.1f}%")
    else:
        findings.append("PASS benign block_rate: 0.0%")

    if benign_mit > 5.0:
        findings.append(f"WARN benign mitigate_rate high: {benign_mit:.1f}% > 5%")
    else:
        findings.append(f"PASS benign mitigate_rate: {benign_mit:.1f}%")

    if noisy_rl < 40.0:
        findings.append(f"FAIL noisy RateLimit recall too low: {noisy_rl:.1f}% < 40%")
    else:
        findings.append(f"PASS noisy RateLimit recall: {noisy_rl:.1f}%")

    if noisy_block > 5.0:
        findings.append(f"WARN noisy block_rate high: {noisy_block:.1f}% > 5%")
    else:
        findings.append(f"PASS noisy block_rate: {noisy_block:.1f}%")

    scan_block = per_type.get("scan", {}).get("block_rate", 0.0)
    syn_block = per_type.get("syn_flood", {}).get("block_rate", 0.0)
    brute_redirect = per_type.get("brute_force", {}).get("actions", {}).get("Redirect", 0.0)
    sqli_redirect = per_type.get("sqli_xss", {}).get("actions", {}).get("Redirect", 0.0)

    if scan_block < 95.0:
        findings.append(f"WARN scan block_rate low: {scan_block:.1f}%")
    else:
        findings.append(f"PASS scan block_rate: {scan_block:.1f}%")

    if syn_block < 95.0:
        findings.append(f"WARN syn_flood block_rate low: {syn_block:.1f}%")
    else:
        findings.append(f"PASS syn_flood block_rate: {syn_block:.1f}%")

    if brute_redirect < 90.0:
        findings.append(f"WARN brute_force redirect rate low: {brute_redirect:.1f}%")
    else:
        findings.append(f"PASS brute_force redirect rate: {brute_redirect:.1f}%")

    if sqli_redirect < 90.0:
        findings.append(f"WARN sqli_xss redirect rate low: {sqli_redirect:.1f}%")
    else:
        findings.append(f"PASS sqli_xss redirect rate: {sqli_redirect:.1f}%")

    return findings


def parse_args():
    parser = argparse.ArgumentParser(description="Preflight evaluator for PPO IDS models")
    parser.add_argument("--model", required=True, help="Path to .zip model")
    parser.add_argument("--episodes", type=int, default=50, help="Evaluation episodes (default: 50)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--json", action="store_true", help="Print raw JSON summary")
    return parser.parse_args()


def main():
    args = parse_args()
    if not os.path.exists(args.model):
        raise SystemExit(f"[ERROR] Model not found: {args.model}")

    summary = evaluate_model(args.model, episodes=args.episodes, seed=args.seed)
    findings = judge_summary(summary)

    print("=" * 80)
    print("PREFLIGHT EVALUATION")
    print("=" * 80)
    print(f"Model: {args.model}")
    print(f"Episodes: {summary['episodes']}")
    print(f"Mean Episode Reward: {summary['mean_episode_reward']:.4f}")
    print(f"Mean Episode Damage: {summary['mean_episode_damage']:.4f}")
    print("Action Rates: " + " | ".join(
        f"{name}={rate:.1f}%" for name, rate in summary["action_rates"].items()
    ))
    print()
    print("Group Metrics:")
    print(f"  Attacker: mitigate={summary['groups']['attacker']['mitigate_rate']:.1f}% | "
          f"block={summary['groups']['attacker']['block_rate']:.1f}%")
    print(f"  Benign:   mitigate={summary['groups']['benign']['mitigate_rate']:.1f}% | "
          f"block={summary['groups']['benign']['block_rate']:.1f}%")
    print(f"  Noisy:    mitigate={summary['groups']['noisy']['mitigate_rate']:.1f}% | "
          f"ratelimit={summary['groups']['noisy']['ratelimit_rate']:.1f}% | "
          f"block={summary['groups']['noisy']['block_rate']:.1f}%")
    print()
    print("Per-Type Action Distribution:")
    for ip_type in sorted(summary["per_type"]):
        actions = summary["per_type"][ip_type]["actions"]
        action_line = " | ".join(f"{name}={actions[name]:.1f}%" for name in ACTION_NAMES.values())
        print(f"  {ip_type:12s}: {action_line}")
    print()
    print("Preflight Checks:")
    for item in findings:
        print(f"  {item}")
    if args.json:
        print()
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
