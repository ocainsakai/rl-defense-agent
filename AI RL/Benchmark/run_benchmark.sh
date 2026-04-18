#!/usr/bin/env bash
# Full Benchmark Pipeline — PPO vs A2C vs DQN vs Rule-Based
# Track: sb3_strict_default_final_primary
# Env: env_ids_harder.py (34D, missing_prob=0.08, drift_max=0.35)
# 3 algos × 5 seeds = 15 training runs (~45-60 min total)
# n_envs=1 for all algos — strict fair comparison
#
# Usage:
#   cd "AI RL/Benchmark"
#   chmod +x run_benchmark.sh
#   ./run_benchmark.sh

set -e
cd "$(dirname "$0")"

echo "========================================"
echo "RL BENCHMARK — PPO vs A2C vs DQN"
echo "Track: sb3_strict_default_final_primary"
echo "Env: env_ids_harder (34D, harder params)"
echo "n_envs=1, checkpoint=final (not best)"
echo "========================================"

# Step 1: Train PPO × 5 seeds
echo ""
echo "[STEP 1] Training PPO (5 seeds)..."
for seed in 42 123 456 789 1337; do
    if [ ! -f "models/ppo_seed${seed}.zip" ]; then
        echo "  [*] ppo seed=$seed"
        python3 train_ppo_default.py --seed $seed
    else
        echo "  [+] ppo seed=$seed already exists — skip"
    fi
done

# Step 2: Train A2C × 5 seeds
echo ""
echo "[STEP 2] Training A2C (5 seeds)..."
for seed in 42 123 456 789 1337; do
    if [ ! -f "models/a2c_seed${seed}.zip" ]; then
        echo "  [*] a2c seed=$seed"
        python3 train_a2c.py --seed $seed
    else
        echo "  [+] a2c seed=$seed already exists — skip"
    fi
done

# Step 3: Train DQN × 5 seeds
echo ""
echo "[STEP 3] Training DQN (5 seeds)..."
for seed in 42 123 456 789 1337; do
    if [ ! -f "models/dqn_seed${seed}.zip" ]; then
        echo "  [*] dqn seed=$seed"
        python3 train_dqn.py --seed $seed
    else
        echo "  [+] dqn seed=$seed already exists — skip"
    fi
done

echo ""
echo "========================================"
echo "[STEP 4] Running Unified Evaluation..."
echo "========================================"
python3 evaluate_all.py

echo ""
echo "========================================"
echo "[STEP 5] Generating Charts..."
echo "========================================"
python3 plot_results.py

echo ""
echo "========================================"
echo "BENCHMARK COMPLETE"
echo "Results: results/benchmark_results.json"
echo "Charts:  charts/*.png"
echo "========================================"
