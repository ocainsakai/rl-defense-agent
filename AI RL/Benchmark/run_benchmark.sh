#!/usr/bin/env bash
# Full Benchmark Pipeline — Run from AI RL/Benchmark/
# Total time: ~75 min (19 seeds × ~4 min/seed)
#
# Usage:
#   cd "AI RL/Benchmark"
#   chmod +x run_benchmark.sh
#   ./run_benchmark.sh

set -e
cd "$(dirname "$0")"

echo "========================================"
echo "RL BENCHMARK — Full Training Pipeline"
echo "========================================"

# Step 1: Train PPO-Tuned seed42 (harder env — not copying from run_final_v4)
if [ ! -f models/ppo_tuned_seed42.zip ]; then
    echo "[*] Training PPO-Tuned seed42 on harder env..."
    python3 train_ppo_tuned.py --seed 42
else
    echo "[+] models/ppo_tuned_seed42.zip already exists — skip"
fi

# Step 2: Train PPO-Tuned seeds 123, 456, 789, 1337
echo ""
echo "[STEP 2] Training PPO-Tuned (4 additional seeds)..."
for seed in 123 456 789 1337; do
    if [ ! -f "models/ppo_tuned_seed${seed}.zip" ]; then
        echo "  [*] ppo_tuned seed=$seed"
        python3 train_ppo_tuned.py --seed $seed
    else
        echo "  [+] ppo_tuned seed=$seed already exists — skip"
    fi
done

# Step 3: Train PPO-Default × 5 seeds
echo ""
echo "[STEP 3] Training PPO-Default (5 seeds)..."
for seed in 42 123 456 789 1337; do
    if [ ! -f "models/ppo_default_seed${seed}.zip" ]; then
        echo "  [*] ppo_default seed=$seed"
        python3 train_ppo_default.py --seed $seed
    else
        echo "  [+] ppo_default seed=$seed already exists — skip"
    fi
done

# Step 4: Train A2C × 5 seeds
echo ""
echo "[STEP 4] Training A2C (5 seeds)..."
for seed in 42 123 456 789 1337; do
    if [ ! -f "models/a2c_seed${seed}.zip" ]; then
        echo "  [*] a2c seed=$seed"
        python3 train_a2c.py --seed $seed
    else
        echo "  [+] a2c seed=$seed already exists — skip"
    fi
done

# Step 5: Train DQN × 5 seeds
echo ""
echo "[STEP 5] Training DQN (5 seeds)..."
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
echo "[STEP 6] Running Unified Evaluation..."
echo "========================================"
python3 evaluate_all.py

echo ""
echo "========================================"
echo "[STEP 7] Generating Charts..."
echo "========================================"
python3 plot_results.py

echo ""
echo "========================================"
echo "BENCHMARK COMPLETE"
echo "Results: results/benchmark_results.json"
echo "Charts:  charts/*.png"
echo "========================================"
