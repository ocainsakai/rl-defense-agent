"""
Create an untrained (random) PPO model for demo purposes.

ACT 1 demo: Show AI "before learning" — random policy that can't distinguish
normal from attack traffic.

Usage:
    cd "AI RL"
    python3 create_random_model.py
    # → saves random_model.zip
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'System'))

from stable_baselines3 import PPO
from env_ids import IDSDefenseEnv

env = IDSDefenseEnv()
model = PPO('MlpPolicy', env, verbose=0)
# KHÔNG gọi model.learn() → random policy (weights initialized but not trained)
model.save('random_model')
print("[+] Saved random_model.zip (untrained — random policy)")
print("    Use with: infer.py --model random_model ...")
