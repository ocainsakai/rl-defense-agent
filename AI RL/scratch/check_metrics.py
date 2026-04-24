import numpy as np

def check_npz(path):
    print(f"\nChecking: {path}")
    data = np.load(path)
    for key in data.keys():
        val = data[key]
        if hasattr(val, 'mean'):
            print(f"{key}: shape={val.shape}, mean={val.mean():.4f}, last={val[-1].mean():.4f}")
        else:
            print(f"{key}: {val}")

check_npz(r'c:\Users\VyVa\Documents\GitHub\rl-defense-agent\AI RL\runs\run_34d_v13\evaluations.npz')
check_npz(r'c:\Users\VyVa\Documents\GitHub\rl-defense-agent\AI RL\runs\run_final_v4\evaluations.npz')
