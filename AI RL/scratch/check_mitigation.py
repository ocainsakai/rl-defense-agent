import json

def extract_rates(path):
    with open(path, 'r') as f:
        data = json.load(f)
    
    for algo in ['ppo', 'dqn', 'a2c']:
        if algo in data:
            rr_seeds = data[algo]['round_robin']
            mit_rates = [seed_data['mitigation_rate'] for seed_data in rr_seeds.values()]
            avg_mit = sum(mit_rates) / len(mit_rates)
            print(f"{algo} Mitigation Rate: {avg_mit:.2f}%")

extract_rates(r'c:\Users\VyVa\Documents\GitHub\rl-defense-agent\AI RL\Benchmark\results\benchmark_results.json')
