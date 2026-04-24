import json

def summarize_benchmark(path):
    with open(path, 'r') as f:
        data = json.load(f)
    
    # Structure is usually { "Algorithm": { "Mode": { "metric": [values] } } }
    # Let's find round_robin metrics
    for algo, modes in data.items():
        if 'round_robin' in modes:
            rr = modes['round_robin']
            print(f"\nAlgo: {algo}")
            for metric, vals in rr.items():
                if isinstance(vals, list) and len(vals) > 0:
                    print(f"  {metric}: {sum(vals)/len(vals):.4f}")

summarize_benchmark(r'c:\Users\VyVa\Documents\GitHub\rl-defense-agent\AI RL\Benchmark\results\benchmark_results.json')
