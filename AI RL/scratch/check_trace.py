import json
from collections import defaultdict

def analyze_trace(path):
    stats = defaultdict(lambda: {'total': 0, 'mitigated': 0, 'blocked': 0})
    action_counts = defaultdict(int)
    
    with open(path, 'r') as f:
        for line in f:
            data = json.loads(line)
            ip_type = data['ip_type']
            action = data['action']
            action_name = data['action_name']
            
            # Map ip_type to groups
            group = 'Unknown'
            if ip_type in ['benign', 'benign_upload']:
                group = 'Benign'
            elif ip_type in ['noisy_normal', 'grayzone']:
                group = 'Noisy'
            elif ip_type in ['syn_flood', 'scan', 'brute_force', 'sqli_xss', 'mimicry_attacker', 'layer7_stealth']:
                group = 'Attacker'
            
            stats[group]['total'] += 1
            action_counts[action_name] += 1
            
            # Mitigation: any non-Allow action for Attacker
            # For Benign/Noisy, "mitigated" means Redirect/RateLimit/Block?
            # Actually, let's just count Actions
            if action != 0: # Not Allow
                stats[group]['mitigated'] += 1
            if action == 3: # Block
                stats[group]['blocked'] += 1
                
    print("\nTraffic Group Analysis:")
    for group, s in stats.items():
        mit_rate = s['mitigated'] / s['total'] * 100 if s['total'] > 0 else 0
        block_rate = s['blocked'] / s['total'] * 100 if s['total'] > 0 else 0
        print(f"  {group}: Mitigate={mit_rate:.1f}%, Block={block_rate:.1f}%, Total={s['total']}")
        
    total_actions = sum(action_counts.values())
    print("\nAction Distribution:")
    for action, count in action_counts.items():
        print(f"  {action}: {count / total_actions * 100:.1f}%")

analyze_trace(r'c:\Users\VyVa\Documents\GitHub\rl-defense-agent\AI RL\runs\escalation_current_trace.jsonl')
