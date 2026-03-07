# Escalation Verification Test - Current Code Summary

**Test Date**: 2026-01-14T12:11:48

**Configuration**:
- Episodes: 30
- Seed: 42
- Model: Random policy
- Total steps: 3600

---

## Critical Questions: Persistence Observability

### Q1: Is `persistence_score` observable by the policy?

**Answer**: [NO]

**Evidence**:
```python
# env_ids.py:900 - Observation space definition
self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(6,), dtype=np.float32)

# env_ids.py:131 - Observation vector composition (FROZEN ORDER)
obs = np.array([PR, SA, DP, PL, FR, CS], dtype=np.float32)
# [packet_rate, syn_ack_ratio, distinct_ports, payload_len, conn_fail_rate, context_score]
```

**Observation space shape**: `(6,)` (6 features)

**Conclusion**: The observation vector contains only `[PR, SA, DP, PL, FR, CS]`. `persistence_score` is tracked internally (`env_ids.py:435`, `traffic_simulator.py:92`) but is **NOT included** in the observation space. The policy cannot see it.

---

### Q2: Is `persistence_score` used in reward shaping?

**Answer**: [NO]

**Evidence**:
```python
# env_ids.py:1068-1116 - _compute_reward() function
def _compute_reward(self, action: int, features_before: Dict, features_after: Dict):
    damage_before = compute_network_damage(features_before)
    damage_after = compute_network_damage(features_after)
    action_cost = compute_action_cost(action)
    base_reward = -(damage_after + action_cost)
    reduction_bonus = (damage_before - damage_after) * 0.5
    context_score = features_before.get('context_score', 0.0)
    action_bonus = compute_action_bonus(action, context_score, damage_before)
    # NOTE: persistence_score is NOT used here
    total_reward = base_reward + reduction_bonus + action_bonus
    return np.clip(total_reward, -1.0, 0.0)
```

**Conclusion**: The reward function uses `context_score` and `damage` but does **NOT** incorporate `persistence_score`. The `compute_action_bonus()` function (`env_ids.py:263-408`) also does not accept or use `persistence_score`.

---

## Overall Action Distribution

| Action | Count | Percentage |
|--------|-------|------------|
| Allow | 843 | 23.4% |
| RateLimit | 923 | 25.6% |
| Redirect | 887 | 24.6% |
| Block | 947 | 26.3% |

## Per-IP-Type Analysis

### IP Type: `layer7_stealth`

**Total steps**: 540

#### Early Window (First 20% of steps)

- **Steps**: 108
- **Avg persistence_score**: 0.0115
- **Action distribution**:
  - Allow: 30 (27.8%)
  - RateLimit: 33 (30.6%)
  - Redirect: 30 (27.8%)
  - Block: 15 (13.9%)

#### Late Window (Last 20% of steps)

- **Steps**: 108
- **Avg persistence_score**: 0.0039
- **Action distribution**:
  - Allow: 24 (22.2%)
  - RateLimit: 29 (26.9%)
  - Redirect: 25 (23.1%)
  - Block: 30 (27.8%)

#### Escalation Pattern Analysis

**Question**: Does Redirect frequency increase before Block as persistence grows?

- Early Redirect: 27.8% (persistence=0.0115)
- Late Redirect: 23.1% (persistence=0.0039)
- Early Block: 13.9%
- Late Block: 27.8%

[WARNING] **No persistence growth**: Persistence did not increase from early to late window

---

### IP Type: `mimicry_attackers`

**Total steps**: 360

#### Early Window (First 20% of steps)

- **Steps**: 72
- **Avg persistence_score**: 0.0178
- **Action distribution**:
  - Allow: 13 (18.1%)
  - RateLimit: 26 (36.1%)
  - Redirect: 17 (23.6%)
  - Block: 16 (22.2%)

#### Late Window (Last 20% of steps)

- **Steps**: 72
- **Avg persistence_score**: 0.0144
- **Action distribution**:
  - Allow: 15 (20.8%)
  - RateLimit: 16 (22.2%)
  - Redirect: 22 (30.6%)
  - Block: 19 (26.4%)

#### Escalation Pattern Analysis

**Question**: Does Redirect frequency increase before Block as persistence grows?

- Early Redirect: 23.6% (persistence=0.0178)
- Late Redirect: 30.6% (persistence=0.0144)
- Early Block: 22.2%
- Late Block: 26.4%

[WARNING] **No persistence growth**: Persistence did not increase from early to late window

---

## Conclusion

### Environment Design Support for Escalation

| Feature | Status | Evidence |
|---------|--------|----------|
| `persistence_score` variable exists | [YES] | `env_ids.py:435`, `traffic_simulator.py:92` |
| `persistence_score` in observation | [NO] | Observation shape=(6,), only [PR,SA,DP,PL,FR,CS] |
| `persistence_score` in reward | [NO] | `_compute_reward()` does not use it |
| Zone-based action bonuses | [YES] | `compute_action_bonus()` env_ids.py:263-408 |
| Temporal escalation signals | [NO] | Policy cannot observe repeated offenses |

### Policy Capability

**Can a trained PPO model learn persistence-based escalation?**

[NO] - The policy cannot learn to escalate based on repeated offenses because:

1. `persistence_score` is not exposed in the observation vector
2. Reward does not vary based on repeated offenses from the same IP
3. Each step samples a different IP (round-robin), losing temporal continuity

The policy can only react to **instantaneous** features (context_score, damage) but cannot track **temporal patterns** (repeated offenses over time).

---

## Recommendations

To enable persistence-based escalation, the **minimum changes** required are:

1. **Add `persistence_score` to observation vector**:
   ```python
   # env_ids.py:131 - Expand observation to 7 features
   obs = np.array([PR, SA, DP, PL, FR, CS, persistence_score], dtype=np.float32)
   self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(7,), dtype=np.float32)
   ```

2. **Incorporate `persistence_score` in reward shaping**:
   ```python
   # env_ids.py:1106 - Pass persistence to action bonus
   action_bonus = compute_action_bonus(action, context_score, damage_before, persistence_score)
   ```

3. **Update `compute_action_bonus()` to penalize early Block**:
   ```python
   # env_ids.py:263 - Add persistence parameter
   def compute_action_bonus(action, cs, damage, persistence=0.0):
       # Penalize Block when persistence is low (early offense)
       if action == 3 and persistence < 0.3:
           bonus -= 0.30  # Strong penalty for premature Block
   ```

