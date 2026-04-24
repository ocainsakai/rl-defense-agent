# Source Document — Schematic Model: RL-Based Network Defense System

## Diagram Requirements

This document provides the information needed to draw a **Schematic Model** (system-level architecture diagram) for a capstone project. The diagram should illustrate:

### Primary Goal
Present the **complete data flow** of a reinforcement learning-based network defense system — from raw network traffic entering the system to defensive actions being enforced, including all closed-loop feedback mechanisms.

### KEY FOCUS: Closed-Loop Mechanism, Reward Impact, and the 14 Enrichment Features

When explaining or diagramming this system, **prioritize the following three aspects** above all else:

#### Focus 1 — The Closed-Loop Mechanism (Section 4)
The core innovation is that this is NOT a one-way detection pipeline. The system forms **3 nested feedback loops** where the Agent's defensive action changes the network environment, which in turn changes the Agent's next observation. Explain clearly:
- **Loop 1 (Real-time, 1s cycle)**: Action at second N → traffic changes → NIDS observes the change at second N+1 → Agent adjusts. This means the Agent is always reacting to consequences of its own previous decisions.
- **Loop 2 (Effect feedback, 1-step delay)**: Nginx logs tell the Agent whether its last action actually worked — did the redirect succeed? Did the block stop the attacker? This feedback is embedded directly into the next observation (F21–F24).
- **Loop 3 (Continuous learning, batch)**: Over hours/days, the system collects real-world decisions, auto-labels them, and retrains the model — allowing it to adapt to attack patterns it has never seen during initial training.

The closed-loop design means the Agent must learn a **strategy**, not just a classification rule. It must consider: "If I redirect now, the attacker will adapt, so what should I do 3 steps later?"

#### Focus 2 — How the Reward System Shapes Agent Behavior (Section 6)
The reward function is the "teacher" that determines WHAT the Agent learns. Explain how each component drives specific behaviors:
- **Base reward (damage reduction)**: Teaches the Agent that the goal is to reduce harm, not just detect attacks.
- **Action cost (Allow=0, RateLimit=0.01, Redirect=0.04, Block=0.15)**: Teaches the Agent to prefer the **lightest effective action**. Without this, the Agent would learn to block everything — safe but destructive to legitimate users.
- **Zone-based bonus**: Teaches the Agent to match the **right action to the right attack type** (e.g., Block for DDoS, Redirect for SQLi, Rate Limit for noisy traffic, Allow for normal).
- **Premature block penalty (−0.20)**: Teaches the Agent to **be patient** — gather evidence via honeypot before blocking. This is what drives the escalation behavior.
- **False positive penalty (−0.60)**: The harshest penalty. Teaches the Agent that blocking a normal user is the worst mistake, worse than allowing an attack to continue temporarily.

The reward structure creates a hierarchy of priorities: (1) never block normal users, (2) use proportional force, (3) gather evidence before escalating, (4) minimize damage.

#### Focus 3 — The 14 Enrichment Features and Their Impact (Section 3, Stage 7)
The NIDS produces 20 features describing "what is happening on the network right now." But 20 features alone lead to poor decisions because the Agent has no memory and no awareness of its own actions. The **14 enrichment features** (10 temporal + 4 effect) solve this:

**10 Temporal State features — Give the Agent "memory":**
- Previous action (4D one-hot): Without this, the Agent doesn't know what it did last step. With it, the Agent can reason: "I'm already rate-limiting, should I escalate?"
- Action hold duration (1D): Without this, the Agent flip-flops between actions every second. With it, the Agent learns stability — holding an action long enough to see its effect.
- Damage trend (2D — EMA + direction): Without this, the Agent only sees a snapshot. With it, the Agent can see: "damage is decreasing, my current action is working, stay the course."
- Session progress (1D): Without this, every step looks identical. With it, the Agent knows how long it has been monitoring — useful for deciding when enough evidence has been gathered.
- Escalation score (1D): Without this, the Agent has no way to know if it has earned the "right" to block. With it, the Agent can see a score from 0 to 1 representing how much evidence has been accumulated via the honeypot.
- Miss budget (1D): Without this, the Agent doesn't know how many mistakes it has made. With it, the Agent becomes more cautious as it approaches the error limit.

**4 Effect Feedback features — Tell the Agent "did my action work?":**
- Web hit ratio (F21): If high after a Block → the block isn't working (maybe wrong IP or evasion).
- Honeypot hit ratio (F22): If high after a Redirect → the redirect is successfully trapping the attacker.
- Presence (F23): If 0 after a Block → attacker has given up. If 1 → attacker is still trying.
- Service damage (F24): The ultimate metric — is the protected service still being harmed?

**Why this matters**: Without the 14 enrichment features, the Agent is essentially a stateless classifier ("see attack → block"). With them, the Agent becomes a **stateful strategist** that considers its own history, evaluates the effectiveness of past actions, and plans multi-step responses (detect → redirect to honeypot → collect evidence → block only when confident).

### Required Diagram Components

1. **Physical Network Infrastructure** (Section 2): Network topology with 4 nodes (Attacker, Router, Webserver, Honeypot), their IP addresses, and interconnections. The Router is the central hub hosting both the NIDS and the firewall.

2. **Data Processing Pipeline** (Section 3): A chain of 9 transformation stages. Each stage should show:
   - Input data (format, dimensionality)
   - Transformation applied (aggregation, extraction, normalization, enrichment)
   - Output data (format, dimensionality)
   - Key highlight: **data changes shape** at every stage (bytes → structured record → flow → 20D vector → 34D vector → action → firewall rule)

3. **3 Feedback Loops** (Section 4): Clearly depict 3 nested loops:
   - Real-time inference loop (1-second cycle)
   - Effect feedback loop (1-step delayed, from nginx logs)
   - Continuous learning loop (batch: collect → label → retrain)

4. **Escalation Mechanism** (Section 5): Show how the Agent accumulates evidence via the honeypot before being permitted to block — this is the system's distinguishing design feature.

5. **Action Space** (Section 3, Stages 8–9): The 4 defensive actions (Allow / Rate Limit / Redirect / Block) and their corresponding firewall effects.

### Diagram Style
- Focus on **logical data flow**, not implementation details (no code, function names, or filenames)
- Use labeled arrows to describe data moving between blocks
- Distinguish **primary flow** (solid lines) from **feedback loops** (dashed lines)
- Annotate key blocks with bilingual terms (English–Vietnamese) where appropriate
- The glossary in Section 10 defines all terminology used

### Detailed Data Below

All information required to draw an accurate diagram is contained in the 10 sections below. Pay special attention to:
- **Section 2**: Network topology and IP addresses
- **Section 3**: 9 data transformation stages (most critical section), **especially Stage 7 (Context Enrichment — the 14 new features)**
- **Section 4**: 3 closed-loop feedback mechanisms **(highest priority)**
- **Section 5**: Escalation mechanism (distinguishing design feature)
- **Section 6**: Reward system **(high priority — explains WHY the Agent behaves the way it does)**
- **Section 9**: Pipeline summary (quick reference)
- **Section 10**: Glossary (for diagram annotations)

---

## 1. System Overview

The system consists of 3 main components operating in sequence:

- **NIDS** (Network Intrusion Detection System): Captures network traffic, parses each packet, aggregates them into time-windowed flows, and extracts 20 behavioral features from each flow. Results are written to a JSONL file.
- **RL Agent** (Reinforcement Learning Agent): Reads the JSONL file from NIDS, enriches it with context (action history, defense effectiveness), and feeds it into a PPO model to select the optimal defensive action.
- **Enforcement**: Applies the selected action to the router's iptables firewall, directly affecting network traffic.

These three components form a **closed loop**: defensive action changes traffic → NIDS observes the change → RL Agent adjusts the next action.

---

## 2. Simulated Network Infrastructure

The system is deployed on a Mininet-based simulated network with the following components:

- **Attacker**: Machine at 10.0.10.10, acting as the attack source.
- **Router**: Sits between the attacker and internal servers. Runs NIDS for traffic monitoring and hosts iptables for enforcement. Has 3 network interfaces connecting to 3 subnets:
  - External interface (r-ext, 10.0.10.254): connects to the attacker
  - Web interface (r-web, 192.168.10.1): connects to the webserver
  - Honeypot interface (r-honey, 192.168.30.1): connects to the honeypot
- **Webserver**: At 192.168.10.10, port 8080. The real target to protect.
- **Honeypot**: At 192.168.30.10, port 8081. A decoy server used to lure attackers when redirected.

The Router runs an nginx reverse proxy: ports 80/443 forward to the real webserver, port 4443 forwards to the honeypot. When the RL Agent selects "Redirect", iptables changes the destination port from 443 to 4443, silently diverting the attacker to the trap.

---

## 3. Main Data Flow — From Raw Packets to Defensive Action

### Stage 1: Packet Capture

NIDS listens on the Router's external interface (r-ext), capturing all passing packets. Two parallel capture streams operate simultaneously:

- **Primary stream**: Uses the Scapy library to capture packets at the network layer (L3/L4 — IP, TCP, UDP).
- **Secondary stream** (optional): Uses tshark to decrypt HTTPS traffic. When traffic is TLS-encrypted, tshark requires a session key file (SSLKEYLOGFILE) to read the HTTP content within. This stream has a maximum grace period of 600ms to wait for decryption keys.

Packets from both streams are placed into a **Packet Queue** — a thread-safe buffer holding up to 10,000 packets, ensuring no packet loss when processing is slower than the network rate.

### Stage 2: Packet Parsing

Each raw packet is unpacked to extract structured information called **LayerInfo**. This process extracts:

- **Network layer (IP)**: Source address, destination address, protocol (TCP/UDP/ICMP)
- **Transport layer (TCP/UDP)**: Source port, destination port, TCP flags (SYN, ACK, RST, FIN)
- **Application layer (HTTP)**: Method (GET/POST), URL path, User-Agent, body content
- **Composite payload**: The system concatenates URL + User-Agent + Body into a single string for application-layer attack analysis (SQLi, XSS).

Result: from a block of raw bytes, we obtain a structured record containing full information from network to application layer.

### Stage 3: Flow Aggregation

This is the most critical transformation step. A single packet cannot reveal behavior — like watching a single footstep without knowing if someone is walking or running.

The system groups packets belonging to the same connection into a **flow**. Each flow is identified by a **5-tuple**: source IP, destination IP, source port, destination port, and protocol. For example: all packets from 10.0.10.10:45678 to 192.168.10.10:443 over TCP belong to the same flow.

Each flow maintains two queues:
- **Forward packets**: packets from source to destination (e.g., requests from the attacker)
- **Backward packets**: packets from destination to source (e.g., responses from the server)

Key design: the system only retains packets within the **most recent 1-second window**. Packets older than 1 second are automatically discarded. This means at any moment, each flow contains only a 1-second "slice" of the connection — this is the fundamental time unit of the entire system.

### Stage 4: Feature Extraction

From the flow state (containing potentially hundreds of packets within 1 second), the system computes **20 behavioral metrics** (a 20-dimensional feature vector). Each metric reflects a different aspect of network behavior:

**Network Group (11 features — F1 through F11)**: Measure network and transport layer traffic characteristics.

| Code | Name | Meaning | Attack Indicator |
|------|------|---------|-----------------|
| F1 | PacketRate | Packets per second | DDoS: very high rate (>100 pps) |
| F2 | SynAckRatio | SYN packets divided by ACK packets | SYN Flood: very high ratio (>5) because attacker sends SYN without completing the handshake |
| F3 | InterArrivalTime | Average time between consecutive packets | Automated bot: very uniform intervals |
| F4 | RstRatio | Percentage of packets carrying the RST (Reset) flag | Port Scan: server rejects many connections → many RSTs |
| F5 | DistinctPorts | Number of distinct destination ports in the window | Port Scan: probing dozens of ports simultaneously |
| F6 | URLConcentration | Fraction of requests targeting the same URL | Brute Force: repeatedly hitting the same login page |
| F7 | HttpIatUniformity | Uniformity of intervals between HTTP requests | Bot: very uniform timing; real users are random |
| F8 | RequestSizeUniformity | Uniformity of request payload sizes | Bot: identical payloads; real users vary |
| F9 | AvgPayloadSize | Average packet payload size (bytes) | SYN Flood: very small; Upload attack: very large |
| F10 | FwdBwdRatio | Forward packets divided by backward packets | DDoS: very high ratio — sending without receiving responses |
| F11 | PacketsPerPort | Average packets sent to each port | DDoS: many packets/port; Scan: few packets/port but many ports |

**SQLi Group (6 features — F12 through F17)**: Analyze payload content to detect SQL Injection attacks.

| Code | Name | Meaning | Attack Indicator |
|------|------|---------|-----------------|
| F12 | SqlSpecialChar | Ratio of SQL-special characters in payload (', ", ;, --, #) | SQLi: high ratio of special characters |
| F13 | CrsSqliScore | Score from ModSecurity CRS ruleset | SQLi: high score (>5) |
| F14 | SqlUnionSelect | Contains UNION SELECT syntax | SQLi: present (=1) → attempting data exfiltration |
| F15 | SqlComment | Contains comment markers (--, #, /* */) | SQLi: present (=1) → attempting to neutralize the rest of the SQL statement |
| F16 | SqlStackedQuery | Contains semicolons (;) for chaining multiple SQL statements | SQLi: present (=1) → attempting multi-statement execution |
| F17 | SqlSelectCount | Number of SELECT keyword occurrences in payload | SQLi: multiple SELECTs → attempting data queries |

**XSS Group (3 features — F18 through F20)**: Analyze payload to detect Cross-Site Scripting attacks.

| Code | Name | Meaning | Attack Indicator |
|------|------|---------|-----------------|
| F18 | CrsXssScore | Score from ModSecurity CRS ruleset for XSS | XSS: high score (>1) |
| F19 | JsFunctionCall | Contains dangerous function calls (alert, eval, document.cookie) | XSS: present (=1) → attempting JavaScript execution |
| F20 | HtmlEventHandler | Contains event handler attributes (onload, onerror, onclick) | XSS: present (=1) → attempting to attach JavaScript to HTML events |

### Stage 5: Normalization

The 20 features have vastly different units and ranges — F1 can reach 500 (packets/sec), F4 is in [0,1], F13 ranges from 0–20. To allow the AI model to compare them, all are scaled to **the same [0, 1] range** using three methods:

- **Logarithmic scale** (for F1, F2, F3, F5, F10, F11): Used for features with very wide value ranges. For example, F1 (packet rate) can range from 1 to 500, but the difference between 1 and 50 is far more significant than between 400 and 500. The log scale compresses high values while preserving sensitivity in the low range.
- **Linear scale** (for F9, F13, F17, F18): Divides by a fixed ceiling. For example, F13 (SQLi score) is divided by 20; values exceeding 20 are clipped to 1.0.
- **Pass-through** (for F4, F6, F7, F8, F12, F14–F16, F19, F20): Features already in the [0,1] range (percentages or binary yes/no values).

Result: a **20-dimensional vector**, each dimension in [0, 1].

### Stage 6: JSONL Serialization

The feature vector and metadata are written to `/tmp/sniffer_output.jsonl`. Each line is a JSON record containing:
- Timestamp
- Source IP address (src_ip)
- 20 raw (un-normalized) feature values
- Metadata about HTTPS decryption quality

This is the **interface** between NIDS and RL Agent — the two components communicate through this file. This allows them to run independently: NIDS writes, RL Agent reads.

### Stage 7: Context Enrichment

The RL Agent reads the JSONL file and normalizes the 20 features. But 20 dimensions are insufficient for good decisions — the Agent needs additional **context** to fully understand the situation.

**Temporal State (10 additional dimensions)**:
- **Previous action** (4 dimensions, one-hot encoded): Encodes the last action chosen. For example, if the previous action was "Redirect", the vector is [0, 0, 1, 0]. Helps the Agent know its current state.
- **Action hold duration** (1 dimension): How many consecutive steps the current action has been held. Prevents the Agent from constantly changing its mind.
- **Damage trend** (2 dimensions): Average damage (EMA) and direction of change (increasing or decreasing). Helps the Agent know if the situation is improving or worsening.
- **Session progress** (1 dimension): How many observation windows have been collected in the current monitoring session.
- **Escalation score** (1 dimension): Level of accumulated evidence indicating this is a serious attack requiring action escalation (see Section 5).
- **Miss budget** (1 dimension): Number of times the Agent chose the wrong action in the current session, divided by the maximum threshold.

**Effect Feedback (4 additional dimensions)**:
This information comes from the nginx access log on the Router, **delayed by 1 step** relative to the action:
- **Web hit ratio** (F21): Percentage of requests reaching the real webserver. High → defense is not effective.
- **Honeypot hit ratio** (F22): Percentage of requests diverted to the trap. High → redirect is working.
- **Presence** (F23): Whether the attacker sent any requests in the past second (0 or 1).
- **Service damage** (F24): Composite of attack intensity and defense penetration rate.

Result: a **34-dimensional vector** = 20 (NIDS) + 10 (temporal) + 4 (effect). This is the actual input to the RL model.

### Stage 8: RL Agent Decision

The PPO (Proximal Policy Optimization) model receives the 34-dimensional vector and selects **1 of 4 actions**:

| ID | Action | When Used | Cost |
|----|--------|-----------|------|
| 0 | Allow | Normal traffic, no attack indicators | None |
| 1 | Rate Limit | Mildly suspicious traffic, "noisy" user but not confirmed attack | Very low |
| 2 | Redirect | Application-layer attack (SQLi, XSS, Brute Force) — divert attacker to honeypot for evidence collection | Low |
| 3 | Block | DDoS, port scan, or after sufficient evidence collected from honeypot | High |

**Cost** reflects severity: full blocking can affect legitimate users, so the Agent is "penalized" more for choosing Block. This forces the Agent to carefully consider before choosing a strong action.

**Safety Override**: Beyond the model's decision, 3 hard safety rules apply:
- If SQLi/XSS is detected but the model chooses Allow → Force override to Redirect
- If SQLi/XSS is detected but the model chooses Block too early (insufficient evidence) → Downgrade to Redirect
- If currently Blocking and the attacker is still present → Do not allow action downgrade

### Stage 9: Firewall Enforcement

The action is translated into iptables commands on the Router:

| Action | iptables Command | Real-World Effect |
|--------|-----------------|-------------------|
| Allow | Delete all rules for this IP | Traffic passes normally |
| Rate Limit | Add hashlimit rule at 2 packets/sec | Only 2 packets/sec pass through; rest are dropped |
| Redirect | Add REDIRECT rule port 443→4443 | Requests silently diverted to honeypot |
| Block | Add DROP rule | All packets silently dropped; attacker disconnected |

iptables commands are executed inside the Router's network namespace via nsenter — a Linux tool that runs commands inside another process's namespace.

---

## 4. Closed-Loop Feedback

The system has **3 nested feedback loops**:

### Loop 1: Real-Time Inference Loop

Cycle: **every 1 second**

```
NIDS captures network traffic
→ Extracts 20 behavioral features
→ Writes to JSONL
→ RL Agent reads, enriches with context (34 dimensions)
→ PPO model selects action
→ Applies iptables to router
→ Network traffic changes (blocked, limited, or redirected)
→ NIDS observes the change in the next cycle
→ Return to start
```

This loop runs continuously, once per second. The action at second N affects the observation at second N+1. This is the "closed loop" — the Agent not only observes but also **acts back** on the environment.

### Loop 2: Effect Feedback Loop

Cycle: **1-step delayed relative to Loop 1**

Nginx on the Router logs every HTTP request. The RL Agent reads this log to determine whether the previous action was effective:
- After choosing "Redirect": check if requests actually reached the honeypot (F22 increased?)
- After choosing "Block": check if the attacker stopped sending requests (F23 decreased?)
- After choosing "Allow": check if the webserver was affected (F24 increased?)

This information (4 dimensions) is fed into the observation at the next step, enabling the Agent to self-evaluate and adjust.

### Loop 3: Continuous Learning Loop

Cycle: **batch-based, after hours/days of deployment**

Consists of 3 steps:
1. **Collection**: During live operation, the Agent logs every decision to a file (features, chosen action, measured effectiveness).
2. **Auto-labeling**: A separate program analyzes collected data and assigns attack labels based on heuristic rules. For example: if CRS SQLi score > 5 → label "sqli"; if packet rate > 100 and SYN/ACK ratio > 5 → label "syn_flood".
3. **Retraining**: Labeled data is used to continue training the model, starting from the current model (warm-start). Each cycle adds 50,000 new training steps.

This loop allows the system to **adapt** to new attack patterns encountered in the field.

---

## 5. Escalation Mechanism

This is a distinctive design feature: the Agent does not jump directly from "Allow" to "Block". Instead, it must **accumulate evidence** before being permitted to block.

**Escalation process for application-layer attacks (SQLi/XSS)**:

1. **L7 signal detection**: NIDS detects anomalous F12–F20 → Agent selects "Redirect" (divert to honeypot)
2. **Evidence accumulation**: Throughout the redirection, the system tracks metrics over a 15-step sliding window:
   - How many times has redirection been applied? (redirect_hits)
   - How many times did the attacker actually reach the honeypot? (honeypot_hits)
   - Is the attacker still present? (presence_hits)
   - Did the Agent miss any opportunities? (miss_count)
3. **Escalation score**: All factors above are combined into a single score [0, 1]
4. **Block condition**: Only when sufficient thresholds are met (≥6 redirects, ≥5 honeypot captures, escalation score ≥0.60), the Agent is permitted to select "Block"
5. **Premature blocking is penalized**: If "Block" is chosen before sufficient evidence → counted as a mistake, Agent is penalized

Significance: the honeypot is not just a trap — it is an **evidence collection tool**. The Agent uses the honeypot to confirm the threat is real before blocking entirely.

---

## 6. Reward System for Training

During training, the Agent learns through trial and error. At each step, it receives a **reward** indicating whether the chosen action was good or bad.

### Base Reward

Based on the change in damage level:
- If damage **decreases** after the action → positive reward (good)
- If damage **increases** after the action → negative reward (bad)

Network damage is computed from:
- Damage from high packet rate (weight 25%) — DDoS
- Damage from RST packets (15%) — port scan
- Damage from port diversity (15%) — service discovery
- Damage from abnormal payload (10%) — suspicious payload
- Damage from SYN flood (10%) — connection flooding
- Damage from application-layer attacks (25%) — SQLi + XSS

### Action Cost

Each action has an associated cost, subtracted from the reward:
- Allow: 0 (free)
- Rate Limit: 0.01 (very cheap)
- Redirect: 0.04 (moderate)
- Block: 0.15 (most expensive)

The cost forces the Agent to prefer the lightest effective action, using stronger actions only when truly necessary.

### Zone-Based Bonus

The system classifies traffic into 4 zones based on features:

| Zone | Detection Criteria | Correct Action | Bonus | Wrong Action | Penalty |
|------|-------------------|----------------|-------|-------------|---------|
| DDoS / Port Scan | F1 high (>80 pps) or F2 high (>10) or F5 high (>50 ports) | Block | +0.30 | Allow | −0.50 |
| Application Attack (L7) | F6–F8 high (brute force) or F12–F20 high (SQLi/XSS) | Redirect | +0.35 | Allow | −0.40 |
| Noisy | F1 moderate (15–80 pps), low attack signals | Rate Limit | +0.46 | Block | −0.20 |
| Normal | Low damage (<0.08), no abnormal signals | Allow | +0.12 | Block | −0.60 |

### Special Penalties
- Blocking before sufficient evidence (premature block): −0.20
- Blocking a normal user (false positive): −0.60

---

## 7. Attack Behavior Simulation in Training (MockIPBehavior)

During training, the system does not use real traffic but generates simulated "personas" with different behaviors:

| Type | Send Rate | Key Characteristics | Adaptive Behavior Under Defense |
|------|-----------|--------------------|---------------------------------|
| Benign | ~8 pps | Normal web browsing, diverse URLs | No change |
| Noisy Normal | ~30 pps | Rapid clicks, many requests but harmless | No change |
| Port Scan | ~160 pps | Probing dozens of different ports | Slows down when rate-limited |
| SYN Flood | ~200 pps | Floods SYN without completing handshake | Stops completely when blocked |
| Brute Force | ~120 pps | Repeatedly hits the same login URL | Switches tactics when redirected |
| Brute Force Keep-Alive | ~100 pps | Like brute force but uses persistent connections, harder to detect | Weakens signals when redirected |
| SQL Injection | ~15 pps | Low rate, but payload contains malicious SQL code | Detects honeypot → signals weaken |
| XSS | ~12 pps | Low rate, payload contains malicious JavaScript code | Similar to SQLi |

Key point: attackers **change their behavior** based on defensive actions. If the Agent blocks, the attacker stops. If the Agent redirects, the attacker detects it's talking to a decoy and its signals weaken. This is the **closed loop** in training — the Agent must learn to react to attackers who are also reacting to it.

---

## 8. Model Training

### PPO Algorithm (Proximal Policy Optimization)

The RL model uses PPO — a widely-used reinforcement learning algorithm. Simply put:

1. The Agent interacts with the simulated environment (MockIPBehavior), collecting experience (observations + actions + rewards)
2. After every 2,048 steps, the Agent uses the collected experience to update its "brain" (neural network)
3. PPO ensures each update doesn't change too much (clipping), keeping the learning process stable

### Neural Network Architecture

- **Actor network** (selects actions): 2 hidden layers, 256 → 128 neurons → 4 outputs (probability for each action)
- **Critic network** (evaluates situations): 3 hidden layers, 256 → 256 → 128 neurons → 1 output (estimated value)

The Critic is deeper than the Actor because evaluating situations is more complex (especially assessing the long-term value of the escalation mechanism).

### Training Process

- Total: 500,000 interaction steps
- 4 parallel environments for acceleration
- Evaluation every 5,000 steps, saving the best model
- Checkpoint every 10,000 steps for interruption recovery
- Final evaluation on 100 episodes

---

## 9. Pipeline Summary

```
Raw packets (bytes)
  ↓ [Capture — Scapy + tshark]
Structured packets (LayerInfo)
  ↓ [Aggregate — by 5-tuple connection, 1-second window]
Data flows (FlowState — containing N packets)
  ↓ [Extract — 20 behavioral metrics]
20-dimensional vector (raw)
  ↓ [Normalize — log / linear / pass-through]
20-dimensional vector (normalized, [0,1])
  ↓ [Write — JSONL file]
  ↓ [Read — RL Agent]
  ↓ [Enrich — +10 temporal context, +4 effect feedback]
34-dimensional vector (full observation)
  ↓ [Inference — PPO neural network]
Action (1 of 4)
  ↓ [Enforce — iptables on router]
Network traffic changes
  ↓ [Feedback loop → return to capture step]
```

---

## 10. Glossary

| English Term | Vietnamese Term | Brief Explanation |
|-------------|----------------|-------------------|
| Packet | Gói tin | Smallest unit of data transmitted on a network |
| Flow | Luồng dữ liệu | Collection of packets belonging to the same connection |
| 5-tuple | 5 thông tin kết nối | Source IP, Dest IP, Source Port, Dest Port, Protocol — uniquely identifies a connection |
| Sliding Window | Cửa sổ trượt | A 1-second time interval, continuously advancing, retaining only the most recent data |
| Feature Vector | Vector đặc trưng | Array of numbers representing network behavior within 1 window |
| Normalization | Chuẩn hóa | Scaling values to a common [0,1] range for AI comparison |
| Observation | Quan sát | All information the Agent receives at each step (34 dimensions) |
| Action | Hành động | Defensive decision: Allow / Rate Limit / Redirect / Block |
| Reward | Phần thưởng | Score evaluating whether an action was good or bad, used for training |
| Escalation | Leo thang | Process of accumulating evidence before upgrading defensive action |
| Honeypot | Bẫy mạng | Decoy server used to lure attackers and collect evidence |
| PPO | Proximal Policy Optimization | RL algorithm that updates the model in small, stable steps |
| iptables | Linux Firewall | Linux tool for managing packet filtering rules |
| NIDS | Network Intrusion Detection System | Software that monitors and analyzes network traffic |
| Closed Loop | Vòng kín | System where output affects input |
| CRS | Core Rule Set (ModSecurity) | Standard ruleset for scoring web attacks |
| SQLi | SQL Injection | Attack injecting SQL code into inputs to access databases illegally |
| XSS | Cross-Site Scripting | Attack injecting JavaScript into web pages to steal user data |
| DDoS | Distributed Denial of Service | Attack flooding a service with massive requests to crash it |
| SYN Flood | SYN Flood | DDoS variant sending mass SYN packets without completing connections |
| Port Scan | Port Scan | Probing a server for running services by trying many ports |
| Brute Force | Brute Force | Repeated trial (e.g., password guessing) until success |
| Temporal State | Trạng thái thời gian | Information about the Agent's recent history (previous action, trends) |
| Effect Feedback | Phản hồi hiệu quả | Information about whether the previous defensive action was effective |
| Network Namespace | Không gian mạng | Linux mechanism isolating network stacks between processes |
| Warm-start | Khởi đầu nóng | Continue training from an existing model instead of starting from scratch |
| Mock | Mô phỏng giả lập | Generate synthetic data/behavior for training without a real system |
| Mininet | Mininet | Network emulation platform that creates virtual hosts, switches, and links |
| nsenter | nsenter | Linux tool to run commands inside another process's network namespace |
| nginx | nginx | Reverse proxy on the Router that forwards traffic to webserver or honeypot |
| SSLKEYLOGFILE | File khóa phiên TLS | File containing TLS session keys, enabling tshark to decrypt HTTPS traffic |

---

## 11. Live Simulation Runtime — How the System Actually Runs

This section describes the **concrete execution sequence** when the entire system runs in the Mininet simulation environment. It bridges the gap between the conceptual pipeline (Sections 1–9) and what actually happens on screen.

### Phase 1: Network Topology Setup

The demo launches by creating the virtual network with Mininet. The following nodes are instantiated as isolated Linux network namespaces:

| Node | IP Address | Role |
|------|-----------|------|
| Attacker | 10.0.10.10 | Source of all attacks |
| Router | r-ext: 10.0.10.254, r-web: 192.168.10.1, r-honey: 192.168.30.1 | Central hub — runs NIDS, nginx, and iptables |
| Webserver | 192.168.10.10 (port 8080) | Real target to protect — a vulnerable Flask web store ("Tech Store") |
| Honeypot | 192.168.30.10 (port 8081) | Decoy web store ("T3ch Stor3") — nearly identical UI, different brand name |

The Router is configured with:
- **iptables baseline**: FORWARD default policy is DROP. Only established connections and attacker→webserver/honeypot traffic is allowed.
- **nginx reverse proxy**: Port 443 → webserver:8080 (real site), port 4443 → honeypot:8081 (trap). Self-signed TLS certificates are generated for both.
- **NIDS sniffer**: Automatically starts inside the Router namespace, listening on the external interface (r-ext) facing the attacker.

Four terminal windows open — one for each node (Attacker, Router, Webserver, Honeypot).

### Phase 2: Services Startup

Three services start in parallel on their respective nodes:

1. **Webserver** (on webserver node): Flask application serving a deliberately vulnerable "Tech Store" website with SQL injection vulnerability in the search parameter.
2. **Honeypot** (on honeypot node): Nearly identical Flask application serving "T3ch Stor3" — captures attacker payloads for evidence. The subtle name difference lets operators verify whether traffic reached the real server or the trap.
3. **RL Agent** (on host machine): The inference script starts watching `/tmp/sniffer_output.jsonl`, loads the trained PPO model (34D observation space), and waits for new NIDS data.

### Phase 3: Monitoring Setup

Two live monitoring views run simultaneously:

- **Firewall monitor** (on Router terminal): Refreshes every 1 second, showing current iptables rules on the FORWARD and PREROUTING chains. The operator sees rules appear and disappear as the RL Agent makes decisions.
- **AI actions log**: Each decision is logged as a JSON record containing: source IP, RL model's raw action, final action (after safety overrides), neural network probability distribution over all 4 actions, temporal state (escalation score, block readiness, damage trend), and effect feedback values.

### Phase 4: Attack Execution & Real-Time Defense

The attacker node provides a menu of attack scenarios. When an attack is launched:

**Every 1 second, the following pipeline executes end-to-end:**

```
Attacker sends HTTPS requests to Router:443
  ↓
nginx proxies to webserver:8080 (or honeypot:8081 if redirected)
  ↓
Scapy captures packets on r-ext interface
  ↓
tshark decrypts HTTPS using shared TLS key file → extracts HTTP method, URL, body
  ↓
FlowManager groups packets by source IP → 1-second window
  ↓
20 features extracted → written to /tmp/sniffer_output.jsonl
  ↓
RL Agent reads new line → normalizes → adds 10 temporal + 4 effect features → 34D vector
  ↓
PPO model selects action → safety overrides applied
  ↓
iptables command executed inside Router namespace via nsenter
  ↓
Next second: NIDS observes the effect of the new firewall rule
```

**TLS decryption** is a critical detail: the attacker's curl/sqlmap writes TLS session keys to a shared file (`SSLKEYLOGFILE`). Without this, tshark cannot read encrypted HTTPS traffic, and features F6–F20 (URL analysis, SQLi/XSS detection) would be blind. This is why the secondary capture stream has a 600ms grace period — it waits for keys to appear before processing.

### Phase 5: Attack Scenarios and Expected Defense Responses

| Attack Type | What the Attacker Does | What the Operator Sees | Expected Agent Response |
|-------------|----------------------|----------------------|------------------------|
| **Noisy Normal** | 18 rapid page loads, 0.09s apart | F1 (PacketRate) spikes, no L7 payload | **Rate Limit** — hashlimit 2 packets/sec |
| **Brute Force** | Repeatedly POST to /login with different passwords | F6 (URLConcentration) + F7 (timing uniformity) high | **Redirect** — traffic silently sent to honeypot |
| **SQL Injection** | sqlmap probes search parameter with --delay=1 | F13 (CRS SQLi score) rises above threshold | **Redirect** first → after ~15 windows, escalation score ≥0.60 → **Block** |
| **XSS** | xsser sends payloads with script tags and event handlers | F18–F20 (XSS indicators) light up | **Redirect** to honeypot |
| **SYN Flood** | hping3 --flood sends 500+ SYN packets/sec | F1 extreme, F2 (SYN/ACK ratio) very high | **Block** immediately — DDoS zone detected |
| **Port Scan** | nmap -sS scans multiple ports | F5 (DistinctPorts) high, F4 (RST ratio) high | **Block** — port scan zone detected |

### Phase 6: Observing the Escalation Process (SQLi Example)

The SQL Injection scenario best demonstrates the closed-loop and escalation mechanism in action:

| Window | What Happens | Agent Action | Escalation Score | Why |
|--------|-------------|-------------|-----------------|-----|
| 1–3 | sqlmap probes with basic payloads | **Redirect** | 0.0 → 0.15 | F13 (SQLi) detected → safety override forces Redirect |
| 4–8 | Attacker now hitting honeypot (T3ch Stor3), doesn't realize | **Redirect** | 0.15 → 0.40 | F22 (honeypot hit ratio) confirms redirect is working |
| 9–12 | Attacker's signals weaken (honeypot returns fake success) | **Redirect** | 0.40 → 0.58 | Evidence accumulating: redirect_hits ≥6, honeypot_hits ≥5 |
| 13–15 | Threshold reached: escalation_score ≥ 0.60 | **Block** | 0.60+ | block_ready_latched = True → model or soft-guard promotes to Block |
| 16+ | All attacker traffic dropped | **Block** (held) | 1.0 | F23 (presence) drops to 0, confirming attacker is stopped |

The operator can observe this entire progression in the actions log — seeing the escalation score climb from 0 to 1, the probability distribution shift from Redirect-dominant to Block-dominant, and finally the iptables DROP rule appear in the firewall monitor.

### Phase 7: What the Operator Sees on Screen

At any moment during the demo, the operator has 4 views:

1. **Attacker terminal**: Shows curl/sqlmap output — responses from "Tech Store" (real) or "T3ch Stor3" (honeypot), revealing whether redirection is active
2. **Router terminal**: Live iptables rules updating every second — rules appearing (Rate Limit, Redirect, Block) and disappearing (Allow)
3. **AI actions log**: JSON records showing every 1-second decision with full transparency: model probabilities, safety override status, temporal state, effect feedback
4. **NIDS output** (optional): Raw JSONL lines showing the 20 features extracted each second

This multi-view setup lets the operator verify the closed-loop in real time: attack starts → features change → Agent responds → firewall updates → traffic shifts → features change again.
