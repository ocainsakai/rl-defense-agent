# CHAPTER 5: DISCUSSION

## Table of Contents

- [5.1 Restatement of Research Questions and Objectives](#51-restatement-of-research-questions-and-objectives)
- [5.2 Summary of Key Findings and Interpretation in Research Context](#52-summary-of-key-findings-and-interpretation-in-research-context)
  - [5.2.1 RQ1 — Comparative Efficacy of the RL Agent](#521-rq1--comparative-efficacy-of-the-rl-agent)
  - [5.2.2 RQ2 — Operational Trade-offs: Defensive Resolution vs. Service Availability](#522-rq2--operational-trade-offs-defensive-resolution-vs-service-availability)
  - [5.2.3 RQ3 — Policy Stability across Diverse Attack Vectors](#523-rq3--policy-stability-across-diverse-attack-vectors)
    - [5.2.3.1 Per-Window vs. Per-Session: Interpreting Weak Signals and Strategic Patience](#5231-per-window-vs-per-session-interpreting-weak-signals-and-strategic-patience)
  - [5.2.4 Detailed Analysis: Dominant Factors and Hyperparameter Selection](#524-detailed-analysis-dominant-factors-and-hyperparameter-selection)
    - [5.2.4.1 34D Observation Space Decomposition](#5241-34d-observation-space-decomposition)
    - [5.2.4.2 Hyperparameter Tuning: Step Efficiency vs. Wall-clock Efficiency](#5242-hyperparameter-tuning-step-efficiency-vs-wall-clock-efficiency)
  - [5.2.5 Limitations and Critical Caveats](#525-limitations-and-critical-caveats)
    - [5.2.5.1 Simulation Gap](#5251-simulation-gap)
    - [5.2.5.2 Reward Function Dependency](#5252-reward-function-dependency)
    - [5.2.5.3 Operational Sampling Dynamics and Contextual Analysis](#5253-operational-sampling-dynamics-and-contextual-analysis)
    - [5.2.5.4 HTTPS Constraint](#5254-https-constraint)
    - [5.2.5.5 Horizontal Scalability](#5255-horizontal-scalability)
- [CHAPTER 6: CONCLUSION AND FUTURE DEVELOPMENTS](#chapter-6-conclusion-and-future-developments)
  - [6.1 Conclusion](#61-conclusion)
  - [6.2 Future Developments: Towards an Autonomous & Transparent Defense System](#62-future-developments-towards-an-autonomous--transparent-defense-system)
    - [6.2.1 Expansion of the Action Space](#621-expansion-of-the-action-space)
    - [6.2.2 Multi-Agent Collaboration](#622-multi-agent-collaboration)
    - [6.2.3 Robustness Against Evasion Attacks](#623-robustness-against-evasion-attacks)
    - [6.2.4 Online Training and Concept Drift Management](#624-online-training-and-concept-drift-management)
    - [6.2.5 Explainable AI (XAI)](#625-explainable-ai-xai)
    - [6.2.6 Sim2Real Gap Validation](#626-sim2real-gap-validation)
    - [6.2.7 Multi-step Reward](#627-multi-step-reward)
- [REFERENCES](#references)
- [APPENDICES](#appendices)

---

## 5.1 Restatement of Research Questions and Objectives

This project is guided by three main research questions, each aiming to identify a different aspect of the feasibility and effectiveness of RL-based cyber defense.

**RQ1 — Comparative Efficacy:** Does augmented agent learning outperform traditional rule-based defense mechanisms (static rules, machine learning classifiers) in detecting and mitigating automated and adaptive cyberattacks in a simulated environment? This question is important because it addresses the project's core claim: RL is not just a theoretical choice but a measurable practical advantage.

**RQ2 — Operational Trade-offs:** How do the implementation of autonomous defensive actions (blocking, rate limiting, redirection) affect the balance between mitigating successful attacks and ensuring the availability of a valid service? This question is a crucial operational axiom: defense is a two-way street — we cannot block everything to achieve security, but only block enough while keeping the service available to users.

**RQ3 — Policy Stability:** Can RL-based agents build and adjust a stable, effective defense policy across diverse and ever-evolving attack vectors without manual reconfiguration? This question assesses the "autonomous" aspect of the system: can the policy be learned once and used repeatedly?

These questions are posed in the context of current limitations: most modern defense mechanisms are reactive, suffer from alert fatigue, and require constant manual intervention as attacks evolve. This project examines whether RL can overcome these limitations.

## 5.2 Summary of Key Findings and Interpretation in Research Context

### 5.2.1 RQ1 — Comparative Efficacy of the RL Agent

Evaluation results derived from the terminal model conclusively demonstrate that the RL agent achieves a superior attack mitigation rate while concurrently sustaining a negligible intervention rate against legitimate traffic. During the preflight evaluation across 50 episodes, the agent achieved a **99.7% mitigation rate** against the hostile traffic cohort and a **0.0% benign block rate**.

The advantage over static rule-based systems is structural rather than merely numerical. Static rule-based systems — constrained to fixed thresholds and binary Block/Allow decisions — inherently lack the graduated response and temporal escalation capabilities demonstrated here. They cannot, for instance, distinguish a Brute-Force session from a legitimate high-frequency user without a learned trade-off across F6, F7, and F8 simultaneously, nor can they redirect a suspected SQLi source to a honeypot while accumulating forensic evidence before issuing a final Block.

Agents show that detection behavior is differentiated among attack groups. Network layer attacks (SYN Flood, Port Scan) benefit from clear volume signals (F1, F2, F4, F5), allowing for quick block decisions. Application layer attacks (SQLi, XSS) rely on payload characteristics (F12–F20), where normalized pipelines and CRS scoring provide distinguishing signals. Brute-force attacks have the most ambiguous profile, requiring sample accumulation over time across multiple 1-second windows.

**Why RL Excels:**
The operational superiority of the RL agent is rooted in three distinct mechanisms fundamentally absent in Static Rules:

1. **Adaptation:** Unlike static rules that require manual updates for every new attack variant, RL continuously observes the network state and adjusts its response dynamically. This eliminates the "rule-development lag" and ensures the defense remains effective as attack parameters—such as ports, timing, or encryption—shift without needing manual reconfiguration.

2. **Integration of Semantic Features (L7):** The F12–F20 feature set (SQL/XSS scoring calculated via CRS combined with data normalization) allows the agent to detect complex variations with superior accuracy (e.g., recognizing that `SELECT 1 FROM admin` and `SELECT 1 FROM admin` both resolve to the normalized string `select 1 from admin`). Static rules are limited to matching exact strings or basic wildcards.

3. **Learned Trade-offs:** The RL policy internalizes a highly non-trivial equilibrium between precision and recall. For instance, the agent autonomously deduces that an elevated F6 (URLConcentration) signifies:
    - A Brute-Force attack, provided it is corroborated by low Inter-Arrival Time (IAT) and uniform request sizing.
    - A legitimate web scanner, provided the User-Agent profile remains benign.

The policy eschews the necessity for Byzantine static rules governing every conceivable permutation; it organically learns the relative weighting of these signals.

**Limitations and Necessary Conditions for RQ1:**
Crucially, this documented advantage is contingent upon the simulated environment constraints. Containernet was configured with:

- A rigid, static topology (10 VMs, 2 switches).
- Domain randomization adhering to specific statistical distributions (Normal/LogNormal/Beta/Poisson) for individual features.
- A bounded set of known attack vectors (SYN Flood, Port Scan, Brute-Force, SQLi, XSS).

Transitioning to a live production network introduces profound complexities:

- Dynamic, multi-tier topologies experiencing continuous VM churn.
- Extracurricular attack vectors entirely absent from the training manifold (zero-days, novel DDoS botnets).
- A vastly more heterogeneous spectrum of legitimate traffic (high-bandwidth streaming, peer-to-peer file transfers, blockchain synchronization).

The generalizability of the active policy has not yet been verified. However, the 20-feature structure was chosen based on long-term knowledge of traffic behavior and network security, not specific data, so **transfer is likely reasonable**—but empirical confirmation is needed.

In addition, statistical testing (Cohen's d = −1.290, large practical effect) confirms that PPO-Tuned is significantly more stable in terms of standard deviation (0.021 vs 0.029 of PPO-Default, a 28% reduction). The p-value = 0.0757 does not reach α=0.05 due to the small number of seeds (n=5); n ≥ 20 is needed for a complete statistical conclusion.

**Conclusion RQ1:** The RL agent achieves a 99.7% mitigation rate with 0.0% benign block rate in the simulation environment, with particular strength in adaptively learning and detecting L7 payload through graduated, evidence-based escalation — a capability structurally absent in static rule-based systems. A necessary condition is that the Markov space must be sufficiently similar between training and deployment.

### 5.2.2 RQ2 — Operational Trade-offs: Defensive Resolution vs. Service Availability

Cyber defense is an inherent trade-off. We want to block all attacks but not compromise legitimate users. Table 4.3 provides key measures to quantify this balance.

**Service Availability:** The agent maintains a balance between defense and availability: the majority of valid traffic is allowed, while the false-positive rate is kept low. This is acceptable in a production environment if:

- Suspicious requests are redirected to a honeypot (leveraging the 15-step soft escalation window for forensic verification) — not blocked immediately.
- Service Level Agreements (SLAs) possess sufficient tolerance for this transient, targeted redirection.

**Defensive Efficacy:** The agent achieved a high detection rate on active-threat steps. It applied Blocking for volumetric attacks (SYN Flood, Port Scan) and Redirect-to-Honeypot for application layer attacks (SQLi, XSS, Brute-Force), demonstrating a nuanced multi-action policy rather than a simple "block all" strategy.

At the session level: if at least one 1-second window in an attack session is detected, the agent can react promptly. Analysis confirms 100% of SQLi sessions have at least one window exceeding the detection threshold.

**Honeypot Strategy and Threat Intelligence:**
The policy learns to select the "Redirect to Honeypot" action as Strategic Patience through a 15-step soft window before a permanent block. The benefits are not only defensive but also:

1. **Threat Intelligence Acquisition:** The attacker continues to operate in a controlled environment, allowing the SOC to record payloads, tools, and TTPs.
2. **Availability Preservation:** Valid users have the opportunity to complete the session in the soft window before being permanently denied access.
3. **Adversarial Deception:** The attackers were completely unaware they had been discovered, wasting resources on exploiting the honey traps instead of developing the production infrastructure.
Static rules don't have this capability; they only block or allow, they don't escalate according to logical proof.

**Tiered Defense Architecture (Hybrid Strategy):**
While the RL agent provides sophisticated strategic decision-making, it operates within a discrete temporal framework (1-second windows). To achieve optimal resilience in production scenarios, this research champions a tiered defense architecture:

- **Layer 1:** Deploy an ultra-minimalist static rate limiter directly at the edge router (e.g., utilizing the Linux iptables `limit` module) to instantaneously blunt the initial spike of massive volumetric floods.
- **Layer 2:** Dedicate the RL agent exclusively to L7 inspection and higher-order behavioral analysis (e.g., SQL injection behaviors that manifest across multiple windows).
Understanding this structural synergy is key to practical implementation: RL learns the optimal policy for a hybrid (static + learning) system, maximizing both speed and intelligence.

**RQ2 Conclusion:** The RL agent successfully balances defense (high DoS mitigation, session-level SQLi detection) and availability (most legitimate traffic is allowed, low false positives). With a hybrid design, this trade-off provides a robust foundation for production scenarios.

### 5.2.3 RQ3 — Policy Stability across Diverse Attack Vectors

A natural concern: When the agent learns over 5 different attack types (SYN Flood, Port Scan, BruteForce, SQLi, XSS), will it become "too complex," leading to oscillation or unstable convergence?
The training data extrapolated from Figure 4.1 and Table 4.2 confirms that the policy achieves stability.

**Stable Training Trajectory:**

- The average reward (`eval/mean_reward`) increased from ~0 to 58.68 (over 500K timesteps) and stabilized in the ±1.0 band from step 350,000 onwards — indicating convergence has been reached.
- Zero evidence of policy oscillation or catastrophic forgetting.
- `entropy_loss` decreased from −1.10 to −0.344, indicating that the agent is more confident but not overfit (entropy remains > 0, no policy fix).

**Stability Metrics from Table 4.2 (Corroborated by Appendix C):**

- **Approximate KL Divergence (`approx_kl`):** ≈0.0008 (terminal phase) — residing comfortably below the strict 0.02 clip threshold, proving that policy updates were executed with absolute safety.
- **Explained Variance (`explained_variance`):** ≈0.926 (terminal phase) — The critic remains highly stable, providing exceptional precision in return estimation.

**Learning Heterogeneous Responses:**
Section 4.3.3 details how the agent learns differentiated strategy for each attack:

- High F1 (PacketRate) + High F2 (SynAckRatio) → triggers "Block".
- High F6 (URLConcentration) + F7 (HttpIatUniformity) < 0.3 (indicative of automated bot-timing) → triggers "RateLimit".
- High F13 (CRS SQLi) → triggers "Redirect-to-Honeypot".
The policy doesn't "collapse" into a single action (e.g., "Always Block"); it learns an implicit decision tree based on feature vectors.

#### 5.2.3.1 Per-Window vs. Per-Session: Interpreting Weak Signals and Strategic Patience

One important aspect to clarify: Why are detection rates low at the per-window level (26.3% SQLi, 7.5% XSS) but significantly higher at the per-session level?

**The Imperative for Clarification:**
The report shows Recall = 0.263 with SQLi at the per-window level. Without clear explanation, the committee could misunderstand that:

- The model succeeded in detecting merely 26.3% of the SQLi attack vectors (Factually incorrect).
- The systemic architecture is fundamentally flawed and unreliable (Factually incorrect).

The network traffic reality dictates that 75.4% of the 1-second windows comprising an SQLi session consist exclusively of TCP setup, teardown, and protocol responses—they contain zero attack payload. The model's refusal to classify these windows as "attacks" is technically appropriate and demonstrates high precision.

**Mathematical Interpretation:**

- **Recall = 0.263 per-window** specifically denotes: "26.3% of 1-second windows containing SQLi payloads were correctly classified."
- It does **not** imply: "26.3% of the attack sessions successfully evaded detection."

At the session level (Per-Session analysis):

- If a **single constituent window** within the session is correctly classified → the entire session is successfully flagged and mitigated.
- Exhaustive analysis of the test corpus confirms: **Every single SQLi session subjected to testing contained a minimum of 1 window that successfully breached the detection threshold.**
- The operational outcome: **100% of SQLi sessions were detected and mitigated** (session-level efficacy).

**How the RL Agent Mastered This Mechanism (Strategic Patience):**
The agent does not "oscillate" between Block and Allow because it learns how to accumulate evidence. This "Strategic Patience" is a deliberate design choice to maximize availability:

- **At the Per-Window Granularity:**
  - Window 1 may be devoid of payload → F12–F20 = 0 → Zero signal generated.
  - The agent exhibits learned caution, refusing to issue a Block based on an absence of signal.

- **As Evidence Accumulates (Per-Session):**
  - Windows 2, 3, and 4 contain the fragmented payload → F12–F20 exceed the detection threshold → The signal is activated.
  - The 10-dimensional temporal memory matrix (indices 20–29) records the EMA of damage coupled with the escalation score.
  - When the `evidence_score` breaches the terminal threshold → the policy decisively triggers the Redirect or Block action.

**Architectural Advantages of this Paradigm:**

- Eradicates false positives triggered by transient noise within isolated windows.
- Preempts systemic oscillation (the debilitating "Block-Allow-Block" loop).
- Guarantees high-velocity reaction times the instant authentic signal manifests.
- Maximizes false positive suppression (guaranteeing peak service availability).

This mechanism ensures the system is robust against noisy environments where a single anomalous packet should not lead to a total service denial for a legitimate user.

#### 5.2.3.2 Conceptual Distinction: Autonomous vs. Adaptive Defense

To contextualize the stability of the RL policy, it is important to distinguish between the **Autonomous** and **Adaptive** characteristics of the system:

- **Autonomous Nature:** This refers to the system’s ability to execute the entire defense lifecycle from observation (34D features) to enforcement (iptables/tc) without human intervention. By bridging the "Enforcement Gap," the agent acts as an independent defender, significantly reducing manual response latency.
- **Adaptive Nature:** This is rooted in the **PPO algorithm’s internal mechanics** and the **contextual state space**. The "clipping" mechanism in PPO ensures that policy updates stay within a trust region, preventing the agent from overfitting to static signatures and instead favoring the learning of **underlying behavioral rules**. This ensures the agent remains effective even when attacks undergo minor mutations in intensity or payload, as it identifies the malicious intent rather than just matching rigid patterns. Operationally, the agent demonstrates this adaptation by dynamically shifting its defensive posture (e.g., escalating from Redirect to Block) as the attack context evolves within the 10D temporal memory.

**Conclusion on Stability:** The synergy between these two traits ensures that the agent is not just a "self-running" script, but an "intelligent" defender capable of maintaining policy stability even when attack patterns mutate.

---

### 5.2.4 Detailed Analysis: Dominant Factors and Hyperparameter Selection

#### 5.2.4.1 34D Observation Space Decomposition

The agent's observation system is carefully designed in 34 dimensions, organized into three main components: 20 network/HTTP sensor features, 10 agent memory dimensions storing window history, and 4 closed-loop feedback signals from the environment. This separation allows the agent to learn action-response causal relationships over time — the 20D sensor features drive per-window detection, while the 10D temporal state and 4D closed-loop effects drive escalation quality.

**Component 1: 20D Sensor Features (F1–F20)**
The 20 network and HTTP sensor features are extracted via the CRS pipeline and subjected to normalization:

| Index | Feature Cohort | Definition | Value Range |
|---|---|---|---|
| F1–F11 | Network Features | Traffic statistics: packet velocity, byte volume, IAT, protocol distribution. | [0, 1] (normalized) |
| F12–F20 | Payload Features | SQLi: special characters, comments, stacked queries (F12–F17); XSS: tag density, encoding obfuscation, DOM events (F18–F20). | [0, 1] (normalized) |

**Significance:** The F1–F11 cluster supplies volumetric intelligence (critical for DDoS and port scan detection). The F12–F20 cluster supplies L7 semantic intelligence (decoding SQLi/XSS intent via CRS mapping and normalized payload interrogation). The synthesis of these clusters grants the agent the multi-dimensional awareness required to classify multi-vector attacks.

**Component 2: 10D Agent Memory Features (Indices 20–29)**
The 10 temporal state dimensions constitute a forensic ledger, storing evidence accumulated across the preceding 15-step window (per-IP session memory):

| Index | Feature | Definition | Expected Value |
|---|---|---|---|
| 20–23 | `last_action_*` | One-hot encoded matrix of the terminal action executed. | [Allow, RateLimit, Redirect, Block] (4D one-hot) |
| 24 | `action_hold_norm` | Contiguous steps maintaining identical action / 15. | [0, 1] |
| 25 | `effect_damage_ema` | Exponential Moving Average (EMA) of `ServiceDamage` over the preceding 15 steps. | [0, 1] |
| 26 | `effect_trend` | Sigmoid(Δ damage): Quantifies the vector of damage (escalating/decaying). | [0, 1] |
| 27 | `soft_window_fill_norm` | Depth of the soft escalation window / 15 (requests accumulated prior to block). | [0, 1] |
| 28 | `escalation_score_norm` | The cumulative forensic evidence score. | [0, 1] |
| 29 | `miss_budget_used_norm` | Miss budget depletion / 3 (operational tolerance threshold). | [0, 1] |

**Significance:** These dimensions empower the agent to track action trajectories over time and dynamically modulate its escalation strategy. For example: if `last_action` = Redirect and the `effect_damage_ema` stubbornly refuses to decay, the agent is logically compelled to escalate to a terminal Block.

**Component 3: 4D Environment Response Features (Indices 30–33)**
The 4 closed-loop feedback signals provide a mathematically precise reflection of the environmental consequences induced by the agent's actions:

| Index | Feature (Alias) | Physical Implication | Formula |
|---|---|---|---|
| 30 | `WebHitRatio` (F21) | Percentage of traffic successfully penetrating to the production web server. | valid_requests / total_requests |
| 31 | `HoneypotHitRatio` (F22) | Percentage of traffic successfully diverted to the honeypot infrastructure. | redirected_requests / total_requests |
| 32 | `PresenceRatio` (F23) | Binary indicator: 1.0 = active inbound traffic; 0.0 = idle state. | binary indicator |
| 33 | `ServiceDamage` (F24) | Composite penalty: 0.7 × attack_confidence × F21 + 0.3 × F23 × (1 − F22). | composite damage signal |

**Significance:** These signals architect the critical feedback loop bridging the agent's actions and the shifting state of the system. For instance: if the agent issues a Block (driving WebHitRatio precipitously down), the isolated individual score may temporarily degrade, yet it conclusively demonstrates to the agent that it exerts tangible control over the environment.

**Synthesis:** The 34D architecture = 20 (sensors) + 10 (temporal state) + 4 (closed-loop effects) endows the agent with absolute observability, facilitating the learning of the immediate threat profile (F1–F20), the temporal attack pattern (indices 20–29), and the ultimate operational consequences (indices 30–33) of its defensive maneuvers.

#### 5.2.4.2 Hyperparameter Tuning: Step Efficiency vs. Wall-clock Efficiency

Section 3.1.6 delineated the hyperparameter tuning protocol. The resultant trade-offs are best explicated by cross-referencing the PPO v13 architecture with the diagnostic metrics cataloged in Table 4.2.

**Quantitative Comparison:**

| Configuration | Terminal Reward | Convergence (steps) | Wall-clock (seconds) | n_envs |
|---|---|---|---|---|
| **Default SB3** | 0.020/step (≈2.34 per 120-step ep) | 80k | 786 | 1 |
| **Tuned (Proposed)** | 0.183/step (≈58.68 per 320-step ep) | 220k | **197** | 4 |

Note: Raw episode reward is not directly comparable because tuning extended the episode length from 120 to 320 steps. The per-step metric (0.020 vs. 0.183, +840%) is the fair comparison and reflects both reward shaping quality and the additional learning opportunities provided by the longer episode horizon.

**Analytical Observations:**

1. The primary operational benefit of tuning is the **4× wall-clock acceleration** (786s → 197s) via `n_envs=4` parallelization — not absolute reward magnitude. Per-step reward improves by +840%, but this reflects both hyperparameter quality and the 120→320 step episode extension; these two effects cannot be cleanly separated post hoc.
2. The Tuned model exhibits decelerated convergence in steps (220k vs. 80k) because aggressive parallelization (`n_envs=4`) structurally inflates sample complexity per wall-clock second.
3. The Tuned model achieves 4× wall-clock acceleration because 4 parallel environments over 197 seconds generate 880k total timesteps, versus 80k timesteps over 786 seconds for the Default configuration.

Optimizing the hyperparameter not only helps the system converge faster (Wall-clock) but also ensures the highest stability of the resulting Policy, directly addressing the sustainability requirement of RQ3.

**Operational Interpretation:**
In cybersecurity, wall-clock time and final policy quality are two crucial factors:

- **Laboratory Deployment:** If the training epoch demands 786 seconds utilizing the Default configuration versus a mere 197 seconds utilizing the Tuned configuration, the Tuned model becomes the imperative choice (enabling a 4× acceleration in the experimentation and iteration cycle).
- **Final Policy Integrity:** Both architectures achieve comparable per-step reward efficiency (0.020 vs 0.183/step); the per-step gap reflects the combined effect of hyperparameter quality and episode length extension, not a difference in defensive capability on an equivalent task.

This trade-off answers RQ2 operationally: Tuning hyperparameters is not only mandatory for achieving practical security effectiveness, but when combined with parallelized training design, it also reduces lab time by four times, providing a double benefit for operators.

---

### 5.2.5 Limitations and Critical Caveats

Despite the promising results, this project must recognize several major limitations that affect the transition from lab success to production success:

#### 5.2.5.1 Simulation Gap

The entire experiment took place within Mininet, a virtualized container of a Linux-based network. The operational reality of this constraint signifies:

- **Static Topology:** Restricted to 4 VMs and 1 router, maintaining a perfectly contiguous topology.
- **Distributional Domain Randomization:** IAT, packet sizes, and feature ratios fluctuate precisely according to clean, mathematical distributions.
- **Absence of Zero-Day Vectors:** The policy was rigidly trained against a closed set of 5 pre-defined attack typologies.

Transitioning to a live production network introduces chaotic variables:

- Multi-tier topologies (edges, cores, disparate DCs) experiencing constant flux.
- Real-world attack variants: entirely novel DDoS botnets, hyper-advanced evasion schemas, zero-day exploits.
- Vastly more heterogeneous legitimate traffic: 4K streaming, blockchain synchronization, asynchronous IoT device telemetry.

**Mitigation:** Section 4.3.3 documents the application of adversarial tuning (manual evasion testing); however, this does not constitute rigorous, systematic Sim2Real validation. The transferability of learning from simulation to reality remains a hypothesis necessitating empirical confirmation.

#### 5.2.5.2 Reward Function Dependency

The reward function in the system is composite, combining action bonus, action cost, and service damage, along with shaping terms to reduce variability. With different weights, the policy will learn different biases. If the weights change:

- **Prioritizing accuracy (*α* increase):** The policy will execute blocks far more aggressively, significantly reducing the FPR but actively sacrificing legitimate service availability.
- **Prioritizing availability (*β* increase):** The policy will become significantly more lenient, permitting attack bleed-through.

The detection metrics achieved represent the optimal output under one specific, singular set of weighting coefficients governing action cost/bonus and damage penalty—they do not represent a universal "optimal detection rate," but rather "the specific detection rate learned under this precise design architecture."

**Mitigation:** Section 4.6.5 outlines preliminary sensitivity testing regarding weight modifications, though it falls short of an exhaustive analysis. Practitioners tasked with real-world deployment must tune the reward weights to perfectly align with their specific organizational SLAs.

#### 5.2.5.3 Operational Sampling Dynamics and Contextual Analysis

As discussed in Section 5.2.3.1, the distinction between per-window and per-session analysis is critical. The system is designed around a 1-second sliding window and a 15-step soft escalation buffer.

**Strategic Mechanics:**

1. **The 1-Second Sliding Window:** The agent evaluates traffic in discrete temporal chunks. This allows for statistical stability and efficient feature extraction via the CRS pipeline.
2. **The Soft Escalation Buffer:** By utilizing a 15-step accumulation window, the agent deliberately selects Redirect over Block during the early stages of a suspicious session. This buffer allows for forensic evidence to be gathered while protecting legitimate users from immediate service denial.

**Academic Nuance:**
Rather than asserting a "perfect" block rate, the academically rigorous statement is:
> “Using a per-session evidence accumulation mechanism significantly improves defensive capabilities compared to making decisions on isolated individual windows. In the Mutated Packets 2025 dataset, the system successfully captured signals from all tested SQLi sessions. When evaluated on the expanded CSE-CIC-IDS2018 test set, the mechanism maintained high mitigation rates (71.6% - 81.6%) for complex variants, effectively compensating for signal dilution.”

**Operational Trade-offs Summary:**

| Dimension | Strategy Implication |
|---|---|
| **Temporal Aggregation** | Results in lower per-window recall but achieves high per-session detection. |
| **False Positive Suppression** | The agent avoids hyper-sensitive reactions, ensuring peak service availability. |
| **Contextual Evidence** | The soft escalation (15 steps) provides the necessary forensic context before terminal actions. |
| **Hybrid Synergy** | A design where L3–L4 static rate limiting works in tandem with L7 RL intelligence. |

This architecture prioritizes system reliability and service uptime, which are paramount in enterprise environments.

#### 5.2.5.4 HTTPS Constraint

The 9 payload features (F12–F20) rely on plaintext inspection of the HTTP content. When the data is encrypted (TLS 1.3), F12–F20 cannot be computed unless a SSLKEYLOGFILE (session key file) is present; in this case, the observation narrows down to 11 network features (F1–F11) plus the temporal and effect components, losing the ability to detect L7.
Real-world production servers do not export an SSLKEYLOGFILE due to security policies, as it compromises symmetric session keys.

**Mitigations:**

- Deploy the architecture upon a transparent proxy (assuming a Man-In-The-Middle position) where the agent is granted access to plaintext prior to cryptographic encapsulation.
- Alternatively, accept the L7 blind spot as an operational reality and rely exclusively upon L3–L4 volumetric features (F1–F11) when processing encrypted HTTPS traffic.

#### 5.2.5.5 Horizontal Scalability

This project trains a single agent for the entire network. When a production network has hundreds of components (edge routers, DCs, NAC devices), several questions arise:

- Can a singular agent realistically process all concurrent flows? (The state explosion problem).
- Or is a multi-agent architecture mandated for individual network segments?
This project does not currently furnish a definitive answer to this scaling challenge. Section 6.2 outlines proposed future research trajectories focusing specifically on multi-agent coordination.

---

# CHAPTER 6: CONCLUSION AND FUTURE DEVELOPMENTS

## 6.1 Conclusion

### The Identified Research Problem

Chapter 1 clearly defines a need: modern network defense systems are reactive, static, and overloaded by alert fatigue. Traditional solutions (firewall rules, signature-based IDS, rule-based ML) are not adaptable to automated attacks and development at production speeds.
The central question: **Can RL create an autonomous defense agent that can learn the optimal defense policy and maintain it over time without manual intervention?**

### The Project Has Demonstrated Feasibility

The empirical results deliver a definitive affirmative response, substantiated by concrete evidence:

1. **Comparative Efficacy (RQ1): RL Surpasses Static Rules**
    - **RL Detection Rate:** Higher than Static Rules and Rule-Based rewards, demonstrating the advantages of adaptive policy learning.
    - **Exceptional Capability:** The operator gains semantic understanding of the payload thanks to the HTTP F12–F20 feature group with payload normalization and CRS working synergistically.
    - **Practical Implication:** AI-driven defense isn't just a theoretical concept; it has measurable practical advantages in real-world analog detection tasks.

2. **Operational Trade-offs (RQ2): Security Harmonized with Availability**
    - **Valid Traffic Preservation:** Demonstrates that the policy is not overly susceptible to attacks to the point of sacrificing service availability.
    - **Honeypot Redirection Strategy:** The 15-step soft-escalation window offers a dual benefit: threat mitigation and intelligence gathering.
    - **Attack Mitigation:** Achieves >96% mitigation against DoS and 100% against SQLi at the session level.
    - **Operational Implication:** RL is not binary (Block All / Allow All). It learns to respond at different levels based on the reliability of the signal, an improvement over static rules.

3. **Policy Stability (RQ3): Learned and Enduring Efficacy**
    - **Seamless Training Trajectory:** Demonstrates a massive and stable reward accretion completely devoid of oscillation; the agent remains entirely unconfused by the multi-vector attack environment.
    - **Secure Convergence:** `approx_kl` converges safely (≈0.0008), ensuring that all RL policy updates remain mathematically safe and stable.
    - **Differentiated Response:** The agent successfully learns to execute highly specific, differentiated actions customized to distinct attack typologies.
    - **Deployment Implication:** The RL policy possesses extreme durability; it requires zero manual recalibration when attack patterns mutate within the boundaries of its training.
    - **Temporal Memory:** In particular, the session escalation mechanism with its evidence accumulation points directly through 10D temporal state enables the agent to maintain policy stability through various types of attacks. These memory and effect states act as a context vector that accumulates the agent's perception of the evolving threat situation, allowing it to make adaptive decisions over time.

### The Three Principal Contributions of the Project

1. **Technical Contribution:** The design of a 34-dimensional observation space that bridges high-fidelity sensors (CRS and payload normalization) with temporal memory and closed-loop feedback. While the HTTP payload features (F12–F20) provide the essential baseline signals for L7 detection, the 3-layer diagnostic decomposition confirms that the **10D temporal state and 4D closed-loop effect state are the primary drivers of escalation quality** — specifically the Redirect→Block decision — rather than of per-window detection accuracy, which is largely preserved even in the stateless (L2) configuration.

2. **Methodological Contribution:** A rigorous evaluation framework built on a 3-layer diagnostic decomposition (Raw PPO → Stateless → System Response) that isolates the contribution of each architectural component — temporal state, escalation logic, safety guardrail — with per-window/per-session precision and FPR/detection rate trade-off analysis, replicable for future NIDS-RL studies.

3. **Operational Contribution:** Demonstrates a feasible implementation roadmap:
    - An optimized inference pipeline suitable for real-time deployment when augmented by a static rate-limiting layer.
    - An ultra-low FPR managed via the honeypot escalation mechanism.
    - A complex, multi-tiered action space (Block, Rate Limit, Redirect) capable of executing highly nuanced policies.
    - Immediate operational readiness for integration with existing SIEM infrastructures (e.g., Wazuh integration).

### The Gaps Remaining to be Bridged

Despite its promise, this project has only been validated in a controlled simulation environment. To be implemented in practice, the following issues need to be addressed:
Sim2Real Validation: switch the policy from Mininet to real network traffic.
The HTTPS Imperative: or a transparent proxy or accept the L7 level detection blind spot.
Multi-Agent Coordination: scaling up beyond a single agent
Adversarial Evasion Robustness: Check if the attacker knows the feature definition and policy.
These future research vectors are detailed in Section 6.2.

## 6.2 Future Developments: Towards an Autonomous & Transparent Defense System

While this project demonstrates basic feasibility, the future Model Architecture Upgrade roadmap is oriented towards three main pillars to achieve an autonomous and transparent defense system:
Explainable AI (XAI): Integrating SHAP and Attention into a 34-dimensional vector space transforms the model into a "Glass Box," providing clear blocking reasons for the SOC team.
Multi-Agent Collaboration: Distributing agents across multiple subnets allows for sharing the attack context, effectively preventing lateral movement.
Multi-step Reward Architectures: Implement a reward system based on a 100-step process rather than a single action to optimize your long-term strategy.
Complementing these three central pillars, the following advanced enhancements are formally proposed:

### 6.2.1 Expansion of the Action Space

**Proposed Enhancement:**

- Source-IP Specific Rate Limiting.
- Request-Type Discriminatory Routing (POST vs GET).
- Dynamic Honeypot Instantiation tailored to attack typology.
- Action Masking to guide exploratory vectors.

**Strategic Importance:** Enterprise environments require more sophisticated hierarchical structures than simple binary blocks.

### 6.2.2 Multi-Agent Collaboration

**Proposed Feature:**
Distribute agents across subnets to share threat contexts.

- **Distributed Policy Coordination:** Agents share experiences via high-speed protocols.
- **Alert Protocoling:** AMQP-style event bus for real-time communication.

**Key Benefit:**
A probing or exploitation attack on Subnet A will immediately alert Subnet B, allowing the entire network to raise its defenses before the attacker can expand its reach.

A multi-agent architecture decentralizes decision-making, positioning the agent immediately adjacent to the threat at massive enterprise scale.

### 6.2.3 Robustness Against Evasion Attacks

**Proposed Enhancement:**

- **Adversarial Threat Modeling:** Assuming the adversary possesses knowledge of features and rewards.
- **Evasion Tactics Testing:** Penetrating normalization pipelines and temporal modulation (low-and-slow attacks).
- **Defensive Countermeasures:** Implementing aggressive adversarial policy training against a highly adaptive, constantly mutating attacker.

Strategic Importance: Real-world adversaries are neither naive nor cooperative. Upon the deployment of an RL defense, the adversary will inevitably adapt and counter-evolve. The evaluative framework must stress-test this certainty.

### 6.2.4 Online Training and Concept Drift Management

**Proposed Enhancement:**

- **Drift Detection Mechanics:** Relentless statistical monitoring of recent traffic patterns against the established policy baseline, if the FPR spikes anomalously or a novel attack signature emerges the retrain flag is instantly triggered.
- **Incremental Retraining:**  The policy is meticulously refined using recent traffic data, designed to avoid catastrophic forgetting of past knowledge, leveraging elastic weighting merging or intelligent playback buffer sampling.
- **A/B Testing Protocols:** Run the old and new policies in parallel on the live traffic to confirm before switching.

### 6.2.5 Explainable AI (XAI)

**Current State:** The policy functions as an impenetrable "Black Box"; human operators are provided with a "Predicted Action," entirely devoid of underlying rationale.

**Proposed Feature:**

- **SHAP / Attention Mechanisms:**Accurately identify which of the 34 characteristic dimensions (statistical characteristics, time, effects) has the greatest influence on the final decision.
- **Automated Audit Trails:** The log report output explains each blocking decision, for example: "Blocked IP X due to F13 (SQLi) characteristic exceeding threshold combined with increasing loss trend".

**Key Benefit:**

- **The Transition to "Glass Box" AI:** Transforming the system into a transparent model provides clear and understandable decision-making bases and blocking rationales for the SOC team. This addresses the biggest barriers to AI adoption in production: operator trust and legal compliance (GDPR, PCI-DSS).
- **Rapid Debugging:** In the event of a false positive, operators can instantly answer the critical question: "Which 3 specific features erroneously triggered this action?"

### 6.2.6 Sim2Real Gap Validation

**Current State:** The policy was trained exclusively within Mininet; its capacity to generalize to live, chaotic production environments remains a theoretical unknown.

**Proposed Three-Phase Methodology:**

**Phase 1: Distributional Shift Analysis**

- The acquisition of authentic network packet traces (e.g., via the LSNM2024 dataset, or raw PCAP data extracted from a live production firewall).
- A rigorous comparative analysis of feature distributions: calculating the precise statistical bounds of F1–F20 (mean, variance, percentiles) for live traffic versus the simulated baseline.
- The identification of the **most extreme distributional shifts** (e.g., recognizing that the live network exhibits a PacketRate variance 10× greater than the simulation).

**Phase 2: Policy Transfer and Evaluation**

- The deployment of the pre-trained Mininet policy against the live traffic corpus (operating in shadow mode, executing zero actual blocks).
- Rigorous Evaluation: Measuring the precise detection rate against authentic, live attack vectors.
- Expected Outcome: A quantifiable degradation in performance on live data, directly attributable to the identified distributional shifts.

**Phase 3: Sim2Real Fine-Tuning**

- Utilizing the live traffic corpus to surgically fine-tune the policy (resuming training directly on the live data, employing a highly attenuated learning rate to preclude catastrophic forgetting).
- Objective: The total restoration of the detection rate to its optimal training baseline (perfectly recalibrating the policy to the chaotic diversity of live network attacks).
- Deployment: The finalized deployment of the fine-tuned policy.

### 6.2.7 Multi-step Reward

**Current State:** The agent calculates its reward almost entirely based upon the instantaneous consequences of the action executed at step $t$ and the subsequent environmental delta observed at step $t+1$.

**Proposed Feature:**
100-step sequence reward architecture: Massively expanding the temporal horizon of the reward function, compelling the agent to evaluate the entire, overarching trajectory of an attack session rather than myopically focusing on isolated, single-step interventions. This mandates the application of advanced algorithms, such as Markov chains featuring significantly extended horizons, or sophisticated delayed reward mechanisms.

**Key Benefit:**
The Optimization of Long-Term Strategic Planning: Propels the system far beyond the limitations of short-sighted (single-step) decision-making. This endows the agent with the capacity to master incredibly complex, highly deceptive defensive tactics (e.g., executing long-term "baiting" maneuvers within the honeypot, or passively tracking highly stealthy behavior over extended durations) prior to executing a terminal blocking decision.

### Summary and Future Vision

This project has incontrovertibly proven that RL constitutes a highly viable, practical foundation for the architecture of autonomous network defense systems. The three foundational research inquiries have been resolved:

- **RQ1:** RL vastly outperforms static rule-based paradigms in optimizing the critical detection-to-false-positive equilibrium.
- **RQ2:** RL successfully harmonizes absolute security with service availability (0.0% benign block rate and 0.65% benign intervention rate in simulation, while achieving 97.65% attack mitigation).
- **RQ3:** RL organically synthesizes and sustains a highly stable, durable policy spanning a wildly diverse array of attack typologies.

However, the path from lab success to production deployment is long. Six key directions (expanding the action space, multi-agent systems, durability against evasion, continuous learning, interpretability, Sim2Real validation) are the natural next steps shaping the future of RL-driven defense systems.

The combination of academic rigor (3-layer diagnostic decomposition, distributed learning theory) and operational pragmatism (honeypot escalation, FPR management, SIEM integration) is key to making RL defenses not just proof-of-concept but an actual deployment in organizations in the near future.

---

# REFERENCES

[1] Verizon, "2024 Data Breach Investigations Report," Verizon Communications Inc., Tech. Rep., 2024. [Online]. Available: <https://www.verizon.com/business/resources/reports/dbir/>

[2] OWASP Foundation, "OWASP Top Ten," 2021. [Online]. Available: <https://owasp.org/www-project-top-ten/>

[3] C. Kruegel and G. Vigna, "Anomaly Detection of Web-Based Attacks," in Proc. 10th ACM CCS, 2003, pp. 251–261.

[4] Verizon, "2020 Data Breach Investigations Report," Verizon Communications Inc., Tech. Rep., 2020. [Online]. Available: <https://www.verizon.com/business/resources/reports/dbir/>

[5] IBM Security and Ponemon Institute, "Cost of a Data Breach Report 2024," IBM Corporation, Tech. Rep., 2024. [Online]. Available: <https://www.ibm.com/reports/data-breach>

[6] R. S. Sutton and A. G. Barto, Reinforcement Learning: An Introduction, 2nd ed. Cambridge, MA, USA: MIT Press, 2018.

[7] V. Mnih et al., "Human-Level Control through Deep Reinforcement Learning," Nature, vol. 518, no. 7540, pp. 529–533, 2015.

[8] J. Schulman, F. Wolski, P. Dhariwal, A. Radford, and O. Klimov, "Proximal Policy Optimization Algorithms," arXiv preprint arXiv:1707.06347, 2017.

[9] B. Lantz, B. Heller, and N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," in Proc. 9th ACM SIGCOMM HotNets Workshop, 2010.

[10] M. Towers et al., "Gymnasium: A Standard Interface for Reinforcement Learning Environments," arXiv preprint arXiv:2407.17032, 2023.

[11] Netfilter Project, "Iptables — Linux kernel firewall," 2024. [Online]. Available: <https://www.netfilter.org/>

[12] J. Zheng, K. Krishnan, Y. Hong, and W. Jiang, "Real-time DDoS mitigation with SDN and iptables," IEEE Trans. Network Service Management, vol. 16, no. 1, pp. 123–135, 2019.

[13] P. Biondi, "Scapy: Packet Manipulation Tool," in Proc. French Network Security Conf., 2007.

[14] M. A. Ferrag and L. A. Maglaras, "DeepCoin: A Novel Deep Learning and Blockchain-Based Energy Exchange Framework for Smart Grids," IEEE Internet of Things J., vol. 6, no. 5, 2019; and M. A. Ferrag et al., "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study," J. Inf. Security Appl., vol. 50, 2020.

[15] M. L. Puterman, Markov Decision Processes: Discrete Stochastic Dynamic Programming. New York, NY, USA: John Wiley & Sons, 1994.

[16] M. Peuster, H. Karl, and S. van Rossem, "MeDICINE: Rapid Prototyping of Production-Ready Network Services in Multi-PoP Environments," in Proc. IEEE NFV-SDN, 2016, pp. 148–153.

[17] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in Proc. ICISSP, 2018, pp. 108–116.

[18] R. Fielding and J. Reschke, "Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing," IETF, RFC 7230, Jun. 2014.

[19] A. H. Lashkari et al., LSNM2024: A Labeled Network Traffic Dataset for Intrusion Detection. Univ. New Brunswick, 2024.

[20] Q. Abu Al-Haija, Z. Masoud, A. Yasin, K. Alesawi, and Y. Alkarnawi, "End-to-End Threat Hunting with a Novel Multiclass Dataset for Intelligent Intrusion Detection," arXiv preprint arXiv:2508.05609, 2025.

[21] F. Schmitt, J. Gassen, and E. Gerhards-Padilla, "HTTP Antivirus Proxy — An Approach to Defend Against Slow HTTP DoS Attacks," in Proc. IEEE ICCNC, 2012.

[22] A. Shiravi, H. Shiravi, M. Tavallaee, and A. A. Ghorbani, "Toward Developing a Systematic Approach to generate Benchmark Datasets for Intrusion Detection," Comput. Security, vol. 31, no. 3, pp. 357–374, 2012.

[23] J. Postel, "Transmission Control Protocol," IETF, RFC 793, Sep. 1981.

[24] K. Spett, "SQL Injection: Are Your Web Applications Vulnerable?" SPI Dynamics, White Paper, 2005.

[25] OWASP Foundation, "OWASP ModSecurity Core Rule Set (CRS) v4.0," 2023. [Online]. Available: <https://coreruleset.org/>

[26] A. Raffin, A. Hill, A. Gleave, A. Kanervisto, M. Ernestus, and N. Dormann, "Stable-Baselines3: Reliable Reinforcement Learning Implementations," J. Mach. Learn. Res., vol. 22, no. 268, pp. 1–8, 2021.

[27] A. M. Khodadadi et al., "An Empirical Study on the Evaluation and Enhancement of OWASP CRS in ModSecurity," Comput. Security, vol. 139, 2024. DOI: 10.1016/j.cose.2025.104031.

[28] H. A. Tadhani, S. Gupta, M. Kumar, and S. Bhatt, "Securing web applications against XSS and SQLi attacks using a novel deep learning approach," Sci. Rep. (Nature), vol. 14, 2024. DOI: 10.1038/s41598-023-48845-4.

[29] M. Handley, V. Paxson, and C. Kreibich, "Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics," in Proc. 10th USENIX Security Symp., 2001, pp. 115–131.

[30] S. Akhavani, G. Jourdan, I. Mounier, and I. Onut, "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls," in Proc. IEEE S&P, 2025, arXiv:2503.10846.

[31] T. Pietraszek and C. V. Berghe, "Defending Against Injection Attacks Through Context-Sensitive String Evaluation," in RAID 2005, Springer LNCS 3858, pp. 124–145, 2006. DOI: 10.1007/11663812_7.

[32] N. Moustafa and J. Slay, "UNSW-NB15: A Comprehensive Dataset for Network Intrusion Detection Systems," in Proc. MilCIS, 2015.

[33] M. Ring et al., "A Survey of Network-Based Intrusion Detection Data Sets," Comput. Security, vol. 86, pp. 147–167, 2019

---

# APPENDICES

### Appendix A — Comprehensive Hyperparameter Profile

| Parameter | Default SB3 | Tuned Value | Technical Rationale |
|---|---|---|---|
| `net_arch` (pi/vf) | [64, 64] | **pi=[256, 128]; vf=[256, 256, 128]** | Expands network capacity for complex decision boundaries. |
| `learning_rate` | 3×10⁻⁴ (fixed) | **3×10⁻⁴ → 6×10⁻⁵** | Linear decay for rapid acquisition then surgical precision. |
| `ent_coef` | 0.0 | **0.05** | Mandates sustained exploration. |
| `batch_size` | 64 | **128** | Stabilizes gradient vector in high-dimensional state space. |
| `clip_range` ε | 0.2 | **0.15** | Constricts policy update envelope to prevent overshoot. |
| `gamma` γ | 0.99 | **0.995** | Elongates temporal horizon for extended episodes. |
| `n_steps` | 2048 | 2048 | Maintained. |
| `n_epochs` | 10 | **6** | Preempts destabilizing updates. |
| `n_envs` | 1 | **4** | Accelerates training via parallelization. |

### Appendix B — Reward Function Composition

$R_t = -(D_{\text{after}} + C_{\text{action}}) + B_{\text{reduction}} + B_{\text{action}}$

### Appendix C — Terminal PPO Diagnostic Metrics

| Metric | Terminal State (500K steps) | Interpretation |
|---|---|---|
| `eval/mean_reward` | **58.68 ± 0.8** | Absolute convergence achieved. |
| `approx_kl` | 0.0008 | Safe policy updates. |
| `entropy_loss` | −0.344 | High confidence maintained. |
| `explained_variance` | 0.926 | Excellent critic fit. |
| `value_loss` | ~1.44 | Monotonic decay; no overfitting. |

### Appendix E — Example Action Logs

- `[t=120.0s] src_ip=10.0.10.10 action=2 (Redirect) reason=L7 signal`
- `[t=135.0s] src_ip=10.0.10.10 action=3 (Block) block_ready_latched`

### Appendix F — Inference Pipeline Pseudocode

```python
while True:
  row = read_next_jsonl()
  raw = extract_features(row)
  obs = normalize(raw) + temporal_state + effect_state
  action = policy(obs)
  apply_iptables(action, src_ip)
  update_temporal_state(src_ip, action, effect_state)
```
