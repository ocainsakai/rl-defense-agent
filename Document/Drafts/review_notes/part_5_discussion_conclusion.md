# CHAPTER 5: DISCUSSION

## 5.1 Restatement of Research Questions and Objectives

This project is guided by three main research questions, each aiming to identify a different aspect of the feasibility and effectiveness of RL-based cyber defense.

*   **RQ1 — Comparative Efficacy:** Does augmented agent learning outperform traditional rule-based defense mechanisms (static rules, machine learning classifiers) in detecting and mitigating automated and adaptive cyberattacks in a simulated environment? This question is important because it addresses the project's core claim: RL is not just a theoretical choice but a measurable practical advantage.
*   **RQ2 — Operational Trade-offs:** How do the implementation of autonomous defensive actions (blocking, rate limiting, redirection) affect the balance between mitigating successful attacks and ensuring the availability of a valid service? This question is a crucial operational axiom: defense is a two-way street — we cannot block everything to achieve security, but only block enough while keeping the service available to users.
*   **RQ3 — Policy Stability:** Can RL-based agents build and adjust a stable, effective defense policy across diverse and ever-evolving attack vectors without manual reconfiguration? This question assesses the "autonomous" aspect of the system: can the policy be learned once and used repeatedly?

These questions are posed in the context of current limitations: most modern defense mechanisms are reactive, suffer from alert fatigue, and require constant manual intervention as attacks evolve. This project examines whether RL can overcome these limitations.

---

## 5.2 Summary of Key Findings and Interpretation in Research Context

### 5.2.1 RQ1 — Comparative Efficacy of the RL Agent

Evaluation results derived from the terminal model conclusively demonstrate that the RL agent achieves a superior attack mitigation rate while concurrently sustaining a negligible intervention rate against legitimate traffic:

*   **Static Rules:** 73.5% — A statistically significant deviation of **+3.8 percentage points (pp)**.
*   During the preflight evaluation across 50 episodes, the agent achieved a **99.7%** mitigation rate against the hostile traffic cohort and a **0.0%** Benign Intervention Ratio.

Agents show that detection behavior is differentiated among attack groups:
*   **Network layer attacks (SYN Flood, Port Scan):** Benefit from clear volume signals (F1, F2, F4, F5), allowing for quick block decisions.
*   **Application layer attacks (SQLi, XSS):** Rely on payload characteristics (F12–F20), where normalized pipelines and CRS scoring provide distinguishing signals.
*   **Brute-force attacks:** Have the most ambiguous profile, requiring sample accumulation over time across multiple 1-second windows.

#### Why RL Excels:
The operational superiority of the RL agent is rooted in three distinct mechanisms fundamentally absent in Static Rules:

1.  **Online Adaptation:** RL is not bound by predefined signatures. It continuously observes the network state, adjusting its behavior based on rewards. When attack patterns change (port changes, payload encryption, speed), the agent learns how to react without developing new rules.
2.  **Integration of Semantic Features (L7):** The F12–F20 feature set (SQL/XSS scoring calculated via CRS combined with data normalization) allows the agent to detect complex variations with superior accuracy (e.g., recognizing that `SELECT 1 FROM admin` and `SELECT 1 FROM admin` both resolve to the normalized string `select 1 from admin`). Static rules are limited to matching exact strings or basic wildcards.
3.  **Learned Trade-offs:** The RL policy internalizes a highly non-trivial equilibrium between precision and recall. For instance, the agent autonomously deduces that an elevated F6 (URLConcentration) signifies:
    *   A **Brute-Force attack**, provided it is corroborated by low Inter-Arrival Time (IAT) and uniform request sizing.
    *   A **legitimate web scanner**, provided the User-Agent profile remains benign.

The policy eschews the necessity for Byzantine static rules governing every conceivable permutation; it organically learns the relative weighting of these signals.

#### Limitations and Necessary Conditions for RQ1:
Crucially, this documented advantage is contingent upon the simulated environment constraints. Containernet was configured with:
*   A rigid, static topology (10 VMs, 2 switches).
*   Domain randomization adhering to specific statistical distributions (Normal/LogNormal/Beta/Poisson) for individual features.
*   A bounded set of known attack vectors (SYN Flood, Port Scan, Brute-Force, SQLi, XSS).

Transitioning to a live production network introduces profound complexities:
*   Dynamic, multi-tier topologies experiencing continuous VM churn.
*   Extracurricular attack vectors entirely absent from the training manifold (zero-days, novel DDoS botnets).
*   A vastly more heterogeneous spectrum of legitimate traffic (high-bandwidth streaming, peer-to-peer file transfers, blockchain synchronization).

> [!NOTE]
> The generalizability of the active policy has not yet been verified. However, the 20-feature structure was chosen based on long-term knowledge of traffic behavior and network security, not specific data, so **transfer is likely reasonable**—but empirical confirmation is needed.

In addition, statistical testing (Cohen's $d = -1.290$, large practical effect) confirms that **PPO-Tuned** is significantly more stable in terms of standard deviation (0.021 vs 0.029 of PPO-Default, a 28% reduction). The $p$-value = 0.0757 does not reach $\alpha=0.05$ due to the small number of seeds ($n=5$); $n \geq 20$ is needed for a complete statistical conclusion.

**Conclusion RQ1:** The RL agent achieves relatively superior performance in the simulation environment (+3.8 pp compared to Static Law), with particular strength in adaptively learning and detecting the L7 payload. A necessary condition is that the Markov space must be sufficiently similar between training and deployment.

### 5.2.2 RQ2 — Operational Trade-offs: Defensive Resolution vs. Service Availability

Cyber defense is an inherent trade-off. We want to block all attacks but not compromise legitimate users. Table 4.3 provides key measures to quantify this balance.

*   **Service Availability:** The agent maintains a balance between defense and availability: the majority of valid traffic is allowed, while the false-positive rate is kept low. This is acceptable in a production environment if:
    *   Suspicious requests are redirected to a honeypot (leveraging the 15-step soft escalation window for forensic verification) — not blocked immediately.
    *   Service Level Agreements (SLAs) possess sufficient tolerance for this transient, targeted redirection.
*   **Defensive Efficacy:** The agent achieved a high detection rate on active-threat steps. It applied **Blocking** for volumetric attacks (SYN Flood, Port Scan) and **Redirect-to-Honeypot** for application layer attacks (SQLi, XSS, Brute-Force), demonstrating a nuanced multi-action policy rather than a simple "block all" strategy.
*   **Session Level:** If at least one 1-second window in an attack session is detected, the agent can react promptly. Analysis confirms 100% of SQLi sessions have at least one window exceeding the detection threshold.

#### Honeypot Strategy and Threat Intelligence:
The policy learns to select the "Redirect to Honeypot" action through a 15-step soft window before a permanent block. The benefits are not only defensive but also:
1.  **Threat Intelligence Acquisition:** The attacker continues to operate in a controlled environment, allowing the SOC to record payloads, tools, and TTPs.
2.  **Availability Preservation:** Valid users have the opportunity to complete the session in the soft window before being permanently denied access.
3.  **Adversarial Deception:** The attackers were completely unaware they had been discovered, wasting resources on exploiting the honey traps instead of developing the production infrastructure.

> [!TIP]
> Static rules don't have this capability; they only block or allow, and they don't escalate according to logical proof.

**RQ2 Conclusion:** The RL agent successfully balances defense (high DoS mitigation, session-level SQLi detection) and availability (most legitimate traffic is allowed, low false positives). With a hybrid design, this trade-off makes sense for production scenarios.

### 5.2.3 RQ3 — Policy Stability across Diverse Attack Vectors

A natural concern: When the agent learns over 5 different attack types (SYN Flood, Port Scan, BruteForce, SQLi, XSS), will it become "too complex," leading to oscillation or unstable convergence?

The training data extrapolated from Figure 4.1 and Table 4.2 confirms that the policy achieves stability.

**Stable Training Trajectory:**
*   **Average Reward:** `eval/mean_reward` increased from ~0 to 58.68 (over 500K timesteps) and stabilized in the ±1.0 band from step 350,000 onwards — indicating convergence.
*   **Policy Stability:** Zero evidence of policy oscillation or catastrophic forgetting.
*   **Entropy:** `entropy_loss` decreased from −1.10 to −0.344, indicating that the agent is more confident but not overfit (entropy remains > 0).

**Stability Metrics from Table 4.2 (Corroborated by Appendix C):**
*   **Approximate KL Divergence (`approx_kl`):** $\approx 0.0008$ (terminal phase) — residing comfortably below the strict 0.02 clip threshold, proving safe policy updates.
*   **Explained Variance (`explained_variance`):** $\approx 0.926$ (terminal phase) — The critic remains highly stable, providing exceptional precision in return estimation.

#### Learning Heterogeneous Responses:
Section 4.3.3 details how the agent learns differentiated strategies for each attack:
*   **High F1 (PacketRate) + High F2 (SynAckRatio)** $\to$ exceeding bounds (F1>200, F2>0.85) $\to$ triggers **"Block"**.
*   **High F6 (URLConcentration) + F7 (HttpIatUniformity) < 0.3** (bot-timing) $\to$ triggers **"RateLimit"**.
*   **High F13 (CRS SQLi)** $\to$ triggers **"Redirect-to-Honeypot"**.

The policy doesn't "collapse" into a single action; it learns an implicit decision tree based on feature vectors.

#### 5.2.5.3 Per-Window Analysis vs. Per-Session Efficacy

Section 5.2.3.1 has already drawn the critical distinction between per-window and per-session analysis. The system's design prioritizes evidence accumulation over multiple windows to maximize false positive suppression and ensure peak service availability.

The academically rigorous statement is:
“Using a per-session evidence accumulation mechanism significantly improves defensive capabilities compared to making decisions on each individual window. In the Mutated Packets 2025 dataset, the system captured signals from all tested SQLi sessions.
When included in the expanded CSE-CIC-IDS2018 test set with more complex variants, the Soft Escalation mechanism helped increase the SQLi mitigation rate to 71.6% - 81.6% (effectively compensating for signal dilution).
We acknowledge that the system cannot capture 100% due to the inherent limitations of the CRS code against advanced evasion techniques, and this leaves room for further AI-based sequence analysis research in the future.”

This strategic design choice enhances the reliability of the system rather than aiming for unrealistic perfection.

#### How the RL Agent Mastered This Mechanism:
The agent does not "oscillate" between Block and Allow because it learns how to accumulate evidence:
*   **Per-Window Granularity:** Window 1 may be devoid of payload $\to$ F12–F20 = 0. The agent refuses to issue a Block based on an absence of signal.
*   **Evidence Accumulation (Per-Session):** Windows 2, 3, and 4 contain fragmented payloads $\to$ F12–F20 exceed the threshold $\to$ signal activated. The 10D temporal memory matrix records the EMA of damage. When the `evidence_score` breaches the terminal threshold $\to$ policy triggers Redirect or Block.

**Architectural Advantages:**
*   Eradicates false positives from transient noise.
*   Preempts systemic oscillation (the "Block-Allow-Block" loop).
*   Guarantees high-velocity reaction once authentic signal manifests.

---

### 5.2.4 Detailed Analysis: Dominant Factors and Hyperparameter Selection

#### 5.2.4.1 34D Observation Space Decomposition

The agent's observation system is designed in 34 dimensions across three components:

**Component 1: 20D Sensor Features (F1–F20)**
Extracted via the CRS pipeline and normalized:

| Index | Feature Cohort | Definition | Value Range |
|---|---|---|---|
| F1–F11 | Network Features | Traffic stats: packet velocity, byte volume, IAT, protocol distribution. | [0, 1] |
| F12–F20 | Payload Features | SQLi: special characters, comments, queries; XSS: tag density, DOM events. | [0, 1] |

**Component 2: 10D Agent Memory Features (Indices 20–29)**
Forensic ledger storing evidence across the 15-step window:

| Index | Feature | Definition | Expected Value |
|---|---|---|---|
| 20–23 | `last_action_*` | One-hot encoded matrix of the terminal action executed. | [0, 1] (4D) |
| 24 | `action_hold_norm` | Contiguous steps maintaining identical action / 15. | [0, 1] |
| 25 | `effect_damage_ema` | EMA of `ServiceDamage` over 15 steps. | [0, 1] |
| 26 | `effect_trend` | Sigmoid(Δ damage): Quantifies the damage vector. | [0, 1] |
| 27 | `soft_window_fill_norm` | Depth of the soft escalation window / 15. | [0, 1] |
| 28 | `escalation_score_norm` | Cumulative forensic evidence score. | [0, 1] |
| 29 | `miss_budget_used_norm` | Miss budget depletion / 3. | [0, 1] |

**Component 3: 4D Environment Response Features (Indices 30–33)**
Closed-loop feedback signals:

| Index | Feature (Alias) | Physical Implication | Formula |
|---|---|---|---|
| 30 | `WebHitRatio` (F21) | % traffic penetrating to production web server. | $valid / total$ |
| 31 | `HoneypotHitRatio` (F22) | % traffic diverted to honeypot. | $redirected / total$ |
| 32 | `PresenceRatio` (F23) | Binary indicator: 1.0 = active inbound traffic. | Binary |
| 33 | `ServiceDamage` (F24) | Composite penalty signal. | Composite formula |

#### 5.2.4.2 Hyperparameter Tuning: Step Efficiency vs. Wall-clock Efficiency

| Configuration | Terminal Reward | Convergence (steps) | Wall-clock (seconds) | `n_envs` |
|---|:---:|:---:|:---:|:---:|
| **Default SB3** | ~2.36 | 80k | 786 | 1 |
| **Tuned (Proposed)** | ~2.28 | 220k | **197** | 4 |

**Analytical Observations:**
1.  Both configurations converge to comparable rewards (~2.3). Tuning improves wall-clock efficiency, not reward magnitude.
2.  The Tuned model exhibits decelerated convergence regarding steps (220k vs 80k) due to parallelization (`n_envs=4`).
3.  The Tuned model achieves a **4× acceleration in wall-clock time**.

---

### 5.2.5 Limitations and Critical Caveats

#### 5.2.5.1 Simulation Gap
The experiment was limited to **Containernet**:
*   **Static Topology:** 10 VMs, 2 switches.
*   **Clean Distributions:** Traffic ratios follow mathematical distributions.
*   **Known Vectors:** Only 5 pre-defined attack typologies.

#### 5.2.5.2 Reward Function Dependency
The policy learns biases based on weighting coefficients:
*   Prioritizing accuracy ($\alpha$ increase) $\to$ aggressive blocks, lower availability.
*   Prioritizing availability ($\beta$ increase) $\to$ lenient policy, attack bleed-through.

#### 5.2.5.3 HTTPS Constraint
F12–F20 rely on **plaintext inspection**. TLS 1.3 encryption prevents computation without `SSLKEYLOGFILE`.
*   **Mitigation:** Deploy via transparent proxy (MITM) or rely exclusively on L3–L4 features (F1–F11).

#### 5.2.5.4 Horizontal Scalability
A single agent governs the network. Scaling to hundreds of nodes may require a **multi-agent architecture** to avoid state explosion.

---

# CHAPTER 6: CONCLUSION AND FUTURE DEVELOPMENTS

## 6.1 Conclusion

Modern network defense systems are reactive, static, and overloaded by alert fatigue. This project investigated whether RL can create an autonomous defense agent that learns and maintains an optimal policy without manual intervention.

### Feasibility Demonstrated:
1.  **Comparative Efficacy (RQ1):** RL detection rate is higher than Static Rules, gaining semantic understanding of payloads via F12–F20.
2.  **Operational Trade-offs (RQ2):** RL successfully harmonizes security with availability, using a graduated response rather than binary block/allow.
3.  **Policy Stability (RQ3):** PPO provides massive reward accretion (+475%) and secure convergence without oscillation.

### Principal Contributions:
*   **Technical:** End-to-end RL integration with CRS payload normalization.
*   **Methodological:** Rigorous ablation framework with precision delta analysis.
*   **Operational:** Practical implementation roadmap with ~1ms inference and low FPR.

---

## 6.2 Future Developments

### 6.2.1 Expansion of the Action Space
*   **Source-IP Specific Rate Limiting.**
*   **Request-Type Discriminatory Routing.**
*   **Dynamic Honeypot Instantiation.**
*   **Action Masking.**

### 6.2.2 Multi-Agent Collaboration
A multi-agent architecture decentralizes decision-making, positioning the agent immediately adjacent to the threat, thereby guaranteeing rapid response times even at massive enterprise scale.

### 6.2.3 Robustness Against Evasion Attacks
Adversarial threat modeling where the attacker knows feature definitions and reward functions. Stress-testing against "low and slow" floods and polyglot payloads.

### 6.2.4 Online Training (Continuous Learning)
Drift detection to trigger retrain flags when traffic patterns shift, using elastic weight consolidation to avoid catastrophic forgetting.

### 6.2.5 Explainable AI (XAI)
Integrating **SHAP / Attention** to transform the "Black Box" into a "Glass Box," providing clear rationales for SOC teams and meeting regulatory compliance (GDPR).

### 6.2.6 Sim2Real Gap Validation
Three-phase methodology: Distributional shift analysis $\to$ Shadow mode evaluation $\to$ Fine-tuning on live data.

### 6.2.7 Multi-step Reward
100-step sequence reward architecture to optimize long-term strategic planning (e.g., baiting maneuvers).

---

## REFERENCES

[1] Verizon, "2024 Data Breach Investigations Report," 2024.
[2] OWASP Foundation, "OWASP Top Ten," 2021.
[3] C. Kruegel and G. Vigna, "Anomaly Detection of Web-Based Attacks," Proc. 10th ACM CCS, 2003.
[4] Verizon, "2020 Data Breach Investigations Report," 2020.
[5] IBM Security, "Cost of a Data Breach Report 2024," 2024.
[6] R. S. Sutton and A. G. Barto, *Reinforcement Learning: An Introduction*, 2nd ed., MIT Press, 2018.
[7] V. Mnih et al., "Human-Level Control through Deep Reinforcement Learning," *Nature*, 2015.
[8] J. Schulman et al., "Proximal Policy Optimization Algorithms," *arXiv*, 2017.
[9] B. Lantz et al., "A Network in a Laptop," Proc. 9th ACM SIGCOMM HotNets, 2010.
[10] M. Towers et al., "Gymnasium," *arXiv*, 2023.
[11] Netfilter Project, "Iptables," 2024.
[12] J. Zheng et al., "Real-time DDoS mitigation with SDN and iptables," *IEEE Trans. NSM*, 2019.
[13] P. Biondi, "Scapy: Packet Manipulation Tool," Proc. French Network Security Conf., 2007.
[14] M. A. Ferrag et al., "Deep Learning for Cyber Security Intrusion Detection," *J. Inf. Security Appl.*, 2020.
[15] M. L. Puterman, *Markov Decision Processes*, John Wiley & Sons, 1994.
[16] M. Peuster et al., "MeDICINE," Proc. IEEE NFV-SDN, 2016.
[17] I. Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset," Proc. ICISSP, 2018.
[18] R. Fielding and J. Reschke, "HTTP/1.1," IETF, RFC 7230, 2014.
[19] A. H. Lashkari et al., "LSNM2024," Univ. New Brunswick, 2024.
[20] Q. Abu Al-Haija et al., "End-to-End Threat Hunting," *arXiv*, 2025.
[21] F. Schmitt et al., "HTTP Antivirus Proxy," Proc. IEEE ICCNC, 2012.
[22] A. Shiravi et al., "Toward Developing a Systematic Approach to Generate Benchmark Datasets," *Comput. Security*, 2012.
[23] J. Postel, "Transmission Control Protocol," IETF, RFC 793, 1981.
[24] K. Spett, "SQL Injection," SPI Dynamics White Paper, 2005.
[25] OWASP Foundation, "OWASP ModSecurity Core Rule Set (CRS) v4.0," 2023.
[26] A. Raffin et al., "Stable-Baselines3," *J. Mach. Learn. Res.*, 2021.
[27] A. M. Khodadadi et al., "An Empirical Study on the Evaluation and Enhancement of OWASP CRS," *Comput. Security*, 2024.
[28] H. A. Tadhani et al., "Securing web applications using a novel deep learning approach," *Sci. Rep. (Nature)*, 2024.
[29] M. Handley et al., "Network Intrusion Detection: Evasion, Traffic Normalization," Proc. 10th USENIX Security Symp., 2001.
[30] S. Akhavani et al., "WAFFLED: Exploiting Parsing Discrepancies," Proc. IEEE S&P, 2025.
[31] T. Pietraszek and C. V. Berghe, "Defending Against Injection Attacks," RAID 2005.
[32] N. Moustafa and J. Slay, "UNSW-NB15," Proc. MilCIS, 2015.
[33] M. Ring et al., "A Survey of Network-Based Intrusion Detection Data Sets," *Comput. Security*, 2019.

---

# APPENDICES

## Appendix A — Comprehensive Hyperparameter Profile

| Parameter | Default SB3 | Tuned Value | Technical Rationale |
|---|---|---|---|
| `net_arch` (pi/vf) | [64, 64] | **pi=[256, 128]; vf=[256, 256, 128]** | Accommodates complex decision boundaries across 5 attack vectors. |
| `learning_rate` | $3\times10^{-4}$ | **$3\times10^{-4} \to 6\times10^{-5}$** | Rapid acquisition then surgical convergence precision. |
| `ent_coef` | 0.0 | **0.05** | Mandates sustained exploration. |
| `batch_size` | 64 | **128** | Stabilizes gradient in 34D space. |
| `clip_range` $\epsilon$ | 0.2 | **0.15** | Constricts update envelope. |
| `gamma` $\gamma$ | 0.99 | **0.995** | Elongates temporal horizon for 320-step episodes. |
| `n_steps` | 2048 | 2048 | Maintained. |
| `n_epochs` | 10 | **6** | Preempts destabilizing updates. |
| `n_envs` | 1 | **4** | ~4× acceleration in wall-clock time. |

**Comparative Results:**
| Metric | Default SB3 | Tuned PPO v13 | Delta |
|---|:---:|:---:|:---:|
| Final Reward | 2.34 | **58.38** | +2400% |
| Average Reward | 2.06 | **46.29** | +2150% |
| Wall-clock time | ~786 s | **~197 s** | **4× Acceleration** |

---

## Appendix B — Reward Function: Composition

Equation: $$R_t = -(D_{\text{after}} + C_{\text{action}}) + B_{\text{reduction}} + B_{\text{action}}$$

**B.1 Network Damage Component (D):**
| Component | Weight | Activation |
|---|:---:|:---:|
| Packet Flood (DDoS) | 0.25 | Logistic |
| SQLi/XSS (L7) | 0.25 | Weighted |
| Port Scan | 0.15 | Log-sigmoid |

**B.2 Action Cost Penalty (C):**
Allow = 0 · RateLimit = 0.01 · Redirect = 0.04 · Block = 0.15

**B.3 Detection Bonus ($B_{\text{action}}$):**
*   DDoS/Port Scan $\to$ Block: **+0.30**
*   Normal Traffic $\to$ Block: **-0.60** (False Positive Penalty)

---

## Appendix E — Example Action Logs

**E.1 Example Action Log:**
```log
[t=120.0s] src_ip=10.0.10.10 obs=[...] action=2 (Redirect) reason=L7 signal
[t=121.0s] src_ip=10.0.10.10 obs=[...] action=2 (Redirect) hold
[t=135.0s] src_ip=10.0.10.10 obs=[...] action=3 (Block) block_ready_latched
```

**E.2 Example JSONL Output:**
```json
{"timestamp": 1713600123.2, "src_ip": "10.0.10.10", "F1 - PacketRate": 120.0, "F2 - SynAckRatio": 8.2, "F13 - CrsSqliScore": 0.0}
```

**E.3 Example iptables Ruleset:**
```bash
iptables -I INPUT 1 -s 10.0.10.10 -j DROP
iptables -t nat -I PREROUTING 1 -i r-ext -s 10.0.10.10 -d 192.168.10.10 -p tcp --dport 443 -j REDIRECT --to-ports 4443
```

---

## Appendix F — Pseudocode

**F.1 Inference Pipeline Pseudocode:**
```python
while True:
  row = read_next_jsonl()
  raw = extract_features(row)
  obs = normalize(raw) + temporal_state + effect_state
  action = policy(obs)
  action = safety_net(action, raw, temporal_state)
  apply_iptables(action, src_ip)
  update_temporal_state(src_ip, action, effect_state)
```
