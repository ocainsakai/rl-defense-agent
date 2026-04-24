# CHAPTER 4: EXPERIMENTAL RESULTS

## Table of Contents

- [4.1 Introduction](#41-introduction)
  - [4.1.1 Definition of Evaluation Metrics](#411-definition-of-evaluation-metrics)
- [4.2 Data Presentation](#42-data-presentation)
  - [4.2.1 Payload Normalization Pipeline Results](#421-payload-normalization-pipeline-results)
  - [4.2.2 CRS Paranoia Level Analysis](#422-crs-paranoia-level-analysis)
  - [4.2.3 Feature-Level Detection Performance](#423-feature-level-detection-performance)
  - [4.2.4 Feature Importance and Clustering](#424-feature-importance-and-clustering)
  - [4.2.5 Benchmark PPO vs DQN vs A2C (Protocol and Data)](#425-benchmark-ppo-vs-dqn-vs-a2c-protocol-and-data)
  - [4.2.6 PPO Hyperparameter Tuning](#426-ppo-hyperparameter-tuning)
  - [4.2.7 Convergence and Training Stability Analysis of v13 PPO Model](#427-convergence-and-training-stability-analysis-of-v13-ppo-model)
  - [4.2.7.1 PPO Default vs PPO v13 (Tuning Impact)](#4271-ppo-default-vs-ppo-v13-tuning-impact)
  - [4.2.8 Final Evaluation Results](#428-final-evaluation-results)
  - [4.2.9 Validation of v13 PPO Model on Real-World Datasets](#429-validation-of-v13-ppo-model-on-real-world-datasets)
- [4.3 Results Analysis](#43-results-analysis)
  - [4.3.1 Analysis by Traffic Group](#431-analysis-by-traffic-group)
  - [4.3.2 Policy Behavior Analysis](#432-policy-behavior-analysis)
  - [4.3.3 Benchmark PPO vs DQN vs A2C Analysis](#433-benchmark-ppo-vs-dqn-vs-a2c-analysis)
  - [4.3.4 Conclusion](#434-conclusion)
- [4.4 Results Interpretation](#44-results-interpretation)
  - [4.4.1 Overall Evaluation](#441-overall-evaluation)
  - [4.4.2 Real-World Scenario Validation](#442-real-world-scenario-validation)
  - [4.4.3 Three Core Design Decisions](#443-three-core-design-decisions)
- [4.5 Comparison with Literature](#45-comparison-with-literature)
- [4.6 Implications of Results](#46-implications-of-results)
  - [4.6.1 When to Prioritize RL over Static Rules?](#461-when-to-prioritize-rl-over-static-rules)
  - [4.6.2 Minimum Infrastructure Requirements](#462-minimum-infrastructure-requirements)
  - [4.6.3 Honeypot as a Strategic Advantage](#463-honeypot-as-a-strategic-advantage)
  - [4.6.4 Policy Reusability](#464-policy-reusability)
  - [4.6.5 Future Directions](#465-future-directions)

---

## 4.1 Introduction

This chapter focuses on the experimental evaluation of the proposed defense system, including the Observer Module and the Reinforcement Defense Agent (RL). The evaluation process is carried out in two key aspects: first, analyzing the accuracy of feature extraction and processing performance of the Observer Module; second, evaluating the convergence capability during training and the policy execution effectiveness of the RL agent.

### 4.1.1 Definition of Evaluation Metrics

**Detection Rate:** Computed exclusively over *active-threat steps* (timesteps where the attack is actively manifesting). Silent steps subsequent to a Block action are deliberately excluded from the sample space to preclude artificial inflation of the metrics.

**False Positive Rate (FPR):** Calculated over *normal-traffic steps* (timesteps involving purely benign, legitimate traffic).

**Per-Window vs. Per-Session Evaluation:** The *per-window* metric assesses detection on aisolated 1-second interval basis. Conversely, the *per-session* metric deems an entire session successfully detected if at least one constituent window within that session breaches the detection threshold.

The entirety of the experimental framework was executed on a Linux environment utilizing the Containernet platform. The operational architecture is anchored in Python 3.x, deploying Stable-Baselines3 (which necessitates `numpy < 2.0`). Reproducibility is enforced by locking the random seed at 42 across all stochastic functions.

Five distinct data sources were leveraged to fulfill varied evaluative objectives, detailed at 3.2.4

---

## 4.2 Data Presentation

### 4.2.1 Payload Normalization Pipeline Results

Intrusion detection systems predicated on pattern matching confront a fundamental challenge: an identical attack payload can be instantiated across multiple encoding schemas while preserving semantic equivalence at the target server. Handley et al. [29] formalized this as the "ambiguity in the packet stream" problem, proving that a detection engine must holistically resolve this ambiguity prior to pattern application—otherwise, adversaries can systematically bypass the engine by selecting an unrecognized representational format. While individual normalization techniques in the academic literature typically address specific evasion classes, a concatenated pipeline is indispensable because real-world attackers routinely stack multiple encoding layers simultaneously, generating a combinatorial space that no single step can adequately cover [30].

To address this, the system constructs a sequential 8-step payload normalization pipeline preceding the CRS pattern matching. The execution sequence constitutes a rigid constraint: HTML entity decoding must precede URL decoding (e.g., `&#x25;27` → `%27` → `'`); similarly, URL decoding must occur before Base64 decoding because `%3D` serves as the Base64 padding character.

**Size Limitation (64 KB):** Mitigates resource exhaustion attacks via excessively large payloads that could induce ReDoS (Regular Expression Denial of Service) within complex CRS regex evaluations.

**Bytes-to-String Conversion** (UTF-8 with Latin-1 fallback): Ensures uniform byte representation, circumventing data loss.

**HTML Entity Decoding:** Counters a prevalent XSS bypass technique, acknowledging that `&lt;script&gt;` and `<script>` possess identical execution semantics within a browser environment [30].

**Unicode NFKC and Smart Quotes Normalization:** Prevents bypasses utilizing full-width characters (e.g., `ａｌｅｒｔ` → `alert`) and Unicode homoglyphs embedded within SQL keywords [30].

**Recursive URL Decoding (Maximum 2 Iterations):** Addresses double-encoding (`%2527` → `%27` → `'`)—a technique identified by Akhavani et al. [30] as the most ubiquitous cause of WAF bypasses in empirical analyses.

**Recursive Base64 Decoding (Maximum 2 Iterations):** Detects attack payloads encapsulated within Base64 strings, a documented evasion tactic observed in live CRS deployments [27].

**Whitespace Normalization:** Eliminates whitespace manipulations (tabs, multi-spaces, newlines within SQL queries) engineered to fracture pattern matching mechanisms [31].

**Lowercase Conversion:** Imposes consistent case-insensitive matching across the entire analytical pipeline [31].

The normalized outputs are systematically cached via packet identifiers, ensuring that each packet traverses the pipeline precisely once, even if multiple feature extractors access the identical payload.

### 4.2.2 CRS Paranoia Level Analysis

This section presents the results of an empirical evaluation of the ModSecurity Core Rule Set (CRS) to determine the optimal Paranoia Level (PL) for two key features: F13 (SQL Injection) and F18 (Cross-Site Scripting).

The experiment used the LSNM2024 SQLi dataset ($n = 2,809 attack samples and 3,000 normal samples). Note that this evaluation was performed on each individual URI to verify the sensitivity of the filter before combining it into a 20-dimensional feature vector.

| PL | Rules | TP | FP | F1-Score | FPR | Decision |
|---|---|---|---|---|---|---|
| PL1 | 19 | 1,695 | 0 | 0.753 | 0.0% | FPR=0, but misses 40% of attacks. |
| **PL2** | **50** | **2,809** | **459** | **0.925** | **15.3%** | **Optimal — Selected.** |
| PL3 | 57 | 2,809 | 520 | 0.915 | 17.3% | Higher FP; no improvement over PL2. |

n = 2,809 SQLi URIs + 3,000 benign URIs from LSNM2024 (Lashkari et al., 2024).

Note: This evaluation is performed on isolated URIs (not 1-second windows); hence, the TP/FP/FPR metrics reflect the isolated efficacy of F13 prior to its integration into the 20D vector.

PL2 was selected: With $F1-Score = 0.925$ and $Recall = 1.0$, PL2 ensures that no SQLi variants are missed in the test set. PL1 achieves zero false positives but misses 40% of attacks, making it unsuitable as a detection signal. PL3 offers no improvement over PL2 while increasing false positives. The URI-level FPR of 15.3% reflects isolated CRS scoring; within the full 20D feature vector, F13 is one signal among many and is weighted accordingly by the RL agent's learned policy.

**CRS XSS (F18) Analysis:** The CRS-941 benchmark against The experiment used the LSNM2024 XSS dataset with 123 GET attack samples (including script-tag and event-handler injections) and 3,000 normal samples. POST body attack samples were excluded due to limitations in the source file's data structure.

| PL | Rules | TP | FP | F1-Score | Decision |
|---|---|---|---|---|---|
| PL1 | 22 | 123 | 0 | 1.000 | Sufficient on test set. |
| **PL2** | **27** | **123** | **0** | **1.000** | **Selected.** |
| PL3 | 27 | 123 | 0 | 1.000 | No improvement over PL2. |

Recall = 1.0, FPR = 0.0% across all levels with the URI-embedded test set.

PL2 was selected to guarantee broader coverage against obfuscated event-handler patterns. Within the system architecture, F18 serves as a supplementary signal to F19/F20 (binary indicators)—the RL Agent is purposefully not solely reliant on F18 to classify XSS vectors.

### 4.2.3 Feature-Level Detection Performance

To verify the effectiveness of the extracted features, the study independently evaluated each feature group using a binary classification model (Random Forest, 200 decision trees). The experiment was performed on a CSV dataset extracted from the PCAP Mutation Packet dataset (Abu Al-Haija et al., 2025).

Table 4.1: Classification Results per Feature Cluster (Source: Mutated Packets PCAP Dataset, Abu Al-Haija et al., 2025; RandomForest 200 trees, balanced sampling, 70/30 split, seed=42)

The evaluation unit is the 1-second window. Each "sample" is a 20D vector representing one temporal window. A typical attack session spanning 30–120 seconds generates 30–120 windows, yet only a fraction of these actively contain the attack payload.

| Attack Type | Primary Features | Precision | Recall | F1-Score | Test Set (Windows) |
|---|---|---|---|---|---|
| SYN Flood | F1, F2, F9 | 0.991 | 1.000 | 0.995 | 426 windows |
| Port Scan | F4, F5, F11 | 1.000 | 0.508 | 0.674 | 969 windows |
| Brute Force | F6, F7, F8 | 0.520 | 1.000 | 0.684 | 1,749 windows |
| SQLi | F13, F14–F16 | 1.000 | 0.263 | 0.417 | 532 windows |
| XSS | F18, F19–F20 | 1.000 | 0.075 | 0.140 | 187 windows |

**Brief Observation:** The network feature cluster exhibits exceptional accuracy in identifying SYN Floods, whereas SQLi/XSS demonstrate diminished recall at the per-window level due to the temporal sparsity of the payload.

**Explanation of results:** The SYN Flood attack achieved an F1 score of 0.995 because the network characteristics (F1, F2, F9) clearly defined the entire attack window—the attack flooded every window in the session. Conversely, the reduced precision (Recall) for SQLi (0.263) and XSS (0.075) is a natural consequence of the window-by-window analysis design: only individual 1-second windows containing actual HTTP requests with payload trigger F12–F20. Empirical analysis of the dataset confirms that 75.4% of windows in an SQLi session do not contain an attack payload (only including TCP setup/cancellation/response), with a comparable sparseness of 92.6% observed in XSS sessions.

**Critical Distinction — Per-Window vs. Per-Session:** A Recall of 0.263 for SQLi signifies that 26.3% of the 1-second windows within the SQLi session are correctly classified as attacks—it does not imply that 26.3% of the attack sessions evaded detection. At the session level, if a minimum of one window within the session is correctly identified, the RL Agent possesses the capacity to react instantaneously. Detailed analysis of the test set verifies that 100% of the SQLi sessions exhibit at least one window breaching the detection threshold, a finding mirrored in the XSS evaluation.

A precision of 1.000 for SQLi and XSS conclusively verifies the absence of false positives—every window classified as an attack unequivocally contained a malicious payload. The lower Recall for Port Scans (0.508) and the attenuated Precision for Brute Force (0.520) reflect a similar dynamic: numerous windows within a scan or brute force session consist of interleaved benign traffic. A precision of 0.520 for Brute Force implies that approximately 48% of the windows flagged as Brute Force actually contained normal traffic—specifically, legitimate web traffic exhibiting a high URLConcentration (e.g., multiple login attempts within the same window by an authentic user). In operational deployment, the RL Agent is not required to detect 100% of the windows; it merely requires a sufficiently early signal within the attack session to initiate mitigation.

### 4.2.4 Feature Importance and Clustering

Random Forest Feature Importances on the CSV set extracted the F1 (PacketRate) and F13 (CRS SQLi) claims as the biggest contributors, consistent with the characteristics of DDoS and SQLi attacks. The t-SNE plot (perplexity = 30) plots the 20-dimensional vector along two main axes, showing clearly separated attack clusters and normal traffic — the F1–F20 claims are highly distinguishable and do not overlap in labels.

### 4.2.5 Performance Evaluation (Benchmark) of PPO, DQN, and A2C

The benchmark test was established based on the principle of strict variable control to ensure objectivity:

- **Environment:** All algorithms ran on the same simulation environment with a 34-dimensional state space.
- **Algorithm Configuration:** Using the default settings of the Stable Baselines3 (SB3) library, no hyperparameter tuning was performed to evaluate the natural convergence of the algorithm.
- **Training Process:** The system trained with a single environment (n_envs=1). The final model was extracted as the official checkpoint for evaluation, instead of selecting the best model to reflect final stability.
- **Statistical method:** To eliminate random error, each algorithm was trained on 5 sets of random numbers (train seeds: 42, 123, 456, 789, 1337). For each model after training, the evaluation process was performed on 5 sets of eval seeds (1001–1005) with 6 episodes each. A total of 30 episodes were performed for each training seed in each mode. The final results were aggregated as the mean with a 95% confidence interval (CI).

Table 4.2: Qualitative Comparison of RL Algorithms

| Criteria | DQN (Deep Q-Network) | A2C (Advantage Actor-Critic) | PPO (Proximal Policy Optimization) |
| :--- | :--- | :--- | :--- |
| **Approach** | Value-based: Learns the $Q(s,a)$ value function. | Actor-Critic: Hybrid of policy and value learning. | Policy-based: Directly optimizes the action policy. |
| **Learning Mode** | Off-policy: Learns from historical data in a replay buffer. | On-policy: Learns directly from current experiences. | On-policy: Learns from current data with multiple updates. |
| **Action Space** | Primarily Discrete. | Discrete & Continuous. | Discrete & Continuous. |
| **Stability** | Moderate (Prone to Q-value overestimation). | Low (High variance, sensitive to noise). | Very High (Clipped objective prevents large updates). |
| **Sample Efficiency** | High (Reuses past data). | Low (Requires more interactions). | Moderate (Balanced stability and efficiency). |
| **Core Mechanism** | Experience Replay & Target Network. | Advantage Function (Reduces variance). | Clipped Surrogate Objective (Limits policy shifts). |

The four evaluation modes are structured to decouple two independent variable axes — session continuity and noise/drift — ensuring performance changes are attributed to the correct source. Detailed parameters are presented in Table 4.3; a causal interpretation of the results is provided in Section 4.3.3.

Table 4.3: Evaluation Mode Parameters and Analytical Implications

| Eval Mode | session_block_size | missing_prob | drift_max | Implication |
|---|---:|---:|---:|---|
| round_robin | 0 | 0.08 | 0.35 | IID-like normal evaluation. |
| round_robin_stress | 0 | 0.15 | 0.50 | Stress noise/drift overlaid on round-robin. |
| session_20 | 20 | 0.08 | 0.35 | Closed-loop/session evaluation. |
| session_20_stress | 20 | 0.15 | 0.50 | Stress noise/drift overlaid on the session context. |

Table 4.4: Benchmark PPO/DQN/A2C — Raw Defensive Performance (round_robin)

| Algorithm | Mean Reward | Mitigation % | Exact Response % | Service Damage AUC |
|---|---:|---:|---:|---:|
| PPO | 58.80 | 97.65 | 90.81 | 0.0644 |
| DQN | 60.71 | 99.54 | 92.26 | 0.0583 |
| A2C | 24.46 | 95.97 | 85.59 | 0.0764 |

In the round-robin mode, DQN leads on raw defensive indicators, while A2C demonstrates a significant performance gap. A causal explanation of this divergence is provided in Section 4.3.3.

Table 4.5: Benchmark PPO/DQN/A2C — Benign-Safety Trade-off (round_robin)

| Algorithm | Mitigation % | Benign Intervention % | Benign Harm Score | Mitig/BenignInt | Mitig/BenignHarm |
|---|---:|---:|---:|---:|---:|
| PPO | 97.65 | 0.65 | 0.79 | 150.2 | 123.3 |
| DQN | 99.54 | 1.39 | 1.39 | 71.5 | 71.5 |
| A2C | 95.97 | 22.27 | 22.27 | 4.3 | 4.3 |

Note: The ratios `Mitig/BenignInt` and `Mitig/BenignHarm` are descriptive magnitude indicators and are not deployed as primary statistical evidence. The full trade-off analysis is presented in Section 4.3.3.

### 4.2.6 PPO Hyperparameter Tuning

Hyperparameters: The table below compares the PPO tuning (v13) configuration with the SB3 default utilized as a baseline.

| Parameter | Default SB3 | Deployed Value | Tuning Rationale |
|---|---|---|---|
| Total training steps | — | ~500k timesteps | Terminate upon reward saturation (empirical convergence) |
| net_arch (pi/vf) | [64, 64] | pi=[256, 128]; vf=[256, 256, 128] | Increase capacity to map decision boundaries across 5 attack spaces |
| learning_rate | $3\times10^{-4}$ (fixed) | $3\times10^{-4} \to 6\times10^{-5}$ (linear decay) | Rapid learning initially, precise fine-tuning in the terminal phase |
| clip_range $\epsilon$ | 0.2 | 0.15 | Tighten policy updates to prevent overshoot |
| gamma $\gamma$ | 0.99 | 0.995 | Extended long-term vision suited for a 320-step episode |
| gae_lambda | 0.95 | 0.97 | Stabilize advantage estimation over extended action sequences |
| ent_coef | 0.0 | 0.05 | Sustain exploration, preventing premature convergence to a single action |
| batch_size | 64 | 128 | Enhanced gradient stability with a 34D State space |
| n_steps | 2048 | 2048 | Maintained — optimal rollout buffer dimension |
| n_epochs | 10 | 6 | Decrease epoch count to avoid aggressively intense updates |
| n_envs | 1 | 4 | Parallelize 4 environments, accelerating training $\sim 4\times$ |
| Seed | 42 | 42 | Ensure result reproducibility |

### 4.2.7 Convergence and Training Stability Analysis of v13 PPO Model

Table 4.6 catalogs the internal PPO algorithmic metrics extracted from TensorBoard, substantiating the stability of the training process and the absence of deleterious anomalies.

Table 4.6: PPO Diagnostic Metrics during Training

| Metric | Initial Value | Terminal Value | Status | Interpretation |
|---|---|---|---|---|
| eval/mean_reward | — | 58.68 | Optimal | Reward ascends and stabilizes at terminal training phase. (Per-episode cumulative reward, n_envs=4, episode_length=320 steps; per-step equivalent ≈ 0.183.) |
| approx_kl | — | 0.0008 | Optimal | Sub-threshold (<0.02) — guarantees safe policy updates. |
| clip_fraction | — | 0.013 | Optimal | Gradient clipping is rarely invoked near convergence. |
| clip_range | — | 0.15 | Fixed | ε = 0.15 as per architectural design. |
| entropy_loss | — | −0.344 | Optimal | Agent exhibits high confidence; exploration is maintained. |
| explained_variance | — | 0.926 | Optimal | Critic is stable, providing an excellent return estimation. |
| value_loss | — | 1.44 | Optimal | Loss diminishes and stabilizes. |
| learning_rate | — | 6×10⁻⁵ | Optimal | Linear decay functions according to design. |

**Brief Observation:** All PPO metrics operate within optimal healthy thresholds, devoid of any indications of excessively aggressive policy updates.

Figure 4.1b: PPO Training Dynamics (train/policy_loss, train/value_loss, train/approx_kl, train/clip_fraction)

Figure 4.1c: Critic Criteria (explained_variance and train/value_loss)

**Learning Curve Analysis:**
The TensorBoard trajectories provide definitive evidence of highly structured learning dynamics:

**Trajectory of Cumulative Return:** The `eval/mean_reward` value monotonically escalates from 0 to ~58.68 over 500K timesteps, delineated into three distinct phases:

- Exploration phase: Timesteps 0–100K, characterized by sluggish reward accretion (slope ≈ 0.2/10K steps).
- Rapid improvement phase: Timesteps 100K–350K, marked by accelerated reward gains (slope ≈ 0.5/10K steps), aligning with the Agent's emergent capacity to discriminate attack typologies.
- Saturation phase: Timesteps 350K–500K, where the reward stabilizes within the [58.5, 58.9] band, exhibiting an amplitude ≤ ±0.2 (coefficient of variation < 0.4%), confirming that the policy has converged near a local optimum.

**Episode Length Invariance:** The `eval/mean_ep_length` metric remains steadfast at ~320 steps, perfectly mirroring the environment's spatial configuration (16 IPs × 20 steps/IP). This invariance confirms the absence of anomalous early terminations or unwarranted episode prolongations instigated by the Agent's actions.

**Entropy Trajectory:** The `train/entropy_loss` value undergoes logarithmic decay from ~−1.1 to ~−0.344, identifying an inflection point around 250K timesteps. The positive entropy configuration indicates that the Agent successfully preserves an exploratory vector (exploration entropy) even during the terminal phases, effectively circumventing "policy collapse" or premature deterministic lock-in.

**PPO Diagnostic Metrics:**
These metrics, monitored by the PPO algorithm, serve to gauge the physiological health of the policy update sequence:

**Approximate KL Divergence (`approx_kl`):** The terminal training value of ≈ 0.0008 resides well below the default clip threshold of 0.02. This affirms that the divergence separating the antecedent policy (π_old) from the updated policy (π_new) consistently remains confined within the trust region. Consequently, gradient updates are demonstrably safe, completely averting policy disruption. This suppressed value simultaneously suggests that the learning rate and clipping parameters are optimally configured.

**Clipped Fraction:** The terminal value of ≈ 0.013 implies that a mere 1.3% of the gradient updates were subjected to clipping for breaching the ε = 0.15 range. This minimal clip ratio signifies that the vast majority of updates occurred within safe bounds; an elevated ratio (>0.2) would be diagnostic of an excessive learning rate or a model undergoing chaotic, hyper-accelerated structural alterations.

**Explained Variance of Value Function:** The value of ≈ 0.926 indicates that the critic accurately models 92.6% of the variance inherent in the empirical returns. Proximity to 1.0 demonstrates exceptional congruence between the value function and the data, meaning the bootstrap estimate (the return estimation predicated on the value function) in TD learning commands high precision. A value < 0.8 would signify critic underfitting.

**Value Loss:** The trajectory exhibits a steady decline from its initial state down to ~1.44, where it achieves stabilization. This trajectory encapsulates the critic's process of learning feature representations optimized for return prediction. Convergence without continuous decline on the training set confirms that the critic avoids overfitting (unconstrained overfitting would manifest as endlessly descending training value loss decoupled from evaluation return improvements).

**Escalation Strategy Metrics Analysis:**
These metrics were architecturally tailored to monitor the policy's soft escalation behavior:

**Escalation Rate (SQLi, XSS, Brute Force):** The fraction of Redirect actions that are successfully upgraded to Block following the saturation of the soft escalation window (15 steps) with accumulated evidence. Values oscillating between 0.79 and 0.99 reveal:

- SQLi: 79% of sessions are upgraded; 21% fail to breach the escalation threshold (potentially due to the honeypot effectively neutralizing the attacker).
- XSS: 99% of sessions are upgraded, reflecting the policy's internal assessment of XSS as critically severe, necessitating definitive Blocking.
- Brute Force: 82% of sessions are upgraded, suggesting that certain brute force sessions are truncated prematurely by rate limiting.

**Overall Escalation Rate:** ~0.85 — On average, 85% of Redirect decisions are subsequently followed by a Block decision, confirming that the soft escalation mechanism functions precisely as engineered.

**Premature Block Rate:** ~0.15 — The frequency at which a Block is issued prior to the complete fulfillment of the soft escalation window. A value exceeding 0 yet remaining well below 0.5 indicates that the Agent possesses a learned tendency to await corroborating evidence prior to Blocking, while retaining the capacity to execute instantaneous Blocks when confronted with overwhelming attack signatures (e.g., a SYN Flood fully saturating the window).

**Benign False Block Rate:** 0 — Zero Block actions were executed against valid traffic in the preflight simulation environment (MockIPBehavior, 50 episodes). Note: this metric is measured on the training-distribution simulator where benign traffic has F13=0 by design. On the out-of-distribution Thursday benchmark (Section 4.2.9), Raw PPO registers a 3% redirect FPR on real benign traffic — a distinct metric reflecting distributional shift, not a contradiction.

**Global Stability Assessment:**
The synthesis of the aforementioned elements permits the following conclusive deductions:

**Convergence Achieved:** The pronounced plateau of `eval/mean_reward` commencing from the 350K timestep serves as conclusive proof that the policy has converged upon a stable equilibrium.

**Absence of Catastrophic Forgetting:** The value loss remains completely stable; catastrophic forgetting would manifest as precipitous collapses in reward.

**Differentiated Policy:** The heterogeneity of the escalation metrics across distinct attack modalities (SQLi escalation rate ≠ XSS escalation rate ≠ Brute Force escalation rate) proves that the policy has successfully synthesized an implicit decision tree, deliberately refraining from "collapsing" into a monolithic, undifferentiated action vector.

#### 4.2.7.1 PPO Default vs PPO v13 (Tuning Impact)

The v13 model represents the culmination of extensive hyperparameter tuning applied to the baseline PPO architecture selected via the benchmark (Section 4.2.5). To quantitatively ascertain the impact of this tuning, a rigorous comparison against the default PPO configuration (SB3 defaults) was executed.

Table 4.7: PPO Default vs PPO v13 (Tuning Impact)

| Metric | Default PPO | v13 Tuned | Improvement |
|--------|-------------|-----------|----------|
| Final Reward (500K steps) | 2.34 | 58.68 | +2400% (see note) |
| **Reward per Step** | **0.0195** | **0.1834** | **+840% (fair comparison)** |
| Average Reward | 2.06 | 46.29 | +2150% |
| Episode Length | 120 steps | 320 steps | +167% |
| Stability (CV) | 0.9719 | 0.9932 | Comparable |
| Wall-clock (500K steps) | 786s | 197s | **4× faster** |
| Convergence Status | Sluggish | Accelerated | (Pass) |

Note: Data derived from 25 evaluation checkpoints, with each checkpoint assessed across 6 episodes. CV = Coefficient of Variation (std/mean). The +2400% raw reward difference reflects both tuning quality and the episode length extension (120 → 320 steps) and is therefore not directly comparable on an absolute basis. The per-step metric (+840%) provides the fair comparison.

**Interpretation of Results:**
The 2400% raw reward difference primarily reflects the episode length extension (120→320 steps); on a per-step basis, v13 achieves a reward rate of 0.183/step versus 0.020/step for Default PPO (+840%). The primary operational benefit of tuning is the **4× wall-clock acceleration** (786s → 197s) via n_envs=4 parallelization. This improvement is principally attributable to:

**Policy Learning Rate Optimization:** v13 deploys a calibrated learning rate schedule, empowering the policy to learn rapidly during the initial exploration phase, followed by precise decelerations in update velocity as convergence is approached.

**Entropy Regularization Tuning:** v13 modulates the entropy coefficient to perfectly balance exploration against exploitation. The Default PPO exhibits a detrimental bias toward exploitation, inevitably precipitating premature convergence upon sub-optimal local minima.

**Episode Length Extension:** v13 amplifies the episode duration from 120 to 320 steps (reflecting the 16 IP configuration at 20 steps/IP), endowing the policy with the necessary temporal horizon to internalize long-term dependencies and effectively implement the soft escalation logic.

**Network Architecture:** v13 has the capability to leverage variant network dimensions (dense layers, hidden units), facilitating the acquisition of vastly more complex representations suited for the high-dimensional 34D state space.

**Conclusion:** Hyperparameter tuning transcends mere absolute reward augmentation; it fundamentally extends the episode length, granting the learning dynamics the requisite temporal runway for the soft escalation mechanism to operate. The commanding performance superiority of v13 dictates its utilization for real-world validation.
4.2.8 Final Evaluation Results
The terminal policy was evaluated via the `preflight_eval.py` script across 50 episodes, utilizing the optimal model derived from the `run_34d_v13` training run.
Table 4.8: Action Classification Results for the RL Defense Agent (Source: preflight eval 50 episodes on the MockIPBehavior simulated environment)

| Traffic Group | Mitigate Rate | Block Rate | Remarks |
|---|---|---|---|
| Attacker | **99.7%** | 52.1% | The overwhelming majority of attacks are successfully mitigated. |
| Benign | 0.1% | **0.0%** | Zero false blocks recorded. |
| Noisy | 52.4% | 0.0% | Predominantly handled via RateLimit. |
Action Distribution: Allow 31.0% | RateLimit 6.6% | Redirect 47.2% | Block 15.1%.

Figure 4.3a: PPO Action Distribution
Brief Observation: The policy strategically prioritizes Redirect for L7 threats, avoids erroneous Blocks on benign traffic, and employs RateLimit as a proportional response to noisy traffic.

4.2.9 Validation of v13 PPO Model on Real-World Datasets
[Figure 4.5, 4.6, 4.7, 4.8]
Figure 4.5: Confusion matrix heatmap (CIC-IDS2017 Friday & CSE-IDS2018 Friday)
Figure 4.6: 3-Layer Diagnosis Comparison (Layer 1/2/3 on CSE-IDS2018 Friday)
Figure 4.7: Benign FPR vs Attack Mitigation Tradeoff
Figure 4.8: Attack Distribution & Detection Rates heatmap
To verify the generalization capacity of the v13 model, the architecture was subjected to evaluation utilizing authentic real-world datasets extracted from CIC-IDS2017 and CSE-CIC-IDS2018, public repositories containing genuine attacks captured within controlled operational environments.
3-Layer Evaluation Design:
To disentangle error sources and pinpoint the exact locus of analytical failure, the benchmark is architected across three escalating layers of complexity. Each layer integrates an additional component to isolate its specific impact:
**Layer 1 (Raw PPO) — Pure Policy Output:**

- Input: 34-dimensional vector = [20D observational features + 10D temporal state + 4D closed-loop effect state].
- Processing: The v13 model ingests the input vector and outputs a direct action vector.
- Output: The raw policy action (devoid of post-processing or safety overrides).
- Objective: Quantifies the fundamental classification capacity of the neural network. Policy errors at this layer indicate systemic deficiencies in model learning.
- Example: If the policy output dictates "Block" during a SYN Flood, but the ground truth requires "Allow", the locus of failure is firmly rooted in L1.
**Layer 2 (Stateless AI Agent) — Isolating the Impact of Temporal State:**
- Input: 20-dimensional vector = [observational features, deliberately omitting the 10D temporal state and 4D effect state].
- Processing: The v13 model evaluates the 20D feature space entirely bereft of historical context.
- Output: The policy action derived without the temporal memory matrix.
- Objective: Quantifies the impact of the temporal state. Divergence between L1 and L2 within the identical window firmly establishes temporal information as the decisive variable. Parity between L1 and L2 confirms that the temporal state was superfluous for that specific decision.
- Example: Analyzing the 5th window within a Brute Force session:
  - If L1 (leveraging the history of 4 prior windows) = "Block" (Correct)
  - And L2 (evaluating window 5 in absolute isolation) = "Allow" (Incorrect)
  - The divergence demonstrates that the temporal state actively facilitates detection.
**Layer 3 (System Response) — Holistic Defensive System:**
- Input: The L2 action augmented by all systemic auxiliary components.
- Processing:
    1. Executes the RL action (Allow/RateLimit/Redirect/Block).
    2. Invokes the soft escalation logic (if the 15th+ window of a session continues to register attack signals → upgrades Redirect to Block).
    3. Enforces firewall rules (iptables, rate limiting).
    4. Triggers the safety guard intervention if deemed necessary (to preempt erroneous blocking of benign traffic).
- Output: The definitive operational decision (Allow/Block/RateLimit).
- Objective: Measures the authentic operational efficacy of the integrated system. L2 and L3 parity indicates that auxiliary components (escalation, safety guard) exerted no influence. Divergence indicates systemic intervention.
- Example: During an SQLi attack:
  - L2 = "Redirect" (policy estimation).
  - L3 = "Block" (post 15-window soft escalation, the policy has amassed conclusive evidence).
  - The superiority of L3 over L2 confirms that the escalation logic improves decision-making.
Results on CIC-IDS2017 Friday DDoS (SYN Flood):
| Metric | Layer 1 (Raw PPO) | Layer 2 (Stateless) | Layer 3 (System) | Interpretation |
|--------|---|---|---|---|
| Overall Accuracy | 100.0% | 100.0% | 99.9% | Raw policy is flawless; L3 incurs a negligible 0.1% error margin localized at the kernel execution level. |
| Mitigation Rate | 100.0% | 100.0% | 99.9% | Total eradication and mitigation of all SYN packets. |
| Safety Overrides | 0 | — | 0 | Zero requirement for safety guard intervention. |
| False Positives | 0 | — | 0 | Absolute preservation of legitimate traffic without erroneous blocks. |
n = 1,169 windows extracted from Friday-07-07-2017 DDoS PCAP, utilizing 20D network features (SYN flood lacks application-layer content).
Results on CIC-IDS2017 Friday Port Scan:
| Metric | Layer 1 | Layer 2 | Layer 3 | Interpretation |
|--------|---|---|---|---|
| Overall Accuracy | 98.5% | 98.5% | 97.8% | Port scan detection remains highly stable, exhibiting minor false positives triggered by legitimate, aggressive port scanning behavior. |
| Mitigation Rate | 94.2% | 94.2% | 93.5% | Overwhelming majority of scans detected; select "friendly" IP entities deliberately bypass blocking. |
| False Positives | 4.1% | 4.1% | 5.2% | Elevated FP at L3 is an artifact of the escalation logic mandating accumulated evidence prior to blocking. |
| Safety Overrides | 2.3% | — | 3.8% | The safety guard intervenes in 3.8% of instances (predominantly substituting Block with RateLimit). |
n = ~1,200 windows, utilizing 20D network features (F6: URLConcentration and F7: HttpIatUniformity functioning as primary port scan signatures).
Results on CSE-CIC-IDS2018 Friday Multi-Attack (2018-02-23):
This complex dataset encapsulates a heterogeneous amalgamation of three distinct attack vectors deployed sequentially across a single operational day: Brute Force (10h–11h), XSS (13h–14h), SQLi (15h–15h30m). Friday functions as the primary attack evaluation day.
| Attack Type | Label Count | Expected Action | Raw Accuracy | Stateless (L2) | Mitigation Rate | Remarks |
|---|---|---|---|---|---|---|
| Benign | 1,702 | Allow | 98.0% | 98.0% | — | HTTPs + DNS + SSL handshake traffic. |
| Brute Force | 3,510 | Redirect | 100.0% | 100.0% | 100.0% | F6 (URLConcentration) = 0.99 → Yields absolute detection precision. |
| XSS | 4,136 | Redirect | 100.0% | 100.0% | 100.0% | F18 (XSS score) = 2.1 → Yields absolute detection precision. |
| SQLi | 81 | Redirect | 71.6% | 71.6% | 71.6% | F13/F14 signal attenuation → Results in 23 false allows (28.4%). |
n = 9,429 windows extracted from CSE-CIC-IDS2018 Friday (44,220 packets, 33 MB PCAP).
**Overall Accuracy (L2):** 99.4% (9,372/9,429 windows).
**Safety Overrides:** 5 (0.1%) — Near-total absence of intervention requirements.
Note regarding CSE-CIC-IDS2018 Thursday (2018-02-22):
Thursday functions as the "benign baseline day", deployed specifically to evaluate the false positive rate suppression capacity and efficacy against attack-like synthetic data. The dataset encompasses 6,691 windows representing authentic benign baseline traffic, systematically infused with synthetic attack patterns designed to emulate specific temporal scenarios.
Results for Thursday Benchmark (Across 3 Evaluation Modes):
| Mode | Total Windows | Overall Accuracy | Benign FPR | Brute Force | XSS | SQLi | Safety Overrides |
|---|---|---|---|---|---|---|---|
| **Raw PPO (baseline)** | 6,691 | 99.33% | 3% (15/500 false positives) | 99.77% | 99.73% | 69.39% | 0 |
| **Stateless (L2 AI)** | 6,241 | 99.65% | 0% (0/50 FP) | 99.85% | 99.95% | 69.39% | 8 |
| **Window Reset (L3 System)** | 6,241 | 99.58% | 0% (0/50 FP) | 99.85% | 99.77% | 81.63% (mitigate) | 2,059 |
Mode-Specific Analytical Breakdown:
**Raw PPO (Baseline):** Direct unfiltered outputs from the 34D v13 model acting upon the unmodified observation vector.
- Benign: 485/500 correctly classified, 15 erroneously redirected → FPR = 3% (operationally acceptable).
- Brute Force: 3,931/3,940 correctly classified (6 erroneously allowed during the nascent stages of escalation).
- XSS: 2,196/2,202 correctly classified (6 erroneously rate-limited instead of redirected).
- SQLi: 34/49 correctly classified (15 erroneously allowed).
- Safety Overrides: 0 → The policy operates autonomously without systemic intervention.
**Stateless (L2 AI Agent):** Evaluates detection efficacy subsequent to the deliberate excision of the temporal memory (10D parameters removed).
- Benign: 50/50 correctly classified → FPR = 0% (Marked improvement!).
- Brute Force: 99.85% (A marginal 0.08% degradation relative to raw-ppo).
- XSS: 99.95% (A 0.22% improvement relative to raw-ppo).
- SQLi: 69.39% (Identical to raw-ppo → Confirms that temporal state is irrelevant for L2 SQLi detection).
- Safety Overrides: 8 → The safety guard actively intervenes to enforce FPR suppression.
**Window Reset (L3 System Response):** Comprehensive simulation of the holistic defensive architecture incorporating the escalation logic.
- Benign: 50/50 correctly classified (rate-limit mechanism is completely dormant).
- Brute Force: 99.85% (A nominal increase in blocking induced by the escalation mechanics).
- XSS: 99.77% (Blocking successfully executed as mandated by the escalation window).
- SQLi: 81.63% mitigate rate (Substantial escalation from 69.39% → Amplification driven by the substitution of Block for Redirect).
- Safety Overrides: 2,059 → Massive intervention required exclusively to preempt erroneous blocking of benign traffic during the highly sensitive escalation process.
Fundamental Insights Extracted from Thursday Benchmark:
**Temporal state redundancy for L2 detection:** The parity between the stateless configuration and raw-ppo across attack modalities demonstrates that temporal history is largely superfluous for foundational detection.
**FPR Improvement Paradigm:** Raw PPO registers a 3% FP rate on benign traffic; Stateless achieves 0% solely due to the vigilant intervention of the safety guard.
**Escalation Logic dictates SQLi efficacy:** The window-reset mitigate rate leaps from 69% to 82% precisely when the Block action is algorithmically substituted for Redirect.
**SQLi Vulnerability Persistence:** The stagnant 69.39% accuracy spanning multiple modes isolates the vulnerability completely away from the RL Agent, firmly attributing it to the intrinsic limitations of the CRS-942 Paranoia Level 2 ruleset.
Comparative Synthesis: CIC-IDS2017 vs. CSE-CIC-IDS2018:
| Dimension | CIC-IDS2017 | CSE-CIC-IDS2018 | Interpretation |
|---|---|---|---|
| **Complexity Profile** | Singular, isolated attack per dataset. | Concurrent, heterogeneous 3-attack blend. | 2018 imposes significantly greater cognitive load via multi-attack interference. |
| **Brute Force** | (Absent) | 100% accuracy. | The URLConcentration signal proves overwhelmingly definitive. |
| **XSS** | (Absent) | 100% accuracy. | The XSS score signal remains universally consistent. |
| **SQLi** | (Absent) | 71.6% accuracy. | Attenuated SQLi signal confirms that CRS struggles to capture all advanced evasion variants. |
| **Volumetric (DDoS)** | 99.9% accuracy. | (Absent) | 2017 validates extreme volumetric proficiency; 2018 validates L7 proficiency. |
| **Port Scan** | 97.8% accuracy. | (Absent) | 2017 exposes the natural ambiguity inherent in port scanning traffic profiles. |
Generalizability Conclusions:
**Volumetric Attacks (SYN Flood):** The policy exhibits flawless generalization on CIC-IDS2017 (99.9% Accuracy), proving that the network features (F1–F3) are **stable across diverse datasets**.
**Layer 7 Attacks (XSS, Brute Force):** Achieving 100% Accuracy on CSE-CIC-IDS2018 incontrovertibly establishes that the CRS-941 (XSS) ruleset and the behavioral features (F6–F8) possess sufficient robustness for universal generalization.
**SQL Injection as the Primary Vulnerability:** The 71.6% Accuracy on CSE-IDS2018 SQLi is the system's primary limitation. The parity between L1 and L2 accuracy (both 71.6%) confirms that the temporal state adds no detection value for this attack class, isolating the bottleneck to the F13 signal. The 2018 dataset contains sophisticated SQLi variants (double-encoding, UNION-based, time-based) that are not covered by CRS-942 PL2 pattern matching.
**Temporal State Impact:** The Layer 2 (stateless) configuration retains a 99.4% accuracy rate on CSE-IDS2018, strongly suggesting that the temporal state primarily serves the L3 escalation decision matrix, offering negligible utility for base L2 detection.
**Strategic Recommendation:** Enhancing SQLi detection necessitates elevating the CRS-942 Paranoia Level; however, this will inextricably induce a spike in False Positives triggered by benign UNION queries (e.g., ORM frameworks). Negotiating this balance represents the inescapable, intrinsic trade-off characterizing all signature-based architectures.

## 4.3 Results Analysis

### 4.3.1 Analysis by Traffic Group

Based on Table 4.8, the trained policy exhibits three characteristics: near-total mitigation of attack traffic; avoidance of erroneous blocks on benign traffic; and systematic application of proportional interventions (RateLimit) for noisy traffic. This behavioral profile aligns with the design of the reward function and the escalating action ladder.

### 4.3.2 Policy Behavior Analysis

When encountering normal traffic, the agent almost never executes erroneous blocks (benign block rate = 0.0%). The marginal 0.1% intervention rate is predominantly constituted by RateLimit actions.

Confronted with volumetric attacks (SYN Flood, Port Scan), the agent directly applies the Block action (Action 3). For Layer 7 attacks (Brute Force, SQLi, XSS), the agent systematically prioritizes Redirecting (Action 2) the traffic to the Honeypot. The soft escalation mechanism leverages a 15-step sliding window and a `block_ready_latched` flag to subsequently recommend a Block once sufficient empirical evidence has been accumulated, entirely eschewing the use of rigid, static timers.

### 4.3.3 Benchmark PPO vs DQN vs A2C Analysis

This section provides a causal interpretation of the quantitative data presented in Section 4.2.5 (Table 4.4 and 4.5), supported by visual evidence from the figures below.

Figure 4.2: Radar chart comparing PPO/DQN/A2C across all evaluation dimensions

Figure 4.3: Exact response rate heatmap by attack typology and algorithm

Figure 4.4: Bar chart — Benign intervention rate per algorithm across all 4 evaluation modes

The benchmark results clearly delineate two divergent optimization axes: raw defensive performance versus the benign-safety/availability trade-off. DQN commands the raw defensive metrics, including mean reward, mitigation rate, exact response, and service damage. PPO trails marginally across these raw metrics but demonstrates a decisively superior profile regarding benign interventions, maintaining a robust mitigation rate while simultaneously minimizing deleterious impacts on legitimate traffic.

**Raw defensive performance:** Within the round-robin paradigm, DQN achieves a higher mean reward than PPO (60.71 vs. 58.80), a superior mitigation rate (99.54% vs. 97.65%), and lower service damage (0.0583 vs. 0.0644). This trajectory corroborates the assessment that DQN is more "aggressive": it exhibits slightly enhanced attack interception but at the explicit cost of escalated benign interventions. The exact response rate further supports this, with DQN achieving 92.26% compared to PPO's 90.81%. A2C occupies the statistical nadir across all three metrics, unequivocally demonstrating its unsuitability for this specific domain under strict default constraints.

*   **Algorithmic Explanation (DQN):** DQN's off-policy Experience Replay mechanism repeatedly reinforces high-reward action-state pairs, systematically biasing the policy toward decisive mitigation actions (Block, RateLimit). This aggression is a structural consequence: DQN cannot distinguish "suspicious" from "malicious" traffic with the same precision as PPO's policy gradient mechanism, leading to the observed 2.1× higher benign intervention rate.

**Benign-safety and availability:** PPO significantly suppresses the `benign intervention rate` with statistical significance across all four evaluation modes (round_robin p=0.0278; round_robin_stress p=0.0021; session_20 p=0.0228; session_20_stress p=0.0486). In the round_robin mode, PPO intervenes against a mere 0.65% of benign traffic, whereas DQN intervenes against 1.39% (a ~2.1× reduction). The `benign harm score` associated with PPO is systematically lower than DQN across all modes, though it achieves statistical significance exclusively under stress configurations (round_robin_stress p=0.0256; session_20_stress p=0.0486). This facilitates a precise conclusion: PPO possesses a distinct structural advantage in availability-preserving defense, whereas DQN excels in raw baseline defensive efficacy.

*   **Algorithmic Explanation (PPO):** PPO's Clipped Surrogate Objective (ε = 0.15) enforces a trust-region constraint that prevents overly large policy updates. Combined with entropy regularization (ent_coef = 0.05), this maintains sufficient policy diversity to avoid collapsing into a reflexive "Block everything" strategy. The heatmap (Figure 4.3) corroborates this: PPO's exact response rate is more consistent across attack classes, indicating a more calibrated decision boundary.

**Performance of A2C:** A2C fails to stabilize its policy in a high-dimensional (34D) environment with a sparse, episodic reward signal, resulting in a benign intervention rate (22.27%) that is approximately 16× higher than PPO's.

*   **Algorithmic Explanation (A2C):** A2C's synchronous on-policy updates compute gradients from a single rollout without a replay buffer, producing high-variance gradient estimates. Under default hyperparameters, A2C fails to reliably discriminate benign from attack traffic within the allotted training budget, making it operationally hazardous in this environment.

**Impact of session state and noise/drift:** The dual evaluation axes are decoupled; thus, stress comparisons must utilize corresponding session pairs. As noise and drift escalate, PPO's benign-safety superiority becomes increasingly pronounced (with the benign harm score achieving statistical significance), while DQN persistently retains its advantage in raw mitigation and service damage. Consequently, stress testing elucidates the trade-off dynamic without inverting the overarching performance conclusions.

*   **Robustness Analysis:** This suggests that PPO's policy is structurally more resilient to observational uncertainty — a critical property for real-world deployment where sensor readings are inherently imperfect.

**Trade-off magnitude (non-statistical evidence):** The `mitigation/benign_intervention` ratios illustrate that PPO achieves mitigation levels approximating those of DQN while "expending" vastly fewer benign interventions. PPO achieves a ratio of 123.3 vs. DQN's 71.5 (~1.7× difference). Given the extreme sensitivity of ratio metrics when the denominator approaches zero, những chỉ số này đóng vai trò như các chỉ báo định tính quan trọng hỗ trợ cho quyết định triển khai thực tế.

### 4.3.4 Conclusion

The benchmark analysis demonstrates that no single algorithm dominates across both optimization axes simultaneously. The deployment context must drive the algorithm selection:

- **DQN** is optimal for threat-centric deployments where maximizing raw mitigation and minimizing service damage are the primary objectives, and a higher benign intervention rate is an acceptable operational trade-off.
- **PPO** is the preferred architecture for availability-sensitive environments — such as public-facing services or SLA-bound infrastructure — where false positive interventions must be minimized, even at a marginal cost in raw mitigation.
- **A2C**, under default hyperparameters, is operationally hazardous in this environment due to its high benign intervention rate and is not recommended.

This analysis directly motivates the selection of PPO as the foundation for the v13 model, which is subsequently optimized via hyperparameter tuning in Section 4.2.6.

---

## 4.4 Results Interpretation

### 4.4.1 Overall Evaluation

The research achieves its foundational objectives: the engineering of an autonomous, RL-driven network defense architecture capable of detecting and mitigating five primary attack classes; and the empirical validation of its operational viability within a closed-loop simulated environment. Experimental results confirm that the agent realizes a high detection rate across active-threat steps, sustains a negligible false positive rate across normal-traffic steps, and achieves an effective equilibrium with service availability. These findings substantiate the viability of Reinforcement Learning within the domain of automated network defense.

The v13 PPO Model (post-tuning) underwent evaluation against a suite of performance indicators, structured to concurrently assess two dimensions: raw defensive quality (baseline mitigation capacity), representing the ability to detect and neutralize threats; and the security-availability trade-off, representing the equilibrium between defensive aggression and the preservation of legitimate service operations.

The paramount academic contribution resides in the architecture of the Observation Module—the vital technical conduit bridging raw network flows and the MDP state space. The performance enhancement observed from v12 to v13 is predominantly attributable to the expansion of the state space from 20 dimensions to 34 dimensions, specifically incorporating: 20 predefined traffic features (F1–F20), 10 temporal state dimensions encapsulating the per-IP memory over the preceding 10 steps, and 4 closed-loop effect dimensions quantifying the empirical consequences of the antecedent action. This expanded dimensionality empowers the agent to internalize the intra-session continuity characterizing IP behavior and the causal relationship linking defensive actions to subsequent environmental state permutations. While the OWASP CRS features (F13, F18) remain indispensable for classifying application-layer (L7) threats, the empirical data confirms that the temporal state component is the primary driver of escalation quality and session-level decision-making — not of base detection accuracy. The 3-layer diagnostic decomposition (Section 4.2.9) shows that L2 (stateless, no temporal state) retains 99.4% accuracy on CSE-CIC-IDS2018, confirming that the 10D temporal state adds marginal value to per-window detection but is essential for the soft escalation logic that drives the Redirect→Block transition.

### 4.4.2 Real-World Scenario Validation

Four representative real-world scenarios were instantiated within the Containernet environment and verified by interrogating the action decisions issued by the RL agent, validating the precise netfilter rules deployed to the active kernel, and confirming the resulting outcomes via empirical iptables logs. These scenarios were specifically selected to span the diverse attack typologies defined within the 5-class taxonomy.

**Legitimate HTTPS Stream (benign baseline):** The observation vector registers F1 < 60 pps (standard packet rate), F12 = 0 (absence of HTTP/HTTPS request payloads), and F7 = 0.1 (low request concentration). The agent deterministically issues **Action 0 (ALLOW)**. Verification: The iptables FORWARD chain remains completely devoid of DROP or REJECT rules. Outcome: Traffic flows unimpeded.

**SYN Flood (volumetric attack):** The `hping3` utility is deployed to orchestrate a volumetric SYN flood targeting port 443 at an intensity of ~1000 pps. The observation vector detects an explosive spike in F1 to 350 pps, accompanied by a payload volume of ≈ 0 (absence of HTTP data). The agent issues **Action 3 (BLOCK)** during the 2nd window (0–1 seconds post-initiation). Verification: A `-j DROP` rule is aggressively injected into the FORWARD chain, specifically targeting the source IP and destination port. Outcome: The entirety of the malicious SYN packet flood is neutralized at the kernel level.

**Evasive SQL Injection:** The `sqlmap` framework is leveraged to inject a `UNION SELECT` payload, obfuscated via double-URL-encoding within a GET parameter. Post-normalization, the underlying UNION SELECT signature is exposed: F14 = 1 (UNION keyword present), and F13 escalates (CRS SQLi rule set 942 triggered). The agent initially issues **Action 2 (REDIRECT)**, routing the traffic to the honeypot on port 4443. The adversary inadvertently continues enumerating the database within the isolated honeypot instance, leaving the production server (192.168.10.10) entirely unaffected. Once the 15-step soft escalation accumulator amasses sufficient forensic evidence, the per-IP state tracker escalates the intervention from Redirect to **Action 3 (BLOCK)**, forcibly terminating the session.

**Cross-Site Scripting via Bot Injection (XSS):** An event handler payload (`onerror=fetch(...)`) is injected to covertly download malware from an infrastructure controlled by the attacker. Detection is achieved via: F18 escalation (CRS XSS rule set 941 triggered) and F20 = 1 (bot-like behavioral signature identified). The agent issues **Action 2 (REDIRECT)** to the honeypot. Following the accumulation of 15 sequential steps of forensic evidence within the soft escalation buffer, the agent **escalates to Action 3 (BLOCK)**.

### 4.4.3 Three Core Design Decisions

Empirical validation unequivocally confirms that three fundamental design decisions serve as the primary determinants of systemic performance:

**Criterion 1 — Integration of Application-Layer Features (F12–F20):** SQL injection and XSS vectors—which lack discriminatory signatures at the network layer—necessitate deep HTTP payload inspection. The architectural methodology involves directly embedding the OWASP CRS rule set 942 (SQLi detection) and 941 (XSS detection) into the feature vector (as F13 and F18, respectively). This approach effectively operationalizes the cumulative security expertise validated by the cybersecurity community over extensive operational lifecycles. While the CRS provides the indispensable baseline detection mechanism, the 3-layer diagnostic decomposition reveals that the performance leap from v12 to v13 is primarily attributable to the temporal memory component (10D) and the closed-loop effect component (4D) — specifically their role in driving escalation decisions (Redirect→Block), not base detection accuracy. The L2 (stateless) configuration retains 99.4% accuracy on CSE-CIC-IDS2018, demonstrating that the temporal state is largely redundant for per-window classification but essential for the 15-step soft escalation mechanism. The primary advantage of CRS integration is the drastic reduction in labeled training data required for L7 attack classification.

**Criterion 2 — Payload Normalization Pipeline:** Evasion techniques, such as double-URL-encoding (`%2527` → `%27` → `'`) or HTML entity obfuscation (`&lt;script&gt;` → `<script>`), represent the most pervasive vectors for WAF bypasses. The 8-step normalization pipeline was engineered with rigid sequential dependencies: HTML entity decoding precedes URL decoding (given that `&#x25;` encodes the `%` character), and URL decoding precedes Base64 decoding (as Base64 padding utilizes the `=` character). Crucially, the recursive URL decoding is capped at a depth of 2 (recursive depth ≤ 2), effectively neutralizing double-encoding tactics without precipitating infinite loops or resource exhaustion vulnerabilities. In the absence of this normalization layer, obfuscated payloads entirely circumvent CRS pattern matching, resulting in catastrophic attack obfuscation.

**Criterion 3 — The 1-Second Temporal Window Unit:** The selection of the sliding window size directly governs the system's capacity to resolve the distinct chronological phases of an attack session. An excessively protracted window (e.g., 5 seconds) inevitably conflates signals spanning disparate attack phases, severely hindering the agent's ability to map state transitions accurately. Conversely, an excessively truncated window (< 1 second) introduces unacceptable levels of statistical noise, as the L7 features (F12–F20) are critically dependent on the aggregate volume of HTTP requests processed within the interval. The 1-second threshold represents the empirically validated equilibrium point between high-fidelity temporal resolution and required statistical stability, perfectly aligning with the requirements for real-time defensive operations.

---

## 4.5 Comparison with Literature

Direct numerical comparisons across disparate studies are problematic due to fundamental variances in dataset composition, labeling taxonomies, and evaluative methodologies. Consequently, this analysis is focused on methodological paradigms.

**Comparison with Traditional Feature Extraction:** Sharafaldin et al. [17] engineered CICFlowMeter with over 80 bidirectional statistical flow features, achieving >97% accuracy on CICIDS2017 via Random Forest. The present system demonstrates that a curated 20-feature set—synthesizing network-level statistics with application-layer payload semantics (F12–F20)—delivers competitive accuracy on the same dataset (99.9% DDoS, 97.8% Port Scan) while maintaining the sub-second inference latency required for a real-time 1-second feedback loop. The key distinction is semantic depth: CICFlowMeter operates exclusively on flow metadata, whereas F12–F20 directly encode HTTP payload intent via CRS scoring.

**Binary Classification vs. Multi-Class Action Selection:** Moustafa & Slay [32] deployed a Random Forest classifier achieving 85.6% accuracy and a 0.89% FPR on the UNSW-NB15 dataset within a binary classification paradigm. These metrics are not directly comparable, as UNSW-NB15 exhibits a divergent label distribution and is restricted to binary classification. In contrast, the present research addresses a fundamentally more complex challenge: the simultaneous multi-class categorization of 5 distinct attack vectors coupled with the autonomous selection of appropriate mitigation actions.

**Supervised Static Detection vs. Closed-Loop RL**: As surveyed by Ring et al. [33], the dominant NIDS paradigm trains classifiers on static, labeled datasets without a feedback mechanism between defensive actions and subsequent network state. The present system departs from this paradigm by embedding the agent within a closed-loop environment where actions mutate observable state—a design validated by explained_variance = 0.926, confirming the critic learns action-consequence causality rather than snapshot classification.

**CRS Integration:** The direct integration of OWASP CRS scoring into the feature vector (F13, F18) constitutes a novel architectural design not observed in the surveyed literature. Rather than attempting to synthesize a novel detection ruleset from first principles, the system pragmatically inherits the validated expertise of the security community. This significantly mitigates the dependency on massive volumes of labeled training data for complex L7 attacks [28].

The algorithmic benchmark analysis (comparing default PPO, A2C, and DQN) is detailed in Sections 4.2.8 and 4.3.4. The conclusions emphasize the operational trade-offs (baseline defensive performance vs. benign-safety) rather than attempting to declare an absolute algorithmic victor.

---

## 4.6 Implications of Results

### 4.6.1 When to Prioritize RL over Static Rules?

RL offers clear value in environments with diverse and constantly changing attacks—especially networks handling both volumetric (SYN Flood) and payload (SQLi, XSS) attacks simultaneously. In environments with monotonous traffic and stable attack patterns, Static Rules remain more effective due to the lack of a training phase.

### 4.6.2 Minimum Infrastructure Requirements

The architecture necessitates a centralized capture node (e.g., an edge router) equipped with Python 3 capabilities and Scapy. The primary resource bottlenecks are flow management (requiring sufficient RAM to track up to 50,000 concurrent flows) and raw packet capture (CPU bounded).

### 4.6.3 Honeypot as a Strategic Advantage

The action of redirecting to a Honeypot—instead of blocking immediately—offers value beyond pure defense: the attacker continues to operate in a controlled environment, allowing the SOC to gather threat intelligence (TTPs, payloads, tools) without compromising the real system. This is an advantage that Static Laws and RF classifiers cannot provide.

### 4.6.4 Policy Reusability

Trained policies can be redeployed to new environments without retraining, provided the 34-dimensional observation vector structure remains the same: 20 traffic characteristic dimensions with the same F1–F20 definitions and normalization formulas, plus 10 time-state dimensions and 4 state effect dimensions built from the same per-IP logic. This allows organizations to quickly deploy policies that have been thoroughly tested in a lab environment before going into production.

### 4.6.5 Future Directions

**Expansion of the Action Space:** Add more detailed actions such as limiting the rate by source IP, redirecting by request type, or creating dynamic honeypots. This requires research into action masking techniques to guide discovery in a larger space.

**Multi-Agent and Distributed Defense architectures:** Expanding from single-agent to multi-agent RL where each network node has its own agent and coordinates via experience-sharing protocols — a natural step toward scaling from a 10-VM topology to a production network based on SDN architecture.
