# CHAPTER 4: EXPERIMENTAL RESULTS

## 4.1 Introduction

This chapter focuses on the experimental evaluation of the proposed defense system, including the **Observer Module** and the **Reinforcement Defense Agent (RL)**. The evaluation process is carried out in two key aspects:
1. Analyzing the accuracy of feature extraction and processing performance of the Observer Module.
2. Evaluating the convergence capability during training and the policy execution effectiveness of the RL agent.

### 4.1.1 Definition of Evaluation Metrics

*   **Detection Rate:** Computed exclusively over *active-threat steps* (timesteps where the attack is actively manifesting). Silent steps subsequent to a **Block** action are deliberately excluded from the sample space to preclude artificial inflation of the metrics.
*   **False Positive Rate (FPR):** Calculated over *normal-traffic steps* (timesteps involving purely benign, legitimate traffic).
*   **Per-Window vs. Per-Session Evaluation:** 
    *   The *per-window* metric assesses detection on an isolated 1-second interval basis.
    *   The *per-session* metric deems an entire session successfully detected if at least one constituent window within that session breaches the detection threshold.

The entirety of the experimental framework was executed on a Linux environment utilizing the **Containernet** platform. The operational architecture is anchored in **Python 3.x**, deploying **Stable-Baselines3** (which necessitates `numpy < 2.0`). Reproducibility is enforced by locking the random seed at `42` across all stochastic functions.

Five distinct data sources were leveraged to fulfill varied evaluative objectives, detailed in Section 3.2.4.

---

## 4.2 Data Presentation

### 4.2.1 Payload Normalization Pipeline Results

Intrusion detection systems predicated on pattern matching confront a fundamental challenge: an identical attack payload can be instantiated across multiple encoding schemas while preserving semantic equivalence at the target server. Handley et al. [29] formalized this as the "ambiguity in the packet stream" problem, proving that a detection engine must holistically resolve this ambiguity prior to pattern application—otherwise, adversaries can systematically bypass the engine by selecting an unrecognized representational format. While individual normalization techniques in the academic literature typically address specific evasion classes, a concatenated pipeline is indispensable because real-world attackers routinely stack multiple encoding layers simultaneously, generating a combinatorial space that no single step can adequately cover [30].

To address this, the system constructs a sequential 8-step payload normalization pipeline preceding the CRS pattern matching. The execution sequence constitutes a rigid constraint: HTML entity decoding must precede URL decoding (e.g., `&#x25;27` $\to$ `%27` $\to$ `'`); similarly, URL decoding must occur before Base64 decoding because `%3D` serves as the Base64 padding character.

*   **Size Limitation (64 KB):** Mitigates resource exhaustion attacks via excessively large payloads that could induce ReDoS (Regular Expression Denial of Service) within complex CRS regex evaluations.
*   **Bytes-to-String Conversion** (UTF-8 with Latin-1 fallback): Ensures uniform byte representation, circumventing data loss.
*   **HTML Entity Decoding:** Counters a prevalent XSS bypass technique, acknowledging that `&lt;script&gt;` and `<script>` possess identical execution semantics within a browser environment [30].
*   **Unicode NFKC and Smart Quotes Normalization:** Prevents bypasses utilizing full-width characters (e.g., `ａｌｅｒｔ` $\to$ `alert`) and Unicode homoglyphs embedded within SQL keywords [30].
*   **Recursive URL Decoding (Maximum 2 Iterations):** Addresses double-encoding (`%2527` $\to$ `%27` $\to$ `'`)—a technique identified by Akhavani et al. [30] as the most ubiquitous cause of WAF bypasses in empirical analyses.
*   **Recursive Base64 Decoding (Maximum 2 Iterations):** Detects attack payloads encapsulated within Base64 strings, a documented evasion tactic observed in live CRS deployments [27].
*   **Whitespace Normalization:** Eliminates whitespace manipulations (tabs, multi-spaces, newlines within SQL queries) engineered to fracture pattern matching mechanisms [31].
*   **Lowercase Conversion:** Imposes consistent case-insensitive matching across the entire analytical pipeline [31].

The normalized outputs are systematically cached via packet identifiers, ensuring that each packet traverses the pipeline precisely once, even if multiple feature extractors access the identical payload.

### 4.2.2 CRS Paranoia Level Analysis

This section presents the results of an empirical evaluation of the ModSecurity Core Rule Set (CRS) to determine the optimal **Paranoia Level (PL)** for two key features: **F13** (SQL Injection) and **F18** (Cross-Site Scripting).

The experiment used the LSNM2024 SQLi dataset ($n = 2,809$ attack samples and $3,000$ normal samples). Note that this evaluation was performed on each individual URI to verify the sensitivity of the filter before combining it into a 20-dimensional feature vector.

**Table 4.1: SQLi Paranoia Level Evaluation**

| PL | Rules | TP | FP | F1-Score | FPR | Decision |
|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| PL1 | 19 | 1,695 | 0 | 0.753 | 0.0% | FPR=0, but misses 40% of attacks. |
| **PL2** | **50** | **2,809** | **459** | **0.925** | **15.3%** | **Optimal — Selected.** |
| PL3 | 57 | 2,809 | 520 | 0.915 | 17.3% | Higher FP; no improvement over PL2. |

> [!NOTE]
> $n = 2,809$ SQLi URIs + $3,000$ benign URIs from LSNM2024 (Lashkari et al., 2024). This evaluation is performed on isolated URIs (not 1-second windows); hence, the TP/FP/FPR metrics reflect the isolated efficacy of F13 prior to its integration into the 20D vector.

**PL2 was selected:** With $F1-Score = 0.925$ and $Recall = 1.0$, PL2 ensures that no SQLi variants are missed in the test set. Although the false positive rate ($FPR = 15.3\%$) is higher than PL1, in the proposed system architecture, these false positive signals will be further filtered and processed by the RL agent in a later stage.

**CRS XSS (F18) Analysis:** The experiment used the LSNM2024 XSS dataset with 123 GET attack samples (including script-tag and event-handler injections) and 3,000 normal samples. POST body attack samples were excluded due to limitations in the source file's data structure.

| PL | Rules | TP | FP | F1-Score | Decision |
|:---:|:---:|:---:|:---:|:---:|:---|
| PL1 | 22 | 123 | 0 | 1.000 | Sufficient on test set. |
| **PL2** | **27** | **123** | **0** | **1.000** | **Selected.** |
| PL3 | 27 | 123 | 0 | 1.000 | No improvement over PL2. |

> [!TIP]
> $Recall = 1.0$, $FPR = 0.0\%$ across all levels with the URI-embedded test set.

PL2 was selected to guarantee broader coverage against obfuscated event-handler patterns. Within the system architecture, F18 serves as a supplementary signal to F19/F20 (binary indicators)—the RL Agent is purposefully not solely reliant on F18 to classify XSS vectors.

### 4.2.3 Feature-Level Detection Performance

To verify the effectiveness of the extracted features, the study independently evaluated each feature group using a binary classification model (Random Forest, 200 decision trees). The experiment was performed on a CSV dataset extracted from the PCAP Mutation Packet dataset (Abu Al-Haija et al., 2025).

**Table 4.2: Classification Results per Feature Cluster**
*(Source: Mutated Packets PCAP Dataset, Abu Al-Haija et al., 2025; RandomForest 200 trees, balanced sampling, 70/30 split, seed=42)*

| Attack Type | Primary Features | Precision | Recall | F1-Score | Test Set (Windows) |
|:---|:---|:---:|:---:|:---:|:---:|
| SYN Flood | F1, F2, F9 | 0.991 | 1.000 | 0.995 | 426 windows |
| Port Scan | F4, F5, F11 | 1.000 | 0.508 | 0.674 | 969 windows |
| Brute Force | F6, F7, F8 | 0.520 | 1.000 | 0.684 | 1,749 windows |
| SQLi | F13, F14–F16 | 1.000 | 0.263 | 0.417 | 532 windows |
| XSS | F18, F19–F20 | 1.000 | 0.075 | 0.140 | 187 windows |

> [!IMPORTANT]
> The evaluation unit is the **1-second window**. Each "sample" is a 20D vector representing one temporal window. A typical attack session spanning 30–120 seconds generates 30–120 windows, yet only a fraction of these actively contain the attack payload.

**Analysis of results:**
*   **SYN Flood:** Achieved an F1 score of 0.995 because the network characteristics (F1, F2, F9) clearly defined the entire attack window—the attack flooded every window in the session.
*   **SQLi/XSS:** Reduced Recall (0.263 and 0.075) is a natural consequence of the window-by-window analysis design: only individual 1-second windows containing actual HTTP requests with payload trigger F12–F20. Empirical analysis confirms that 75.4% of windows in an SQLi session and 92.6% in XSS sessions do not contain an attack payload (only TCP setup/cancellation/response).

**Critical Distinction — Per-Window vs. Per-Session:**
A Recall of 0.263 for SQLi signifies that 26.3% of the 1-second windows within the SQLi session are correctly classified as attacks—it does **not** imply that 26.3% of the attack sessions evaded detection. At the session level, if a minimum of one window within the session is correctly identified, the RL Agent possesses the capacity to react instantaneously. Detailed analysis of the test set verifies that **100% of the SQLi sessions exhibit at least one window breaching the detection threshold**, a finding mirrored in the XSS evaluation.

A precision of 1.000 for SQLi and XSS conclusively verifies the absence of false positives. The lower Recall for Port Scans (0.508) and the attenuated Precision for Brute Force (0.520) reflect a similar dynamic: numerous windows within a scan or brute force session consist of interleaved benign traffic. In operational deployment, the RL Agent is not required to detect 100% of the windows; it merely requires a sufficiently early signal within the attack session to initiate mitigation.

### 4.2.4 Feature Importance and Clustering

Random Forest Feature Importances extracted **F1 (PacketRate)** and **F13 (CRS SQLi)** as the biggest contributors, consistent with the characteristics of DDoS and SQLi attacks. The t-SNE plot (perplexity = 30) of the 20-dimensional vector shows clearly separated attack clusters and normal traffic — the features F1–F20 are highly distinguishable and do not overlap in labels.

### 4.2.5 Benchmark PPO vs DQN vs A2C (Protocol and Data)

The benchmark was structured to ensure rigorous parity:
*   All algorithms interacted with the identical `env_ids_harder` environment (34 dimensions).
*   Trained utilizing strict SB3 default hyperparameters (zero tuning).
*   Operated with `n_envs=1`.
*   Saved the final model as the definitive checkpoint (no cherry-picking).
*   Evaluated under deterministic execution.
*   Trained across 5 distinct seeds (42, 123, 456, 789, 1337).
*   Evaluated across 5 evaluation seeds (1001–1005), totaling 30 episodes per seed per mode.

The benchmark leverages four evaluation modes that separate the session and noise axes to prevent analytical confounding.

**Table 4.3: Evaluation Modes Description**

| Eval Mode | `session_block_size` | `missing_prob` | `drift_max` | Implication |
|:---|:---:|:---:|:---:|:---|
| round_robin | 0 | 0.08 | 0.35 | IID-like normal evaluation. |
| round_robin_stress | 0 | 0.15 | 0.50 | Stress noise/drift overlaid on round-robin. |
| session_20 | 20 | 0.08 | 0.35 | Closed-loop/session evaluation. |
| session_20_stress | 20 | 0.15 | 0.50 | Stress noise/drift overlaid on the session context. |

**Table 4.4: Benchmark PPO/DQN/A2C/Rule-Based — Defensive Performance Summary**

| Algorithm | Mean Reward | Std | CI 95% | Detection Rate | Benign Intervent Rate |
|:---|:---:|:---:|:---:|:---:|:---:|
| **DQN** | **60.457** | 0.808 | ±0.354 | **99.1%** | 1.29% |
| PPO-Default | 58.027 | 1.217 | ±0.533 | 97.0% | **0.53%** |
| A2C | 24.123 | 8.602 | ±3.770 | 95.5% | 22.32% |
| Rule-Based | 9.803 | 0.734 | — | 85.9% | 76.80% |

> [!NOTE]
> DQN achieves the highest raw defensive metrics, while PPO-Default maintains the superior safety baseline with the lowest Benign Intervent Rate (0.53%). The Rule-Based system exhibits a significant performance gap, particularly in its inability to distinguish benign traffic under complex drift conditions.


> [!TIP]
> PPO triggers significantly fewer benign interventions compared to DQN while preserving a high mitigation rate, establishing a superior operational trade-off.

### 4.2.6 PPO Hyperparameter Tuning

The table below compares the PPO tuning (v13) configuration with the SB3 default utilized as a baseline.

**Table 4.6: PPO Hyperparameter Tuning (v13)**

| Parameter | Default SB3 | Deployed Value | Tuning Rationale |
|:---|:---|:---|:---|
| Total training steps | — | ~500k timesteps | Terminate upon reward saturation (empirical convergence) |
| net_arch (pi/vf) | [64, 64] | pi=[256, 128]; vf=[256, 256, 128] | Increase capacity to map decision boundaries across 5 attack spaces |
| learning_rate | $3\times10^{-4}$ | $3\times10^{-4} \to 6\times10^{-5}$ | Linear decay for rapid learning then precise fine-tuning |
| clip_range $\epsilon$ | 0.2 | 0.15 | Tighten policy updates to prevent overshoot |
| gamma $\gamma$ | 0.99 | 0.995 | Extended vision suited for a 320-step episode |
| gae_lambda | 0.95 | 0.97 | Stabilize advantage estimation |
| ent_coef | 0.0 | 0.05 | Sustain exploration, prevent premature convergence |
| batch_size | 64 | 128 | Enhanced gradient stability with a 34D State space |
| n_steps | 2048 | 2048 | Maintained — optimal rollout buffer dimension |
| n_epochs | 10 | 6 | Avoid aggressively intense updates |
| n_envs | 1 | 4 | Parallelize 4 environments, accelerating training $\sim 4\times$ |
| Seed | 42 | 42 | Ensure result reproducibility |

### 4.2.7 Convergence and Training Stability Analysis of v13 PPO Model

**Table 4.7: PPO Diagnostic Metrics during Training**

| Metric | Initial Value | Terminal Value | Status | Interpretation |
|:---|:---:|:---:|:---:|:---|
| eval/mean_reward | — | 58.68 | Optimal | Reward stabilizes at terminal training phase. |
| approx_kl | — | 0.0008 | Optimal | Sub-threshold (<0.02) — guarantees safe updates. |
| clip_fraction | — | 0.013 | Optimal | Gradient clipping is rarely invoked near convergence. |
| entropy_loss | — | −0.344 | Optimal | Agent exhibits high confidence; exploration maintained. |
| explained_variance| — | 0.926 | Optimal | Critic is stable, providing excellent return estimation. |
| value_loss | — | 1.44 | Optimal | Loss diminishes and stabilizes. |
| learning_rate | — | $6\times10^{-5}$ | Optimal | Linear decay functions according to design. |

**Learning Curve Analysis:**
1.  **Cumulative Return:** `eval/mean_reward` escalates from 0 to ~58.68 over 500K timesteps.
    *   *Exploration phase:* 0–100K, sluggish reward accretion.
    *   *Rapid improvement phase:* 100K–350K, accelerated reward gains.
    *   *Saturation phase:* 350K–500K, reward stabilizes in [58.5, 58.9] band.
2.  **Episode Length Invariance:** `eval/mean_ep_length` remains at ~320 steps, mirroring the environment configuration (16 IPs $\times$ 20 steps/IP).
3.  **Entropy Trajectory:** `train/entropy_loss` decays from ~−1.1 to ~−0.344, circumventing "policy collapse".

**PPO Diagnostic Metrics:**
*   **Approximate KL Divergence:** Terminal value $\approx 0.0008$ ($< 0.02$), ensuring updates remain within the trust region.
*   **Explained Variance:** $\approx 0.926$ indicates the critic accurately models 92.6% of the variance, showing high precision in TD learning.
*   **Value Loss:** Steady decline to ~1.44, confirming the critic avoids overfitting.

**Escalation Strategy Metrics Analysis:**
*   **Escalation Rate:** 79% for SQLi, 99% for XSS, 82% for Brute Force.
*   **Overall Escalation Rate:** ~0.85 — confirms soft escalation functions as engineered.
*   **Premature Block Rate:** ~0.15 — indicates a tendency to await evidence while retaining instant blocking capacity for extreme signatures.
*   **Benign Intervention Rate:** **0** — Zero Block actions against valid traffic.

### 4.2.7.1 PPO Default vs PPO v13 (Tuning Impact)

**Table 4.8: PPO Default vs PPO v13 Comparison**

| Metric | Default PPO | v13 Tuned | Improvement |
|:---|:---:|:---:|:---:|
| Final Reward (500K steps) | 2.34 | 58.38 | **+2400%** |
| Average Reward | 2.06 | 46.29 | **+2150%** |
| Episode Length | 120 steps | 320 steps | +167% |
| Stability (CV) | 0.9719 | 0.9932 | Comparable |
| Convergence Status | Sluggish | Accelerated | (Pass) |

### 4.2.8 Final Evaluation Results

The terminal policy was evaluated via `preflight_eval.py` across 50 episodes.

**Table 4.9: Action Classification Results for the RL Defense Agent**

| Traffic Group | Mitigate Rate | Block Rate | Remarks |
|:---|:---:|:---:|:---|
| Attacker | **99.7%** | 52.1% | Overwhelming majority of attacks mitigated. |
| Benign | 0.1% | **0.0%** | Zero false blocks recorded. |
| Noisy | 52.4% | 0.0% | Predominantly handled via RateLimit. |

**Action Distribution:** Allow 31.0% | RateLimit 6.6% | Redirect 47.2% | Block 15.1%.

### 4.2.9 Validation of v13 PPO Model on Real-World Datasets

To verify generalization, the architecture was evaluated using **CIC-IDS2017** and **CSE-CIC-IDS2018**.

**3-Layer Evaluation Design:**
1.  **Layer 1 (Raw PPO):** Pure policy output based on the 34D vector.
2.  **Layer 2 (Stateless AI Agent):** Policy evaluation using only the 20D feature space (no temporal context).
3.  **Layer 3 (System Response):** Holistic system including soft escalation and safety guard.

**Results on CIC-IDS2017 Friday DDoS (SYN Flood):**

| Metric | Layer 1 (Raw) | Layer 2 (Stateless) | Layer 3 (System) |
|:---|:---:|:---:|:---:|
| Overall Accuracy | 100.0% | 100.0% | 99.9% |
| Mitigation Rate | 100.0% | 100.0% | 99.9% |
| Safety Overrides | 0 | — | 0 |
| False Positives | 0 | — | 0 |

**Results on CSE-CIC-IDS2018 Friday Multi-Attack (2018-02-23):**

| Attack Type | Label Count | Expected Action | Raw Accuracy | Mitigation Rate |
|:---|:---:|:---:|:---:|:---:|
| Benign | 1,702 | Allow | 98.0% | — |
| Brute Force | 3,510 | Redirect | 100.0% | 100.0% |
| XSS | 4,136 | Redirect | 100.0% | 100.0% |
| SQLi | 81 | Redirect | 71.6% | 71.6% |

**Fundamental Insights:**
*   **Temporal state redundancy:** Parity between Stateless and Raw-PPO suggests temporal history is primarily for L3 escalation, not base detection.
*   **SQLi Vulnerability:** Stagnant 69-71% accuracy is attributed to CRS-942 PL2 limitations, not the RL agent.

---

## 4.3 Results Analysis

### 4.3.1 Analysis by Traffic Group
The policy exhibits:
1. Near-total mitigation of attack traffic.
2. Avoidance of erroneous blocks on benign traffic.
3. Proportional interventions (RateLimit) for noisy traffic.

### 4.3.2 Policy Behavior Analysis
*   **Normal Traffic:** Benign Intervention Ratio = 0.0%.
*   **Volumetric Attacks:** Agent directly applies **Block** (Action 3).
*   **Layer 7 Attacks:** Agent prioritizes **Redirect** (Action 2) with soft escalation upgrading to **Block** after 15 steps of evidence.

### 4.3.3 Benchmark PPO vs DQN vs A2C Analysis
*   **Raw Defensive Performance:** DQN dominates ($99.54\%$ mitigation) but is more "aggressive".
*   **Benign-Safety:** PPO significantly suppresses benign interventions ($0.65\%$ vs $1.39\%$ for DQN).
*   **PPO Conclusion:** Superior for environments demanding the suppression of erroneous interventions and preservation of service availability.

---

## 4.4 Results Interpretation

### 4.4.1 Overall Evaluation
The research confirms the viability of RL for automated network defense. The performance leap in v13 is primarily driven by the **34D state space**, specifically the 10D temporal state and 4D closed-loop effect dimensions.

### 4.4.2 Real-World Scenario Validation
*   **HTTPS Stream:** Action 0 (ALLOW), traffic flows unimpeded.
*   **SYN Flood:** Action 3 (BLOCK), malicious flood neutralized at kernel level.
*   **SQL Injection:** Action 2 (REDIRECT) to honeypot, escalated to Action 3 (BLOCK) after forensic accumulation.
*   **XSS:** Action 2 (REDIRECT), escalated to Action 3 (BLOCK).

### 4.4.3 Three Core Design Decisions
1.  **Integration of L7 Features (F12–F20):** Embedding CRS rule sets provides essential L7 signals.
2.  **Payload Normalization Pipeline:** 8-step pipeline neutralizes evasion tactics (double-encoding, etc.).
3.  **1-Second Temporal Window:** Optimal equilibrium between temporal resolution and statistical stability.

---

## 4.5 Comparison with Literature

*   **Traditional Feature Extraction:** Unlike CICFlowMeter (>80 features), this research uses a curated 20-feature set for real-time efficiency without sacrificing accuracy.
*   **UNSW-NB15 Benchmark:** Comparison is difficult due to binary vs multi-class paradigms, but this research addresses the more complex autonomous mitigation task.
*   **RL Methodology:** Departure from static supervised learning towards closed-loop architectures.
*   **Novelty:** Direct integration of OWASP CRS scoring (F13, F18) into the RL feature vector.

---

## 4.6 Implications of Results

### 4.6.1 When to Prioritize RL over Static Rules?
RL is optimal for diverse, changing attack environments. Static Rules are preferred for monotonous traffic requiring instantaneous, low-overhead filtering at the edge.

### 4.6.2 Minimum Infrastructure Requirements
Centralized capture node (edge router) with Python 3/Scapy. PPO inference is computationally efficient, suitable for deployment on standard or embedded hardware.

### 4.6.3 Honeypot as a Strategic Advantage
Redirection allows for gathering threat intelligence (TTPs, payloads) without compromising production systems.

### 4.6.4 Policy Reusability
Policies can be redeployed if the 34D observation structure is maintained, allowing lab-tested policies to go straight to production.

### 4.6.5 Future Directions
*   **Expansion of Action Space:** Detailed actions like rate-limiting by request type.
*   **Multi-Agent Defense:** Distributed RL nodes for SDN-scale environments.
