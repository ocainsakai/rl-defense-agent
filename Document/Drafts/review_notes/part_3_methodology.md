# CHAPTER 3: RESEARCH METHODOLOGY

## Table of Contents

- [3.1 Research Design](#31-research-design)
  - [3.1.1 Threat Model](#311-threat-model)
  - [3.1.2 Methodological Framework](#312-methodological-framework)
  - [3.1.3 System Architecture](#313-system-architecture)
  - [3.1.4 MDP Formalization](#314-mdp-formalization)
  - [3.1.5 Experimental Network Topology](#315-experimental-network-topology)
  - [3.1.6 RL Defense Agent Design](#316-rl-defense-agent-design)
    - [3.1.6.1 RL Training Environment Implementation](#3161-rl-training-environment-implementation)
    - [3.1.6.2 Traffic Generation and Domain Randomization](#3162-traffic-generation-and-domain-randomization)
    - [3.1.6.3 Action Space and Defensive Strategy](#3163-action-space-and-defensive-strategy)
    - [3.1.6.4 Temporal Observation Window and Soft Escalation](#3164-temporal-observation-window-and-soft-escalation)
    - [3.1.6.5 Reward Function and Persistence-Aware Shaping](#3165-reward-function-and-persistence-aware-shaping)
    - [3.1.6.6 Policy Optimization (PPO)](#3166-policy-optimization-ppo)
    - [3.1.6.7 Training Configuration and Academic Calibration](#3167-training-configuration-and-academic-calibration)
    - [3.1.6.8 Adversarial Dynamics and Closed-Loop Feedback](#3168-adversarial-dynamics-and-closed-loop-feedback)
  - [3.1.7 Inference Deployment and Enforcement Pipeline](#317-real-time-inference-and-enforcement-pipeline)
  - [3.1.8 Emulation-Based Validation Protocol](#318-emulation-based-validation-protocol)
- [3.2 Data Collection Methodology](#32-data-collection-methodology)
  - [3.2.1 Packet Capture and Dissection](#321-packet-capture-and-dissection)
  - [3.2.2 Connection Session Management](#322-connection-session-management)
  - [3.2.3 1-Second Sliding Window](#323-1-second-sliding-window)
  - [3.2.4 Data Sources](#324-data-sources)
- [3.3 Sampling & Data Analysis Techniques](#33-sampling--data-analysis-techniques)
  - [3.3.1 Data Sampling Strategy](#331-data-sampling-strategy)
  - [3.3.2 Feature Engineering Overview](#332-feature-engineering-overview)
    - [3.3.2.1 Payload Normalization Pipeline](#3321-payload-normalization-pipeline)
    - [3.3.2.2 Multi-dimensional Feature Representation (34D)](#3322-multi-dimensional-feature-representation-34d)
      - [A. Traffic & Payload Features (20D: F1-F20)](#a-traffic--payload-features-20d-f1-f20)
      - [B. Temporal Context State (10D: F21-F30)](#b-temporal-context-state-10d-f21-f30)
      - [C. Closed-Loop Effect Feedback (4D: F31-F34)](#c-closed-loop-effect-feedback-4d-f31-f34)
    - [3.3.2.3 Attack Coverage Matrix](#3323-attack-coverage-matrix)
    - [3.3.2.4 Feature Vector Normalization](#3324-feature-vector-normalization)
- [3.4 Methodological Limitations](#34-methodological-limitations)

---

This chapter delineates the methodological framework of the research, designed to systematically address the Information Asymmetry, Contextual Gap, and Enforcement Gap identified in Chapter 2. It details the design, training, and deployment of the Reinforcement Learning defense Agent, formalizing the system architecture from data extraction and state representation to real-time enforcement and emulation-based validation.

## 3.1 Research Design

### 3.1.1 Threat Model

To establish a clear scope for our defensive system, we first define a threat model that identifies potential adversaries and their capabilities. We assume an external attacker operating at the network level, targeting public-facing web services.

Attacks are classified based on technical characteristics and impact level:

- **Volumetric Attacks:** High-volume traffic (DDoS, SYN Flood) exhausting bandwidth and TCP connection tables.
- **Reconnaissance:** Port Scan to map active services.
- **Credential Attacks:** Brute-force attacks to bypass authentication information.
- **Application Layer Attacks (L7):** Exploiting Web application layer vulnerabilities (Layer 7) through SQL Injection (SQLi) and Cross-Site Scripting (XSS) in HTTP payloads.

**Adversary constraints:** The attacker possesses no internal privileges (Black-box setup, unaware of defense policies).
**Defender capabilities:** The defender maintains comprehensive monitoring at the edge router, TLS decryption capabilities via `SSLKEYLOGFILE`, and real-time enforcement authority via `iptables`.

### 3.1.2 Methodological Framework

The project approaches the network defense problem from the perspective of automatic sequential decision-making. The system not only detects attacks but also selects appropriate response actions according to each context.

The research methodology is executed across two parallel branches:

1. **Observation & Feature Extraction Module:** Captures the network state. This module converts and statistically analyzes raw network traffic into semantic meaningful observation vectors for the Agent.
2. **RL Defense Agent:** Implements the **Learning Agent** architecture (Russell & Norvig, 2020) as detailed in the theoretical framework of Chapter 2. In this deployment:
    - The **Performance Element** consists of the trained PPO policy network.
    - The **Critic** facilitates training via state-value estimation.
    - The **Learning Element** executes the optimization loop.
    - The **Problem Generator** is implemented via the Gymnasium environment.

**System Classification: Offline-Trained, Inference-Deployed.** As established in Section 2.1.2, the proposed system is an **offline-trained, inference-deployed** architecture — a distinction that governs the entire design of this chapter. The two stages operate under fundamentally different learning modes:

| Stage | Learning Mode | Weight Updates | Data Source |
|---|---|---|---|
| **Training** (IDSDefenseEnv simulator) | On-policy (PPO) | Active — gradient descent per rollout | Synthetic simulator (MockIPBehavior + domain randomization) |
| **Deployment** (Mininet + iptables) | **None — frozen inference** | None | Live network traffic (observation only) |

During the Training Stage, the Learning Element (PPO optimization loop) actively updates the policy weights $\theta$ via gradient descent through interaction with the simulator. Once training converges, $\theta$ is **permanently frozen**. In the Deployment Stage on Mininet, the system executes policy inference $\pi_{\theta^*}(s_t)$ exclusively — a forward pass through the frozen policy network — without any gradient computation or weight update. The agent's adaptivity in production derives entirely from what was learned during training, not from live traffic.

This classification has two direct consequences for the system design described in this chapter: (1) the Training Stage must expose the agent to sufficient diversity of attack scenarios to generalize to unseen variations at deployment time; and (2) the Deployment Stage operates at **near real-time** granularity, which is distinct from the sub-millisecond latency of the iptables enforcement layer that applies rules instantaneously once set.

Building upon the theoretical advantages of PPO discussed in Chapter 2, the research team performed an empirical screening step on the CIC datasets comparing PPO, DQN, and A2C. The benchmark results, presented in Chapter 4, validate the selection of PPO based on its superior stability and operational safety in stochastic network environments.

**Table 3.1: RL Algorithm Comparison and Selection Rationale**

| Criteria | DQN (Deep Q-Network) | A2C (Advantage Actor-Critic) | PPO (Proximal Policy Optimization) |
|---|---|---|---|
| **Approach** | Value-based: Learns the $Q(s, a)$ function. | Actor-Critic: Hybrid approach. | Policy-based: Directly optimizes the policy. |
| **Learning Mode** | Off-policy: Reuses historical data. | On-policy: Learns from current experience. | On-policy: Uses clipped updates. |
| **Stability** | Moderate (Prone to overestimation). | Low (High variance). | **Very High** (Clipped objective). |
| **Sample Efficiency** | High (Reuses past data). | Low (Requires more interactions). | Moderate (Balanced stability). |
| **Core Mechanism** | Experience Replay & Target Network. | Advantage Function. | Clipped Surrogate Objective. |

### 3.1.3 System Architecture

The proposed defensive system is structured according to a three-layer architecture:

1. **Observation & Feature Extraction Layer:** Captures raw network packets to extract **20 behavioral features** from bidirectional flows. It simultaneously integrates **14 internal state dimensions** (10D persistent temporal context and 4D delayed environmental feedback) maintained by the system memory to construct the unified **34D observation vector**.
2. **Decision-Making Layer (RL Defense Agent):** Receives the consolidated 34D vector as a complete snapshot of the system's context. It utilizes the trained PPO policy to map this observation to the optimal defensive action $a_t$. In accordance with the Two-Stage Development Framework established in Chapter 2, the Agent is first trained for 500,000 steps in a Gymnasium simulation before being transitioned to the Mininet emulation environment for deployment and validation.
3. **Enforcement Layer:** Deploys defensive actions into the network infrastructure via `iptables`:
    - **Allow (0):** Permits traffic to pass without interference.
    - **Rate Limit (1):** Constrains bandwidth using `hashlimit` (2 pkt/s).
    - **Redirect (2):** Routes traffic to a honeypot via NAT PREROUTING.
    - **Block (3):** Completely drops traffic via `iptables` DROP.

Each action carries a distinct deployment cost ($C_{action}$), incorporated into the reward function to guide the Agent in equilibrating security and service performance.

### 3.1.4 MDP Formalization

Building upon the task environment properties analyzed in Chapter 2 (Section 2.1.1), the network defense challenge is formalized for implementation. While the problem is theoretically a **Partially Observable Markov Decision Process (POMDP)**, the research overcomes the computational intractability of belief-state tracking by engineering a **34-dimensional observation vector**.

This vector serves as an **approximate Sufficient Statistic**. By integrating instantaneous traffic metrics with 10D temporal context and 4D feedback signals, the system captures enough environmental history to satisfy the Markov property. This allows the Agent to treat the environment as a standard **Markov Decision Process (MDP)**, defined by the tuple $(S, A, P, R, \gamma)$, where the policy $\pi$ maps the 34D state directly to the optimal defensive action.

**State Space ($S$):** The observation space consists of a 34-dimensional vector, normalized to $[0, 1]$.

**Table 3.2: 34D Observation Space Segmentation**

| Group | Dimensions | Content |
|---|---|---|
| Traffic Features | 20D (F1–F20) | Instantaneous statistical and payload-based network metrics. |
| Temporal State | 10D ([20–29]) | Persistent temporal context and internal IP-tracking state. |
| Closed-Loop Feedback | 4D ([30–33]) | Delayed feedback from the environment ($effect_{t-1}$) from the previous action. |

**Action Space ($A$):** The Agent selects from a set of four discrete actions ($a_t \in \mathcal{A}$), each associated with an operational cost $c(a)$:

- **Allow ($a_0$):** $c_0 = 0$. No interference; default for benign traffic.
- **Rate Limit ($a_1$):** $c_1 > c_0$. Bandwidth constraint using `hashlimit`.
- **Redirect ($a_2$):** $c_2 > c_1$. Honeypot routing for L7 analysis.
- **Block ($a_3$):** $c_3 > c_2$. Full neutralization via `iptables` DROP.

The hierarchical cost structure $c_0 < c_1 < c_2 < c_3$ ensures the Agent prioritizes low-intervention actions unless the threat severity justifies a more restrictive response.

**Reward Function ($R$):** The reward signal $r_t$ is structured to balance security and availability as a two-stage objective.

The baseline component defines the instantaneous trade-off:
$$R_{base} = B_{action} - C_{action} - 0.12 \cdot service\_damage$$

Where:

- **$B(s, a)$:** A contextual bonus for selecting an action appropriate to the detected threat typology.
- **$c(a)$:** The operational cost of action $a$.

The total reward for the v13 Agent incorporates strategic shaping components:
$$R = R_{base} + P_{osc} + B_{stab} + B_{ramp} + B_{persist} + P_{premature}$$

The shaping components are engineered to drive the escalation logic:

- **Oscillation Penalty ($P_{osc}$):** Penalizes downgrading defense levels while attack pressure remains elevated.
- **Stability Bonus ($B_{stab}$):** Rewards sustaining contextually appropriate actions; specifically incentivizes holding Redirect during active L7 sessions.
- **Ramp Bonus ($B_{ramp}$):** Provides a progressive reward gradient to transition from Redirect to Block as forensic evidence accumulates.
- **Persistence Bonus ($B_{persist}$):** Heavily rewards the final transition to Block once the block ready flag is triggered.
- **Premature Penalty ($P_{premature}$):** Penalizes issuing a Block action before sufficient session evidence is gathered.

**Relationship between $R_{base}$ and $R$:**
The two-stage structure ensures a balance between **instantaneous utility** and **strategic continuity**. While $R_{base}$ provides the primary gradient for immediate damage mitigation, the aggregate components ($P, B$) function as a "strategic overlay." This compatibility allows the Agent to prioritize short-term network health while adhering to long-term defensive protocols (e.g., waiting for forensic evidence in the Honeypot before a full Block).

Finally, the reward is clamped within the range $[-1, 1]$ to stabilize the training process.

**Discount Factor ($\gamma = 0.995$):** Encourages long-term cumulative reward optimization, essential for identifying multi-step attack patterns.

### 3.1.5 Experimental Network Topology

The experimental environment is constructed upon **Mininet** (network virtualization) and **Docker** (application isolation). It facilitates the creation of realistic network topologies on standard hardware:

- **Router (10.0.10.254/24):** The central node hosting `iptables` and Nginx Reverse Proxy. Nginx routes port 443 to the Webserver and port 4443 to the Honeypot. The `X-Real-IP` header is injected to ensure the flow manager accurately identifies the source IP post-NAT.
- **Webserver (192.168.10.10/24):** The legitimate service, acting as the primary attack target.
- **Honeypot (192.168.30.10/24):** The server absorbs Layer 7 attacks. When the Agent selects Redirect, the attacker continues operations on the Honeypot while the real server remains secure.
- **Attacker (10.0.10.10/24):** Attack source node implementing scenarios using `hping3`, `sqlmap`, and `nmap`.
- **Wazuh SIEM (192.168.20.20/24):** Records secondary baseline logs for cross-verification.

### 3.1.6 RL Defense Agent Design

Unlike traditional signature-based classifiers, the RL Agent does not learn to explicitly categorize attack labels. Instead, it learns the causal relationship between interventions and outcomes: given a specific network state, it evaluates whether selecting Action A will yield a healthier future system state than Action B. This sequential, consequence-driven decision making is the core essence of the proposed adaptive defense.

#### 3.1.6.1. RL Training Environment Implementation

The training environment, designated **IDSDefenseEnv**, is structured as a closed-loop control system, formalized through the Markov Decision Process (MDP) theoretical framework outlined in Section 3.1.4. IDSDefenseEnv is implemented as a Gymnasium-compatible environment, integrating dynamic entity management mechanisms to simulate session persistence across heterogeneous IP behavioral profiles.

**Episode Structure:** The temporal dynamics of the simulation are defined by a fixed episode length of 320 steps, corresponding to an operational window of 8 minutes. This duration is calibrated to ensure sufficient time for the Agent to observe the progressive development of L7 attack campaigns and formulate a context-aware defensive response.

**Session Allocation:** The system simultaneously simulates 16 heterogeneous IP entities, where each session performs a 20-step behavioral process to collect more features before context switching. This structure allows the agent to learn temporal dependencies and early warning signs of multi-stage attacks.

#### 3.1.6.2. Traffic Generation and Domain Randomization

IDSDefenseEnv integrates a **Stateful Behavioral Simulation Engine** — designated **MockIPBehavior** — to simulate a comprehensive suite of network attack vectors. Each IP entity within an episode is represented by a dedicated MockIPBehavior instance, which maintains persistent behavioral state across its 20-step session lifecycle and generates feature vectors via statistical distributions calibrated from empirical datasets such as CSE-CIC-IDS2018. This design ensures that the Agent is exposed to a diverse range of adversarial behaviors, ranging from targeted, high-intensity attacks to stealthy, distributed campaigns.

**Traffic Generation and Domain Randomization:**

The simulation logic orchestrates MockIPBehavior instances sequentially within an episode, with each instance assigned one of six behavioral profiles: benign, SYN Flood, Port Scan, Brute Force, SQL Injection, or XSS.

To enhance the sustainability of the Agent and prevent the phenomenon of "rote learning" (overfitting) static attack signals, the system employs **domain randomization**. This technique prevents the agent from converging on fixed thresholds (local thresholds), forcing the policy to extract abstract and non-linear behavioral patterns from the data. Network features are parameterized based on specific mathematical distributions to reflect the randomness of reality:

- **Packet Rate:** Uses the Gaussian Normal Distribution to model bandwidth variability.
- **Port Probing:** Uses the Poisson Distribution to describe the discrete nature of connection events during port scanning.
- **Feature Ratios:** Applies the Beta Distribution to limit variables to the $[0, 1]$ domain, suitable for features such as URL concentration or packet error rate.

 By exposing the Agent to a non-stationary environment where the statistical properties of the traffic vary, the system promotes the development of generalized defensive policies resilient to novel attack variations.

**Synthetic Attack Vectors:**

- **DDoS (SYN Flood):** This behavioral profile generates synthetic volumetric traffic characterized by a massive surge in packet rates ($F_1 \approx 350$ pkt/s) and a highly asymmetric SYN/ACK ratio ($F_2 \approx 10$), typical of half-open connection attempts. Feature distributions are sampled statistically within the simulator. In the Mininet emulation stage, equivalent traffic is generated using `hping3` for deployment validation.

- **Port Scan:** This behavioral profile generates synthetic reconnaissance traffic exhibiting a high number of distinct destination ports ($F_5$) and elevated reset ratios ($F_4 \approx 0.60$), reflecting failed connection attempts across multiple services. In the Mininet emulation stage, equivalent traffic is generated using `nmap` for deployment validation.

- **Brute Force:** This behavioral profile generates synthetic HTTP credential-stuffing traffic calibrated from CIC-IDS2018 empirical measurements. Two subtypes are modeled: standard HTTP brute force ($F_7 \approx 0.12$) and a keep-alive bot variant exhibiting high temporal uniformity ($F_7 \approx 0.85$) and request size uniformity ($F_8 \approx 0.88$). All feature distributions are generated via statistical sampling within the simulator without invoking any external tool.

- **SQL Injection:** This behavioral profile generates synthetic SQLi traffic calibrated from CIC-IDS2018 SQL Injection windows, reflecting low-rate attack behavior ($F_1 \approx 12$ pkt/s), concentrated exploit URLs ($F_6 \approx 0.70$), and elevated CRS 942 scores ($F_{13} \approx 5.5$), UNION SELECT indicators ($F_{14} \approx 0.4$), and SQL comment markers ($F_{15} \approx 0.6$). All feature vectors are generated statistically within the simulator. In the Mininet emulation stage, `sqlmap` is used directly for deployment validation.

- **XSS Attack:** This behavioral profile generates synthetic XSS traffic calibrated from CIC-IDS2018 Brute Force-XSS windows, characterized by high URL concentration ($F_6 \approx 0.95$), elevated CRS 941 scores ($F_{18} \approx 2.2$), and JavaScript function call indicators ($F_{19} \approx 0.9$). All feature vectors are generated statistically within the simulator without invoking any external XSS tool.

#### 3.1.6.3. Action Space and Defensive Strategy

The defense system utilizes a discrete action space consisting of 4 levels, designed according to the Action Ladder model. Each action corresponds to a specific technical execution mechanism at the network and application layers via iptables, where current action changes future state and reward.

- **Allow ($a=0$)**: The system will not interfere with the packets. This is the default state for traffic identified as safe (benign traffic), ensuring availability and a smooth experience for legitimate users.
- **Rate Limit ($a=1$)**: Uses the iptables hashlimit tool to limit packet frequency to 2 packets/second with a burst threshold of 5 packets. This action acts as a defensive buffer, typically applied to traffic sources showing signs of "noise" or behavioral patterns that are not sufficiently evidence to confirm an attack but are not entirely normal either.
- **Redirect ($a=2$)**: This is a defense mechanism specifically designed for application layer (L7) attacks such as Brute Force, SQL Injection (SQLi), and Cross-Site Scripting (XSS). Instead of immediately blocking, the system redirects traffic to a decoy server (Honeypot). This gives the Agent more time to analyze the attacker's intentions without jeopardizing the real system, while also providing valuable data to Wazuh SIEM for analyzing attack patterns.
- **Block ($a=3$)**: The system uses the iptables DROP command to completely cut off the connection from the attack source. This is the strongest measure, reserved for volumetric attacks such as DDoS, SYN Flood, or Port Scan. These types of attacks require immediate intervention to protect bandwidth and system resources from depletion.

**Table 3.3: MDP Implementation Parameters**

| Symbol | Parameter | v13 Value | Description |
|---|---|---|---|
| $\omega$ | Damage Weight | 0.12 | Weight for $F_{24}$ (Service Damage). |
| $c_0$ | Cost (Allow) | 0.00 | Baseline cost for no intervention. |
| $c_1$ | Cost (RateLimit) | 0.01 | Minimal overhead for bandwidth throttling. |
| $c_2$ | Cost (Redirect) | 0.04 | Operational cost for Honeypot traffic routing. |
| $c_3$ | Cost (Block) | 0.15 | Maximum penalty for service unavailability. |

The cost of the actions is set to increase progressively from $0.00 to $0.15 to reflect the trade-off between security and service availability:

- The increasing cost encourages the RL agent to prioritize mild interventions before resorting to extreme measures. The agent will learn to only use the Block command when the threat level truly exceeds the dangerous threshold.

- In a real-world environment, mistakenly blocking a legitimate user causes significant economic damage. Therefore, the cost of $c_3 = $0.15 acts as a heavy penalty, forcing the agent to accumulate sufficient evidence (through the Redirect phase) before making a final blocking decision.

- This cost ladder creates "economic pressure" on the agent, prompting the formation of an escalation strategy: Observe ($\rightarrow$), Restrict ($\rightarrow$), Isolate ($\rightarrow$), and Block.

#### 3.1.6.4. Temporal Observation Window and Soft Escalation

To ensure high-precision decision-making and minimize false positives, the system integrates a **Temporal Observation Window ($W_{total}$)** with a **Soft Escalation** protocol. This unified mechanism ensures that high-impact actions, such as **Block**, are only executed after a sufficient accumulation of forensic evidence.

**1. Session Lifecycle and Window Structure ($W_{lifecycle} = 20$ steps):**
Each unique IP entity is allocated a total lifecycle of 20 discrete time steps within an episode. Within this lifecycle, the system maintains a 15-step soft monitoring window ($W_{soft} = 15$) specifically for evidence accumulation and escalation scoring. This window provides the "forensic runway" necessary for the Agent to observe behavioral evolution across 3 distinct operational phases:

- **Phase 1: Observation & Monitoring (Steps 1–11):** Initial assessment of traffic features. If L7 signals exceed 0.35, the IP is flagged. During this phase, the Agent is incentivized to use the **Redirect** action to route traffic into the Honeypot. Issuing a **Block** action here is penalized as "premature" since the evidence is not yet statistically significant.
- **Phase 2: Ramp Zone / Critical Decision Window (Steps 12–14):** This 3-step window (15% of the session lifecycle) constitutes the critical decision point of the Soft Escalation mechanism. If the accumulated threat confidence score reaches $\ge 0.60$, the latching enforcement flag is activated. The Agent is then encouraged to transition from Redirect to Block via a progressive **Ramp bonus**.
- **Phase 3: Enforcement & Persistence (Steps 15–20):** Once the latching enforcement flag is activated, the system enters the enforcement phase. The Agent must sustain the **Block** action; any reversion to Allow or Redirect is heavily penalized to prevent "evasive flickering" by the attacker.

**2. Evidence-Based Escalation Logic:**
The escalation score is not purely instantaneous but is a moving accumulation of:

- **Signal Consistency:** Malicious payload features ($F_{12}$–$F_{20}$).
- **Isolation Feedback:** The honeypot hit rate from Nginx logs.
- **Temporal Persistence:** The duration of the IP's presence in the network.

This tiered approach—Observe $\to$ Redirect (Analyze) $\to$ Block—ensures that service disruption is reserved strictly for verified threats while maintaining system availability for legitimate users.

#### 3.1.6.5. Reward Function and Persistence-Aware Shaping

The reward function $r_t$ is engineered to maximize the expected cumulative return $G_t$ as defined in the RL mathematical foundations of Chapter 2. Instead of a simple binary reward, the system employs a **Persistence-Aware Shaping** architecture, structured as a unified formula combining a core baseline with strategic shaping components:

$$R_{total} = \underbrace{(B_{action} - C_{action} - 0.12 \cdot service\_damage)}_{\text{Base Reward } (R_{base})} + \underbrace{\sum R_{shaping}}_{\text{Shaping Components}}$$

Where $B_{action}$ is the detection reward, $C_{action}$ is the operational cost, and $0.12 \cdot service\_damage$ is the penalty for service disruption.

The network damage function $D$, computed from the 20 raw feature dimensions, comprises 6 components with weights reflecting severity:

**Table 3.4: Network Damage Function ($D$) Components**

| Component | Weight | Feature | Non-linear Function |
|---|---|---|---|
| PPS Overflow (DDoS) | 0.25 | F1 | Logistic: $1/(1+e^{-5(F1/anchor - 1)})$ |
| RST Ratio (scan/brute) | 0.15 | F4 | Tanh: $\tanh(F4 \times 2)$ |
| Port Scan Distribution | 0.15 | F5 | Log-sigmoid over raw port count |
| Payload Anomaly | 0.10 | F9, F4, F5 | Logistic, excluding benign uploads |
| SYN flood | 0.10 | F2 | Tanh over threshold exceedance ratio |
| SQLi/XSS (L7 attack) | 0.25 | F12–F20 | Normalized weighted combination |

The logistic and tanh functions neutralize minor noise (benign traffic inflicts damage $\approx$ 0) but exhibit pronounced reactions when thresholds are breached. Legitimate uploads (F9 $\ge$ 3000 + low F4 + low F5) are excluded from payload damage to circumvent unwarranted penalties.

Detection Reward $B_{action}$: Grants rewards/penalties based on soft gating partitions:

- DDoS/Port Scan prompting Block $\to$ +0.30; prompting Allow $\to$ −0.50
- Brute Force/SQLi/XSS prompting Redirect $\to$ +0.35; prompting Allow $\to$ −0.40
- Benign traffic prompting Block $\to$ **−0.60** (most severe penalty — false positives inducing service disruption)

To govern escalation and prevent erratic behavior, the system integrates five strategic shaping components ($\sum R_{shaping}$), detailed below:

**Table 3.5: Reward Shaping Components**

| Component | Symbol | Value | Trigger Condition | Strategic Function |
|---|---|---|---|---|
| Stability Bonus | $B_{stab}$ | +0.01 (general); +0.05 (L7 Redirect) | Action held for at least one consecutive step in a contextually appropriate state; or Redirect is active during an L7 session | Reinforces holding the correct action; provides a stronger incentive to maintain Redirect while honeypot evidence accumulates. |
| Ramp Bonus | $B_{ramp}$ | +0.08 / +0.15 (Block); −0.03 / −0.06 (Redirect) | Monitoring session active, enforcement flag not yet latched, step ∈ {12–13} or {14}, escalation score ≥ 0.50 | Creates a progressive reward gradient driving the transition from Redirect to Block; penalty magnitude increases at step 14 to create urgency at the final decision boundary. |
| Persistence Bonus | $B_{persist}$ | +0.45 (Block); −0.35 (Redirect); −0.40 (Allow/RateLimit) | Enforcement flag latched and attacker presence confirmed | Heavily rewards sustained Block once sufficient evidence is accumulated; symmetric penalties prevent reversion to weaker actions. |
| Oscillation Penalty | $P_{osc}$ | −0.05 (outside session); −0.10 / −0.15 (inside session) | Defense level downgraded while service damage remains elevated; or Allow/RateLimit issued during an active session at step < 12 / ≥ 12 | Discourages flickering back to weaker actions while attack pressure persists; penalty escalates with session depth. |
| Premature Penalty | $P_{premature}$ | −0.20 | Monitoring session active, enforcement flag not yet latched, Block issued prior to the ramp zone (before step 12) | Prevents aggressive early blocking before sufficient forensic evidence is gathered, reducing false positives on benign traffic. |

This multi-component reward function not only tells the Agent to "block the attack," but also teaches the Agent to "observe carefully, accumulate evidence through the Nginx log, and only block when absolutely certain so as not to disrupt normal users."

#### 3.1.6.6. Policy Optimization (PPO)

As established in Chapter 2, to achieve stable policy convergence and maximize the aforementioned reward $R_{total}$ within the high-dimensional state space, the Agent utilizes the **Clipped Surrogate Objective** of the PPO algorithm:
$$L^{CLIP}(\theta) = \hat{\mathbb{E}}_t\left[\min\left(r_t(\theta)\hat{A}_t,\; \text{clip}(r_t(\theta), 1-\epsilon, 1+\epsilon)\hat{A}_t\right)\right]$$

Advantage estimation is facilitated through **Generalized Advantage Estimation (GAE)** to balance bias and variance:
$$\hat{A}_t^{GAE(\gamma,\lambda)} = \sum_{l=0}^{\infty} (\gamma\lambda)^l \delta_{t+l}$$

The following algorithm summarizes the iterative optimization procedure utilized for training the defense policy:

**Algorithm 1: PPO-based Defense Policy Optimization**
---

1: Initialize policy parameters $\theta$ (Actor) and value function parameters $\phi$ (Critic)
2: **for** iteration = 1, 2, ... **do**
3:   **for** actor = 1, ..., N **do**
4:     Run current policy $\pi_{\theta_{old}}$ in simulation for $T$ timesteps
5:     Compute reward $r_t$ and observe next state $s_{t+1}$
6:     Calculate advantage estimates $\hat{A}_1, \ldots, \hat{A}_T$ using GAE
7:   **end for**
8:   **for** epoch = 1, ..., K **do**
9:     Update $\theta$ by maximizing the Clipped Surrogate Objective $L^{CLIP}$
10:    Update $\phi$ by minimizing the Value Function Loss $L^{VF}$
11:  **end for**
12:  $\theta_{old} \leftarrow \theta$
13: **end for**
---

#### 3.1.6.7. Training Configuration and Academic Calibration

**Table 3.6: PPO Agent Training Hyperparameters**

| Parameter | Value | Design Rationale |
|---|---|---|
| **Total Steps** | 500,000 | Ensure convergence across all 5 attack typologies. |
| **Net Arch (pi, vf)** | [256, 128], [256, 256, 128] | Increased capacity to map complex high-dimensional boundaries. |
| **Clip Range ($\epsilon$)** | 0.15 | Tighten policy updates to prevent overshoot and ensure stability. |
| **Discount ($\gamma$)** | 0.995 | Extended temporal horizon to capture dependencies in 320-step episodes. |
| **Learning Rate** | $3 \times 10^{-4}$ | Standard Adam LR with linear decay to refine the terminal policy. |
| **Entropy Coef** | 0.05 | Maintains exploration to prevent policy collapse. |
| **Batch Size** | 128 | Enhanced gradient stability for the 34D observation space. |

#### 3.1.6.8. Adversarial Dynamics and Closed-Loop Feedback

In contrast to traditional detection systems that treat network traffic as a static data stream, this RL environment establishes a **Closed-Loop Feedback** mechanism through the reactive attacker model. This architecture transforms the network defense challenge from a static 'traffic classification and action mapping' problem into a dynamic sequential decision-making process. Every action taken by the Agent actively alters the subsequent state of the environment and the trajectory of future rewards.

- **Reactive Behavior:** Adversaries are modeled as dynamic agents. For instance, if the Agent applies a **Rate Limit**, the attacker may respond by increasing payload intensity or diversifying access vectors to bypass the throttle. This forces the Agent to learn that sub-optimal mitigation can lead to escalated adversarial pressure.
- **Deceptive Isolation (Safe Observation):** When the **Redirect** action is enforced, the attacker is transparently routed to the Honeypot. From the adversary's perspective, the service remains operational, encouraging them to proceed with their full exploit chain (e.g., transitioning from SQLi probing to data exfiltration). This allows the Agent to safely observe the entire "Kill Chain" without jeopardizing production assets.
- **Strategic Interaction:** This mechanism prevents the policy from overfitting to static thresholds. The Agent must learn to anticipate the consequences of its actions, fostering a balance between immediate threat suppression and long-term forensic evidence collection.
- **Asymmetric Visibility:** A unique technical feature of the environment is the preservation of visibility. Even when an IP is **Blocked** (Layer 3 DROP), the monitoring model continues to record raw connection attempts while the application-layer damage metrics drop to zero. This differentiation allows the Agent to distinguish between the continued presence of an attacker and the actual impact on service availability.

### 3.1.7 Inference Deployment and Enforcement Pipeline

The operational system transitions the trained policy into a Mininet environment. This pipeline provides the technical implementation of the high-level escalation strategy defined in Section 3.1.6.4, structured into three functional layers:

1. **Data Acquisition Layer:** Operates as a continuous sniffer, capturing packets and aggregating them into statistical summaries every second. This decoupling ensures that the capture process is not blocked by model inference.
2. **Inference Engine:** Performs normalization, state expansion (concatenating the 10D temporal and 4D feedback states), and policy prediction.
    - **SafetyNet (Inference Guardrails):** The SafetyNet layer enforces infrastructure constraints during inference: it overrides to Redirect when pronounced L7 signals are detected yet the model erroneously selects Allow/RateLimit, and it maintains Block when the rolling average damage remains critical to prevent oscillation. This layer does not supersede the RL policy; it solely rectifies operational risk scenarios.
3. **Enforcement Layer:** Actions are enforced via `iptables` rules.
    - **IP State Tracker:** Sustains a per-IP dictionary logging action history and session states. The soft escalation protocol (15-step soft window) progresses through the following sequence:
        - **Action Recording:** The system records the most recent action and its duration so that the Agent can understand the current context of each IP.
        - **Session Initialization:** When the Agent selects Redirect and detects a sufficiently strong application layer (L7) attack signal, a 15-step monitoring session is initiated.
        - **Evidence Accumulation:** In each second of the session, the system records 5 key metrics: redirect status, traffic presence, honeypot capture capability, number of misses, and attack pressure.
        - **Evidence Score Calculation:** The Redirect ratio, Honeypot ratio, Presence ratio, and mean pressure are synthesized into an escalation score (`escalation_score`) bounded within [0,1].
        - **Permissible Miss Budget Management:** If the IP address remains active but is not captured by the honeypot more than 3 times (miss_count), the score will be reduced and a risk warning will be issued.
        - **Block Ready Flag Activation:** Once sufficient reliable evidence has been accumulated and the minimum number of steps is reached, the system sets the "Block Ready" flag to suggest promotion to the Block action.
        - **Session Termination:** The monitoring session automatically resets when the IP address becomes inactive or the traffic becomes clean, preventing the system from maintaining redundant controls. This mechanism replaces rigid timers with flexible, validated decision-making logic based on the actual behavior of each IP address.

The complete pipeline is formalized in Algorithm 2, which integrates the three functional layers described above into a unified near real-time control loop.

**Algorithm 2: Near Real-Time Inference and Enforcement Pipeline**
---

**Input:** Live network traffic stream from Mininet Router interface

**Output:** `iptables` enforcement action $a_t$ per source IP per 1-second window

1: **loop** *(continuous, one iteration per 1-second window)*
2:   Collect all packets within $[t-1, t]$ → compute 20D feature vector $\mathbf{f}_t = [F_1, \ldots, F_{20}]$
3:   Retrieve per-IP **PerIPTemporalState** → 10D temporal vector $\mathbf{h}_t$
4:   Retrieve closed-loop feedback from previous step → 4D effect vector $\mathbf{e}_{t-1}$
5:   Construct $\mathbf{obs}_{34} \leftarrow [\mathbf{f}_t \;\|\; \mathbf{h}_t \;\|\; \mathbf{e}_{t-1}]$ $\quad \triangleright$ normalized to $[0,1]^{34}$
6:   $a_t \leftarrow \pi_{\theta^*}(\mathbf{obs}_{34})$ $\quad \triangleright$ frozen policy forward pass — no gradient computation
7:   **if** SafetyNet override condition met **then**
8:     $a_t \leftarrow \text{SafetyNet}(a_t,\; \mathbf{obs}_{34})$ $\quad \triangleright$ guardrail correction for operational risk
9:   **end if**
10:  Enforce $a_t$ via `iptables` rule on source IP
11:  **if** $a_t = \text{Redirect}$ **and** L7 signal $\geq 0.35$ **then**
12:    Increment soft escalation window; record evidence metrics
13:    **if** escalation\_score $\geq 0.60$ **and** step $\geq 12$ **then**
14:      Activate **block\_ready** flag $\quad \triangleright$ promote to Block at next step
15:    **end if**
16:  **end if**
17:  Update **PerIPTemporalState** with $(a_t, \mathbf{obs}_{34})$
18:  Update $\mathbf{e}_t$ from network feedback (webserver reachability, honeypot capture ratio)
19: **end loop**

---

Specifically, each action generates a measurable effect on the 34-dimensional observation space, exerting a direct impact on the 20 traffic feature dimensions and reflecting in the 4 effect state dimensions; the 10 temporal state dimensions are updated based on the IP state:

**Table 3.7: Action Impact on Observation Space**

| Action | Impact on the 34D components at the subsequent step |
|---|---|
| **Rate Limit** | 20D: PacketRate and per-port packet density decrease; RST signals attenuate. 4D effect: service damage magnitude decreases. 10D temporal: IP-specific action hold counter increments. |
| **Redirect** | 20D: Brute force and L7 payload signals diminish as the honeypot absorbs them. 4D effect: honeypot capture ratio increases. 10D temporal: recent action history is updated. |
| **Block** | 20D: Attack signals are entirely neutralized in subsequent steps; traffic is completely severed. 4D effect: webserver reachability drops to 0. 10D temporal: escalation score increases. |

### 3.1.8 Emulation-Based Validation Protocol

To validate the Agent in a realistic environment, an emulation-based protocol is implemented:

1. **Mixed Attack Scenarios:** Using `hping3`, `nmap`, and `sqlmap` against a benign background stream generated by legitimate client nodes.
2. **Real-time Monitoring:** Capturing live traffic from the Router's interface and executing kernel-level `iptables` and `tc` rules.
3. **Performance Indicators (KPIs):** Measuring Mitigation Rate (packets neutralized), Service Availability (latency/success rate), and Decision Accuracy (Precision/Recall).

**Table 3.8: System Design Summary — From Problem Formulation to Deployment**

| Layer | Component | Role |
|---|---|---|
| **Problem Formulation** | POMDP → MDP approximation (34D sufficient statistic) | Defines $\mathcal{S}$ (34D), $\mathcal{A}$ (4 actions), $R_{total}$ |
| **Optimization Algorithm** | PPO — on-policy, GAE advantage estimation, clipped objective | Solves for optimal frozen policy $\pi_{\theta^*}$ |
| **Training Output** | Frozen policy $\pi_{\theta^*}$ (IDSDefenseEnv, 500k steps) | Weights fixed after convergence; no further updates |
| **Deployment** | Inference pipeline on Mininet + `iptables` enforcement | Near real-time defense (~1s granularity), no weight update |

---

## 3.2 Data Collection Methodology

### 3.2.1 Packet Capture and Dissection

The pipeline processes packets in two modes: Real-time Direct (via Scapy) and PCAP Offline (via PcapReader). The packet splitter extracts L3/L4 information—including IP address, TCP flags (SYN, ACK, RST, FIN), and payload size—into an immutable structured data object for each packet. In Real-time mode, the system supports HTTPS decryption by running tshark in parallel with Scapy: tshark reads SSLKEYLOGFILE to decrypt TLS, reassess the TCP stream, and outputs the decrypted HTTP fields (URI, User-Agent, Body); the results are appended back to the corresponding TCP packets in the flow for F12–F20 to analyze the payload as normal HTTP traffic.

At the application layer (L7), the system uses a **HTTP composite payload per-packet** method: at the time of parsing each packet, the system concatenates `[URI] + [User-Agent] + [Body]` from the same packet into a single string of bytes. This string is stored and reused directly when the F12–F20 features need to be parsed—no recalculation is required. The per-packet approach works efficiently because SQLi/XSS payloads from common tools are usually contained within a URI (GET request) or the small body of a single POST request.

### 3.2.2 Connection Session Management

Packets are first classified into flows by the flow manager. The flow manager identifies flows using 5-tuples (src_ip, dst_ip, src_port, dst_port, protocol) and stores flow objects in a dictionary. Each flow maintains two separate queues of packets (forward packets: src→dst, and reverse packets: dst→src), which allows independent calculation of flow-based features. Memory is controlled with a maximum of 50,000 concurrent flows and 3,000 packets per flow.

HTTP payload analysis is performed at the per-request level, meaning the analysis unit is each HTTP packet rather than the entire TCP stream. For HTTPS traffic, tshark reassembles the TCP stream before outputting HTTP fields, eliminating the need for manual reassembly. This design is consistent with the feature engineering approach that defines payload-based features proportionally to the number of HTTP requests.

### 3.2.3 1-Second Sliding Window

The RL agent requires the observed vector to reflect the current state of the network, not the entire session history. A 1-second sliding window fulfills this requirement: at each step, only packets within the range [t−1s, t] are used for feature calculation.

The 1-second size is experimentally adjusted from two opposing constraints: a window too short would not have enough packets to calculate the stability of statistical features; a window too long would blur the boundaries between attack phases, making it difficult for the agent to distinguish when a change in action is needed. Internal testing confirms that 1 second is the optimal balance point. This design ensures the following requirements:

- Normalization: Fixed time frame helps rate-based and packet interval (IAT) features maintain a consistent scale, preventing bias in policy optimization.
- Experimental equilibrium point: Through experiments, 1.0 second is determined to be the optimal "break point" long enough to ensure the stability of statistical features, but short enough to be sensitive to sudden changes between attack phases.
- MDP update process: At each decision step, the system performs sequentially: (1) Remove old packets outside the 1-second threshold; (2) Query current flows; (3) Feature extraction. Meaning: This process eliminates the phenomenon of old data leakage, ensuring that each state $s_t$ is an independent and pure slice of the network at the time of observation, helping the RL agent to react accurately to real-time fluctuations.

### 3.2.4 Data Sources

A fundamental characteristic of dataset (PCAPs) is the **lack of naturally occurring attack labels**. To overcome this challenge, labels in the study were assigned using a *controlled experimental labeling* method — the research team knew in advance the type of attack running at the time of data capture, so that all traffic in that session was assigned a corresponding label.

Five distinct data sources are incorporated, serving disparate objectives:

- **LSNM2024 Labeled URI Dataset [19]:** A public dataset disseminated by Lashkari et al. (University of New Brunswick)—comprising 3,000 benign URIs and 2,809 pre-labeled SQLi URIs. This dataset is designated for calibrating the CRS Paranoia Level and authenticating the payload normalization pipeline. This repository lacks authentic PCAP traffic—it exclusively houses HTTP URI strings, rendering network features F1–F11 inapplicable.
- **Mutated Packets PCAP Dataset (Abu Al-Haija et al., 2025) [20]:** A public PCAP dataset curated and disseminated by research teams at Jordan University of Science and Technology and Princess Sumaya University for Technology. The dataset encapsulates 15 attack typologies generated within a controlled laboratory Environment utilizing pragmatic tools: hping3 (SYN Flood, Port Scan), sqlmap (SQL Injection), Hydra/Burp Suite (Brute Force), XSS, DoS[21], Ares Botnet, Metasploit, Patator, and nmap. The research team exported the PCAP files via Wireshark into CSV format compliant with standardized formatting, subsequently feeding them into the feature extraction pipeline to formulate a labeled evaluation set. This constitutes the primary evaluation corpus for Tables 4.1 and 4.2.
- **Simulated MockIPBehavior (custom-built):** A state vector simulation Environment constructed by the research team, allocated **exclusively for PPO training**. It generates synthetic behavioral objects infused with distribution-based noise (Normal/LogNormal/Beta/Poisson) across individual features, purposely engineered to heighten generalization capabilities. This dataset is omitted from empirical performance evaluations.
- **CIC-IDS2017 (PCAP benchmark) [22]:** The IDS2017 dataset provides network traffic in the form of native PCAP files, documenting normal network behavior and common attacks. This data is used to evaluate the model through analysis of traffic labeled by timestamps and source IP addresses. The main scenarios include brute-force attacks, SQLi/XSS, port scans, and DDoS attacks, which are mapped to the problem's 5-class taxonomy.
- **CSE-CIC-IDS2018 (PCAP benchmark):** The IDS2018 dataset, built on AWS cloud computing infrastructure, CSE-CIC-IDS2018 is an expanded, larger-scale version reflecting the complexity of modern enterprise networks. This data is used to verify the model's stability under attack scenarios that vary daily. Traffic is extracted in 1-second timeframes and the PCAP benchmark pipeline is run. This method helps the system simulate real-time response capabilities, ensuring consistency between offline data and the actual deployment environment.

---

## 3.3 Sampling & Data Analysis Techniques

### 3.3.1 Data Sampling Strategy

The data sampling strategy for Reinforcement Learning (PPO) training is designed to combine Stratified Proportioning and Dynamic Generation techniques, ensuring practicality and optimizing performance.

**Stratified Proportioning:** Instead of using the default balanced or 60/40 sampling rate, the training environment is configured for "oversampling" complex attack scenarios. Specifically, data is allocated at a ratio of approximately 37.5% for secure (Benign/Noisy) traffic and 62.5% for attack traffic. Notably, application layer attacks (Layer-7 attacks such as SQLi, XSS, and brute-force) account for up to 50% of the data. This asymmetrical sampling structure forces the agent to continuously process lengthy sequences of behavior, thereby learning how to accurately escalate defenses from the `Redirect` (Honeypot redirection) to `Block` (Blocking) level.

**Dynamic Generation:** The Agent's input architecture is designed based on a combination of network data and internal state context, encompassing a total of 34 characteristic data dimensions. First, the system extracts 20 sensor features which are initialized using **Domain Randomization** techniques based on statistical distributions, enabling the agent to increase its generalization capabilities and adapt to noise variations in the real-world environment. Simultaneously, to ensure consistency in sequential decision-making, 14 contextual features, including 10 historical (temporal) dimensions and 4 effect dimensions, are integrated into the state space.

**Closed-loop feedback loop:** Data is sampled interactively, where the network state at the next step is determined by the Agent's defensive action at the previous step, allowing the model to learn the consequences of the executed decisions.

### 3.3.2 Feature Engineering Overview

Feature engineering in this research is designed as a tiered architecture that bridges the gap between low-level network packets and high-level defensive decisions. The process transforms raw, unstructured bytes into a condensed, 34-dimensional state vector that ensures the Reinforcement Learning agent has a Markovian state representation. This multi-layered approach integrates instantaneous traffic signals, historical context (temporal memory), and closed-loop environmental feedback, allowing the Agent to optimize its long-term defensive strategy.

#### 3.3.2.1 Payload Normalization Pipeline

Attackers habitually obfuscate payloads utilizing URL encoding, HTML entities, or Base64 to bypass rudimentary inspection filters. The payload normalization engine deploys an 8-step sequential pipeline executing prior to pattern matching, perfectly cohesive with Section 4.2.1:

**Size Limitation (64 KB):** Actively neutralizes resource exhaustion attacks stemming from excessively monolithic payloads instigating ReDoS against complex CRS regex engines.
**Bytes $\to$ String Conversion** (UTF-8 with Latin-1 fallback): Ensures uniform byte representation, preventing data loss due to encoding mismatches.
**HTML Entity Decoding:** Standardizes HTML-encoded variants such as `&lt;script&gt;` to their canonical form `<script>`, countering a prevalent XSS evasion technique.
**Unicode NFKC and Smart Quotes Normalization:** Resolves bypass attempts utilizing full-width characters and Unicode homoglyphs embedded within attack keywords.
**Recursive URL Decoding (Max 2 iterations):** Addresses double-encoding schemes (e.g., `%2527` → `%27` → `'`), one of the most common WAF bypass vectors.
**Recursive Base64 Decoding (Max 2 iterations):** Detects attack payloads encapsulated within Base64 strings, a documented evasion tactic in live CRS deployments.
**Whitespace Normalization:** Eliminates whitespace manipulations (tabs, multi-spaces, embedded newlines) designed to fragment pattern matching.
**Lowercase Conversion:** Enforces case-insensitive matching uniformly across the pipeline.
The pipeline is optimized to complete the entire process in a much shorter time than the 1-second MDP observation window; the normalization results are cached by packet identifier to avoid repeated calculations on the same packet.

#### 3.3.2.2 Multi-dimensional Feature Representation (34D)

To provide the Agent with comprehensive situational awareness, the observation space is structured into a 34-dimensional vector, integrating instantaneous traffic signals, historical context, and environmental feedback.

#### A. Traffic & Payload Features (20D: F1–F20)

The 20-feature design stems from the question: "What does the RL agent need to know about the network to make the right defensive decisions?" The agent needs enough information to differentiate five types of attacks from normal traffic, and to distinguish them from each other in order to choose the appropriate action — for example, Blocking is effective with SYN Floods but wasteful with SQLi where Redirecting to a Honeypot allows for threat intelligence gathering.

**Table 3.9: Inventory of 20 Traffic and Payload Features (F1-F20)**

| Code | Feature Name | Concise Description | Scaling | Cap | Detection Target |
|---|---|---|---|---|---|
| F1 | PacketRate | Packet volume per second across the time window | Log | 500 pkt/s | DDoS / SYN Flood |
| F2 | SynAckRatio | Ratio of outbound SYN versus inbound SYN-ACK during TCP handshake | Log | 100 | SYN Flood |
| F3 | InterArrivalTime | Mean duration interspersed between consecutive outbound packets | Log | 5.0 s | Automated attacks or packet floods |
| F4 | RstRatio | Ratio of RST packets relative to aggregate bidirectional packets | Pass-through | — | Port Scan |
| F5 | DistinctPorts | Volume of heterogeneous destination ports within the window | Log | 500 | Port Scan |
| F6 | URLConcentration | Proportion of the predominant URL against total HTTP requests | Pass-through | — | Brute Force / L7 DDoS |
| F7 | HttpIatUniformity | Temporal uniformity interspersing HTTP requests (inverse CV) | Pass-through | — | Automated bot cadence |
| F8 | RequestSizeUniformity | Uniformity defining HTTP payload dimensions (inverse CV) | Pass-through | — | Brute Force |
| F9 | AvgPayloadSize | Mean payload dimensions corresponding to outbound packets | Linear | 1,500 bytes | SYN Flood ($\approx$0) |
| F10 | FwdBwdRatio | Ratio comparing outbound packets against inbound packets | Log | 100 | Traffic asymmetry |
| F11 | PacketsPerPort | Mean packet volume distributed per destination port | Log | 500 | Port Scan density |
| F12 | SqlSpecialChar | Ratio characterizing SQL special characters (`'`, `;`, `#`) within normalized payload | Pass-through | — | SQLi |
| F13 | CrsSqliScore | Aggregate score derived from OWASP CRS 942 PL2 rules per request | Linear | 20 | SQLi (CRS PL2) |
| F14 | SqlUnionSelect | Identifies UNION SELECT syntax designated for data extraction | Binary | — | SQLi — UNION |
| F15 | SqlComment | Identifies SQL comment characters (`--`, `#`, `/**/`) designed to neutralize queries | Binary | — | SQLi — comment |
| F16 | SqlStackedQuery | Identifies stacked SQL command syntax (`; DROP`, `; DELETE`...) | Binary | — | SQLi — stacked |
| F17 | SqlSelectCount | Frequency mapping the SELECT keyword within payload per request | Linear | 10 | SQLi — reconnaissance |
| F18 | CrsXssScore | Aggregate score derived from OWASP CRS 941 PL2 rules (regex + phrase match) | Linear | 4 | XSS (CRS PL2) |
| F19 | JsFunctionCall | Identifies deleterious JavaScript function invocations (`alert()`, `eval()`...) | Binary | — | XSS — JS |
| F20 | HtmlEventHandler | Identifies HTML event handler attributes (`onerror=`, `onload=`...) | Binary | — | XSS — events |

#### B. Temporal Context State (10D: F21–F30)

This group of 10 dimensions implements a short-term memory mechanism based on each agent's IP address. Instead of simply reacting to instantaneous network states, the agent maintains an internal representation that accumulates over each observation cycle, allowing for the identification of escalating behavioral patterns that persist over time and cannot be detected by a single observation window.
The 10 dimensions are divided into four semantic groups: action identification, damage measurement, session escalation monitoring, and budget control.

**Table 3.10: 10 Temporal State Dimensions (F21-F30)**

| Index | Identifier | Formula / Derivation Source | Strategic Function |
|---|---|---|---|
| [20–23] | `last_action_onehot` | Dedicated one-hot encoding targeting the immediate preceding action `last_action \in \{0,1,2,3\}` | Informs the Agent defining whether the IP currently undergoes Allow / Rate Limit / Redirect / Block |
| [24] | `action_hold_norm` | `action_hold_steps / 15`, rigidly clipped at 1.0 | Aggregated consecutive steps preserving a unified action — highly effective detecting stalling actions |
| [25] | `effect_damage_ema` | Dedicated EMA processing `service_damage` sourced from previous steps ($\alpha = 0.3$) | Tracks service damage trends over time while suppressing short-term noise |
| [26] | `effect_trend` | `sigmoid(EMA(damage_t - damage_{t-1}))` | Highlights damage directional movement: >0.5 = intensifying degradation, <0.5 = active recovery |
| [27] | `soft_window_fill_norm` | `len(window_flags) / 15` | Measures saturation levels populating the attack evidence buffer (15-step sliding window configuration) |
| [28] | `escalation_score_norm` | Consolidated evidence score mathematically sourced via `redirect_hits`, `honeypot_hits`, `pressure_mean` | Denotes operational reliability validating an active attack, subsequently guiding the Agent toward escalation timing |
| [29] | `miss_budget_used_norm` | `miss_count / 3` | Totals the frequency an IP successfully "escapes" the Redirect — striking 3 immediately triggers block_ready activation |

These ten dimensions transform the agent from a reflexive classifier (observing traffic → determining action) into a sequential controller with memory (remembering history → accumulating evidence → making strategic decisions). 

#### C. Closed-Loop Effect Feedback (4D: F31–F34)

This 4D group realizes a closed feedback loop between the agent and the network environment. While the 20D sensor group tells the agent what the traffic characteristics are, this 4D group tells the agent whether the defensive action just taken was actually effective. This is the factor that distinguishes sequential feedback control from conventional classification problems.

These 4 dimensions are collected from the access logs of the nginx reverse proxy located on the router, behind the iptables firewall and after the nginx routing process. This is the only location in the system where the actual destination of each request can be observed — the real web server or the honeypot.

Because the information is only available after the proxy has finished processing, this group carries a one-cycle delay: the values ​​fed into the observation vector at cycle t reflect the effect of the action performed at cycle t-1.
The data is aggregated in pairs of source IP addresses and a 1-second time window, ensuring consistency with the time resolution of the entire system.

**Table 3.11: 4 Closed-Loop Feedback Dimensions (F31-F34)**

| Index | Identifier | Significance |
|---|---|---|
| [30] | `webserver_reachability` | Assesses if the production webserver generated responses (1.0 = normal, 0 = severe congestion) |
| [31] | `honeypot_capture_ratio` | Calculates the ratio comparing suspected traffic successfully captured by the honeypot against the gross traffic emanating from the IP |
| [32] | `service_presence` | Determines whether the source IP currently persists transmitting traffic directly toward the webserver |
| [33] | `service_damage` | Analyzes precise, authentic service damage actively measured post-execution from the preceding action step |

Unlike the 20 traffic features (instantaneous measurements) and the 10 temporal state dimensions (local history), these 4 effect state dimensions reflect the direct consequences of the Agent's actions on the network Environment, transforming the RL process into a closed-loop system.

#### 3.3.2.3 Attack Coverage Matrix

Table 3.2 illustrates that every attack category is covered by at least two independent features, ensuring reliable detection even if one feature is affected by noise.

#### 3.3.2.4 Feature Vector Normalization

Following raw value calculation, the 20 features undergo absolute normalization converging into [0,1] firmly anchored to individual feature distributions. (For structural design rationale defining the normalization clusters refer to Chapter 2, Section 2.1.4.5; this segment dissects deployment specifics and exact technical logic.) Three distinctive clusters exist:

**Log scale** (F1, F2, F3, F5, F10, F11): Heavily right-skewed distributions commanding vast scopes — for example, F1 occasionally detonates hitting 350 pkt/s amid DDoS onslaughts yet routinely lingers < 10 under benign conditions. Formula: `f_norm = log(1 + min(f_raw, cap)) / log(1 + cap)`, wherein `cap` functions as the empirically calibrated cutoff ceiling (Table 3.1). The log scale aggressively compresses the extended tail (extreme attack outliers) securely into the [0.8–1.0] spectrum, preemptively dodging vanishing gradients concerning normal operational windows.

**Linear scale** (F9, F13, F17, F18): Exhibiting approximately linear distributions inhabiting constricted operational ranges. Formula: `f_norm = min(f_raw, cap) / cap`. Applied to frequency counting features (CRS scores, SELECT counts) exhibiting empirical data footprints firmly rooted within highly predictable boundaries.

**Pass-through** (F4, F6, F7, F8, F12, F14–F16, F19, F20): Structurally defined natively within the [0,1] bounds (ratios, 1/(1+CV) mathematical functions, or stark binary outputs). Implements a rigid clamp onto [0,1] to mandate absolute mathematical safety neutralizing esoteric marginal calculation errors.

Normalization converging upon [0,1] dictates a draconian technical necessity commanded by the PPO neural network: gradient descent routinely fails to securely converge whenever inputs showcase radically differing magnitude scales (e.g., raw F1 ~100–500 pkt/s opposing F14 binary {0,1}). The `MlpPolicy` integrated within Stable-Baselines3 [26] executes an auxiliary VecNormalize layer deploying running mean/standard deviation computations — performing optimally exclusively when initial inputs are successfully clipped entering finite ranges, shielding VecNormalize from catastrophic skewing induced by massive extreme outliers.

## 3.4 Methodological Limitations

- The Markov assumption should be viewed with caution, as the 34-dimensional observation vector only serves as an approximate statistical measure. If a 1-second window and a 10-dimensional time state are insufficient to represent significant long-term dependencies, the resulting policy may not be optimal.

- The adversary is also a significant source of uncertainty, as the RL training process only reflects the response distribution of known attack patterns. In reality, a sophisticated adversary could alter the attack distribution, for example with zero-day variations, to exploit policy convergence on fixed thresholds.

- The current observational framework is primarily suited to high-speed and high-intensity L7 attacks. For prolonged attack scenarios like slowloris, which can last for minutes or hours, a 1-second sliding window may not be sufficient for detection.

- The Mininet environment offers flexibility for testing, but it remains limited due to its tight control. Therefore, it does not fully simulate the complexity, latency variations, and multi-step operating conditions of a real-world production network.

- The effectiveness of the F12–F20 content feature group heavily depends on the ability to decode TLS via `SSLKEYLOGFILE`. When the payload cannot be observed, the analytical capability at layer 7 is significantly degraded.
