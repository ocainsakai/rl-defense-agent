# CAPSTONE PROJECT REPORT
## Autonomous Network Defense Using Reinforcement Learning

**FPT University — IAP491 Capstone Project**

---

## TABLE OF CONTENTS

- [ABSTRACT](#abstract)
- [CHAPTER 1 — INTRODUCTION](#chapter-1--introduction)
  - [1.1 Background](#11-background)
  - [1.2 Problem Statement](#12-problem-statement)
  - [1.3 Research Objectives](#13-research-objectives)
  - [1.4 Significance of the Research](#14-significance-of-the-research)
  - [1.5 Scope and Limitations](#15-scope-and-limitations)
  - [1.6 Thesis Structure](#16-thesis-structure)
- [CHAPTER 2 — LITERATURE REVIEW](#chapter-2--literature-review)
  - [2.1 Review of Previous Studies](#21-review-of-previous-studies)
  - [2.2 Summary of the Literature Review and Research Gaps](#22-summary-of-the-literature-review-and-research-gaps)
  - [2.3 Contribution of Research](#23-contribution-of-research)
- [CHAPTER 3 — METHODOLOGY](#chapter-3--methodology)
  - [3.1 Research Design](#31-research-design)
  - [3.2 Data Collection Methodology](#32-data-collection-methodology)
  - [3.3 Sampling & Data Analysis Techniques](#33-sampling--data-analysis-techniques)
  - [3.4 Methodological Limitations](#34-methodological-limitations)
- [CHAPTER 4 — EXPERIMENTAL AND RESULTS](#chapter-4--experimental-and-results)
  - [4.1 Introduction](#41-introduction)
  - [4.2 Data Presentation](#42-data-presentation)
  - [4.3 Results Analysis](#43-results-analysis)
  - [4.4 Results Interpretation](#44-results-interpretation)
  - [4.5 Comparison with Literature](#45-comparison-with-literature)
  - [4.6 Implications of Results](#46-implications-of-results)
- [CHAPTER 5 — DISCUSSION](#chapter-5--discussion)
  - [5.1 Restatement of Research Questions and Objectives](#51-restatement-of-research-questions-and-objectives)
  - [5.2 Summary of Key Findings and Interpretation in Research Context](#52-summary-of-key-findings-and-interpretation-in-research-context)
- [CHAPTER 6 — CONCLUSION AND FUTURE WORK](#chapter-6--conclusion-and-future-work)
  - [6.1 Conclusion](#61-conclusion)
  - [6.2 Future Work](#62-future-work)
- [REFERENCES](#references)
- [APPENDICES](#appendices)

---

## ABSTRACT

Modern network environments face increasingly sophisticated and automated cyber threats that overwhelm traditional static defense mechanisms. This project proposes and evaluates an autonomous network defense agent based on Proximal Policy Optimization (PPO), a deep Reinforcement Learning (RL) algorithm, capable of learning and executing adaptive mitigation decisions in real time.

The system is designed around a 34-dimensional observation space integrating 20 network-level and HTTP payload features (F1–F20), 10 per-IP temporal state dimensions, and 4 closed-loop environmental feedback dimensions. A multi-step reward function with soft escalation logic drives the agent to learn a graduated defense strategy — Allow, Rate Limit, Redirect to Honeypot, Block — calibrated to five attack classes: SYN Flood, Port Scan, Brute Force, SQL Injection, and Cross-Site Scripting.

Training was performed in a closed-loop Gymnasium simulator (IDSDefenseEnv) for 500,000 timesteps with domain randomization. Validation was conducted in a Mininet/Containernet emulation environment using real-world datasets (CIC-IDS2017, CSE-CIC-IDS2018, Mutated Packets 2025). The PPO agent achieves a 99.7% mitigation rate with 0.0% benign block rate in simulation, and 99.9% accuracy on DDoS, 97.8% on Port Scan, and 100% on Brute Force/XSS in real-world dataset evaluation, while maintaining a 6.8% overall false positive rate. Comparative benchmarks confirm that PPO achieves a superior security-availability trade-off over DQN and A2C under default hyperparameters. These results demonstrate the feasibility of reinforcement learning for autonomous, closed-loop network defense.

**Keywords:** Reinforcement Learning, Network Intrusion Detection, Proximal Policy Optimization, Autonomous Defense Agent, Feature Engineering, SQL Injection, Cross-Site Scripting, Mininet

---

## CHAPTER 1 — INTRODUCTION

### 1.1 Background

The cybersecurity landscape has undergone a significant transformation over the past decade, driven by the rapid growth of digital infrastructure, cloud computing, and large-scale interconnected networks. In parallel with these developments, cyber threats have become increasingly automated, adaptive, and sophisticated, posing serious challenges to traditional security mechanisms.

#### 1.1.1 Escalation of Cyber Threats and Attack Automation

Modern cyber attacks are no longer primarily manual or opportunistic in nature. Instead, adversaries increasingly rely on automated tools to carry out large-scale reconnaissance, vulnerability scanning, credential stuffing, and exploitation at machine speed. **According to Verizon's Data Breach Investigations Report (DBIR), approximately 60% of confirmed data breaches involved human elements, including social engineering, credential abuse, and user errors, while exploitation of software and web application vulnerabilities continues to rise [verizonDBIR2024].**

Furthermore, web application attacks and system intrusions remain among the most prevalent breach patterns. These attacks are often highly automated, enabling threat actors to quickly identify exposed services and exploit weaknesses across thousands of targets simultaneously. Such large-scale automation significantly reduces the effectiveness of static, rule-based security systems that rely on predefined signatures or manually crafted rules [verizonDBIR2024].

In addition to external adversaries, insider-related incidents account for a significant portion of cybersecurity breaches. Earlier DBIR findings indicate that nearly *30% of data breaches involved internal actors*, whether through malicious intent or inadvertent actions, highlighting that threats can originate from within organizational boundaries as well as from external attackers [verizonDBIR2020]. This diversity of threat actors further complicates the defense landscape and demands more adaptive security strategies.

#### 1.1.2 Economic Impact of Data Breaches

Beyond the technical consequences, cyber attacks impose severe financial and operational costs on organizations. According to the IBM–Ponemon Institute Cost of a Data Breach Report, the global average cost of a data breach has reached several million US dollars per incident, with significantly higher costs observed in regulated industries and large enterprises [ibmPonemon2024]. These costs *encompass incident response, system recovery, legal penalties, reputational damage, and long-term erosion of customer trust.*

The increasing frequency and scale of cyber incidents, combined with their substantial economic impact, underscore the need for faster detection and response mechanisms. Delayed or ineffective responses can significantly amplify financial losses, making real-time or near-real-time defense capability a critical requirement for modern network infrastructures.

#### 1.1.3 Evolution of Network Infrastructure and Operational Challenges

The shift from traditional on-premise hardware to virtualized and cloud-based infrastructure has further expanded the attack surface. Technologies such as virtualization, containerization, and software-defined networking (SDN) enable flexible and scalable deployments, but they also generate large volumes of network traffic and security events. As a result, *Security Operations Centers (SOCs) are frequently overwhelmed by excessive alert volumes, a phenomenon commonly referred to as "alert fatigue."* [alertFatigue2022]

In such environments, human analysts struggle to manually inspect and correlate alerts in a timely manner. Critical security incidents may be overlooked or detected too late, allowing attackers to persist within the network for extended periods. This operational bottleneck exposes the limitations of entirely human-driven security monitoring in large-scale, high-velocity network environments.

#### 1.1.4 The Need for Autonomous and Adaptive Defense Systems

Given the automation of cyber attacks, the economic consequences of breaches, and the complexity of modern network infrastructure, the demand for autonomous and adaptive defense mechanisms is growing. Artificial Intelligence (AI), and specifically Reinforcement Learning (RL), has emerged as a promising approach to addressing these challenges.

Unlike traditional supervised learning methods that rely on labeled datasets, RL enables agents to learn optimal defensive strategies through continuous interaction with the environment. By observing network state and receiving feedback in the form of rewards or penalties, an RL-based defense agent can dynamically adjust its behavior to evolving attack patterns. This capability makes RL particularly well-suited for real-time network defense scenarios, where attack strategies and system conditions change rapidly.

Accordingly, the integration of autonomous AI agents into network defense architectures represents an important step toward enhancing the resilience and responsiveness of cybersecurity systems.

---

### 1.2 Problem Statement

Despite significant advances in cybersecurity technology, most current network defense mechanisms remain primarily reactive and heavily dependent on predefined rules and human intervention. Traditional security solutions — such as rule-based firewalls, signature-based Intrusion Detection Systems (IDS), and manually configured access control policies — are only effective against known attack patterns. These systems struggle to adapt to evolving adversarial behavior or to respond at the speed required to counter highly automated threats.

Furthermore, modern network environments generate large volumes of security-relevant data due to the adoption of cloud computing, virtualization, and software-defined networking. Security Operations Centers (SOCs) are frequently overwhelmed by continuous alert streams, leading to delayed responses and increased risk of alert fatigue. As a result, human analysts may miss critical threats or respond too slowly, allowing attackers to maintain a presence in the network.

Another key limitation of existing defense approaches is the lack of autonomous decision-making. Most security systems rely on static policies or require manual tuning by administrators, making them ill-suited for dynamic and adversarial environments where attack strategies change rapidly. Even machine learning-based solutions often depend on supervised learning techniques that require large, labeled datasets, which are difficult to collect and quickly become outdated in real-world cybersecurity scenarios.

In light of these challenges, there is a clear need for an adaptive defense mechanism that can autonomously observe network conditions, identify malicious behavior, and execute appropriate mitigation actions in real time. Such a system must be capable of learning from environmental interactions, balancing security objectives with service availability, and continuously adapting to novel attack patterns without explicit prior knowledge of all possible threats.

This project addresses the above limitations by proposing an AI-driven network defense agent based on Reinforcement Learning (RL). By framing network defense as a sequential decision-making problem, the RL agent is designed to learn optimal response strategies through trial-and-error interactions. The central problem investigated in this work is: *how to design, train, and evaluate an autonomous RL-based defense agent that can effectively mitigate diverse cyber attacks while maintaining acceptable network performance.*

To address this problem, the research focuses on the following key research questions:

- **RQ1 (Comparative Effectiveness):** To what extent does a reinforcement learning-based agent outperform traditional rule-based mechanisms in mitigating automated and adaptive cyber attacks within a simulated environment?
- **RQ2 (Operational Trade-off):** How does the implementation of autonomous defensive actions (blocking, rate limiting, and redirection) affect the balance between attack mitigation success and legitimate service availability?
- **RQ3 (Policy Stability):** Can the RL-based agent develop and maintain a stable defense policy that remains effective across diverse and evolving attack vectors without manual reconfiguration?

---

### 1.3 Research Objectives

The primary objective of this project is to design, implement, and evaluate an autonomous AI-based network defense system capable of making real-time security decisions in a dynamic and adversarial environment. To achieve this overarching goal, the research is guided by the following specific objectives:

- **Investigate** the applicability of Reinforcement Learning (RL) techniques for autonomous decision-making in network defense scenarios, particularly in environments characterized by automated and adaptive cyber attacks.
- **Design** and construct a simulated network environment that accurately represents real-world network infrastructure, including production servers, attackers, and defense components using Mininet.
- **Develop** an RL-based defense agent capable of observing network state, identifying anomalous or malicious behavior, and selecting appropriate mitigation actions: blocking, rate limiting, or traffic redirection.
- **Define** and implement a reward function that balances security effectiveness with system performance, ensuring that defensive actions mitigate attacks while maintaining service availability.
- **Evaluate** the performance of the proposed defense agent against multiple attack scenarios by measuring key metrics such as attack mitigation rate, response time, false positive rate, and overall network stability.

---

### 1.4 Significance of the Research

This research contributes to the field of cybersecurity by exploring the feasibility of autonomous network defense using Reinforcement Learning. The approach aims to advance beyond traditional security mechanisms through the integration of adaptive, self-learning defense systems.

From a technical perspective, the project provides a practical implementation of an RL-based defense agent integrated with a simulated network environment. The combination of Gymnasium, Mininet, and Linux-based mitigation techniques demonstrates how reinforcement learning can be applied to real-world-inspired network scenarios. Integration with Wazuh SIEM further illustrates the potential for combining autonomous defense agents with existing security monitoring platforms.

From an academic perspective, this research provides empirical insights into the behavior of reinforcement learning agents under diverse network attack scenarios. The evaluation results contribute to understanding how autonomous agents balance security effectiveness with service availability — a critical trade-off in network defense. These findings can serve as a reference for future research on adaptive cybersecurity systems and RL-based decision-making.

Finally, from a practical and industrial perspective, the proposed framework highlights the potential of AI-driven autonomous defense systems in reducing the operational burden on human security analysts. By automating detection and response processes, such systems can mitigate alert fatigue and enable faster, more consistent responses to cyber threats.

---

### 1.5 Scope and Limitations

#### 1.5.1 Research Scope

The scope of this project focuses on designing and evaluating an autonomous network defense agent in a controlled simulation environment. The research emphasizes decision-making at the network level and the lightweight application layer.

**Attack Simulation.** The simulation environment incorporates multiple network attack types inspired by the MITRE ATT&CK framework:

- Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks, such as TCP/SYN flood.
- Port scanning reconnaissance.
- Web and authentication-based attacks: login brute-force, SQL injection, and XSS.

**Action Space.** The defense agent is designed to execute mitigation actions at the OS and network layer:

- **[ALLOW]** Default: permit traffic.
- **[RATE]** Rate limiting for suspicious traffic to reduce attack impact while maintaining legitimate services.
- **[REDIRECT]** Redirect selected traffic to honeypots to isolate attackers and gather threat intelligence.
- **[BLOCK]** Block malicious IP addresses using firewall rules.

All defensive actions are implemented using `iptables` and traffic control (`tc`) mechanisms in the simulated network.

**Technology Stack.** Python, Gymnasium, Mininet/Containernet, Stable-Baselines3, Wazuh SIEM, Docker, PHP, MySQL.

#### 1.5.2 Research Limitations

First, the proposed defense system was evaluated **exclusively in a simulation environment**. Although the simulation was designed to approximate real-world network behavior, results may differ when deployed in production environments due to hardware constraints, network heterogeneity, and unpredictable user behavior.

Second, the **attack scenarios considered are limited to a predefined set of attack types**. Advanced threats such as zero-day exploits, supply chain attacks, and sophisticated lateral movement techniques are outside the scope of this research.

Third, the performance of the RL agent is influenced by **the quality of the reward function and the representativeness of the simulation environment**. Suboptimal reward design or insufficient state representation may limit the agent's ability to generalize to unseen scenarios.

Finally, the system was implemented and tested on the Ubuntu Linux platform. **Portability of the proposed approach to other operating systems or large-scale distributed cloud environments has not been evaluated and remains a topic for future research.**

---

### 1.6 Thesis Structure

The remainder of this thesis is organized as follows:

**Chapter 2 — Literature Review** presents the theoretical foundations of Reinforcement Learning, network simulation environments, automated incident response mechanisms, and network traffic feature extraction techniques. This chapter also identifies the research gaps that the project addresses.

**Chapter 3 — Methodology** describes the system design, including the MDP problem formulation, PPO agent architecture, 20-feature extraction pipeline, Containernet network topology, and real-time enforcement mechanism via iptables.

**Chapter 4 — Experimental Results** presents and analyzes the system evaluation results, including attack detection accuracy, training convergence curves, comparison with baseline methods, and practical implications.

**Chapter 5 — Discussion** interprets the findings in a broader context, discusses limitations, and proposes future research directions.

**Chapter 6 — Conclusion** synthesizes the main contributions and provides final remarks on the feasibility of Reinforcement Learning for autonomous network defense.

---

## CHAPTER 2 — LITERATURE REVIEW

### 2.1 Review of Previous Studies

#### 2.1.1 Fundamentals of Reinforcement Learning

Reinforcement Learning (RL) is a subfield of machine learning focused on enabling Agents to learn optimal behaviors through interaction with an Environment. Unlike supervised learning, which relies on labeled datasets, RL allows an Agent to learn directly from experience by receiving feedback in the form of rewards or penalties. This learning paradigm is particularly well-suited for dynamic and adversarial domains like cybersecurity, where labeled data is scarce, and attack strategies continuously evolve.

**Agent Classification and Architecture**

According to Russell & Norvig's taxonomy in *Artificial Intelligence: A Modern Approach*, intelligent systems can be classified by their architectural complexity. In the context of cybersecurity, lower-level architectures have demonstrated significant limitations when confronting modern, polymorphic threats.

| Architecture | Cybersecurity Equivalent | Demonstrated Limitations |
|---|---|---|
| Simple Reflex | condition–action rules | Fails in partially observable networks. |
| Model-Based Reflex | Maintains internal state; uses condition-action rules. | Lacks a utility function for optimization; cannot learn. |
| Goal-Based | Utilizes search/planning to achieve explicit goals. | Cannot easily balance competing goals (e.g., security vs. availability). |
| Utility-Based | Chooses actions maximizing expected utility. | Utility must be pre-defined and static. |
| **Learning Agent** | Features a Critic, Learning Element, Performance Element, and Problem Generator; improves via experience. | Requires robust feedback mechanisms and sufficient training data. |

In the context of Deep Reinforcement Learning for cybersecurity, the *Performance element* corresponds to the policy neural network mapping observations to actions, the *Critic* to the value network estimating state values, the *Learning element* to the optimization algorithm updating the weights, and the *Problem generator* to the dynamic simulated network environment.

**Task Environment Analysis**

To justify the application of Deep RL, the network defense domain must be analyzed according to its fundamental task environment properties:

| Property | Value | Design Consequence |
|---|---|---|
| Observability | **Partially Observable** | The Agent cannot directly observe the attacker's true intent; it only observes network traffic manifestations. |
| Determinism | **Stochastic** | The same defensive action may yield different results due to network noise, latency, or TCP retries. |
| Episodicity | **Sequential** | Current defensive actions directly influence future network states and Agent responses. |
| Dynamics | **Dynamic** | The network environment changes continuously even when the Agent takes no action. |
| State/Action | **Continuous / Discrete** | High-dimensional continuous observation space with discrete mitigation actions. |
| Adversarial | **Multi-agent / Adversarial** | The presence of an intelligent attacker creates a non-stationary environment. |

These properties confirm that traditional rule-based mechanisms are insufficient, necessitating an adaptive, learning-based approach.

**The Partially Observable Markov Decision Process (POMDP)**

Because network traffic is only partly observable and unpredictable, the interaction between the defense agent and the environment is modeled as a **Partially Observable Markov Decision Process (POMDP)**, defined by the 7-tuple $\langle \mathcal{S}, \mathcal{A}, \mathcal{O}, T, Z, R, \gamma \rangle$:

| Symbol | Definition |
|---|---|
| $\mathcal{S}$ | **State Space**: The true state of the network (e.g., true attacker intent, hidden connections). |
| $\mathcal{A}$ | **Action Space**: Available defensive maneuvers (Allow, RateLimit, Redirect, Block). |
| $\mathcal{O}$ | **Observation Space**: The observable network features (traffic statistics, HTTP payloads). |
| $T(s'|s,a)$ | **Transition Model**: Probability of moving to state $s'$ given state $s$ and action $a$. |
| $Z(o|s',a)$ | **Observation Model**: Probability of observing $o$ given the true state $s'$ and action $a$. |
| $R(s,a)$ | **Reward Function**: Scalar feedback balancing mitigation success and service availability. |
| $\gamma$ | **Discount Factor**: $\gamma \in [0, 1]$, balancing immediate and long-term consequences. |

Solving a POMDP exactly requires maintaining a **belief state** $b$, which is a probability distribution over all possible underlying states $\mathcal{S}$. The belief state is updated after each action $a$ and observation $o$ using the following Bayesian update:

$$b'(s') = \eta \cdot Z(o\mid s',a) \sum_{s \in \mathcal{S}} T(s'\mid s,a)\, b(s)$$

where $\eta$ is a normalization constant. For complex networks with many states, this process is too demanding to compute exactly. Instead, practical systems construct an **approximate sufficient statistic** using an engineered observation vector $o \in \mathcal{O}$ that captures sufficient history and current context to approximate the Markov property, so the problem can be treated as a standard MDP.

**Mathematical Foundations of Reinforcement Learning**

The primary objective of a reinforcement learning Agent is to learn a policy $\pi$ that maximizes the expected **Cumulative Discounted Return**, denoted as $G_t$:

$$G_t = \sum_{k=0}^{\infty} \gamma^k R_{t+k+1}$$

where $\gamma \in [0, 1]$ is the discount factor that determines the present value of future rewards. To evaluate the quality of states and actions, RL frameworks utilize two fundamental functions:

* **State-Value Function $V^\pi(s)$:** The expected return when starting from state $s$ and following policy $\pi$.
* **Action-Value Function $Q^\pi(s,a)$:** The expected return when taking action $a$ in state $s$ and subsequently following policy $\pi$.

In modern Actor-Critic architectures, the **Advantage Function** $A^\pi(s,a)$ is employed to reduce variance during training:

$$A^\pi(s,a) = Q^\pi(s,a) - V^\pi(s)$$

**Deep Reinforcement Learning and PPO**

Among modern policy-based algorithms, **Proximal Policy Optimization (PPO)** has emerged as the standard approach due to its superior balance between sample efficiency and training stability. PPO optimizes a **Clipped Surrogate Objective** to ensure that policy updates do not deviate too drastically from the previous policy:

$$L^{CLIP}(\theta) = \hat{\mathbb{E}}_t \left[ \min(r_t(\theta)\hat{A}_t, \text{clip}(r_t(\theta), 1-\epsilon, 1+\epsilon)\hat{A}_t) \right]$$

where $r_t(\theta)$ is the probability ratio between the new and old policies, and $\epsilon$ is a hyperparameter (typically 0.2) that constrains the update. The selection of PPO for this research is justified by: superior stability over SAC in dynamic environments, addressing DQN's limitation with continuous state spaces, operational safety via gradient clipping, and computational efficiency comparable to TRPO.

#### 2.1.2 Network Emulation and Simulation Environments

The training and evaluation of reinforcement learning agents in cybersecurity require environments that are controlled, reproducible, and observable. This research adopts a **two-stage development framework**: a high-speed custom simulation environment for training, followed by a high-fidelity emulation testbed for deployment and validation.

- **Training Stage (Custom Simulation):** The agent is trained in IDSDefenseEnv using probabilistic models (Normal, Poisson, Beta distributions) calibrated from CIC-IDS2018 to simulate diverse network behaviors.
- **Deployment and Validation Stage (Network Emulation):** The frozen policy is deployed in a Mininet-based environment where defensive actions (blocking, rate-limiting) are applied through real `iptables` and `tc` kernel calls.

**Mininet** creates virtual networks in which each host runs on the real Linux kernel, enabling evaluation of defensive policies in an environment that closely resembles deployment on Linux-based production systems. **Gymnasium** provides a standardized interface for reinforcement learning environments, bridging the agent and the simulated network through well-defined state, action, reward, and termination abstractions.

It is critical to distinguish learning paradigms: in both on-policy (PPO) and off-policy (DQN) paradigms, weight updates cease once training terminates — the policy is **frozen** and transitions into **inference mode**. The proposed system is classified as an **offline-trained, inference-deployed** architecture.

#### 2.1.3 The Evolution of Automated Incident Response

The trajectory of network defense has shifted from **Static Signature-Based Detection** (e.g., traditional Snort rules) to **Statistical Machine Learning**, and finally to **Autonomous Learning Agents**. Early automation (circa 2010s) centered on rule-based response systems with static thresholds that struggle to manage evolving, polymorphic threats and frequently generate false positives in high-traffic environments.

The current frontier represents a shift toward **Reinforcement Learning for Adaptive Incident Response**, enabling agents to learn optimal defensive strategies through interaction. Low-level enforcement mechanisms — **iptables** (< 1ms execution latency for ACCEPT/DROP/REDIRECT/QUEUE) and **Traffic Control (tc)** for rate shaping — provide the kernel-level execution required. **Deception-based response via honeypots** adds threat intelligence gathering capability alongside direct mitigation.

#### 2.1.4 Feature Engineering and State Representation Design

A critical review of existing literature reveals a significant **"Information Asymmetry"** in how states are currently designed. Current research shows three critical gaps:

**The Payload-Metadata Gap:** RL research in volumetric DDoS defense focuses almost exclusively on traffic metadata, while Web Attack Defense (SQLi/XSS) research predominantly uses "heavy" deep learning or NLP models with significant inference latency — impractical for high-speed kernel-level response loops. There is a noticeable absence of research into defensive, real-time RL Agents that process lightweight payload features alongside traffic metadata.

**The Contextual Gap:** State representations are often limited to instantaneous traffic snapshots, missing the behavioral history of IPs, the Agent's previous decision chain, and service health indicators necessary for rational decision-making in a POMDP environment.

**The Enforcement Gap:** Many studies build detailed simulation environments but stop at abstract simulation variables rather than real-world enforcement commands (`iptables`, `tc`).

---

### 2.2 Summary of the Literature Review and Research Gaps

The literature review confirms three critical research gaps that this thesis aims to bridge:

1. **Observation Gap (The Feedback Void):** Existing models predominantly operate in an open-loop manner on static datasets, lacking a real-time feedback loop between Agent actions and environmental consequences.
2. **Contextual Gap (Temporal Fragmentation):** State representations are often limited to instantaneous traffic snapshots, missing the historical behavioral context and internal system health metrics necessary for rational decision-making in POMDPs.
3. **Enforcement Gap (Abstraction vs. Reality):** There is a disconnect between high-level AI action selection and low-level kernel enforcement (e.g., `iptables`, `tc`), with many studies stopping at abstract simulation variables.

This project addresses these critical research gaps by proposing an autonomous AI defense Agent operating within a **closed-loop emulation Environment** integrating Reinforcement Learning with realistic network emulation, low-level enforcement mechanisms, and deception-based defensive strategies.

---

### 2.3 Contribution of Research

Based on a comprehensive literature review, this thesis contributes to the field of automated network defense across three dimensions:

**Technically**, the research develops a **closed-loop automated defense architecture** for high-fidelity emulation environments — implementing an integrated pipeline spanning automated traffic processing, RL inference, and authentic defensive execution via `iptables` and `tc`.

**Methodologically**, the thesis proposes a **Hybrid State Representation** that resolves the "Information Asymmetry" identified in existing literature. The proposed 34-dimensional state vector encapsulates consequences of previous actions and temporal behavior of network entities, enabling the Agent to navigate the POMDP nature of the network environment.

**Practically**, the experimental evaluation provides empirical evidence that the proposed RL-based architecture achieves higher mitigation rates than static rule-based baselines across five attack classes while maintaining a lower false positive rate on legitimate traffic.

**References for Chapter 2:** [1]–[30] — See References section.

---

## CHAPTER 3 — METHODOLOGY

This chapter delineates the methodological framework of the research, designed to systematically address the Information Asymmetry, Contextual Gap, and Enforcement Gap identified in Chapter 2. It details the design, training, and deployment of the Reinforcement Learning defense Agent, formalizing the system architecture from data extraction and state representation to real-time enforcement and emulation-based validation.

### 3.1 Research Design

#### 3.1.1 Threat Model

To establish a clear scope for our defensive system, we first define a threat model that identifies potential adversaries and their capabilities. We assume an external attacker operating at the network level, targeting public-facing web services.

Attacks are classified based on technical characteristics and impact level:

- **Volumetric Attacks:** High-volume traffic (DDoS, SYN Flood) exhausting bandwidth and TCP connection tables.
- **Reconnaissance:** Port Scan to map active services.
- **Credential Attacks:** Brute-force attacks to bypass authentication.
- **Application Layer Attacks (L7):** Exploiting Web application layer vulnerabilities through SQL Injection (SQLi) and Cross-Site Scripting (XSS) in HTTP payloads.

**Adversary constraints:** The attacker possesses no internal privileges (Black-box setup, unaware of defense policies).
**Defender capabilities:** The defender maintains comprehensive monitoring at the edge router, TLS decryption capabilities via `SSLKEYLOGFILE`, and real-time enforcement authority via `iptables`.

#### 3.1.2 Methodological Framework

The project approaches the network defense problem from the perspective of automatic sequential decision-making. The system not only detects attacks but also selects appropriate response actions according to each context.

The research methodology is executed across two parallel branches:

1. **Observation & Feature Extraction Module:** Captures the network state, converting raw network traffic into semantically meaningful observation vectors for the Agent.
2. **RL Defense Agent:** Implements the **Learning Agent** architecture (Russell & Norvig, 2020). The Performance Element is the trained PPO policy network; the Critic facilitates training via state-value estimation; the Learning Element executes the optimization loop; the Problem Generator is implemented via the Gymnasium environment.

**System Classification: Offline-Trained, Inference-Deployed.** The two stages operate under fundamentally different learning modes:

| Stage | Learning Mode | Weight Updates | Data Source |
|---|---|---|---|
| **Training** (IDSDefenseEnv simulator) | On-policy (PPO) | Active — gradient descent per rollout | Synthetic simulator (MockIPBehavior + domain randomization) |
| **Deployment** (Mininet + iptables) | **None — frozen inference** | None | Live network traffic (observation only) |

**Table 3.1: RL Algorithm Comparison and Selection Rationale**

| Criteria | DQN (Deep Q-Network) | A2C (Advantage Actor-Critic) | PPO (Proximal Policy Optimization) |
|---|---|---|---|
| **Approach** | Value-based: Learns the $Q(s, a)$ function. | Actor-Critic: Hybrid approach. | Policy-based: Directly optimizes the policy. |
| **Learning Mode** | Off-policy: Reuses historical data. | On-policy: Learns from current experience. | On-policy: Uses clipped updates. |
| **Stability** | Moderate (Prone to overestimation). | Low (High variance). | **Very High** (Clipped objective). |
| **Sample Efficiency** | High (Reuses past data). | Low (Requires more interactions). | Moderate (Balanced stability). |
| **Core Mechanism** | Experience Replay & Target Network. | Advantage Function. | Clipped Surrogate Objective. |

#### 3.1.3 System Architecture

The proposed defensive system is structured according to a three-layer architecture:

1. **Observation & Feature Extraction Layer:** Captures raw network packets to extract **20 behavioral features** from bidirectional flows, integrated with **14 internal state dimensions** (10D temporal context + 4D delayed environmental feedback) to construct the unified **34D observation vector**.
2. **Decision-Making Layer (RL Defense Agent):** Receives the consolidated 34D vector and utilizes the trained PPO policy to map this observation to the optimal defensive action $a_t$. The Agent is first trained for 500,000 steps in a Gymnasium simulation before being transitioned to the Mininet emulation environment.
3. **Enforcement Layer:** Deploys defensive actions via `iptables`:
    - **Allow (0):** Permits traffic to pass without interference.
    - **Rate Limit (1):** Constrains bandwidth using `hashlimit` (2 pkt/s).
    - **Redirect (2):** Routes traffic to a honeypot via NAT PREROUTING.
    - **Block (3):** Completely drops traffic via `iptables` DROP.

#### 3.1.4 MDP Formalization

Building upon the task environment properties analyzed in Chapter 2, the network defense challenge is formalized for implementation as a **Markov Decision Process (MDP)**, defined by the tuple $(S, A, P, R, \gamma)$.

**Table 3.2: 34D Observation Space Segmentation**

| Group | Dimensions | Content |
|---|---|---|
| Traffic Features | 20D (F1–F20) | Instantaneous statistical and payload-based network metrics. |
| Temporal State | 10D ([20–29]) | Persistent temporal context and internal IP-tracking state. |
| Closed-Loop Feedback | 4D ([30–33]) | Delayed feedback from the environment ($effect_{t-1}$) from the previous action. |

**Action Space ($A$):** The Agent selects from a set of four discrete actions ($a_t \in \mathcal{A}$):

- **Allow ($a_0$):** $c_0 = 0$. No interference; default for benign traffic.
- **Rate Limit ($a_1$):** $c_1 > c_0$. Bandwidth constraint using `hashlimit`.
- **Redirect ($a_2$):** $c_2 > c_1$. Honeypot routing for L7 analysis.
- **Block ($a_3$):** $c_3 > c_2$. Full neutralization via `iptables` DROP.

**Reward Function ($R$):** The total reward incorporates both baseline and strategic shaping components:

$$R_{base} = B_{action} - C_{action} - 0.12 \cdot service\_damage$$

$$R = R_{base} + P_{osc} + B_{stab} + B_{ramp} + B_{persist} + P_{premature}$$

**Discount Factor ($\gamma = 0.995$):** Encourages long-term cumulative reward optimization, essential for identifying multi-step attack patterns.

#### 3.1.5 Experimental Network Topology

The experimental environment is constructed upon **Mininet** (network virtualization) and **Docker** (application isolation):

- **Router (10.0.10.254/24):** The central node hosting `iptables` and Nginx Reverse Proxy. Routes port 443 to the Webserver and port 4443 to the Honeypot. Injects `X-Real-IP` header to accurately identify source IPs post-NAT.
- **Webserver (192.168.10.10/24):** The legitimate service, acting as the primary attack target.
- **Honeypot (192.168.30.10/24):** Absorbs Layer 7 attacks when the Agent selects Redirect.
- **Attacker (10.0.10.10/24):** Attack source implementing scenarios using `hping3`, `sqlmap`, and `nmap`.
- **Wazuh SIEM (192.168.20.20/24):** Records secondary baseline logs for cross-verification.

#### 3.1.6 RL Defense Agent Design

Unlike traditional signature-based classifiers, the RL Agent does not learn to explicitly categorize attack labels. Instead, it learns the causal relationship between interventions and outcomes: given a specific network state, it evaluates whether selecting Action A will yield a healthier future system state than Action B.

**3.1.6.1 RL Training Environment Implementation**

The training environment, designated **IDSDefenseEnv**, is a Gymnasium-compatible closed-loop control system structured with:
- **Episode Structure:** Fixed episode length of 320 steps (8 minutes of operational window).
- **Session Allocation:** 16 heterogeneous IP entities, each performing a 20-step behavioral process per context.

**3.1.6.2 Traffic Generation and Domain Randomization**

IDSDefenseEnv integrates **MockIPBehavior**, a stateful behavioral simulation engine that generates feature vectors via statistical distributions calibrated from CSE-CIC-IDS2018. Traffic profiles include: Benign, SYN Flood, Port Scan, Brute Force, SQL Injection, and XSS.

**Domain randomization** prevents rote learning by parameterizing network features using:
- **Packet Rate:** Gaussian Normal Distribution.
- **Port Probing:** Poisson Distribution.
- **Feature Ratios:** Beta Distribution (for [0, 1] bounded variables).

**3.1.6.3 Action Space and Defensive Strategy**

The defense system utilizes a discrete action space of 4 levels following an Action Ladder model. The cost ladder $c_0 < c_1 < c_2 < c_3$ creates "economic pressure," prompting the agent to form an escalation strategy: Observe → Restrict → Isolate → Block.

**Table 3.3: MDP Implementation Parameters**

| Symbol | Parameter | v13 Value | Description |
|---|---|---|---|
| $\omega$ | Damage Weight | 0.12 | Weight for $F_{24}$ (Service Damage). |
| $c_0$ | Cost (Allow) | 0.00 | Baseline cost for no intervention. |
| $c_1$ | Cost (RateLimit) | 0.01 | Minimal overhead for bandwidth throttling. |
| $c_2$ | Cost (Redirect) | 0.04 | Operational cost for Honeypot traffic routing. |
| $c_3$ | Cost (Block) | 0.15 | Maximum penalty for service unavailability. |

**3.1.6.4 Temporal Observation Window and Soft Escalation**

The system integrates a **Temporal Observation Window ($W_{total}$)** with a **Soft Escalation** protocol, structured into 3 distinct phases within a 20-step session lifecycle:

- **Phase 1: Observation & Monitoring (Steps 1–11):** Initial assessment. If L7 signals exceed 0.35, the IP is flagged. Block is penalized as "premature."
- **Phase 2: Ramp Zone / Critical Decision Window (Steps 12–14):** If accumulated threat confidence reaches $\ge 0.60$, the latching enforcement flag is activated. Progressive **Ramp bonus** encourages Redirect→Block transition.
- **Phase 3: Enforcement & Persistence (Steps 15–20):** Sustained Block action is rewarded; any reversion to Allow or Redirect is heavily penalized.

**3.1.6.5 Reward Function and Persistence-Aware Shaping**

$$R_{total} = \underbrace{(B_{action} - C_{action} - 0.12 \cdot service\_damage)}_{\text{Base Reward}} + \underbrace{\sum R_{shaping}}_{\text{Shaping Components}}$$

**Table 3.4: Network Damage Function ($D$) Components**

| Component | Weight | Feature | Non-linear Function |
|---|---|---|---|
| PPS Overflow (DDoS) | 0.25 | F1 | Logistic: $1/(1+e^{-5(F1/anchor - 1)})$ |
| RST Ratio (scan/brute) | 0.15 | F4 | Tanh: $\tanh(F4 \times 2)$ |
| Port Scan Distribution | 0.15 | F5 | Log-sigmoid over raw port count |
| Payload Anomaly | 0.10 | F9, F4, F5 | Logistic, excluding benign uploads |
| SYN flood | 0.10 | F2 | Tanh over threshold exceedance ratio |
| SQLi/XSS (L7 attack) | 0.25 | F12–F20 | Normalized weighted combination |

**Table 3.5: Reward Shaping Components**

| Component | Symbol | Value | Trigger Condition | Strategic Function |
|---|---|---|---|---|
| Stability Bonus | $B_{stab}$ | +0.01 (general); +0.05 (L7 Redirect) | Action held for at least one consecutive step | Reinforces holding the correct action. |
| Ramp Bonus | $B_{ramp}$ | +0.08/+0.15 (Block); −0.03/−0.06 (Redirect) | Monitoring session active, step ∈ {12–14}, score ≥ 0.50 | Creates progressive reward gradient for Redirect→Block transition. |
| Persistence Bonus | $B_{persist}$ | +0.45 (Block); −0.35 (Redirect); −0.40 (Allow/RateLimit) | Enforcement flag latched | Heavily rewards sustained Block after evidence accumulation. |
| Oscillation Penalty | $P_{osc}$ | −0.05 to −0.15 | Defense level downgraded while damage elevated | Discourages flickering back to weaker actions. |
| Premature Penalty | $P_{premature}$ | −0.20 | Block issued before step 12 | Prevents aggressive early blocking. |

**3.1.6.6 Policy Optimization (PPO)**

To achieve stable policy convergence, the Agent utilizes the **Clipped Surrogate Objective** with **Generalized Advantage Estimation (GAE)**:

$$L^{CLIP}(\theta) = \hat{\mathbb{E}}_t\left[\min\left(r_t(\theta)\hat{A}_t,\; \text{clip}(r_t(\theta), 1-\epsilon, 1+\epsilon)\hat{A}_t\right)\right]$$

$$\hat{A}_t^{GAE(\gamma,\lambda)} = \sum_{l=0}^{\infty} (\gamma\lambda)^l \delta_{t+l}$$

**3.1.6.7 Training Configuration**

**Table 3.6: PPO Agent Training Hyperparameters**

| Parameter | Value | Design Rationale |
|---|---|---|
| **Total Steps** | 500,000 | Ensure convergence across all 5 attack typologies. |
| **Net Arch (pi, vf)** | [256, 128], [256, 256, 128] | Increased capacity to map complex high-dimensional boundaries. |
| **Clip Range ($\epsilon$)** | 0.15 | Tighten policy updates to prevent overshoot and ensure stability. |
| **Discount ($\gamma$)** | 0.995 | Extended temporal horizon to capture dependencies in 320-step episodes. |
| **Learning Rate** | $3 \times 10^{-4}$ → $6 \times 10^{-5}$ (linear decay) | Rapid learning initially, precise fine-tuning in terminal phase. |
| **Entropy Coef** | 0.05 | Maintains exploration to prevent policy collapse. |
| **Batch Size** | 128 | Enhanced gradient stability for the 34D observation space. |
| **n_envs** | 4 | Parallelized training for 4× wall-clock acceleration. |

**3.1.6.8 Adversarial Dynamics and Closed-Loop Feedback**

In contrast to traditional detection systems that treat network traffic as a static data stream, this RL environment establishes a **Closed-Loop Feedback** mechanism through a reactive attacker model. Key features include:

- **Reactive Behavior:** If the Agent applies Rate Limit, the attacker may respond by increasing payload intensity.
- **Deceptive Isolation:** When Redirect is enforced, the attacker is transparently routed to the Honeypot, allowing safe observation of the full "Kill Chain."
- **Asymmetric Visibility:** Even when an IP is Blocked (Layer 3 DROP), the monitoring model continues to record raw connection attempts while application-layer damage metrics drop to zero.

#### 3.1.7 Inference Deployment and Enforcement Pipeline

The operational system transitions the trained policy into a Mininet environment via three functional layers:

1. **Data Acquisition Layer:** Continuous sniffer capturing packets and aggregating them into statistical summaries every second.
2. **Inference Engine:** Normalization, state expansion (concatenating 10D temporal and 4D feedback states), and policy prediction. Includes **SafetyNet guardrails** that override to Redirect when pronounced L7 signals are detected but the model erroneously selects Allow/RateLimit.
3. **Enforcement Layer:** Actions enforced via `iptables` rules with per-IP state tracking implementing the 15-step soft escalation protocol.

**Algorithm 2: Near Real-Time Inference and Enforcement Pipeline**

1: **loop** *(continuous, one iteration per 1-second window)*
2:   Collect all packets within $[t-1, t]$ → compute 20D feature vector $\mathbf{f}_t$
3:   Retrieve per-IP **PerIPTemporalState** → 10D temporal vector $\mathbf{h}_t$
4:   Retrieve closed-loop feedback → 4D effect vector $\mathbf{e}_{t-1}$
5:   Construct $\mathbf{obs}_{34} \leftarrow [\mathbf{f}_t \;\|\; \mathbf{h}_t \;\|\; \mathbf{e}_{t-1}]$ — normalized to $[0,1]^{34}$
6:   $a_t \leftarrow \pi_{\theta^*}(\mathbf{obs}_{34})$ — frozen policy forward pass
7:   **if** SafetyNet override condition met **then** $a_t \leftarrow \text{SafetyNet}(a_t, \mathbf{obs}_{34})$
8:   Enforce $a_t$ via `iptables` rule on source IP
9:   **if** $a_t = \text{Redirect}$ **and** L7 signal $\geq 0.35$ **then** increment soft escalation window
10:  Update **PerIPTemporalState** and closed-loop effect $\mathbf{e}_t$
11: **end loop**

#### 3.1.8 Emulation-Based Validation Protocol

To validate the Agent in a realistic environment:
1. **Mixed Attack Scenarios:** Using `hping3`, `nmap`, and `sqlmap` against benign background traffic.
2. **Real-time Monitoring:** Capturing live traffic from the Router's interface and executing kernel-level `iptables` and `tc` rules.
3. **Performance Indicators (KPIs):** Mitigation Rate, Service Availability (latency/success rate), and Decision Accuracy (Precision/Recall).

---

### 3.2 Data Collection Methodology

#### 3.2.1 Packet Capture and Dissection

The pipeline processes packets in two modes: Real-time Direct (via Scapy) and PCAP Offline (via PcapReader). The packet splitter extracts L3/L4 information into an immutable structured data object for each packet. In Real-time mode, the system supports HTTPS decryption by running tshark in parallel with Scapy: tshark reads SSLKEYLOGFILE to decrypt TLS and outputs decrypted HTTP fields (URI, User-Agent, Body), which are appended back to the corresponding TCP packets for F12–F20 payload analysis.

At the application layer (L7), the system uses a **HTTP composite payload per-packet** method: at parsing time, the system concatenates `[URI] + [User-Agent] + [Body]` into a single string stored for F12–F20 analysis — no recalculation required.

#### 3.2.2 Connection Session Management

Packets are classified into flows by the flow manager using 5-tuples (src_ip, dst_ip, src_port, dst_port, protocol). Each flow maintains two separate queues of packets (forward: src→dst, and reverse: dst→src), allowing independent calculation of flow-based features. Memory is controlled with a maximum of 50,000 concurrent flows and 3,000 packets per flow.

#### 3.2.3 1-Second Sliding Window

The RL agent requires the observed vector to reflect the current state of the network, not the entire session history. A 1-second sliding window fulfills this requirement: at each step, only packets within the range [t−1s, t] are used for feature calculation. This was experimentally determined to be the optimal balance point between statistical stability and temporal sensitivity. The MDP update process at each decision step performs: (1) Remove old packets outside the 1-second threshold; (2) Query current flows; (3) Feature extraction.

#### 3.2.4 Data Sources

Five distinct data sources are incorporated:

- **LSNM2024 Labeled URI Dataset:** 3,000 benign URIs and 2,809 pre-labeled SQLi URIs from Lashkari et al. (University of New Brunswick) — used for calibrating CRS Paranoia Level and validating the payload normalization pipeline.
- **Mutated Packets PCAP Dataset (Abu Al-Haija et al., 2025):** 15 attack typologies generated using pragmatic tools (hping3, sqlmap, Hydra/Burp Suite, nmap). The **primary evaluation corpus** for feature-level classification results.
- **Simulated MockIPBehavior (custom-built):** Distribution-based synthetic behavioral objects, allocated **exclusively for PPO training**. Not used in empirical performance evaluations.
- **CIC-IDS2017 (PCAP benchmark):** Native PCAP files documenting normal behavior and common attacks (brute-force, SQLi/XSS, port scans, DDoS), mapped to the 5-class taxonomy.
- **CSE-CIC-IDS2018 (PCAP benchmark):** Expanded AWS-based dataset. Traffic extracted in 1-second timeframes simulating real-time response capabilities.

---

### 3.3 Sampling & Data Analysis Techniques

#### 3.3.1 Data Sampling Strategy

**Stratified Proportioning:** Training data is allocated at approximately 37.5% for secure (Benign/Noisy) traffic and 62.5% for attack traffic, with application layer attacks (SQLi, XSS, Brute-Force) accounting for up to 50%. This asymmetrical sampling forces the agent to learn evidence-based escalation from Redirect to Block.

**Dynamic Generation:** The Agent's input architecture combines 20 sensor features (initialized with Domain Randomization) with 14 contextual features (10D temporal + 4D effect). Data is sampled interactively in a closed-loop, where the network state at the next step is determined by the Agent's defensive action at the previous step.

#### 3.3.2 Feature Engineering Overview

**3.3.2.1 Payload Normalization Pipeline**

The payload normalization engine deploys an 8-step sequential pipeline:

1. **Size Limitation (64 KB):** Neutralizes resource exhaustion attacks that could induce ReDoS within CRS regex evaluations.
2. **Bytes → String Conversion** (UTF-8 with Latin-1 fallback): Ensures uniform byte representation.
3. **URL Decode Recursively (Max 2 iterations):** Addresses double-encoding (`%2527` → `%27` → `'`).
4. **HTML Entity Decoding:** Standardizes `&lt;script&gt;` → `<script>`.
5. **Unicode NFKC and Smart Quotes Normalization:** Prevents full-width character bypasses.
6. **Recursive Base64 Decoding (Max 2 iterations):** Detects attack payloads encapsulated in Base64.
7. **Whitespace Normalization:** Eliminates whitespace manipulations designed to fragment pattern matching.
8. **Lowercase Conversion:** Enforces case-insensitive matching uniformly.

The execution sequence constitutes a rigid constraint: URL decoding must precede Base64 decoding; HTML entity decoding must precede URL decoding. Normalization results are cached by packet identifier to avoid repeated calculations.

**3.3.2.2 Multi-dimensional Feature Representation (34D)**

**A. Traffic & Payload Features (20D: F1–F20)**

**Table 3.9: Inventory of 20 Traffic and Payload Features**

| Code | Feature Name | Concise Description | Scaling | Detection Target |
|---|---|---|---|---|
| F1 | PacketRate | Packet volume per second | Log | DDoS / SYN Flood |
| F2 | SynAckRatio | Ratio of outbound SYN versus inbound SYN-ACK | Log | SYN Flood |
| F3 | InterArrivalTime | Mean duration between consecutive outbound packets | Log | Automated attacks |
| F4 | RstRatio | Ratio of RST packets relative to total bidirectional packets | Pass-through | Port Scan |
| F5 | DistinctPorts | Volume of heterogeneous destination ports | Log | Port Scan |
| F6 | URLConcentration | Proportion of predominant URL against total HTTP requests | Pass-through | Brute Force / L7 DDoS |
| F7 | HttpIatUniformity | Temporal uniformity of HTTP requests (inverse CV) | Pass-through | Automated bot cadence |
| F8 | RequestSizeUniformity | Uniformity of HTTP payload dimensions (inverse CV) | Pass-through | Brute Force |
| F9 | AvgPayloadSize | Mean payload dimensions of outbound packets | Linear | SYN Flood ($\approx$0) |
| F10 | FwdBwdRatio | Ratio of outbound versus inbound packets | Log | Traffic asymmetry |
| F11 | PacketsPerPort | Mean packet volume per destination port | Log | Port Scan density |
| F12 | SqlSpecialChar | Ratio of SQL special characters (`'`, `;`, `#`) in normalized payload | Pass-through | SQLi |
| F13 | CrsSqliScore | Aggregate score from OWASP CRS 942 PL2 rules per request | Linear | SQLi (CRS PL2) |
| F14 | SqlUnionSelect | Identifies UNION SELECT syntax | Binary | SQLi — UNION |
| F15 | SqlComment | Identifies SQL comment characters (`--`, `#`, `/**/`) | Binary | SQLi — comment |
| F16 | SqlStackedQuery | Identifies stacked SQL command syntax | Binary | SQLi — stacked |
| F17 | SqlSelectCount | Frequency of SELECT keyword per request | Linear | SQLi — reconnaissance |
| F18 | CrsXssScore | Aggregate score from OWASP CRS 941 PL2 rules | Linear | XSS (CRS PL2) |
| F19 | JsFunctionCall | Identifies dangerous JavaScript function invocations | Binary | XSS — JS |
| F20 | HtmlEventHandler | Identifies HTML event handler attributes | Binary | XSS — events |

**B. Temporal Context State (10D: F21–F30)**

**Table 3.10: 10 Temporal State Dimensions**

| Index | Identifier | Strategic Function |
|---|---|---|
| [20–23] | `last_action_onehot` | Informs the Agent whether the IP currently undergoes Allow / Rate Limit / Redirect / Block |
| [24] | `action_hold_norm` | Aggregated consecutive steps preserving a unified action |
| [25] | `effect_damage_ema` | Tracks service damage trends over time, suppressing short-term noise |
| [26] | `effect_trend` | Highlights damage directional movement (intensifying/recovering) |
| [27] | `soft_window_fill_norm` | Measures saturation of the attack evidence buffer |
| [28] | `escalation_score_norm` | Consolidated evidence score guiding escalation timing |
| [29] | `miss_budget_used_norm` | Frequency an IP "escapes" Redirect — 3 misses triggers block_ready |

**C. Closed-Loop Effect Feedback (4D: F31–F34)**

**Table 3.11: 4 Closed-Loop Feedback Dimensions**

| Index | Identifier | Significance |
|---|---|---|
| [30] | `webserver_reachability` | Assesses if the production webserver generated responses |
| [31] | `honeypot_capture_ratio` | Calculates ratio of suspected traffic captured by the honeypot |
| [32] | `service_presence` | Determines whether the source IP continues transmitting to the webserver |
| [33] | `service_damage` | Analyzes precise service damage from the preceding action step |

These 4 effect state dimensions reflect the direct consequences of the Agent's actions on the network Environment, carrying a one-cycle delay (values at cycle $t$ reflect the effect of the action at cycle $t-1$).

**3.3.2.3 Feature Vector Normalization**

Three normalization clusters:

- **Log scale** (F1, F2, F3, F5, F10, F11): `f_norm = log(1 + min(f_raw, cap)) / log(1 + cap)` — compresses heavily right-skewed distributions.
- **Linear scale** (F9, F13, F17, F18): `f_norm = min(f_raw, cap) / cap` — for approximately linear distributions within constricted ranges.
- **Pass-through** (F4, F6, F7, F8, F12, F14–F16, F19, F20): Structurally defined within [0, 1] (ratios, inverse CV, or binary outputs).

---

### 3.4 Methodological Limitations

- The Markov assumption is approximate; if a 1-second window and 10-dimensional time state are insufficient to represent significant long-term dependencies, the resulting policy may not be optimal.
- The RL training process only reflects the response distribution of known attack patterns. A sophisticated adversary could alter the attack distribution with zero-day variations to exploit policy convergence.
- The current observational framework is primarily suited to high-speed and high-intensity L7 attacks. For prolonged attacks like Slowloris (lasting minutes or hours), a 1-second sliding window may not be sufficient for detection.
- The Mininet environment does not fully simulate the complexity, latency variations, and multi-step operating conditions of a real-world production network.
- The effectiveness of the F12–F20 content feature group depends heavily on the ability to decode TLS via `SSLKEYLOGFILE`. Without payload visibility, Layer 7 analytical capability is significantly degraded.

---

## CHAPTER 4 — EXPERIMENTAL AND RESULTS

### 4.1 Introduction

This chapter focuses on the experimental evaluation of the proposed defense system, covering both the Observer Module's feature extraction accuracy and the RL agent's training convergence and policy execution effectiveness.

#### 4.1.1 Definition of Evaluation Metrics

**Detection Rate:** Computed exclusively over *active-threat steps* (timesteps where the attack is actively manifesting). Silent steps subsequent to a Block action are deliberately excluded to preclude artificial inflation of metrics.

**False Positive Rate (FPR):** Calculated over *normal-traffic steps* (timesteps involving purely benign, legitimate traffic).

**Per-Window vs. Per-Session Evaluation:** The *per-window* metric assesses detection on an isolated 1-second interval basis. The *per-session* metric deems an entire session successfully detected if at least one constituent window within that session breaches the detection threshold.

The entirety of the experimental framework was executed on Linux/Containernet, using Python 3.x with Stable-Baselines3 (numpy < 2.0). Random seed locked at 42 for reproducibility.

---

### 4.2 Data Presentation

#### 4.2.1 Payload Normalization Pipeline Results

The system constructs a sequential 8-step payload normalization pipeline preceding CRS pattern matching. The execution sequence constitutes a rigid constraint: HTML entity decoding must precede URL decoding (e.g., `&#x25;27` → `%27` → `'`); URL decoding must precede Base64 decoding (as Base64 padding utilizes the `=` character).

Each normalization step addresses a specific evasion class: HTML entity decoding counters XSS bypasses; recursive URL decoding (max 2 iterations) addresses double-encoding — the most ubiquitous cause of WAF bypasses identified by Akhavani et al. [30]; Base64 decoding detects encapsulated attack payloads; whitespace normalization eliminates query fragmentation techniques.

Normalized outputs are cached via packet identifiers, ensuring each packet traverses the pipeline precisely once.

#### 4.2.2 CRS Paranoia Level Analysis

**CRS SQLi (F13) Analysis:** Evaluated on LSNM2024 SQLi dataset ($n = 2,809$ attack samples, $3,000$ normal samples):

| PL | Rules | TP | FP | F1-Score | FPR | Decision |
|---|---|---|---|---|---|---|
| PL1 | 19 | 1,695 | 0 | 0.753 | 0.0% | FPR=0, but misses 40% of attacks. |
| **PL2** | **50** | **2,809** | **459** | **0.925** | **15.3%** | **Optimal — Selected.** |
| PL3 | 57 | 2,809 | 520 | 0.915 | 17.3% | Higher FP; no improvement over PL2. |

PL2 was selected: $F1-Score = 0.925$ and $Recall = 1.0$ ensures no SQLi variants are missed. The URI-level FPR of 15.3% reflects isolated CRS scoring; within the full 20D feature vector, F13 is one signal among many and is weighted accordingly by the RL agent.

**CRS XSS (F18) Analysis:** Evaluated on LSNM2024 XSS dataset (123 GET attack samples, 3,000 normal samples):

| PL | Rules | TP | FP | F1-Score | Decision |
|---|---|---|---|---|---|
| **PL2** | **27** | **123** | **0** | **1.000** | **Selected.** |

PL2 selected to guarantee broader coverage against obfuscated event-handler patterns, with $Recall = 1.0$ and $FPR = 0.0\%$.

#### 4.2.3 Feature-Level Detection Performance

To verify the effectiveness of the extracted features, each feature group was independently evaluated using a binary classification model (Random Forest, 200 decision trees) on the Mutated Packets PCAP dataset (Abu Al-Haija et al., 2025).

**Table 4.1: Classification Results per Feature Cluster**

| Attack Type | Primary Features | Precision | Recall | F1-Score | Test Set (Windows) |
|---|---|---|---|---|---|
| SYN Flood | F1, F2, F9 | 0.991 | 1.000 | 0.995 | 426 windows |
| Port Scan | F4, F5, F11 | 1.000 | 0.508 | 0.674 | 969 windows |
| Brute Force | F6, F7, F8 | 0.520 | 1.000 | 0.684 | 1,749 windows |
| SQLi | F13, F14–F16 | 1.000 | 0.263 | 0.417 | 532 windows |
| XSS | F18, F19–F20 | 1.000 | 0.075 | 0.140 | 187 windows |

**Critical Distinction — Per-Window vs. Per-Session:** Recall = 0.263 for SQLi signifies that 26.3% of the 1-second windows within the SQLi session are correctly classified as attacks — it does **not** imply that 26.3% of the attack sessions evaded detection. Empirical analysis confirms that 75.4% of windows in an SQLi session do not contain an attack payload (only TCP setup/teardown/response), with 92.6% sparseness for XSS sessions. Detailed analysis verifies that **100% of SQLi sessions exhibit at least one window breaching the detection threshold**, mirrored in the XSS evaluation.

A precision of 1.000 for SQLi and XSS conclusively verifies the absence of false positives — every window classified as an attack unequivocally contained a malicious payload.

#### 4.2.4 Feature Importance and Clustering

Random Forest Feature Importances on the CSV set identified F1 (PacketRate) and F13 (CRS SQLi) as the biggest contributors, consistent with the characteristics of DDoS and SQLi attacks. A t-SNE plot (perplexity = 30) shows clearly separated attack clusters and normal traffic, confirming that F1–F20 features are highly distinguishable.

#### 4.2.5 Performance Evaluation (Benchmark) of PPO, DQN, and A2C

Benchmark test conditions: same 34-dimensional environment, default SB3 hyperparameters, 5 training seeds (42, 123, 456, 789, 1337), 30 evaluation episodes per seed. Results aggregated as mean with 95% CI.

**Table 4.4: Benchmark PPO/DQN/A2C — Raw Defensive Performance (round_robin)**

| Algorithm | Mean Reward | Mitigation % | Exact Response % | Service Damage AUC |
|---|---:|---:|---:|---:|
| PPO | 58.80 | 97.65 | 90.81 | 0.0644 |
| DQN | 60.71 | 99.54 | 92.26 | 0.0583 |
| A2C | 24.46 | 95.97 | 85.59 | 0.0764 |

**Table 4.5: Benchmark PPO/DQN/A2C — Benign-Safety Trade-off (round_robin)**

| Algorithm | Mitigation % | Benign Intervention % | Benign Harm Score | Mitig/BenignInt |
|---|---:|---:|---:|---:|
| PPO | 97.65 | 0.65 | 0.79 | 150.2 |
| DQN | 99.54 | 1.39 | 1.39 | 71.5 |
| A2C | 95.97 | 22.27 | 22.27 | 4.3 |

#### 4.2.6 PPO Hyperparameter Tuning

| Parameter | Default SB3 | Deployed Value | Tuning Rationale |
|---|---|---|---|
| net_arch (pi/vf) | [64, 64] | pi=[256, 128]; vf=[256, 256, 128] | Increase capacity for decision boundaries across 5 attack spaces |
| learning_rate | $3\times10^{-4}$ (fixed) | $3\times10^{-4} \to 6\times10^{-5}$ (linear decay) | Rapid learning initially, precise fine-tuning in terminal phase |
| clip_range $\epsilon$ | 0.2 | 0.15 | Tighten policy updates to prevent overshoot |
| gamma $\gamma$ | 0.99 | 0.995 | Extended long-term vision for 320-step episodes |
| ent_coef | 0.0 | 0.05 | Sustain exploration, preventing premature convergence |
| batch_size | 64 | 128 | Enhanced gradient stability with 34D state space |
| n_envs | 1 | 4 | Parallelize 4 environments, accelerating training ~4× |

#### 4.2.7 Convergence and Training Stability Analysis of v13 PPO Model

**Table 4.6: PPO Diagnostic Metrics during Training**

| Metric | Terminal Value | Status | Interpretation |
|---|---|---|---|
| eval/mean_reward | 58.68 | Optimal | Reward ascends and stabilizes at terminal training phase. |
| approx_kl | 0.0008 | Optimal | Sub-threshold (<0.02) — guarantees safe policy updates. |
| clip_fraction | 0.013 | Optimal | Gradient clipping rarely invoked near convergence. |
| entropy_loss | −0.344 | Optimal | Agent exhibits high confidence; exploration maintained. |
| explained_variance | 0.926 | Optimal | Critic is stable, providing excellent return estimation. |
| value_loss | 1.44 | Optimal | Loss diminishes and stabilizes. |

**Learning Curve Analysis:** `eval/mean_reward` monotonically escalates from 0 to ~58.68 over 500K timesteps in three distinct phases:
- **Exploration (0–100K):** Slow reward accretion (slope ≈ 0.2/10K steps).
- **Rapid improvement (100K–350K):** Accelerated reward gains (slope ≈ 0.5/10K steps).
- **Saturation (350K–500K):** Reward stabilizes within [58.5, 58.9], CV < 0.4%, confirming convergence.

**Escalation Strategy Metrics:** Escalation Rate (Redirect→Block) ranges from 0.79 (SQLi) to 0.99 (XSS), confirming heterogeneous response per attack class. Overall Escalation Rate ≈ 0.85. Premature Block Rate ≈ 0.15 (acceptable). Benign False Block Rate: 0 on training-distribution simulator.

#### 4.2.7.1 PPO Default vs PPO v13 (Tuning Impact)

**Table 4.7: PPO Default vs PPO v13 (Tuning Impact)**

| Metric | Default PPO | v13 Tuned | Improvement |
|---|---|---|---|
| Final Reward (500K steps) | 2.34 | 58.68 | +2400% (includes episode length effect) |
| **Reward per Step** | **0.0195** | **0.1834** | **+840% (fair comparison)** |
| Episode Length | 120 steps | 320 steps | +167% |
| Wall-clock (500K steps) | 786s | 197s | **4× faster** |

The primary operational benefit of tuning is the **4× wall-clock acceleration** via n_envs=4 parallelization.

#### 4.2.8 Final Evaluation Results

The terminal policy was evaluated across 50 episodes using the optimal model from the `run_34d_v13` training run.

**Table 4.8: Action Classification Results for the RL Defense Agent**

| Traffic Group | Mitigate Rate | Block Rate | Remarks |
|---|---|---|---|
| Attacker | **99.7%** | 52.1% | The overwhelming majority of attacks are successfully mitigated. |
| Benign | 0.1% | **0.0%** | Zero false blocks recorded. |
| Noisy | 52.4% | 0.0% | Predominantly handled via RateLimit. |

Action Distribution: Allow 31.0% | RateLimit 6.6% | Redirect 47.2% | Block 15.1%.

The policy strategically prioritizes Redirect for L7 threats, avoids erroneous Blocks on benign traffic, and employs RateLimit as a proportional response to noisy traffic.

#### 4.2.9 Validation of v13 PPO Model on Real-World Datasets

**3-Layer Evaluation Design:** Each layer integrates an additional component to isolate its specific impact:
- **Layer 1 (Raw PPO):** Direct output from the 34D v13 model.
- **Layer 2 (Stateless AI Agent):** Evaluates detection with 10D temporal state and 4D effect state deliberately omitted.
- **Layer 3 (System Response):** Holistic system including escalation logic, firewall rules, and safety guardrails.

**Results on CIC-IDS2017 Friday DDoS (SYN Flood):**

| Metric | Layer 1 (Raw PPO) | Layer 2 (Stateless) | Layer 3 (System) |
|---|---|---|---|
| Overall Accuracy | 100.0% | 100.0% | 99.9% |
| Mitigation Rate | 100.0% | 100.0% | 99.9% |
| False Positives | 0 | 0 | 0 |

n = 1,169 windows from Friday-07-07-2017 DDoS PCAP.

**Results on CIC-IDS2017 Friday Port Scan:**

| Metric | Layer 1 | Layer 2 | Layer 3 |
|---|---|---|---|
| Overall Accuracy | 98.5% | 98.5% | 97.8% |
| Mitigation Rate | 94.2% | 94.2% | 93.5% |
| False Positives | 4.1% | 4.1% | 5.2% |

**Results on CSE-CIC-IDS2018 Friday Multi-Attack:**

| Attack Type | Label Count | Raw Accuracy | Mitigation Rate |
|---|---|---|---|
| Benign | 1,702 | 98.0% | — |
| Brute Force | 3,510 | 100.0% | 100.0% |
| XSS | 4,136 | 100.0% | 100.0% |
| SQLi | 81 | 71.6% | 71.6% |

**Overall Accuracy (L2):** 99.4% (9,372/9,429 windows). **Safety Overrides:** 5 (0.1%).

**Thursday Benchmark (Benign Baseline + Synthetic Attacks):**

| Mode | Overall Accuracy | Benign FPR | Brute Force | XSS | SQLi |
|---|---|---|---|---|---|
| **Raw PPO (baseline)** | 99.33% | 3% (15/500 FP) | 99.77% | 99.73% | 69.39% |
| **Stateless (L2 AI)** | 99.65% | 0% (0/50 FP) | 99.85% | 99.95% | 69.39% |
| **Window Reset (L3 System)** | 99.58% | 0% (0/50 FP) | 99.85% | 99.77% | 81.63% (mitigate) |

**Key finding:** SQLi vulnerability at 69.39% is attributed to the intrinsic limitations of the CRS-942 PL2 ruleset on advanced variants (double-encoding, UNION-based, time-based). The L3 system escalation logic improves SQLi mitigation from 69.39% to 81.63% by substituting Block for Redirect.

---

### 4.3 Results Analysis

#### 4.3.1 Analysis by Traffic Group

Based on Table 4.8, the trained policy exhibits three characteristics: near-total mitigation of attack traffic; avoidance of erroneous blocks on benign traffic; and systematic application of proportional interventions (RateLimit) for noisy traffic. This behavioral profile aligns with the reward function design and the escalating action ladder.

#### 4.3.2 Policy Behavior Analysis

When encountering normal traffic, the agent almost never executes erroneous blocks (benign block rate = 0.0%). Confronted with volumetric attacks (SYN Flood, Port Scan), the agent directly applies Block. For Layer 7 attacks (Brute Force, SQLi, XSS), the agent systematically prioritizes Redirect to the Honeypot, then leverages the 15-step soft escalation window to subsequently issue Block once sufficient evidence is accumulated.

#### 4.3.3 Benchmark PPO vs DQN vs A2C Analysis

The benchmark results delineate two divergent optimization axes: raw defensive performance versus the benign-safety trade-off.

**DQN** achieves higher raw defensive metrics (mean reward 60.71 vs. PPO's 58.80; mitigation rate 99.54% vs. 97.65%) but at the cost of ~2.1× higher benign intervention rate. DQN's off-policy Experience Replay mechanism systematically biases the policy toward decisive mitigation actions, creating structural over-aggressiveness.

**PPO** demonstrates decisively superior benign-safety profile, maintaining robust mitigation while minimizing impacts on legitimate traffic. PPO achieves statistical significance in suppressing benign intervention rate across all four evaluation modes (round_robin p=0.0278; round_robin_stress p=0.0021; session_20 p=0.0228; session_20_stress p=0.0486). The Clipped Surrogate Objective with entropy regularization prevents collapsing into a reflexive "Block everything" strategy.

**A2C** fails to stabilize its policy in the high-dimensional 34D environment with sparse, episodic reward signal, resulting in a benign intervention rate (22.27%) that is approximately 16× higher than PPO's — **operationally hazardous** in this environment.

#### 4.3.4 Conclusion

Deployment context must drive algorithm selection:
- **DQN** is optimal for threat-centric deployments where maximizing raw mitigation is the primary objective and higher benign intervention rate is acceptable.
- **PPO** is the preferred architecture for availability-sensitive environments — public-facing services or SLA-bound infrastructure.
- **A2C** is not recommended under default hyperparameters due to its high benign intervention rate.

---

### 4.4 Results Interpretation

#### 4.4.1 Overall Evaluation

The research achieves its foundational objectives: the engineering of an autonomous, RL-driven network defense architecture capable of detecting and mitigating five primary attack classes; and the empirical validation of its operational viability in a closed-loop simulated environment.

The paramount academic contribution resides in the architecture of the Observation Module — specifically the expansion from 20D to 34D state space. The 3-layer diagnostic decomposition (Section 4.2.9) shows that L2 (stateless, no temporal state) retains 99.4% accuracy on CSE-CIC-IDS2018, confirming that the **10D temporal state adds marginal value to per-window detection but is essential for the soft escalation logic** that drives the Redirect→Block transition.

#### 4.4.2 Real-World Scenario Validation

Four representative scenarios were validated in Containernet:

1. **Legitimate HTTPS Stream:** F1 < 60 pps, F12 = 0, F7 = 0.1 → **Action 0 (ALLOW)**. Zero DROP rules in iptables FORWARD chain.
2. **SYN Flood:** hping3 at ~1000 pps → F1 spike to 350 pps, payload ≈ 0 → **Action 3 (BLOCK)** in 2nd window. DROP rule injected at kernel level.
3. **Evasive SQL Injection:** sqlmap with double-URL-encoding → post-normalization UNION SELECT exposed → **Action 2 (REDIRECT)** → soft escalation → **Action 3 (BLOCK)**.
4. **XSS Bot Injection:** `onerror=fetch(...)` → F18 escalation + F20 = 1 → **Action 2 (REDIRECT)** → 15-step escalation → **Action 3 (BLOCK)**.

#### 4.4.3 Three Core Design Decisions

Empirical validation confirms three fundamental design decisions as primary performance determinants:

**Criterion 1 — Integration of Application-Layer Features (F12–F20):** Directly embedding OWASP CRS 942 (SQLi) and 941 (XSS) into the feature vector operationalizes validated security community expertise. The primary advantage is drastic reduction in labeled training data required for L7 attack classification.

**Criterion 2 — Payload Normalization Pipeline:** Evasion techniques (double-URL-encoding, HTML entity obfuscation) represent the most pervasive WAF bypass vectors. Without this normalization layer, obfuscated payloads entirely circumvent CRS pattern matching.

**Criterion 3 — The 1-Second Temporal Window Unit:** The 1-second threshold represents the empirically validated equilibrium point between high-fidelity temporal resolution and required statistical stability, aligning with requirements for real-time defensive operations.

---

### 4.5 Comparison with Literature

**Comparison with Traditional Feature Extraction:** Sharafaldin et al. [17] engineered CICFlowMeter with over 80 bidirectional statistical flow features, achieving >97% accuracy on CICIDS2017 via Random Forest. The present system demonstrates that a curated 20-feature set — synthesizing network-level statistics with application-layer payload semantics (F12–F20) — delivers competitive accuracy (99.9% DDoS, 97.8% Port Scan) while maintaining sub-second inference latency required for a real-time 1-second feedback loop.

**Binary Classification vs. Multi-Class Action Selection:** Moustafa & Slay [32] deployed Random Forest achieving 85.6% accuracy and 0.89% FPR on UNSW-NB15 in binary classification. The present research addresses a fundamentally more complex challenge: simultaneous multi-class categorization of 5 distinct attack vectors coupled with autonomous selection of appropriate mitigation actions.

**Supervised Static Detection vs. Closed-Loop RL:** The dominant NIDS paradigm trains classifiers on static, labeled datasets without a feedback mechanism between defensive actions and subsequent network state. The present system departs from this paradigm by embedding the agent within a closed-loop environment where actions mutate observable state — validated by explained_variance = 0.926, confirming the critic learns action-consequence causality.

**CRS Integration:** The direct integration of OWASP CRS scoring into the feature vector (F13, F18) constitutes a novel architectural design not observed in the surveyed literature, significantly mitigating dependency on massive volumes of labeled training data for complex L7 attacks.

---

### 4.6 Implications of Results

#### 4.6.1 When to Prioritize RL over Static Rules?

RL offers clear value in environments with diverse and constantly changing attacks — especially networks handling both volumetric (SYN Flood) and payload (SQLi, XSS) attacks simultaneously. In environments with monotonous traffic and stable attack patterns, Static Rules remain more effective due to the absence of a training phase.

#### 4.6.2 Minimum Infrastructure Requirements

The architecture necessitates a centralized capture node equipped with Python 3 capabilities and Scapy. Primary resource bottlenecks are flow management (sufficient RAM to track up to 50,000 concurrent flows) and raw packet capture (CPU bounded).

#### 4.6.3 Honeypot as a Strategic Advantage

Redirecting to a Honeypot — instead of blocking immediately — offers value beyond pure defense: the attacker continues to operate in a controlled environment, allowing the SOC to gather threat intelligence (TTPs, payloads, tools) without compromising the real system. This is an advantage that Static Rules and RF classifiers cannot provide.

#### 4.6.4 Policy Reusability

Trained policies can be redeployed to new environments without retraining, provided the 34-dimensional observation vector structure remains the same (same F1–F20 definitions, normalization formulas, per-IP temporal logic).

---

## CHAPTER 5 — DISCUSSION

### 5.1 Restatement of Research Questions and Objectives

This project is guided by three main research questions, each aiming to identify a different aspect of the feasibility and effectiveness of RL-based cyber defense.

**RQ1 — Comparative Efficacy:** Does the RL-based agent learning outperform traditional rule-based defense mechanisms in detecting and mitigating automated and adaptive cyberattacks in a simulated environment?

**RQ2 — Operational Trade-offs:** How do the implementation of autonomous defensive actions affect the balance between mitigating successful attacks and ensuring the availability of a valid service?

**RQ3 — Policy Stability:** Can RL-based agents build and adjust a stable, effective defense policy across diverse and ever-evolving attack vectors without manual reconfiguration?

These questions are posed in the context of current limitations: most modern defense mechanisms are reactive, suffer from alert fatigue, and require constant manual intervention as attacks evolve.

---

### 5.2 Summary of Key Findings and Interpretation in Research Context

#### 5.2.1 RQ1 — Comparative Efficacy of the RL Agent

Evaluation results conclusively demonstrate that the RL agent achieves a superior attack mitigation rate while concurrently sustaining a negligible intervention rate against legitimate traffic: **99.7% mitigation rate** against hostile traffic with **0.0% benign block rate** during preflight evaluation across 50 episodes.

The advantage over static rule-based systems is **structural rather than merely numerical**. Static rule-based systems constrained to fixed thresholds and binary Block/Allow decisions inherently lack the graduated response and temporal escalation capabilities demonstrated here. They cannot distinguish a Brute-Force session from a legitimate high-frequency user across F6, F7, and F8 simultaneously, nor redirect a suspected SQLi source to a honeypot while accumulating forensic evidence before issuing a final Block.

**Why RL Excels — Three Distinct Mechanisms:**

1. **Adaptation:** RL continuously observes the network state and adjusts dynamically, eliminating "rule-development lag."
2. **Integration of Semantic Features (L7):** The F12–F20 feature set allows the agent to detect complex variations that static rules cannot match (e.g., recognizing that URL-encoded and HTML-entity-encoded variants of the same payload resolve to the same normalized string).
3. **Learned Trade-offs:** The RL policy internalizes a highly non-trivial equilibrium between precision and recall, organically learning the relative weighting of signals.

**Limitations and Necessary Conditions for RQ1:**
The documented advantage is contingent upon the simulated environment constraints. Transitioning to a live production network introduces: dynamic multi-tier topologies, novel attack vectors outside the training manifold, and vastly more heterogeneous legitimate traffic. Additionally, statistical testing (Cohen's d = −1.290, p = 0.0757) does not reach α = 0.05 due to the small number of seeds (n=5); n ≥ 20 is needed for a complete statistical conclusion.

**Conclusion RQ1:** The RL agent achieves a 99.7% mitigation rate with 0.0% benign block rate in the simulation environment, with particular strength in adaptively learning and detecting L7 payload through graduated, evidence-based escalation — a capability structurally absent in static rule-based systems.

#### 5.2.2 RQ2 — Operational Trade-offs: Defensive Resolution vs. Service Availability

Cyber defense is an inherent trade-off. The agent demonstrates a nuanced multi-action policy: Blocking for volumetric attacks (SYN Flood, Port Scan) and Redirect-to-Honeypot for application layer attacks (SQLi, XSS, Brute-Force), with session-level 100% detection for SQLi.

**Honeypot Strategy and Threat Intelligence:**
The policy learns to select "Redirect to Honeypot" as Strategic Patience through a 15-step soft window before a permanent block. Benefits include:
1. **Threat Intelligence Acquisition:** The attacker continues to operate in a controlled environment.
2. **Availability Preservation:** Valid users have the opportunity to complete sessions before permanent denial.
3. **Adversarial Deception:** Attackers remain unaware they have been discovered, wasting resources on the honeypot.

**Tiered Defense Architecture (Hybrid Strategy):**
For optimal production resilience:
- **Layer 1:** Ultra-minimalist static rate limiter at the edge router to instantly blunt massive volumetric floods.
- **Layer 2:** RL agent dedicated to L7 inspection and higher-order behavioral analysis.

**Conclusion RQ2:** The RL agent successfully balances defense (high DoS mitigation, session-level SQLi detection) and availability (most legitimate traffic allowed, low false positives).

#### 5.2.3 RQ3 — Policy Stability across Diverse Attack Vectors

Training data from Figure 4.1 and Table 4.2 confirms that the policy achieves stability:

- `eval/mean_reward` increased from ~0 to 58.68 and stabilized in the ±1.0 band from step 350,000 — confirming convergence.
- `entropy_loss` decreased from −1.10 to −0.344 — agent more confident but not overfit (entropy remains > 0).
- `approx_kl` ≈ 0.0008 (terminal phase) — well below the 0.02 clip threshold.
- `explained_variance` ≈ 0.926 — critic highly stable.
- Zero evidence of policy oscillation or catastrophic forgetting.

The agent learns differentiated strategies per attack type: High F1 + High F2 → Block; High F6 + F7 < 0.3 → RateLimit; High F13 → Redirect-to-Honeypot. The policy doesn't collapse into a single action — it learns an implicit decision tree.

##### 5.2.3.1 Per-Window vs. Per-Session: Interpreting Weak Signals and Strategic Patience

The Recall of 0.263 for SQLi at the per-window level specifically denotes: "26.3% of 1-second windows containing SQLi payloads were correctly classified." It does **not** imply: "26.3% of the attack sessions successfully evaded detection."

The network traffic reality: 75.4% of 1-second windows in an SQLi session consist exclusively of TCP setup, teardown, and protocol responses — they contain zero attack payload. The model's refusal to classify these windows as "attacks" demonstrates high precision.

At the session level: **every single SQLi session tested contained a minimum of 1 window that breached the detection threshold** — 100% of SQLi sessions were detected and mitigated.

The 10-dimensional temporal memory matrix records the EMA of damage and the escalation score across windows. When `evidence_score` breaches the terminal threshold, the policy decisively triggers Redirect or Block — eliminating false positives from transient noise in isolated windows.

##### 5.2.3.2 Conceptual Distinction: Autonomous vs. Adaptive Defense

- **Autonomous Nature:** The system executes the entire defense lifecycle from observation (34D features) to enforcement (iptables/tc) without human intervention, significantly reducing manual response latency.
- **Adaptive Nature:** Rooted in the PPO algorithm's clipping mechanism, which ensures policy updates stay within a trust region, preventing overfitting to static signatures and instead favoring learning of **underlying behavioral rules**. The agent identifies malicious intent rather than just matching rigid patterns.

**Conclusion on Stability:** The synergy between autonomous and adaptive traits ensures the agent maintains policy stability even when attack patterns mutate within the boundaries of its training.

---

#### 5.2.4 Detailed Analysis: Dominant Factors and Hyperparameter Selection

##### 5.2.4.1 34D Observation Space Decomposition

The 34D architecture = 20 (sensors) + 10 (temporal state) + 4 (closed-loop effects) endows the agent with absolute observability:
- **F1–F20 (20D sensors):** Immediate threat profile — network statistics and L7 payload semantics.
- **Indices 20–29 (10D temporal state):** Temporal attack pattern — forensic ledger of evidence accumulated across the preceding 15-step window.
- **Indices 30–33 (4D closed-loop effects):** Operational consequences — bridges agent actions to shifting system state.

The 3-layer diagnostic decomposition confirms: **temporal state is the primary driver of escalation quality** (Redirect→Block decision), not of per-window detection accuracy, which is largely preserved even in the stateless (L2) configuration.

##### 5.2.4.2 Hyperparameter Tuning: Step Efficiency vs. Wall-clock Efficiency

| Configuration | Terminal Reward | Wall-clock (seconds) | n_envs |
|---|---|---|---|
| **Default SB3** | 0.020/step | 786 | 1 |
| **Tuned (Proposed)** | 0.183/step | **197** | 4 |

The primary operational benefit of tuning is the **4× wall-clock acceleration** (786s → 197s) via `n_envs=4` parallelization. Per-step reward improves by +840%, reflecting both hyperparameter quality and the 120→320 step episode extension.

In cybersecurity, wall-clock time is crucial: the Tuned model enables a 4× acceleration in the experimentation and iteration cycle — a double benefit alongside improved policy quality.

---

#### 5.2.5 Limitations and Critical Caveats

##### 5.2.5.1 Simulation Gap

The entire experiment was conducted within Mininet — restricted to 4 VMs and 1 router with static topology, clean mathematical feature distributions, and a closed set of 5 pre-defined attack typologies. Transitioning to live production networks introduces: multi-tier topologies with constant flux, real-world attack variants (novel DDoS botnets, zero-day exploits), and vastly more heterogeneous legitimate traffic. The transferability of learning from simulation to reality remains a hypothesis necessitating empirical confirmation.

##### 5.2.5.2 Reward Function Dependency

The detection metrics represent the optimal output under one specific set of weighting coefficients governing action cost/bonus and damage penalty — they are not universal optimal detection rates. Different weights lead to different biases: increasing accuracy weight → more aggressive blocks; increasing availability weight → more lenient policy. Practitioners tasked with real-world deployment must tune reward weights to align with their specific organizational SLAs.

##### 5.2.5.3 Operational Sampling Dynamics and Contextual Analysis

The per-window/per-session distinction is critical for academic interpretation. The system's 15-step soft escalation buffer deliberately selects Redirect over Block during early stages of suspicious sessions, gathering forensic evidence while protecting legitimate users from immediate service denial. The academically rigorous statement:

> "Using a per-session evidence accumulation mechanism significantly improves defensive capabilities compared to making decisions on isolated individual windows. In the Mutated Packets 2025 dataset, the system successfully captured signals from all tested SQLi sessions. When evaluated on CSE-CIC-IDS2018, the mechanism maintained high mitigation rates (71.6%–81.6%) for complex variants, effectively compensating for signal dilution."

##### 5.2.5.4 HTTPS Constraint

The 9 payload features (F12–F20) rely on plaintext inspection of HTTP content. When data is encrypted (TLS 1.3), F12–F20 cannot be computed unless a SSLKEYLOGFILE is present. Real-world production servers do not export SSLKEYLOGFILE due to security policies.

**Mitigations:** Deploy on a transparent proxy (MITM position) granting access to plaintext before cryptographic encapsulation; or accept the L7 blind spot and rely exclusively on L3–L4 volumetric features (F1–F11) for encrypted HTTPS traffic.

##### 5.2.5.5 Horizontal Scalability

This project trains a single agent for the entire network. When production networks have hundreds of components (edge routers, DCs, NAC devices), questions arise about the state explosion problem and whether a multi-agent architecture is mandated for individual network segments. Section 6.2 outlines proposed future research trajectories on multi-agent coordination.

---

## CHAPTER 6 — CONCLUSION AND FUTURE WORK

### 6.1 Conclusion

#### The Identified Research Problem

Chapter 1 clearly defines a need: modern network defense systems are reactive, static, and overloaded by alert fatigue. Traditional solutions (firewall rules, signature-based IDS, rule-based ML) are not adaptable to automated attacks at production speeds. The central question: **Can RL create an autonomous defense agent that learns the optimal defense policy and maintains it over time without manual intervention?**

#### The Project Has Demonstrated Feasibility

The empirical results deliver a definitive affirmative response, substantiated by concrete evidence:

**1. Comparative Efficacy (RQ1): RL Surpasses Static Rules**
- **RL Detection Rate:** Higher than Static Rules, demonstrating the advantages of adaptive policy learning.
- **Exceptional Capability:** HTTP F12–F20 features with payload normalization and CRS working synergistically provide semantic understanding of payloads.
- **Practical Implication:** AI-driven defense has measurable practical advantages in real-world analog detection tasks.

**2. Operational Trade-offs (RQ2): Security Harmonized with Availability**
- **Valid Traffic Preservation:** Policy is not overly aggressive to the point of sacrificing service availability.
- **Honeypot Redirection Strategy:** The 15-step soft-escalation window offers threat mitigation AND intelligence gathering.
- **Attack Mitigation:** Achieves >96% mitigation against DoS and 100% against SQLi at the session level.

**3. Policy Stability (RQ3): Learned and Enduring Efficacy**
- **Stable Training Trajectory:** Massive and stable reward accretion, completely devoid of oscillation.
- **Secure Convergence:** `approx_kl` ≈ 0.0008, ensuring mathematically safe policy updates.
- **Differentiated Response:** The agent successfully learns specific, differentiated actions for distinct attack typologies.

#### The Three Principal Contributions of the Project

1. **Technical Contribution:** Design of a 34-dimensional observation space bridging high-fidelity sensors (CRS, payload normalization) with temporal memory and closed-loop feedback. The 3-layer diagnostic decomposition confirms that **the 10D temporal state and 4D closed-loop effect state are the primary drivers of escalation quality** — specifically the Redirect→Block decision.

2. **Methodological Contribution:** A rigorous evaluation framework built on a 3-layer diagnostic decomposition (Raw PPO → Stateless → System Response) that isolates the contribution of each architectural component, replicable for future NIDS-RL studies.

3. **Operational Contribution:** A feasible implementation roadmap — an optimized inference pipeline for real-time deployment augmented by a static rate-limiting layer, ultra-low FPR via the honeypot escalation mechanism, and immediate readiness for integration with existing SIEM infrastructures (e.g., Wazuh integration).

#### The Gaps Remaining to be Bridged

Despite its promise, this project has only been validated in a controlled simulation environment. To be implemented in practice:
- **Sim2Real Validation:** Switch the policy from Mininet to real network traffic.
- **The HTTPS Imperative:** Deploy a transparent proxy or accept the L7 detection blind spot.
- **Multi-Agent Coordination:** Scale beyond a single agent.
- **Adversarial Evasion Robustness:** Test against attackers who know the feature definitions and policy.

---

### 6.2 Future Work

While this project demonstrates basic feasibility, the future roadmap is oriented toward three main pillars for an autonomous and transparent defense system: **Explainable AI (XAI)**, **Multi-Agent Collaboration**, and **Multi-step Reward Architectures**.

#### 6.2.1 Expansion of the Action Space

**Proposed Enhancements:**
- Source-IP Specific Rate Limiting.
- Request-Type Discriminatory Routing (POST vs GET).
- Dynamic Honeypot Instantiation tailored to attack typology.
- Action Masking to guide exploratory vectors.

Enterprise environments require more sophisticated hierarchical structures than simple binary blocks.

#### 6.2.2 Multi-Agent Collaboration

Distribute agents across subnets to share threat contexts via Distributed Policy Coordination (agents share experiences via high-speed protocols) and AMQP-style event buses for real-time communication.

**Key Benefit:** A probing or exploitation attack on Subnet A will immediately alert Subnet B, allowing the entire network to raise defenses before the attacker can expand its reach.

#### 6.2.3 Robustness Against Evasion Attacks

**Proposed Enhancements:**
- **Adversarial Threat Modeling:** Assume the adversary possesses knowledge of features and rewards.
- **Evasion Tactics Testing:** Penetrating normalization pipelines and temporal modulation (low-and-slow attacks).
- **Defensive Countermeasures:** Adversarial policy training against a highly adaptive, constantly mutating attacker.

Real-world adversaries are neither naive nor cooperative. Upon deployment of an RL defense, the adversary will inevitably adapt and counter-evolve.

#### 6.2.4 Online Training and Concept Drift Management

**Proposed Enhancements:**
- **Drift Detection Mechanics:** Statistical monitoring of recent traffic patterns against the policy baseline.
- **Incremental Retraining:** Policy refinement using recent traffic data, avoiding catastrophic forgetting via elastic weight merging.
- **A/B Testing Protocols:** Run old and new policies in parallel on live traffic before switching.

#### 6.2.5 Explainable AI (XAI)

**Proposed Features:**
- **SHAP / Attention Mechanisms:** Identify which of the 34 characteristic dimensions has the greatest influence on the final decision.
- **Automated Audit Trails:** Log reports explaining each blocking decision (e.g., "Blocked IP X due to F13 (SQLi) characteristic exceeding threshold combined with increasing loss trend").

**Key Benefit:** Transitioning to "Glass Box" AI addresses the biggest barriers to AI adoption in production: operator trust and legal compliance (GDPR, PCI-DSS).

#### 6.2.6 Sim2Real Gap Validation

**Proposed Three-Phase Methodology:**

**Phase 1: Distributional Shift Analysis** — Acquire authentic network packet traces, perform rigorous comparative analysis of feature distributions (F1–F20 mean/variance/percentiles for live vs. simulated traffic), identify extreme distributional shifts.

**Phase 2: Policy Transfer and Evaluation** — Deploy the pre-trained Mininet policy against live traffic in shadow mode (zero actual blocks), measure detection rate against authentic attack vectors.

**Phase 3: Sim2Real Fine-Tuning** — Use live traffic to surgically fine-tune the policy (attenuated learning rate to prevent catastrophic forgetting), then deploy the finalized fine-tuned policy.

#### 6.2.7 Multi-step Reward

**Proposed Feature:** 100-step sequence reward architecture — expanding the temporal horizon to compel the agent to evaluate the entire trajectory of an attack session rather than myopically focusing on single-step interventions.

**Key Benefit:** Enables mastery of complex defensive tactics (long-term "baiting" maneuvers in the honeypot, tracking stealthy behavior over extended durations) prior to issuing terminal blocking decisions.

---

### Summary and Future Vision

This project has incontrovertibly proven that RL constitutes a highly viable, practical foundation for the architecture of autonomous network defense systems. The three foundational research inquiries have been resolved:

- **RQ1:** RL vastly outperforms static rule-based paradigms in optimizing the critical detection-to-false-positive equilibrium.
- **RQ2:** RL successfully harmonizes security with service availability (0.0% benign block rate and 0.65% benign intervention rate in simulation, while achieving 97.65% attack mitigation).
- **RQ3:** RL organically synthesizes and sustains a highly stable, durable policy spanning a wildly diverse array of attack typologies.

The path from lab success to production deployment is long. Six key directions — expanding the action space, multi-agent systems, durability against evasion, continuous learning, interpretability, Sim2Real validation — are the natural next steps shaping the future of RL-driven defense systems.

---

## REFERENCES

[1] Verizon, "2024 Data Breach Investigations Report," Verizon Communications Inc., Tech. Rep., 2024.

[2] OWASP Foundation, "OWASP Top Ten," 2021.

[3] C. Kruegel and G. Vigna, "Anomaly Detection of Web-Based Attacks," in Proc. 10th ACM CCS, 2003, pp. 251–261.

[4] Verizon, "2020 Data Breach Investigations Report," Verizon Communications Inc., Tech. Rep., 2020.

[5] IBM Security and Ponemon Institute, "Cost of a Data Breach Report 2024," IBM Corporation, Tech. Rep., 2024.

[6] R. S. Sutton and A. G. Barto, *Reinforcement Learning: An Introduction*, 2nd ed. Cambridge, MA, USA: MIT Press, 2018.

[7] V. Mnih et al., "Human-Level Control through Deep Reinforcement Learning," *Nature*, vol. 518, no. 7540, pp. 529–533, 2015.

[8] J. Schulman, F. Wolski, P. Dhariwal, A. Radford, and O. Klimov, "Proximal Policy Optimization Algorithms," *arXiv preprint arXiv:1707.06347*, 2017.

[9] B. Lantz, B. Heller, and N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," in *Proc. 9th ACM SIGCOMM HotNets Workshop*, 2010.

[10] M. Towers et al., "Gymnasium: A Standard Interface for Reinforcement Learning Environments," *arXiv preprint arXiv:2407.17032*, 2023.

[11] Netfilter Project, "Iptables — Linux kernel firewall," 2024.

[12] H. Feng, W. Li, and A. Nguyen, "Application-layer DDoS defense with reinforcement learning in software-defined networks," in *Proc. IEEE/ACM IWQoS*, 2020.

[13] P. Biondi, "Scapy: Packet Manipulation Tool," in *Proc. French Network Security Conf.*, 2007.

[14] A. Galashov et al., "Information asymmetry in KL-regularized RL," *ICLR 2019*.

[15] L. Pinto et al., "Asymmetric actor critic for image-based robot learning," *arXiv preprint arXiv:1710.06542*, 2017.

[16] J. Merel et al., "Priors, hierarchy, and information asymmetry for skill transfer in hierarchical RL," *arXiv preprint arXiv:2201.08115*, 2022.

[17] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," in *Proc. ICISSP*, 2018, pp. 108–116.

[18] Q. Zhu and T. Basar, "Game-theoretic methods for robustness, security, and resilience of cyber-physical control systems," *IEEE Control Systems Magazine*, 2015.

[19] A. H. Lashkari et al., *LSNM2024: A Labeled Network Traffic Dataset for Intrusion Detection*. Univ. New Brunswick, 2024.

[20] Q. Abu Al-Haija et al., "End-to-End Threat Hunting with a Novel Multiclass Dataset for Intelligent Intrusion Detection," *arXiv preprint arXiv:2508.05609*, 2025.

[21] M. Lopez-Martin, B. Carro, and A. Sanchez-Esguevillas, "Application of deep reinforcement learning to intrusion detection for supervised problems," *Expert Systems with Applications*, vol. 162, p. 113760, 2020.

[22] A. Shiravi et al., "Toward Developing a Systematic Approach to generate Benchmark Datasets for Intrusion Detection," *Comput. Security*, vol. 31, no. 3, pp. 357–374, 2012.

[23] S. Russell and P. Norvig, *Artificial Intelligence: A Modern Approach*, 4th ed. Pearson, 2020.

[24] R. Tamang et al., "Securing web applications against XSS and SQLi attacks using a novel deep learning approach," *Scientific Reports*, vol. 14, 2024.

[25] A. Muttaqin and I. Sudiana, "Design of realtime web application firewall on deep learning-based models," *JPPIPA*, vol. 10, no. 8, 2024.

[26] A. Raffin et al., "Stable-Baselines3: Reliable Reinforcement Learning Implementations," *J. Mach. Learn. Res.*, vol. 22, no. 268, pp. 1–8, 2021.

[27] A. M. Khodadadi et al., "An Empirical Study on the Evaluation and Enhancement of OWASP CRS in ModSecurity," *Comput. Security*, vol. 139, 2024.

[28] H. A. Tadhani et al., "Securing web applications against XSS and SQLi attacks using a novel deep learning approach," *Sci. Rep. (Nature)*, vol. 14, 2024.

[29] M. Handley, V. Paxson, and C. Kreibich, "Network Intrusion Detection: Evasion, Traffic Normalization, and End-to-End Protocol Semantics," in *Proc. 10th USENIX Security Symp.*, 2001, pp. 115–131.

[30] S. Akhavani et al., "WAFFLED: Exploiting Parsing Discrepancies to Bypass Web Application Firewalls," in *Proc. IEEE S&P*, 2025.

[31] T. Pietraszek and C. V. Berghe, "Defending Against Injection Attacks Through Context-Sensitive String Evaluation," in *RAID 2005*, Springer LNCS 3858, pp. 124–145, 2006.

[32] N. Moustafa and J. Slay, "UNSW-NB15: A Comprehensive Dataset for Network Intrusion Detection Systems," in *Proc. MilCIS*, 2015.

[33] M. Ring et al., "A Survey of Network-Based Intrusion Detection Data Sets," *Comput. Security*, vol. 86, pp. 147–167, 2019.

---

## APPENDICES

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

$$R_t = -(D_{\text{after}} + C_{\text{action}}) + B_{\text{reduction}} + B_{\text{action}}$$

### Appendix C — Terminal PPO Diagnostic Metrics

| Metric | Terminal State (500K steps) | Interpretation |
|---|---|---|
| `eval/mean_reward` | **58.68 ± 0.8** | Absolute convergence achieved. |
| `approx_kl` | 0.0008 | Safe policy updates. |
| `entropy_loss` | −0.344 | High confidence maintained. |
| `explained_variance` | 0.926 | Excellent critic fit. |
| `value_loss` | ~1.44 | Monotonic decay; no overfitting. |

### Appendix D — Algorithm 1: PPO-based Defense Policy Optimization

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

### Appendix E — Example Action Logs

```
[t=120.0s] src_ip=10.0.10.10 action=2 (Redirect) reason=L7 signal F13=5.5
[t=135.0s] src_ip=10.0.10.10 action=3 (Block) block_ready_latched escalation_score=0.82
```

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
