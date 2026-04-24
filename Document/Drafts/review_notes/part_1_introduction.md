***
**MINISTRY OF EDUCATION AND TRAINING**
**FPT UNIVERSITY**

***

# CAPSTONE PROJECT DOCUMENT

## Research and Development of an AI Agent with Adaptive Self-Defense Capabilities in a Simulated Environment using Reinforcement Learning Techniques

---

**Student Team:**

| Full Name | Student ID |
|---|---|
| Ho Le Binh | [Student ID] |
| Nguyen Hoang Tri | [Student ID] |
| Pham Tuan Anh | [Student ID] |
| Trinh Nguyen Yen Vy | [Student ID] |

**Supervisor:** Mai Hoang Dinh

**Capstone Project Code:** SP26IA03

---

**Ho Chi Minh City, 2026**

---

# ABSTRACT

**Background:** Traditional network defenses rely on static rules and signatures that struggle to adapt to evolving, automated cyberattacks. These mechanisms often enforce a rigid trade-off between security and service availability, leading to alert fatigue and delayed responses. This study proposes an autonomous network defense system utilizing Reinforcement Learning (RL) to develop an adaptive policy that balances effective attack mitigation with the preservation of legitimate service availability.

**Methods:** We designed an RL Agent trained using the Proximal Policy Optimization (PPO) algorithm within a virtualized *Containernet* environment. The Agent utilizes a 34-dimensional state space that integrates network traffic statistics, per-IP temporal memory, and closed-loop environment feedback. It operates across a nuanced action space (Allow, Rate Limit, Redirect, Block) and employs a novel evidence-based soft escalation mechanism. This mechanism leverages a temporal window to accumulate forensic data, allowing the Agent to transition from redirection to blocking only when a specific confidence threshold is breached.

**Results:** Experimental evaluations demonstrate that the RL-driven defense effectively mitigates diverse threats, including volumetric attacks, and application-layer attacks (SQLi, XSS, Brute Force). The Agent achieved stable training convergence and maintained a superior equilibrium between security and availability compared to static baselines. The engineered observation space empowers the Agent to internalize session continuity and action-reaction causality, capabilities often missing in traditional classification-based systems.

**Conclusions:** The research validates Reinforcement Learning as a viable foundation for autonomous network defense. The proposed architecture is scalable and ready for integration with existing security infrastructures. Future work will explore distributed architectures and the validation of policy transferability to real-world production environments.

**Keywords:** Reinforcement Learning, Network Intrusion Detection, AI Agent, Policy Learning, Honeypot, Adaptive Defense.

---

# TABLE OF CONTENTS

- ABSTRACT
- TABLE OF CONTENTS
- LIST OF FIGURES
- LIST OF TABLES
- LIST OF ABBREVIATIONS

## Chapter 1: INTRODUCTION

- 1.1 Background
  - 1.1.1 The Escalation of Cyber Threats and Attack Automation
  - 1.1.2 Economic Impact of Data Breaches
  - 1.1.3 Evolution of Network Infrastructure and Operational Challenges
  - 1.1.4 The Need for Autonomous and Adaptive Defense Systems
- 1.2 Problem Statement
- 1.3 Research Objectives
- 1.4 Significance of the Study
- 1.5 Scope and Limitations
  - 1.5.1 Research Scope
  - 1.5.2 Limitations of the Study
- 1.6 Research Questions
- 1.7 Thesis Structure

## Chapter 2: LITERATURE REVIEW

- 2.1 Fundamentals of Reinforcement Learning
- 2.2 Network Simulation Environments
- 2.3 Automated Incident Response Mechanisms
- 2.4 Feature Engineering Techniques for Network Traffic
- 2.5 Summary and Research Gaps
- 2.6 Research Contributions

## Chapter 3: RESEARCH METHODOLOGY

- 3.1 Research Design
  - 3.1.1 Threat Model
  - 3.1.2 Methodological Framework
  - 3.1.3 Overall System Architecture
  - 3.1.4 MDP Problem Formalization
  - 3.1.5 Experimental Network Topology
  - 3.1.6 RL Defense Agent Design
  - 3.1.7 Real-Time Inference and Enforcement Pipeline
- 3.2 Data Collection Methodology
  - 3.2.1 Packet Capture and Dissection
  - 3.2.2 Connection Session Management
  - 3.2.3 1-Second Sliding Window
  - 3.2.4 Data Sources
- 3.3 Data Analysis Techniques
  - 3.3.1 Feature Engineering Overview
  - 3.3.2 Network Features (F1–F11)
  - 3.3.3 SQL Injection Features (F12–F17)
  - 3.3.4 Cross-Site Scripting Features (F18–F20)
  - 3.3.5 Payload Normalization Pipeline
  - 3.3.6 Attack Coverage Matrix
  - 3.3.7 Feature Vector Normalization
  - 3.3.8 Per-IP Temporal State (10D)
  - 3.3.9 Closed-Loop Feedback (Effect state from the preceding step)
- 3.4 Methodological Limitations

## Chapter 4: EXPERIMENTAL RESULTS

- 4.1 Introduction
  - 4.1.1 Evaluation Metrics Definition
- 4.2 Data Presentation
  - 4.2.1 Payload Normalization Pipeline Results
  - 4.2.2 CRS Paranoia Level Analysis
  - 4.2.3 Feature-Based Detection Performance
  - 4.2.4 Feature Importance and Clustering
  - 4.2.5 RL Agent Learning Curves
  - 4.2.6 PPO Diagnostic Metrics
  - 4.2.7 Final Evaluation Results
  - 4.2.8 PPO vs DQN vs A2C Benchmark (Protocol and Data)
  - 4.2.9 PPO v13 Model Training Convergence and Stability Analysis
    - 4.2.9.1 Default PPO vs PPO v13 Comparison (Tuning Impact)
  - 4.2.10 PPO v13 Model Validation on Real-World Datasets
- 4.3 Results Analysis
  - 4.3.1 Traffic Group Analysis
  - 4.3.2 Policy Behavior Analysis
  - 4.3.3 PPO vs DQN vs A2C Benchmark Analysis
- 4.4 Interpretation
  - 4.4.1 Overall Assessment
  - 4.4.2 Realistic Scenario Verification
  - 4.4.3 Three Core Design Decisions
- 4.5 Comparison with Literature
- 4.6 Implications
  - 4.6.1 When to Prioritize RL over Static Rules
  - 4.6.2 Minimum Infrastructure Requirements
  - 4.6.3 Latency versus Accuracy Trade-off
  - 4.6.4 Honeypot as a Strategic Advantage
  - 4.6.5 Policy Reusability
  - 4.6.6 Future Development Trajectories

## Chapter 5: DISCUSSION

- 5.1 Restatement of Research Questions and Objectives
- 5.2 Summary of Key Findings and Contextual Interpretation
  - 5.2.1 RQ1 — Comparative Effectiveness of the RL Agent
  - 5.2.2 RQ2 — Operational Trade-offs: Defensive Actions vs. Service Availability
  - 5.2.3 RQ3 — Policy Stability Across Diverse Attack Vectors
    - 5.2.3.1 Per-Window vs. Per-Session: Explaining Weak Signals and Defending Findings
  - 5.2.4 Detailed Analysis: Dominant Factors and Hyperparameter Choices
    - 5.2.4.1 Dominant Factor: HTTP Payload Feature Cluster (F12–F20) Not CRS Alone
    - 5.2.4.2 Hyperparameter Tuning: Step Efficiency vs. Wall-clock Efficiency Trade-off
  - 5.2.5 Limitations and Critical Caveats
    - 5.2.5.1 The Simulation Gap
    - 5.2.5.2 Reward Function Dependency
    - 5.2.5.3 Per-window Analysis and Latency Trade-off
    - 5.2.5.4 HTTPS Constraint
    - 5.2.5.5 Horizontal Scalability

## Chapter 6: CONCLUSION AND FUTURE WORK

- 6.1 Conclusion
- 6.2 Future Work
  - 6.2.1 Expanding the Action Space
  - 6.2.2 Distributed and Multi-Agent Defense
  - 6.2.3 Robustness Against Evasion Attacks
  - 6.2.4 Online Training and Concept Drift Handling (Continual Learning)
  - 6.2.5 Transparent Decision Logging and Explainability
  - 6.2.6 Simulation-to-Reality Gap Validation (Sim2Real Transfer)

---

# LIST OF FIGURES

- Figure 4.1: Mean reward learning curve (`eval/mean_reward`) and entropy loss (`train/entropy_loss`) over training steps
- Figure 4.1b: PPO training dynamics: Multi-axis chart displaying `train/policy_loss`, `train/value_loss`, `train/approx_kl`, and `train/clip_fraction` over timesteps — demonstrating policy update stability
- Figure 4.1c: Critic evaluation: `explained_variance` (variance ratio explained by Critic) and `train/value_loss` curves over timesteps — assessing value estimation quality
- Figure 4.3a: PPO action distribution from Preflight Eval — 100% stacked bar chart displaying the ratio of Allow (31%), RateLimit (6.6%), Redirect (47.2%), Block (15.1%) across 50 episodes
- Figure 4.2: Radar chart comparing the overall performance of 4 algorithms (PPO/DQN/A2C/Rule-Based) across metrics: detection rate, false positive rate, response latency, and service availability
- Figure 4.3: Correct response rate heatmap categorized by attack type and algorithm — network layer (SYN Flood, Port Scan) vs. application layer (SQLi, XSS, Brute Force)
- Figure 4.4: Operational safety metrics bar chart: benign intervention rate and weighted benign harm score across algorithms over 4 evaluation modes
- Figure 4.5: Confusion matrix heatmap for PPO v13 across 3 real datasets (CIC-IDS2017 Friday DDoS/Port Scan, CSE-IDS2018 Friday Multi-Attack) — displaying True Positive, False Positive, False Negative per attack type
- Figure 4.6: Comparison of 3-Layer Diagnosis (Layer 1 Raw, Layer 2 Stateless, Layer 3 System) on the CSE-IDS2018 Friday dataset — Accuracy, Mitigation rate, and Safety Overrides
- Figure 4.7: Benign False Positive Rate vs. Attack Mitigation Rate trade-off on CIC-IDS2017 & CSE-IDS2018 — illustrating the balance between service safety and defensive efficacy
- Figure 4.8: Attack type distribution and detection rate across datasets (CIC-IDS2017 Friday DDoS/Port Scan, CSE-IDS2018 Friday/Thursday) — detection rate heatmap (%) for each attack type across each dataset
- Figure F.1: Defensive inference and execution pipeline flowchart

---

# LIST OF TABLES

- Table 3.1: Inventory of 20 features within the RL Agent's observation vector
- Table 3.2: Coverage Matrix — Features × Attack Typologies
- Table 3.2b: Ten temporal state dimensions (dimensions 20 through 29 within the observation vector)
- Table 4.1: Classification results per feature group
- Table 4.2: PPO diagnostic metrics during training
- Table 4.3: Action classification results of the RL Defense Agent
- Table 4.4: PPO/DQN/A2C Benchmark — Raw defensive performance (round-robin)
- Table 4.5: PPO/DQN/A2C Benchmark — Benign-safety trade-off (round-robin)

---

# LIST OF ABBREVIATIONS

| Abbreviation | Full Meaning |
|---|---|
| AI | Artificial Intelligence |
| API | Application Programming Interface |
| CAPTCHA | Completely Automated Public Turing test to tell Computers and Humans Apart |
| CRS | Core Rule Set |
| CSV | Comma-Separated Values |
| DDoS | Distributed Denial of Service |
| DoS | Denial of Service |
| RL | Reinforcement Learning |
| FPR | False Positive Rate |
| HTTP | Hypertext Transfer Protocol |
| HTTPS | Hypertext Transfer Protocol Secure |
| IDS | Intrusion Detection System |
| NIDS | Network Intrusion Detection System |
| KL | Kullback-Leibler (Divergence) |
| MDP | Markov Decision Process |
| MIME | Multipurpose Internet Mail Extensions |
| ML | Machine Learning |
| MTU | Maximum Transmission Unit |
| NFKC | Compatibility Decomposition, followed by Canonical Composition |
| NLP | Natural Language Processing |
| OWASP | Open Web Application Security Project |
| PCAP | Packet Capture Format |
| PL | Paranoia Level |
| PPO | Proximal Policy Optimization |
| RQ | Research Question |
| RFC | Request for Comments |
| SB3 | Stable-Baselines3 |
| SDN | Software-Defined Networking |
| SIEM | Security Information and Event Management |
| SLA | Service Level Agreement |
| SOC | Security Operations Center |
| SQL | Structured Query Language |
| SQLi | SQL Injection |
| SSH | Secure Shell |
| SSL/TLS | Secure Sockets Layer / Transport Layer Security |
| SYN | Synchronization flag (TCP) |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TTPs | Tactics, Techniques, and Procedures |
| UDP | User Datagram Protocol |
| VM | Virtual Machine |
| XAI | Explainable Artificial Intelligence |
| XML | Extensible Markup Language |
| XSS | Cross-Site Scripting |
| Zero-day | Previously unknown software vulnerability |

---

# CHAPTER 1: INTRODUCTION

## 1.1 Background

Cybersecurity has undergone significant transformations over the past decade. The rapid growth of digital infrastructure, cloud computing, and large-scale interconnected networks has opened new opportunities while simultaneously expanding the attack surface. Concurrently, cyber threats have become increasingly automated, adaptive, and sophisticated, posing severe challenges to traditional security mechanisms.

### 1.1.1 The Escalation of Cyber Threats and Attack Automation

Modern cyberattacks are no longer primarily manual or opportunistic. Instead, adversaries leverage automated tools to execute large-scale reconnaissance, vulnerability scanning, credential stuffing, and exploitation at machine speed. Verizon's Data Breach Investigations Report (DBIR) reveals that approximately 60% of data breaches involve human elements—including social engineering, credential abuse, and human error—while the exploitation of software and web application vulnerabilities continues to rise [1], [2].

Web application attacks and system intrusions remain the most prevalent breach patterns [3]. These attacks exhibit a high degree of automation, allowing attackers to rapidly identify exposed services and exploit weaknesses across thousands of targets simultaneously. Such large-scale automation significantly degrades the efficacy of static, rule-based security systems that rely on predefined signatures or manually crafted rules [1].

Beyond external adversaries, insider threats cannot be overlooked. DBIR findings indicate that nearly 30% of data breaches involve internal actors—whether driven by malicious intent or inadvertent actions—demonstrating that threats do not solely originate from outside organizational boundaries [4]. This diversity complicates the defensive landscape and necessitates more adaptive security strategies.

### 1.1.2 Economic Impact of Data Breaches

Beyond technical consequences, cyberattacks inflict severe financial and operational costs. The IBM-Ponemon Institute's Cost of a Data Breach Report states that the global average cost of a breach has reached several million US dollars, with significantly higher costs in regulated industries and large enterprises [5]. This cost encompasses incident response, system recovery, regulatory fines, reputational damage, and long-term loss of customer trust.

The increasing frequency and magnitude of cyber incidents, combined with substantial economic impacts, underscore the imperative for more rapid detection and response mechanisms. Delayed or ineffective responses amplify financial losses, making real-time (or near real-time) defensive capabilities a critical requirement for modern network infrastructures.

### 1.1.3 Evolution of Network Infrastructure and Operational Challenges

The transition from on-premises hardware to virtualized and cloud-based infrastructures has broadened the attack surface. Technologies such as virtualization, containerization, and Software-Defined Networking (SDN) enable flexible deployment but also generate an overwhelming volume of network traffic and security events. As a result, Security Operations Centers (SOCs) are frequently overwhelmed by an excessive number of alerts—a phenomenon known as "alert fatigue".

In such environments, human analysts struggle to manually and promptly examine and correlate alerts. Critical security incidents may be overlooked or detected too late, permitting attackers to persist within the network for extended periods. This operational bottleneck exposes the limitations of human-driven security monitoring in high-speed, large-scale network environments.

### 1.1.4 The Need for Autonomous and Adaptive Defense Systems

Given the automation of cyberattacks, the economic ramifications of breaches, and the complexity of modern network infrastructures, the demand for autonomous and adaptive defensive mechanisms is intensifying. Artificial Intelligence (AI), particularly Reinforcement Learning (RL), has emerged as a promising approach to address these challenges.

Unlike supervised learning, which relies on labeled datasets, RL enables an Agent to learn an optimal defensive policy through continuous interaction with the Environment. The Agent observes network states and receives rewards or penalties, thereby dynamically adjusting its behavior to evolving attack patterns. This capability makes RL particularly well-suited for real-time network defense, where attack strategies and system conditions change rapidly.

Consequently, the integration of autonomous AI Agents into network defense architectures represents a critical step towards enhancing the resilience and responsiveness of cybersecurity systems.

## 1.2 Problem Statement

Despite significant advancements in cybersecurity technology, current network defenses remain predominantly reactive and reliant on predefined rules and human intervention. Traditional security solutions—rule-based firewalls, signature-based Intrusion Detection Systems (IDS), and manually configured access control policies—are effective only against known attack patterns. They struggle to adapt to novel adversarial behaviors or respond with the requisite speed against highly automated attacks.

Furthermore, modern network infrastructures generate massive volumes of security data due to cloud computing, virtualization, and SDN. SOCs are often overwhelmed by a continuous stream of alerts, resulting in delayed responses and an increased risk of alert fatigue. Human analysts may miss critical threats or react too slowly, allowing attackers extended dwell time within the network.

Another primary limitation is the lack of autonomous decision-making capabilities. Most security systems depend on static policies or necessitate manual tuning, rendering them inadequate for dynamic environments where attack strategies rapidly evolve. Even machine learning solutions frequently rely on supervised learning—which requires large, labeled datasets that are difficult to collect and quickly become obsolete in the real-world cybersecurity landscape.

In light of these challenges, an adaptive defensive mechanism is required that can autonomously observe network conditions, identify malicious behavior, and execute appropriate mitigation in real-time. The system must be capable of learning from interactions with the Environment, balancing security objectives with service availability, and continuously adapting to novel attack patterns without explicit prior knowledge.

This project addresses the aforementioned limitations by proposing an AI-driven network defense Agent utilizing Reinforcement Learning (RL). By modeling network defense as a sequential decision-making problem, the RL Agent is designed to learn an optimal response policy through trial-and-error interactions. The central problem is: **How can an autonomous defense Agent be designed, trained, and evaluated to effectively mitigate diverse cyberattacks while maintaining network performance at an acceptable level?**

## 1.3 Research Objectives

The primary objective is to design, implement, and evaluate an autonomous network defense system capable of real-time security decision-making within dynamic and adversarial environments. To accomplish this, the research is guided by the following specific objectives:

- **Investigate** the applicability of Reinforcement Learning (RL) techniques for autonomous decision-making in network defense scenarios, particularly in environments characterized by automated and adaptive cyberattacks.
- **Design** and construct a simulated network environment that accurately represents real-world network infrastructures, encompassing production servers, attackers, and defensive components using Mininet.
- **Develop** an RL-based defense Agent capable of observing network states, identifying anomalous or malicious behaviors, and selecting appropriate mitigation actions: blocking, rate limiting, or redirecting traffic.
- **Define** and implement a reward function that balances security efficacy with system performance, ensuring that defensive actions mitigate attacks while preserving service availability.
- **Evaluate** the performance of the proposed defense Agent against multiple attack scenarios by quantifying key metrics such as attack mitigation rate, response latency, false positive rate, and overall network stability.

By addressing these objectives, the project demonstrates the feasibility and efficacy of RL in constructing autonomous network defenses, while providing empirical insights into the Agent's behavior under diverse attack conditions.

## 1.4 Significance of the Study

This research explores the viability of autonomous network defense employing Reinforcement Learning, aiming to enhance traditional security mechanisms through adaptive and self-learning defenses.

From a technical perspective, the project delivers a practical implementation of an RL-based defense Agent integrated within a simulated network environment. The combination of Gymnasium, Mininet, and Linux techniques illustrates how RL can be applied to real-world-inspired network scenarios. The integration with Wazuh SIEM exemplifies the potential of coupling an autonomous Agent with existing monitoring platforms to augment observability.

From an academic perspective, the project provides empirical insights into the RL Agent under diverse attack scenarios. The evaluation results elucidate how the autonomous Agent balances security efficacy with service availability—a critical trade-off in network defense. These findings serve as a reference for future research on adaptive security systems and RL-driven decision-making.

From a practical perspective, the project highlights the potential of autonomous, AI-driven defense systems in alleviating the operational burden on human analysts. Automating detection and response can diminish alert fatigue and facilitate more rapid, consistent reactions. Consequently, the project establishes a fundamental groundwork for future intelligent, scalable, and flexible network defense solutions.

## 1.5 Scope and Limitations

This section delineates the research scope and clarifies the limitations of the proposed approach to establish realistic expectations for the study's outcomes.

### 1.5.1 Research Scope

The scope of this project is concentrated on designing and evaluating an autonomous network defense Agent within a controlled, simulated Environment. The research emphasizes decision-making at the network layer and lightweight application layer.

**Attack Simulation**
The simulated Environment incorporates multiple network attack types inspired by the MITRE ATT&CK framework. These attacks are selected to represent prevalent and high-impact threat vectors observed in real-world networks, including:

- **Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks, such as TCP/SYN floods.**
- **Reconnaissance via port scanning.**
- **Web and authentication-based attacks: brute-force logins, SQL injection, and XSS.**

**Action Space**
The defense Agent is engineered to execute mitigation actions at the operating system and network layers. These actions encompass:

- **[ALLOW] Default.**
- **[RATE] Rate limiting suspicious traffic to diminish the attack's impact while sustaining legitimate services.**
- **[REDIRECT] Redirecting selected traffic to honeypots (decoy systems) to isolate attackers and gather intelligence.**
- **[BLOCK] Blocking malicious IP addresses utilizing firewall rules.**
**All defensive actions are implemented using `iptables` mechanisms, the Linux kernel-level firewall management tool, enabling packet filtering and redirection with minimal latency (~1ms); and traffic control (`tc`) within the simulated network.**

**Technology Stack**
The implementation leverages a suite of widely adopted open-source tools and frameworks, including:

- **Python** as the primary programming language.
- **Gymnasium** to define the Reinforcement Learning Environment.
- **Mininet** to emulate virtual network topologies.
- **Stable Baselines3** to train the Reinforcement Learning models.
- **Wazuh SIEM** for log collection, visualization, and performance monitoring.
Additional technologies encompass: **Docker, PHP, MySQL, ...**

### 1.5.2 Limitations of the Study

Despite its contributions, this research possesses several limitations that must be acknowledged.

Firstly, the defensive system is evaluated solely within a simulated Environment. While the simulation is designed to approximate real-world network behavior, production deployment results may diverge due to hardware constraints, network heterogeneity, and unpredictable user behaviors.

Secondly, attack scenarios are restricted to a predefined set of types. Advanced persistent threats such as zero-days, supply chain attacks, and sophisticated lateral movement fall outside the scope.

Thirdly, the RL Agent's performance is contingent upon the quality of the reward function and the representativeness of the simulated Environment. Suboptimal reward design or incomplete state spaces may constrain the Agent's generalization capabilities to novel situations.

Lastly, the system is implemented on Ubuntu Linux. Its transferability to other operating systems or large-scale, distributed cloud environments has not been evaluated and remains a subject for future research.

## 1.6 Research Questions

Based on the aforementioned problem statement and research objectives, this thesis seeks to answer three research questions:

- **RQ1 (Comparative Effectiveness):** To what extent does the RL Agent outperform traditional rule-based mechanisms in mitigating diverse cyberattacks within a simulated Environment?
- **RQ2 (Operational Trade-offs):** How do autonomous defensive actions (blocking, rate limiting, redirecting) impact the balance between attack mitigation and the availability of legitimate services?
- **RQ3 (Policy Stability):** Can the RL Agent formulate and sustain a stable, effective defensive policy against diverse and continuously evolving attack vectors without necessitating manual reconfiguration?

These three questions are addressed sequentially in Chapter 4 (Experimental Results) and Chapter 5 (Discussion).

## 1.7 Thesis Structure

The remainder of the thesis is organized as follows:

**Chapter 2 — Literature Review** presents the foundational concepts of RL, network simulation environments, automated incident response, and feature extraction techniques. This chapter identifies the research gaps that the project targets.

**Chapter 3 — Research Methodology** details the system design, encompassing the formalization of the MDP problem, the PPO Agent architecture, the extraction pipeline for 20 statistical features (F1–F20) and its expansion into a 34-dimensional observation vector (20 dimensions of statistical data + 10 dimensions of temporal states + 4D of closed-loop feedback), the Mininet network topology, and the real-time execution mechanism via `iptables`.

**Chapter 4 — Experimental Results** presents and analyzes the system's evaluation outcomes, including attack detection accuracy, training convergence curves, comparisons with baseline methods, and practical implications.

**Chapter 5 — Discussion** interprets the findings within a broader context, discusses limitations, and proposes directions for future research.

**Chapter 6 — Conclusion** synthesizes the primary contributions and provides concluding remarks regarding the viability of Reinforcement Learning in autonomous network defense.

---
