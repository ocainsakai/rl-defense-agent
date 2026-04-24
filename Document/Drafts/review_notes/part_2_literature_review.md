# Chapter 2: Literature Review

## 2.1 Review of Previous Studies

### 2.1.1 Fundamentals of Reinforcement Learning

Reinforcement Learning (RL) is a subfield of machine learning focused on enabling Agents to learn optimal behaviors through interaction with an Environment. Unlike supervised learning, which relies on labeled datasets, RL allows an Agent to learn directly from experience by receiving feedback in the form of rewards or penalties. This learning paradigm is particularly well-suited for dynamic and adversarial domains like cybersecurity, where labeled data is scarce, and attack strategies continuously evolve.

#### Agent Classification and Architecture

According to Russell & Norvig's taxonomy in *Artificial Intelligence: A Modern Approach*, intelligent systems can be classified by their architectural complexity. In the context of cybersecurity, lower-level architectures have demonstrated significant limitations when confronting modern, polymorphic threats.

| Architecture | Cybersecurity Equivalent | Demonstrated Limitations |
|---|---|---|
| Simple Reflex | condition–action rules | Fails in partially observable networks. |
| Model-Based Reflex | Maintains internal state; uses condition-action rules. | Lacks a utility function for optimization; cannot learn. |
| Goal-Based | Utilizes search/planning to achieve explicit goals. | Cannot easily balance competing goals (e.g., security vs. availability). |
| Utility-Based | Chooses actions maximizing expected utility. | Utility must be pre-defined and static. |
| **Learning Agent** | Features a Critic, Learning Element, Performance Element, and Problem Generator; improves via experience. | Requires robust feedback mechanisms and sufficient training data. |

In the context of Deep Reinforcement Learning for cybersecurity, the *Performance element* corresponds to the policy neural network mapping observations to actions, the *Critic* to the value network estimating state values, the *Learning element* to the optimization algorithm updating the weights, and the *Problem generator* to the dynamic simulated network environment.

#### Task Environment Analysis

To justify the application of Deep RL, the network defense domain must be analyzed according to its fundamental task environment properties:

| Property | Value | Design Consequence |
|---|---|---|
| Observability | **Partially Observable** | The Agent cannot directly observe the attacker's true intent; it only observes network traffic manifestations. |
| Determinism | **Stochastic** | The same defensive action may yield different results due to network noise, latency, or TCP retries. |
| Episodicity | **Sequential** | Current defensive actions directly influence future network states and Agent responses. |
| Dynamics | **Dynamic** | The network environment changes continuously even when the Agent takes no action. |
| State/Action | **Continuous / Discrete** | High-dimensional continuous observation space with discrete mitigation actions. |
| Adversarial | **Multi-agent / Adversarial**| The presence of an intelligent attacker creates a non-stationary environment. |

These properties confirm that traditional rule-based mechanisms are insufficient, necessitating an adaptive, learning-based approach.

#### The Partially Observable Markov Decision Process (POMDP)

Because network traffic is only partly observable and unpredictable, the interaction between the defense agent and the environment is modeled as a  **Partially Observable Markov Decision Process (POMDP)**, defined by the 7-tuple $\langle \mathcal{S}, \mathcal{A}, \mathcal{O}, T, Z, R, \gamma \rangle$:

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

where $\eta$ is a normalization constant (derived from the denominator of Bayes' rule to ensure the distribution sums to one). For complex networks with many states, this process is too demanding to compute exactly. Instead, practical systems construct an **approximate sufficient statistic** using an engineered observation vector $o \in \mathcal{O}$ that captures sufficient history and current context to approximate the Markov property, so the problem can be treated as a standard MDP.

#### Mathematical Foundations of Reinforcement Learning

The primary objective of a reinforcement learning Agent is to learn a policy $\pi$ that maximizes the expected **Cumulative Discounted Return**, denoted as $G_t$:

$$G_t = \sum_{k=0}^{\infty} \gamma^k R_{t+k+1}$$

where $\gamma \in [0, 1]$ is the discount factor that determines the present value of future rewards. To evaluate the quality of states and actions, RL frameworks utilize two fundamental functions:

* **State-Value Function $V^\pi(s)$:** The expected return when starting from state $s$ and following policy $\pi$.
* **Action-Value Function $Q^\pi(s,a)$:** The expected return when taking action $a$ in state $s$ and subsequently following policy $\pi$.

In modern Actor-Critic architectures, the **Advantage Function** $A^\pi(s,a)$ is employed to reduce variance during training. It measures how much better a specific action is compared to the average behavior at that state:

$$A^\pi(s,a) = Q^\pi(s,a) - V^\pi(s)$$

#### Model-Based and Model-Free Reinforcement Learning

Reinforcement learning algorithms are broadly categorized as either model-based or model-free. Model-based RL methods try to learn or utilize explicit models of how the environment works, which can then be used for planning and decision-making. While these methods may offer sample efficiency, accurately modeling complex network environments and attacker behaviors is often impractical.

In contrast, model-free RL derives optimal policies directly from interactions with the environment, without requiring an explicit model. These methods are more prevalent in cybersecurity research due to their flexibility and ability to manage complex, partially observable environments. Common model-free approaches include value-based and policy-based methods.

#### Deep Reinforcement Learning and PPO

Traditional reinforcement learning techniques struggle to scale to environments featuring massive or continuous state spaces. Deep Reinforcement Learning (DRL) addresses this limitation by integrating deep neural networks as function approximators. DRL methods are broadly categorized into **Value-based methods**, such as Deep Q-Networks (DQN) [7], which approximate the action-value function to maximize expected rewards, and **Policy-based methods**, which directly optimize the policy function. Policy-based approaches are typically better suited for high-dimensional action spaces and stochastic environments common in network security.

Among modern policy-based algorithms, **Proximal Policy Optimization (PPO)** has emerged as the standard approach due to its superior balance between sample efficiency and training stability. PPO optimizes a **Clipped Surrogate Objective** to ensure that policy updates do not deviate too drastically from the previous policy:

$$L^{CLIP}(\theta) = \hat{\mathbb{E}}_t \left[ \min(r_t(\theta)\hat{A}_t, \text{clip}(r_t(\theta), 1-\epsilon, 1+\epsilon)\hat{A}_t) \right]$$

where $r_t(\theta)$ is the probability ratio between the new and old policies, and $\epsilon$ is a hyperparameter (typically 0.2) that constrains the update. **The selection of PPO for this research is justified by several critical factors when compared to other DRL algorithms:**

* **Superior Stability over SAC**: Soft Actor-Critic (SAC) is often more sample-efficient because it is off-policy, but it can be unstable in environments with changing conditions and unpredictable rewards, like dynamic network traffic. PPO’s on-policy method and clipping mechanism help ensure steady improvement and prevent 'policy collapse' when an agent reacts too strongly to sudden network changes.
* **Addressing DQN Limitations**: Traditional Deep Q-Networks (DQN) only work with discrete action spaces and often overestimate value functions. DQN also cannot handle the complex, continuous state spaces needed for advanced intrusion detection. PPO, as a policy-gradient method, manages these challenges more reliably.
* **Operational Safety**: In network environments, unstable updates can cause serious service disruptions. PPO’s clipping keeps the agent’s learning within safe limits, preventing the disruptive or overly aggressive mitigation actions often that sometimes happen with basic policy gradient methods.
* **Computational Efficiency**: PPO delivers performance comparable to TRPO but with significantly lower overhead, making it suitable for near-real-time requirements.

Overall, reinforcement learning provides a flexible and robust framework for autonomous decision-making. Its capability to learn from interaction and adapt to fluctuating environments forms the theoretical foundation for the AI-driven network defense Agent proposed in this study [8].

### 2.1.2 Network Emulation and Simulation Environments

The training and evaluation of reinforcement learning agents in cybersecurity require environments that are controlled, reproducible, and observable. Deploying learning agents directly into production networks is risky, as it may cause service disruption or unintended security issues. To solve this, this research adopts a two-stage development framework: a high-speed custom simulation environment for training, followed by a high-fidelity emulation testbed for validation. This design helps connect theoretical learning models with more realistic deployment conditions.

#### The Two-Stage Approach: Training vs. Validation

To balance the requirements of sample efficiency and operational realism, the proposed system is developed in two distinct stages:

* **Training Stage (Custom Simulation):** The agent is mainly trained in a specialized closed-loop environment called IDSDefenseEnv. This environment uses probabilistic models, such as Normal, Poisson, and Beta distributions, to simulate network behavior ranging from normal traffic to multi-stage attacks such as SQL injection and XSS. The simulation is based on real-world traffic patterns from well-established datasets such as CIC-IDS2018, so that the learned policies reflect measured network statistics while still allowing the high-speed execution needed for DRL training.
* **Validation Stage (Network Emulation):** After training, the agent is deployed in a Mininet-based emulation environment. Unlike the training stage, which relies on simulated state transitions, this stage uses the real Linux networking stack. Actions such as blocking and rate-limiting are applied through iptables and tc on virtual hosts. This stage is used to validate the agent’s enforcement capability under realistic network latency, TCP/IP stack behavior, and service-level performance conditions.

By combining an abstract, closed-loop simulation for learning with a kernel-level execution for verification, this research provides a practical way to develop adaptive agents that are both intelligent and usable in real deployment.

#### The Role of Emulation in Cybersecurity Research

Network simulation helps researchers represent complex infrastructures, generate realistic attack traffic, and observe how systems behave under adversarial conditions. Unlike static datasets, a simulated environment supports interactive learning, where the agent’s actions can change future network states. This makes simulation well suited to reinforcement learning, which relies on continuous interaction between the agent and the environment.

Simulation also makes it possible to safely execute destructive attack scenarios, such as DDoS, brute-force login attempts, and reconnaissance scanning. Since these activities are isolated from real-world systems, researchers can evaluate defense strategies without causing operational or ethical problems. In addition, simulated environments make experiments repeatable, allowing fair comparisons across different algorithms and defense strategies.

#### Mininet: From Abstract Simulation to High-Fidelity Emulation

Mininet is a widely used network emulation framework that differs from traditional simulators by creating virtual networks in which each host runs on the real Linux kernel and uses the actual Linux networking stack. Rather than representing packet behavior through abstract mathematical models, Mininet relies on Linux network namespaces to create lightweight but realistic virtual hosts. As a result, these hosts can execute real binaries and interact with standard networking tools such as iptables, tc, and iproute2. This high level of realism makes it possible to evaluate defensive policies in an environment that closely resembles deployment on Linux-based production systems, thereby improving the practical transferability of the results.

In the context of reinforcement learning, Mininet serves as a High-Fidelity Emulation Testbed. It permits the precise modeling of latency, bandwidth, and packet loss as they would occur on physical hardware, while supporting the dynamic reconfiguration of network topologies during runtime. By integrating with iptables and Traffic Control (tc), Mininet enables the Agent to face the same constraints and stochastic perturbations found in operational environments—an essential requirement for narrowing the gap between theoretical research and practical deployment.

#### Reinforcement Learning Environments with Gymnasium

**Gymnasium, the successor to OpenAI Gym, provides a standardized interface for reinforcement learning environments**. It delineates clear abstractions for the State space, Action space, reward function, and episode termination conditions. These abstractions simplify the integration of complex environments with reinforcement learning algorithms and training frameworks.

Within the context of network defense, Gymnasium serves as the bridge between the reinforcement learning Agent and the simulated network. Network metrics such as traffic volume, connection rates, packet entropy, and alert signals can be encoded into numerical state representations. Similarly, defensive actions like IP blocking, rate limiting, or traffic redirection can be mapped to discrete or continuous action spaces.

The utilization of Gymnasium ensures compatibility with widely adopted reinforcement learning libraries, including Stable Baselines3. This compatibility facilitates rapid experimentation with state-of-the-art deep reinforcement learning algorithms while maintaining reproducibility and modularity.

#### Hybrid Simulation Architectures

Recent research increasingly adopts hybrid simulation architectures that fuse network emulation platforms with reinforcement learning frameworks. In such architectures, Mininet is responsible for generating realistic network behavior, while Gymnasium orchestrates the reinforcement learning loop. This separation of responsibilities enables flexible experimentation and simplifies system maintenance.

Hybrid environments also support the integration of monitoring and visualization tools, such as Security Information and Event Management (SIEM) systems. However, it is critical to distinguish the role of SIEM from the Agent's primary observation loop. While SIEM platforms are utilized for **long-term audit, evidence storage, and human-centric visualization**, they are not the source of the RL Agent's real-time features. To ensure minimal latency and operational independence, the Agent relies on **dedicated high-speed network sensors (Sniffers)** that process traffic directly at the network interface. This separation prevents the inherent processing delays of SIEM log ingestion from impacting the Agent's 1-second decision window.

Overall, network emulation environments form the empirical backbone of autonomous cybersecurity research. By combining realistic network emulation with standardized reinforcement learning interfaces and independent monitoring layers, these environments enable the safe and effective development of adaptive defense Agents [9], [10].

### 2.1.3 The Evolution of Automated Incident Response

The trajectory of network defense has shifted from **Static Signature-Based Detection** (e.g., traditional Snort rules) to **Statistical Machine Learning**, and finally to **Autonomous Learning Agents**.
Conventional security systems predominantly focus on detection, delegating response decisions to human operators. While Intrusion Detection Systems (IDS) can identify suspicious activities, the absence of automated enforcement permits attackers to continue exploiting the system during the response delay. **Recent research highlights the necessity of coupling detection mechanisms with automated responses to minimize attack dwell times.**

Early automation (circa 2010s) centered on **Rule-Based and Policy-Based Response Systems**, which depended on static thresholds and predefined security policies. For instance, if a connection threshold is breached, an IP address might be automatically blacklisted. While effective against known attack patterns, such rule-based methods struggle to manage evolving, polymorphic threats and **frequently generate false positives** in high-traffic environments.

The current frontier represents a shift toward **Reinforcement Learning for Adaptive Incident Response**. RL introduces a paradigm shift by enabling Agents to learn optimal defensive strategies through interaction with the Environment. Rather than relying on rigid rules, modern RL Agents evaluate the consequences of their actions utilizing reward signals derived from security and performance metrics. **This approach permits the system to dynamically tailor response strategies to varying attack intensities—an evolution from reactive blocking to proactive, intelligent mitigation.**

In network defense scenarios, RL Agents can autonomously select actions such as blocking, rate limiting, or monitoring based on the observed network state. Over time, the Agent learns to mitigate security risks while avoiding unnecessary disruptions to legitimate traffic. **Several studies demonstrate that RL-based response systems outperform static methodologies in handling complex, multi-stage attacks.**

#### Low-Level Enforcement Mechanisms

Effective automated response necessitates reliable enforcement mechanisms at the network and system levels. Linux kernel-level tools—primarily **iptables** and **Traffic Control (tc)**—are frequently employed to execute real-time defenses.

**iptables** is the firewall management utility on Linux, operating at the kernel level to filter and route IP packets [11]. It defines chains comprising multiple rules, each specifying matching criteria (address, port, protocol) and a target action (ACCEPT, DROP, REDIRECT, QUEUE). With an execution latency of < 1ms, `iptables` guarantees the near real-time response indispensable for network security. Primary actions include:

* **ACCEPT**: Permits the packet to pass (default).
* **DROP**: Discards the packet without sending a response.
* **REDIRECT**: Reroutes the packet to an alternate port (utilized for honeypots).
* **QUEUE**: Forwards the packet to userspace (where the RL Agent can process it).

**Traffic Control (tc)** is a traffic shaping utility that enables rate limiting and dynamic bandwidth throttling on network interfaces. In conjunction with `iptables`, TC permits the application of sophisticated defensive policies, such as limiting a specific IP to 10 packets per second.

By integrating the decision-making of the RL Agent with these kernel-level controls, the automated defense system can react with both velocity (kernel) and intelligence (AI). This integration bridges the chasm between high-level reasoning and pragmatic network security enforcement [12].

#### Deception-Based Response and Honeypots

Deception techniques increasingly play a pivotal role in modern incident response strategies. Honeypots are decoy systems designed to lure attackers and monitor malicious behavior without endangering production assets. By redirecting suspicious traffic to honeypots, defenders can accumulate valuable intelligence while mitigating direct attack impacts.

#### Integration with SIEM Systems

Security Information and Event Management (SIEM) systems aggregate and correlate security logs from disparate sources to deliver centralized visibility. Integrating automated response mechanisms with SIEM platforms empowers administrators to oversee defensive actions and system performance in real-time. Alert visualization and correlation bolster trust in autonomous systems by conferring transparency and auditability.

In research contexts, SIEM integration facilitates the quantitative evaluation of response efficacy through metrics such as alert reduction, response latency, and attack mitigation success. These insights are paramount for validating autonomous defense Agents and appraising their readiness for real-world deployment.

### 2.1.4 Feature Engineering and State Representation Design

Feature engineering is the process of transforming raw network data into a structured State representation that an RL Agent can interpret. However, a critical review of existing literature reveals a significant **"Information Asymmetry"** in how states are currently designed, spanning theoretical, operational, and adversarial dimensions.

#### The Theory of Information Asymmetry in RL

In the broader context of reinforcement learning, **Information Asymmetry** is often a deliberate architectural choice used to stabilize training or improve skill transfer. **Galashov et al. (2019)** demonstrated that imposing information constraints on certain policy components can force the Agent to learn more robust and reusable behaviors [14]. Similarly, research into **Asymmetric Actor-Critic** architectures for Partially Observable Markov Decision Processes (POMDPs) suggests that providing "privileged information" to the Critic while restricting the Actor to real-world observations can significantly enhance convergence without introducing bias [15]. Furthermore, hierarchical RL studies have shown that the trade-off between providing "too much" or "too little" history in the state representation determines whether learned skills are overly specific or too generalized [16].

#### Information Asymmetry in Cybersecurity

In cybersecurity, Information Asymmetry is an inherent property of the adversarial interaction. Many **Security Games** models emphasize that while an attacker can observe defensive maneuvers, the defender often cannot directly observe the attacker's actions, observing only the system's resulting state changes [17]. This is formally modeled as games with **incomplete information** or partial observability.

Current research into **Adversarial Reinforcement Learning** in cyber simulations often grants the Agent access to internal system variables that are rarely available in real-world deployments, creating a gap between the "information set" in simulation and the signals available during operation [18]. As highlighted in recent surveys, this creates a distinct asymmetry between the ground-truth labels used during training and the local, noisy observations available to a defender in production infrastructures [19]. This asymmetry is not merely a technical flaw but a fundamental constraint of real-world cybersecurity, where the defender must operate under **Bounded Rationality** due to incomplete network visibility.

#### The Dominance and Limitations of Traffic-Centric Features

In many studies, the problem of network defense via reinforcement learning is simplified into a classification task on static datasets such as NSL-KDD, AWID, or CSE-CIC-IDS2018. For instance, **Lopez-Martin et al. [1]** apply various Deep RL algorithms to intrusion detection, but the entire "environment" is merely a sampling function from the datasets. Rewards are calculated based on classification errors for individual records; thus, the framework is essentially supervised learning reformulated in RL terminology. Similarly, the **AE-SAC model [2]** and comparative studies on NSL-KDD/CICIDS2017 [3] evaluate performance entirely on pre-collected data, disconnected from a dynamic network system.

The core limitation of this approach is the absence of a **feedback loop** between the Agent's actions and the system's subsequent state. When an Agent decides to block an IP or change defense configurations, a static dataset cannot reflect the resulting impact on traffic flow, latency, or service availability. This creates an **Offline-Online Asymmetry**: the model is trained on "dead" data with global statistics that are not available at decision-time in a live environment. Consequently, these systems operate in an **open-loop** manner, where actions serve only as right/wrong labels for historical logs rather than interventions in the network's evolution.

Modern feature selection techniques, such as the **BBOFS-DRL** framework which uses binary butterfly optimization [20] or hybrid feature selection for Random Forest models [21], still largely focus on optimizing classification accuracy on these static, "information-rich" offline spaces. This amplifies the risk of policy failure when transferred to a real-world infrastructure where only local, raw observations are available.

#### The Payload-Metadata Gap in Web Defense

A granular analysis of recent literature (2022–2025) reveals a distinct divergence in how Reinforcement Learning is applied to network security, resulting in what this thesis defines as the **"Payload-Metadata Gap."**

On one hand, RL research in **volumetric DDoS defense** is highly mature but remains almost exclusively focused on traffic metadata. Studies such as **Heseding (2022)** utilize hierarchical heavy hitters and volume-based features (rate, bandwidth, flow frequency) to optimize TCAM filters at the data plane [22]. Similarly, **Satpathy (2025)** proposes hybrid feature selection for DDoS detection in cloud environments, but the state representation relies entirely on flow-level statistics from datasets like CICDDoS2019, neglecting payload analysis [23]. Even research targeting application-layer DDoS, such as **Feng et al. (2020)**, characterizes the environment through resource metrics (CPU/RAM/latency) rather than dissecting the malicious payloads of SQLi or XSS attacks [12].

On the other hand, research into **Web Attack Defense (SQLi/XSS)** predominantly avoids Reinforcement Learning in favor of "heavy" Deep Learning or Natural Language Processing (NLP) models. Architectures using **CNN+LSTM (Tamang et al., 2024)** or hybrid deep networks (**Muttaqin & Sudiana, 2024**) achieve high accuracy by processing raw HTTP strings and tokens [24, 25]. However, these NLP-heavy approaches introduce significant inference latency, making them impractical for the high-speed, kernel-level response loops required by RL Agents. Other machine learning-based WAFs (**Durmuşkaya & Bayraklı, 2025**) continue to focus on rich content representations that lack the lightweight, statistical nature necessary for on-policy learning in production environments [26].

Furthermore, where Reinforcement Learning *is* applied to exploits like XSS, it is currently skewed toward **offensive applications**. RL agents are utilized to evade filters (**Mondal et al., 2022**), generate adversarial payloads (**Pasini et al., 2025**), or automate black-box vulnerability detection (**Lee et al., 2022**) [27, 28, 29]. There is a noticeable absence of research into **defensive, real-time RL Agents** that process lightweight payload features alongside traffic metadata to provide a unified, low-latency defense at the kernel level.

#### Contextual Gap and the Snapshot Limitation

The common denominator of these studies is the lack of comprehensive representation of historical context and internal system states. The Agent primarily observes "snapshots" of current traffic, while the behavioral history of IPs, the Agent's previous decision chain, and service health indicators (latency, error rate, queue length, etc.) are not encoded into the state. Consequently, models may achieve high performance in typical attack scenarios but remain insensitive to low-rate/slow-rate attacks or sophisticated behavioral patterns that only manifest over longer durations. This void is defined as the **Contextual Gap**: the Agent lacks the temporal context and system state necessary to make truly rational defense decisions in a POMDP environment.

#### The Enforcement Gap: Abstraction vs. Reality

Conversely, some studies build detailed simulation environments but stop at the research prototype level, failing to reach the enforcement layer of real systems. The work of **Feng, Li, and Nguyen [7]** on application-layer DDoS defense with RL is a prime example: the authors design a testbed using Open vSwitch and Mininet, observing 12 state features and choosing between actions like delay, drop, or block. However, the entire interaction is implemented within a simulator framework where rewards are calculated based on ground truth information available within the simulation.

The **Enforcement Gap** arises because the actions in many studies are logical variables or abstract API calls (e.g., "block_flow") within a simulator framework rather than real-world enforcement commands. Bridging this gap requires an architecture where the AI's high-level reasoning is directly coupled with authentic, low-level network controls.

This thesis addresses the Enforcement Gap by deploying the RL Agent within a **Mininet-based emulation environment integrated with iptables/tc**. By executing defensive actions through real kernel-level rules and measuring rewards based on actual service metrics (latency, error rates), the system subjects the Agent to the authentic constraints of a Linux-based infrastructure. While Mininet remains an emulation running on a single physical host—limiting the scale and hardware diversity of a true production environment—it serves as a critical intermediary step. This **high-fidelity emulation** validates the feasibility of a closed-loop RL defense architecture at the kernel level, establishing a robust foundation for future deployment in complex, multi-tenant production networks.

#### Extraction Challenges and Real-Time Constraints

Current feature extraction tools often face a trade-off between granularity and latency. While frameworks like Scapy [13] offer deep protocol dissection, their overhead can become a bottleneck in high-speed networks. The challenge lies in engineering a state representation that is "Sufficiently Statistic" (capturing enough information to satisfy the Markov property) while remaining lightweight enough for a 20ms-50ms inference loop.

## 2.2 Summary of the Literature Review and Research Gaps

The literature review confirms that while Reinforcement Learning (RL) has moved beyond simple detection to adaptive response, the existing body of work suffers from three critical "Research Gaps" that this thesis aims to bridge:

1. **Observation Gap (The Feedback Void):** Existing models predominantly operate in an open-loop manner on static datasets, lacking a real-time feedback loop between Agent actions and environmental consequences.
2. **Contextual Gap (Temporal Fragmentation):** State representations are often limited to instantaneous traffic snapshots, missing the historical behavioral context and internal system health metrics (latency, resources) necessary for rational decision-making in POMDPs.
3. **Enforcement Gap (Abstraction vs. Reality):** There is a disconnect between high-level AI action selection and low-level kernel enforcement (e.g., `iptables`, `tc`), with many studies stopping at abstract simulation variables.

This project addresses these critical research gaps by proposing an autonomous AI defense Agent operating within a **closed-loop emulation Environment**. The system integrates Reinforcement Learning with realistic network emulation, low-level enforcement mechanisms, and deception-based defensive strategies. By amalgamating both security and performance metrics into the learning process, the proposed methodology achieves a balanced and pragmatic solution for adaptive network defense.

#### Future Directions in Autonomous Defense

The evolution of the field suggests that the next generation of autonomous defense will move toward **Multi-Agent Reinforcement Learning (MARL)**, where multiple specialized Agents collaborate to defend partitioned network segments. Furthermore, the integration of **Robust RL**—which accounts for adversarial perturbations during training—will likely be necessary to combat attackers who specifically target the AI's decision-making logic. This thesis provides the foundational architecture for such advancements by establishing a reliable, real-world enforcement pipeline.

The subsequent chapter delineates the system architecture and methodology, detailing the design of the simulated Environment, the RL framework, and the implementation of automated response mechanisms.

## 2.3 Contribution of Research

Based on a comprehensive literature review, this thesis contributes to the field of automated network defense across technical, methodological, and practical dimensions.

Technically, the research develops a **closed-loop automated defense architecture** specifically designed for **high-fidelity emulation environments**. This architecture provides a functional bridge between high-level AI decision-making and low-level kernel enforcement. Unlike traditional research limited to offline detection, the proposed system implements an integrated pipeline—spanning automated traffic processing, **RL inference**, and authentic defensive execution via `iptables` and `tc`. By operating within a dynamic emulation framework, the study effectively validates the feasibility of AI-driven defense beyond abstract mathematical models.

Methodologically, the thesis proposes a **Hybrid State Representation** that resolves the "Information Asymmetry" identified in existing literature. By integrating environmental traffic metrics with agent-centric feedback signals, the proposed state vector encapsulates the consequences of previous actions and the temporal behavior of network entities. This design enables the Agent to better navigate the POMDP nature of the network environment, facilitating causal reasoning and optimizing the critical trade-off between aggressive threat mitigation and the preservation of service availability.

Practically, the study provides empirical evidence that reinforcement learning can surpass static rule-based mechanisms in complex, adversarial scenarios. Through diverse attack vectors within the testbed, the system demonstrates robust adaptability to evolving threats while maintaining acceptable operational standards. This work serves as a proof-of-concept for the deployment of adaptive, learning-based defense agents in modern, software-defined network infrastructures.

## References

[1] M. Lopez-Martin, B. Carro, and A. Sanchez-Esguevillas, "Application of deep reinforcement learning to intrusion detection for supervised problems," *Expert Systems with Applications*, vol. 162, p. 113760, 2020.

[2] J. Gu and S. Lu, "An effective intrusion detection approach using autoencoder and soft actor-critic," *Applied Sciences*, vol. 11, no. 15, p. 7058, 2021.

[3] R. Panigrahi and S. Borah, "A detailed analysis of CICIDS2017 dataset for designing intrusion detection systems," *International Journal of Engineering & Technology*, vol. 7, no. 3.24, pp. 479-482, 2018.

[4] S. Russell and P. Norvig, *Artificial Intelligence: A Modern Approach*, 4th ed. Pearson, 2020.

[5] S. T. Mehedi, et al., "Deep Q-Network based DDoS detection and mitigation in Software-Defined Networks," *Journal of Network and Computer Applications*, 2021.

[6] L. Zhang, et al., "ID-RDRL: An intelligent intrusion detection system based on reduced deep reinforcement learning," *IEEE Access*, 2022.

[7] V. Mnih, et al., "Human-level control through deep reinforcement learning," *Nature*, vol. 518, no. 7540, pp. 529-533, 2015.

[8] J. Schulman, et al., "Proximal policy optimization algorithms," *arXiv preprint arXiv:1707.06347*, 2017.

[9] B. Lantz, B. Heller, and N. McKeown, "A network in a laptop: rapid prototyping for software-defined networks," in *Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks*, 2010.

[10] M. Towers, et al., "Gymnasium: A standard interface for reinforcement learning environments," *arXiv preprint arXiv:2205.01561*, 2022.

[11] G. Kroah-Hartman, *Linux Kernel in a Nutshell*. O'Reilly Media, 2006.

[12] H. Feng, W. Li, and A. Nguyen, "Application-layer DDoS defense with reinforcement learning in software-defined networks," in *2020 IEEE/ACM 28th International Symposium on Quality of Service (IWQoS)*, 2020.

[13] P. Biondi, "Scapy: Packet crafting for Python," 2023. [Online]. Available: <https://scapy.net/>

[14] A. Galashov, et al., "Information asymmetry in KL-regularized RL," *ICLR 2019*.

[15] L. P. Kaelbling, et al., "Informed asymmetric actor-critic," *arXiv preprint arXiv:2509.26000*, 2021.

[16] J. Merel, et al., "Priors, hierarchy, and information asymmetry for skill transfer in hierarchical RL," *arXiv preprint arXiv:2201.08115*, 2022.

[17] Q. Zhu and T. Basar, "Game-theoretic methods for robustness, security, and resilience of cyber-physical control systems," *IEEE Control Systems Magazine*, 2015.

[18] T. T. Nguyen, et al., "Adversarial reinforcement learning in a cyber security simulation," *TU Eindhoven Research*, 2020.

[19] M. Nguyen, et al., "Deep reinforcement learning for cyber security," *Harvard University Projects*, 2023.

[20] H. Zhang, et al., "BBOFS-DRL: A binary butterfly optimization-based feature selection with deep reinforcement learning for intrusion detection," *Computer Systems Science and Engineering*, vol. 46, no. 3, 2023.

[21] S. G. Sahu, et al., "A hybrid feature selection and hyperparameter tuning for intrusion detection systems," *International Journal of Interactive Multimedia and Artificial Intelligence*, 2022.

[22] C. Heseding, "Reinforcement learning-controlled mitigation of volumetric DDoS attacks," *Karlsruhe Institute of Technology (KIT)*, 2022.

[23] S. Satpathy, "Cloud-based DDoS detection using hybrid feature selection with DRL," *Scientific Reports*, vol. 15, 2025.

[24] R. Tamang, et al., "Securing web applications against XSS and SQLi attacks using a novel deep learning approach," *Scientific Reports*, vol. 14, 2024.

[25] A. Muttaqin and I. Sudiana, "Design of realtime web application firewall on deep learning-based models," *JPPIPA*, vol. 10, no. 8, 2024.

[26] S. Durmuşkaya and M. Bayraklı, "Web application firewall based on machine learning models," *PeerJ Computer Science*, vol. 11, 2025.

[27] D. Mondal, et al., "XSS filter evasion using reinforcement learning to assist cross-site scripting testing," *International Journal of Health Sciences*, 2022.

[28] F. Pasini, et al., "XSS adversarial attacks based on deep reinforcement learning: A replication and extension study," *arXiv preprint arXiv:2502.19095*, 2025.

[29] S. Lee, et al., "Link: Black-box detection of cross-site scripting vulnerabilities via reinforcement learning," in *Proceedings of the WWW Conference*, 2022.

[30] S. Dawadi, "Deep learning technique-enabled web application firewall for the detection of web attacks," *Sensors*, vol. 23, no. 5, 2023.
