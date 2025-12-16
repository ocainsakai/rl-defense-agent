# RL Defense Agent (Capstone Project IAP491)

**Topic:** Research and development of AI Agent capable of adaptive self-defense in simulated environments based on Reinforcement Learning techniques.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![PyTorch](https://img.shields.io/badge/PyTorch-Stable%20Baselines3-orange)
![Mininet](https://img.shields.io/badge/Network-Mininet-green)

## 👥 Team Members

| Role | Student Name | Student Code | Responsibility |
|------|--------------|--------------|----------------|
| **Leader** | **Hồ Lê Bình** | **SE183564** | Infrastructure, Attack Sim, Core logic |
| Member | Nguyễn Hoàng Trí | SE183413 | AI Core, RL Algorithms |
| Member | Phạm Tuấn Anh | SE183403 | SIEM (Wazuh), Dashboard |
| Member | Trịnh Nguyễn Yến Vy | SE183776 | Integration, Sniffer, Logging |

## 🚀 Project Overview

This project aims to build an **Adaptive AI Defense Agent** trained using Reinforcement Learning (RL). The agent operates within a simulated network environment to autonomously detect and mitigate cyber attacks (DoS, Scanning, Brute-force) while maintaining service availability.

### Key Components:
1.  **Simulation Env:** Mininet + Docker (Victims & Honeypots).
2.  **Attack Simulation:** Kali Linux tools (Nmap, Hping3, Hydra).
3.  **AI Agent:** Deep Reinforcement Learning (PPO/DQN) via Stable Baselines3 & Gymnasium.
4.  **Monitoring:** Wazuh SIEM for visualization and logging.

## 🛠 Installation & Setup

### Prerequisites
* Ubuntu 20.04/22.04 LTS
* Python 3.8+
* Docker & Docker Compose

### 1. Clone Repository
```bash
git clone [https://github.com/YOUR_USERNAME/rl-defense-agent.git](https://github.com/YOUR_USERNAME/rl-defense-agent.git)
cd rl-defense-agent
