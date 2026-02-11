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
5.  **Feature Extraction:** Modular plugin-based system with 16 behavioral features (Network, Application, Payload, Context).

---

## 🧩 Feature Calculator Architecture

**Version:** 2.0.0 | **Status:** Production Ready ✅

The NIDS system uses a **plugin-based feature calculator** to extract 16 behavioral features from network flows for attack detection.

### Architecture Overview

```
feature/
├── base.py              # Core abstractions (FeatureBase, FeatureRegistry)
├── calculator.py        # FlowFeatureCalculator (orchestrator)
├── calculators/
│   ├── network.py       # F1-F5: Network features
│   ├── application.py   # F6-F8: Application layer
│   ├── payload.py       # F9-F14: Payload analysis
│   └── context.py       # F15-F16: Contextual features
└── feature_flow.py      # [DEPRECATED] Old monolithic calculator
```

### Feature Categories

| Category | Features | Description |
|----------|----------|-------------|
| **Network (F1-F5)** | Packet rate, SYN/ACK ratio, Avg packet size, Bandwidth, ICMP ratio | Basic network statistics |
| **Application (F6-F8)** | Port diversity, HTTP method diversity, Protocol violations | Application layer behavior |
| **Payload (F9-F14)** | Entropy, SQLi/XSS keywords, Shellcode patterns, Binary content | Payload analysis |
| **Context (F15-F16)** | WAMM score, WAMM confidence | ML-based attack classification |

### Quick Start

**Basic Usage:**
```python
from feature.calculator import FlowFeatureCalculator

# Initialize calculator (with optional WAMM classifier)
calc = FlowFeatureCalculator(wamm_classifier=wamm)

# Calculate all 16 features (optimized)
features = calc.calculate_all_optimized(flows)  # Returns list[float]

# Or get dictionary output for easier access
feature_dict = calc.calculate_dict(flows, optimized=True)
# Access: feature_dict['pps'], feature_dict['sqli_keyword'], etc.
```

**Custom Feature Registration:**
```python
from feature.base import FeatureBase, FeatureMetadata, register_feature

@register_feature
class F_NewDetection(FeatureBase):
    metadata = FeatureMetadata(
        code="F_NEW",
        name="New Detection",
        category="custom",
        description="Your custom detection logic"
    )
    
    def calculate(self, flows, **kwargs):
        # Your implementation
        return score
```

### Performance

- **Speedup:** 1.14x average with caching (2-3x for payload features)
- **Compatibility:** 100% backward compatible (0.000000 difference)
- **Memory:** Same footprint as old architecture

### Documentation

📚 **Detailed Documentation:**
- [API Documentation](System/docs/API_DOCUMENTATION.md) - Complete API reference
- [Migration Guide](System/docs/MIGRATION_GUIDE.md) - Upgrade from v1.x to v2.0

### Migration Notice

⚠️ **Old calculator is deprecated!** If you're using:
```python
from feature.feature_flow import FlowFeatureCalculator
```

Migrate to:
```python
from feature.calculator import FlowFeatureCalculator  # Same interface!
```

See [Migration Guide](System/docs/MIGRATION_GUIDE.md) for details. Old code continues to work with deprecation warnings.

---

## 🛠 Installation & Setup

### Prerequisites
* Ubuntu 20.04/22.04 LTS
* Python 3.8+
* Docker & Docker Compose

### 1. Clone Repository
```bash
git clone [https://github.com/ocainsakai/rl-defense-agent.git](https://github.com/ocainsakai/rl-defense-agent.git)
cd rl-defense-agent
