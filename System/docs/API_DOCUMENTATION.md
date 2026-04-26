# Feature Calculator API Documentation

**Version:** 2.0.0  
**Date:** February 10, 2026  
**Architecture:** Plugin-based modular system

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Core Components](#core-components)
  - [FeatureRegistry](#featureregistry)
  - [FeatureBase](#featurebase)
  - [FlowFeatureCalculator](#flowfeaturecalculator)
- [Feature Modules](#feature-modules)
- [Advanced Usage](#advanced-usage)
- [Migration Guide](#migration-guide)
- [Performance Tuning](#performance-tuning)

---

## Overview

The Feature Calculator system provides a **plugin-based architecture** for computing network intrusion detection features from flow data. The system consists of:

- **16 features** organized into 4 categories (Network, Application, Payload, Context)
- **Plugin architecture** with auto-discovery via `@register_feature` decorator
- **FeatureRegistry** for centralized feature management
- **Caching optimization** via FeatureContext (1.14x speedup for payload features)
- **100% backward compatible** with old feature_flow.py (deprecated)

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Feature Calculator                       │
│                     (Aggregator)                            │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ Uses
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                   FeatureRegistry                           │
│          (Central plugin management)                        │
│                                                             │
│  registry = {                                               │
│    'F1': F1_PacketRate,                                     │
│    'F2': F2_SynAckRatio,                                    │
│    ...                                                      │
│    'F16': F16_SqlStackedQuery                               │
│  }                                                          │
└────────────────┬────────────────────────────────────────────┘
                 │
                 │ Auto-discovers
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              Feature Modules (Plugins)                      │
│                                                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │  Network    │  │ Application  │  │   Payload    │       │
│  │  Features   │  │  Features    │  │   Features   │       │
│  │  (F1-F5)    │  │  (F6-F8)     │  │   (F9-F14)   │       │
│  └─────────────┘  └──────────────┘  └──────────────┘       │
│                                                             │
│  ┌─────────────┐                                            │
│  │  Context    │                                            │
│  │  Features   │                                            │
│  │  (F15-F16)  │                                            │
│  └─────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Installation

```bash
cd System
pip install -r requirements.txt  # If you have one
```

### Basic Usage

```python
from core.flow_state import FlowState
from feature.calculator import FlowFeatureCalculator

# Create calculator
calc = FlowFeatureCalculator()

# Compute features from flows
flows = [...]  # List of FlowState objects
features = calc.calculate_all(flows)

# features = [f1, f2, ..., f16]
print(f"Calculated {len(features)} features")
print(f"Packet rate: {features[0]:.2f} pkt/s")
print(f"SQLi score: {features[10]:.2f}")
```

### With Caching (Recommended for Payload Features)

```python
# Use optimized calculation for 1.14x speedup
features = calc.calculate_all_optimized(flows)

# Or get dict output
feature_dict = calc.calculate_dict(flows, optimized=True)
print(f"Payload entropy: {feature_dict['payload_entropy']:.2f}")
```

---

## Core Components

### FeatureRegistry

**Location:** `feature/base.py`

Central registry for all feature plugins. Features auto-register on import via `@register_feature` decorator.

#### Methods

##### `register(code: str, feature_class: Type[FeatureBase])`

Register a feature class.

```python
FeatureRegistry.register('F1', F1_PacketRate)
```

##### `instantiate(code: str, **kwargs) -> FeatureBase`

Create feature instance by code.

```python
feature = FeatureRegistry.instantiate('F1')
value = feature.calculate(flows)
```

##### `get_all_features() -> List[str]`

Get list of all registered feature codes.

```python
all_features = FeatureRegistry.get_all_features()
# ['F1', 'F2', ..., 'F16']
```

##### `get_metadata(code: str) -> FeatureMetadata`

Get feature metadata.

```python
meta = FeatureRegistry.get_metadata('F1')
print(f"{meta.code}: {meta.name}")
print(f"Category: {meta.category}")
print(f"Description: {meta.description}")
```

#### Example: Using Registry Directly

```python
from feature.base import FeatureRegistry

# List all features
for code in FeatureRegistry.get_all_features():
    meta = FeatureRegistry.get_metadata(code)
    print(f"{code}: {meta.name} ({meta.category})")

# Instantiate specific feature
f1 = FeatureRegistry.instantiate('F1')
packet_rate = f1.calculate(flows)
```

---

### FeatureBase

**Location:** `feature/base.py`

Abstract base class for all features. Provides template for feature implementation.

#### Required Methods

##### `calculate(flows: List[FlowState], **kwargs) -> float`

Compute feature value from flows.

**Parameters:**
- `flows`: List of FlowState objects from same source IP
- `**kwargs`: Optional parameters (e.g., `context` for caching)

**Returns:** Float value (raw, not normalized)

#### Metadata Attributes

- `metadata.code`: Feature code (e.g., "F1")
- `metadata.name`: Human-readable name (e.g., "Packet Rate")
- `metadata.category`: Category (network/application/payload/context)
- `metadata.description`: What the feature detects
- `metadata.unit`: Measurement unit (e.g., "packets/second")

#### Example: Custom Feature

```python
from feature.base import FeatureBase, FeatureMetadata, register_feature

@register_feature
class F_CustomFeature(FeatureBase):
    metadata = FeatureMetadata(
        code="F_CUSTOM",
        name="Custom Feature",
        category="custom",
        description="My custom detection logic",
        unit="score"
    )
    
    def calculate(self, flows, **kwargs):
        # Your logic here
        return sum(f.get_packet_count() for f in flows) * 2.0
```

---

### FlowFeatureCalculator

**Location:** `feature/calculator.py`

Aggregator class that computes all 16 features using FeatureRegistry.

#### Constructor

```python
FlowFeatureCalculator(config=None)
```

**Parameters:**
- `config`: Optional NIDSConfig instance (passed to features)

#### Methods

##### `calculate_all(flows: List[FlowState]) -> List[float]`

Calculate all 16 features without caching.

```python
calc = FlowFeatureCalculator()
features = calc.calculate_all(flows)
# [f1, f2, ..., f16]
```

##### `calculate_all_optimized(flows: List[FlowState]) -> List[float]`

Calculate with FeatureContext caching (1.14x faster).

```python
features = calc.calculate_all_optimized(flows)
```

**Performance:**
- Network features (F1-F5): No speedup (don't use payload cache)
- Application features (F6-F8): ~1.2x speedup
- Payload features (F9-F14): ~2-3x speedup
- Context features (F15-F16): ~2x speedup (ML prediction cache)

##### `calculate_all_with_flags(flows) -> Tuple[List[float], List[int]]`

Calculate features and track missing data.

```python
features, missing_indices = calc.calculate_all_with_flags(flows)

if missing_indices:
    print(f"Warning: {len(missing_indices)} features missing")
    print(f"Missing: {missing_indices}")  # [0, 3, ...] (indices)
```

##### `calculate_dict(flows, optimized=True) -> Dict[str, float]`

Calculate features as named dictionary.

```python
feature_dict = calc.calculate_dict(flows, optimized=True)

print(f"Packet rate: {feature_dict['pps']}")
print(f"SQLi score: {feature_dict['sqli_keyword']}")
print(f"Entropy: {feature_dict['payload_entropy']}")
```

##### `get_feature_names() -> List[str]` (static)

Get list of feature names.

```python
names = FlowFeatureCalculator.get_feature_names()
# ['pps', 'syn_ack_ratio', 'iat', ...]
```

##### `get_feature_count() -> int` (static)

Get total number of features.

```python
count = FlowFeatureCalculator.get_feature_count()
# 16
```

---

## Feature Modules

### Network Features (F1-F5)

**Location:** `feature/calculators/network_features.py`

Detect network-layer attacks (DDoS, SYN Flood, Port Scan).

| Code | Name | Unit | Use Case |
|------|------|------|----------|
| F1 | PacketRate | packets/second | DDoS detection |
| F2 | SynAckRatio | ratio | SYN Flood detection |
| F3 | InterArrivalTime | seconds | DoS pattern detection |
| F4 | RstRatio | ratio [0,1] | Connection failure detection |
| F5 | DistinctPorts | count | Port Scan detection |

**Example:**

```python
from feature.calculators import F1_PacketRate, F5_DistinctPorts

f1 = F1_PacketRate()
pps = f1.calculate(flows)
print(f"Packet rate: {pps:.2f} pkt/s")

if pps > 1000:
    print("⚠️  Possible DDoS attack!")

f5 = F5_DistinctPorts()
ports = f5.calculate(flows)

if ports > 100:
    print("⚠️  Possible Port Scan!")
```

### Application Features (F6-F8)

**Location:** `feature/calculators/application_features.py`

Detect application-layer attacks (Brute Force, L7 DDoS).

| Code | Name | Unit | Use Case |
|------|------|------|----------|
| F6 | URLConcentration | ratio [0,1] | Brute Force detection |
| F7 | AuthFailureRate | ratio [0,1] | Authentication attack |
| F8 | ServerErrorRate | ratio [0,1] | L7 DDoS detection |

**Example:**

```python
from feature.calculators import F7_AuthFailureRate

f7 = F7_AuthFailureRate()
auth_fail = f7.calculate(flows)

if auth_fail > 0.8:
    print("⚠️  Brute Force login attack!")
```

### Payload Features (F9-F14)

**Location:** `feature/calculators/payload_features.py`

Detect SQLi, XSS, obfuscation in HTTP payloads.

| Code | Name | Unit | Use Case |
|------|------|------|----------|
| F9 | PayloadLength | bytes | Anomaly detection |
| F10 | PayloadEntropy | bits [0,8] | Obfuscation detection |
| F11 | SqliKeyword | weighted score | SQLi detection |
| F12 | SqlSpecialChar | ratio [0,1] | SQLi special chars |
| F13 | XssKeyword | weighted score | XSS detection |
| F14 | XssSpecialChar | ratio [0,1] | XSS special chars |

**Example:**

```python
from feature.calculators import F10_PayloadEntropy, F11_SqliKeyword

# Check for obfuscation
f10 = F10_PayloadEntropy()
entropy = f10.calculate(flows)

if entropy > 7.0:
    print("⚠️  High entropy - possible obfuscated payload!")

# Check for SQLi
f11 = F11_SqliKeyword()
sqli_score = f11.calculate(flows)

if sqli_score > 5.0:
    print("⚠️  SQL Injection detected!")
```

### SQL Injection Pattern Features (F15-F16)

**Location:** `feature/calculators/sqli_features.py`

Regex-based detection of high-risk SQL injection techniques over normalized payload (`FeatureContext.get_normalized()`).

| Code | Name | Unit | Values |
|------|------|------|--------|
| F15 | SqlComment | binary | 1.0 = comment injection (--, #, /**/) detected |
| F16 | SqlStackedQuery | binary | 1.0 = stacked query detected (; DROP/DELETE/INSERT/...) |

**Example:**

```python
from feature.calculator import FlowFeatureCalculator

calc = FlowFeatureCalculator()
features = calc.calculate_all_optimized(flows)

sql_comment = features[14]   # F15
sql_stacked = features[15]   # F16

if sql_stacked == 1.0:
    print("⚠️  Stacked SQL query — high-risk technique (DROP/DELETE possible)!")
elif sql_comment == 1.0:
    print("⚠️  SQL comment injection (--, #, /**/)")
```

---

## Advanced Usage

### Custom Feature Registration

```python
from feature.base import FeatureBase, FeatureMetadata, register_feature
from typing import List
from core.flow_state import FlowState

@register_feature
class F_AvgPacketSize(FeatureBase):
    """Calculate average packet size."""
    
    metadata = FeatureMetadata(
        code="F_AVG_PKT_SIZE",
        name="Average Packet Size",
        category="network",
        description="Mean packet size across all flows",
        unit="bytes"
    )
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        total_bytes = sum(
            f.get_total_fwd_bytes() + f.get_total_bwd_bytes()
            for f in flows
        )
        total_packets = sum(f.get_packet_count() for f in flows)
        
        return total_bytes / max(total_packets, 1)

# Auto-registered! Use immediately:
from feature.base import FeatureRegistry

calc = FeatureRegistry.instantiate('F_AVG_PKT_SIZE')
avg_size = calc.calculate(flows)
```

### Dependency Injection

```python
from feature.calculator import FlowFeatureCalculator
from config.nids_config import NIDSConfig

# Setup config
config = NIDSConfig(analysis_window=5.0)

# Create calculator with config
calc = FlowFeatureCalculator(config=config)

# All features will use config.analysis_window
features = calc.calculate_all_optimized(flows)
```

### Batch Processing

```python
from feature.calculator import FlowFeatureCalculator

calc = FlowFeatureCalculator()

# Process multiple flow groups
flow_groups = [
    flows_from_client1,
    flows_from_client2,
    flows_from_client3
]

results = []
for flows in flow_groups:
    features = calc.calculate_all_optimized(flows)
    results.append(features)

# Convert to numpy array for ML
import numpy as np
feature_matrix = np.array(results)  # Shape: (N, 16)
```

---

## Migration Guide

### From Old Architecture (feature_flow.py)

#### Old Code (Deprecated)

```python
# ❌ DEPRECATED - Shows warning
from feature.feature_flow import FlowFeatureCalculator

calc = FlowFeatureCalculator()
features = calc.calculate_all(flows)
```

**Warning Message:**
```
DeprecationWarning: FlowFeatureCalculator is deprecated (since version 2.0.0)
- Use FlowFeatureCalculator from feature.calculator instead (new plugin-based architecture)
Migration: from feature.calculator import FlowFeatureCalculator
```

#### New Code (Recommended)

```python
# ✅ NEW - No warnings
from feature.calculator import FlowFeatureCalculator

calc = FlowFeatureCalculator()
features = calc.calculate_all(flows)
```

### Individual Features

#### Old

```python
from feature.feature_flow import FlowFeature1_PacketRate

calc = FlowFeature1_PacketRate()  # ⚠️ DeprecationWarning
value = calc.calculate(flows)
```

#### New

```python
from feature.calculators import F1_PacketRate

calc = F1_PacketRate()  # No warning
value = calc.calculate(flows)
```

### Registry-based

```python
from feature.base import FeatureRegistry

# Discover all features
for code in FeatureRegistry.get_all_features():
    calc = FeatureRegistry.instantiate(code)
    value = calc.calculate(flows)
    print(f"{code}: {value:.4f}")
```

---

## Performance Tuning

### Cache Effectiveness

The FeatureContext cache provides:
- **Overall: 1.14x speedup** (measured)
- **Payload features (F9-F14): 2-3x speedup**
- **ML features (F15-F16): 2x speedup**
- **Network/App features (F1-F8): ~1.0x** (no payload caching needed)

### When to Use Caching

✅ **Use `calculate_all_optimized()` when:**
- Processing flows with large payloads (>1KB)
- Computing many payload-based features (F12-F20)
- Batch processing multiple flow groups

❌ **Skip caching when:**
- Only computing network features (F1-F5)
- Memory constrained (cache uses ~100KB per 1000 packets)
- Single-feature calculation (overhead not worth it)

### Memory Optimization

```python
from feature.calculator import FlowFeatureCalculator

# For memory-constrained environments
calc = FlowFeatureCalculator()

# Process in smaller batches
batch_size = 100
for i in range(0, len(all_flows), batch_size):
    batch = all_flows[i:i+batch_size]
    features = calc.calculate_all_optimized(batch)
    # Process features...
    # Cache automatically cleared after each call
```

### Benchmarking

```python
import time
from feature.calculator import FlowFeatureCalculator

calc = FlowFeatureCalculator()

# Benchmark non-cached
start = time.time()
for _ in range(10):
    features = calc.calculate_all(flows)
elapsed_nocache = time.time() - start

# Benchmark cached
start = time.time()
for _ in range(10):
    features = calc.calculate_all_optimized(flows)
elapsed_cached = time.time() - start

speedup = elapsed_nocache / elapsed_cached
print(f"Speedup: {speedup:.2f}x")
```

---

## Feature Reference

### Complete Feature List

| Code | Name | Category | Unit | Range | Use Case |
|------|------|----------|------|-------|----------|
| F1 | PacketRate | Network | pkt/s | 0+ | DDoS detection |
| F2 | SynAckRatio | Network | ratio | 0+ | SYN Flood |
| F3 | InterArrivalTime | Network | sec | 0+ | DoS patterns |
| F4 | RstRatio | Network | ratio | [0,1] | Connection failures |
| F5 | DistinctPorts | Network | count | 0+ | Port Scan |
| F6 | URLConcentration | Application | ratio | [0,1] | Brute Force |
| F7 | AuthFailureRate | Application | ratio | [0,1] | Auth attacks |
| F8 | ServerErrorRate | Application | ratio | [0,1] | L7 DDoS |
| F9 | PayloadLength | Payload | bytes | 0+ | Anomalies |
| F10 | PayloadEntropy | Payload | bits | [0,8] | Obfuscation |
| F11 | SqliKeyword | Payload | score | 0+ | SQLi detection |
| F12 | SqlSpecialChar | Payload | ratio | [0,1] | SQLi chars |
| F13 | XssKeyword | Payload | score | 0+ | XSS detection |
| F14 | XssSpecialChar | Payload | ratio | [0,1] | XSS chars |
| F15 | SqlComment | SQLi | binary | {0,1} | SQL comment injection (--, #, /**/) |
| F16 | SqlStackedQuery | SQLi | binary | {0,1} | Stacked query (; DROP/DELETE/...) |

### Feature Names (for dict output)

```python
names = [
    'pps',                  # F1
    'syn_ack_ratio',        # F2
    'iat',                  # F3
    'rst_ratio',            # F4
    'distinct_ports',       # F5
    'url_concentration',    # F6
    'auth_fail_rate',       # F7
    'server_error_rate',    # F8
    'payload_length',       # F9
    'payload_entropy',      # F10
    'sqli_keyword',         # F11
    'sql_special_char',     # F12
    'xss_keyword',          # F13
    'xss_special_char',     # F14
    'sql_comment',          # F15
    'sql_stacked_query',    # F16
]
```

---

## Troubleshooting

### Features Return 0.0

**Problem:** All features return 0.0

**Solutions:**
1. Check flows are not empty: `len(flows) > 0`
2. Verify flows have packets: `flows[0].get_packet_count() > 0`
3. For F15/F16: Verify HTTP payload is captured (need URI/body for regex match)

### Import Errors

**Problem:** `ModuleNotFoundError: No module named 'feature.calculators'`

**Solution:**
```python
# Make sure you're in System/ directory
import sys
sys.path.insert(0, '/path/to/rl-defense-agent/System')

from feature.calculator import FlowFeatureCalculator
```

### Deprecation Warnings

**Problem:** Too many deprecation warnings

**Solution:**
```python
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Or migrate to new architecture (recommended)
```

### Performance Issues

**Problem:** Slow feature calculation

**Solutions:**
1. Use `calculate_all_optimized()` for caching
2. Reduce flow batch size
3. Profile which features are slowest
4. Consider computing only needed features

---

## Support

For issues, questions, or contributions:

- **Documentation:** [System/docs/](../docs/)
- **Examples:** [System/test_calculator_integration.py](../test_calculator_integration.py)
- **Team:** See [README.md](../../README.md) for team contacts

---

**Last Updated:** February 10, 2026  
**Version:** 2.0.0  
**Maintainers:** NIDS Team
