"""Feature calculators package - Auto-registers all features when imported.

This package contains refactored feature calculator classes using the new
plugin architecture with FeatureBase and @register_feature decorator.

Modules:
- network_features: F1-F5 (Packet Rate, SYN/ACK Ratio, IAT, RST Ratio, Distinct Ports)
- application_features: F6-F8 (URL Concentration, Auth Failure Rate, Server Error Rate)
- payload_features: F9-F14 (Payload Length, Entropy, SQLi/XSS patterns)
- context_features: F15-F16 (Context Score, WAMM Classifier)

Usage:
    from feature.calculators import *
    # All features are automatically registered in FeatureRegistry
    
    from feature.base import FeatureRegistry
    calculator = FeatureRegistry.instantiate('F1', config=my_config)
    result = calculator.calculate(flows)

Author: NIDS Team
Date: 2024
"""

# Import all feature modules (this triggers @register_feature decorators)
from feature.calculators.network_features import (
    F1_PacketRate,
    F2_SynAckRatio,
    F3_InterArrivalTime,
    F4_RstRatio,
    F5_DistinctPorts,
)

from feature.calculators.application_features import (
    F6_URLConcentration,
    F7_AuthFailureRate,
    F8_ServerErrorRate,
)

from feature.calculators.payload_features import (
    F9_PayloadLength,
    F10_PayloadEntropy,
    F11_SqliKeyword,
    F12_SqlSpecialChar,
    F13_XssKeyword,
    F14_XssSpecialChar,
)

from feature.calculators.context_features import (
    F15_WammAttackType,
    F16_WammConfidence,
)

__all__ = [
    # Network features (F1-F5)
    'F1_PacketRate',
    'F2_SynAckRatio',
    'F3_InterArrivalTime',
    'F4_RstRatio',
    'F5_DistinctPorts',
    
    # Application features (F6-F8)
    'F6_URLConcentration',
    'F7_AuthFailureRate',
    'F8_ServerErrorRate',
    
    # Payload features (F9-F14)
    'F9_PayloadLength',
    'F10_PayloadEntropy',
    'F11_SqliKeyword',
    'F12_SqlSpecialChar',
    'F13_XssKeyword',
    'F14_XssSpecialChar',
    
    # Context features (F15-F16)
    'F15_WammAttackType',
    'F16_WammConfidence',
]
