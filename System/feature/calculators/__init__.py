"""Feature calculators package - Auto-registers all features when imported.

This package contains refactored feature calculator classes using the new
plugin architecture with FeatureBase and @register_feature decorator.

Modules:
- network_features:     F1-F5   (Packet Rate, SYN/ACK Ratio, IAT, RST Ratio, Distinct Ports)
- application_features: F6-F8   (URL Concentration, HTTP IAT Uniformity, Request Size Uniformity)
- network_features_ext: F9-F11  (Avg Payload Size, Fwd/Bwd Ratio, Packets Per Port)
- sqli_features:        F12-F17 (SqlSpecialChar, CRS 942 score, UNION, Comment, Stacked, SELECT count)
- xss_features:         F18-F20 (CRS 941 score, JS functions, event handlers)

Usage:
    from feature.calculators import *
    # All features are automatically registered in FeatureRegistry

    from feature.base import FeatureRegistry
    calculator = FeatureRegistry.instantiate('F13', config=my_config)
    result = calculator.calculate(flows)
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
    F7_HttpIatUniformity,
    F8_RequestSizeUniformity,
)

from feature.calculators.network_features_ext import (
    F9_AvgPayloadSize,
    F10_FwdBwdRatio,
    F11_PacketsPerPort,
)

# SQLi features (F12=SqlSpecialChar, F13=CrsSqliScore, F14=UnionSelect, F15=Comment, F16=Stacked, F17=SelectCount)
from feature.calculators.sqli_features import (
    F12_SqlSpecialChar,
    F13_CrsSqliScore,
    F14_SqlUnionSelect,
    F15_SqlComment,
    F16_SqlStackedQuery,
    F17_SqlSelectCount,
)

# CRS-powered XSS features (F18=CrsXssScore, F19=JsFunctionCall, F20=HtmlEventHandler)
from feature.calculators.xss_features import (
    F18_CrsXssScore,
    F19_JsFunctionCall,
    F20_HtmlEventHandler,
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
    'F7_HttpIatUniformity',
    'F8_RequestSizeUniformity',

    # Network extended features (F9-F11)
    'F9_AvgPayloadSize',
    'F10_FwdBwdRatio',
    'F11_PacketsPerPort',

    # SQLi features (F12-F17)
    'F12_SqlSpecialChar',
    'F13_CrsSqliScore',
    'F14_SqlUnionSelect',
    'F15_SqlComment',
    'F16_SqlStackedQuery',
    'F17_SqlSelectCount',

    # CRS XSS features (F18-F20)
    'F18_CrsXssScore',
    'F19_JsFunctionCall',
    'F20_HtmlEventHandler',
]
