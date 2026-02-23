"""Flow Feature Calculator - Aggregator for all 20 features.

This module provides the main calculator class that computes all 20 features
using the new plugin architecture with FeatureRegistry.

Usage:
    from feature.calculator import FlowFeatureCalculator

    calculator = FlowFeatureCalculator()
    features = calculator.calculate_all(flows)
    # features = [f1, f2, ..., f20]  — in FEATURE_ORDER from data_params.py

    # With feature names:
    feature_dict = calculator.calculate_dict(flows)
    # {'packet_rate': 100.5, 'syn_ack_ratio': 1.2, ...}

Author: NIDS Team
Date: 2024
"""

import logging
from typing import List, Dict, Tuple, Optional
from core.flow_state import FlowState
from feature.base import FeatureRegistry
from config.data_params import FEATURE_ORDER

# Import all feature calculators to trigger @register_feature decorators
# This ensures FeatureRegistry is populated before instantiation
import feature.calculators

logger = logging.getLogger(__name__)


from feature.context import FeatureContext


class FlowFeatureCalculator:
    """
Aggregator class để tính tất cả 20 features từ flows.

    Uses FeatureRegistry to automatically discover and instantiate all
    registered features. Feature order follows FEATURE_ORDER from data_params.py.

    20 FEATURES (RAW VALUES) — grouped by layer:
        Network [0-10]:
          F1:  PacketRate              packets/second
          F2:  SynAckRatio             ratio
          F3:  InterArrivalTime        seconds
          F4:  RstRatio                ratio [0,1]
          F5:  DistinctPorts           count
          F6:  URLConcentration        ratio [0,1]
          F7:  AuthFailureRate         ratio [0,1] (401+403)
          F8:  ServerErrorRate         ratio [0,1] (5xx)
          F9:  AvgPayloadSize          bytes
          F10: FwdBwdRatio             ratio
          F11: PacketsPerPort          ratio
        SQLi [11-16]:
          F12: SqlSpecialChar          ratio [0,1]
          F13: CrsSquliScore           count (0-N)
          F14: SqlUnionSelect          binary 0/1
          F15: SqlComment              binary 0/1
          F16: SqlStackedQuery         binary 0/1
          F17: SqlSelectCount          count
        XSS [17-19]:
          F18: CrsXssScore             count (0-N)
          F19: JsFunctionCall          binary 0/1
          F20: HtmlEventHandler        binary 0/1

    Note: All features return RAW VALUES (not normalized).
    """

    # Feature codes in canonical FEATURE_ORDER (20 features)
    FEATURE_CODES = FEATURE_ORDER

    NUM_FEATURES = len(FEATURE_ORDER)  # 20

    def __init__(self, config=None, wamm_classifier=None):
        """Initialize calculator with all registered features.

        Args:
            config: Optional NIDSConfig instance (passed to features)
            wamm_classifier: Unused (kept for backward compatibility).
        """
        self.config = config

        # Instantiate all features using FeatureRegistry
        self.calculators = []
        for code in self.FEATURE_CODES:
            try:
                calculator = FeatureRegistry.instantiate(
                    code,
                    config=self.config,
                )
                self.calculators.append(calculator)
            except KeyError:
                # Feature not registered yet - log warning and use None placeholder
                logger.warning(f"Feature {code} not registered, using 0.0 default")
                self.calculators.append(None)

    def calculate_all(self, flows: List[FlowState]) -> List[float]:
        """Calculate all 20 features.

        Args:
            flows: List of FlowState objects from same source IP

        Returns:
            list: 20 raw values in FEATURE_ORDER
        """
        if not flows:
            return [0.0] * self.NUM_FEATURES

        results = []
        for calc in self.calculators:
            if calc is None:
                results.append(0.0)
            else:
                try:
                    value = calc.calculate(flows)
                    results.append(value)
                except Exception as e:
                    logger.error(f"Feature {calc.metadata.code} failed: {e}")
                    results.append(0.0)

        return results

    def calculate_all_optimized(self, flows: List[FlowState]) -> List[float]:
        """Calculate all 20 features with caching optimization.

        Uses FeatureContext to:
        - Compute normalized payloads once
        - Cache results for pattern-based features

        Args:
            flows: List of FlowState objects from same source IP

        Returns:
            list: 20 raw values in FEATURE_ORDER
        """
        if not flows:
            return [0.0] * self.NUM_FEATURES

        # Create context with cached normalization
        ctx = FeatureContext(flows)

        results = []
        for calc in self.calculators:
            if calc is None:
                results.append(0.0)
            else:
                try:
                    # Pass context to enable caching
                    value = calc.calculate(flows, context=ctx)
                    results.append(value)
                except Exception as e:
                    logger.error(f"Feature {calc.metadata.code} failed: {e}")
                    results.append(0.0)

        return results

    def calculate_all_with_flags(self, flows: List[FlowState]) -> Tuple[List[float], List[int]]:
        """Calculate features and track missing data.

        Args:
            flows: List of FlowState objects

        Returns:
            tuple: (features_list, missing_indices_list)
            - features_list: 20 raw values
            - missing_indices_list: [0, 3, ...] (indices of missing features)

        Missing data cases:
            - Empty flows list → all features missing
            - Feature calculation error → mark as missing
        """
        if not flows:
            default_vector = [0.0] * self.NUM_FEATURES
            missing_indices = list(range(self.NUM_FEATURES))
            return (default_vector, missing_indices)

        features = []
        missing_indices = []

        for idx, calc in enumerate(self.calculators):
            if calc is None:
                features.append(0.0)
                missing_indices.append(idx)
            else:
                try:
                    feat_value = calc.calculate(flows)
                    features.append(feat_value)
                except Exception as e:
                    logger.error(f"Feature {calc.metadata.code} failed: {e}")
                    features.append(0.0)
                    missing_indices.append(idx)

        return (features, missing_indices)

    def calculate_all_with_flags_optimized(self, flows: List[FlowState]) -> Tuple[List[float], List[int]]:
        """Calculate features with optimization and track missing data.

        Args:
            flows: List of FlowState objects

        Returns:
            tuple: (features_list, missing_indices_list)
        """
        if not flows:
            default_vector = [0.0] * self.NUM_FEATURES
            missing_indices = list(range(self.NUM_FEATURES))
            return (default_vector, missing_indices)

        try:
            features = self.calculate_all_optimized(flows)
            return (features, [])
        except Exception as e:
            logger.error(f"Optimized calculation failed: {e}, falling back to standard")
            return self.calculate_all_with_flags(flows)

    def calculate_dict(self, flows: List[FlowState], optimized: bool = True) -> Dict[str, float]:
        """Calculate all features and return as dictionary.

        Args:
            flows: List of FlowState objects
            optimized: Use optimized calculation (default True)

        Returns:
            dict: {'packet_rate': 100.5, 'syn_ack_ratio': 1.2, ...}
        """
        if optimized:
            features = self.calculate_all_optimized(flows)
        else:
            features = self.calculate_all(flows)

        feature_names = self.get_feature_names()
        return dict(zip(feature_names, features))

    @staticmethod
    def get_feature_names() -> List[str]:
        """Return list of 20 feature names (matching FEATURE_ORDER).

        Returns:
            list: 20 snake_case names in canonical order
        """
        return [
            # Network [0-10]
            'packet_rate',          # F1
            'syn_ack_ratio',        # F2
            'inter_arrival_time',   # F3
            'rst_ratio',            # F4
            'distinct_ports',       # F5
            'url_concentration',    # F6
            'auth_fail_rate',       # F7
            'server_error_rate',    # F8
            'avg_payload_size',     # F9
            'fwd_bwd_ratio',        # F10
            'packets_per_port',     # F11
            # SQLi [11-16]
            'sql_special_char',     # F12
            'crs_sqli_score',       # F13
            'sql_union_select',     # F14
            'sql_comment',          # F15
            'sql_stacked_query',    # F16
            'sql_select_count',     # F17
            # XSS [17-19]
            'crs_xss_score',        # F18
            'js_function_call',     # F19
            'html_event_handler',   # F20
        ]

    @staticmethod
    def get_feature_count() -> int:
        """Return total number of features.

        Returns:
            int: 20
        """
        return FlowFeatureCalculator.NUM_FEATURES


# Backward compatibility: Export old name
__all__ = [
    'FlowFeatureCalculator',
]
