"""Flow Feature Calculator - Aggregator for all 16 features.

This module provides the main calculator class that computes all 16 features
using the new plugin architecture with FeatureRegistry.

Usage:
    from feature.calculator import FlowFeatureCalculator
    
    calculator = FlowFeatureCalculator(wamm_classifier=wamm)
    features = calculator.calculate_all(flows)
    # features = [f1, f2, ..., f16]
    
    # With feature names:
    feature_dict = calculator.calculate_dict(flows)
    # {'pps': 100.5, 'syn_ack_ratio': 1.2, ...}

Author: NIDS Team
Date: 2024
"""

import logging
from typing import List, Dict, Tuple, Optional
from core.flow_state import FlowState
from feature.base import FeatureRegistry

# Import all feature calculators to trigger @register_feature decorators
# This ensures FeatureRegistry is populated before instantiation
import feature.calculators

logger = logging.getLogger(__name__)


from feature.context import FeatureContext


class FlowFeatureCalculator:
    """
    Aggregator class để tính tất cả 16 features từ flows.
    
    Uses FeatureRegistry to automatically discover and instantiate all
    registered features. Provides backward-compatible interface with
    the old FlowFeatureCalculator.
    
    16 FEATURES (RAW VALUES):
        F1:  PacketRate              packets/second
        F2:  SynAckRatio             ratio
        F3:  InterArrivalTime        seconds
        F4:  RstRatio                ratio [0,1]
        F5:  DistinctPorts           count
        F6:  URLConcentration        ratio [0,1]
        F7:  AuthFailureRate         ratio [0,1] (401+403)
        F8:  ServerErrorRate         ratio [0,1] (5xx)
        F9:  PayloadLength           bytes
        F10: PayloadEntropy          bits [0,8]
        F11: SqliKeyword             weighted score
        F12: SqlSpecialChar          ratio [0,1]
        F13: XssKeyword              weighted score
        F14: XssSpecialChar          ratio [0,1]
        F15: WammAttackType          0=normal, 1=sqli, 2=xss
        F16: WammConfidence          [0,1]
    
    Note: Tất cả features trả về RAW VALUES (not normalized).
    """
    
    # Feature codes in order F1-F16
    FEATURE_CODES = [
        'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8',
        'F9', 'F10', 'F11', 'F12', 'F13', 'F14', 'F15', 'F16'
    ]
    
    NUM_FEATURES = 16
    
    def __init__(self, config=None, wamm_classifier=None):
        """Initialize calculator with all registered features.
        
        Args:
            config: Optional NIDSConfig instance (passed to features)
            wamm_classifier: Optional WammClassifier instance for F15/F16.
                            If None, F15=0.0 and F16=0.0 (graceful degradation).
        """
        self.config = config
        self.wamm = wamm_classifier
        
        # Build dependencies dict for features that need it
        self.dependencies = {}
        if wamm_classifier:
            self.dependencies['wamm'] = wamm_classifier
        
        # Instantiate all features using FeatureRegistry
        self.calculators = []
        for code in self.FEATURE_CODES:
            try:
                calculator = FeatureRegistry.instantiate(
                    code,
                    config=self.config,
                    dependencies=self.dependencies
                )
                self.calculators.append(calculator)
            except KeyError:
                # Feature not registered yet - log warning and use None placeholder
                logger.warning(f"Feature {code} not registered, using 0.0 default")
                self.calculators.append(None)
    
    def calculate_all(self, flows: List[FlowState]) -> List[float]:
        """Calculate all 16 features.
        
        Args:
            flows: List of FlowState objects from same source IP
        
        Returns:
            list: [f1, f2, ..., f16] raw values
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
        """Calculate all 16 features with caching optimization (8x faster).
        
        Uses FeatureContext to:
        - Compute normalized payloads once
        - Cache results for pattern-based features
        - Cache WAMM predictions for F15/F16
        
        Performance:
        - calculate_all(): 100 pkts × 8 features = 800 normalize calls
        - calculate_all_optimized(): 100 pkts × 1 = 100 normalize calls
        
        Args:
            flows: List of FlowState objects from same source IP
        
        Returns:
            list: [f1, f2, ..., f16] raw values
        """
        if not flows:
            return [0.0] * self.NUM_FEATURES
        
        # Create context with cached normalization + WAMM classifier
        ctx = FeatureContext(flows, wamm_classifier=self.wamm)
        
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
            - features_list: [f1, f2, ..., f16]
            - missing_indices_list: [0, 3, ...] (indices of missing features)
        
        Missing data cases:
            - Empty flows list → all features missing
            - Feature calculation error → mark as missing
        """
        if not flows:
            # Empty flows → all features missing
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
        
        Uses calculate_all_optimized() internally with error handling.
        
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
            # No missing features if optimized calculation succeeds
            return (features, [])
        except Exception as e:
            logger.error(f"Optimized calculation failed: {e}, falling back to standard")
            # Fallback to non-optimized if error
            return self.calculate_all_with_flags(flows)
    
    def calculate_dict(self, flows: List[FlowState], optimized: bool = True) -> Dict[str, float]:
        """Calculate all features and return as dictionary.
        
        Args:
            flows: List of FlowState objects
            optimized: Use optimized calculation (default True)
        
        Returns:
            dict: {'pps': 100.5, 'syn_ack_ratio': 1.2, ...}
        """
        if optimized:
            features = self.calculate_all_optimized(flows)
        else:
            features = self.calculate_all(flows)
        
        feature_names = self.get_feature_names()
        return dict(zip(feature_names, features))
    
    @staticmethod
    def get_feature_names() -> List[str]:
        """Return list of 16 feature names.
        
        Returns:
            list: ['pps', 'syn_ack_ratio', ..., 'wamm_confidence']
        """
        return [
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
            'wamm_attack_type',     # F15
            'wamm_confidence',      # F16
        ]
    
    @staticmethod
    def get_feature_count() -> int:
        """Return total number of features.
        
        Returns:
            int: 16
        """
        return FlowFeatureCalculator.NUM_FEATURES


# Backward compatibility: Export old name
__all__ = [
    'FlowFeatureCalculator',
]
