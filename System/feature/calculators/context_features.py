"""Context-level features (F15-F16) - ML-based attack classification.

Các features sử dụng WAMM XGBoost classifier để phân loại payload thành:
- 0: normal
- 1: SQLi attack
- 2: XSS attack

Features:
- F15: WammAttackType - Multiclass attack classification (0/1/2)
- F16: WammConfidence - Confidence score from ML model [0.0,1.0]

Dependencies:
- FeatureContext: Caching layer for WAMM predictions
- WammClassifier: XGBoost-based ML classifier (must be injected via dependencies)

Usage:
    wamm = WammClassifier()
    calculator = FeatureRegistry.instantiate('F15', dependencies={'wamm': wamm})
    
    # Or via context:
    context = FeatureContext(flows, wamm_classifier=wamm)
    result = calculator.calculate(flows, context=context)

Author: NIDS Team
Date: 2024
"""

import logging
from typing import List, Optional
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature

logger = logging.getLogger(__name__)


from feature.context import FeatureContext


@register_feature(FeatureMetadata(
    name="WammAttackType",
    code="F15",
    description="WAMM multiclass attack type - 0=normal, 1=sqli, 2=xss",
    category="context",
    depends_on=["WammClassifier"]
))
class F15_WammAttackType(FeatureBase):
    """
    F15: WAMM ATTACK TYPE
    
    Phân loại multiclass từ WAMM XGBoost classifier:
    - 0 = normal (benign traffic)
    - 1 = sqli (SQL Injection attack)
    - 2 = xss (Cross-Site Scripting attack)
    
    Logic: 
    - Max pooling: Lấy attack_type từ packet có confidence cao nhất
    - Cache predictions trong FeatureContext để F16 tái sử dụng
    
    Returns:
        Integer (0, 1, or 2) as float, NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Get attack type from WAMM classifier (max pooling by confidence)."""
        context = kwargs.get('context')
        
        # If no context provided, try to create one with wamm from dependencies
        if not context:
            wamm = self.dependencies.get('wamm') if self.dependencies else None
            context = FeatureContext(flows, wamm_classifier=wamm)
        
        # Check if context has WAMM prediction capability
        if not hasattr(context, 'get_wamm_prediction'):
            return 0.0
        
        best_type = 0
        best_conf = 0.0
        
        # Max pooling: find packet with highest confidence
        for f in flows:
            for pkt in f.get_fwd_packets():
                attack_type, confidence = context.get_wamm_prediction(pkt)
                if confidence > best_conf:
                    best_conf = confidence
                    best_type = attack_type
        
        return float(best_type)


@register_feature(FeatureMetadata(
    name="WammConfidence",
    code="F16",
    description="WAMM confidence score - probability from ML model [0,1]",
    category="context",
    depends_on=["WammClassifier"]
))
class F16_WammConfidence(FeatureBase):
    """
    F16: WAMM CONFIDENCE SCORE
    
    Confidence score từ WAMM XGBoost predict_proba.
    
    Logic:
    - Max pooling: Lấy confidence cao nhất trong tất cả packets
    - Reuses predictions cached by F15 (efficient)
    
    Returns:
        Float [0.0, 1.0], NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Get confidence score from WAMM classifier (max pooling)."""
        context = kwargs.get('context')
        
        # If no context provided, try to create one with wamm from dependencies
        if not context:
            wamm = self.dependencies.get('wamm') if self.dependencies else None
            context = FeatureContext(flows, wamm_classifier=wamm)
        
        # Check if context has WAMM prediction capability
        if not hasattr(context, 'get_wamm_prediction'):
            return 0.0
        
        best_conf = 0.0
        
        # Max pooling: find highest confidence
        for f in flows:
            for pkt in f.get_fwd_packets():
                _, confidence = context.get_wamm_prediction(pkt)
                if confidence > best_conf:
                    best_conf = confidence
        
        return best_conf


# Export all features
__all__ = [
    'F15_WammAttackType',
    'F16_WammConfidence',
]
