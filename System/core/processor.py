# core/processor.py
"""
=============================================================================
FEATURE VECTOR BUILDER - Orchestrator
=============================================================================

CHỨC NĂNG:
- ORCHESTRATION: Kết nối FlowManager với Feature Calculators
- KHÔNG tính features trực tiếp (để feature_flow.py làm)
- Cung cấp API đơn giản: LayerInfo -> Vector [f1, f2, f3, f4, f5, f6]

KIẾN TRÚC:
    LayerInfo -> FlowManager -> FlowState -> FlowFeatureCalculator -> Vector
"""

import numpy as np
from core.layer_info import LayerInfo
from core.flow_manager import FlowManager
from feature.feature_flow import FlowFeatureCalculator


class FeatureVectorBuilder:
    """
    Lớp ORCHESTRATION - kết nối các components.
    
    KHÔNG tính features trực tiếp!
    Gọi FlowFeatureCalculator để tính.
    
    CÁCH SỬ DỤNG:
        builder = FeatureVectorBuilder(window_size=1.0)
        vector = builder.process_layer_info(layer_info)
        # vector = [f1_norm, f2_norm, f3_norm, f4_norm, f5_norm, f6_norm]
    """
    
    def __init__(self, window_size: float = 1.0):
        """
        Khởi tạo FeatureVectorBuilder.
        
        Args:
            window_size (float): Kích thước cửa sổ thời gian (giây).
        """
        # Flow Management
        self.flow_manager = FlowManager(
            window_size=window_size,
            flow_timeout=30.0,
            cleanup_interval=100
        )
        
        # Feature Calculation - Gọi class riêng
        self.feature_calculator = FlowFeatureCalculator()
        
        self.window_size = window_size

    def process_layer_info(self, layer_info: LayerInfo) -> np.ndarray:
        """
        Xử lý LayerInfo và trả về vector 6 features đã chuẩn hóa.
        
        PIPELINE:
        1. FlowManager xác định flow và direction (fwd/bwd)
        2. Lấy tất cả flows của src_ip
        3. FlowFeatureCalculator tính 6 features
        4. Trả về numpy array
        
        Args:
            layer_info (LayerInfo): Thông tin gói tin đã phân tích
            
        Returns:
            np.ndarray: Vector 6 phần tử, mỗi phần tử trong [0, 1]
        """
        # Bước 1: Process packet vào FlowManager
        flow = self.flow_manager.process_packet(layer_info)
        
        if flow is None or not layer_info.has_ip:
            return np.zeros(6)
        
        # Bước 2: Lấy tất cả flows của flow initiator (Inter-flow)
        # Quan trọng: với backward packets, layer_info.src_ip là server; ta vẫn muốn
        # tính features cho initiator/client (flow.src_ip) để F5/F6 cập nhật đúng entity.
        src_ip = flow.src_ip
        all_flows = self.flow_manager.get_flows_by_src(src_ip)
        
        # Bước 3: Gọi FlowFeatureCalculator để tính features
        vector = self.feature_calculator.calculate_all(all_flows)
        
        return np.array(vector)
    
    '''def get_raw_features(self, layer_info: LayerInfo) -> np.ndarray:
        """Lấy features chưa normalize (cho debugging)"""
        if not layer_info.has_ip:
            return np.zeros(6)

        flow = self.flow_manager.process_packet(layer_info)
        if flow is None:
            return np.zeros(6)

        src_ip = flow.src_ip
        all_flows = self.flow_manager.get_flows_by_src(src_ip)
        
        return np.array(self.feature_calculator.calculate_all_raw(all_flows))'''
    
    def cleanup_inactive_flows(self) -> int:
        """Dọn dẹp flows không hoạt động."""
        return self.flow_manager._cleanup_expired_flows()
    
    def get_stats(self) -> dict:
        """Trả về thống kê"""
        return self.flow_manager.get_stats()