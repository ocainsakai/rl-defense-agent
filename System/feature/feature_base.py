# features/base.py
"""
=============================================================================
BASE FEATURE CALCULATOR - Lớp cơ sở cho các bộ tính toán đặc trưng
=============================================================================

CHỨC NĂNG:
- Định nghĩa interface chung cho tất cả Feature Calculators
- Cung cấp cơ chế chuẩn hóa (normalize) tự động
- Quản lý metadata của features (tên, giá trị min/max)

CÁCH TẠO FEATURE MỚI:
    class Feature7_NewFeature(BaseFeatureCalculator):
        META_NAME = "new_feature"     # Tên feature
        META_MAX = 100.0              # Giá trị tối đa để chuẩn hóa
        
        def calculate_raw(self, layer_info, window) -> float:
            # Logic tính toán giá trị thô
            return raw_value
"""

import numpy as np
from abc import ABC, abstractmethod
from core.layer_info import LayerInfo
from core.window_packet import PacketWindow


class BaseFeatureCalculator(ABC):
    """
    Lớp trừu tượng cơ sở cho tất cả các Feature Calculators.
    
    THIẾT KẾ:
    - Subclass phải định nghĩa META_NAME và META_MAX ở cấp class
    - Subclass phải implement calculate_raw() để tính giá trị thô
    - normalize() sẽ tự động chuẩn hóa về [0, 1]
    - calculate() = calculate_raw() + normalize()
    """
    
    # Định nghĩa các thuộc tính mặc định (để tránh lỗi nếu quên khai báo)
    META_NAME = "unknown"   # Tên feature (subclass phải override)
    META_MAX = 1.0          # Giá trị tối đa để chuẩn hóa

    def __init__(self):
        """
        Khởi tạo calculator.
        
        LƯU Ý:
        - Tự động đọc META_NAME và META_MAX từ class con
        - min_val mặc định là 0.0 cho tất cả features (trừ F6)
        """
        # Đọc metadata từ class con (cho phép subclass override)
        self.name = self.__class__.META_NAME
        self.min_val = 0.0  # Mặc định min luôn là 0
        self.max_val = self.__class__.META_MAX
    
    @abstractmethod
    def calculate_raw(self, layer_info: LayerInfo, window: PacketWindow) -> float:
        """
        Tính toán giá trị thô của feature (CHƯA chuẩn hóa).
        
        SUBCLASS PHẢI IMPLEMENT HÀM NÀY.
        
        Args:
            layer_info (LayerInfo): Thông tin gói tin hiện tại
            window (PacketWindow): Cửa sổ chứa lịch sử gói tin
            
        Returns:
            float: Giá trị thô của feature
        """
        pass
    
    def calculate(self, layer_info: LayerInfo, window: PacketWindow) -> float:
        """
        Tính toán và chuẩn hóa giá trị feature.
        
        PIPELINE:
        1. Gọi calculate_raw() để lấy giá trị thô
        2. Gọi normalize() để chuẩn hóa về [0, 1]
        
        Args:
            layer_info (LayerInfo): Thông tin gói tin hiện tại
            window (PacketWindow): Cửa sổ chứa lịch sử gói tin
            
        Returns:
            float: Giá trị đã chuẩn hóa trong [0, 1]
        """
        raw_value = self.calculate_raw(layer_info, window)
        return self.normalize(raw_value)
    
    def normalize(self, value: float) -> float:
        """
        Chuẩn hóa giá trị về khoảng [0, 1].
        
        CÔNG THỨC: normalized = raw_value / max_val
        - Nếu raw_value > max_val: clip về 1.0
        - Nếu raw_value < 0: clip về 0.0
        
        Args:
            value (float): Giá trị thô cần chuẩn hóa
            
        Returns:
            float: Giá trị đã chuẩn hóa trong [0, 1]
        
        LƯU Ý:
        - F6 (Context Score) override hàm này vì có giá trị âm (-1, 0, 1)
        """
        if self.max_val == 0: 
            return 0.0
        normalized = value / self.max_val
        return float(np.clip(normalized, 0.0, 1.0))