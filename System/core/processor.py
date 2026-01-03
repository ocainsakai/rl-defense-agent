# core/processor.py
"""
=============================================================================
FEATURE VECTOR BUILDER - Xây dựng vector đặc trưng từ gói tin
=============================================================================

CHỨC NĂNG:
- Điều phối việc tính toán 6 features từ LayerInfo
- Quản lý PacketWindow để lưu trữ context theo thời gian
- Cung cấp API đơn giản: LayerInfo -> Vector [f1, f2, f3, f4, f5, f6]

KIẾN TRÚC:
    LayerInfo -> PacketWindow -> 6 Feature Calculators -> Vector [0-1, 0-1, ...]

6 FEATURES:
1. Packet Rate: Tốc độ gói tin/giây (phát hiện DDoS)
2. SYN/ACK Ratio: Tỷ lệ SYN trên tổng (phát hiện SYN Flood)
3. Distinct Ports: Số cổng đích khác nhau (phát hiện Port Scan)
4. Payload Length: Độ dài trung bình payload (phát hiện Buffer Overflow)
5. Fail Rate: Tỷ lệ kết nối lỗi (phát hiện Brute Force, Scan)
6. Context Score: Điểm ngữ cảnh từ payload (phát hiện SQLi, XSS, v.v.)
"""

import numpy as np
from core.layer_info import LayerInfo
from core.window_packet import PacketWindow
from feature.feature_logic import (
    Feature1_PacketRate, Feature2_SynAckRatio, Feature3_DistinctPorts,
    Feature4_PayloadLength, Feature5_FailRate, Feature6_ContextScore
)


class FeatureVectorBuilder:
    """
    Lớp điều phối việc tính toán vector đặc trưng.
    
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
                                 Mặc định 1.0s để tính features/giây.
        """
        # PacketWindow lưu trữ lịch sử gói tin theo IP
        self.window = PacketWindow(window_size)
        
        # Danh sách 6 Feature Calculators (theo thứ tự F1-F6)
        self.calculators = [
            Feature1_PacketRate(),      # F1: Packet Rate
            Feature2_SynAckRatio(),     # F2: SYN/ACK Ratio
            Feature3_DistinctPorts(),   # F3: Distinct Ports
            Feature4_PayloadLength(),   # F4: Payload Length
            Feature5_FailRate(),        # F5: Fail Rate
            Feature6_ContextScore()     # F6: Context Score
        ]

    def process_layer_info(self, layer_info: LayerInfo) -> np.ndarray:
        """
        Xử lý LayerInfo và trả về vector 6 features đã chuẩn hóa.
        
        PIPELINE:
        1. Cập nhật PacketWindow với gói tin mới
        2. Tính toán từng feature bằng calculator tương ứng
        3. Mỗi calculator tự normalize về [0, 1]
        4. Trả về numpy array [f1, f2, f3, f4, f5, f6]
        
        Args:
            layer_info (LayerInfo): Thông tin gói tin đã phân tích
            
        Returns:
            np.ndarray: Vector 6 phần tử, mỗi phần tử trong [0, 1]
        
        LƯU Ý:
        - Các giá trị đã được chuẩn hóa về [0, 1]
        - Giá trị cao hơn = nghi ngờ tấn công hơn
        """
        # Bước 1: Thêm gói tin vào cửa sổ trượt
        self.window.add(layer_info)
        
        # Bước 2: Tính toán từng feature
        vector = []
        for calc in self.calculators:
            # calc.calculate() đã bao gồm normalize
            val = calc.calculate(layer_info, self.window)
            vector.append(val)
            
        return np.array(vector)
    
    def cleanup_inactive_ips(self, min_packets: int = 10) -> int:
        """
        Dọn dẹp các IP không hoạt động để giải phóng bộ nhớ.
        
        LOGIC:
        - Xóa các IP có ít hơn min_packets gói tin
        - Gọi định kỳ (VD: mỗi 100,000 packets) để tránh tràn RAM
        
        Args:
            min_packets (int): Ngưỡng tối thiểu. IP nào có ít hơn sẽ bị xóa.
            
        Returns:
            int: Số lượng IP đã xóa.
        """
        return self.window.cleanup_inactive_ips(min_packets)