"""Đặc trưng cấp mạng (F1-F5) - Tái cấu trúc với kiến trúc plugin.

Các đặc trưng cấp mạng phát hiện tấn công tầng mạng như DDoS, SYN Flood, Port Scan.

Đặc trưng:
- F1: PacketRate - Số gói tin mỗi giây (phát hiện DDoS, Flood)
- F2: SynAckRatio - Tỷ lệ SYN/ACK (phát hiện SYN Flood)
- F3: InterArrivalTime - Thời gian trung bình giữa các gói tin (phát hiện tấn công tự động)
- F4: RstRatio - Tỷ lệ gói RST (phát hiện Port Scan, lỗi kết nối)
- F5: DistinctPorts - Số cổng đích duy nhất (phát hiện Port Scan)
"""

import logging
from typing import List, Optional
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature

logger = logging.getLogger(__name__)


@register_feature(FeatureMetadata(
    name="PacketRate",
    code="F1",
    description="Số gói tin mỗi giây - phát hiện DDoS và Flood",
    category="network",
    depends_on=None
))
class F1_PacketRate(FeatureBase):
    """
    F1: TỐC ĐỘ GÓI TIN (Packets per second)
    
    Công thức: total_packets / window_size
    
    Ứng dụng:
    - Phát hiện DDoS, Flood attacks
    - Normal: 10-100 gói/giây
    - Attack: 1000+ gói/giây
    
    Thứ tự ưu tiên logic:
    1. Dùng 'analysis_window_size' (từ công cụ cửa sổ trượt)
    2. Dùng 'window_size' (từ FlowState)
    3. Dùng tổng thời gian (fallback cho PCAP tĩnh)
    
    Returns:
        Giá trị thô (gói/giây), chưa chuẩn hóa
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tốc độ gói tin - trả về giá trị thô (gói/giây)."""
        if not flows:
            return 0.0

        # Tính tổng gói tin từ tất cả flows
        total_packets = float(sum(f.get_packet_count() for f in flows))
        first_flow = flows[0]
        
        # 1. Thử analysis_window_size (được đặt bởi công cụ cửa sổ trượt)
        window_size = getattr(first_flow, 'analysis_window_size', None)
        
        # 2. Thử window_size từ FlowState (được đặt bởi core/flow_manager.py)
        if window_size is None or window_size <= 0:
            window_size = getattr(first_flow, 'window_size', None)
            
        # Tính tốc độ nếu có window_size hợp lệ
        if window_size and window_size > 0:
            return total_packets / window_size
            
        # 3. Fallback: Dùng thời gian flow (cho PCAP tĩnh không có cấu hình window)
        start_times = [f.created_at for f in flows]
        end_times = [f.last_update for f in flows]
        
        if not start_times or not end_times:
            return 0.0
            
        # Tính thời gian thực tế từ bắt đầu sớm nhất đến kết thúc muộn nhất
        total_duration = max(end_times) - min(start_times)
        
        if total_duration > 0.000001:
            return float(total_packets) / total_duration
            
        # Nếu thời gian thực tế bằng 0 (ví dụ: flow 1 gói), trả về 0.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SynAckRatio",
    code="F2",
    description="Tỷ lệ SYN/ACK - phát hiện SYN Flood",
    category="network",
    depends_on=None
))
class F2_SynAckRatio(FeatureBase):
    """
    F2: TỶ LỆ SYN/ACK
    
    Công thức: SYN_count / max(ACK_count, 1)
    
    Ứng dụng:
    - Phát hiện SYN Flood attack
    - Normal: SYN và ACK cân bằng (~1.0)
    - Attack: SYN >> ACK (ratio > 10)
    
    Returns:
        Giá trị thô, chưa chuẩn hóa
        - 0 = Không có traffic TCP
        - 1 = SYN và ACK cân bằng
        - >1 = SYN nhiều hơn ACK (nghi ngờ SYN Flood)
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ SYN/ACK - trả về giá trị thô."""
        total_syn = 0
        total_ack = 0
        
        for f in flows:
            flags = f.get_fwd_tcp_flags_count()
            total_syn += flags['SYN']
            total_ack += flags['ACK']
        
        # Tránh chia cho 0: nếu ACK=0, dùng 1
        if total_ack == 0:
            # Nếu ACK=0 và SYN>0 → ratio = SYN (rất cao, dấu hiệu SYN Flood)
            # Nếu ACK=0 và SYN=0 → ratio = 0 (không có traffic TCP)
            return float(total_syn)
        
        return float(total_syn) / float(total_ack)


@register_feature(FeatureMetadata(
    name="InterArrivalTime",
    code="F3",
    description="Thời gian trung bình giữa các gói tin - phát hiện tấn công tự động",
    category="network",
    depends_on=None
))
class F3_InterArrivalTime(FeatureBase):
    """
    F3: THỜI GIAN GIỮA CÁC GÓI TIN (IAT)
    
    Công thức: avg(timestamp[i+1] - timestamp[i]) cho các gói tin chiều xuôi
    
    Ứng dụng:
    - Phát hiện tấn công tự động (IAT rất thấp và đều đặn)
    - Normal: ~0.1-1.0 giây (hành vi người dùng)
    - Attack: ~0.001 giây (tấn công có script)
    
    Returns:
        Giá trị thô (giây), chưa chuẩn hóa
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính thời gian trung bình giữa các gói tin chiều xuôi."""
        timestamps = []
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                if pkt.timestamp:
                    timestamps.append(pkt.timestamp)
        
        if len(timestamps) < 2:
            return 0.0
        
        # Sắp xếp theo thời gian
        timestamps.sort()
        
        # Tính delta giữa các gói tin liên tiếp
        deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        
        # Trả về trung bình
        return sum(deltas) / len(deltas) if deltas else 0.0


@register_feature(FeatureMetadata(
    name="RstRatio",
    code="F4",
    description="Tỷ lệ gói RST - phát hiện Port Scan và lỗi kết nối",
    category="network",
    depends_on=None
))
class F4_RstRatio(FeatureBase):
    """
    F4: TỶ LỆ RST
    
    Công thức: RST_count / max(total_bwd_packets, 1)
    
    Ứng dụng:
    - Phát hiện Port Scan (server trả RST cho các cổng đóng)
    - Phát hiện lỗi kết nối
    - Normal: ~0 (kết nối được thiết lập thành công)
    - Attack Port Scan: > 0.5 (nhiều cổng đóng trả RST)
    
    Returns:
        Ratio [0, 1], chưa chuẩn hóa
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ RST từ các gói tin chiều ngược."""
        total_rst = 0
        total_bwd = 0
        
        for f in flows:
            bwd_flags = f.get_bwd_tcp_flags_count()
            total_rst += bwd_flags.get('RST', 0)
            total_bwd += f.get_bwd_packet_count()
        
        if total_bwd == 0:
            return 0.0
        
        return float(total_rst) / float(total_bwd)


@register_feature(FeatureMetadata(
    name="DistinctPorts",
    code="F5",
    description="Số cổng đích duy nhất - phát hiện Port Scan",
    category="network",
    depends_on=None
))
class F5_DistinctPorts(FeatureBase):
    """
    F5: SỐ CỔNG ĐÍCH DUY NHẤT
    
    Công thức: len(unique_dst_ports)
    
    Ứng dụng:
    - Phát hiện Port Scan attack
    - Normal: 1-5 cổng (web, email, v.v.)
    - Attack Port Scan: 50-1000+ cổng
    
    Returns:
        Số cổng (số nguyên dạng float), chưa chuẩn hóa
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Đếm số cổng đích duy nhất từ tất cả flows."""
        all_ports = set()
        for f in flows:
            all_ports.update(f.get_distinct_ports())
        return float(len(all_ports))


# Export tất cả đặc trưng
__all__ = [
    'F1_PacketRate',
    'F2_SynAckRatio',
    'F3_InterArrivalTime',
    'F4_RstRatio',
    'F5_DistinctPorts',
]
