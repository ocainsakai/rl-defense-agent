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
    F2: TỶ LỆ SYN/SYN-ACK

    Công thức: fwd_SYN / bwd_SYN
    - fwd_SYN  : SYN packet từ client (muốn kết nối)
    - bwd_SYN  : SYN-ACK packet từ server (phản hồi, có cả flag SYN+ACK)

    TCP 3-way handshake bình thường:
        Client → SYN        (fwd_SYN += 1)
        Server ← SYN-ACK   (bwd_SYN += 1)
        Client → ACK
    → ratio ≈ 1.0

    SYN Flood:
        Client → SYN x10000  (fwd_SYN = 10000)
        Server ← SYN-ACK x~  (bwd_SYN thấp vì server không kịp)
    → ratio >> 1.0

    Spoofed SYN Flood (IP giả):
        Server gửi SYN-ACK đến IP giả → không về collector → bwd_SYN = 0
    → trả về float(fwd_SYN) làm signal cường độ (unbounded)

    Returns:
        Giá trị thô, chưa chuẩn hóa
        - 0.0  = Không có TCP SYN (không có kết nối nào)
        - ~1.0 = Bình thường (mỗi SYN đều có SYN-ACK)
        - >1.0 = SYN Flood (server không kịp phản hồi)
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ fwd_SYN / bwd_SYN - phản ánh đúng SYN Flood."""
        total_fwd_syn = 0
        total_bwd_syn = 0

        for f in flows:
            fwd_flags = f.get_fwd_tcp_flags_count()
            bwd_flags = f.get_bwd_tcp_flags_count()
            total_fwd_syn += fwd_flags['SYN']
            total_bwd_syn += bwd_flags['SYN']  # bwd SYN = SYN-ACK từ server

        if total_bwd_syn == 0:
            # Spoofed flood: không có phản hồi từ server → dùng fwd_SYN làm signal
            return float(total_fwd_syn)

        return float(total_fwd_syn) / float(total_bwd_syn)


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
        """Tính thời gian trung bình giữa các gói tin chiều xuôi (per-flow, rồi aggregate)."""
        all_iats = []

        for f in flows:
            # Thu thập timestamps per-flow — cho phép timestamp=0.0
            timestamps = [
                pkt.timestamp for pkt in f.get_fwd_packets()
                if pkt.timestamp is not None
            ]
            if len(timestamps) < 2:
                continue
            timestamps.sort()
            flow_iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
            all_iats.extend(flow_iats)

        return sum(all_iats) / len(all_iats) if all_iats else 0.0


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

    Công thức: (fwd_RST + bwd_RST) / total_packets

    Đếm RST cả 2 chiều:
    - bwd_RST: Server trả RST cho port đóng (SYN Scan, Connect Scan)
    - fwd_RST: Client gửi RST sau scan (cleanup), hoặc Idle/Zombie scan

    Dùng total_packets (fwd+bwd) làm mẫu số để:
    - Tránh chia 0 khi Spoofed SYN Flood (bwd = 0)
    - Chuẩn hóa đúng ratio trong [0, 1]

    Ứng dụng:
    - Phát hiện Port Scan (RST từ closed ports)
    - Normal: ~0 (kết nối thành công, ít RST)
    - Port Scan: > 0.3 (nhiều cổng đóng trả RST)

    Returns:
        Ratio [0, 1], chưa chuẩn hóa
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ RST (cả fwd + bwd) / total_packets."""
        total_rst = 0
        total_packets = 0

        for f in flows:
            fwd_flags = f.get_fwd_tcp_flags_count()
            bwd_flags = f.get_bwd_tcp_flags_count()
            total_rst += fwd_flags.get('RST', 0) + bwd_flags.get('RST', 0)
            total_packets += f.get_packet_count()

        if total_packets == 0:
            return 0.0

        return float(total_rst) / float(total_packets)


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
