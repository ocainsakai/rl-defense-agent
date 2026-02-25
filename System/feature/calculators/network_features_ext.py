"""Đặc trưng mạng mở rộng (F9-F11) - Phát hiện SYN Flood & Port Scan.

Đặc trưng:
- F9:  AvgPayloadSize - Kích thước payload chiều xuôi trung bình (SYN Flood = 0)
- F10: FwdBwdRatio - Tỷ lệ gói tin chiều xuôi/ngược (SYN Flood >> 1)
- F11: PacketsPerPort - Số gói tin mỗi cổng duy nhất (Port Scan ~ 1)

Nguồn: Thiết kế thủ công dựa trên đặc điểm tấn công mạng.
"""

import logging
from typing import List
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature

logger = logging.getLogger(__name__)


@register_feature(FeatureMetadata(
    name="AvgPayloadSize",
    code="F9",
    description="Kích thước payload chiều xuôi trung bình - gói SYN Flood không có payload",
    category="network",
    depends_on=None
))
class F9_AvgPayloadSize(FeatureBase):
    """
    F9: KÍCH THƯỚC PAYLOAD TRUNG BÌNH

    Công thức: sum(fwd_payload_lengths) / max(fwd_packet_count, 1)

    Ứng dụng:
    - SYN Flood: Gửi SYN packets không có payload → avg = 0
    - Normal HTTP: Có payload (GET/POST requests) → avg > 0
    - Brute Force: Payload nhỏ nhưng > 0

    Returns:
        Giá trị thô (byte), chưa chuẩn hóa
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        total_payload_len = 0
        total_fwd_pkts = 0

        for f in flows:
            total_payload_len += sum(f.get_fwd_payload_lengths())
            total_fwd_pkts += f.get_fwd_packet_count()

        if total_fwd_pkts == 0:
            return 0.0

        return float(total_payload_len) / float(total_fwd_pkts)


@register_feature(FeatureMetadata(
    name="FwdBwdRatio",
    code="F10",
    description="Tỷ lệ gói tin chiều xuôi/ngược - SYN Flood có tỷ lệ cao",
    category="network",
    depends_on=None
))
class F10_FwdBwdRatio(FeatureBase):
    """
    F10: TỶ LỆ GÓI TIN CHIỀU XUÔI/NGƯỢC

    Công thức: fwd_pkts / max(bwd_pkts, 1)

    Ứng dụng:
    - SYN Flood: Client gửi SYN liên tục, server không kịp phản hồi → ratio >> 1
    - Normal TCP: Giao tiếp 2 chiều cân bằng → ratio ≈ 1
    - Port Scan: Tùy loại, SYN scan có ratio cao

    Returns:
        Giá trị thô, chưa chuẩn hóa
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        total_fwd = 0
        total_bwd = 0

        for f in flows:
            total_fwd += f.get_fwd_packet_count()
            total_bwd += f.get_bwd_packet_count()

        if total_bwd == 0:
            return float(total_fwd)

        return float(total_fwd) / float(total_bwd)


@register_feature(FeatureMetadata(
    name="PacketsPerPort",
    code="F11",
    description="Số gói tin mỗi cổng duy nhất - Port Scan có tỷ lệ ~1",
    category="network",
    depends_on=None
))
class F11_PacketsPerPort(FeatureBase):
    """
    F11: SỐ GÓI TIN MỖI CỔNG

    Công thức: fwd_pkts / max(distinct_ports, 1)

    Ứng dụng:
    - Port Scan: Quét nhiều cổng, mỗi cổng 1-2 packets → ratio ≈ 1
    - Normal: Nhiều packets trên ít cổng (web: 80, 443) → ratio cao
    - SYN Flood: Nhiều packets trên 1 cổng → ratio rất cao

    Returns:
        Giá trị thô, chưa chuẩn hóa
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        total_fwd = 0
        all_ports = set()

        for f in flows:
            total_fwd += f.get_fwd_packet_count()
            all_ports.update(f.get_distinct_ports())

        num_ports = len(all_ports)
        if num_ports == 0:
            return float(total_fwd)

        return float(total_fwd) / float(num_ports)


__all__ = [
    'F9_AvgPayloadSize',
    'F10_FwdBwdRatio',
    'F11_PacketsPerPort',
]
