"""Đặc trưng cấp ứng dụng (F6-F8) - Tái cấu trúc với kiến trúc plugin.

Các đặc trưng cấp ứng dụng phát hiện tấn công tầng ứng dụng.

Đặc trưng:
- F6: URLConcentration    - Tỷ lệ tập trung URL (phát hiện Brute Force, L7 DDoS)
- F7: HttpIatUniformity   - Độ đồng đều thời gian giữa HTTP request (phát hiện Brute Force bot)
- F8: RequestSizeUniformity - Độ đồng đều kích thước payload HTTP (phát hiện Brute Force)
"""

import logging
from typing import List
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature

logger = logging.getLogger(__name__)


@register_feature(FeatureMetadata(
    name="URLConcentration",
    code="F6",
    description="Tỷ lệ tập trung URL - phát hiện Brute Force và L7 DDoS",
    category="application",
    depends_on=None
))
class F6_URLConcentration(FeatureBase):
    """
    F6: URL CONCENTRATION (TẬP TRUNG URL)

    Công thức: max_requests_to_single_url / total_requests

    Ứng dụng:
    - Phát hiện Brute Force (spam 1 endpoint như /login)
    - Phát hiện L7 DDoS (flood 1 URL)
    - Normal: ~0.1-0.3 (nhiều URL khác nhau)
    - Attack: ~0.9-1.0 (spam 1 URL)

    Note: URL được normalize bỏ query params để group các request giống nhau

    Returns:
        Ratio [0, 1], chưa chuẩn hóa
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ tập trung URL từ các HTTP request chiều xuôi."""
        url_counts = {}
        total_requests = 0

        for f in flows:
            for pkt in f.get_fwd_packets():
                if getattr(pkt, 'has_http', False) and getattr(pkt, 'http_uri', None):
                    # Chuẩn hóa: bỏ query params để nhóm các request tương tự
                    full_uri = pkt.http_uri
                    base_uri = full_uri.split('?')[0] if full_uri else ''

                    if base_uri:
                        url_counts[base_uri] = url_counts.get(base_uri, 0) + 1
                        total_requests += 1

        if total_requests == 0:
            return 0.0

        # Single-request window: F6=1/1=1.0 là artifact thống kê (không đủ mẫu),
        # không phải dấu hiệu tấn công. Brute force thật luôn có nhiều request liên tục.
        if total_requests < 3:
            return 0.0

        max_count = max(url_counts.values()) if url_counts else 0
        return float(max_count) / float(total_requests)


@register_feature(FeatureMetadata(
    name="HttpIatUniformity",
    code="F7",
    description="Độ đồng đều IAT giữa HTTP request - phát hiện Brute Force bot",
    category="application",
    depends_on=None
))
class F7_HttpIatUniformity(FeatureBase):
    """
    F7: HTTP IAT UNIFORMITY (ĐỘ ĐỀU NHỊP HTTP)

    Bot brute force gửi request với nhịp thời gian cực kỳ đều đặn.
    Normal user nhấn F5, click link có timing bất thường.

    Công thức:
        IATs = khoảng cách thời gian giữa các HTTP packet liên tiếp (per-flow)
        CV   = std_dev(IATs) / mean(IATs)
        F7   = 1.0 / (1.0 + CV)

    | Traffic                        | CV     | F7      |
    |--------------------------------|--------|---------|
    | Bot (50ms cố định giữa req)    | ≈ 0.0  | ≈ 1.0  |
    | Human (click không đều)        | > 1.5  | < 0.40 |
    | < 2 IAT values (guard)         | —      | 0.0    |

    Khác với F3 (InterArrivalTime):
    - F3: mean IAT của TẤT CẢ fwd packets (L3/4) — đo tốc độ
    - F7: CV IAT chỉ HTTP packets (L7) — đo nhịp điệu

    Phối hợp với F6 + F8:
    - {F6 cao + F7 cao + F8 cao} → Brute Force bot (spam /login đều, đồng đều)
    - {F6 cao + F7 thấp + F8 thấp} → Human F5 spam (không đều, ít packet)

    Returns:
        Float [0.0, 1.0] — cao khi nhịp đều (bot), thấp khi bất thường (người)
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính độ đồng đều IAT giữa các HTTP request chiều xuôi."""
        all_iats = []

        for f in flows:
            # Chỉ lấy timestamp của HTTP packets
            timestamps = [
                pkt.timestamp for pkt in f.get_fwd_packets()
                if getattr(pkt, 'has_http', False) and pkt.timestamp is not None
            ]
            if len(timestamps) < 2:
                continue
            timestamps.sort()
            flow_iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
            all_iats.extend(flow_iats)

        # Guard: cần ít nhất 2 IAT để tính CV có nghĩa
        if len(all_iats) < 2:
            return 0.0

        mean = sum(all_iats) / len(all_iats)
        if mean == 0:
            return 0.0

        variance = sum((x - mean) ** 2 for x in all_iats) / len(all_iats)
        cv = (variance ** 0.5) / mean
        return 1.0 / (1.0 + cv)


@register_feature(FeatureMetadata(
    name="RequestSizeUniformity",
    code="F8",
    description="Độ đồng đều kích thước payload HTTP - phát hiện Brute Force",
    category="application",
    depends_on=None
))
class F8_RequestSizeUniformity(FeatureBase):
    """
    F8: REQUEST SIZE UNIFORMITY (BRUTE FORCE PAYLOAD UNIFORMITY)

    Brute force gửi request rất đồng đều (cùng JSON structure: {"user":"x","pass":"y"}).
    Normal user có payload size biến thiên lớn.

    Công thức:
        CV  = std_dev(payload_lengths) / mean(payload_lengths)
        F8  = 1.0 / (1.0 + CV)

    | Traffic                          | CV    | F8      |
    |----------------------------------|-------|---------|
    | Brute force (identical payloads) | ≈ 0.0 | ≈ 1.0  |
    | Normal API (varied requests)     | > 2.0 | < 0.33 |
    | < 3 HTTP packets (guard)         | —     | 0.0    |

    Note: payload_length trong LayerInfo = len(URI + User-Agent + Body) — composite.
    Guard < 3 packets để tránh nhiễu khi chỉ có 1-2 request trong window.

    Returns:
        Float [0.0, 1.0] — cao khi đồng đều (bot), thấp khi đa dạng (normal)
    """

    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính độ đồng đều kích thước payload HTTP chiều xuôi."""
        payload_sizes = [
            pkt.payload_length
            for f in flows
            for pkt in f.get_fwd_packets()
            if getattr(pkt, 'has_http', False) and getattr(pkt, 'has_payload', False)
        ]

        if len(payload_sizes) < 3:
            return 0.0

        mean = sum(payload_sizes) / len(payload_sizes)
        if mean == 0:
            return 0.0

        variance = sum((x - mean) ** 2 for x in payload_sizes) / len(payload_sizes)
        cv = (variance ** 0.5) / mean
        return 1.0 / (1.0 + cv)


# Backward-compatible aliases — chỉ dùng bởi test/_archive/, KHÔNG dùng trong code mới
# Tên cũ (AuthFailureRate/ServerErrorRate) không còn mô tả đúng chức năng hiện tại.
F7_AuthFailureRate = F7_HttpIatUniformity
F8_ServerErrorRate = F8_RequestSizeUniformity


# Export theo tên thật — alias KHÔNG được export ra ngoài package
__all__ = [
    'F6_URLConcentration',
    'F7_HttpIatUniformity',
    'F8_RequestSizeUniformity',
]
