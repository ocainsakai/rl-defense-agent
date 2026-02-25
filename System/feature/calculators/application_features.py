"""Đặc trưng cấp ứng dụng (F6-F8) - Tái cấu trúc với kiến trúc plugin.

Các đặc trưng cấp ứng dụng phát hiện tấn công tầng ứng dụng như Brute Force,
L7 DDoS, xác thực bypass.

Đặc trưng:
- F6: URLConcentration - Tỷ lệ tập trung URL (phát hiện Brute Force, L7 DDoS)
- F7: AuthFailureRate - Tỷ lệ lỗi HTTP 401+403 (phát hiện Brute Force login)
- F8: ServerErrorRate - Tỷ lệ lỗi HTTP 5xx (phát hiện SQLi/DoS gây crash)
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
        
        max_count = max(url_counts.values()) if url_counts else 0
        return float(max_count) / float(total_requests)


@register_feature(FeatureMetadata(
    name="AuthFailureRate",
    code="F7",
    description="Tỷ lệ lỗi HTTP 401+403 - phát hiện Brute Force login",
    category="application",
    depends_on=None
))
class F7_AuthFailureRate(FeatureBase):
    """
    F7: TỶ LỆ LỖI XÁC THỰC (401 + 403)
    
    Công thức: (HTTP 401 + HTTP 403) / total_http_responses
    
    Ứng dụng:
    - Phát hiện Brute Force login (nhiều 401 Unauthorized)
    - Phát hiện Access Control bypass attempts (nhiều 403 Forbidden)
    - Normal: ~0 (xác thực thành công)
    - Attack: ~0.9+ (hầu hết attempts thất bại)
    
    Returns:
        Ratio [0, 1], chưa chuẩn hóa
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ lỗi xác thực từ các HTTP response."""
        auth_failures = 0
        total_responses = 0
        
        for f in flows:
            # Kiểm tra packets chiều ngược để lấy mã trạng thái HTTP response
            for pkt in f.get_bwd_packets():
                status = getattr(pkt, 'http_status', None)
                if status:
                    total_responses += 1
                    if status == 401 or status == 403:
                        auth_failures += 1
        
        if total_responses == 0:
            return 0.0
        
        return float(auth_failures) / float(total_responses)


@register_feature(FeatureMetadata(
    name="ServerErrorRate",
    code="F8",
    description="Tỷ lệ lỗi HTTP 5xx - phát hiện SQLi/DoS gây crash server",
    category="application",
    depends_on=None
))
class F8_ServerErrorRate(FeatureBase):
    """
    F8: TỶ LỆ LỖI SERVER (5xx)
    
    Công thức: HTTP 5xx / total_http_responses
    
    Ứng dụng:
    - Phát hiện SQLi gây crash (500 Internal Server Error)
    - Phát hiện DoS gây overload (503 Service Unavailable)
    - Normal: ~0 (server hoạt động tốt)
    - Attack: >0.1 (nhiều server errors)
    
    Returns:
        Ratio [0, 1], chưa chuẩn hóa
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Tính tỷ lệ lỗi server từ các HTTP response."""
        server_errors = 0
        total_responses = 0
        
        for f in flows:
            # Kiểm tra packets chiều ngược để lấy mã trạng thái HTTP response
            for pkt in f.get_bwd_packets():
                status = getattr(pkt, 'http_status', None)
                if status:
                    total_responses += 1
                    # Mã trạng thái 5xx biểu thị lỗi server
                    if 500 <= status < 600:
                        server_errors += 1
        
        if total_responses == 0:
            return 0.0
        
        return float(server_errors) / float(total_responses)


# Export tất cả đặc trưng
__all__ = [
    'F6_URLConcentration',
    'F7_AuthFailureRate',
    'F8_ServerErrorRate',
]
