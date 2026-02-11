"""Application-level features (F6-F8) - Refactored with plugin architecture.

Các features cấp application phát hiện application-layer attacks như Brute Force,
L7 DDoS, Authentication bypass.

Features:
- F6: URLConcentration - URL concentration ratio (detects Brute Force, L7 DDoS)
- F7: AuthFailureRate - HTTP 401+403 failure ratio (detects Brute Force login)
- F8: ServerErrorRate - HTTP 5xx error ratio (detects SQLi/DoS causing crashes)

Author: NIDS Team
Date: 2024
"""

import logging
from typing import List
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature

logger = logging.getLogger(__name__)


@register_feature(FeatureMetadata(
    name="URLConcentration",
    code="F6",
    description="URL concentration ratio - detects Brute Force and L7 DDoS",
    category="application",
    depends_on=None
))
class F6_URLConcentration(FeatureBase):
    """
    F6: URL CONCENTRATION
    
    Công thức: max_requests_to_single_url / total_requests
    
    Ứng dụng:
    - Phát hiện Brute Force (spam 1 endpoint như /login)
    - Phát hiện L7 DDoS (flood 1 URL)
    - Normal: ~0.1-0.3 (nhiều URL khác nhau)
    - Attack: ~0.9-1.0 (spam 1 URL)
    
    Note: URL được normalize bỏ query params để group các request giống nhau
    
    Returns:
        Ratio [0, 1], NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate URL concentration from forward HTTP requests."""
        url_counts = {}
        total_requests = 0
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                if getattr(pkt, 'has_http', False) and getattr(pkt, 'http_uri', None):
                    # Normalize: remove query params để group similar requests
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
    description="HTTP 401+403 failure ratio - detects Brute Force login attempts",
    category="application",
    depends_on=None
))
class F7_AuthFailureRate(FeatureBase):
    """
    F7: AUTHENTICATION FAILURE RATE (401 + 403)
    
    Công thức: (HTTP 401 + HTTP 403) / total_http_responses
    
    Ứng dụng:
    - Phát hiện Brute Force login (nhiều 401 Unauthorized)
    - Phát hiện Access Control bypass attempts (nhiều 403 Forbidden)
    - Normal: ~0 (authenticated successfully)
    - Attack: ~0.9+ (hầu hết attempts fail)
    
    Returns:
        Ratio [0, 1], NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate authentication failure rate from HTTP responses."""
        auth_failures = 0
        total_responses = 0
        
        for f in flows:
            # Check backward packets for HTTP response status codes
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
    description="HTTP 5xx error ratio - detects SQLi/DoS causing server crashes",
    category="application",
    depends_on=None
))
class F8_ServerErrorRate(FeatureBase):
    """
    F8: SERVER ERROR RATE (5xx)
    
    Công thức: HTTP 5xx / total_http_responses
    
    Ứng dụng:
    - Phát hiện SQLi gây crash (500 Internal Server Error)
    - Phát hiện DoS gây overload (503 Service Unavailable)
    - Normal: ~0 (server healthy)
    - Attack: >0.1 (nhiều server errors)
    
    Returns:
        Ratio [0, 1], NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate server error rate from HTTP responses."""
        server_errors = 0
        total_responses = 0
        
        for f in flows:
            # Check backward packets for HTTP response status codes
            for pkt in f.get_bwd_packets():
                status = getattr(pkt, 'http_status', None)
                if status:
                    total_responses += 1
                    # 5xx status codes indicate server errors
                    if 500 <= status < 600:
                        server_errors += 1
        
        if total_responses == 0:
            return 0.0
        
        return float(server_errors) / float(total_responses)


# Export all features
__all__ = [
    'F6_URLConcentration',
    'F7_AuthFailureRate',
    'F8_ServerErrorRate',
]
