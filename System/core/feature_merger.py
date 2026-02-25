"""Feature Merger - Ghép network và log features thành vector 20 features.

Kết hợp kết quả từ NetworkSensor (F1-F11) và NginxLogSensor
(F6-F8, F12-F20) thành một vector 20 features hoàn chỉnh.

Tương quan:
- Merge theo src_ip (IP khớp tự nhiên giữa Scapy và nginx $remote_addr)
- Thời gian đồng bộ qua window boundaries chung

Dữ liệu thiếu:
- Nếu chỉ có network features: log features = 0.0
- Nếu chỉ có log features: network features = 0.0
- Cả hai thiếu: vector toàn 0.0
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set

from feature.calculator import FlowFeatureCalculator


# =============================================================================
# LỚP DỮ LIỆU
# =============================================================================

@dataclass
class MergedFeatureVector:
    """20-feature vector hoàn chỉnh từ merged sensors."""
    timestamp: float
    src_ip: str
    features: List[float]
    feature_names: List[str] = field(default_factory=list)
    network_available: bool = True
    log_available: bool = True
    packet_count: int = 0
    request_count: int = 0


# =============================================================================
# FEATURE MERGER
# =============================================================================

# Phân bổ features
NETWORK_FEATURES: Set[str] = {'F1', 'F2', 'F3', 'F4', 'F5', 'F9', 'F10', 'F11'}
LOG_FEATURES: Set[str] = {
    'F6', 'F7', 'F8',
    'F12',
    'F13', 'F14', 'F15', 'F16', 'F17',
    'F18', 'F19', 'F20',
}


class FeatureMerger:
    """Ghép kết quả NetworkSensor và NginxLogSensor.

    Lắp ráp 20 features theo thứ tự FlowFeatureCalculator.FEATURE_CODES.
    Features thiếu mặc định 0.0.
    """

    FEATURE_ORDER = FlowFeatureCalculator.FEATURE_CODES  # 20 features theo thứ tự
    FEATURE_NAMES = FlowFeatureCalculator.get_feature_names()

    def merge(self, network_features: Optional[Dict[str, float]],
              log_features: Optional[Dict[str, float]],
              window_end: float, src_ip: str,
              packet_count: int = 0,
              request_count: int = 0) -> MergedFeatureVector:
        """Ghép các tập feature thành một vector 20 features.

        Args:
            network_features: Dict {feature_code: value} từ NetworkSensor
            log_features: Dict {feature_code: value} từ NginxLogSensor
            window_end: Timestamp kết thúc window
            src_ip: Địa chỉ IP nguồn
            packet_count: Tổng packets từ NetworkSensor
            request_count: Tổng requests từ NginxLogSensor

        Returns:
            MergedFeatureVector với 20 features theo FEATURE_ORDER
        """
        feature_map: Dict[str, float] = {}

        if network_features:
            feature_map.update(network_features)

        if log_features:
            feature_map.update(log_features)

        # Lắp ráp theo FEATURE_ORDER (20 features)
        features = [feature_map.get(code, 0.0) for code in self.FEATURE_ORDER]

        return MergedFeatureVector(
            timestamp=window_end,
            src_ip=src_ip,
            features=features,
            feature_names=self.FEATURE_NAMES,
            network_available=network_features is not None,
            log_available=log_features is not None,
            packet_count=packet_count,
            request_count=request_count,
        )

    def merge_all(self, network_results: Dict[str, dict],
                  log_results: Dict[str, dict],
                  window_end: float) -> List[MergedFeatureVector]:
        """Ghép kết quả từ cả hai sensors cho tất cả src_ip.

        Args:
            network_results: {src_ip: NetworkFeatureResult}
            log_results: {src_ip: LogFeatureResult}
            window_end: Timestamp kết thúc window

        Returns:
            Danh sách MergedFeatureVector, mỗi src_ip một vector
        """
        all_src_ips = set()
        if network_results:
            all_src_ips.update(network_results.keys())
        if log_results:
            all_src_ips.update(log_results.keys())

        vectors = []
        for src_ip in sorted(all_src_ips):
            net_result = network_results.get(src_ip) if network_results else None
            log_result = log_results.get(src_ip) if log_results else None

            net_features = net_result.features if net_result else None
            log_features = log_result.features if log_result else None
            pkt_count = net_result.packet_count if net_result else 0
            req_count = log_result.request_count if log_result else 0

            merged = self.merge(
                network_features=net_features,
                log_features=log_features,
                window_end=window_end,
                src_ip=src_ip,
                packet_count=pkt_count,
                request_count=req_count,
            )
            vectors.append(merged)

        return vectors

    def to_dict(self, vector: MergedFeatureVector) -> dict:
        """Chuyển MergedFeatureVector thành dict có thể serialize JSON."""
        result = {
            'timestamp': vector.timestamp,
            'src_ip': vector.src_ip,
            'packet_count': vector.packet_count,
            'request_count': vector.request_count,
            'network_available': vector.network_available,
            'log_available': vector.log_available,
        }

        # Thêm features kèm tên
        for name, value in zip(self.FEATURE_NAMES, vector.features):
            result[name] = value

        return result
