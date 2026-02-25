"""Network Sensor - Bắt gói tin nhẹ cho network-layer features.

Capture trên interface trước nginx (r-ext) để lấy network characteristics
thật của attacker. Chỉ tính 8 features (F1-F5, F9-F11).

Thành phần:
- NetworkFeatureCalculator: Calculator cho 8 network features
- NetworkSensor: Scapy capture + flow management + tính features

Hiệu năng:
- 8 calculators cho network features (không cần HTTP parsing)
- Pure math trên packet headers: không regex, không normalization
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import List, Dict, Optional

from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from core.packet_queue import PacketQueue
from core.sniffer import NetworkSniffer
from config.nids_config import NIDSConfig, DEFAULT_CONFIG

logger = logging.getLogger(__name__)


# =============================================================================
# LỚP DỮ LIỆU
# =============================================================================

@dataclass
class NetworkFeatureResult:
    """Kết quả features từ NetworkSensor cho một src_ip."""
    src_ip: str
    window_start: float
    window_end: float
    features: Dict[str, float]
    packet_count: int = 0


# =============================================================================
# NETWORK FEATURE CALCULATOR
# =============================================================================

# Mã feature tính từ packet capture (8 features)
NETWORK_FEATURE_CODES = ['F1', 'F2', 'F3', 'F4', 'F5', 'F9', 'F10', 'F11']


class NetworkFeatureCalculator:
    """Tính F1-F5, F9-F11 từ FlowState objects.

    Chỉ khởi tạo 8 network feature calculators.
    Tất cả đều là pure math trên packet headers - không cần HTTP parsing.
    """

    def __init__(self, config=None):
        from feature.base import FeatureRegistry
        import feature.calculators  # noqa: F401 - trigger @register_feature

        self.calculators = []
        for code in NETWORK_FEATURE_CODES:
            try:
                calc = FeatureRegistry.instantiate(code, config=config)
                self.calculators.append((code, calc))
            except KeyError:
                logger.warning(f"Feature {code} not registered, skipping")

    def calculate(self, flows: list,
                  window_size: float = 1.0) -> Dict[str, float]:
        """Tính network features từ FlowState objects.

        Args:
            flows: Danh sách FlowState từ cùng source IP
            window_size: Kích thước window phân tích (giây)

        Returns:
            Dict ánh xạ feature code -> giá trị thô
        """
        if not flows:
            return {code: 0.0 for code, _ in self.calculators}

        # Set analysis_window_size cho F1 (PacketRate)
        for flow in flows:
            flow.analysis_window_size = window_size

        results = {}
        for code, calc in self.calculators:
            try:
                results[code] = calc.calculate(flows)
            except Exception as e:
                logger.debug(f"Feature {code} failed: {e}")
                results[code] = 0.0

        return results


# =============================================================================
# NETWORK SENSOR
# =============================================================================

class NetworkSensor:
    """Sensor nhẹ dựa trên Scapy cho network-layer features.

    Capture trên interface encrypted (r-ext) và tính F1-F5, F9-F11.
    KHÔNG parse HTTP (traffic là HTTPS encrypted).

    Mô hình thread:
    - Caller chạy capture_thread (Scapy sniff)
    - Caller gọi process_packets() định kỳ
    - Caller gọi compute_features() tại ranh giới window

    Thread-safety: _flow_lock bảo vệ flow_manager
    """

    def __init__(self, window_size: float = None, config: NIDSConfig = None):
        cfg = config or DEFAULT_CONFIG
        self.window_size = window_size if window_size is not None else cfg.DEFAULT_WINDOW_SIZE

        # Thành phần chính - tái sử dụng class có sẵn, config từ NIDSConfig
        self.packet_queue = PacketQueue(max_size=cfg.MAX_QUEUE_SIZE)
        self.parser = PacketLayerExtractor()
        self.flow_manager = FlowManager(
            config=cfg,
            window_size=self.window_size,
        )
        self.calculator = NetworkFeatureCalculator(config=cfg)
        self.sniffer = NetworkSniffer()

        self._flow_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
        }

    def packet_callback(self, raw_pkt) -> None:
        """Callback cho Scapy sniff - put packet vào queue."""
        success = self.packet_queue.put(raw_pkt)
        with self._stats_lock:
            if success:
                self._stats['packets_captured'] += 1
            else:
                self._stats['packets_dropped'] += 1

    def process_packets(self) -> int:
        """Rút hết packet queue → parse → thêm vào flow manager.

        Returns:
            Số packets đã xử lý
        """
        count = 0
        while True:
            raw_pkt = self.packet_queue.get(timeout=0.0)
            if raw_pkt is None:
                break

            layer_info = self.parser.extract(raw_pkt)
            if layer_info and layer_info.has_ip:
                with self._flow_lock:
                    self.flow_manager.process_packet(layer_info)
                count += 1

        with self._stats_lock:
            self._stats['packets_processed'] += count
        return count

    def compute_features(self, window_start: float,
                         window_end: float) -> Dict[str, NetworkFeatureResult]:
        """Tính network features theo src_ip cho window hiện tại.

        Args:
            window_start: Timestamp bắt đầu window
            window_end: Timestamp kết thúc window

        Returns:
            Dict ánh xạ src_ip -> NetworkFeatureResult
        """
        with self._flow_lock:
            all_flows = self.flow_manager.get_all_flows()
            self.flow_manager.slide_window_packets(window_end)

        # Nhóm flows theo src_ip
        flows_by_src: Dict[str, list] = {}
        for flow in all_flows:
            src_ip = flow.effective_src_ip
            if src_ip not in flows_by_src:
                flows_by_src[src_ip] = []
            flows_by_src[src_ip].append(flow)

        # Tính features cho từng src_ip
        results = {}
        for src_ip, flows in flows_by_src.items():
            features = self.calculator.calculate(flows, self.window_size)
            packet_count = sum(f.get_packet_count() for f in flows)

            if packet_count > 0:
                results[src_ip] = NetworkFeatureResult(
                    src_ip=src_ip,
                    window_start=window_start,
                    window_end=window_end,
                    features=features,
                    packet_count=packet_count,
                )

        return results

    def get_stats(self) -> dict:
        """Lấy thống kê capture."""
        return self._stats.copy()
