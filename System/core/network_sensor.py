"""Network Sensor - Lightweight packet capture for network-layer features.

Capture trên interface trước nginx (r-ext) để lấy network characteristics
thật của attacker. Chỉ tính 8 features (F1-F5, F9-F11).

Components:
- NetworkFeatureCalculator: Subset calculator cho 8 network features
- NetworkSensor: Scapy capture + flow management + feature computation

Performance:
- 8 calculators thay vì 30: bỏ 22 payload/regex calculators
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

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
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

# Feature codes computed from packet capture (8 features)
NETWORK_FEATURE_CODES = ['F1', 'F2', 'F3', 'F4', 'F5', 'F9', 'F10', 'F11']


class NetworkFeatureCalculator:
    """Tính F1-F5, F9-F11 từ FlowState objects.

    Chỉ instantiate 8 network feature calculators (thay vì 30).
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
        """Calculate network features from FlowState objects.

        Args:
            flows: List of FlowState objects from same source IP
            window_size: Analysis window size (seconds)

        Returns:
            Dict mapping feature code to raw value
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
    """Lightweight Scapy-based sensor for network-layer features.

    Capture trên interface encrypted (r-ext) và tính F1-F5, F9-F11.
    KHÔNG parse HTTP (traffic là HTTPS encrypted).

    Thread model:
    - Caller runs capture_thread (Scapy sniff)
    - Caller calls process_packets() periodically
    - Caller calls compute_features() at window boundaries

    Thread-safety: _flow_lock protects flow_manager
    """

    def __init__(self, window_size: float = 1.0, config=None):
        self.window_size = window_size

        # Core components - reuse existing classes
        self.packet_queue = PacketQueue(max_size=10000)
        self.parser = PacketLayerExtractor()
        self.flow_manager = FlowManager(
            window_size=window_size,
            flow_timeout=window_size * 10,
        )
        self.calculator = NetworkFeatureCalculator(config=config)
        self.sniffer = NetworkSniffer()

        self._flow_lock = threading.Lock()
        self._stats = {
            'packets_captured': 0,
            'packets_processed': 0,
            'packets_dropped': 0,
        }

    def packet_callback(self, raw_pkt) -> None:
        """Callback cho Scapy sniff - put packet vào queue."""
        success = self.packet_queue.put(raw_pkt)
        if success:
            self._stats['packets_captured'] += 1
        else:
            self._stats['packets_dropped'] += 1

    def process_packets(self) -> int:
        """Drain packet queue → parse → add to flow manager.

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

        self._stats['packets_processed'] += count
        return count

    def compute_features(self, window_start: float,
                         window_end: float) -> Dict[str, NetworkFeatureResult]:
        """Compute network features per src_ip for current window.

        Args:
            window_start: Window start timestamp
            window_end: Window end timestamp

        Returns:
            Dict mapping src_ip to NetworkFeatureResult
        """
        with self._flow_lock:
            all_flows = self.flow_manager.get_all_flows()
            self.flow_manager.slide_window_packets(window_end)

        # Group flows by src_ip
        flows_by_src: Dict[str, list] = {}
        for flow in all_flows:
            src_ip = flow.effective_src_ip
            if src_ip not in flows_by_src:
                flows_by_src[src_ip] = []
            flows_by_src[src_ip].append(flow)

        # Calculate features per src_ip
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
