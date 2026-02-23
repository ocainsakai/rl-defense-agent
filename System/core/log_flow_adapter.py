"""Log Flow Adapter - Adapts nginx log entries to FlowState/LayerInfo interface.

Cho phép các feature calculators hiện tại (F6-F30) hoạt động với dữ liệu
từ nginx access log mà KHÔNG cần sửa đổi code calculator.

Design Pattern: Adapter (GoF)
- LogLayerInfo adapts log entry → LayerInfo interface (forward packet)
- LogResponseLayerInfo adapts status code → LayerInfo interface (backward packet)
- LogFlowState adapts grouped log entries → FlowState interface

Compatibility:
- HttpPayloadExtractor.build_composite_payload() dùng getattr() → tương thích
- FeatureContext caching dùng id(pkt) → tương thích
- Tất cả 22 calculators (F6-F30) dùng getattr() → tương thích
"""

from typing import List, Dict, Set, Optional

from core.iflow_state import IFlowState


class LogLayerInfo:
    """Adapts a log entry to look like a LayerInfo for feature calculators.

    Represents a FORWARD packet (client request) extracted from nginx log.
    """

    def __init__(self, remote_addr: str, timestamp: float, method: str,
                 path: str, user_agent: str, host: str = "",
                 content_length: int = 0, request_id: str = "",
                 packet_number: int = 0):
        # Metadata
        self.timestamp = timestamp
        self.packet_number = packet_number

        # IP layer (minimal)
        self.has_ip = True
        self.ip_version = 4
        self.src_ip = remote_addr
        self.dst_ip = None
        self.ttl = None
        self.ip_len = None
        self.protocol = 6  # TCP

        # TCP layer (minimal - no flags from log)
        self.has_tcp = True
        self.tcp_sport = 0
        self.tcp_dport = 443
        self.tcp_flags = None
        self.tcp_seq = None
        self.tcp_ack = None
        self.tcp_window = None

        # HTTP layer
        self.has_http = True
        self.http_method = method
        self.http_uri = path
        self.http_host = host
        self.http_user_agent = user_agent
        self.http_status = None  # Status is on response, not request
        self.x_real_ip = None
        self.x_request_id = request_id

        # DNS layer
        self.has_dns = False
        self.dns_query = None

        # Payload: composite from URI + User-Agent
        composite = self._build_composite(path, user_agent)
        self.has_payload = bool(composite)
        self.payload_bytes = composite
        self.payload_length = len(composite)

    @staticmethod
    def _build_composite(path: str, user_agent: str) -> bytes:
        """Build composite payload: [URI] + [User-Agent] (no body from log)."""
        parts = []
        if path:
            parts.append(path.encode('utf-8', errors='ignore'))
        if user_agent:
            parts.append(user_agent.encode('utf-8', errors='ignore'))
        return b' '.join(parts) if parts else b''

    @property
    def is_reset(self) -> bool:
        return False


class LogResponseLayerInfo:
    """Adapts response info from log for backward packet simulation.

    Represents a BACKWARD packet (server response) with HTTP status code.
    Used by F7 (AuthFailureRate) and F8 (ServerErrorRate).
    """

    def __init__(self, remote_addr: str, timestamp: float, status: int,
                 packet_number: int = 0):
        # Metadata
        self.timestamp = timestamp
        self.packet_number = packet_number

        # IP layer
        self.has_ip = True
        self.ip_version = 4
        self.src_ip = None
        self.dst_ip = remote_addr
        self.ttl = None
        self.ip_len = None
        self.protocol = 6

        # TCP layer
        self.has_tcp = True
        self.tcp_sport = 443
        self.tcp_dport = 0
        self.tcp_flags = 'A'  # ACK
        self.tcp_seq = None
        self.tcp_ack = None
        self.tcp_window = None

        # HTTP layer - status code is the key value
        self.has_http = True
        self.http_method = None
        self.http_uri = None
        self.http_host = None
        self.http_user_agent = None
        self.http_status = status
        self.x_real_ip = None
        self.x_request_id = None

        # DNS
        self.has_dns = False
        self.dns_query = None

        # No payload for response adapter
        self.has_payload = False
        self.payload_bytes = None
        self.payload_length = 0

    @property
    def is_reset(self) -> bool:
        return False


class LogFlowState(IFlowState):
    """Adapts grouped log entries to FlowState interface.

    Groups NidsLogEntry objects by src_ip and exposes them through
    the same interface as FlowState, allowing existing calculators
    to work without modification.
    """

    def __init__(self, src_ip: str, fwd_packets: List[LogLayerInfo],
                 bwd_packets: List[LogResponseLayerInfo],
                 window_size: float = 1.0):
        self._src_ip = src_ip
        self._fwd_packets = fwd_packets
        self._bwd_packets = bwd_packets
        self.window_size = window_size
        self.analysis_window_size = window_size

        self.flow_key = (src_ip, '', 0, 443, 6)
        self.created_at = fwd_packets[0].timestamp if fwd_packets else 0.0
        self.last_update = fwd_packets[-1].timestamp if fwd_packets else 0.0
        self._x_real_ip = None

    # =========================================================================
    # PACKET COUNTS
    # =========================================================================

    def get_fwd_packet_count(self) -> int:
        return len(self._fwd_packets)

    def get_bwd_packet_count(self) -> int:
        return len(self._bwd_packets)

    def get_packet_count(self) -> int:
        return len(self._fwd_packets) + len(self._bwd_packets)

    def is_empty(self) -> bool:
        return len(self._fwd_packets) == 0 and len(self._bwd_packets) == 0

    # =========================================================================
    # PACKET LISTS
    # =========================================================================

    def get_fwd_packets(self) -> list:
        return list(self._fwd_packets)

    def get_bwd_packets(self) -> list:
        return list(self._bwd_packets)

    def get_all_packets(self) -> list:
        return list(self._fwd_packets) + list(self._bwd_packets)

    # =========================================================================
    # TCP FLAGS - Log không có TCP flags, trả về empty
    # =========================================================================

    def get_fwd_tcp_flags_count(self) -> Dict[str, int]:
        return {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0}

    def get_bwd_tcp_flags_count(self) -> Dict[str, int]:
        return {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0}

    def get_tcp_flags_count(self) -> Dict[str, int]:
        return {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0}

    # =========================================================================
    # PORTS - Log traffic luôn là HTTPS (443)
    # =========================================================================

    def get_distinct_ports(self) -> Set[int]:
        return {443}

    # =========================================================================
    # PAYLOADS
    # =========================================================================

    def get_fwd_payload_lengths(self) -> List[int]:
        return [p.payload_length for p in self._fwd_packets if p.has_payload]

    def get_bwd_payload_lengths(self) -> List[int]:
        return []

    def get_payload_lengths(self) -> List[int]:
        return self.get_fwd_payload_lengths()

    def get_fwd_payloads(self) -> List[bytes]:
        return [p.payload_bytes for p in self._fwd_packets
                if p.has_payload and p.payload_bytes]

    def get_bwd_payloads(self) -> List[bytes]:
        return []

    def get_payloads(self) -> List[bytes]:
        return self.get_fwd_payloads()

    def get_reassembled_fwd_payload(self) -> bytes:
        return b''.join(self.get_fwd_payloads())

    def get_reassembled_bwd_payload(self) -> bytes:
        return b''

    def get_reassembled_payload(self) -> bytes:
        return self.get_reassembled_fwd_payload()

    # =========================================================================
    # PROPERTIES
    # =========================================================================

    @property
    def src_ip(self) -> str:
        return self._src_ip

    @property
    def dst_ip(self) -> str:
        return ''

    @property
    def src_port(self) -> int:
        return 0

    @property
    def dst_port(self) -> int:
        return 443

    @property
    def protocol(self) -> int:
        return 6

    @property
    def x_real_ip(self) -> Optional[str]:
        return self._x_real_ip

    @property
    def effective_src_ip(self) -> str:
        return self._x_real_ip if self._x_real_ip else self._src_ip

    @property
    def duration(self) -> float:
        if len(self._fwd_packets) < 2:
            return 0.0
        timestamps = [p.timestamp for p in self._fwd_packets if p.timestamp]
        if len(timestamps) < 2:
            return 0.0
        return max(timestamps) - min(timestamps)

    # =========================================================================
    # UTILITY
    # =========================================================================

    def is_expired(self, current_time: float, timeout: float) -> bool:
        return (current_time - self.last_update) > timeout

    def clear(self) -> None:
        self._fwd_packets.clear()
        self._bwd_packets.clear()
