"""IFlowState - Abstract Base Class for flow state objects.

Defines the contract that both FlowState (packet capture) and
LogFlowState (nginx log adapter) must implement. This ensures
feature calculators can work with either data source transparently.

Design:
- All feature calculators depend on this interface, not concrete classes
- FlowState: Real packet data from Scapy capture
- LogFlowState: Adapted nginx log entries (Adapter pattern)
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Set


class IFlowState(ABC):
    """Abstract interface for flow state objects.

    Required attributes (set by subclasses):
        flow_key: tuple — 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        window_size: float — sliding window size in seconds
        analysis_window_size: float — window size for feature calculation
        created_at: float — timestamp of flow creation
        last_update: float — timestamp of last packet/entry
    """

    # =========================================================================
    # PACKET COUNTS
    # =========================================================================

    @abstractmethod
    def get_fwd_packet_count(self) -> int:
        """Number of forward (client -> server) packets."""
        ...

    @abstractmethod
    def get_bwd_packet_count(self) -> int:
        """Number of backward (server -> client) packets."""
        ...

    @abstractmethod
    def get_packet_count(self) -> int:
        """Total packet count (forward + backward)."""
        ...

    @abstractmethod
    def is_empty(self) -> bool:
        """Check if flow has no packets."""
        ...

    # =========================================================================
    # PACKET LISTS
    # =========================================================================

    @abstractmethod
    def get_fwd_packets(self) -> list:
        """Get forward packets (LayerInfo or LogLayerInfo)."""
        ...

    @abstractmethod
    def get_bwd_packets(self) -> list:
        """Get backward packets."""
        ...

    @abstractmethod
    def get_all_packets(self) -> list:
        """Get all packets (forward + backward)."""
        ...

    # =========================================================================
    # TCP FLAGS
    # =========================================================================

    @abstractmethod
    def get_fwd_tcp_flags_count(self) -> Dict[str, int]:
        """Count TCP flags in forward packets."""
        ...

    @abstractmethod
    def get_bwd_tcp_flags_count(self) -> Dict[str, int]:
        """Count TCP flags in backward packets."""
        ...

    @abstractmethod
    def get_tcp_flags_count(self) -> Dict[str, int]:
        """Count TCP flags in all packets."""
        ...

    # =========================================================================
    # PORTS
    # =========================================================================

    @abstractmethod
    def get_distinct_ports(self) -> Set[int]:
        """Get set of distinct destination ports."""
        ...

    # =========================================================================
    # PAYLOADS
    # =========================================================================

    @abstractmethod
    def get_fwd_payload_lengths(self) -> List[int]:
        """Payload lengths of forward packets."""
        ...

    @abstractmethod
    def get_bwd_payload_lengths(self) -> List[int]:
        """Payload lengths of backward packets."""
        ...

    @abstractmethod
    def get_payload_lengths(self) -> List[int]:
        """Payload lengths of all packets."""
        ...

    @abstractmethod
    def get_fwd_payloads(self) -> List[bytes]:
        """Raw payloads of forward packets."""
        ...

    @abstractmethod
    def get_bwd_payloads(self) -> List[bytes]:
        """Raw payloads of backward packets."""
        ...

    @abstractmethod
    def get_payloads(self) -> List[bytes]:
        """Raw payloads of all packets."""
        ...

    @abstractmethod
    def get_reassembled_fwd_payload(self) -> bytes:
        """Concatenated forward payloads."""
        ...

    @abstractmethod
    def get_reassembled_bwd_payload(self) -> bytes:
        """Concatenated backward payloads."""
        ...

    @abstractmethod
    def get_reassembled_payload(self) -> bytes:
        """Concatenated all payloads."""
        ...

    # =========================================================================
    # PROPERTIES
    # =========================================================================

    @property
    @abstractmethod
    def src_ip(self) -> str:
        ...

    @property
    @abstractmethod
    def dst_ip(self) -> str:
        ...

    @property
    @abstractmethod
    def src_port(self) -> int:
        ...

    @property
    @abstractmethod
    def dst_port(self) -> int:
        ...

    @property
    @abstractmethod
    def protocol(self) -> int:
        ...

    @property
    @abstractmethod
    def effective_src_ip(self) -> str:
        """Actual client IP (prefers X-Real-IP over packet src_ip)."""
        ...

    @property
    @abstractmethod
    def duration(self) -> float:
        """Flow duration in seconds."""
        ...

    # =========================================================================
    # UTILITY
    # =========================================================================

    @abstractmethod
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """Check if flow has expired."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Clear all packets from flow."""
        ...
