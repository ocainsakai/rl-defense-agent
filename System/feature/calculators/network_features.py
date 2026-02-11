"""Network-level features (F1-F5) - Refactored with plugin architecture.

Các features cấp mạng phát hiện network-level attacks như DDoS, SYN Flood, Port Scan.

Features:
- F1: PacketRate - Packets per second (detects DDoS, Flood)
- F2: SynAckRatio - SYN/ACK ratio (detects SYN Flood)
- F3: InterArrivalTime - Average time between packets (detects automated attacks)
- F4: RstRatio - RST packet ratio (detects Port Scan, connection issues)
- F5: DistinctPorts - Unique destination ports count (detects Port Scan)

Author: NIDS Team
Date: 2024
"""

import logging
from typing import List, Optional
from core.flow_state import FlowState
from feature.base import FeatureBase, FeatureMetadata, register_feature

logger = logging.getLogger(__name__)


@register_feature(FeatureMetadata(
    name="PacketRate",
    code="F1",
    description="Packets per second - detects DDoS and Flood attacks",
    category="network",
    depends_on=None
))
class F1_PacketRate(FeatureBase):
    """
    F1: PACKET RATE (Packets per second)
    
    Công thức: total_packets / window_size
    
    Ứng dụng:
    - Phát hiện DDoS, Flood attacks
    - Normal: 10-100 pkt/s
    - Attack: 1000+ pkt/s
    
    Priority logic:
    1. Use 'analysis_window_size' (from sliding window tool)
    2. Use 'window_size' (from FlowState)
    3. Use total duration (static PCAP fallback)
    
    Returns:
        Raw value (packets/second), NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate packet rate - returns raw value (packets/second)."""
        if not flows:
            return 0.0

        # Calculate total packets from all flows
        total_packets = float(sum(f.get_packet_count() for f in flows))
        first_flow = flows[0]
        
        # 1. Try analysis_window_size (set by sliding window tools)
        window_size = getattr(first_flow, 'analysis_window_size', None)
        
        # 2. Try window_size from FlowState (set by core/flow_manager.py)
        if window_size is None or window_size <= 0:
            window_size = getattr(first_flow, 'window_size', None)
            
        # Calculate rate if we have valid window_size
        if window_size and window_size > 0:
            return total_packets / window_size
            
        # 3. Fallback: Use flow duration (for static PCAP without window config)
        start_times = [f.created_at for f in flows]
        end_times = [f.last_update for f in flows]
        
        if not start_times or not end_times:
            return 0.0
            
        # Calculate actual duration from earliest start to latest end
        total_duration = max(end_times) - min(start_times)
        
        if total_duration > 0.000001:
            return float(total_packets) / total_duration
            
        # If duration is practically 0 (e.g. single packet flow), return 0.0
        return 0.0


@register_feature(FeatureMetadata(
    name="SynAckRatio",
    code="F2",
    description="SYN/ACK ratio - detects SYN Flood attacks",
    category="network",
    depends_on=None
))
class F2_SynAckRatio(FeatureBase):
    """
    F2: SYN/ACK RATIO
    
    Công thức: SYN_count / max(ACK_count, 1)
    
    Ứng dụng:
    - Phát hiện SYN Flood attack
    - Normal: SYN và ACK balanced (~1.0)
    - Attack: SYN >> ACK (ratio > 10)
    
    Returns:
        Raw ratio, NOT normalized
        - 0 = No TCP traffic
        - 1 = SYN and ACK balanced
        - >1 = More SYN than ACK (suspicious SYN Flood)
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate SYN/ACK ratio - returns raw value."""
        total_syn = 0
        total_ack = 0
        
        for f in flows:
            flags = f.get_fwd_tcp_flags_count()
            total_syn += flags['SYN']
            total_ack += flags['ACK']
        
        # Avoid division by zero: if ACK=0, use 1
        if total_ack == 0:
            # If ACK=0 and SYN>0 => ratio = SYN (very high, sign of SYN Flood)
            # If ACK=0 and SYN=0 => ratio = 0 (no TCP traffic)
            return float(total_syn)
        
        return float(total_syn) / float(total_ack)


@register_feature(FeatureMetadata(
    name="InterArrivalTime",
    code="F3",
    description="Average time between packets - detects automated attacks",
    category="network",
    depends_on=None
))
class F3_InterArrivalTime(FeatureBase):
    """
    F3: INTER-ARRIVAL TIME (IAT)
    
    Công thức: avg(timestamp[i+1] - timestamp[i]) for forward packets
    
    Ứng dụng:
    - Phát hiện automated attacks (very low, consistent IAT)
    - Normal: ~0.1-1.0s (human behavior)
    - Attack: ~0.001s (scripted attacks)
    
    Returns:
        Raw value (seconds), NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate average inter-arrival time from forward packets."""
        timestamps = []
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                if pkt.timestamp:
                    timestamps.append(pkt.timestamp)
        
        if len(timestamps) < 2:
            return 0.0
        
        # Sort by time
        timestamps.sort()
        
        # Calculate delta between consecutive packets
        deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        
        # Return average
        return sum(deltas) / len(deltas) if deltas else 0.0


@register_feature(FeatureMetadata(
    name="RstRatio",
    code="F4",
    description="RST packet ratio - detects Port Scan and connection issues",
    category="network",
    depends_on=None
))
class F4_RstRatio(FeatureBase):
    """
    F4: RST RATIO
    
    Công thức: RST_count / max(total_bwd_packets, 1)
    
    Ứng dụng:
    - Phát hiện Port Scan (server returns RST for closed ports)
    - Phát hiện connection issues
    - Normal: ~0 (connections established successfully)
    - Attack Port Scan: > 0.5 (many closed ports return RST)
    
    Returns:
        Ratio [0, 1], NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Calculate RST ratio from backward packets."""
        total_rst = 0
        total_bwd = 0
        
        for f in flows:
            bwd_flags = f.get_bwd_tcp_flags_count()
            total_rst += bwd_flags.get('RST', 0)
            total_bwd += f.get_bwd_packet_count()
        
        if total_bwd == 0:
            return 0.0
        
        return float(total_rst) / float(total_bwd)


@register_feature(FeatureMetadata(
    name="DistinctPorts",
    code="F5",
    description="Unique destination ports count - detects Port Scan",
    category="network",
    depends_on=None
))
class F5_DistinctPorts(FeatureBase):
    """
    F5: DISTINCT DESTINATION PORTS
    
    Công thức: len(unique_dst_ports)
    
    Ứng dụng:
    - Phát hiện Port Scan attack
    - Normal: 1-5 ports (web, email, etc.)
    - Attack Port Scan: 50-1000+ ports
    
    Returns:
        Port count (integer as float), NOT normalized
    """
    
    def calculate(self, flows: List[FlowState], **kwargs) -> float:
        """Count unique destination ports from all flows."""
        all_ports = set()
        for f in flows:
            all_ports.update(f.get_distinct_ports())
        return float(len(all_ports))


# Export all features
__all__ = [
    'F1_PacketRate',
    'F2_SynAckRatio',
    'F3_InterArrivalTime',
    'F4_RstRatio',
    'F5_DistinctPorts',
]
