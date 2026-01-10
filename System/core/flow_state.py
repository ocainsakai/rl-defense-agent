"""
FlowState - Trạng thái của một flow (5-tuple)

CHỨC NĂNG:
- Lưu trữ packets theo FORWARD và BACKWARD direction
- Forward: Packets từ src → dst (client → server)
- Backward: Packets từ dst → src (server → client)
- Cung cấp data access methods cho feature extraction

QUAN TRỌNG:
- Forward/Backward separation giúp F5 (Fail Rate) đếm được RST từ server
- FlowManager sẽ xác định direction khi gọi add_packet()
"""

from collections import deque
from typing import Dict, Any, Set, List
import time

from core.layer_info import LayerInfo


class FlowState:
    """
    Trạng thái của một flow dựa trên 5-tuple.
    
    Hỗ trợ BIDIRECTIONAL tracking:
    - fwd_packets: Packets từ src → dst (forward)
    - bwd_packets: Packets từ dst → src (backward)
    """
    
    def __init__(self, flow_key: tuple, window_size: float = 1.0):
        """
        Args:
            flow_key: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
            window_size: Kích thước sliding window (giây)
        """
        self.flow_key = flow_key
        self.window_size = window_size
        
        # BIDIRECTIONAL: Tách riêng forward và backward
        self.fwd_packets: deque = deque(maxlen=3000)  # src → dst
        self.bwd_packets: deque = deque(maxlen=3000)  # dst → src
        
        # Timestamps
        self.created_at: float = time.time()
        self.last_update: float = time.time()
    
    def add_forward_packet(self, layer_info: LayerInfo) -> None:
        """Thêm packet FORWARD (src → dst)"""
        self.fwd_packets.append(layer_info)
        self.last_update = layer_info.timestamp if layer_info.timestamp else time.time()
        self._cleanup_old_packets(self.last_update)
    
    def add_backward_packet(self, layer_info: LayerInfo) -> None:
        """Thêm packet BACKWARD (dst → src)"""
        self.bwd_packets.append(layer_info)
        self.last_update = layer_info.timestamp if layer_info.timestamp else time.time()
        self._cleanup_old_packets(self.last_update)
    
    def _cleanup_old_packets(self, current_time: float) -> None:
        """
        Xóa packets cũ hơn window_size (sliding window).
        
        CRITICAL FIX: Validate timestamp before comparison to prevent TypeError.
        If timestamp is None, packet is kept (assumed to be current).
        """
        cutoff = current_time - self.window_size
        
        # Cleanup forward - validate timestamp before comparison
        while self.fwd_packets:
            pkt = self.fwd_packets[0]
            # Skip packets with invalid timestamp
            if pkt.timestamp is None or pkt.timestamp >= cutoff:
                break
            self.fwd_packets.popleft()
        
        # Cleanup backward - validate timestamp before comparison
        while self.bwd_packets:
            pkt = self.bwd_packets[0]
            # Skip packets with invalid timestamp
            if pkt.timestamp is None or pkt.timestamp >= cutoff:
                break
            self.bwd_packets.popleft()
    
    # =========================================================================
    # PACKET COUNTS
    # =========================================================================
    
    def get_fwd_packet_count(self) -> int:
        """Số forward packets"""
        return len(self.fwd_packets)
    
    def get_bwd_packet_count(self) -> int:
        """Số backward packets"""
        return len(self.bwd_packets)
    
    def get_packet_count(self) -> int:
        """Tổng packets (cả 2 chiều)"""
        return len(self.fwd_packets) + len(self.bwd_packets)
    
    # =========================================================================
    # PACKET LISTS
    # =========================================================================
    
    def get_fwd_packets(self) -> List[LayerInfo]:
        """Lấy forward packets"""
        return list(self.fwd_packets)
    
    def get_bwd_packets(self) -> List[LayerInfo]:
        """Lấy backward packets"""
        return list(self.bwd_packets)
    
    def get_all_packets(self) -> List[LayerInfo]:
        """Lấy tất cả packets"""
        return list(self.fwd_packets) + list(self.bwd_packets)
    
    # =========================================================================
    # TCP FLAGS - Tách riêng forward/backward
    # =========================================================================
    
    def get_fwd_tcp_flags_count(self) -> Dict[str, int]:
        """Đếm TCP flags của FORWARD packets"""
        return self._count_flags(self.fwd_packets)
    
    def get_bwd_tcp_flags_count(self) -> Dict[str, int]:
        """Đếm TCP flags của BACKWARD packets (QUAN TRỌNG cho F5!)"""
        return self._count_flags(self.bwd_packets)
    
    def get_tcp_flags_count(self) -> Dict[str, int]:
        """Đếm TCP flags của TẤT CẢ packets"""
        fwd = self.get_fwd_tcp_flags_count()
        bwd = self.get_bwd_tcp_flags_count()
        return {k: fwd[k] + bwd[k] for k in fwd}
    
    def _count_flags(self, packets) -> Dict[str, int]:
        """Helper: Đếm flags từ list packets"""
        counts = {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0}
        for pkt in packets:
            if pkt.has_tcp and pkt.tcp_flags:
                flags = pkt.tcp_flags
                if 'S' in flags: counts['SYN'] += 1
                if 'A' in flags: counts['ACK'] += 1
                if 'F' in flags: counts['FIN'] += 1
                if 'R' in flags: counts['RST'] += 1
                if 'P' in flags: counts['PSH'] += 1
                if 'U' in flags: counts['URG'] += 1
        return counts
    
    # =========================================================================
    # PORTS
    # =========================================================================
    
    def get_distinct_ports(self) -> Set[int]:
        """
        Lấy distinct destination ports (từ forward packets).
        
        NOTE: Mỗi flow (5-tuple) theo định nghĩa chỉ có 1 dst_port cố định.
        Method này thực tế sẽ return set với 1 phần tử duy nhất = self.flow_key[3].
        
        Tuy nhiên, khi aggregate nhiều flows (trong Feature3), ta được tất cả
        các ports khác nhau mà src_ip đã kết nối đến → Phát hiện Port Scanning.
        """
        ports = set()
        for pkt in self.fwd_packets:
            if pkt.has_tcp and pkt.tcp_dport:
                ports.add(pkt.tcp_dport)
            elif pkt.has_udp and pkt.udp_dport:
                ports.add(pkt.udp_dport)
        return ports
    
    # =========================================================================
    # PAYLOADS
    # =========================================================================
    
    def get_fwd_payload_lengths(self) -> List[int]:
        """Payload lengths của forward packets"""
        return [p.payload_length for p in self.fwd_packets if p.has_payload]
    
    def get_bwd_payload_lengths(self) -> List[int]:
        """Payload lengths của backward packets"""
        return [p.payload_length for p in self.bwd_packets if p.has_payload]
    
    def get_payload_lengths(self) -> List[int]:
        """Payload lengths của TẤT CẢ packets"""
        return self.get_fwd_payload_lengths() + self.get_bwd_payload_lengths()
    
    def get_fwd_payloads(self) -> List[bytes]:
        """Payloads của forward packets"""
        return [p.payload_bytes for p in self.fwd_packets if p.has_payload and p.payload_bytes]
    
    def get_bwd_payloads(self) -> List[bytes]:
        """Payloads của backward packets"""
        return [p.payload_bytes for p in self.bwd_packets if p.has_payload and p.payload_bytes]
    
    def get_payloads(self) -> List[bytes]:
        """Payloads của TẤT CẢ packets"""
        return self.get_fwd_payloads() + self.get_bwd_payloads()
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """Kiểm tra flow đã hết hạn chưa"""
        return (current_time - self.last_update) > timeout
    
    def clear(self) -> None:
        """Xóa dữ liệu trong flow"""
        self.fwd_packets.clear()
        self.bwd_packets.clear()
    
    @property
    def src_ip(self) -> str:
        return self.flow_key[0]
    
    @property
    def dst_ip(self) -> str:
        return self.flow_key[1]
    
    @property
    def src_port(self) -> int:
        return self.flow_key[2]
    
    @property
    def dst_port(self) -> int:
        return self.flow_key[3]
    
    @property
    def protocol(self) -> int:
        return self.flow_key[4]

    @property
    def duration(self) -> float:
        """
        Tính duration của flow từ packet đầu tiên đến packet cuối cùng.
        
        Returns:
            float: Duration in seconds, 0.0 if flow is empty
    """
        all_packets = self.get_all_packets()
    
        if not all_packets:
            return 0.0
    
        timestamps = [p.timestamp for p in all_packets if p.timestamp]
    
        if not timestamps or len(timestamps) < 2:
            return 0.0
        
        return max(timestamps) - min(timestamps)