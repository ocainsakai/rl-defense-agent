"""
FlowState - Trạng thái của một flow (5-tuple)

CHỨC NĂNG:
- Lưu trữ packets theo FORWARD và BACKWARD direction
- Forward: Packets từ src → dst (client → server)
- Backward: Packets từ dst → src (server → client)
- Cung cấp data access methods cho feature extraction

QUAN TRỌNG:
- Forward/Backward separation giúp F4 (RstRatio) đếm được RST từ server
- FlowManager sẽ xác định direction khi gọi add_packet()
"""

import functools
from collections import deque
from typing import Dict, Any, Optional, Set, List
import time

from config.nids_config import DEFAULT_CONFIG
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
        self.analysis_window_size = window_size

        # BIDIRECTIONAL: Tách riêng forward và backward
        # maxlen = MAX_PACKETS_PER_FLOW từ config (thay đổi config → tự động áp dụng)
        self.fwd_packets: deque = deque(maxlen=DEFAULT_CONFIG.MAX_PACKETS_PER_FLOW)  # src → dst
        self.bwd_packets: deque = deque(maxlen=DEFAULT_CONFIG.MAX_PACKETS_PER_FLOW)  # dst → src
        
        # Timestamps
        self.created_at: float = time.time()
        self.last_update: float = time.time()
        
        # Nginx Proxy: X-Real-IP (IP gốc của client khi sniff sau Nginx)
        self._x_real_ip: Optional[str] = None
    
    def add_forward_packet(self, layer_info: LayerInfo) -> None:
        """Thêm packet FORWARD (src → dst)"""
        self.fwd_packets.append(layer_info)
        self.last_update = layer_info.timestamp if layer_info.timestamp else time.time()
        self._cleanup_old_packets(self.last_update)
        
        # Capture X-Real-IP từ packet (nếu có)
        if not self._x_real_ip and hasattr(layer_info, 'x_real_ip') and layer_info.x_real_ip:
            self._x_real_ip = layer_info.x_real_ip
    
    def add_backward_packet(self, layer_info: LayerInfo) -> None:
        """Thêm packet BACKWARD (dst → src)"""
        self.bwd_packets.append(layer_info)
        self.last_update = layer_info.timestamp if layer_info.timestamp else time.time()
        self._cleanup_old_packets(self.last_update)
        
        # Capture X-Real-IP từ packet (nếu có)
        if not self._x_real_ip and hasattr(layer_info, 'x_real_ip') and layer_info.x_real_ip:
            self._x_real_ip = layer_info.x_real_ip
    
    def _cleanup_old_packets(self, current_time: float) -> None:
        """
        Xóa packets cũ hơn window_size (sliding window).
        """
        cutoff = current_time - self.window_size
        
        # Dọn dẹp forward - loại bỏ packets cũ và packets không có timestamp
        while self.fwd_packets:
            pkt = self.fwd_packets[0]
            if pkt.timestamp is None:
                self.fwd_packets.popleft()
                continue
            if pkt.timestamp >= cutoff:
                break
            self.fwd_packets.popleft()

        # Dọn dẹp backward - loại bỏ packets cũ và packets không có timestamp
        while self.bwd_packets:
            pkt = self.bwd_packets[0]
            if pkt.timestamp is None:
                self.bwd_packets.popleft()
                continue
            if pkt.timestamp >= cutoff:
                break
            self.bwd_packets.popleft()
    
    # =========================================================================
    # SỐ LƯỢNG GÓI TIN
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
    
    def is_empty(self) -> bool:
        """
        Kiểm tra flow có rỗng không (không còn packets nào).
        Được sử dụng bởi FlowManager.slide_window_packets() để cleanup flows rỗng.
        """
        return len(self.fwd_packets) == 0 and len(self.bwd_packets) == 0
    
    # =========================================================================
    # DANH SÁCH GÓI TIN
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
    # CỜ TCP - Tách riêng forward/backward
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
    # CỔNG
    # =========================================================================
    
    def get_distinct_ports(self) -> Set[int]:
        """
        Lấy distinct destination ports (từ forward TCP packets).

        NOTE: Mỗi flow (5-tuple) theo định nghĩa chỉ có 1 dst_port cố định.
        Method này thực tế sẽ return set với 1 phần tử duy nhất = self.flow_key[3].

        Tuy nhiên, khi aggregate nhiều flows (trong Feature5), ta được tất cả
        các ports khác nhau mà src_ip đã kết nối đến → Phát hiện Port Scanning.
        """
        ports = set()
        for pkt in self.fwd_packets:
            if pkt.has_tcp and pkt.tcp_dport is not None:
                ports.add(pkt.tcp_dport)
        return ports
    
    # =========================================================================
    # TẢI TRỌNG (PAYLOADS)
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
    # GHÉP NỐI PAYLOAD - Nối payload theo thứ tự TCP sequence number
    # =========================================================================

    @staticmethod
    def _reassemble(packets) -> bytes:
        """
        Ghép payload từ list packets theo TCP sequence number (L2 fix).

        Thuật toán:
        1. Lọc packets có payload thực sự.
        2. Tách thành nhóm có seq và không có seq.
        3. Sort nhóm có seq theo RFC 793 modular arithmetic:
           b đến sau a  ⟺  (b - a) & 0xFFFF_FFFF < 2^31
           → xử lý đúng TCP wraparound kể cả khi ISN gần 2^32.
        4. Dedup retransmission: cùng seq → giữ packet có payload dài hơn.
        5. Packets không có seq (ví dụ: UDP, stripped header) nối ở cuối.

        Args:
            packets: iterable[LayerInfo]

        Returns:
            bytes: payload đã sắp xếp đúng thứ tự TCP
        """
        pkts = [p for p in packets if p.has_payload and p.payload_bytes]
        if not pkts:
            return b''

        with_seq    = [(p.tcp_seq, p) for p in pkts if p.tcp_seq is not None]
        without_seq = [p for p in pkts if p.tcp_seq is None]

        if not with_seq:
            # Không có seq nào → fallback về thứ tự đến (hành vi cũ)
            return b''.join(p.payload_bytes for p in pkts)

        # RFC 793 modular sort — đúng kể cả khi ISN gần 2^32 và wrap về 0.
        # Nguyên tắc: b đến SAU a  ⟺  (b - a) & 0xFFFF_FFFF < 2^31
        # Không dùng (seq - min_seq) vì min_seq có thể là giá trị sau wrap
        # (nhỏ hơn numerically nhưng thực ra muộn hơn về mặt TCP).
        def _rfc793_cmp(a, b):
            diff = (b[0] - a[0]) & 0xFFFF_FFFF
            if diff == 0:
                return 0
            return -1 if diff < 0x8000_0000 else 1

        with_seq.sort(key=functools.cmp_to_key(_rfc793_cmp))

        # Dedup retransmission: cùng seq → giữ payload dài nhất
        best: dict = {}  # seq → LayerInfo
        for seq, pkt in with_seq:
            if seq not in best or len(pkt.payload_bytes) > len(best[seq].payload_bytes):
                best[seq] = pkt

        # Xây dựng danh sách cuối (theo thứ tự seq đã sort, loại bỏ trùng)
        seen_seqs: set = set()
        ordered = []
        for seq, _ in with_seq:
            if seq not in seen_seqs:
                seen_seqs.add(seq)
                ordered.append(best[seq])

        # Packets không có seq nối ở cuối (vị trí không xác định)
        ordered.extend(without_seq)

        return b''.join(p.payload_bytes for p in ordered)

    def get_reassembled_fwd_payload(self) -> bytes:
        """
        Nối forward payloads theo thứ tự TCP sequence number.

        Xử lý: out-of-order delivery, TCP wraparound, retransmission.
        Fallback về thứ tự packet đến nếu không có seq (ví dụ: UDP payload).

        USE CASE: Phát hiện SQLi/XSS signature bị phân mảnh qua nhiều packet.

        Returns:
            bytes: Payload đã ghép theo đúng thứ tự TCP
        """
        return self._reassemble(self.fwd_packets)

    def get_reassembled_bwd_payload(self) -> bytes:
        """
        Nối backward payloads theo thứ tự TCP sequence number.

        Returns:
            bytes: Payload từ server response đã ghép đúng thứ tự
        """
        return self._reassemble(self.bwd_packets)

    def get_reassembled_payload(self) -> bytes:
        """
        Nối payloads cả 2 chiều: reassemble mỗi chiều riêng rồi ghép lại.

        Không trộn seq của fwd và bwd vì chúng thuộc hai TCP stream khác nhau.

        Returns:
            bytes: Toàn bộ payload của flow (fwd trước, bwd sau)
        """
        return self.get_reassembled_fwd_payload() + self.get_reassembled_bwd_payload()


    # =========================================================================
    # PHƯƠNG THỨC TIỆN ÍCH
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
    def x_real_ip(self) -> str:
        """IP gốc của client (từ X-Real-IP header sau Nginx)"""
        return self._x_real_ip
    
    @property
    def effective_src_ip(self) -> str:
        """IP thực sự của client: Uu tiên X-Real-IP nếu có (sau Nginx)"""
        return self._x_real_ip if self._x_real_ip else self.flow_key[0]
    
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