"""
FlowManager - Quản lý các flows dựa trên 5-tuple

CHỨC NĂNG:
1. Nhận packet đã parse (LayerInfo)
2. Map packet vào flow tuple
3. XÁC ĐỊNH DIRECTION: Forward hay Backward
4. Tạo flow mới nếu chưa tồn tại
5. Cleanup flow cũ theo timeout

BIDIRECTIONAL:
- Forward: Packet có src_ip = flow.src_ip
- Backward: Packet có src_ip = flow.dst_ip (đổi chiều)
"""

from typing import Dict, Any, Optional, List, Set, Union
from collections import defaultdict
import time

from core.layer_info import LayerInfo
from core.flow_state import FlowState
from config.nids_config import NIDSConfig, DEFAULT_CONFIG


class FlowManager:
    """
    Quản lý các network flows với BIDIRECTIONAL tracking.
    """

    def __init__(
        self,
        config: Optional[NIDSConfig] = None,
        *,
        window_size: Optional[float] = None,
        flow_timeout: Optional[float] = None,
        cleanup_interval: Optional[int] = None,
        max_flows: Optional[int] = None,
    ):
        """
        Args:
            config: NIDSConfig instance (ưu tiên). Nếu None thì dùng DEFAULT_CONFIG.
            window_size: Override window_size từ config
            flow_timeout: Override flow_timeout từ config
            cleanup_interval: Override cleanup_interval từ config
            max_flows: Override max_flows từ config
        """
        cfg = config or DEFAULT_CONFIG
        self.window_size = window_size if window_size is not None else cfg.DEFAULT_WINDOW_SIZE
        self.flow_timeout = flow_timeout if flow_timeout is not None else cfg.FLOW_TIMEOUT_SECONDS
        self.cleanup_interval = cleanup_interval if cleanup_interval is not None else cfg.CLEANUP_INTERVAL
        self.max_flows = max_flows if max_flows is not None else cfg.MAX_FLOWS
        
        # Flow storage: {flow_key: FlowState}
        self.flows: Dict[tuple, FlowState] = {}
        
        # Index: {src_ip: set of flow_keys}
        self.flows_by_src: Dict[str, Set[tuple]] = defaultdict(set)
        
        # Counter
        self._packet_counter: int = 0
        self._last_packet_time: float = time.time()  # Track last packet time for cleanup
    
    def _make_flow_key(self, layer_info: LayerInfo) -> tuple:
        """Tạo flow key từ 5-tuple (chỉ TCP)"""
        src_port = layer_info.tcp_sport or 0
        dst_port = layer_info.tcp_dport or 0
        
        return (
            layer_info.src_ip or '',
            layer_info.dst_ip or '',
            src_port,
            dst_port,
            layer_info.protocol or 0
        )
    
    def _make_reverse_key(self, flow_key: tuple) -> tuple:
        """Tạo reverse key (đổi src/dst)"""
        return (
            flow_key[1],  # dst → src
            flow_key[0],  # src → dst
            flow_key[3],  # dst_port → src_port
            flow_key[2],  # src_port → dst_port
            flow_key[4]   # protocol giữ nguyên
        )
    
    def process_packet(self, layer_info: LayerInfo) -> Optional[FlowState]:
        """
        Xử lý 1 packet: Map vào flow và xác định direction.
        
        LOGIC (theo CICFlowMeter):
        1. Packet đầu tiên tạo flow và set src/dst
        2. Packets sau: So sánh packet.src_ip với flow.src_ip
           - Nếu packet.src_ip == flow.src_ip → FORWARD
           - Nếu packet.src_ip == flow.dst_ip → BACKWARD
        
        CÁCH HOẠT ĐỘNG:
        - Tìm flow bằng flow_key hoặc reverse_key
        - Sau đó check packet.src_ip để xác định direction
        - Đơn giản và chính xác như CICFlowMeter
        """
        if not layer_info.has_ip:
            return None
        
        flow_key = self._make_flow_key(layer_info)
        reverse_key = self._make_reverse_key(flow_key)
        
        flow = None
        is_forward = True
        
        # BƯỚC 1: Tìm flow (check cả 2 chiều)
        if flow_key in self.flows:
            flow = self.flows[flow_key]
            # CHECK theo CICFlowMeter: packet.src == flow.src?
            is_forward = (layer_info.src_ip == flow.src_ip)
        
        # Case 2: Backward packet (reverse_key tồn tại)
        elif reverse_key in self.flows:
            flow = self.flows[reverse_key]
            # CHECK theo CICFlowMeter: packet.src == flow.src?
            is_forward = (layer_info.src_ip == flow.src_ip)
        
        # Case 3: New flow (packet đầu tiên LÀ FORWARD)
        else:
            # KIỂM TRA GIỚI HẠN BỘ NHỚ (Memory Safety)
            if len(self.flows) >= self.max_flows:
                # Thử dọn dẹp các flow hết hạn trước
                removed = self._cleanup_expired_flows()
                
                # Nếu vẫn đầy sau khi dọn dẹp -> Drop flow mới (Fail-safe)
                if len(self.flows) >= self.max_flows:
                    return None
            
            flow = FlowState(flow_key, self.window_size)
            self.flows[flow_key] = flow
            self.flows_by_src[flow_key[0]].add(flow_key)
            is_forward = True
        
        # Add packet theo direction
        if is_forward:
            flow.add_forward_packet(layer_info)
        else:
            flow.add_backward_packet(layer_info)
        
        # Cleanup định kỳ (dùng packet timestamp, không phải system time)
        self._packet_counter += 1
        self._last_packet_time = layer_info.timestamp or time.time()
        
        if self._packet_counter >= self.cleanup_interval:
            self._cleanup_expired_flows()
            self._packet_counter = 0
        
        return flow
    
    def _cleanup_expired_flows(self) -> int:
        """
        Xóa các flows đã hết hạn (dùng packet time cho PCAP compatibility).
        
        LOGIC cho OFFLINE PCAP:
        - Sử dụng packet timestamp từ PCAP, không phải system time
        - Flows expire khi không nhận packets trong flow_timeout giây
        - Phù hợp cho phân tích PCAP offline
        """
        current_time = self._last_packet_time  # Dùng packet time, không phải system time
        expired_keys = []
        
        for flow_key, flow in self.flows.items():
            if flow.is_expired(current_time, self.flow_timeout):
                expired_keys.append(flow_key)
        
        # CRITICAL FIX: Cleanup expired flows AND remove empty src_ip entries
        for flow_key in expired_keys:
            src_ip = flow_key[0]
            self.flows_by_src[src_ip].discard(flow_key)
            del self.flows[flow_key]
            
            # Remove empty src_ip set to prevent memory leak
            if not self.flows_by_src[src_ip]:
                del self.flows_by_src[src_ip]
        
        return len(expired_keys)
    
    # =========================================================================
    # QUERY METHODS
    # =========================================================================
    
    def get_flow(self, flow_key: tuple) -> Optional[FlowState]:
        """Lấy FlowState theo flow_key"""
        return self.flows.get(flow_key)
    
    def get_flows_by_src(self, src_ip: str) -> List[FlowState]:
        """Lấy tất cả flows của 1 src_ip"""
        flow_keys = self.flows_by_src.get(src_ip, set())
        return [self.flows[k] for k in flow_keys if k in self.flows]
    
    def get_flow_count_by_src(self, src_ip: str) -> int:
        """Số flows active của 1 src_ip"""
        return len(self.flows_by_src.get(src_ip, set()))
    
    def get_all_flows(self) -> List[FlowState]:
        """Lấy tất cả flows"""
        return list(self.flows.values())
    
    def get_all_src_ips(self) -> List[str]:
        """Lấy tất cả src_ip đang có flows"""
        return list(self.flows_by_src.keys())
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def get_stats(self) -> Dict[str, int]:
        """Trả về thống kê"""
        return {
            'total_flows': len(self.flows),
            'total_hosts': len(self.flows_by_src),
            'packets_processed': self._packet_counter
        }
    
    def clear(self) -> None:
        """Xóa tất cả flows"""
        self.flows.clear()
        self.flows_by_src.clear()
        self._packet_counter = 0

    def slide_window_packets(self, current_time: float) -> None:
        """
        Thực hiện Sliding Window:
        1. Xóa packets cũ hơn window_size trong tất cả các flows.
        2. Nếu flow rỗng sau khi xóa -> Xóa flow.
        """
        # 1. Cleanup old packets in each flow
        for flow in self.flows.values():
            flow._cleanup_old_packets(current_time)
            
        # 2. Cleanup empty flows
        expired_keys = [k for k, f in self.flows.items() if f.is_empty()]
        
        for flow_key in expired_keys:
            del self.flows[flow_key]
            # Clean index
            src_ip = flow_key[0]
            if src_ip in self.flows_by_src:
                self.flows_by_src[src_ip].discard(flow_key)
                if not self.flows_by_src[src_ip]:
                    del self.flows_by_src[src_ip]
