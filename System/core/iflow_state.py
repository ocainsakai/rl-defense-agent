"""IFlowState - Lớp trừu tượng cơ sở cho flow state.

Định nghĩa giao diện chung mà FlowState (packet capture) và
LogFlowState (nginx log adapter) phải triển khai. Đảm bảo các
feature calculators hoạt động được với cả hai nguồn dữ liệu.

Thiết kế:
- Tất cả feature calculators phụ thuộc vào interface này, không phải class cụ thể
- FlowState: Dữ liệu gói tin thật từ Scapy capture
- LogFlowState: Log nginx được chuyển đổi (Adapter pattern)
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Set


class IFlowState(ABC):
    """Giao diện trừu tượng cho flow state.

    Thuộc tính bắt buộc (do subclass đặt):
        flow_key: tuple — 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
        window_size: float — kích thước sliding window (giây)
        analysis_window_size: float — kích thước window để tính features
        created_at: float — thời điểm tạo flow
        last_update: float — thời điểm cập nhật cuối
    """

    # =========================================================================
    # SỐ LƯỢNG GÓI TIN
    # =========================================================================

    @abstractmethod
    def get_fwd_packet_count(self) -> int:
        """Số gói tin chiều forward (client -> server)."""
        ...

    @abstractmethod
    def get_bwd_packet_count(self) -> int:
        """Số gói tin chiều backward (server -> client)."""
        ...

    @abstractmethod
    def get_packet_count(self) -> int:
        """Tổng số gói tin (forward + backward)."""
        ...

    @abstractmethod
    def is_empty(self) -> bool:
        """Kiểm tra flow có rỗng không."""
        ...

    # =========================================================================
    # DANH SÁCH GÓI TIN
    # =========================================================================

    @abstractmethod
    def get_fwd_packets(self) -> list:
        """Lấy danh sách gói tin forward (LayerInfo hoặc LogLayerInfo)."""
        ...

    @abstractmethod
    def get_bwd_packets(self) -> list:
        """Lấy danh sách gói tin backward."""
        ...

    @abstractmethod
    def get_all_packets(self) -> list:
        """Lấy tất cả gói tin (forward + backward)."""
        ...

    # =========================================================================
    # CỜ TCP
    # =========================================================================

    @abstractmethod
    def get_fwd_tcp_flags_count(self) -> Dict[str, int]:
        """Đếm cờ TCP trong gói tin forward."""
        ...

    @abstractmethod
    def get_bwd_tcp_flags_count(self) -> Dict[str, int]:
        """Đếm cờ TCP trong gói tin backward."""
        ...

    @abstractmethod
    def get_tcp_flags_count(self) -> Dict[str, int]:
        """Đếm cờ TCP trong tất cả gói tin."""
        ...

    # =========================================================================
    # CỔNG
    # =========================================================================

    @abstractmethod
    def get_distinct_ports(self) -> Set[int]:
        """Lấy tập hợp các cổng đích phân biệt."""
        ...

    # =========================================================================
    # PAYLOADS
    # =========================================================================

    @abstractmethod
    def get_fwd_payload_lengths(self) -> List[int]:
        """Độ dài payload các gói tin forward."""
        ...

    @abstractmethod
    def get_bwd_payload_lengths(self) -> List[int]:
        """Độ dài payload các gói tin backward."""
        ...

    @abstractmethod
    def get_payload_lengths(self) -> List[int]:
        """Độ dài payload tất cả gói tin."""
        ...

    @abstractmethod
    def get_fwd_payloads(self) -> List[bytes]:
        """Payload thô của gói tin forward."""
        ...

    @abstractmethod
    def get_bwd_payloads(self) -> List[bytes]:
        """Payload thô của gói tin backward."""
        ...

    @abstractmethod
    def get_payloads(self) -> List[bytes]:
        """Payload thô của tất cả gói tin."""
        ...

    @abstractmethod
    def get_reassembled_fwd_payload(self) -> bytes:
        """Payload forward ghép nối."""
        ...

    @abstractmethod
    def get_reassembled_bwd_payload(self) -> bytes:
        """Payload backward ghép nối."""
        ...

    @abstractmethod
    def get_reassembled_payload(self) -> bytes:
        """Payload tất cả ghép nối."""
        ...

    # =========================================================================
    # THUỘC TÍNH
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
        """IP thực của client (ưu tiên X-Real-IP hơn src_ip)."""
        ...

    @property
    @abstractmethod
    def duration(self) -> float:
        """Thời lượng flow tính bằng giây."""
        ...

    # =========================================================================
    # TIỆN ÍCH
    # =========================================================================

    @abstractmethod
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """Kiểm tra flow đã hết hạn chưa."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Xóa tất cả gói tin trong flow."""
        ...
