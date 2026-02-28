"""Hàng đợi gói tin thread-safe cho pipeline bắt gói.

Đệm gói tin thô giữa thread Sniffer và thread Analyzer.
Khi hàng đợi đầy, gói tin mới sẽ bị bỏ (không block) để tránh tràn RAM.
"""

import queue
import threading
import time
from typing import Optional

class PacketQueue:
    """Hàng đợi thread-safe đệm gói tin giữa Sniffer và Analyzer.

    Attributes:
        queue: Hàng đợi FIFO bên dưới.
        max_size: Số gói tin tối đa (tránh tràn bộ nhớ).
        dropped_packets: Bộ đếm gói tin bị bỏ do hàng đợi đầy.
    """

    def __init__(self, max_size: int = 10000):
        self.queue = queue.Queue(maxsize=max_size)
        self.max_size = max_size
        self._stats_lock = threading.Lock()
        self.dropped_packets = 0
        self.total_enqueued = 0

    def put(self, packet, block: bool = False, timeout: Optional[float] = None) -> bool:
        """Thêm gói tin vào hàng đợi.

        Args:
            packet: Đối tượng gói tin Scapy.
            block: Có chờ khi hàng đợi đầy không. Mặc định False (bỏ gói).
            timeout: Thời gian chờ tối đa (giây).

        Returns:
            True nếu thêm thành công, False nếu bị bỏ (hàng đợi đầy).
        """
        try:
            self.queue.put(packet, block=block, timeout=timeout)
            with self._stats_lock:
                self.total_enqueued += 1
            return True
        except queue.Full:
            with self._stats_lock:
                self.dropped_packets += 1
            return False

    def get(self, block: bool = True, timeout: Optional[float] = None):
        """Lấy gói tin từ hàng đợi.

        Returns:
            Đối tượng gói tin Scapy, hoặc None nếu hàng đợi rỗng.
        """
        try:
            return self.queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self.queue.qsize()

    def empty(self) -> bool:
        return self.queue.empty()

    def full(self) -> bool:
        return self.queue.full()

    def get_stats(self) -> dict:
        """Lấy thống kê hàng đợi."""
        return {
            'current_size': self.qsize(),
            'max_size': self.max_size,
            'total_dropped': self.dropped_packets,
            'total_enqueued': self.total_enqueued
        }
