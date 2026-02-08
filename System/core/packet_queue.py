import queue
import time
from typing import Optional

class PacketQueue:
    """
    Thread-safe Queue for buffering raw packets between Sniffer and Analyzer threads.
    
    Attributes:
        queue (queue.Queue): The underlying FIFO queue.
        max_size (int): Maximum number of packets to hold (to prevent OOM).
        dropped_packets (int): Counter for packets dropped due to full queue.
    """
    
    def __init__(self, max_size: int = 10000):
        self.queue = queue.Queue(maxsize=max_size)
        self.max_size = max_size
        self.dropped_packets = 0
        self.total_enqueued = 0
        
    def put(self, packet, block: bool = False, timeout: Optional[float] = None) -> bool:
        """
        Add a packet to the queue.
        
        Args:
            packet: The Scapy packet object.
            block: Whether to block if queue is full. Default False (Risk dropping).
            timeout: Timeout for blocking.
            
        Returns:
            bool: True if enqueued, False if dropped (Full).
        """
        try:
            self.queue.put(packet, block=block, timeout=timeout)
            self.total_enqueued += 1
            return True
        except queue.Full:
            self.dropped_packets += 1
            return False
            
    def get(self, block: bool = True, timeout: Optional[float] = None):
        """
        Get a packet from the queue.
        
        Returns:
            packet: The Scapy packet object, or None if Empty (and not blocking).
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
        return {
            'current_size': self.qsize(),
            'max_size': self.max_size,
            'total_dropped': self.dropped_packets,
            'total_enqueued': self.total_enqueued
        }
