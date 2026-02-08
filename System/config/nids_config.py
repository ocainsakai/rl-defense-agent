# config/nids_config.py
"""
=============================================================================
NIDS CONFIGURATION - Centralized Configuration for NIDS System
=============================================================================

Mục đích:
- Tập trung tất cả magic numbers vào một file
- Dễ dàng thay đổi config mà không cần sửa code
- Hỗ trợ các môi trường khác nhau (dev, test, production)

Sử dụng:
    from config.nids_config import NIDSConfig
    
    # Trong code:
    deque(maxlen=NIDSConfig.MAX_PACKETS_PER_FLOW)
    FlowManager(flow_timeout=NIDSConfig.FLOW_TIMEOUT_SECONDS)
=============================================================================
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class NIDSConfig:
    """
    Config class chứa tất cả các hằng số của hệ thống NIDS.
    
    Sử dụng frozen=True để đảm bảo config không bị thay đổi sau khi khởi tạo.
    """
    
    # =========================================================================
    # FLOW MANAGEMENT
    # =========================================================================
    
    # Số packets tối đa lưu trong 1 flow (forward + backward)
    # Giá trị cao hơn = tracking chính xác hơn, nhưng tốn RAM
    MAX_PACKETS_PER_FLOW: int = 3000
    
    # Thời gian inactive để coi flow là expired (giây)
    FLOW_TIMEOUT_SECONDS: float = 30.0
    
    # Số packets giữa các lần cleanup expired flows
    # Giá trị cao = ít cleanup hơn, tiết kiệm CPU nhưng tốn RAM
    CLEANUP_INTERVAL: int = 100
    
    # Số flows tối đa trong hệ thống (bảo vệ RAM)
    MAX_FLOWS: int = 50000
    
    # =========================================================================
    # SLIDING WINDOW
    # =========================================================================
    
    # Kích thước window mặc định (giây)
    DEFAULT_WINDOW_SIZE: float = 1.0
    
    # Slide step mặc định (giây) - tạo overlap
    DEFAULT_SLIDE_STEP: float = 0.5
    
    # =========================================================================
    # PACKET QUEUE
    # =========================================================================
    
    # Kích thước hàng đợi packet tối đa
    MAX_QUEUE_SIZE: int = 10000
    
    # =========================================================================
    # FEATURE THRESHOLDS (Reference Values)
    # =========================================================================
    
    # F1: Packet Rate - Ngưỡng nghi ngờ DDoS (packets/giây)
    THRESHOLD_HIGH_PACKET_RATE: float = 1000.0
    
    # F2: SYN/ACK Ratio - Ngưỡng nghi ngờ SYN Flood
    THRESHOLD_HIGH_SYN_RATIO: float = 10.0
    
    # F3: Distinct Ports - Ngưỡng nghi ngờ Port Scan
    THRESHOLD_HIGH_DISTINCT_PORTS: int = 50
    
    # F4: Payload Length - MTU tiêu chuẩn (bytes)
    STANDARD_MTU_SIZE: int = 1500
    
    # F5: Fail Rate - Ngưỡng nghi ngờ Brute Force
    THRESHOLD_HIGH_FAIL_RATE: float = 0.7
    
    # =========================================================================
    # CONTEXT SCORE (F6)
    # =========================================================================
    
    # Context Score chỉ có 2 giá trị:
    # - 0: NEUTRAL (bình thường, không phát hiện mẫu độc hại)
    # - 1: MALICIOUS (phát hiện SQLi, XSS, Command Injection, etc.)
    CONTEXT_NEUTRAL: float = 0.0
    CONTEXT_MALICIOUS: float = 1.0
    
    # Max payload size để scan (tránh memory issues)
    MAX_PAYLOAD_SCAN_SIZE: int = 65536
    
    # =========================================================================
    # LOGGING
    # =========================================================================
    
    # Log file max size (bytes) - 10MB
    LOG_MAX_SIZE: int = 10 * 1024 * 1024
    
    # Số backup log files giữ lại
    LOG_BACKUP_COUNT: int = 5
    
    # =========================================================================
    # PERFORMANCE
    # =========================================================================
    
    # Buffer size cho latency tracking
    LATENCY_BUFFER_SIZE: int = 1000


# Default config instance
DEFAULT_CONFIG = NIDSConfig()
