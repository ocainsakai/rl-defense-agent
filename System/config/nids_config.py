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

import os
from dataclasses import dataclass, fields
from typing import Any, Dict, Optional


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
    # PAYLOAD SCAN
    # =========================================================================

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
    
    # =========================================================================
    # CLASS METHODS - Configuration Loaders
    # =========================================================================
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'NIDSConfig':
        """
        Tạo NIDSConfig từ dictionary.
        
        Args:
            config_dict: Dictionary chứa config values
        
        Returns:
            NIDSConfig instance với values từ dict
        
        Example:
            >>> config = NIDSConfig.from_dict({
            ...     'MAX_PACKETS_PER_FLOW': 5000,
            ...     'FLOW_TIMEOUT_SECONDS': 60.0
            ... })
        """
        # Lấy tên tất cả fields
        field_names = {f.name for f in fields(cls)}
        
        # Filter chỉ các key hợp lệ
        valid_kwargs = {
            k: v for k, v in config_dict.items()
            if k in field_names
        }
        
        return cls(**valid_kwargs)
    
    @classmethod
    def from_env(cls, prefix: str = 'NIDS_') -> 'NIDSConfig':
        """
        Tạo NIDSConfig từ environment variables.
        
        Environment variables được map theo pattern: {prefix}{FIELD_NAME}
        Ví dụ: NIDS_MAX_PACKETS_PER_FLOW=5000
        
        Args:
            prefix: Prefix cho environment variables (mặc định 'NIDS_')
        
        Returns:
            NIDSConfig instance với values từ env vars
        
        Example:
            >>> # Set env vars:
            >>> # export NIDS_MAX_PACKETS_PER_FLOW=5000
            >>> # export NIDS_FLOW_TIMEOUT_SECONDS=60.0
            >>> config = NIDSConfig.from_env()
        """
        kwargs = {}
        
        for field in fields(cls):
            env_var = f"{prefix}{field.name}"
            value = os.getenv(env_var)
            
            if value is not None:
                # Type conversion dựa vào field type
                field_type = field.type
                
                try:
                    if field_type == int:
                        kwargs[field.name] = int(value)
                    elif field_type == float:
                        kwargs[field.name] = float(value)
                    elif field_type == bool:
                        # Parse bool từ string
                        kwargs[field.name] = value.lower() in ('true', '1', 'yes', 'on')
                    elif field_type == str:
                        kwargs[field.name] = value
                    else:
                        # Default: giữ nguyên string
                        kwargs[field.name] = value
                        
                except (ValueError, TypeError) as e:
                    # Log warning nhưng không crash
                    import warnings
                    warnings.warn(
                        f"Failed to parse {env_var}={value} as {field_type.__name__}: {e}",
                        UserWarning
                    )
        
        return cls(**kwargs)
    
    @classmethod
    def merge(
        cls,
        base: Optional['NIDSConfig'] = None,
        overrides: Optional[Dict[str, Any]] = None
    ) -> 'NIDSConfig':
        """
        Merge config từ base config và overrides.
        
        Args:
            base: Base config (mặc định là DEFAULT_CONFIG)
            overrides: Dict chứa values muốn override
        
        Returns:
            NIDSConfig instance đã merged
        
        Example:
            >>> custom = NIDSConfig.merge(
            ...     overrides={'MAX_PACKETS_PER_FLOW': 10000}
            ... )
        """
        if base is None:
            # Sử dụng default values
            base_dict = {}
        else:
            # Convert base config thành dict
            base_dict = {f.name: getattr(base, f.name) for f in fields(base)}
        
        # Merge với overrides
        if overrides:
            base_dict.update(overrides)
        
        return cls(**base_dict)


# Default config instance
DEFAULT_CONFIG = NIDSConfig()
