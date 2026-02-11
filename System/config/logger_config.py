"""Cấu hình ghi nhật ký cho hệ thống NIDS.

Module này cung cấp tiện ích để thiết lập ghi nhật ký có cấu trúc
cho toàn bộ hệ thống NIDS.

Features:
- Ghi nhật ký bảng điều khiển với định dạng có màu sắc (tùy chọn)
- Ghi nhật ký tệp với xoay vòng tự động
- Mức nhật ký có thể cấu hình
- Loại bỏ các thư viện ồn ào (scapy, urllib3)
- Định dạng thống nhất trên tất cả các mô-đun

Example:
    from config.logger_config import LoggerSetup
    
    # Thiết lập ghi nhật ký cơ bản (chỉ console)
    LoggerSetup.setup(log_level='INFO')
    
    # Thiết lập với tệp nhật ký
    LoggerSetup.setup(log_level='DEBUG', log_file='nids.log')
    
    # Sử dụng trong mã
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Processing started")
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional


class LoggerSetup:
    """Thiết lập và cấu hình ghi nhật ký cho hệ thống NIDS.
    
    Lớp này cung cấp các phương thức tĩnh để cấu hình
    hệ thống ghi nhật ký chuẩn của Python với các cài đặt thích hợp
    cho ứng dụng NIDS.
    """
    
    # Định dạng nhật ký mặc định
    DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Định dạng chi tiết hơn cho debugging
    DETAILED_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    
    # Định dạng ngày giờ
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    @staticmethod
    def setup(
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        log_format: Optional[str] = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
        console_output: bool = True,
        detailed: bool = False
    ) -> None:
        """Thiết lập ghi nhật ký với trình xử lý bảng điều khiển và tệp tùy chọn.
        
        Args:
            log_level: Mức nhật ký ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
            log_file: Đường dẫn tệp nhật ký (nếu None, chỉ ghi vào console)
            log_format: Chuỗi định dạng nhật ký tùy chỉnh
            max_bytes: Kích thước tối đa của tệp nhật ký trước khi xoay vòng
            backup_count: Số tệp nhật ký sao lưu để giữ
            console_output: Có ghi vào console không
            detailed: Sử dụng định dạng chi tiết (bao gồm tên tệp và số dòng)
        
        Example:
            # Ghi nhật ký cơ bản
            LoggerSetup.setup(log_level='INFO')
            
            # Ghi nhật ký với tệp
            LoggerSetup.setup(
                log_level='DEBUG',
                log_file='logs/nids.log',
                detailed=True
            )
        """
        # Lấy logger gốc
        root = logging.getLogger()
        root.setLevel(log_level.upper())
        
        # Xóa các trình xử lý hiện có để tránh trùng lặp
        root.handlers.clear()
        
        # Chọn định dạng
        if log_format is None:
            log_format = LoggerSetup.DETAILED_FORMAT if detailed else LoggerSetup.DEFAULT_FORMAT
        
        formatter = logging.Formatter(log_format, datefmt=LoggerSetup.DATE_FORMAT)
        
        # Thêm trình xử lý bảng điều khiển
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level.upper())
            console_handler.setFormatter(formatter)
            root.addHandler(console_handler)
        
        # Thêm trình xử lý tệp nếu được chỉ định
        if log_file:
            # Tạo thư mục nếu không tồn tại
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Sử dụng RotatingFileHandler để xoay vòng tệp nhật ký
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(log_level.upper())
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        
        # Loại bỏ các thư viện ồn ào
        LoggerSetup._suppress_noisy_loggers()
        
        # Ghi thông báo khởi động
        logging.info(f"Logging initialized: level={log_level}, file={log_file or 'None'}")
    
    @staticmethod
    def _suppress_noisy_loggers() -> None:
        """Loại bỏ các logger ồn ào từ các thư viện bên thứ ba.
        
        Đặt mức WARNING cho các thư viện thường tạo ra quá nhiều
        thông báo nhật ký debug/info.
        """
        noisy_loggers = [
            'scapy',
            'scapy.runtime',
            'urllib3',
            'urllib3.connectionpool',
            'matplotlib',
            'PIL',
        ]
        
        for logger_name in noisy_loggers:
            logging.getLogger(logger_name).setLevel(logging.WARNING)
    
    @staticmethod
    def setup_from_config(config) -> None:
        """Thiết lập ghi nhật ký từ đối tượng NIDSConfig.
        
        Args:
            config: Đối tượng NIDSConfig với các thuộc tính LOG_LEVEL và LOG_FORMAT
        
        Example:
            from config.nids_config import NIDSConfig
            config = NIDSConfig()
            LoggerSetup.setup_from_config(config)
        """
        log_level = getattr(config, 'LOG_LEVEL', 'INFO')
        log_format = getattr(config, 'LOG_FORMAT', LoggerSetup.DEFAULT_FORMAT)
        log_file = getattr(config, 'LOG_FILE', None)
        
        LoggerSetup.setup(
            log_level=log_level,
            log_file=log_file,
            log_format=log_format
        )
    
    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """Lấy logger cho một mô-đun cụ thể.
        
        Args:
            name: Tên logger (thường là __name__)
        
        Returns:
            Logger instance
        
        Example:
            logger = LoggerSetup.get_logger(__name__)
            logger.info("Message")
        """
        return logging.getLogger(name)
    
    @staticmethod
    def set_level(level: str) -> None:
        """Thay đổi mức nhật ký trong runtime.
        
        Args:
            level: Mức nhật ký mới ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
        
        Example:
            LoggerSetup.set_level('DEBUG')
        """
        logging.getLogger().setLevel(level.upper())
        logging.info(f"Log level changed to {level.upper()}")
    
    @staticmethod
    def add_file_handler(
        log_file: str,
        log_level: Optional[str] = None,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5
    ) -> None:
        """Thêm trình xử lý tệp bổ sung.
        
        Hữu ích để ghi các loại nhật ký khác nhau vào các tệp khác nhau.
        
        Args:
            log_file: Đường dẫn tệp nhật ký
            log_level: Mức nhật ký (nếu None, sử dụng mức gốc)
            max_bytes: Kích thước tối đa trước khi xoay vòng
            backup_count: Số tệp sao lưu
        
        Example:
            # Ghi lỗi vào tệp riêng
            LoggerSetup.add_file_handler('logs/errors.log', log_level='ERROR')
        """
        root = logging.getLogger()
        
        # Tạo thư mục
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Tạo trình xử lý
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        
        # Đặt mức
        if log_level:
            file_handler.setLevel(log_level.upper())
        else:
            file_handler.setLevel(root.level)
        
        # Đặt định dạng
        formatter = logging.Formatter(
            LoggerSetup.DEFAULT_FORMAT,
            datefmt=LoggerSetup.DATE_FORMAT
        )
        file_handler.setFormatter(formatter)
        
        # Thêm vào logger gốc
        root.addHandler(file_handler)
        
        logging.info(f"Added file handler: {log_file}")


# Tiện ích để tạo logger nhanh
def get_logger(name: str = __name__) -> logging.Logger:
    """Tiện ích nhanh để lấy logger.
    
    Args:
        name: Tên logger (mặc định: __name__)
    
    Returns:
        Logger instance
    
    Example:
        from config.logger_config import get_logger
        logger = get_logger(__name__)
    """
    return logging.getLogger(name)
