"""Các ngoại lệ tùy chỉnh cho hệ thống NIDS.

Module này định nghĩa hệ thống phân cấp ngoại lệ cho toàn bộ hệ thống NIDS,
cho phép xử lý lỗi cụ thể và ghi nhật ký tốt hơn.

Hệ thống phân cấp:
    NIDSException (cơ sở)
    ├── FlowError (lỗi xử lý flow)
    ├── FeatureError (lỗi tính toán đặc trưng)
    ├── PayloadError (lỗi xử lý payload)
    ├── ConfigError (lỗi cấu hình)
    ├── PipelineError (lỗi pipeline)
    └── ParserError (lỗi phân tích gói tin)

Example:
    from core.exception import FeatureError
    
    def calculate_feature(flows):
        if not flows:
            raise FeatureError("No flows provided for calculation")
        # ... tính toán
"""

import logging

logger = logging.getLogger(__name__)


class NIDSException(Exception):
    """Ngoại lệ cơ sở cho tất cả các lỗi hệ thống NIDS.
    
    Tất cả các ngoại lệ tùy chỉnh của NIDS nên kế thừa từ lớp này.
    Điều này cho phép bắt tất cả các lỗi liên quan đến NIDS bằng một except duy nhất.
    
    Example:
        try:
            # ... NIDS operations
        except NIDSException as e:
            logger.error(f"NIDS error: {e}")
    """
    pass


class FlowError(NIDSException):
    """Lỗi xử lý flow.
    
    Được ném ra khi có vấn đề với quản lý flow:
    - Tạo flow thất bại
    - Cập nhật flow thất bại
    - Quá nhiều flow (giới hạn bộ nhớ)
    - Flow không hợp lệ
    
    Example:
        if len(self.flows) > self.max_flows:
            raise FlowError(f"Flow limit exceeded: {len(self.flows)} > {self.max_flows}")
    """
    pass


class FeatureError(NIDSException):
    """Lỗi tính toán đặc trưng.
    
    Được ném ra khi tính toán đặc trưng thất bại:
    - Dữ liệu đầu vào không hợp lệ
    - Lỗi tính toán (chia cho 0, v.v.)
    - Phụ thuộc bị thiếu
    - Lỗi trong trình tính toán đặc trưng
    
    Example:
        if window_size <= 0:
            raise FeatureError(f"Invalid window size: {window_size}")
    """
    pass


class PayloadError(NIDSException):
    """Lỗi xử lý payload.
    
    Được ném ra khi xử lý payload thất bại:
    - Payload bị hỏng hoặc không hợp lệ
    - Lỗi chuẩn hóa
    - Lỗi phân tích payload
    - Payload quá lớn
    
    Example:
        if len(payload) > MAX_PAYLOAD_SIZE:
            raise PayloadError(f"Payload too large: {len(payload)} bytes")
    """
    pass


class ConfigError(NIDSException):
    """Lỗi cấu hình.
    
    Được ném ra khi có vấn đề với cấu hình hệ thống:
    - Tệp cấu hình không hợp lệ
    - Giá trị cấu hình thiếu
    - Giá trị cấu hình không hợp lệ
    - Xung đột cấu hình
    
    Example:
        if config.FLOW_TIMEOUT_SECONDS <= 0:
            raise ConfigError(f"Invalid flow timeout: {config.FLOW_TIMEOUT_SECONDS}")
    """
    pass


class PipelineError(NIDSException):
    """Lỗi pipeline.
    
    Được ném ra khi xử lý pipeline thất bại:
    - Lỗi khởi tạo pipeline
    - Lỗi thực thi pipeline
    - Lỗi định dạng đầu ra
    - Nguồn dữ liệu không hợp lệ
    
    Example:
        if not pcap_file.exists():
            raise PipelineError(f"PCAP file not found: {pcap_file}")
    """
    pass


class ParserError(NIDSException):
    """Lỗi phân tích gói tin.
    
    Được ném ra khi phân tích gói tin thất bại:
    - Gói tin bị hỏng
    - Định dạng không được hỗ trợ
    - Lỗi trích xuất trường
    - Lỗi giải mã
    
    Example:
        if not packet.haslayer(IP):
            raise ParserError("Packet missing IP layer")
    """
    pass


class ModelError(NIDSException):
    """Lỗi mô hình học máy.
    
    Được ném ra khi có vấn đề với mô hình ML:
    - Tải mô hình thất bại
    - Dự đoán thất bại
    - Mô hình bị thiếu
    - Lỗi định dạng mô hình
    
    Example:
        if not model_path.exists():
            raise ModelError(f"Model file not found: {model_path}")
    """
    pass


# Các hàm tiện ích để xử lý ngoại lệ với ghi nhật ký

def handle_error(error: Exception, context: str = "", reraise: bool = True) -> None:
    """Xử lý và ghi nhật ký ngoại lệ.
    
    Args:
        error: Ngoại lệ để xử lý
        context: Ngữ cảnh bổ sung để ghi nhật ký
        reraise: Có ném lại ngoại lệ sau khi ghi nhật ký không
    
    Raises:
        Exception: Ném lại ngoại lệ gốc nếu reraise=True
    
    Example:
        try:
            calculate_feature(flows)
        except FeatureError as e:
            handle_error(e, context="F1_PacketRate calculation", reraise=False)
    """
    error_type = type(error).__name__
    message = f"{error_type}"
    if context:
        message += f" in {context}"
    message += f": {str(error)}"
    
    logger.error(message, exc_info=True)
    
    if reraise:
        raise


def validate_not_none(value, name: str, error_class=NIDSException) -> None:
    """Xác thực rằng giá trị không phải là None.
    
    Args:
        value: Giá trị để kiểm tra
        name: Tên của giá trị (cho thông báo lỗi)
        error_class: Lớp ngoại lệ để ném (mặc định: NIDSException)
    
    Raises:
        error_class: Nếu giá trị là None
    
    Example:
        validate_not_none(config, "config", ConfigError)
    """
    if value is None:
        raise error_class(f"{name} cannot be None")


def validate_positive(value, name: str, error_class=NIDSException) -> None:
    """Xác thực rằng giá trị là số dương.
    
    Args:
        value: Giá trị để kiểm tra
        name: Tên của giá trị (cho thông báo lỗi)
        error_class: Lớp ngoại lệ để ném (mặc định: NIDSException)
    
    Raises:
        error_class: Nếu giá trị không dương
    
    Example:
        validate_positive(window_size, "window_size", FeatureError)
    """
    if not isinstance(value, (int, float)) or value <= 0:
        raise error_class(f"{name} must be a positive number, got: {value}")


def validate_in_range(value, min_val, max_val, name: str, error_class=NIDSException) -> None:
    """Xác thực rằng giá trị nằm trong phạm vi.
    
    Args:
        value: Giá trị để kiểm tra
        min_val: Giá trị tối thiểu (bao gồm)
        max_val: Giá trị tối đa (bao gồm)
        name: Tên của giá trị (cho thông báo lỗi)
        error_class: Lớp ngoại lệ để ném (mặc định: NIDSException)
    
    Raises:
        error_class: Nếu giá trị ngoài phạm vi
    
    Example:
        validate_in_range(port, 0, 65535, "port", ParserError)
    """
    if not (min_val <= value <= max_val):
        raise error_class(
            f"{name} must be in range [{min_val}, {max_val}], got: {value}"
        )
