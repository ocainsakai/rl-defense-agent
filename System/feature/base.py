"""Lớp cơ sở trừu tượng cho tất cả các đặc trưng và registry đặc trưng.

Module này cung cấp:
- FeatureMetadata: Siêu dữ liệu mô tả một đặc trưng
- FeatureBase: Lớp cơ sở trừu tượng cho tất cả các trình tính toán đặc trưng
- FeatureRegistry: Registry tập trung để đăng ký và khám phá đặc trưng
- @register_feature: Decorator để tự động đăng ký đặc trưng
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Type, Optional
from dataclasses import dataclass


@dataclass
class FeatureMetadata:
    """Siêu dữ liệu về một đặc trưng.
    
    Attributes:
        name: Tên đầy đủ của đặc trưng (ví dụ: "PacketRate")
        code: Mã định danh duy nhất (ví dụ: "F1")
        description: Mô tả chi tiết về đặc trưng
        category: Danh mục ("network", "application", "payload", "context")
        depends_on: Danh sách các phụ thuộc (ví dụ: ["PayloadContextScorer"])
    """
    name: str
    code: str
    description: str
    category: str
    depends_on: Optional[List[str]] = None


class FeatureBase(ABC):
    """Lớp cơ sở trừu tượng cho tất cả các trình tính toán đặc trưng.
    
    Tất cả các đặc trưng phải kế thừa lớp này và triển khai phương thức calculate().
    
    Attributes:
        metadata: FeatureMetadata mô tả đặc trưng này
        config: Đối tượng cấu hình NIDSConfig
        dependencies: Dict các phụ thuộc được inject (ví dụ: payload_scorer)
    
    Example:
        @register_feature(FeatureMetadata(
            name="PacketRate",
            code="F1",
            description="Packets per second",
            category="network"
        ))
        class F1_PacketRate(FeatureBase):
            def calculate(self, flows):
                return sum(f.get_packet_count() for f in flows) / window_size
    """
    
    metadata: FeatureMetadata = None  # Lớp con phải định nghĩa
    
    def __init__(self, config=None, dependencies: Optional[Dict] = None):
        """Khởi tạo trình tính toán đặc trưng.
        
        Args:
            config: Phiên bản NIDSConfig (nếu None, sẽ sử dụng mặc định)
            dependencies: Dict của các phụ thuộc được inject
                Ví dụ: {"payload_scorer": PayloadContextScorer()}
        """
        self.config = config
        self.dependencies = dependencies or {}
    
    @abstractmethod
    def calculate(self, flows) -> float:
        """Tính giá trị đặc trưng này.
        
        Args:
            flows: Danh sách các đối tượng FlowState cho một src_ip hoặc flow cluster
        
        Returns:
            float: Giá trị đặc trưng thô (raw value, chưa chuẩn hóa)
        
        Raises:
            FeatureError: Nếu tính toán thất bại
        """
        pass
    
    @classmethod
    def get_metadata(cls) -> FeatureMetadata:
        """Lấy siêu dữ liệu của đặc trưng này.
        
        Returns:
            FeatureMetadata instance
        """
        if cls.metadata is None:
            # Fallback nếu metadata không được định nghĩa
            return FeatureMetadata(
                name=cls.__name__,
                code=cls.__name__.split('_')[0] if '_' in cls.__name__ else cls.__name__,
                description=cls.__doc__ or "",
                category="unknown"
            )
        return cls.metadata


class FeatureRegistry:
    """Registry tập trung cho tất cả các đặc trưng có sẵn.
    
    Registry này cho phép:
    - Đăng ký đặc trưng tự động khi tải mô-đun
    - Khám phá tất cả các đặc trưng đã đăng ký
    - Tạo phiên bản đặc trưng theo mã
    - Liệt kê siêu dữ liệu của tất cả đặc trưng
    
    Example:
        # Đăng ký
        FeatureRegistry.register(F1_PacketRate)
        
        # Lấy lớp đặc trưng
        feature_class = FeatureRegistry.get("F1")
        
        # Tạo phiên bản
        feature = FeatureRegistry.instantiate("F1", config=config)
        
        # Liệt kê tất cả
        all_features = FeatureRegistry.list_all()
    """
    
    # Storage cho các lớp đặc trưng và siêu dữ liệu
    _features: Dict[str, Type[FeatureBase]] = {}
    _metadata: Dict[str, FeatureMetadata] = {}
    
    @classmethod
    def register(cls, feature_class: Type[FeatureBase]) -> None:
        """Đăng ký một đặc trưng trong registry.
        
        Được gọi tự động bởi decorator @register_feature khi tải mô-đun.
        
        Args:
            feature_class: Lớp kế thừa từ FeatureBase
        
        Raises:
            ValueError: Nếu feature_class không có metadata hoặc metadata.code trùng lặp
        """
        if not hasattr(feature_class, 'metadata') or feature_class.metadata is None:
            raise ValueError(f"{feature_class.__name__} must have metadata attribute")
        
        code = feature_class.metadata.code
        
        if code in cls._features:
            import warnings
            warnings.warn(
                f"Feature {code} already registered, overwriting with {feature_class.__name__}",
                UserWarning
            )
        
        cls._features[code] = feature_class
        cls._metadata[code] = feature_class.metadata
    
    @classmethod
    def get(cls, code: str) -> Type[FeatureBase]:
        """Lấy lớp đặc trưng theo mã.
        
        Args:
            code: Mã đặc trưng (ví dụ: 'F1', 'F2', ...)
        
        Returns:
            Lớp đặc trưng đã đăng ký
        
        Raises:
            KeyError: Nếu mã không được tìm thấy trong registry
        """
        if code not in cls._features:
            available = ', '.join(sorted(cls._features.keys()))
            raise KeyError(
                f"Feature '{code}' not registered. Available features: {available}"
            )
        return cls._features[code]
    
    @classmethod
    def list_all(cls) -> Dict[str, FeatureMetadata]:
        """Lấy siêu dữ liệu cho tất cả các đặc trưng đã đăng ký.
        
        Returns:
            Dict ánh xạ mã đặc trưng -> FeatureMetadata
        """
        return cls._metadata.copy()
    
    @classmethod
    def list_by_category(cls, category: str) -> Dict[str, FeatureMetadata]:
        """Lấy tất cả các đặc trưng trong một danh mục.
        
        Args:
            category: Danh mục đặc trưng ("network", "application", "payload", "context")
        
        Returns:
            Dict ánh xạ mã đặc trưng -> FeatureMetadata
        """
        return {
            code: metadata
            for code, metadata in cls._metadata.items()
            if metadata.category == category
        }
    
    @classmethod
    def instantiate(cls, code: str, config=None, dependencies=None) -> FeatureBase:
        """Tạo phiên bản của một đặc trưng.
        
        Args:
            code: Mã đặc trưng (ví dụ: 'F1')
            config: Đối tượng NIDSConfig (tùy chọn)
            dependencies: Dict phụ thuộc để inject (tùy chọn)
        
        Returns:
            Phiên bản đã khởi tạo của đặc trưng
        
        Raises:
            KeyError: Nếu mã không được tìm thấy
        """
        feature_class = cls.get(code)
        return feature_class(config=config, dependencies=dependencies)
    
    @classmethod
    def instantiate_all(cls, config=None, dependencies=None) -> Dict[str, FeatureBase]:
        """Tạo phiên bản của tất cả các đặc trưng đã đăng ký.
        
        Args:
            config: Đối tượng NIDSConfig (tùy chọn)
            dependencies: Dict phụ thuộc để inject (tùy chọn)
        
        Returns:
            Dict ánh xạ mã đặc trưng -> phiên bản đặc trưng
        """
        return {
            code: feature_class(config=config, dependencies=dependencies)
            for code, feature_class in cls._features.items()
        }
    
    @classmethod
    def clear(cls) -> None:
        """Xóa tất cả các đặc trưng đã đăng ký.
        
        Chủ yếu được sử dụng cho kiểm thử.
        """
        cls._features.clear()
        cls._metadata.clear()


def register_feature(metadata: FeatureMetadata):
    """Decorator để tự động đăng ký đặc trưng trong registry.
    
    Decorator này nên được áp dụng cho tất cả các lớp đặc trưng.
    Nó sẽ tự động đăng ký đặc trưng khi mô-đun được tải.
    
    Args:
        metadata: FeatureMetadata mô tả đặc trưng
    
    Returns:
        Decorator function
    
    Example:
        @register_feature(FeatureMetadata(
            name="PacketRate",
            code="F1",
            description="Packets per second - detects DDoS",
            category="network"
        ))
        class F1_PacketRate(FeatureBase):
            def calculate(self, flows):
                # ... implementation
                pass
    """
    def decorator(cls):
        # Gắn metadata vào lớp
        cls.metadata = metadata
        
        # Đăng ký trong registry
        FeatureRegistry.register(cls)
        
        return cls
    
    return decorator
