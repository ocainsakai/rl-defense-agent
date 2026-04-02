"""Flow Feature Calculator - Bộ tổng hợp 20 features.

Module này cung cấp class calculator chính để tính tất cả 20 features
sử dụng kiến trúc plugin với FeatureRegistry.

Cách sử dụng:
    from feature.calculator import FlowFeatureCalculator

    calculator = FlowFeatureCalculator()

    # PRIMARY — có cache + flags (biết feature nào bị lỗi)
    features, missing = calculator.calculate(flows)
    # features = [f1, f2, ..., f20]  — giá trị thô theo FEATURE_ORDER
    # missing  = [12, 17]            — index các features bị lỗi (rỗng = OK)

    # WRAPPER — backward compat, chỉ trả về features (không có flags)
    features = calculator.calculate_all_optimized(flows)
"""

import logging
from typing import List, Tuple
from core.flow_state import FlowState
from feature.base import FeatureRegistry
from config.data_params import FEATURE_ORDER

# Import tất cả feature calculators để kích hoạt @register_feature decorators
# Đảm bảo FeatureRegistry được điền trước khi khởi tạo
import feature.calculators

logger = logging.getLogger(__name__)


from feature.context import FeatureContext


class FlowFeatureCalculator:
    """Lớp tổng hợp để tính tất cả 20 features từ flows.

    Sử dụng FeatureRegistry để tự động khám phá và khởi tạo tất cả
    features đã đăng ký. Thứ tự theo FEATURE_ORDER từ data_params.py.

    20 FEATURES (GIÁ TRỊ THÔ) — phân nhóm theo layer:
        Network [0-10]:
          F1:  PacketRate              gói/giây
          F2:  SynAckRatio             tỷ lệ
          F3:  InterArrivalTime        giây
          F4:  RstRatio                tỷ lệ [0,1]
          F5:  DistinctPorts           số lượng
          F6:  URLConcentration        tỷ lệ [0,1]
          F7:  HttpIatUniformity       1/(1+CV) HTTP IAT, Brute Force bot
          F8:  RequestSizeUniformity   1/(1+CV) payload sizes, Brute Force
          F9:  AvgPayloadSize          bytes
          F10: FwdBwdRatio             tỷ lệ
          F11: PacketsPerPort          tỷ lệ
        SQLi [11-16]:
          F12: SqlSpecialChar          tỷ lệ [0,1]
          F13: CrsSqliScore            số lượng (0-N)
          F14: SqlUnionSelect          nhị phân 0/1
          F15: SqlComment              nhị phân 0/1
          F16: SqlStackedQuery         nhị phân 0/1
          F17: SqlSelectCount          số lượng
        XSS [17-19]:
          F18: CrsXssScore             số lượng (0-N)
          F19: JsFunctionCall          nhị phân 0/1
          F20: HtmlEventHandler        nhị phân 0/1

    Lưu ý: Tất cả features trả về GIÁ TRỊ THÔ (chưa chuẩn hóa).
    """

    # Mã features theo thứ tự FEATURE_ORDER (20 features)
    FEATURE_CODES = FEATURE_ORDER

    NUM_FEATURES = len(FEATURE_ORDER)  # 20

    def __init__(self, config=None, wamm_classifier=None):
        """Khởi tạo calculator với tất cả features đã đăng ký.

        Args:
            config: NIDSConfig instance (tùy chọn, truyền cho features)
            wamm_classifier: Không sử dụng (giữ lại để tương thích ngược).
        """
        self.config = config

        # Khởi tạo tất cả features bằng FeatureRegistry
        self.calculators = []
        for code in self.FEATURE_CODES:
            try:
                calculator = FeatureRegistry.instantiate(
                    code,
                    config=self.config,
                )
                self.calculators.append(calculator)
            except KeyError:
                # Feature chưa đăng ký - ghi cảnh báo và dùng placeholder None
                logger.warning(f"Feature {code} chưa đăng ký, dùng mặc định 0.0")
                self.calculators.append(None)

    def calculate(self, flows: List[FlowState]) -> Tuple[List[float], List[int]]:
        """Tính tất cả 20 features — PRIMARY method.

        Sử dụng FeatureContext (cache) để tránh normalize payload nhiều lần,
        và trả về missing_indices để caller phân biệt được "0.0 thật" vs "0.0 do lỗi".

        Args:
            flows: Danh sách FlowState từ cùng source IP

        Returns:
            tuple:
                - features (List[float]): 20 giá trị thô theo FEATURE_ORDER
                - missing (List[int]): index các features bị lỗi hoặc chưa đăng ký
                  (rỗng = tất cả OK)
        """
        if not flows:
            return ([0.0] * self.NUM_FEATURES, list(range(self.NUM_FEATURES)))

        ctx = FeatureContext(flows)
        features = []
        missing = []

        for idx, calc in enumerate(self.calculators):
            if calc is None:
                features.append(0.0)
                missing.append(idx)
            else:
                try:
                    features.append(calc.calculate(flows, context=ctx))
                except Exception as e:
                    logger.error(f"Feature {calc.metadata.code} failed: {e}")
                    features.append(0.0)
                    missing.append(idx)

        return (features, missing)

    def calculate_all_optimized(self, flows: List[FlowState]) -> List[float]:
        """Wrapper backward-compat — trả về chỉ features (không có flags).

        Các caller cũ (tools, tests) không cần sửa.
        Dùng calculate() nếu cần biết feature nào bị lỗi.
        """
        return self.calculate(flows)[0]

    @staticmethod
    def get_feature_names() -> List[str]:
        """Trả về danh sách 20 tên feature (tương ứng FEATURE_ORDER).

        Returns:
            list: 20 tên snake_case theo thứ tự chuẩn
        """
        return [
            # Network [0-10]
            'packet_rate',          # F1
            'syn_ack_ratio',        # F2
            'inter_arrival_time',   # F3
            'rst_ratio',            # F4
            'distinct_ports',       # F5
            'url_concentration',    # F6
            'http_iat_uniformity',  # F7
            'request_size_uniformity',  # F8
            'avg_payload_size',     # F9
            'fwd_bwd_ratio',        # F10
            'packets_per_port',     # F11
            # SQLi [11-16]
            'sql_special_char',     # F12
            'crs_sqli_score',       # F13
            'sql_union_select',     # F14
            'sql_comment',          # F15
            'sql_stacked_query',    # F16
            'sql_select_count',     # F17
            # XSS [17-19]
            'crs_xss_score',        # F18
            'js_function_call',     # F19
            'html_event_handler',   # F20
        ]

    @staticmethod
    def get_feature_labels() -> List[str]:
        """Trả về danh sách 20 label feature theo format 'FN - ClassName'.

        Returns:
            list: ['F1 - PacketRate', 'F2 - SynAckRatio', ...]
        """
        return [
            # Network [0-10]
            'F1 - PacketRate',
            'F2 - SynAckRatio',
            'F3 - InterArrivalTime',
            'F4 - RstRatio',
            'F5 - DistinctPorts',
            'F6 - URLConcentration',
            'F7 - HttpIatUniformity',
            'F8 - RequestSizeUniformity',
            'F9 - AvgPayloadSize',
            'F10 - FwdBwdRatio',
            'F11 - PacketsPerPort',
            # SQLi [11-16]
            'F12 - SqlSpecialChar',
            'F13 - CrsSqliScore',
            'F14 - SqlUnionSelect',
            'F15 - SqlComment',
            'F16 - SqlStackedQuery',
            'F17 - SqlSelectCount',
            # XSS [17-19]
            'F18 - CrsXssScore',
            'F19 - JsFunctionCall',
            'F20 - HtmlEventHandler',
        ]

    @staticmethod
    def get_feature_count() -> int:
        """Trả về tổng số features.

        Returns:
            int: 20
        """
        return FlowFeatureCalculator.NUM_FEATURES


__all__ = [
    'FlowFeatureCalculator',
]
