# feature/feature_flow.py
"""
=============================================================================
BỘ TÍNH TOÁN FEATURES SỬ DỤNG FLOWSTATE (BIDIRECTIONAL)
=============================================================================

File này chứa 14 Feature calculators sử dụng FlowState (bidirectional).
Tất cả features trả về GIÁ TRỊ THÔ (RAW VALUES).

14 FEATURES:
  Network & Timing (F1-F5):
    1. PPS (Packet Rate): packets / window_size
    2. SYN/ACK Ratio: SYN / max(ACK, 1)
    3. IAT (Inter-Arrival Time): avg delta time between fwd packets
    4. RST Ratio: RST / bwd_packets
    5. Distinct Ports: count(unique_dst_ports)

  Application Behavior (F6-F8):
    6. URL Concentration: max_single_url / total_requests
    7. Auth Failure Rate: (401 + 403) / total_responses
    8. Server Error Rate: 5xx / total_responses

  Payload Analysis (F9-F14):
    9.  Payload Length: sum(payload_lengths)
    10. Payload Entropy: shannon_entropy(raw_bytes)
    11. SQLi Keyword: count(all_sqli_patterns)
    12. SQL Special Char Ratio: count(chars) / len
    13. XSS Keyword: count(all_xss_patterns)
    14. XSS Special Char Ratio: count(chars) / len

=============================================================================
"""

import math
from collections import Counter
from typing import List, Optional
from core.flow_state import FlowState
from feature.payload_context import PayloadContextScorer
from core.packet_parser import HttpPayloadExtractor

# =============================================================================
# CONTEXT SCORES
# =============================================================================
# Chỉ có 2 giá trị: 0 (NEUTRAL) và 1 (MALICIOUS)
CONTEXT_NEUTRAL = 0.0
CONTEXT_MALICIOUS = 1.0


class FlowFeature1_PacketRate:
    """
    F1: TỐC ĐỘ GÓI TIN (PACKET RATE)
    
    Công thức: total_packets / window_size (packets/giây)
    
    Ứng dụng:
    - Phát hiện tấn công DDoS, Flood
    - Bình thường: 10-100 pkt/s
    - Tấn công: 1000+ pkt/s
    
    Trả về: Giá trị thô (packets/giây), KHÔNG normalize
    """
    META_NAME = "packet_rate"
    # META_MAX = config.MAX_PACKET_RATE  # Chỉ để tham khảo
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        """Tính packet rate - trả về giá trị thô (packets/giây)."""
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính tốc độ gói tin (packets/giây).
        
        Logic ưu tiên:
        1. Ưu tiên 1: Dùng 'analysis_window_size' (Sliding Window Tool)
        2. Ưu tiên 2: Dùng 'window_size' từ FlowState (Real-time System)
        3. Ưu tiên 3: Dùng Total Duration (Static PCAP Fallback)
        
        Trả về:
            float: Số packets / giây
        """
        if not flows:
            return 0.0

        # Tính tổng số gói tin từ tất cả flows
        total_packets = float(sum(f.get_packet_count() for f in flows))
        first_flow = flows[0]
        
        # 1. Thử lấy analysis_window_size (set bởi main_pcap_sliding.py)
        window_size = getattr(first_flow, 'analysis_window_size', None)
        
        # 2. Thử lấy window_size nội bộ (set bởi core/flow_manager.py)
        if window_size is None or window_size <= 0:
            window_size = getattr(first_flow, 'window_size', None)
            
        # Tính rate nếu có window_size hợp lệ
        if window_size and window_size > 0:
            return total_packets / window_size
            
        # 3. Fallback: Dùng Flow Duration (cho Static PCAP không có window config)
        start_times = [f.created_at for f in flows]
        end_times = [f.last_update for f in flows]
        
        if not start_times or not end_times:
            return 0.0
            
        # Tính duration thực tế từ thời điểm bắt đầu flow sớm nhất đến kết thúc muộn nhất
        total_duration = max(end_times) - min(start_times)
        
        if total_duration > 0.000001:
            return float(total_packets) / total_duration
            
        # If duration is practically 0 (e.g. single packet flow), return 0.0
        # to avoid division by zero or infinite rates.
        return 0.0


class FlowFeature2_SynAckRatio:
    """
    F2: TỶ LỆ SYN/ACK
    
    Công thức: SYN / max(ACK, 1)
    
    Ứng dụng:
    - Phát hiện SYN Flood attack
    - Bình thường: SYN và ACK cân bằng (~1.0)
    - Tấn công SYN Flood: SYN >> ACK (ratio > 10)
    
    Trả về: Giá trị thô (ratio), KHÔNG normalize
    - 0 = Không có TCP traffic
    - 1 = SYN và ACK cân bằng
    - >1 = SYN nhiều hơn ACK (nghi ngờ SYN Flood)
    """
    META_NAME = "syn_ack_ratio"
    # META_MAX = config.MAX_SYN_RATIO  # Chỉ để tham khảo
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        """Tính SYN/ACK ratio - trả về giá trị thô."""
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính tỷ lệ SYN / ACK từ forward packets.
        
        Trả về:
            float: SYN / max(ACK, 1). Giá trị có thể > 1.
        """
        total_syn = 0
        total_ack = 0
        
        for f in flows:
            flags = f.get_fwd_tcp_flags_count()
            total_syn += flags['SYN']
            total_ack += flags['ACK']
        
        # Tránh chia cho 0: Nếu ACK=0, dùng 1
        if total_ack == 0:
            # Nếu ACK=0 và SYN>0 => Tỷ lệ = SYN (rất cao, dấu hiệu SYN Flood)
            # Nếu ACK=0 và SYN=0 => Tỷ lệ = 0 (không có traffic TCP)
            return float(total_syn)
        
        return float(total_syn) / float(total_ack)


class FlowFeature3_IAT:
    """
    F3: INTER-ARRIVAL TIME (IAT)
    
    Công thức: avg(timestamp[i+1] - timestamp[i]) cho forward packets
    
    Ứng dụng:
    - Phát hiện automated attacks (IAT rất thấp, đều đặn)
    - Bình thường: ~0.1-1.0s (human behavior)
    - Tấn công: ~0.001s (scripted attacks)
    
    Trả về: Giá trị thô (giây), KHÔNG normalize
    """
    META_NAME = "iat"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính Inter-Arrival Time trung bình từ forward packets.
        
        Trả về:
            float: Thời gian trung bình giữa các packets (giây)
        """
        timestamps = []
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                if pkt.timestamp:
                    timestamps.append(pkt.timestamp)
        
        if len(timestamps) < 2:
            return 0.0
        
        # Sort theo thời gian
        timestamps.sort()
        
        # Tính delta giữa các packets liên tiếp
        deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        
        # Trả về trung bình
        return sum(deltas) / len(deltas) if deltas else 0.0


class FlowFeature4_RstRatio:
    """
    F4: TỶ LỆ RST (RST RATIO)
    
    Công thức: RST_count / max(total_bwd_packets, 1)
    
    Ứng dụng:
    - Phát hiện Port Scan (server trả RST cho port đóng)
    - Phát hiện connection issues
    - Bình thường: ~0 (connections established thành công)
    - Tấn công Port Scan: > 0.5 (nhiều port đóng trả RST)
    
    Trả về: Ratio [0, 1], KHÔNG normalize
    """
    META_NAME = "rst_ratio"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính tỷ lệ RST từ backward packets.
        """
        total_rst = 0
        total_bwd = 0
        
        for f in flows:
            bwd_flags = f.get_bwd_tcp_flags_count()
            total_rst += bwd_flags.get('RST', 0)
            total_bwd += f.get_bwd_packet_count()
        
        if total_bwd == 0:
            return 0.0
        
        return float(total_rst) / float(total_bwd)


class FlowFeature5_DistinctPorts:
    """
    F3: SỐ CỔNG ĐÍCH KHÁC NHAU (DISTINCT PORTS)
    
    Công thức: len(unique_dst_ports)
    
    Ứng dụng:
    - Phát hiện Port Scan attack
    - Bình thường: 1-5 ports (web, email, v.v.)
    - Tấn công Port Scan: 50-1000+ ports
    
    Trả về: Số lượng cổng (integer), KHÔNG normalize
    """
    META_NAME = "distinct_ports"
    # META_MAX = config.MAX_DISTINCT_PORTS  # Chỉ để tham khảo
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        """Tính số ports đích khác nhau - trả về giá trị thô."""
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Đếm số cổng đích unique từ tất cả flows.
        
        Trả về:
            float: Số lượng cổng đích duy nhất
        """
        all_ports = set()
        for f in flows:
            all_ports.update(f.get_distinct_ports())
        return float(len(all_ports))

class FlowFeature6_URLConcentration:
    """
    F6: URL CONCENTRATION
    
    Công thức: max_requests_to_single_url / total_requests
    
    Ứng dụng:
    - Phát hiện Brute Force (spam 1 endpoint như /login)
    - Phát hiện L7 DDoS (flood 1 URL)
    - Bình thường: ~0.1-0.3 (nhiều URL khác nhau)
    - Tấn công: ~0.9-1.0 (spam 1 URL)
    
    Note: URL được normalize bỏ query params
    Trả về: Ratio [0, 1]
    """
    META_NAME = "url_concentration"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính URL concentration từ forward HTTP requests.
        URL normalize: bỏ query params để group các request giống nhau.
        """
        url_counts = {}
        total_requests = 0
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                if getattr(pkt, 'has_http', False) and getattr(pkt, 'http_uri', None):
                    # Normalize: bỏ query params
                    full_uri = pkt.http_uri
                    base_uri = full_uri.split('?')[0] if full_uri else ''
                    
                    if base_uri:
                        url_counts[base_uri] = url_counts.get(base_uri, 0) + 1
                        total_requests += 1
        
        if total_requests == 0:
            return 0.0
        
        max_count = max(url_counts.values()) if url_counts else 0
        return float(max_count) / float(total_requests)


class FlowFeature7_AuthFailRate:
    """
    F7: AUTH FAILURE RATE (401 + 403)
    
    Công thức: (HTTP 401 + HTTP 403) / total_http_responses
    
    Ứng dụng:
    - Phát hiện Brute Force login (nhiều 401)
    - Phát hiện Access Control bypass attempts (nhiều 403)
    - Bình thường: ~0 (authenticated successfully)
    - Tấn công: ~0.9+ (hầu hết attempts fail)
    
    Trả về: Ratio [0, 1]
    """
    META_NAME = "auth_fail_rate"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính tỷ lệ auth failures từ HTTP responses (backward packets).
        """
        auth_failures = 0
        total_responses = 0
        
        for f in flows:
            for pkt in f.get_bwd_packets():
                status = getattr(pkt, 'http_status', None)
                if status:
                    total_responses += 1
                    if status == 401 or status == 403:
                        auth_failures += 1
        
        if total_responses == 0:
            return 0.0
        
        return float(auth_failures) / float(total_responses)


class FlowFeature8_ServerErrorRate:
    """
    F8: SERVER ERROR RATE (5xx)
    
    Công thức: HTTP 5xx / total_http_responses
    
    Ứng dụng:
    - Phát hiện SQLi gây crash (500 Internal Error)
    - Phát hiện DoS gây overload (503 Service Unavailable)
    - Bình thường: ~0 (server healthy)
    - Tấn công: >0.1 (nhiều server errors)
    
    Trả về: Ratio [0, 1]
    """
    META_NAME = "server_error_rate"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows)
    
    def calculate_raw(self, flows: List[FlowState]) -> float:
        """
        Tính tỷ lệ server errors từ HTTP responses (backward packets).
        """
        server_errors = 0
        total_responses = 0
        
        for f in flows:
            for pkt in f.get_bwd_packets():
                status = getattr(pkt, 'http_status', None)
                if status:
                    total_responses += 1
                    if 500 <= status < 600:
                        server_errors += 1
        
        if total_responses == 0:
            return 0.0
        
        return float(server_errors) / float(total_responses)

class FlowFeature9_PayloadLength:
    """
    F9: PAYLOAD LENGTH
    
    Công thức: sum(all forward payload lengths)
    
    Ứng dụng:
    - Payload lớn bất thường có thể chứa shellcode, buffer overflow
    - Phối hợp với entropy để phát hiện obfuscated data
    
    Trả về: Raw length (bytes)
    """
    META_NAME = "payload_length"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows, context)
    
    def calculate_raw(self, flows: List[FlowState], context=None) -> float:
        """
        Tính tổng độ dài payload từ forward packets.
        Always uses Composite Payload (Headers + Body) logic via FeatureContext.
        """
        total_length = 0
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                # Always use composite payload for consistency
                payload = ctx.get_raw_payload(pkt)
                if payload:
                    total_length += len(payload)
        
        return float(total_length)


class FlowFeature10_PayloadEntropy:
    """
    F10: PAYLOAD ENTROPY (Shannon Entropy)
    
    Công thức: -sum(p * log2(p)) cho mỗi byte value
    
    Ứng dụng:
    - Entropy cao (~7-8): Encrypted/compressed/obfuscated data
    - Entropy trung bình (~4-5): Normal text
    - Entropy thấp (~1-2): Repetitive data
    
    Trả về: Raw entropy [0, 8]
    """
    META_NAME = "payload_entropy"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows, context)
    
    def calculate_raw(self, flows: List[FlowState], context=None) -> float:
        """
        Tính Shannon entropy của combined forward payloads.
        Tính trên raw bytes (không normalize).
        Sử dụng Counter để tối ưu bộ nhớ.
        """
        byte_counts = Counter()
        total_len = 0
        
        # Always use FeatureContext to ensure Composite Payload is used
        ctx = context if context else FeatureContext(flows)

        for f in flows:
            for pkt in f.get_fwd_packets():
                # Always use composite payload for consistency
                payload = ctx.get_raw_payload(pkt)
                
                if payload:
                    byte_counts.update(payload)
                    total_len += len(payload)
        
        if total_len < 10:
            return 0.0
            
        # Tính Shannon entropy từ frequency maps
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
        
        return entropy  # Range [0, 8]


# =============================================================================
# F11-F14: SQLi/XSS DETECTION (Reuse patterns from PayloadContextScorer)
# =============================================================================

class FlowFeature11_SqliKeyword:
    """
    F11: SQLi WEIGHTED SCORE
    
    Tính tổng điểm SQLi dựa trên weighted scoring:
    - Keyword (union, select...): 1 điểm
    - Pattern match (union...select, or 1=1): 2 điểm
    
    Logic: Aggregate (Tổng dồn từ tất cả packets)
    
    Trả về: Weighted score (float)
    """
    META_NAME = "sqli_keyword"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows, context)
    
    def calculate_raw(self, flows: List[FlowState], context=None) -> float:
        """Tính tổng điểm SQLi dựa trên keyword + pattern."""
        total_score = 0.0
        
        # Dùng context để cache việc decode payload
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                raw_payload = ctx.get_raw_payload(pkt)
                # Gọi hàm counting mới với weighted scoring
                total_score += PayloadContextScorer.count_sqli_indicators(raw_payload)
        
        return total_score


class FlowFeature12_SqlSpecialChar:
    """
    F12: SQL SPECIAL CHARACTER RATIO
    
    Tỷ lệ ký tự đặc biệt SQLi trong payload.
    Chars: ' - ; # = --
    
    Trả về: Ratio [0, 1]
    """
    META_NAME = "sql_special_char"
    
    SQLI_CHARS = set(b"'-;#=")
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows, context)
    
    def calculate_raw(self, flows: List[FlowState], context=None) -> float:
        """Tính tỷ lệ SQL special chars."""
        total_len = 0
        char_count = 0
        
        # Always use FeatureContext for consistency
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                payload = ctx.get_raw_payload(pkt)
                    
                if not payload:
                    continue
                
                total_len += len(payload)
                char_count += sum(1 for b in payload if b in self.SQLI_CHARS)
        
        if total_len == 0:
            return 0.0
        
        return float(char_count) / float(total_len)


class FlowFeature13_XssKeyword:
    """
    F13: XSS WEIGHTED SCORE
    
    Tính tổng điểm XSS dựa trên weighted scoring:
    - Keyword (script, alert, onerror...): 1 điểm
    - Pattern match (<script>, onerror=...): 2 điểm
    
    Logic: Aggregate (Tổng dồn từ tất cả packets)
    
    Trả về: Weighted score (float)
    """
    META_NAME = "xss_keyword"
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows, context)
    
    def calculate_raw(self, flows: List[FlowState], context=None) -> float:
        """Tính tổng điểm XSS dựa trên keyword + pattern."""
        total_score = 0.0
        
        # Dùng context để cache việc decode payload
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                raw_payload = ctx.get_raw_payload(pkt)
                # Gọi hàm counting mới với weighted scoring
                total_score += PayloadContextScorer.count_xss_indicators(raw_payload)
        
        return total_score


class FlowFeature14_XssSpecialChar:
    """
    F14: XSS SPECIAL CHARACTER RATIO
    
    Tỷ lệ ký tự đặc biệt XSS trong payload.
    Chars: < > ( ) = /
    
    Trả về: Ratio [0, 1]
    """
    META_NAME = "xss_special_char"
    
    XSS_CHARS = set(b"<>()=/")
    
    def calculate(self, flows: List[FlowState], context: Optional['FeatureContext'] = None) -> float:
        return self.calculate_raw(flows, context)
    
    def calculate_raw(self, flows: List[FlowState], context=None) -> float:
        """Tính tỷ lệ XSS special chars."""
        total_len = 0
        char_count = 0
        
        # Always use FeatureContext
        ctx = context if context else FeatureContext(flows)
        
        for f in flows:
            for pkt in f.get_fwd_packets():
                payload = ctx.get_raw_payload(pkt)
                    
                if not payload:
                    continue
                
                total_len += len(payload)
                char_count += sum(1 for b in payload if b in self.XSS_CHARS)
        
        if total_len == 0:
            return 0.0
        
        return float(char_count) / float(total_len)


# =============================================================================
# FEATURE CONTEXT: CACHED PAYLOAD NORMALIZATION (Performance Optimization)
# =============================================================================


def normalize_payload(payload_bytes: bytes) -> str:
    """
    Normalize payload for pattern matching.
    Reuses PayloadContextScorer's robust normalization:
    - URL decode (including '+' → space)
    - HTML entity decode
    - Unicode normalization (NFKC)
    - Smart quote → ASCII quote
    - Lowercase
    """
    if not payload_bytes:
        return ""
    return PayloadContextScorer._normalize_payload(payload_bytes)


class FeatureContext:
    """
    Context object for efficient feature calculation.
    
    Purpose:
    - Cache normalized payloads to avoid redundant computation
    - Reduce normalize_payload calls from O(N × Features) to O(N)
    
    Performance:
    - Without cache: 100 packets × 8 features = 800 normalize calls
    - With cache: 100 packets × 1 = 100 normalize calls (8x faster)
    
    Usage:
        ctx = FeatureContext(flows)
        for flow in flows:
            for pkt in flow.get_fwd_packets():
                normalized = ctx.get_normalized(pkt)  # Cached!
    """
    
    def __init__(self, flows: List[FlowState]):
        """
        Initialize context with flows.
        
        Args:
            flows: List of FlowState objects to analyze
        """
        self.flows = flows
        self._normalized_cache = {}  # packet_id → normalized_str
        self._raw_cache = {}         # packet_id → raw_bytes (for char ratio)
    
    def get_normalized(self, pkt) -> str:
        """
        Get normalized payload string (cached).
        
        Returns cached result if available, otherwise computes and caches.
        Used by pattern-based features (F7-F10, F12-F14).
        """
        pkt_id = id(pkt)
        if pkt_id not in self._normalized_cache:
            raw = self.get_raw_payload(pkt)
            self._normalized_cache[pkt_id] = normalize_payload(raw)
        return self._normalized_cache[pkt_id]
    
    def get_raw_payload(self, pkt) -> bytes:
        """Get composite raw payload bytes (cached). Delegates to HttpPayloadExtractor."""
        pkt_id = id(pkt)
        if pkt_id not in self._raw_cache:
            self._raw_cache[pkt_id] = HttpPayloadExtractor.build_composite_payload(pkt)
        return self._raw_cache[pkt_id]
    
    def get_fwd_packets_with_payloads(self):
        """
        Generator yielding (packet, raw_payload, normalized_payload) tuples.
        
        Optimized iteration for features that need both raw and normalized.
        """
        for flow in self.flows:
            for pkt in flow.get_fwd_packets():
                raw = self.get_raw_payload(pkt)
                if raw:
                    yield pkt, raw, self.get_normalized(pkt)


# LỚP AGGREGATOR - Tính tất cả 14 features cùng lúc
# ============================================================================

class FlowFeatureCalculator:
    """
    Lớp Aggregator để tính tất cả 14 features từ flows.
    
    Sử dụng:
        calculator = FlowFeatureCalculator()
        vector = calculator.calculate_all(flows)
        # vector = [f1, f2, ..., f14]
    
    14 FEATURES (RAW VALUES):
        F1:  PPS (Packet Rate)       packets/giây
        F2:  SYN/ACK Ratio           ratio
        F3:  IAT                     giây (inter-arrival time)
        F4:  RST Ratio               ratio [0,1]
        F5:  Distinct Ports          count
        F6:  URL Concentration       ratio [0,1]
        F7:  Auth Fail Rate          ratio [0,1] (401+403)
        F8:  Server Error Rate       ratio [0,1] (5xx)
        F9:  Payload Length          bytes
        F10: Payload Entropy         bits [0,8]
        F11: SQLi Keyword            count (merged patterns)
        F12: SQL Special Char Ratio  ratio [0,1]
        F13: XSS Keyword             count (merged patterns)
        F14: XSS Special Char Ratio  ratio [0,1]
    
    LƯU Ý: Tất cả features trả về giá trị THÔ (raw values).
    """
    
    NUM_FEATURES = 14
    
    def __init__(self):
        """Khởi tạo 14 feature calculators."""
        self.calculators = [
            FlowFeature1_PacketRate(),       # F1: PPS
            FlowFeature2_SynAckRatio(),      # F2: SYN/ACK
            FlowFeature3_IAT(),              # F3: IAT
            FlowFeature4_RstRatio(),         # F4: RST Ratio
            FlowFeature5_DistinctPorts(),    # F5: Distinct Ports
            FlowFeature6_URLConcentration(), # F6: URL Concentration
            FlowFeature7_AuthFailRate(),     # F7: Auth Fail (401/403)
            FlowFeature8_ServerErrorRate(),  # F8: Server Error (5xx)
            FlowFeature9_PayloadLength(),    # F9: Payload Length
            FlowFeature10_PayloadEntropy(),  # F10: Payload Entropy
            FlowFeature11_SqliKeyword(),     # F11: SQLi Keyword (from PayloadContextScorer)
            FlowFeature12_SqlSpecialChar(),  # F12: SQL Special Char
            FlowFeature13_XssKeyword(),      # F13: XSS Keyword (from PayloadContextScorer)
            FlowFeature14_XssSpecialChar(),  # F14: XSS Special Char
        ]
    
    def calculate_all(self, flows: List[FlowState]) -> list:
        """
        Tính tất cả 14 features.
        
        Tham số:
            flows: Danh sách FlowState từ cùng 1 source IP
            
        Trả về:
            list: [f1, f2, ..., f14]
        """
        return [calc.calculate(flows) for calc in self.calculators]
    
    def calculate_all_optimized(self, flows: List[FlowState]) -> list:
        """
        Tính tất cả 14 features với tối ưu hóa cache (8x faster).
        
        Sử dụng FeatureContext để:
        - Compute normalized payloads 1 lần duy nhất
        - Cache kết quả cho tất cả pattern-based features
        
        Performance:
        - calculate_all(): 100 pkts × 8 features = 800 normalize calls
        - calculate_all_optimized(): 100 pkts × 1 = 100 normalize calls
        
        Tham số:
            flows: Danh sách FlowState từ cùng 1 source IP
            
        Trả về:
            list: [f1, f2, ..., f14]
        """
        if not flows:
            return [0.0] * self.NUM_FEATURES
        
        # Create context with cached normalization
        ctx = FeatureContext(flows)
        
        # Calculate network features (F1-F5) - no payload needed
        results = [calc.calculate(flows) for calc in self.calculators[:5]]
        
        # Calculate L7 features (F6-F14) using cached context (Single Pass)
        results.extend(self._calculate_l7_features_with_context(ctx))
        
        return results
    
    def _calculate_l7_features_with_context(self, ctx: 'FeatureContext') -> list:
        """
        Calculate L7 features (F6-F14) using cached normalized payloads.
        
        Refactored to delegate logic to individual feature classes to adhere to DRY.
        Passes the FeatureContext to them to enable caching.
        
        FEATURES:
        - F6: URL Concentration
        - F7: Auth Fail Rate (401/403)
        - F8: Server Error Rate (5xx)
        - F9: Payload Length
        - F10: Payload Entropy
        - F11: SQLi Keyword (from PayloadContextScorer)
        - F12: SQL Special Char Ratio
        - F13: XSS Keyword (from PayloadContextScorer)
        - F14: XSS Special Char Ratio
        """
        flows = ctx.flows
        
        # Reuse calculator instances from self.calculators instead of creating new ones
        # F6: URL Concentration (index 5)
        f6 = self.calculators[5].calculate(flows, ctx)
        
        # F7: Auth Fail Rate (index 6)
        f7 = self.calculators[6].calculate(flows, ctx)
        
        # F8: Server Error Rate (index 7)
        f8 = self.calculators[7].calculate(flows, ctx)
        
        # Payload features (index 8-13) - pass context for caching
        f9 = self.calculators[8].calculate(flows, ctx)
        f10 = self.calculators[9].calculate(flows, ctx)
        f11 = self.calculators[10].calculate(flows, ctx)
        f12 = self.calculators[11].calculate(flows, ctx)
        f13 = self.calculators[12].calculate(flows, ctx)
        f14 = self.calculators[13].calculate(flows, ctx)
        
        return [
            f6, f7, f8, f9, f10, f11, f12, f13, f14
        ]


    
    def calculate_all_raw(self, flows: List[FlowState]) -> list:
        """
        Tính tất cả 14 features (tương tự calculate_all).
        
        Giữ lại để backward compatibility.
        
        Trả về:
            list: [f1, f2, ..., f14]
        """
        return [calc.calculate_raw(flows) for calc in self.calculators]
    
    def calculate_all_with_flags(self, flows: List[FlowState]) -> tuple:
        """
        Tính features và track missing data.
        
        Trả về:
            tuple: (features_list, missing_indices_list)
            - features_list: [f1, f2, ..., f14]
            - missing_indices_list: [0, 3, ...] (indices của features thiếu dữ liệu)
        
        Trường hợp missing data:
            - Empty flows list → tất cả features missing
        """
        if not flows:
            # Empty flows → tất cả features missing
            default_vector = [0.0] * self.NUM_FEATURES
            missing_indices = list(range(self.NUM_FEATURES))
            return (default_vector, missing_indices)
        
        features = []
        missing_indices = []
        
        for idx, calc in enumerate(self.calculators):
            try:
                feat_value = calc.calculate(flows)
                features.append(feat_value)
            except Exception:
                # Lỗi khi tính feature → đánh dấu missing
                features.append(0.0)
                missing_indices.append(idx)
        
        return (features, missing_indices)
    
    def calculate_all_with_flags_optimized(self, flows: List[FlowState]) -> tuple:
        """
        Tính features với tối ưu hóa và track missing data.
        
        Sử dụng calculate_all_optimized() bên trong.
        """
        if not flows:
            default_vector = [0.0] * self.NUM_FEATURES
            missing_indices = list(range(self.NUM_FEATURES))
            return (default_vector, missing_indices)
        
        try:
            features = self.calculate_all_optimized(flows)
            return (features, [])
        except Exception:
            # Fallback to non-optimized if error
            return self.calculate_all_with_flags(flows)
    
    @staticmethod
    def get_feature_names() -> list:
        """Trả về danh sách tên 14 features."""
        return [
            'pps',                  # F1
            'syn_ack_ratio',        # F2
            'iat',                  # F3
            'rst_ratio',            # F4
            'distinct_ports',       # F5
            'url_concentration',    # F6
            'auth_fail_rate',       # F7
            'server_error_rate',    # F8
            'payload_length',       # F9
            'payload_entropy',      # F10
            'sqli_keyword',         # F11
            'sql_special_char',     # F12
            'xss_keyword',          # F13
            'xss_special_char',     # F14
        ]

