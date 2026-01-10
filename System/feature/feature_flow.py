# feature/feature_flow.py
"""
=============================================================================
FEATURE CALCULATORS SỬ DỤNG FLOWSTATE
=============================================================================

File này chứa 6 Feature calculators sử dụng FlowState (bidirectional).
Giữ nguyên feature_logic.py cho backward compatibility với PacketWindow.

6 FEATURES:
1. Packet Rate: Tổng packets trong window
2. SYN/ACK Ratio: SYN / (SYN + ACK) từ forward packets
3. Distinct Ports: Số ports đích khác nhau (inter-flow)
4. Payload Length: Trung bình payload length
5. Fail Rate: RST từ BACKWARD packets / tổng packets
6. Context Score: Phát hiện malicious patterns
"""

from typing import List
from config import ai_config as config
from core.flow_state import FlowState
from feature.payload_context import score_payload


class FlowFeature1_PacketRate:
    """
    F1: PACKET RATE (RAW VALUE - No normalization)
    Tổng packets từ tất cả flows của src_ip
    
    Returns: Packets per second (raw value)
    """
    META_NAME = "packet_rate"
    
    def calculate(self, flows: List[FlowState]) -> float:
        """Packets per second trong sliding window (RAW VALUE)."""
        if not flows:
            return 0.0

        total_packets = float(sum(f.get_packet_count() for f in flows))
        total_duration = sum(f.duration for f in flows)

        if total_duration <= 0:
            return total_packets

        return total_packets / total_duration

        '''total_packets = float(sum(f.get_packet_count() for f in flows))
        window_size = float(getattr(flows[0], 'window_size', 1.0) or 1.0)
        if window_size <= 0:
            return 0.0

        return total_packets / window_size'''


class FlowFeature2_SynAckRatio:
    """
    F2: SYN/ACK RATIO - SYN Flood Detection (RAW VALUE - No normalization)
    
    Formula: SYN / (ACK + 1) từ FORWARD packets ONLY
    
    WHY FORWARD ONLY? (Phát hiện SYN Flood)
    ========================================
    Normal TCP Handshake:
        Client → Server: SYN           (forward: SYN=1, ACK=0)
        Server → Client: SYN-ACK       (backward: SYN=1, ACK=1) ← IGNORE
        Client → Server: ACK           (forward: SYN=0, ACK=1)
        → Forward ratio = 1/(1+1) = 0.5 (balanced)
    
    SYN Flood Attack:
        Attacker → Server: SYN×1000    (forward: SYN=1000, ACK=0)
        Server → Attacker: SYN-ACK×1000 (backward: ignore)
        Attacker: NO ACK!              (forward: no ACK response)
        → Forward ratio = 1000/(1000+0) = 1.0 (attack detected!)
    
    Nếu đếm cả backward, server's SYN-ACK sẽ làm giảm ratio → MISS ATTACK!
    """
    META_NAME = "syn_ack_ratio"
    
    def calculate(self, flows: List[FlowState]) -> float:
        """Tỷ lệ SYN / (SYN + ACK) từ forward packets (RAW VALUE)"""
        total_syn = 0
        total_ack = 0
        
        for f in flows:
            flags = f.get_fwd_tcp_flags_count()
            total_syn += flags['SYN']
            total_ack += flags['ACK']
        
        total = total_syn + total_ack
        if total == 0:
            return 0.0
        
        return float(total_syn) / float(total_ack + 1)


class FlowFeature3_DistinctPorts:
    """
    F3: DISTINCT PORTS (RAW VALUE - No normalization)
    Số ports đích khác nhau từ TẤT CẢ flows của src_ip
    
    Returns: Number of distinct destination ports
    """
    META_NAME = "distinct_ports"
    
    def calculate(self, flows: List[FlowState]) -> float:
        """Đếm số ports đích unique (RAW VALUE)"""
        all_ports = set()
        for f in flows:
            all_ports.update(f.get_distinct_ports())
        return float(len(all_ports))


class FlowFeature4_PayloadLength:
    """
    F4: PAYLOAD LENGTH (RAW VALUE - No normalization)
    
    Returns average payload length from forward packets.
    
    SIMPLIFIED: Always returns AVERAGE (removed outlier detection logic).
    Outlier detection was unstable for model training per code review.
    
    Returns: Average payload length in bytes
    """
    META_NAME = "payload_length"
    
    def calculate(self, flows: List[FlowState]) -> float:
        """Trung bình payload length (RAW VALUE)"""
        all_lengths = []
        for f in flows:
            all_lengths.extend(f.get_fwd_payload_lengths())
        
        if not all_lengths:
            return 0.0
        
        # Simplified: always return average
        return float(sum(all_lengths) / len(all_lengths))
    
    def calculate_all_stats(self, flows: List[FlowState]) -> dict:
        """
        Tính TẤT CẢ thống kê (cho debugging hoặc advanced features).
        
        Returns:
            dict: {'avg': float, 'max': float, 'var': float, 'count': int}
        """
        all_lengths = []
        for f in flows:
            all_lengths.extend(f.get_fwd_payload_lengths())
        
        if not all_lengths:
            return {'avg': 0.0, 'max': 0.0, 'var': 0.0, 'count': 0}
        
        return self._compute_stats(all_lengths)
    
    def _compute_stats(self, lengths: list) -> dict:
        """Tính avg, max, variance từ list lengths."""
        n = len(lengths)
        if n == 0:
            return {'avg': 0.0, 'max': 0.0, 'var': 0.0, 'count': 0}
        
        avg = sum(lengths) / n
        max_len = max(lengths)
        
        # Variance = E[(X - μ)²]
        if n > 1:
            variance = sum((x - avg) ** 2 for x in lengths) / n
        else:
            variance = 0.0
        
        return {
            'avg': avg,
            'max': max_len,
            'var': variance,
            'count': n
        }
    
    def calculate_all_stats(self, flows: List[FlowState]) -> dict:
        """
        Tính TẤT CẢ thống kê (cho debugging hoặc advanced features).
        
        Returns:
            dict: {'avg': float, 'max': float, 'var': float, 'count': int}
        """
        all_lengths = []
        for f in flows:
            all_lengths.extend(f.get_fwd_payload_lengths())
        
        if not all_lengths:
            return {'avg': 0.0, 'max': 0.0, 'var': 0.0, 'count': 0}
        
        return self._compute_stats(all_lengths)
    
    def _compute_stats(self, lengths: list) -> dict:
        """Tính avg, max, variance từ list lengths."""
        n = len(lengths)
        if n == 0:
            return {'avg': 0.0, 'max': 0.0, 'var': 0.0, 'count': 0}
        
        avg = sum(lengths) / n
        max_len = max(lengths)
        
        # Variance = E[(X - μ)²]
        if n > 1:
            variance = sum((x - avg) ** 2 for x in lengths) / n
        else:
            variance = 0.0
        
        return {
            'avg': avg,
            'max': max_len,
            'var': variance,
            'count': n
        }


class FlowFeature5_FailRate:
    """
    F5: FAIL RATE (RAW VALUE - No normalization)
    
    Đếm failures từ BACKWARD packets:
    1. RST từ server (port closed) - Port Scan detection
    2. HTTP 4xx/5xx từ server - Brute Force / Fuzzing detection
    
    Formula: (bwd_rst + http_errors) / total_packets
    
    HTTP STATUS PARSING REQUIREMENTS:
    ==================================
    - LayerInfo.http_status field được populate bởi PacketLayerExtractor
    - Yêu cầu: enable_http_parsing=True khi create extractor
    - Chỉ hoạt động với plain HTTP, KHÔNG hỗ trợ HTTPS encrypted traffic
    - HTTP status được parse từ payload: "HTTP/1.1 404 Not Found"
    
    Xem: packet_parser.py lines 245-255 cho implementation details
    
    Returns: Ratio in [0, 1] (already normalized by nature)
    """
    META_NAME = "fail_rate"
    
    def calculate(self, flows: List[FlowState]) -> float:
        """
        Tính tỷ lệ failures từ backward packets (RAW VALUE).
        
        Failures bao gồm:
        - RST từ server (port closed)
        - HTTP 4xx/5xx từ server (authentication failed, not found, etc.)
        """
        total_failures = 0
        total_packets = 0
        
        for f in flows:
            # 1. ĐẾM RST TỪ BACKWARD (server → client)
            bwd_flags = f.get_bwd_tcp_flags_count()
            total_failures += bwd_flags['RST']
            
            # 2. ĐẾM HTTP 4xx/5xx TỪ BACKWARD packets
            for pkt in f.get_bwd_packets():
                if hasattr(pkt, 'http_status') and pkt.http_status:
                    if pkt.http_status >= 400:
                        total_failures += 1
            
            # Tổng packets cả 2 chiều
            total_packets += f.get_packet_count()
        
        if total_packets == 0:
            return 0.0
        
        return float(total_failures) / float(total_packets)


class FlowFeature6_ContextScore:
    """F6: CONTEXT SCORE - Deep Packet Inspection for Malicious Patterns (RAW VALUE)

    Discrete domain by design: {-1.0, 0.0, 1.0}.
    - +1.0: malicious signature detected (SQL injection, XSS, shell commands)
    - -1.0: safe upload signature detected (images, static files)
    -  0.0: neutral
    
    PORT FILTERING LIMITATIONS:
    ===========================
    Current implementation only scans HTTP_PORTS = {80, 443, 808, 8443, 8000}
    
    SCENARIOS WHERE ATTACKS MAY BE MISSED:
    - Custom web server ports (3000, 4000, 5000, 8080, 8888, 9000)
    - Tunneled traffic via SSH (port 22), VPN
    - Non-HTTP attacks (FTP brute force port 21, Telnet port 23, SMB port 445)
    
    RECOMMENDED FOR PRODUCTION:
    - Option 1: Expand HTTP_PORTS list with common custom ports
    - Option 2: Content-based HTTP detection (check for "GET ", "POST ", "HTTP/")
    - Option 3: Remove port filtering entirely (may increase false positives)
    
    For offline PCAP analysis validation against CICFlowMeter, verify web server
    port configuration matches HTTP_PORTS list.
    
    Returns: Discrete score {-1.0, 0.0, 1.0} (no further normalization needed)
    """
    META_NAME = "context_score"
    
    HTTP_PORTS = {80, 443, 808, 8443, 8000}
    
    def calculate(self, flows: List[FlowState]) -> float:
        """Scan forward payloads for malicious/safe signatures.

        Priority:
        - If any payload is malicious => +1.0
        - Else if any payload is safe => -1.0
        - Else => 0.0
        """
        has_safe_upload = False

        for f in flows:
            # Use service port (dst_port) for forward direction.
            if f.dst_port not in self.HTTP_PORTS:
                continue

            for pkt in f.get_fwd_packets():
                raw = getattr(pkt, 'payload_bytes', None) or b''
                if not raw:
                    continue

                score = score_payload(raw)
                if score == config.CONTEXT_MALICIOUS:
                    return config.CONTEXT_MALICIOUS
                if score == config.CONTEXT_SAFE:
                    has_safe_upload = True

        if has_safe_upload:
            return config.CONTEXT_SAFE

        return config.CONTEXT_NEUTRAL


# ============================================================================
# AGGREGATOR CLASS - Thuận tiện để sử dụng
# ============================================================================

class FlowFeatureCalculator:
    """
    Aggregator class để tính tất cả 6 features từ flows (RAW VALUES ONLY).
    
    Usage:
        calculator = FlowFeatureCalculator()
        vector = calculator.calculate_all(flows)
        # vector = [f1_raw, f2_raw, f3_raw, f4_raw, f5_raw, f6_raw]
    
    IMPORTANT CHANGES:
    - All features now return RAW VALUES (no normalization)
    - Returns None if flows list is empty
    - Normalization should be done separately if needed
    
    For CICFlowMeter comparison: Use raw values directly
    For AI training: Apply your own norm alization after extraction
    """
    
    def __init__(self):
        self.calculators = [
            FlowFeature1_PacketRate(),
            FlowFeature2_SynAckRatio(),
            FlowFeature3_DistinctPorts(),
            FlowFeature4_PayloadLength(),
            FlowFeature5_FailRate(),
            FlowFeature6_ContextScore(),
        ]
    
    def calculate_all(self, flows: List[FlowState]) -> list:
        """
        Tính tất cả 6 features (RAW VALUES - no normalization).
        
        Returns:
            list: [f1_raw, f2_raw, f3_raw, f4_raw, f5_raw, f6_raw] nếu flows không rỗng
            None: nếu flows rỗng (không thể tính features)
        
        Example output:
            [2500.0, 0.85, 15.0, 800.0, 0.02, 1.0]
        """
        if not flows:
            return None  # Không trả về [0,0,0,0,0,0] - đó là invalid state
        return [calc.calculate(flows) for calc in self.calculators]
