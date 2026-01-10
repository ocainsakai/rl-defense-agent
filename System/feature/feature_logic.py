# features/logic.py
# Enhanced Security Version with:
# - Anti-ReDoS patterns
# - Multi-layer decoding (URL, HTML, Unicode)
# - Anti-Padding Attack protection

import re
import html
import unicodedata
from urllib.parse import unquote
from config import ai_config as config
from feature.feature_base import BaseFeatureCalculator
from core.layer_info import LayerInfo
from core.window_packet import PacketWindow


# --- F1: PACKET RATE ---
class Feature1_PacketRate(BaseFeatureCalculator):
    """
    FEATURE 1: TỐC ĐỘ GÓI TIN (PACKET RATE)
    
    CÔNG THỨC: packet_rate = số_gói_tin / window_size (packets/giây)
    
    ỨNG DỤNG:
    - Phát hiện tấn công DDoS, Flood
    - Bình thường: 10-100 pkt/s
    - Tấn công: 1000+ pkt/s
    
    CHUẨN HÓA: rate / MAX_PACKET_RATE (3000)
    - 0.0 = không có hoạt động
    - 1.0 = đạt nghi ngờ cao nhất (3000+ pkt/s)
    """
    META_NAME = "packet_rate"
    META_MAX = config.MAX_PACKET_RATE
    
    def calculate_raw(self, info: LayerInfo, window: PacketWindow) -> float:
        """
        Tính tốc độ gói tin từ IP nguồn trong cửa sổ thời gian.
        
        Returns:
            float: Số gói tin / giây
        """
        if not info.has_ip: 
            return 0.0
        return float(window.get_count(info.src_ip)) / window.window_size


# --- F2: SYN RATIO ---
class Feature2_SynAckRatio(BaseFeatureCalculator):
    """
    FEATURE 2: TỶ LỆ SYN/ACK
    
    CÔNG THỨC: syn_ratio = SYN_count / (SYN_count + ACK_count)
    
    ỨNG DỤNG:
    - Phát hiện SYN Flood attack
    - Bình thường: SYN và ACK cân bằng (~0.5)
    - Tấn công SYN Flood: Chỉ có SYN, không có ACK (~1.0)
    
    CHUẨN HÓA: Giá trị đã trong [0, 1]
    - 0.0 = chỉ có ACK (normal response)
    - 0.5 = cân bằng SYN/ACK (kết nối bình thường)
    - 1.0 = chỉ có SYN (SYN Flood attack)
    """
    META_NAME = "syn_ack_ratio"
    META_MAX = config.MAX_SYN_RATIO
    
    def calculate_raw(self, info: LayerInfo, window: PacketWindow) -> float:
        """
        Tính tỷ lệ SYN trên tổng SYN+ACK.
        
        Returns:
            float: Tỷ lệ SYN trong [0, 1]
        """
        if not info.has_ip: 
            return 0.0
        flags = window.get_tcp_flags_count(info.src_ip)
        total = flags['SYN'] + flags['ACK']
        if total == 0: 
            return 0.0
        return float(flags['SYN']) / float(total)


# --- F3: DISTINCT PORTS ---
class Feature3_DistinctPorts(BaseFeatureCalculator):
    """
    FEATURE 3: SỐ CỔNG ĐÍCH KHÁC NHAU (DISTINCT PORTS)
    
    CÔNG THỨC: distinct_ports = len(unique_dst_ports)
    
    ỨNG DỤNG:
    - Phát hiện Port Scan attack
    - Bình thường: 1-5 ports (web, email, v.v.)
    - Tấn công Port Scan: 50-100+ ports trong 1 giây
    
    CHUẨN HÓA: ports / MAX_DISTINCT_PORTS (100)
    - 0.0 = không có kết nối outbound
    - 1.0 = 100+ ports khác nhau (Port Scan nghi ngờ cao)
    """
    META_NAME = "distinct_ports"
    META_MAX = config.MAX_DISTINCT_PORTS
    
    def calculate_raw(self, info: LayerInfo, window: PacketWindow) -> float:
        """
        Đếm số cổng đích khác nhau đã kết nối.
        
        Returns:
            float: Số lượng cổng đích duy nhất
        """
        if not info.has_ip: 
            return 0.0
        return float(len(window.get_distinct_ports(info.src_ip)))


# --- F4: PAYLOAD LENGTH ---
class Feature4_PayloadLength(BaseFeatureCalculator):
    """
    Payload Length với Outlier Detection.
    
    Logic:
    - Bình thường: return average payload length
    - Nếu có outlier (max > 3× avg và > 500 bytes): return max
    
    Mục đích: Phát hiện buffer overflow attacks khi có 1 packet payload cực lớn giữa nhiều packets bình thường.
    """
    META_NAME = "payload_length"
    META_MAX = config.MAX_PAYLOAD_LEN
    
    # Ngưỡng để xác định outlier
    OUTLIER_MULTIPLIER = 3.0  # max > 3× avg
    MIN_OUTLIER_SIZE = 500    # min 500 bytes để tránh false positive
    
    def calculate_raw(self, info: LayerInfo, window: PacketWindow) -> float:
        if not info.has_ip: 
            return 0.0
        lengths = window.get_payload_lengths(info.src_ip)
        if not lengths: 
            return 0.0
        
        avg = sum(lengths) / len(lengths)
        max_len = max(lengths)
        
        # Outlier detection: nếu max > 3× avg và > 500 bytes
        if max_len > avg * self.OUTLIER_MULTIPLIER and max_len > self.MIN_OUTLIER_SIZE:
            return float(max_len)
        
        return float(avg)


# --- F5: FAIL RATE (Enhanced with Bidirectional Tracking) ---
class Feature5_FailRate(BaseFeatureCalculator):
    """
    Fail Rate với Bidirectional Tracking.
    
    Nguồn lỗi được đếm:
    1. Outbound failures:
       - RST từ src_ip (connection reset by client)
       - ICMP Unreachable từ src_ip
       - HTTP 4xx/5xx status trong request
       
    2. Inbound failures (MỚI):
       - RST từ destination IP (port closed, connection refused)
       - ICMP Unreachable từ destination
       
    Formula: (outbound_fails + inbound_fails) / (outbound_total + inbound_total)
    
    Use case: Port Scan - victim gửi RST về khi port đóng
    """
    META_NAME = "fail_rate"
    META_MAX = config.MAX_FAIL_RATE
    
    def calculate_raw(self, info: LayerInfo, window: PacketWindow) -> float:
        if not info.has_ip: 
            return 0.0
        
        # Lấy packets outbound từ src_ip
        outbound_packets = window.get_packets(info.src_ip)
        
        # Lấy packets inbound (response từ destination IPs)
        inbound_packets = window.get_response_packets(info.src_ip)
        
        total = len(outbound_packets) + len(inbound_packets)
        if total == 0: 
            return 0.0
        
        failed = 0
        
        # Đếm failures từ outbound packets
        for pkt in outbound_packets:
            is_l4 = pkt.is_reset or pkt.is_icmp_unreach
            is_l7 = pkt.http_status is not None and pkt.http_status >= 400
            if is_l4 or is_l7: 
                failed += 1
        
        # Đếm failures từ inbound packets (RST từ victim)
        for pkt in inbound_packets:
            is_l4 = pkt.is_reset or pkt.is_icmp_unreach
            if is_l4: 
                failed += 1
            
        return float(failed) / float(total)


# --- F6: CONTEXT SCORE (Enhanced Security + Performance Optimized) ---
class Feature6_ContextScore(BaseFeatureCalculator):
    """
    Context Score với Multi-Layer Defense:
    
    Security Features:
    1. Anti-ReDoS: Giới hạn quantifiers trong regex
    2. Multi-layer Decoding: URL, HTML, Unicode normalization
    3. Anti-Padding Attack:
       - Whitespace collapsing
       - Multi-point sampling (HEAD, MIDDLE, TAIL, STRIPPED)
       - Padding ratio detection
    
    Performance Optimizations:
    1. Class-level regex compilation (compile 1 lần khi load module)
    2. Fail-fast check (skip regex nếu không có suspicious chars)
    
    Author: Security Enhanced + Performance Optimized Version
    """
    
    META_NAME = "context_score"
    
    # =====================================================
    # CONFIGURATION
    # =====================================================
    
    # Kích thước tối đa payload xử lý (tránh DoS)
    MAX_PAYLOAD_TOTAL = 65536      # 64KB max
    
    # Kích thước mỗi vùng scan
    SCAN_CHUNK_SIZE = 4096         # 4KB per chunk
    
    # Ngưỡng phát hiện padding attack
    PADDING_RATIO_THRESHOLD = 0.8  # 80% whitespace = suspicious
    MIN_PAYLOAD_FOR_RATIO = 1000   # Chỉ check ratio nếu payload > 1KB
    
    # Số lần decode tối đa (chống infinite loop)
    MAX_DECODE_ITERATIONS = 3
    
    # =====================================================
    # FAIL-FAST: Suspicious Characters
    # =====================================================
    # Chỉ scan regex nếu payload chứa ít nhất 1 ký tự này
    SUSPICIOUS_CHARS = frozenset('<>\'"`;(){}[]$&|\\/')
    FAIL_FAST_SAMPLE_SIZE = 2000  # Check 2KB đầu
    
    # =====================================================
    # CLASS-LEVEL COMPILED PATTERNS (compile 1 lần)
    # =====================================================
    
    # SQL Injection Patterns
    _SQL_PATTERNS = [
        r"union\s{1,10}select",
        r"union\s{1,10}all\s{1,10}select",
        r"'\s{0,5}or\s{1,10}['\"0-9]",
        r"'\s{0,5}and\s{1,10}['\"0-9]",
        r";\s{0,5}drop\s{1,10}table",
        r";\s{0,5}delete\s{1,10}from",
        r"'\s{0,5};\s{0,5}--",
        r"order\s{1,10}by\s{1,10}\d{1,5}",
        r"group\s{1,10}by\s{1,10}\d{1,5}",
        r"having\s{1,10}['\"0-9]",
        r"waitfor\s{1,10}delay",
        r"benchmark\s{0,3}\(",
        r"sleep\s{0,3}\(",
        r"load_file\s{0,3}\(",
        r"into\s{1,10}outfile",
        r"into\s{1,10}dumpfile",
    ]
    
    # XSS Patterns
    _XSS_PATTERNS = [
        r"<script",
        r"javascript\s{0,3}:",
        r"on(?:error|load|click|mouse|focus|blur|change|submit)\s{0,3}=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"<svg\s{0,5}onload",
        r"<img\s{1,10}src\s{0,3}=\s{0,3}[\"']?javascript:",
        r"expression\s{0,3}\(",
        r"vbscript\s{0,3}:",
        r"<body\s{1,10}onload",
        r"<input\s{1,10}onfocus",
    ]
    
    # Command Injection Patterns
    _CMD_PATTERNS = [
        r";\s{0,3}cat\s",
        r";\s{0,3}ls\s",
        r";\s{0,3}id\s{0,3}$",
        r";\s{0,3}whoami",
        r";\s{0,3}uname",
        r"\|\s{0,3}cat\s",
        r"\|\s{0,3}sh\s{0,3}$",
        r"\|\s{0,3}bash",
        r"`[^`]{1,100}`",
        r"\$\([^)]{1,100}\)",
        r"\$\{[^}]{1,50}\}",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self",
        r"c:\\windows\\system32",
        r"cmd\.exe",
        r"powershell",
        r"certutil\s{0,5}-urlcache",
    ]
    
    # Path Traversal Patterns
    _TRAVERSAL_PATTERNS = [
        r"\.\.[/\\]",
        r"\.\.%2[fF]",
        r"\.\.%5[cC]",
        r"%2e%2e[/\\%]",
        r"\.\.%c0%af",
        r"\.\.%c1%9c",
    ]
    
    # PHP/Web Shell Patterns
    _WEBSHELL_PATTERNS = [
        r"<\?php",
        r"<\?=",
        r"eval\s{0,3}\(",
        r"base64_decode\s{0,3}\(",
        r"gzinflate\s{0,3}\(",
        r"gzuncompress\s{0,3}\(",
        r"str_rot13\s{0,3}\(",
        r"system\s{0,3}\(",
        r"exec\s{0,3}\(",
        r"passthru\s{0,3}\(",
        r"shell_exec\s{0,3}\(",
        r"popen\s{0,3}\(",
        r"proc_open\s{0,3}\(",
        r"assert\s{0,3}\(",
        r"preg_replace\s{0,3}\(.{0,20}/e",
        r"create_function\s{0,3}\(",
        r"\$_(?:GET|POST|REQUEST|COOKIE)\s{0,3}\[",
    ]
    
    # SSRF/XXE Patterns
    _SSRF_PATTERNS = [
        r"file://",
        r"gopher://",
        r"dict://",
        r"ftp://",
        r"ldap://",
        r"<!entity\s",
        r"<!doctype\s{1,10}[^>]{0,50}entity",
        r"xmlns:xi\s{0,3}=",
    ]
    
    # Safe Patterns
    _SAFE_PATTERNS = [
        r"^POST\s{1,5}/upload",
        r"content-type:\s{0,5}image/",
        r"content-type:\s{0,5}application/json",
        r"content-type:\s{0,5}text/plain",
    ]
    
    # Compile all patterns at class definition time (once)
    DANGEROUS_REGEX = None  # Will be initialized in _init_class_patterns
    SAFE_REGEX = None
    _PATTERNS_COMPILED = False
    
    @classmethod
    def _init_class_patterns(cls):
        """Biên dịch các pattern một lần tại khi sử dụng đầu tiên (lazy init)"""
        if cls._PATTERNS_COMPILED:
            return
        
        all_dangerous = (
            cls._SQL_PATTERNS + cls._XSS_PATTERNS + cls._CMD_PATTERNS +
            cls._TRAVERSAL_PATTERNS + cls._WEBSHELL_PATTERNS + cls._SSRF_PATTERNS
        )
        cls.DANGEROUS_REGEX = [re.compile(p, re.IGNORECASE) for p in all_dangerous]
        cls.SAFE_REGEX = [re.compile(p, re.IGNORECASE) for p in cls._SAFE_PATTERNS]
        cls._PATTERNS_COMPILED = True
    
    def __init__(self):
        super().__init__()
        self.name = "context_score"
        self.min_val = config.CONTEXT_SAFE      # -1.0
        self.max_val = config.CONTEXT_MALICIOUS # 1.0
        
        # Ensure class patterns are compiled (lazy init, only once)
        self._init_class_patterns()
    
    def _has_suspicious_chars(self, sample: str) -> bool:
        """
        Fail-fast check: payload có chứa ký tự đáng ngờ không?
        
        Nếu không có ký tự như < > ' " ; ( ) thì không cần scan regex.
        Giúp tiết kiệm CPU đáng kể với traffic bình thường.
        
        Args:
            sample: Sample string để check
            
        Returns:
            True nếu có ký tự đáng ngờ
        """
        return any(c in self.SUSPICIOUS_CHARS for c in sample)
    
    def _is_binary_payload(self, raw_bytes: bytes) -> bool:
        """
        Nhận diện binary payload (video, image, encrypted, compressed).
        
        Binary payload có tỷ lệ non-printable chars cao.
        Tránh false positive khi scan regex trên binary data.
        
        Args:
            raw_bytes: Payload bytes thô
            
        Returns:
            True nếu là binary payload (không nên scan regex)
        """
        if len(raw_bytes) < 100:
            return False
        
        # Lấy sample đầu tiên
        sample = raw_bytes[:1000]
        
        # Đếm printable ASCII chars (32-126) và whitespace
        printable_count = sum(
            1 for b in sample 
            if 32 <= b <= 126 or b in (9, 10, 13)  # Tab, LF, CR
        )
        
        ratio = printable_count / len(sample)
        
        # Nếu < 70% printable → Binary (video, encrypted, compressed)
        # Không nên scan regex vì sẽ false positive
        return ratio < 0.70
    
    # =====================================================
    # ANTI-PADDING ATTACK METHODS
    # =====================================================
    
    def _detect_padding_attack(self, raw_bytes: bytes) -> bool:
        """
        Phát hiện Padding Attack dựa trên:
        1. Tỷ lệ whitespace/padding quá cao (>80%)
        2. Pattern lặp lại bất thường
        
        Args:
            raw_bytes: Payload bytes thô
            
        Returns:
            True nếu nghi ngờ là padding attack
        """
        if len(raw_bytes) < self.MIN_PAYLOAD_FOR_RATIO:
            return False
        
        # Đếm các ký tự padding phổ biến
        padding_chars = {ord(' '), ord('\t'), ord('\n'), ord('\r'), 0, 11, 12}
        padding_count = sum(1 for b in raw_bytes if b in padding_chars)
        
        ratio = padding_count / len(raw_bytes)
        
        # Nếu > 80% là whitespace → Padding Attack
        if ratio > self.PADDING_RATIO_THRESHOLD:
            return True
        
        # Kiểm tra pattern lặp lại (VD: "AAAA...AAAA")
        # Lấy sample 100 bytes đầu
        sample = raw_bytes[:100]
        if len(set(sample)) <= 3:  # Chỉ có ≤3 ký tự khác nhau
            return True
        
        return False
    
    def _collapse_whitespace(self, text: str) -> str:
        """
        Thu gọn whitespace để chống padding:
        - Nhiều spaces → 1 space
        - Xóa leading/trailing whitespace
        
        Args:
            text: Input string
            
        Returns:
            String đã thu gọn whitespace
        """
        # Thu gọn multiple whitespace thành single space
        collapsed = re.sub(r'\s+', ' ', text)
        return collapsed.strip()
    
    def _multi_point_sample(self, raw_bytes: bytes) -> list:
        """
        Lấy samples từ nhiều vị trí trong payload:
        1. HEAD: Đầu payload
        2. MIDDLE: Giữa payload  
        3. TAIL: Cuối payload
        4. STRIPPED: Sau khi loại bỏ whitespace đầu
        
        Args:
            raw_bytes: Payload bytes thô
            
        Returns:
            List of (sample_name, sample_bytes)
        """
        total_len = len(raw_bytes)
        chunk = self.SCAN_CHUNK_SIZE
        
        samples = []
        
        # 1. HEAD: [0 : chunk]
        samples.append(("HEAD", raw_bytes[:chunk]))
        
        # 2. MIDDLE: [middle - chunk/2 : middle + chunk/2]
        if total_len > chunk * 2:
            mid_start = (total_len // 2) - (chunk // 2)
            mid_end = mid_start + chunk
            samples.append(("MIDDLE", raw_bytes[mid_start:mid_end]))
        
        # 3. TAIL: [-chunk : end]
        if total_len > chunk:
            samples.append(("TAIL", raw_bytes[-chunk:]))
        
        # 4. STRIPPED: Loại bỏ leading whitespace rồi lấy chunk đầu
        stripped = raw_bytes.lstrip(b' \t\n\r\x00')
        if len(stripped) > 0 and stripped != raw_bytes[:len(stripped)]:
            samples.append(("STRIPPED", stripped[:chunk]))
        
        return samples
    
    # =====================================================
    # PAYLOAD NORMALIZATION (Multi-Layer Decoding)
    # =====================================================
    
    def _normalize_payload(self, raw_bytes: bytes) -> str:
        """
        Multi-layer payload normalization:
        
        Pipeline:
        1. Bytes → String (UTF-8 decode)
        2. Recursive URL Decoding (%XX → char)
        3. HTML Entity Decoding (&#60; → <)
        4. Unicode Normalization (NFKC)
        5. Whitespace Collapsing (chống padding nhỏ)
        6. Remove null bytes
        7. Lowercase
        
        Args:
            raw_bytes: Payload bytes thô
            
        Returns:
            Normalized string để scan patterns
        """
        try:
            # Step 1: Bytes to String
            payload = raw_bytes.decode('utf-8', errors='ignore')
            
            # Step 2: Recursive URL Decoding
            # Attacker có thể double/triple encode: %253C = %3C = <
            for _ in range(self.MAX_DECODE_ITERATIONS):
                decoded = unquote(payload)
                if decoded == payload:  # Không còn gì để decode
                    break
                payload = decoded
            
            # Step 3: HTML Entity Decoding
            # &#60; = < , &lt; = <
            payload = html.unescape(payload)
            
            # Step 4: Unicode Normalization (NFKC)
            # Chuyển các ký tự đặc biệt về dạng chuẩn:
            # - ᴜɴɪᴏɴ → UNION (small caps → normal)
            # - ＜ → < (fullwidth → normal)
            # - ① → 1 (circled → normal)
            payload = unicodedata.normalize('NFKC', payload)
            
            # Step 5: Remove null bytes (bypass technique)
            payload = payload.replace('\x00', '')
            
            # Step 6: Collapse whitespace (chống padding nhỏ)
            payload = self._collapse_whitespace(payload)
            
            # Step 7: Lowercase for case-insensitive matching
            payload = payload.lower()
            
            return payload
            
        except Exception:
            return ""
    
    # =====================================================
    # PATTERN SCANNING
    # =====================================================
    
    def _scan_for_patterns(self, payload: str) -> float:
        """
        Scan payload cho dangerous/safe patterns
        
        Args:
            payload: Normalized payload string
            
        Returns:
            CONTEXT_MALICIOUS, CONTEXT_SAFE, hoặc CONTEXT_NEUTRAL
        """
        if not payload:
            return config.CONTEXT_NEUTRAL
        
        # FAIL-FAST: Skip regex scan nếu không có suspicious chars
        # Check toàn bộ payload (đã được normalize và collapse whitespace)
        if not self._has_suspicious_chars(payload):
            return config.CONTEXT_NEUTRAL
        
        # Priority 1: Check DANGEROUS patterns
        for regex in self.DANGEROUS_REGEX:
            if regex.search(payload):
                return config.CONTEXT_MALICIOUS
        
        # Priority 2: Check SAFE patterns
        for regex in self.SAFE_REGEX:
            if regex.search(payload):
                return config.CONTEXT_SAFE
        
        return config.CONTEXT_NEUTRAL
    
    # =====================================================
    # MAIN CALCULATION METHOD
    # =====================================================
    
    def calculate_raw(self, info: LayerInfo, window: PacketWindow) -> float:
        """
        Enhanced calculation với Multi-Layer Defense.
        
        Security Flow:
        1. Kiểm tra có payload không
        2. Giới hạn kích thước tối đa (tránh DoS)
        3. Phát hiện Padding Attack → Strip và scan
        4. Multi-point sampling (HEAD, MIDDLE, TAIL, STRIPPED)
        5. Scan từng sample
        6. Trả về kết quả nghiêm trọng nhất
        
        Args:
            info: LayerInfo từ gói tin
            window: PacketWindow chứa context
            
        Returns:
            CONTEXT_MALICIOUS (1.0), CONTEXT_SAFE (-1.0), hoặc CONTEXT_NEUTRAL (0.0)
        """
        # Bước 0: Kiểm tra có payload không
        if not info.payload_bytes:
            return config.CONTEXT_NEUTRAL
        
        raw_bytes = info.payload_bytes
        
        # Bước 1: Giới hạn kích thước để tránh DoS
        if len(raw_bytes) > self.MAX_PAYLOAD_TOTAL:
            raw_bytes = raw_bytes[:self.MAX_PAYLOAD_TOTAL]
        
        # =====================================================
        # LAYER 0: Skip Binary Payload (video, encrypted, etc.)
        # =====================================================
        if self._is_binary_payload(raw_bytes):
            # Binary traffic (YouTube video, encrypted, compressed)
            # Không scan regex để tránh false positive
            return config.CONTEXT_NEUTRAL
        
        # =====================================================
        # LAYER 1: Phát hiện Padding Attack
        # =====================================================
        if self._detect_padding_attack(raw_bytes):
            # Padding attack detected!
            # Strip tất cả leading/trailing padding và scan
            stripped = raw_bytes.strip(b' \t\n\r\x00')
            
            if stripped:
                normalized = self._normalize_payload(stripped)
                result = self._scan_for_patterns(normalized)
                if result == config.CONTEXT_MALICIOUS:
                    # TODO: Log padding attack attempt
                    # security_logger.warning(
                    #     f"Padding attack detected from {info.src_ip}"
                    # )
                    return config.CONTEXT_MALICIOUS
        
        # =====================================================
        # LAYER 2: Multi-Point Sampling
        # =====================================================
        samples = self._multi_point_sample(raw_bytes)
        
        results = []
        for sample_name, sample_bytes in samples:
            normalized = self._normalize_payload(sample_bytes)
            result = self._scan_for_patterns(normalized)
            results.append(result)
            
            # Early exit: Nếu tìm thấy MALICIOUS ở bất kỳ đâu → Return ngay
            if result == config.CONTEXT_MALICIOUS:
                # TODO: Log with sample_name for forensics
                # security_logger.warning(
                #     f"Malicious in {sample_name} from {info.src_ip}"
                # )
                return config.CONTEXT_MALICIOUS
        
        # =====================================================
        # LAYER 3: Kết luận cuối cùng
        # =====================================================
        
        # Nếu có ít nhất 1 SAFE → SAFE
        if config.CONTEXT_SAFE in results:
            return config.CONTEXT_SAFE
        
        return config.CONTEXT_NEUTRAL
    
    # =====================================================
    # NORMALIZATION OVERRIDE
    # =====================================================
    
    def normalize(self, value: float) -> float:
        """
        Override normalize cho F6 vì có giá trị âm.
        
        Min-Max Scaling:
        - (-1 - -1) / (1 - -1) = 0/2 = 0.0 (SAFE)
        - (0 - -1) / (1 - -1) = 1/2 = 0.5 (NEUTRAL)
        - (1 - -1) / (1 - -1) = 2/2 = 1.0 (MALICIOUS)
        
        Args:
            value: Raw context score (-1, 0, or 1)
            
        Returns:
            Normalized value trong range [0, 1]
        """
        rng = self.max_val - self.min_val
        if rng == 0:
            return 0.0
        return (value - self.min_val) / rng