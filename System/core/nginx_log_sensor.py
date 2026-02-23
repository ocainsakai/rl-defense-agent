"""Nginx Log Sensor - Parse nginx access log and compute application features.

Đọc nginx access log (lab_detail format) theo chế độ tail, extract HTTP
information, và tính toán features F6-F30 thông qua LogFlowState adapter.

Components:
- NidsLogEntry: Dataclass cho một dòng log
- NidsLogParser: Compiled regex parser cho lab_detail format
- LogFeatureCalculator: Subset calculator cho features liên quan đến HTTP
- NginxLogSensor: Tail-mode log reader + feature computation

Performance:
- Batch reading: đọc tất cả dòng mới mỗi iteration
- FeatureContext caching: mỗi payload normalize 1 lần
- Pre-compiled regex: O(1) pattern lookup
"""

import os
import re
import time
import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict

from core.log_flow_adapter import LogLayerInfo, LogResponseLayerInfo, LogFlowState

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class NidsLogEntry:
    """Một dòng từ nginx access.log (lab_detail format)."""
    remote_addr: str = ""
    timestamp: float = 0.0
    time_local: str = ""
    method: str = ""
    path: str = ""
    http_version: str = ""
    status: int = 0
    body_bytes_sent: int = 0
    request_time: float = 0.0
    upstream_response_time: float = 0.0
    upstream_addr: str = ""
    upstream_status: int = 0
    host: str = ""
    ssl_server_name: str = ""
    tls_info: str = ""
    referer: str = ""
    user_agent: str = ""
    x_forwarded_for: str = ""
    content_length: int = 0
    content_type: str = ""
    request_id: str = ""
    raw_line: str = ""


@dataclass
class LogFeatureResult:
    """Kết quả features từ NginxLogSensor cho một src_ip."""
    src_ip: str
    window_start: float
    window_end: float
    features: Dict[str, float]
    request_count: int = 0


# =============================================================================
# LOG PARSER
# =============================================================================

class NidsLogParser:
    """Parser cho nginx lab_detail log format.

    Format:
        $remote_addr - $remote_user [$time_local]
        "$request" $status $body_bytes_sent
        rt=$request_time urt=$upstream_response_time
        uaddr="$upstream_addr" ustatus="$upstream_status"
        host="$host" sni="$ssl_server_name"
        tls=$ssl_protocol/$ssl_cipher
        ref="$http_referer" ua="$http_user_agent"
        xff="$http_x_forwarded_for"
        cl="$http_content_length" ct="$http_content_type"
        reqid="$request_id"
    """

    # Compiled regex cho lab_detail format
    _PATTERN = re.compile(
        r'(?P<remote_addr>\S+)'
        r' - '
        r'(?P<remote_user>\S+)'
        r' \[(?P<time_local>[^\]]+)\]'
        r' "(?P<request>[^"]*)"'
        r' (?P<status>\d{3})'
        r' (?P<body_bytes_sent>\d+)'
        r'(?P<extra>.*)'
    )

    # Sub-patterns cho extra fields (compiled once)
    _RT_PATTERN = re.compile(r'rt=([\d.]+)')
    _URT_PATTERN = re.compile(r'urt=([\d.]+)')
    _UADDR_PATTERN = re.compile(r'uaddr="([^"]*)"')
    _USTATUS_PATTERN = re.compile(r'ustatus="([^"]*)"')
    _HOST_PATTERN = re.compile(r'host="([^"]*)"')
    _SNI_PATTERN = re.compile(r'sni="([^"]*)"')
    _TLS_PATTERN = re.compile(r'tls=(\S+)')
    _REF_PATTERN = re.compile(r'ref="([^"]*)"')
    _UA_PATTERN = re.compile(r'ua="([^"]*)"')
    _XFF_PATTERN = re.compile(r'xff="([^"]*)"')
    _CL_PATTERN = re.compile(r'cl="([^"]*)"')
    _CT_PATTERN = re.compile(r'ct="([^"]*)"')
    _REQID_PATTERN = re.compile(r'reqid="([^"]*)"')

    @classmethod
    def parse_line(cls, line: str) -> Optional[NidsLogEntry]:
        """Parse một dòng lab_detail log."""
        match = cls._PATTERN.match(line)
        if not match:
            return None

        entry = NidsLogEntry()
        entry.raw_line = line
        entry.remote_addr = match.group('remote_addr')
        entry.time_local = match.group('time_local')

        # Parse timestamp
        try:
            dt = datetime.strptime(entry.time_local, '%d/%b/%Y:%H:%M:%S %z')
            entry.timestamp = dt.timestamp()
        except (ValueError, TypeError):
            entry.timestamp = time.time()

        # Parse request line: "METHOD /path?q=attack payload HTTP/1.1"
        # URI can contain spaces (attack payloads), so split carefully:
        # - Split from left for METHOD (first space)
        # - Split from right for HTTP/x.x (last space)
        request_str = match.group('request')
        # Split off HTTP version from the right
        right_parts = request_str.rsplit(' ', 1)
        if len(right_parts) == 2 and right_parts[1].startswith('HTTP/'):
            method_and_path = right_parts[0]
            entry.http_version = right_parts[1]
            # Split off METHOD from the left
            first_space = method_and_path.find(' ')
            if first_space > 0:
                entry.method = method_and_path[:first_space]
                entry.path = method_and_path[first_space + 1:]
            else:
                entry.method = method_and_path
                entry.path = ''
        else:
            # Fallback: simple split
            req_parts = request_str.split(' ', 2)
            if len(req_parts) >= 2:
                entry.method = req_parts[0]
                entry.path = req_parts[1]
                if len(req_parts) >= 3:
                    entry.http_version = req_parts[2]

        entry.status = int(match.group('status'))
        entry.body_bytes_sent = int(match.group('body_bytes_sent'))

        # Parse extra fields
        extra = match.group('extra')
        if extra:
            cls._parse_extra(entry, extra)

        return entry

    @classmethod
    def _parse_extra(cls, entry: NidsLogEntry, extra: str) -> None:
        """Parse extra fields từ lab_detail format."""
        m = cls._RT_PATTERN.search(extra)
        if m:
            entry.request_time = float(m.group(1))

        m = cls._URT_PATTERN.search(extra)
        if m:
            try:
                entry.upstream_response_time = float(m.group(1))
            except ValueError:
                pass

        m = cls._UADDR_PATTERN.search(extra)
        if m:
            entry.upstream_addr = m.group(1)

        m = cls._USTATUS_PATTERN.search(extra)
        if m:
            try:
                entry.upstream_status = int(m.group(1))
            except ValueError:
                pass

        m = cls._HOST_PATTERN.search(extra)
        if m:
            entry.host = m.group(1)

        m = cls._SNI_PATTERN.search(extra)
        if m:
            entry.ssl_server_name = m.group(1)

        m = cls._TLS_PATTERN.search(extra)
        if m:
            entry.tls_info = m.group(1)

        m = cls._REF_PATTERN.search(extra)
        if m:
            entry.referer = m.group(1)

        m = cls._UA_PATTERN.search(extra)
        if m:
            entry.user_agent = m.group(1)

        m = cls._XFF_PATTERN.search(extra)
        if m:
            entry.x_forwarded_for = m.group(1)

        m = cls._CL_PATTERN.search(extra)
        if m:
            try:
                entry.content_length = int(m.group(1))
            except ValueError:
                pass

        m = cls._CT_PATTERN.search(extra)
        if m:
            entry.content_type = m.group(1)

        m = cls._REQID_PATTERN.search(extra)
        if m:
            entry.request_id = m.group(1)


# =============================================================================
# LOG FEATURE CALCULATOR
# =============================================================================

# Feature codes computed from nginx log (22 features)
LOG_FEATURE_CODES = [
    'F6', 'F7', 'F8',                                      # Application
    'F9', 'F10', 'F11', 'F12', 'F13', 'F14',              # Payload
    'F18', 'F19', 'F20', 'F21', 'F22', 'F23', 'F24',      # SQLi
    'F25', 'F26', 'F27', 'F28', 'F29', 'F30',             # XSS
]


class LogFeatureCalculator:
    """Tính F6-F30 từ LogFlowState objects.

    Dùng FeatureRegistry để instantiate chỉ 22 calculators cần thiết.
    Dùng FeatureContext để cache normalized payloads (performance).
    """

    def __init__(self, config=None):
        from feature.base import FeatureRegistry
        import feature.calculators  # noqa: F401 - trigger @register_feature

        self.calculators = []
        for code in LOG_FEATURE_CODES:
            try:
                calc = FeatureRegistry.instantiate(code, config=config)
                self.calculators.append((code, calc))
            except KeyError:
                logger.warning(f"Feature {code} not registered, skipping")

    def calculate(self, log_flows: List[LogFlowState],
                  context=None) -> Dict[str, float]:
        """Calculate F6-F30 features from LogFlowState objects.

        Args:
            log_flows: List of LogFlowState (adapter objects)
            context: Optional FeatureContext for caching

        Returns:
            Dict mapping feature code to raw value
        """
        if not log_flows:
            return {code: 0.0 for code, _ in self.calculators}

        # Create FeatureContext for caching if not provided
        if context is None:
            from feature.context import FeatureContext
            context = FeatureContext(log_flows)

        results = {}
        for code, calc in self.calculators:
            try:
                results[code] = calc.calculate(log_flows, context=context)
            except Exception as e:
                logger.debug(f"Feature {code} failed on log data: {e}")
                results[code] = 0.0

        return results


# =============================================================================
# NGINX LOG SENSOR
# =============================================================================

class NginxLogSensor:
    """Đọc nginx access log và tính application features.

    Chế độ hoạt động:
    - Tail mode: đọc dòng mới từ log file (giống tail -f)
    - Batch reading: đọc tất cả dòng mới mỗi iteration
    - Buffer entries theo src_ip
    - flush_window(): convert buffer → features → clear

    Thread-safety: _entries_lock protects _entries_buffer
    """

    def __init__(self, log_path: str, window_size: float = 1.0, config=None):
        self.log_path = log_path
        self.window_size = window_size
        self._calculator = LogFeatureCalculator(config=config)

        # Buffer: {src_ip: [NidsLogEntry, ...]}
        self._entries_buffer: Dict[str, List[NidsLogEntry]] = defaultdict(list)
        self._entries_lock = threading.Lock()

        # File reading state
        self._file_pos = 0
        self._file_inode = None

    def start_tail(self) -> None:
        """Seek to end of file (skip existing content)."""
        if not os.path.exists(self.log_path):
            logger.warning(f"Log file not found: {self.log_path}")
            return

        try:
            stat = os.stat(self.log_path)
            self._file_inode = getattr(stat, 'st_ino', None)
            self._file_pos = stat.st_size
            logger.info(f"NginxLogSensor: tailing {self.log_path} "
                        f"(pos={self._file_pos})")
        except OSError as e:
            logger.error(f"Cannot stat log file: {e}")

    def read_new_entries(self) -> int:
        """Đọc tất cả dòng mới từ log file (batch read).

        Returns:
            Số entries mới đã đọc
        """
        if not os.path.exists(self.log_path):
            return 0

        count = 0
        try:
            # Check for log rotation (inode change)
            stat = os.stat(self.log_path)
            current_inode = getattr(stat, 'st_ino', None)
            if self._file_inode and current_inode != self._file_inode:
                logger.info("Log file rotated, resetting position")
                self._file_pos = 0
                self._file_inode = current_inode

            # File shrunk (truncated)
            if stat.st_size < self._file_pos:
                logger.info("Log file truncated, resetting position")
                self._file_pos = 0

            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self._file_pos)
                lines = f.readlines()
                self._file_pos = f.tell()

            with self._entries_lock:
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    entry = NidsLogParser.parse_line(line)
                    if entry:
                        self._entries_buffer[entry.remote_addr].append(entry)
                        count += 1

        except OSError as e:
            logger.error(f"Error reading log: {e}")

        return count

    def flush_window(self, window_start: float = 0.0,
                     window_end: float = 0.0) -> Dict[str, LogFeatureResult]:
        """Convert buffered entries → LogFlowState → features → clear buffer.

        Returns:
            Dict mapping src_ip to LogFeatureResult
        """
        with self._entries_lock:
            buffer_snapshot = dict(self._entries_buffer)
            self._entries_buffer.clear()

        results = {}
        for src_ip, entries in buffer_snapshot.items():
            if not entries:
                continue

            # Convert entries to adapter objects
            fwd_packets = []
            bwd_packets = []
            for i, entry in enumerate(entries):
                fwd = LogLayerInfo(
                    remote_addr=entry.remote_addr,
                    timestamp=entry.timestamp,
                    method=entry.method,
                    path=entry.path,
                    user_agent=entry.user_agent,
                    host=entry.host,
                    content_length=entry.content_length,
                    request_id=entry.request_id,
                    packet_number=i,
                )
                fwd_packets.append(fwd)

                bwd = LogResponseLayerInfo(
                    remote_addr=entry.remote_addr,
                    timestamp=entry.timestamp,
                    status=entry.status,
                    packet_number=i,
                )
                bwd_packets.append(bwd)

            # Create LogFlowState
            log_flow = LogFlowState(
                src_ip=src_ip,
                fwd_packets=fwd_packets,
                bwd_packets=bwd_packets,
                window_size=self.window_size,
            )

            # Calculate features
            features = self._calculator.calculate([log_flow])

            results[src_ip] = LogFeatureResult(
                src_ip=src_ip,
                window_start=window_start,
                window_end=window_end,
                features=features,
                request_count=len(entries),
            )

        return results

    def get_buffer_size(self) -> int:
        """Số entries hiện tại trong buffer."""
        with self._entries_lock:
            return sum(len(v) for v in self._entries_buffer.values())
