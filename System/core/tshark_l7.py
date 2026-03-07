"""
TsharkL7Reader - TLS-aware L7 enrichment using tshark + SSLKEYLOGFILE.

Runs a tshark subprocess in parallel with Scapy to decrypt HTTPS and
extract HTTP fields (URI, method, user-agent, POST body).

Usage in _run_realtime():
    reader = TsharkL7Reader(interface='r-ext', keylog_file='/tmp/tls_keys.log')
    reader.start()
    ...
    events = reader.drain_events()  # {(src_ip, sport): [event_dict, ...]}
    _enrich_flows_with_tshark(all_flows, events)
    reader.stop()

event_dict keys:
    timestamp      (float)  wire timestamp from tshark
    src_ip         (str)
    sport          (int)
    dst_ip         (str)
    dport          (int)
    http_method    (str)    GET, POST, ...
    http_uri       (str)    /path?params
    http_user_agent(str)
    payload        (bytes)  composite: URI + User-Agent + POST body
"""

import subprocess
import threading
import logging
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Field separator: SOH char, never appears in HTTP values
_SEP = '\x01'


class TsharkL7Reader:
    """
    Reads decrypted HTTP events from tshark via SSLKEYLOGFILE.

    Stores events indexed by (src_ip, sport) for efficient flow lookup.
    Thread-safe: drain_events() can be called from main thread at any time.
    """

    def __init__(self, interface: str, keylog_file: str):
        self._iface = interface
        self._keylog = keylog_file
        self._events: Dict[Tuple[str, int], List[dict]] = {}
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        """Start tshark subprocess and background reader thread."""
        # Pre-create keylog file so tshark can watch it from start
        try:
            open(self._keylog, 'a').close()
        except Exception:
            pass

        cmd = [
            'tshark', '-i', self._iface,
            '-o', f'tls.keylog_file:{self._keylog}',
            '-Y', 'http.request',
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'tcp.srcport',
            '-e', 'ip.dst',
            '-e', 'tcp.dstport',
            '-e', 'http.request.method',
            '-e', 'http.request.uri',
            '-e', 'http.user_agent',
            '-e', 'http.file_data',       # POST body (URL-encoded or raw)
            '-E', f'separator={_SEP}',
            '-l',                          # line-buffered stdout
        ]

        logger.info(f"TsharkL7Reader: starting on {self._iface}, keylog={self._keylog}")
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        self._running = True
        self._thread = threading.Thread(
            target=self._reader_loop, daemon=True, name='tshark-l7'
        )
        self._thread.start()
        logger.info("TsharkL7Reader: started (pid=%d)", self._proc.pid)

    def _reader_loop(self) -> None:
        """Parse tshark output lines and store HTTP events."""
        for line in self._proc.stdout:
            if not self._running:
                break
            line = line.rstrip('\n')
            if not line:
                continue
            try:
                parts = line.split(_SEP)
                if len(parts) < 6:
                    continue
                ts_str, src_ip, sport_str, dst_ip, dport_str, method = parts[:6]
                uri        = parts[6] if len(parts) > 6 else ''
                user_agent = parts[7] if len(parts) > 7 else ''
                file_data  = parts[8] if len(parts) > 8 else ''

                if not src_ip or not method:
                    continue

                sport = int(sport_str) if sport_str else 0
                dport = int(dport_str) if dport_str else 443
                ts    = float(ts_str)  if ts_str    else time.time()

                # Build composite payload: URI + User-Agent + POST body
                composite = uri
                if user_agent:
                    composite += ' ' + user_agent
                if file_data:
                    composite += ' ' + file_data

                event = {
                    'timestamp':       ts,
                    'src_ip':          src_ip,
                    'sport':           sport,
                    'dst_ip':          dst_ip,
                    'dport':           dport,
                    'http_method':     method,
                    'http_uri':        uri,
                    'http_user_agent': user_agent,
                    'payload':         composite.encode('utf-8', errors='ignore'),
                }

                with self._lock:
                    self._events.setdefault((src_ip, sport), []).append(event)

            except Exception as e:
                logger.debug("TsharkL7Reader parse error: %s | line: %.100s", e, line)

    def drain_events(self) -> Dict[Tuple[str, int], List[dict]]:
        """Return and clear all pending HTTP events.

        Returns:
            {(src_ip, sport): [event_dict, ...]}
        """
        with self._lock:
            events = dict(self._events)
            self._events.clear()
        return events

    def stop(self) -> None:
        """Stop tshark subprocess."""
        self._running = False
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        logger.info("TsharkL7Reader: stopped")


def enrich_flows_with_tshark(all_flows: list, tshark_events: dict) -> int:
    """Inject tshark HTTP data into matching TCP packets inside FlowState objects.

    For each tshark HTTP event, find the best-matching forward TCP packet in the
    corresponding flow (matched by src_ip + sport + approximate timestamp within
    500ms) and enrich it in-place with HTTP fields.

    Does NOT add or remove packets - only modifies existing LayerInfo fields.
    F1-F11 (network features) are unaffected since packet counts stay the same.

    Args:
        all_flows: list of FlowState objects from flow_manager.get_all_flows()
        tshark_events: dict from TsharkL7Reader.drain_events()

    Returns:
        Number of packets enriched.
    """
    if not tshark_events:
        return 0

    # Build lookup: (src_ip, sport) -> flat list of fwd LayerInfo objects
    flow_pkts: Dict[tuple, list] = {}
    for fl in all_flows:
        key = (fl.src_ip, fl.src_port)
        flow_pkts.setdefault(key, []).extend(fl.get_fwd_packets())

    enriched = 0
    for (src_ip, sport), events in tshark_events.items():
        pkts = flow_pkts.get((src_ip, sport))
        if not pkts:
            continue

        for event in events:
            ts = event['timestamp']

            # Find closest unmatched TCP data packet within 500ms
            best_pkt = None
            best_diff = float('inf')
            for pkt in pkts:
                if pkt.has_http:          # already enriched
                    continue
                if pkt.timestamp is None:
                    continue
                flags = str(pkt.tcp_flags or '')
                # Data packets carry PSH or ACK+data; skip pure ACK/SYN/FIN/RST
                if not ('P' in flags or ('A' in flags and pkt.payload_length > 0)):
                    continue
                diff = abs(pkt.timestamp - ts)
                if diff < best_diff and diff < 0.5:
                    best_diff = diff
                    best_pkt = pkt

            if best_pkt is not None:
                best_pkt.has_http        = True
                best_pkt.http_method     = event['http_method']
                best_pkt.http_uri        = event['http_uri']
                best_pkt.http_user_agent = event['http_user_agent']
                best_pkt.has_payload     = True
                best_pkt.payload_bytes   = event['payload']
                best_pkt.payload_length  = len(event['payload'])
                enriched += 1

    return enriched
