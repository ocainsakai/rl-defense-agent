"""
helpers.py - Shared test utilities.

Packet builders, dataset loaders, and common helpers
used across multiple test files.
"""

import csv
import os
from dataclasses import dataclass
from typing import List, Tuple, Optional
from urllib.parse import parse_qs, unquote_plus

from scapy.all import IP, TCP, UDP, Raw, Ether


# ============================================================================
# DATASET DIRECTORY
# ============================================================================

DATASET_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'dataset'
)


# ============================================================================
# PACKET BUILDERS
# ============================================================================

def make_tcp_packet(src_ip="192.168.1.100", dst_ip="10.0.0.1",
                    sport=5000, dport=80, flags="S",
                    seq=0, ack=0, window=65535,
                    payload=None, timestamp=None):
    """Build a TCP packet with Scapy."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags=flags,
        seq=seq, ack=ack, window=window
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    if timestamp is not None:
        pkt.time = timestamp
    return pkt


def make_udp_packet(src_ip="192.168.1.100", dst_ip="8.8.8.8",
                    sport=12345, dport=53,
                    payload=None, timestamp=None):
    """Build a UDP packet with Scapy."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(
        sport=sport, dport=dport
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    if timestamp is not None:
        pkt.time = timestamp
    return pkt


def make_http_packet(payload_text, src_ip="192.168.1.100", dst_ip="10.0.0.1",
                     sport=5000, dport=80, seq_num=0, method="GET",
                     timestamp=None):
    """Build an HTTP packet embedding payload_text into the request."""
    if method.upper() == "POST":
        http_request = (
            f"POST /page HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(payload_text)}\r\n"
            f"\r\n"
            f"{payload_text}"
        ).encode('utf-8', errors='ignore')
    else:
        http_request = (
            f"GET /page?q={payload_text} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode('utf-8', errors='ignore')

    return make_tcp_packet(
        src_ip=src_ip, dst_ip=dst_ip,
        sport=sport + (seq_num % 1000), dport=dport,
        flags="PA", seq=seq_num,
        payload=http_request, timestamp=timestamp,
    )


def reconstruct_http_packet(method, url, content, seq_num=0,
                            src_ip="192.168.1.100", dst_ip="10.0.0.1",
                            timestamp=None):
    """Reconstruct HTTP packet from CSIC CSV fields."""
    if method.upper() == 'POST':
        http_request = (
            f"POST {url} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(content)}\r\n"
            f"\r\n"
            f"{content}"
        ).encode('utf-8', errors='ignore')
    else:
        http_request = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: target.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        ).encode('utf-8', errors='ignore')

    return make_tcp_packet(
        src_ip=src_ip, dst_ip=dst_ip,
        sport=5000 + (seq_num % 1000), dport=80,
        flags="PA", seq=seq_num,
        payload=http_request, timestamp=timestamp,
    )


# ============================================================================
# DATASET LOADERS
# ============================================================================

def load_sqli_csv(filepath: str, limit: Optional[int] = None,
                  encoding: str = 'utf-16') -> List[Tuple[str, int]]:
    """
    Load SQLi CSV dataset.

    Format: Sentence,Label (1=attack, 0=normal)

    Returns:
        List of (sentence, label) tuples
    """
    records = []
    with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for i, row in enumerate(reader):
            if limit and i >= limit:
                break
            if len(row) < 2:
                continue
            try:
                records.append((row[0], int(row[1])))
            except (ValueError, IndexError):
                continue
    return records


@dataclass
class CSICRecord:
    """A record from the CSIC HTTP dataset."""
    label: str
    method: str
    url: str
    content: str

    @property
    def is_attack(self) -> bool:
        return self.label.lower().strip() != "normal"

    def get_payload(self) -> str:
        """Extract payload from URL query string and POST body."""
        payloads = []

        if '?' in self.url:
            try:
                query_part = self.url.split('?', 1)[1].split(' ')[0]
                params = parse_qs(query_part, keep_blank_values=True)
                for key, values in params.items():
                    payloads.append(unquote_plus(key))
                    for v in values:
                        payloads.append(unquote_plus(v))
            except Exception:
                pass

        if self.content:
            try:
                pairs = self.content.split('&')
                for pair in pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        payloads.append(unquote_plus(key))
                        payloads.append(unquote_plus(value))
                    else:
                        payloads.append(unquote_plus(pair))
            except Exception:
                pass

        return ' '.join(payloads)


def load_csic_csv(filepath: str, limit: Optional[int] = None,
                  balanced: bool = False) -> List[CSICRecord]:
    """
    Load CSIC dataset from CSV file.

    Args:
        filepath: Path to CSV file
        limit: Max records to return
        balanced: If True and limit is set, return equal normal + attack records.
                  Useful because CSIC has 36k normals first, then 25k attacks.

    Returns:
        List of CSICRecord
    """
    all_records = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        headers = next(reader)

        method_idx = headers.index('Method') if 'Method' in headers else 1
        url_idx = headers.index('URL') if 'URL' in headers else -1
        content_idx = headers.index('content') if 'content' in headers else None

        for row in reader:
            if len(row) < 2:
                continue
            try:
                all_records.append(CSICRecord(
                    label=row[0],
                    method=row[method_idx] if method_idx < len(row) else 'GET',
                    url=row[url_idx] if url_idx >= 0 and abs(url_idx) < len(row) else '',
                    content=row[content_idx] if content_idx and content_idx < len(row) else '',
                ))
            except Exception:
                continue

    if not limit:
        return all_records

    if balanced:
        normals = [r for r in all_records if not r.is_attack]
        attacks = [r for r in all_records if r.is_attack]
        half = limit // 2
        return normals[:half] + attacks[:half]

    return all_records[:limit]
