# TỔNG QUAN KIẾN TRÚC VÀ KỸ THUẬT XỬ LÝ - FOLDER SYSTEM

**Version:** 2.0.0  
**Last Updated:** February 11, 2026  
**Language:** Tiếng Việt  
**Team:** NIDS Development Team

---

## 📋 MỤC LỤC

1. [Tổng Quan Hệ Thống](#1-tổng-quan-hệ-thống)
2. [Kiến Trúc Tổng Thể](#2-kiến-trúc-tổng-thể)
3. [Pipeline Xử Lý Dữ Liệu](#3-pipeline-xử-lý-dữ-liệu)
4. [Chi Tiết Các Module](#4-chi-tiết-các-module)
5. [Kỹ Thuật Trích Xuất Feature](#5-kỹ-thuật-trích-xuất-feature)
6. [Cấu Trúc Thư Mục](#6-cấu-trúc-thư-mục)
7. [Workflow và Luồng Dữ Liệu](#7-workflow-và-luồng-dữ-liệu)
8. [Tối Ưu Hiệu Năng](#8-tối-ưu-hiệu-năng)
9. [Use Cases](#9-use-cases)

---

## 1. TỔNG QUAN HỆ THỐNG

### 1.1 Mục Đích

Folder **System** chứa hệ thống **Network Intrusion Detection System (NIDS)** - một IDS dựa trên phân tích hành vi mạng (Behavioral Analysis) để phát hiện các cuộc tấn công:

- **DDoS/DoS** - Denial of Service attacks
- **Port Scanning** - Quét cổng mạng
- **Brute Force** - Tấn công vét cạn
- **Web Attacks** - SQL Injection, XSS, Command Injection
- **Protocol Violations** - Vi phạm giao thức mạng

### 1.2 Nguyên Lý Hoạt Động

```
Network Traffic → Packet Capture → Flow Aggregation → Feature Extraction → AI Detection
                    (Sniffer)        (Flow Manager)     (16 Features)       (RL Agent)
```

**Đặc điểm:**
- ✅ **Flow-based Analysis** - Phân tích theo luồng mạng (không phải per-packet)
- ✅ **Bidirectional Tracking** - Theo dõi hai chiều (forward/backward)
- ✅ **Real-time & Offline** - Hỗ trợ cả live capture và PCAP analysis
- ✅ **Behavioral Features** - 16 features hành vi (không dựa vào signature)
- ✅ **Plugin Architecture** - Dễ dàng mở rộng features mới

### 1.3 Công Nghệ Sử Dụng

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Packet Capture** | Scapy + Npcap | Bắt gói tin từ network interface |
| **Feature Extraction** | Python (Plugin-based) | Tính toán 20 behavioral features (network + SQLi + XSS) |
| **L7 Detection** | Regex + ModSecurity CRS | F12-F20: SQLi/XSS pattern detection trên payload chuẩn hóa |
| **Flow Management** | Custom Python | Quản lý flows với sliding window |
| **AI Detection** | Stable Baselines3 (RL) | Training AI agent (tích hợp với RL-Defense-Agent) |

---

## 2. KIẾN TRÚC TỔNG THỂ

### 2.1 Kiến Trúc Hệ Thống (System Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│                        NETWORK LAYER                             │
│  Network Interface (Ethernet/WiFi) hoặc PCAP File                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PACKET CAPTURE LAYER                          │
│  core/sniffer.py - NetworkSniffer                                │
│  • Live Mode: Scapy sniff() từ interface                         │
│  • Offline Mode: PcapReader từ file                              │
│  • BPF Filter: "ip" (loại bỏ ARP, lớp 2)                         │
└────────────────────────┬────────────────────────────────────────┘
                         │ Raw Packets (Scapy Packet objects)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PACKET PARSING LAYER                          │
│  core/packet_parser.py - PacketLayerExtractor                    │
│  • Parse IP/TCP/UDP/ICMP/HTTP headers                            │
│  • Extract payload (HTTP URI, body, headers)                     │
│  • Build LayerInfo object (normalized data structure)            │
└────────────────────────┬────────────────────────────────────────┘
                         │ LayerInfo objects (parsed packets)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FLOW MANAGEMENT LAYER                         │
│  core/flow_manager.py - FlowManager                              │
│  • Group packets theo 5-tuple (src_ip, dst_ip, src_port,         │
│    dst_port, protocol)                                           │
│  • Bidirectional tracking (forward/backward)                     │
│  • Sliding window (1 second default)                             │
│  • Flow timeout cleanup (30 seconds)                             │
└────────────────────────┬────────────────────────────────────────┘
                         │ FlowState objects (aggregated flows)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                 FEATURE EXTRACTION LAYER                         │
│  feature/calculator.py - FlowFeatureCalculator                   │
│  • Auto-discover features via FeatureRegistry                    │
│  • Calculate 20 behavioral features:                             │
│    - Network (F1-F11): PPS, SYN/ACK, IAT, RST, Ports, URL,       │
│                       HttpIatUnif, ReqSizeUnif, AvgPayload,      │
│                       FwdBwdRatio, PktsPerPort                   │
│    - SQLi (F12-F17): SqlSpecial, CrsSqliScore, SqlUnion,         │
│                      SqlComment, SqlStackedQuery, SqlSelectCount │
│    - XSS (F18-F20): CrsXssScore, JsFnCall, HtmlEventHandler      │
└────────────────────────┬────────────────────────────────────────┘
                         │ Feature Vector [f1, f2, ..., f20]
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AI DETECTION LAYER                            │
│  • Reinforcement Learning Agent (PPO/DQN)                        │
│  • Decision: ALLOW / BLOCK / RATE_LIMIT                          │
│  • Action: iptables rules, ACL updates                           │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Luồng Dữ Liệu (Data Flow)

```
1. RAW PACKET
   ┌─────────────────────────────────────────┐
   │ Ethernet Frame (14 bytes header)        │
   │ ├─ IP Packet (20+ bytes header)         │
   │    ├─ TCP/UDP Segment (20+/8 bytes)     │
   │       └─ Application Data (payload)     │
   └─────────────────────────────────────────┘

2. PARSED PACKET (LayerInfo)
   {
     src_ip: "192.168.1.100",
     dst_ip: "10.0.0.1",
     tcp_sport: 54321,
     tcp_dport: 80,
     protocol: 6,
     payload: b"GET /admin' OR 1=1--",
     http_uri: "/admin",
     timestamp: 1234567890.123
   }

3. FLOW STATE (FlowState)
   Flow(192.168.1.100:54321 → 10.0.0.1:80)
   ├─ fwd_packets: [pkt1, pkt2, ...]  (client → server)
   └─ bwd_packets: [pkt3, pkt4, ...]  (server → client)

4. FEATURE VECTOR (20D)
   [
     100.5,    # F1:  PacketRate (pkts/sec)
     1.2,      # F2:  SynAckRatio
     0.005,    # F3:  InterArrivalTime (sec)
     0.1,      # F4:  RstRatio
     15,       # F5:  DistinctPorts
     0.8,      # F6:  URLConcentration
     0.85,     # F7:  HttpIatUniformity (cross-flow timing)
     0.92,     # F8:  RequestSizeUniformity
     512.3,    # F9:  AvgPayloadSize (bytes)
     2.1,      # F10: FwdBwdRatio
     45,       # F11: PacketsPerPort
     0.3,      # F12: SqlSpecialChar ratio
     8.5,      # F13: CrsSqliScore (CRS 942 rules hit)
     1.0,      # F14: SqlUnionSelect (binary)
     1.0,      # F15: SqlComment (binary — --, #, /**/ detected)
     0.0,      # F16: SqlStackedQuery (binary — ; DROP/DELETE)
     2.0,      # F17: SqlSelectCount
     0.0,      # F18: CrsXssScore
     0.0,      # F19: JsFunctionCall (binary)
     0.0       # F20: HtmlEventHandler (binary)
   ]

5. AI DECISION
   Action: REDIRECT (SQLi detected — F13/F14/F15 elevated)
   Rule: iptables -t nat -A PREROUTING -s 192.168.1.100 -p tcp --dport 443 -j REDIRECT --to-ports 4443
```

---

## 3. PIPELINE XỬ LÝ DỮ LIỆU

### 3.1 Pipeline Overview

```python
# BƯỚC 1: PACKET CAPTURE
sniffer = NetworkSniffer()
sniffer.start_live(interface="Ethernet", callback=process_packet)

# BƯỚC 2: PACKET PARSING
parser = PacketLayerExtractor()
layer_info = parser.parse(raw_packet)

# BƯỚC 3: FLOW AGGREGATION
flow_manager = FlowManager(window_size=1.0, flow_timeout=30.0)
flow = flow_manager.process_packet(layer_info)

# BƯỚC 4: FEATURE EXTRACTION
calculator = FlowFeatureCalculator()
features = calculator.calculate_all_optimized([flow])

# BƯỚC 5: AI DETECTION
action = ai_agent.predict(features)  # ALLOW / BLOCK / RATE_LIMIT
```

### 3.2 Các Mode Hoạt Động

#### **Mode 1: Live Capture (Real-time)**
```bash
# Chạy với quyền Administrator/root
python main_live_scapy.py -i Ethernet -f "ip" -w 1.0
```

**Use case:**
- Production deployment
- Real-time attack detection
- Live traffic monitoring

**Đặc điểm:**
- Bắt gói tin trực tiếp từ network interface
- Xử lý real-time với sliding window
- Memory efficient (store=0 trong Scapy)

#### **Mode 2: PCAP Analysis (Offline)**
```bash
python main_pcap.py -p attack.pcap -o features.csv
```

**Use case:**
- Forensic analysis
- Model training
- Testing và validation

**Đặc điểm:**
- Đọc và phân tích file PCAP có sẵn
- Sử dụng packet timestamp từ file (không phải system time)
- Dễ dàng replay và debug

#### **Mode 3: Sliding Window (Time-series)**
```bash
python main_pcap_sliding.py -p traffic.pcap -w 1.0 -s 0.5 -o timeseries.csv
```

**Use case:**
- Time-series analysis
- Attack pattern visualization
- Model training với temporal features

**Đặc điểm:**
- Tạo feature vectors theo windows overlap
- Window size: 1s, Slide step: 0.5s
- Output: Multiple rows per src_ip (time-series)

---

## 4. CHI TIẾT CÁC MODULE

### 4.1 Core Module

#### **4.1.1 NetworkSniffer (core/sniffer.py)**

**Chức năng:**
- Wrapper cho Scapy `sniff()` function
- Hỗ trợ live capture và PCAP file
- BPF filter để lọc packet không cần thiết

**Key Features:**
```python
class NetworkSniffer:
    def start_live(interface, callback, packet_count, bpf_filter="ip"):
        """
        Live packet capture từ network interface.
        
        Args:
            interface: Tên interface (VD: "Ethernet", "eth0")
            callback: Function xử lý mỗi packet
            packet_count: Số packets tối đa (None = unlimited)
            bpf_filter: BPF filter string (default: "ip")
        """
    
    def start_pcap(pcap_path, callback, packet_count):
        """
        Đọc và xử lý file PCAP.
        """
```

**Best Practices:**
- ✅ Luôn dùng `bpf_filter="ip"` để loại bỏ ARP và traffic lớp 2
- ✅ Dùng `store=0` để tránh memory leak
- ✅ Handle `KeyboardInterrupt` để cleanup gracefully

#### **4.1.2 PacketLayerExtractor (core/packet_parser.py)**

**Chức năng:**
- Parse Scapy packet → LayerInfo object
- Extract headers (IP, TCP, UDP, ICMP, HTTP)
- Extract payload và metadata

**Supported Protocols:**
- IP (v4): Source/Dest IP, TTL, ToS
- TCP: Ports, Flags (SYN, ACK, RST, FIN, PSH, URG)
- UDP: Ports
- ICMP: Type, Code
- HTTP: Method, URI, Host, User-Agent, Status Code

**LayerInfo Structure:**
```python
class LayerInfo:
    # Network Layer
    src_ip: str
    dst_ip: str
    protocol: int  # 6=TCP, 17=UDP, 1=ICMP
    
    # Transport Layer
    tcp_sport: int
    tcp_dport: int
    tcp_flags: set  # {'SYN', 'ACK', ...}
    
    # Application Layer
    has_http: bool
    http_method: str  # GET, POST, ...
    http_uri: str
    http_status: int  # 200, 404, 500, ...
    
    # Payload
    payload: bytes
    payload_len: int
    
    # Metadata
    timestamp: float
    packet_len: int
```

**Advanced Features:**
- **HTTP Composite Payload:** `[URI] + [User-Agent] + [Body]` để fail-fast detection
- **Nginx Proxy Headers:** Parse `X-Real-IP`, `X-Forwarded-For` để lấy client IP thực
- **Timestamp Handling:** Dùng packet time (PCAP) hoặc system time (live)

#### **4.1.3 FlowManager (core/flow_manager.py)**

**Chức năng:**
- Aggregate packets thành flows dựa trên 5-tuple
- Bidirectional tracking (forward/backward)
- Sliding window và timeout cleanup

**5-Tuple Flow Key:**
```python
flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

# Example:
("192.168.1.100", "10.0.0.1", 54321, 80, 6)  # TCP flow
```

**Bidirectional Detection:**
```python
# FORWARD: packet.src_ip == flow.src_ip
if packet.src_ip == flow.src_ip:
    flow.add_forward_packet(packet)  # Client → Server

# BACKWARD: packet.src_ip == flow.dst_ip
else:
    flow.add_backward_packet(packet)  # Server → Client
```

**Why Bidirectional?**
- Phát hiện RST từ server (F4: RST Ratio)
- Phân tích response time
- Detect protocol violations

**Cleanup Strategy:**
```python
# 1. Sliding Window Cleanup (mỗi khi add packet)
cutoff = current_time - window_size
while packets[0].timestamp < cutoff:
    packets.popleft()  # Xóa packets cũ

# 2. Flow Timeout Cleanup (mỗi 100 packets)
if packet_counter % 100 == 0:
    for flow in flows:
        if current_time - flow.last_update > 30.0:
            del flows[flow_key]  # Xóa flow không active
```

#### **4.1.4 FlowState (core/flow_state.py)**

**Chức năng:**
- Lưu trữ packets của một flow
- Tách riêng forward/backward packets
- Provide data access methods cho feature extraction

**Key Methods:**
```python
class FlowState:
    # Packet Management
    def add_forward_packet(packet)
    def add_backward_packet(packet)
    
    # Counts
    def get_fwd_packet_count() -> int
    def get_bwd_packet_count() -> int
    def get_total_packet_count() -> int
    
    # Payload Analysis
    def get_fwd_payload_total() -> int
    def get_average_payload_length() -> float
    def get_all_payloads() -> List[bytes]
    
    # TCP Flags
    def get_syn_count() -> int
    def get_ack_count() -> int
    def get_rst_count() -> int
    def get_fin_count() -> int
    
    # HTTP Analysis
    def get_http_status_codes() -> List[int]
    def get_401_count() -> int
    def get_403_count() -> int
    def get_5xx_count() -> int
    
    # Timing
    def get_duration() -> float
    def get_inter_arrival_times() -> List[float]
```

**Memory Management:**
```python
# Giới hạn packets per flow
fwd_packets: deque(maxlen=3000)  # Tự động drop packets cũ
bwd_packets: deque(maxlen=3000)
```

---

### 4.2 Feature Module (Plugin Architecture)

#### **4.2.1 Kiến Trúc Plugin-based**

```
feature/
├── base.py              # Core abstractions
│   ├── FeatureBase      # Abstract base class
│   ├── FeatureRegistry  # Auto-discovery registry
│   ├── FeatureMetadata  # Metadata (name, category, unit)
│   └── @register_feature # Decorator
│
├── calculator.py        # Orchestrator
│   └── FlowFeatureCalculator  # Aggregates all 16 features
│
├── context.py           # Caching system
│   └── FeatureContext   # Cached payload processing
│
└── calculators/         # Feature implementations
    ├── network.py       # F1-F5
    ├── application.py   # F6-F8
    ├── payload.py       # F9-F14
    └── context.py       # F15-F16
```

**Auto-Discovery Mechanism:**
```python
# 1. Register feature với decorator
@register_feature
class F1_PacketRate(FeatureBase):
    metadata = FeatureMetadata(
        code="F1",
        name="Packet Rate",
        category="network",
        unit="packets/second"
    )
    
    def calculate(self, flows, **kwargs):
        # Implementation
        return pps

# 2. Auto-discovery khi import
import feature.calculators  # Trigger all @register_feature

# 3. Registry tự động lưu
FeatureRegistry._features = {
    'F1': F1_PacketRate,
    'F2': F2_SynAckRatio,
    ...
}

# 4. Instantiate tất cả features
calculator = FlowFeatureCalculator()
features = calculator.calculate_all(flows)
```

#### **4.2.2 Các Nhóm Features**

**NETWORK FEATURES (F1-F5) - feature/calculators/network.py**

| Feature | Code | Mô Tả | Đơn Vị | Phát Hiện |
|---------|------|-------|--------|-----------|
| **Packet Rate** | F1 | Packets/second từ tất cả flows của src_ip | packets/s | DDoS, DoS |
| **SYN/ACK Ratio** | F2 | Tỷ lệ SYN/ACK packets | ratio | SYN Flood |
| **Inter-Arrival Time** | F3 | Thời gian trung bình giữa các packets | seconds | Traffic pattern |
| **RST Ratio** | F4 | Tỷ lệ RST packets (failed connections) | ratio [0,1] | Brute force |
| **Distinct Ports** | F5 | Số ports khác nhau được kết nối | count | Port scanning |

**Kỹ Thuật:**
```python
# F1: Packet Rate
def calculate(flows):
    total_packets = sum(flow.get_total_packet_count() for flow in flows)
    duration = max(flow.get_duration() for flow in flows)
    return total_packets / duration if duration > 0 else 0

# F2: SYN/ACK Ratio
def calculate(flows):
    syn_count = sum(flow.get_syn_count() for flow in flows)
    ack_count = sum(flow.get_ack_count() for flow in flows)
    return syn_count / ack_count if ack_count > 0 else 0

# F5: Distinct Ports (QUAN TRỌNG: Cần gom flows theo src_ip)
def calculate(flows):
    distinct_ports = set()
    for flow in flows:  # Tất cả flows từ 1 src_ip
        distinct_ports.add(flow.dst_port)
    return len(distinct_ports)
```

**APPLICATION FEATURES (F6-F8) - feature/calculators/application.py**

| Feature | Code | Mô Tả | Đơn Vị | Phát Hiện |
|---------|------|-------|--------|-----------|
| **URL Concentration** | F6 | Tỷ lệ requests tập trung vào 1 URL | ratio [0,1] | Targeted attack |
| **Auth Failure Rate** | F7 | Tỷ lệ HTTP 401+403 (authentication failed) | ratio [0,1] | Brute force login |
| **Server Error Rate** | F8 | Tỷ lệ HTTP 5xx (server errors) | ratio [0,1] | Exploit attempts |

**Kỹ Thuật:**
```python
# F6: URL Concentration
def calculate(flows):
    uri_counts = Counter()
    for flow in flows:
        for pkt in flow.fwd_packets:
            if pkt.http_uri:
                uri_counts[pkt.http_uri] += 1
    
    total = sum(uri_counts.values())
    max_count = max(uri_counts.values()) if uri_counts else 0
    return max_count / total if total > 0 else 0

# F7: Auth Failure Rate
def calculate(flows):
    auth_fails = 0  # HTTP 401, 403
    total_http = 0
    
    for flow in flows:
        auth_fails += flow.get_401_count() + flow.get_403_count()
        total_http += len(flow.get_http_status_codes())
    
    return auth_fails / total_http if total_http > 0 else 0
```

**PAYLOAD FEATURES (F9-F14) - feature/calculators/payload.py**

| Feature | Code | Mô Tả | Đơn Vị | Phát Hiện |
|---------|------|-------|--------|-----------|
| **Payload Length** | F9 | Trung bình độ dài payload | bytes | Large payload attacks |
| **Payload Entropy** | F10 | Shannon entropy của payload | bits [0,8] | Encrypted/packed malware |
| **SQLi Keyword** | F11 | Weighted score cho SQLi keywords | score | SQL Injection |
| **SQL Special Char** | F12 | Tỷ lệ SQL special chars (`'`, `;`, `--`) | ratio [0,1] | SQL Injection |
| **XSS Keyword** | F13 | Weighted score cho XSS keywords | score | Cross-Site Scripting |
| **XSS Special Char** | F14 | Tỷ lệ XSS special chars (`<`, `>`, `script`) | ratio [0,1] | XSS |

**Kỹ Thuật:**

```python
# F10: Shannon Entropy
def calculate_entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    
    # Count byte frequencies
    counts = [0] * 256
    for byte in payload:
        counts[byte] += 1
    
    # Shannon entropy formula
    entropy = 0.0
    length = len(payload)
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy  # [0, 8] bits

# F11: SQLi Keyword Score (Weighted)
SQLI_KEYWORDS = {
    'union': 5.0,      # High risk
    'select': 4.0,
    'insert': 4.0,
    'update': 4.0,
    'delete': 4.0,
    'drop': 5.0,
    'exec': 4.0,
    'script': 3.0,
    'or 1=1': 10.0,    # Very high risk
    'or true': 10.0,
    '0x': 2.0          # Hex encoding
}

def calculate(payload: str) -> float:
    payload_lower = payload.lower()
    score = 0.0
    
    for keyword, weight in SQLI_KEYWORDS.items():
        count = payload_lower.count(keyword)
        score += count * weight
    
    return score

# F12: SQL Special Character Ratio
SQL_SPECIAL_CHARS = {"'", '"', ';', '--', '/*', '*/', '#'}

def calculate(payload: str) -> float:
    if not payload:
        return 0.0
    
    special_count = sum(payload.count(char) for char in SQL_SPECIAL_CHARS)
    return min(special_count / len(payload), 1.0)
```

**Why Payload Caching (FeatureContext)?**
```python
# Problem: F9-F14 cần đọc payload nhiều lần
# → Inefficient nếu parse lại mỗi feature

# Solution: FeatureContext caches parsed payloads
context = FeatureContext(flows)
context.all_payloads  # Cached: chỉ parse 1 lần
context.composite_payloads  # Cached: [URI + User-Agent + Body]

# Speedup: 1.14x average, 2-3x cho payload-heavy workloads
```

**SQLI HIGH-RISK FEATURES (F15-F16) - feature/calculators/sqli_features.py**

| Feature | Code | Mô Tả | Đơn Vị | Phát Hiện |
|---------|------|-------|--------|-----------|
| **SqlComment** | F15 | Comment injection (--, #, /**/) | binary {0,1} | Cắt query gốc |
| **SqlStackedQuery** | F16 | Stacked query (; DROP/DELETE/INSERT) | binary {0,1} | Lệnh phá hoại |

**Kỹ Thuật:**
```python
# F15/F16 dùng regex trên payload đã chuẩn hóa qua FeatureContext
from feature.context import FeatureContext

ctx = FeatureContext(flows)
for flow in flows:
    for pkt in flow.get_fwd_packets():
        normalized = ctx.get_normalized(pkt)   # cached
        # F15: kiểm tra _COMMENT_PATTERNS (--, #, /**/)
        # F16: kiểm tra _STACKED_QUERY_PATTERNS (; DROP, ; DELETE, ; INSERT, ...)
        if any(p.search(normalized) for p in _COMMENT_PATTERNS):
            return 1.0
return 0.0
```

→ Không cần ML model — pattern matching đủ chính xác cho 2 kỹ thuật high-risk này.

---

### 4.3 Config Module

#### **4.3.1 NIDSConfig (config/nids_config.py)**

**Chức năng:**
- Centralized configuration cho toàn hệ thống
- Tránh magic numbers trong code
- Dễ dàng tune parameters

**Key Parameters:**
```python
@dataclass(frozen=True)
class NIDSConfig:
    # Flow Management
    MAX_PACKETS_PER_FLOW: int = 3000
    FLOW_TIMEOUT_SECONDS: float = 30.0
    CLEANUP_INTERVAL: int = 100
    MAX_FLOWS: int = 50000
    
    # Sliding Window
    DEFAULT_WINDOW_SIZE: float = 1.0
    DEFAULT_SLIDE_STEP: float = 0.5
    
    # Thresholds (Reference Values)
    THRESHOLD_HIGH_PACKET_RATE: float = 1000.0  # DDoS
    THRESHOLD_HIGH_SYN_RATIO: float = 10.0      # SYN Flood
    THRESHOLD_HIGH_DISTINCT_PORTS: int = 50     # Port Scan
    THRESHOLD_HIGH_FAIL_RATE: float = 0.7       # Brute Force
```

**Usage:**
```python
from config.nids_config import NIDSConfig

flow_manager = FlowManager(
    window_size=NIDSConfig.DEFAULT_WINDOW_SIZE,
    flow_timeout=NIDSConfig.FLOW_TIMEOUT_SECONDS
)
```

---

## 5. KỸ THUẬT TRÍCH XUẤT FEATURE

### 5.1 Why Flow-based Analysis?

**Packet-based vs Flow-based:**

| Approach | Pros | Cons | Use Case |
|----------|------|------|----------|
| **Packet-based** | Real-time, fast | Thiếu context, dễ bypass | Signature-based IDS |
| **Flow-based** | Behavioral analysis, context-aware | Cần buffer, tốn RAM | Behavioral IDS (NIDS) |

**Ví dụ: Port Scanning Detection**

```python
# PACKET-BASED (Sai!)
# Mỗi packet chỉ có 1 dst_port → F5 luôn = 1
for packet in packets:
    distinct_ports = {packet.dst_port}  # Always 1!

# FLOW-BASED (Đúng!)
# Gom tất cả flows từ 1 src_ip → F5 = số ports khác nhau
flows_by_src = group_flows_by_src_ip(all_flows)

for src_ip, flows in flows_by_src.items():
    distinct_ports = set()
    for flow in flows:
        distinct_ports.add(flow.dst_port)
    
    f5_score = len(distinct_ports)
    
    if f5_score > 50:
        alert(f"Port Scan detected from {src_ip}")
```

### 5.2 Feature Aggregation Strategy

**Tại sao cần gom flows theo src_ip?**

```
PCAP File:
├─ Flow 1: 192.168.1.100:54321 → 10.0.0.1:22
├─ Flow 2: 192.168.1.100:54322 → 10.0.0.1:80
├─ Flow 3: 192.168.1.100:54323 → 10.0.0.1:443
├─ Flow 4: 192.168.1.100:54324 → 10.0.0.1:8080
├─ Flow 5: 192.168.1.200:12345 → 10.0.0.1:22
└─ Flow 6: 192.168.1.200:12346 → 10.0.0.1:80

Group by src_ip:
├─ 192.168.1.100: [Flow 1, 2, 3, 4]  → F5 = 4 ports {22, 80, 443, 8080}
└─ 192.168.1.200: [Flow 5, 6]        → F5 = 2 ports {22, 80}

Analysis:
→ 192.168.1.100 nghi ngờ Port Scanning (4 ports khác nhau)
→ 192.168.1.200 bình thường (2 ports, có thể là web browsing)
```

**Code Implementation:**
```python
def group_flows_by_src_ip(flows: list) -> dict:
    """Group flows by source IP."""
    flows_by_src = {}
    for flow in flows:
        src_ip = flow.src_ip
        if src_ip not in flows_by_src:
            flows_by_src[src_ip] = []
        flows_by_src[src_ip].append(flow)
    return flows_by_src

# Calculate features per src_ip
calculator = FlowFeatureCalculator()

for src_ip, flows in flows_by_src.items():
    features = calculator.calculate_all(flows)
    # features = [f1, f2, ..., f16] cho src_ip này
```

### 5.3 Sliding Window Technique

**Fixed Window vs Sliding Window:**

```
FIXED WINDOW (NON-OVERLAPPING):
Time:    0s----1s----2s----3s----4s----5s
Window:  [  W1  ][  W2  ][  W3  ][  W4  ]
Problem: Miss attacks nằm giữa 2 windows

SLIDING WINDOW (OVERLAPPING):
Time:    0s----1s----2s----3s----4s----5s
Window:  [  W1  ]
            [  W2  ]
               [  W3  ]
                  [  W4  ]
                     [  W5  ]
Benefit: Capture all patterns, no gaps
```

**Implementation:**
```python
# Sliding window với overlap
window_size = 1.0   # 1 second
slide_step = 0.5    # Slide 0.5 second → 50% overlap

windows = []
current_time = 0.0

while current_time <= total_duration:
    # Extract flows trong [current_time, current_time + window_size]
    window_flows = [
        flow for flow in all_flows
        if current_time <= flow.start_time < current_time + window_size
    ]
    
    # Calculate features cho window này
    features = calculator.calculate_all(window_flows)
    windows.append({
        'time': current_time,
        'features': features
    })
    
    current_time += slide_step

# Output: Time-series features
# [
#   {time: 0.0, features: [...]},
#   {time: 0.5, features: [...]},
#   {time: 1.0, features: [...]},
#   ...
# ]
```

### 5.4 Bidirectional Tracking

**Why Track Forward & Backward?**

```
CLIENT (192.168.1.100)         SERVER (10.0.0.1:22)
      |                              |
      |  SYN (forward)               |
      |----------------------------->|
      |                              |
      |        SYN-ACK (backward)    |
      |<-----------------------------|
      |                              |
      |  ACK (forward)               |
      |----------------------------->|
      |                              |
      |  Password: admin (forward)   |
      |----------------------------->|
      |                              |
      |        RST (backward)        |  ← Server rejects
      |<-----------------------------|
      |                              |

Analysis:
- Forward packets: 3 (SYN, ACK, Password)
- Backward packets: 2 (SYN-ACK, RST)
- RST from server → Failed login attempt
- F4 (RST Ratio) = 1/5 = 0.2
- F7 (Auth Fail Rate) = 1/1 = 1.0 (nếu có HTTP 401)
```

**Implementation:**
```python
# FlowManager xác định direction
if packet.src_ip == flow.src_ip:
    flow.add_forward_packet(packet)   # Client → Server
else:
    flow.add_backward_packet(packet)  # Server → Client

# Feature calculation sử dụng cả 2 directions
def calculate_rst_ratio(flow):
    # RST từ server (backward) = failed connection
    bwd_rst = sum(1 for pkt in flow.bwd_packets if 'RST' in pkt.tcp_flags)
    total_pkts = flow.get_total_packet_count()
    return bwd_rst / total_pkts if total_pkts > 0 else 0
```

---

## 6. CẤU TRÚC THƯ MỤC

```
System/
├── core/                          # Core processing modules
│   ├── __init__.py
│   ├── sniffer.py                 # Network packet capture
│   ├── packet_parser.py           # Packet → LayerInfo parsing
│   ├── flow_manager.py            # Flow aggregation & management
│   ├── flow_state.py              # Flow state storage
│   ├── layer_info.py              # LayerInfo data structure
│   ├── packet_queue.py            # Thread-safe packet queue
│   ├── validators.py              # Input validation utilities
│   ├── utils.py                   # Helper functions
│   └── deprecation.py             # Deprecation system
│
├── feature/                       # Feature extraction (Plugin architecture)
│   ├── __init__.py
│   ├── base.py                    # FeatureBase, FeatureRegistry, @register_feature
│   ├── context.py                 # FeatureContext caching + PayloadNormalizer
│   ├── calculator.py              # FlowFeatureCalculator (orchestrator)
│   └── calculators/               # Modular features (plugin-based)
│       ├── __init__.py
│       ├── network_features.py        # F1-F5: PacketRate, SynAck, IAT, Rst, Ports
│       ├── application_features.py    # F6-F8: URL, HttpIatUnif, ReqSizeUnif (cross-flow)
│       ├── network_features.py        # F9-F11: AvgPayload, FwdBwdRatio, PktsPerPort
│       ├── sqli_features.py           # F12-F17: SQLi (chars, CRS, UNION, comment, stacked, SELECT)
│       └── xss_features.py            # F18-F20: XSS (CRS, JsFnCall, HtmlEvent)
│
├── config/                        # Configuration files
│   ├── __init__.py
│   ├── nids_config.py             # Central config (thresholds, timeouts)
│   ├── data_params.py             # FEATURE_ORDER, normalize_feature_vector, OBS_DIM=20
│   └── ai_config.py               # AI model config
│
├── dataset/                       # Training datasets
│   ├── csic_database.csv          # CSIC 2010 HTTP dataset
│   ├── sqli.csv                   # SQLi samples
│   ├── XSS_dataset.csv            # XSS samples
│   └── SQLiV3.csv                 # SQLi v3
│
├── test/                          # Test suites (72 tests total)
│   ├── conftest.py                # Pytest fixtures
│   ├── helpers.py                 # Test utilities
│   ├── test_features.py           # Feature calculation tests
│   ├── test_flow_manager.py       # FlowManager tests
│   ├── test_flow_state.py         # FlowState tests
│   ├── test_behavioral_features.py
│   ├── test_csic_dataset.py
│   └── test_full_pipeline.py
│
├── test_deprecation_warnings.py   # Phase 3: Deprecation tests (4/4)
├── test_backward_compatibility.py # Phase 3: Compatibility tests (5/5)
├── test_performance_benchmark.py  # Phase 3: Performance benchmarks
├── test_main_script_integration.py # Phase 4: Integration tests (6/6)
│
├── docs/                          # Documentation
│   ├── API_DOCUMENTATION.md       # Complete API reference
│   ├── MIGRATION_GUIDE.md         # v1.x → v2.0 migration
│   └── OPTION_B_IMPLEMENTATION_GUIDE.md
│
├── main_pcap.py                   # PCAP analysis script
├── main_pcap_sliding.py           # Sliding window PCAP analysis
├── main_live_scapy.py             # Live packet capture
├── main_live_sliding.py           # Live sliding window
├── main_packet_viewer.py          # Debug: View packets
│
├── logs/                          # Runtime logs
├── test_output/                   # Test output files
├── tools/                         # Utility scripts
│
├── pytest.ini                     # Pytest configuration
├── run_tests.py                   # Test runner script
│
├── PHASE2_COMPLETION_SUMMARY.md   # Phase 2 documentation
├── PHASE3_COMPLETION_SUMMARY.md   # Phase 3 documentation
└── PHASE4_COMPLETION_SUMMARY.md   # Phase 4 documentation
```

---

## 7. WORKFLOW VÀ LUỒNG DỮ LIỆU

### 7.1 Live Capture Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. INITIALIZATION                                            │
├─────────────────────────────────────────────────────────────┤
│ • NetworkSniffer(interface="Ethernet")                       │
│ • PacketLayerExtractor(use_packet_time=False)               │
│ • FlowManager(window_size=1.0, flow_timeout=30.0)           │
│ • FlowFeatureCalculator()                                    │
└─────────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. PACKET CAPTURE LOOP                                       │
├─────────────────────────────────────────────────────────────┤
│ while True:                                                  │
│     raw_packet = sniff(interface, bpf_filter="ip")          │
│     │                                                        │
│     ├─> Parse: layer_info = parser.parse(raw_packet)        │
│     │                                                        │
│     ├─> Aggregate: flow = flow_manager.process_packet(...)  │
│     │                                                        │
│     ├─> Every 100 packets:                                  │
│     │   └─> Cleanup: flow_manager.cleanup_expired_flows()   │
│     │                                                        │
│     └─> Every 1 second (window_size):                       │
│         └─> Extract features: calculator.calculate_all(...) │
│             └─> AI Decision: agent.predict(features)        │
│                 └─> Action: iptables / alert                │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 PCAP Analysis Workflow

```python
#!/usr/bin/env python3
# Simplified workflow

# 1. SETUP
from scapy.all import PcapReader
from core.packet_parser import PacketLayerExtractor
from core.flow_manager import FlowManager
from feature.calculator import FlowFeatureCalculator

parser = PacketLayerExtractor(use_packet_time=True)  # Use PCAP timestamps
flow_manager = FlowManager(window_size=1.0)
calculator = FlowFeatureCalculator()

# 2. PARSE ALL PACKETS
all_flows = []

with PcapReader('attack.pcap') as pcap:
    for raw_packet in pcap:
        # Parse packet
        layer_info = parser.parse(raw_packet)
        
        # Map to flow
        flow = flow_manager.process_packet(layer_info)

# 3. GROUP FLOWS BY SRC_IP
flows_by_src = {}
for flow in flow_manager.flows.values():
    src_ip = flow.src_ip
    if src_ip not in flows_by_src:
        flows_by_src[src_ip] = []
    flows_by_src[src_ip].append(flow)

# 4. EXTRACT FEATURES PER SRC_IP
results = []

for src_ip, flows in flows_by_src.items():
    features = calculator.calculate_all_optimized(flows)
    
    results.append({
        'src_ip': src_ip,
        'total_flows': len(flows),
        'features': features  # [f1, f2, ..., f16]
    })

# 5. EXPORT CSV
import csv

with open('output.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    
    # Header
    header = ['Src_IP', 'Total_Flows'] + calculator.get_feature_names()
    writer.writerow(header)
    
    # Data
    for row in results:
        csv_row = [row['src_ip'], row['total_flows']] + row['features']
        writer.writerow(csv_row)

print(f"✅ Exported {len(results)} src_ips to output.csv")
```

### 7.3 Sliding Window Workflow

```python
# main_pcap_sliding.py logic

window_size = 1.0  # 1 second
slide_step = 0.5   # Slide 0.5 second

# 1. Parse all packets (with PCAP timestamps)
all_packets = []
for pkt in pcap:
    layer_info = parser.parse(pkt)
    all_packets.append(layer_info)

# 2. Find time range
min_time = min(pkt.timestamp for pkt in all_packets)
max_time = max(pkt.timestamp for pkt in all_packets)

# 3. Sliding window iteration
current_time = min_time
results = []

while current_time <= max_time:
    window_end = current_time + window_size
    
    # 3a. Extract packets trong window [current_time, window_end)
    window_packets = [
        pkt for pkt in all_packets
        if current_time <= pkt.timestamp < window_end
    ]
    
    # 3b. Create flows từ packets
    window_manager = FlowManager(window_size=window_size)
    for pkt in window_packets:
        window_manager.process_packet(pkt)
    
    # 3c. Group flows by src_ip
    flows_by_src = group_flows_by_src_ip(window_manager.flows.values())
    
    # 3d. Calculate features per src_ip
    for src_ip, flows in flows_by_src.items():
        features = calculator.calculate_all(flows)
        
        results.append({
            'window_start': current_time,
            'window_end': window_end,
            'src_ip': src_ip,
            'features': features
        })
    
    # 3e. Slide window
    current_time += slide_step

# 4. Export time-series CSV
with open('timeseries.csv', 'w') as f:
    writer = csv.writer(f)
    writer.writerow(['Window_Start', 'Window_End', 'Src_IP'] + feature_names)
    
    for row in results:
        csv_row = [
            row['window_start'],
            row['window_end'],
            row['src_ip']
        ] + row['features']
        writer.writerow(csv_row)

print(f"✅ Exported {len(results)} windows to timeseries.csv")
```

---

## 8. TỐI ƯU HIỆU NĂNG

### 8.1 Memory Management

**Problem:** Live capture có thể chạy 24/7 → Memory leak nguy hiểm

**Solutions:**

1. **Scapy store=0**
```python
# ❌ BAD: Lưu tất cả packets trong RAM
sniff(iface=interface, prn=callback, store=1)

# ✅ GOOD: Không lưu packets sau khi xử lý
sniff(iface=interface, prn=callback, store=0)
```

2. **deque maxlen**
```python
# ❌ BAD: Unlimited growth
packets = []  # Có thể tràn RAM

# ✅ GOOD: Auto-drop old packets
from collections import deque
packets = deque(maxlen=3000)  # Chỉ giữ 3000 packets mới nhất
```

3. **Flow cleanup**
```python
# Cleanup expired flows mỗi 100 packets
if packet_counter % 100 == 0:
    current_time = time.time()
    
    expired = [
        key for key, flow in flows.items()
        if current_time - flow.last_update > 30.0
    ]
    
    for key in expired:
        del flows[key]
```

4. **Max flows limit**
```python
# Hard limit số flows để protect RAM
MAX_FLOWS = 50000

if len(flows) >= MAX_FLOWS:
    # Xóa flow cũ nhất
    oldest_key = min(flows.keys(), key=lambda k: flows[k].last_update)
    del flows[oldest_key]
```

### 8.2 CPU Optimization

**1. FeatureContext Caching**

```python
# ❌ WITHOUT CACHING: Parse payload 6 times (F9-F14)
def calculate_f9(flows):
    payloads = [pkt.payload for flow in flows for pkt in flow.packets]
    return sum(len(p) for p in payloads) / len(payloads)

def calculate_f10(flows):
    payloads = [pkt.payload for flow in flows for pkt in flow.packets]  # Re-parse!
    return calculate_entropy(payloads)

# ... F11-F14 re-parse again!

# ✅ WITH CACHING: Parse 1 lần, cache result
context = FeatureContext(flows)
context.all_payloads  # Cached property

def calculate_f9(context):
    return sum(len(p) for p in context.all_payloads) / len(context.all_payloads)

def calculate_f10(context):
    return calculate_entropy(context.all_payloads)  # Use cached!

# Speedup: 1.14x average, 2-3x for payload features
```

**2. Optimized Method: calculate_all_optimized()**

```python
# ❌ SLOW: No caching
features = calculator.calculate_all(flows)

# ✅ FAST: With FeatureContext caching
features = calculator.calculate_all_optimized(flows)
```

**3. Early Return Optimization**

```python
# F15 (SqlComment), F16 (SqlStackedQuery): Skip regex nếu payload rỗng
def calculate(self, flows, **kwargs):
    ctx = kwargs.get('context') or FeatureContext(flows)
    for flow in flows:
        for pkt in flow.get_fwd_packets():
            normalized = ctx.get_normalized(pkt)
            if not normalized:
                continue                              # Early skip
            if any(p.search(normalized) for p in _PATTERNS):
                return 1.0                            # Early return
    return 0.0
```

### 8.3 Performance Benchmarks

**Test Setup:**
- CPU: Intel i5-8250U
- RAM: 8GB
- Dataset: 1000 flows, 50000 packets

**Results:**

| Operation | Old (v1.x) | New (v2.0) | Speedup |
|-----------|------------|------------|---------|
| **Packet Parsing** | 1.23s | 1.20s | 1.02x |
| **Flow Aggregation** | 0.85s | 0.82s | 1.04x |
| **Feature Extraction (no cache)** | 2.34s | 2.51s | 0.93x |
| **Feature Extraction (cached)** | 2.34s | 2.05s | **1.14x** ✅ |
| **Full Pipeline** | 4.42s | 4.08s | **1.08x** ✅ |

**Memory Usage:**

| Component | Memory |
|-----------|--------|
| 1 FlowState (100 packets) | ~50 KB |
| 1000 FlowStates | ~50 MB |
| 50000 FlowStates (max) | ~2.5 GB |
| FeatureContext cache | ~5 MB (negligible) |

---

## 9. USE CASES

### 9.1 Use Case 1: DDoS Detection

**Scenario:** Phát hiện DDoS attack từ botnet

**Features sử dụng:**
- **F1 (Packet Rate):** > 1000 packets/second
- **F2 (SYN/ACK Ratio):** > 10 (SYN Flood)
- **F5 (Distinct Ports):** = 1 (tấn công 1 port cố định)

**Detection Logic:**
```python
features = calculator.calculate_all(flows)

f1_pps = features[0]
f2_syn_ratio = features[1]
f5_ports = features[4]

if f1_pps > 1000 and f2_syn_ratio > 10 and f5_ports <= 3:
    action = "BLOCK"
    reason = "DDoS/SYN Flood detected"
    
    # Auto-mitigation
    os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
    log_alert(src_ip, reason, features)
```

### 9.2 Use Case 2: Port Scanning Detection

**Scenario:** Phát hiện nmap port scan

**Features sử dụng:**
- **F5 (Distinct Ports):** > 50 ports
- **F4 (RST Ratio):** > 0.5 (nhiều connections failed)
- **F3 (Inter-Arrival Time):** < 0.01s (fast scanning)

**Detection Logic:**
```python
f3_iat = features[2]
f4_rst = features[3]
f5_ports = features[4]

if f5_ports > 50 and f4_rst > 0.5 and f3_iat < 0.01:
    action = "ALERT"
    reason = "Port Scanning detected"
    
    # Honeypot redirect
    os.system(f"iptables -t nat -A PREROUTING -s {src_ip} -j DNAT --to-destination {honeypot_ip}")
    log_alert(src_ip, reason, features)
```

### 9.3 Use Case 3: SQL Injection Detection

**Scenario:** Phát hiện SQLi attack qua HTTP

**Features sử dụng:**
- **F12 (SqlSpecialChar):** > 0.2 (tỷ lệ ký tự đặc biệt ', ;, --)
- **F13 (CrsSqliScore):** ≥ 5 (số rule CRS 942 hit)
- **F14 (SqlUnionSelect):** = 1 (UNION SELECT detected)
- **F15 (SqlComment):** = 1 (--, #, /**/ injection)
- **F16 (SqlStackedQuery):** = 1 (; DROP/DELETE/INSERT)

**Detection Logic:**
```python
f12_sql_char    = features[11]
f13_crs_score   = features[12]
f14_union       = features[13]
f15_comment     = features[14]
f16_stacked     = features[15]

# AI agent (PPO) học pattern từ tổng hợp F12-F17.
# Rule-based safety_net override: Redirect → Block escalation
if f16_stacked == 1.0 or (f13_crs_score >= 5 and f15_comment == 1.0):
    action = "REDIRECT"   # Đẩy attacker vào honeypot
    reason = "High-risk SQLi pattern (stacked query / comment + CRS hit)"
    os.system(f"iptables -t nat -I PREROUTING 1 -s {src_ip} "
              f"-d {server_ip} -p tcp --dport 443 -j REDIRECT --to-ports 4443")
```

### 9.4 Use Case 4: Brute Force Login Detection

**Scenario:** Phát hiện brute force SSH/HTTP login

**Features sử dụng:**
- **F4 (RST Ratio):** > 0.7 (nhiều failed connections)
- **F7 (Auth Failure Rate):** > 0.8 (HTTP 401/403)
- **F1 (Packet Rate):** Moderate (~10-100 pps)

**Detection Logic:**
```python
f1_pps = features[0]
f4_rst = features[3]
f7_auth_fail = features[6]

if f4_rst > 0.7 or f7_auth_fail > 0.8:
    if 10 < f1_pps < 100:  # Not DDoS, but persistent
        action = "RATE_LIMIT"
        reason = "Brute Force Login detected"
        
        # Rate limiting
        os.system(f"iptables -A INPUT -s {src_ip} -m limit --limit 5/min -j ACCEPT")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_alert(src_ip, reason, features)
```

### 9.5 Use Case 5: Forensic Analysis (PCAP)

**Scenario:** Phân tích PCAP sau incident

**Workflow:**
```bash
# 1. Analyze PCAP file
python main_pcap.py -p incident_20260211.pcap -o analysis.csv

# 2. Review CSV output
# Sắp xếp theo F11 (SQLi score) giảm dần
cat analysis.csv | sort -t',' -k12 -rn | head -20

# 3. Tìm src_ip có F11 > 5.0
grep "F11 > 5.0" analysis.csv > sqli_attempts.csv

# 4. Investigate chi tiết
python main_packet_viewer.py -p incident_20260211.pcap -s 192.168.1.100

# 5. Generate report
python generate_report.py -i analysis.csv -o incident_report.pdf
```

---

## 10. KẾT LUẬN

### 10.1 Điểm Mạnh

✅ **Flow-based Analysis:** Hiểu hành vi thay vì chỉ signature  
✅ **Bidirectional Tracking:** Phát hiện được RST, response time  
✅ **Plugin Architecture:** Dễ dàng thêm features mới  
✅ **Performance:** 1.14x speedup với caching, memory efficient  
✅ **Flexible:** Hỗ trợ cả live và offline analysis  
✅ **Tested:** 72 tests passed, 100% backward compatible  
✅ **Documented:** 1,600+ lines comprehensive docs  

### 10.2 Giới Hạn

⚠️ **Encrypted Traffic:** Không phân tích được HTTPS payload (cần SSL/TLS interception)  
⚠️ **IPv6:** Chưa hỗ trợ đầy đủ IPv6  
⚠️ **Performance:** 1.10x overhead so với old (acceptable trade-off cho modularity)  
⚠️ **Memory:** Max 50,000 flows (~2.5GB RAM) - cần scale cho enterprise  

### 10.3 Roadmap

**Short-term (Next Sprint):**
- [ ] Migrate main_*.py scripts to new calculator
- [ ] Add IPv6 support
- [ ] Performance optimization (reduce 1.10x → 1.0x)

**Medium-term (Next Release):**
- [ ] Add more features (F17-F20)
- [ ] Support HTTPS decryption (mitmproxy integration)
- [ ] Dashboard visualization (Grafana)

**Long-term (v3.0):**
- [ ] Distributed processing (Apache Kafka)
- [ ] GPU acceleration for ML features
- [ ] Remove deprecated old calculator

---

## 📚 TÀI LIỆU THAM KHẢO

### Documentation
- [API Documentation](API_DOCUMENTATION.md) - Complete API reference
- [Migration Guide](MIGRATION_GUIDE.md) - v1.x → v2.0 upgrade
- [Phase 2 Summary](../PHASE2_COMPLETION_SUMMARY.md) - Feature refactoring
- [Phase 3 Summary](../PHASE3_COMPLETION_SUMMARY.md) - Deprecation
- [Phase 4 Summary](../PHASE4_COMPLETION_SUMMARY.md) - Documentation

### Research Papers
- CICFlowMeter: Network Traffic Flow Generator and Analyser
- Kruegel et al. - Anomaly Detection of Web-based Attacks
- OWASP ModSecurity Core Rule Set (CRS) — F13 (CrsSqliScore), F18 (CrsXssScore)

### Tools & Libraries
- [Scapy](https://scapy.net/) - Packet manipulation
- [Npcap](https://npcap.com/) - Windows packet capture driver
- [Stable-Baselines3](https://stable-baselines3.readthedocs.io/) - PPO/DQN RL agent

---

**Document Version:** 1.0  
**Author:** NIDS Development Team  
**Date:** February 11, 2026  
**Status:** Complete ✅
