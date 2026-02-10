# HƯỚNG DẪN TRIỂN KHAI OPTION B: 2 SNIFFERS

**Dự án:** RL Defense Agent  
**Ngày tạo:** 10/02/2026  
**Phiên bản:** 1.0

---

## MỤC LỤC

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Hai Sniffer - Phân công nhiệm vụ](#2-hai-sniffer---phân-công-nhiệm-vụ)
3. [Vector 20 Features](#3-vector-20-features)
4. [Data Flow và Aggregation](#4-data-flow-và-aggregation)
5. [Inter-Process Communication (IPC)](#5-inter-process-communication-ipc)
6. [PPO-RL Agent Input/Output](#6-ppo-rl-agent-inputoutput)
7. [Trigger Logic](#7-trigger-logic)
8. [Containernet Topology](#8-containernet-topology)
9. [Action Execution](#9-action-execution)
10. [Wazuh Integration](#10-wazuh-integration)
11. [Implementation Roadmap](#11-implementation-roadmap)
12. [Checklist tổng hợp](#12-checklist-tổng-hợp)

---

## 1. TỔNG QUAN KIẾN TRÚC

### 1.1 System Diagram

```
                              INTERNET
                                  │
                            10.0.10.10/24
                            [ATTACKER/USER]
                                  │
                                  │ HTTPS (encrypted)
                                  ▼
                           ══════════════
                           ║ SNIFFER #1 ║  ← Sniff raw TCP
                           ══════════════
                                  │
                           10.0.10.254/24
                      ┌───────────────────────┐
                      │   FIREWALL + NGINX    │
                      └───────────┬───────────┘
                                  │ HTTP plaintext
                           ══════════════
                           ║ SNIFFER #2 ║  ← Sniff HTTP
                           ══════════════
                                  │
                      ┌───────────────────────┐
                      │       AI AGENT        │
                      │    (PPO-RL + Actions) │
                      └───────────┬───────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
    ┌──────────┐           ┌──────────┐           ┌──────────┐
    │WEBSERVER │           │  BLOCK   │           │ HONEYPOT │
    │  (DMZ)   │           │(Firewall)│           │(ISOLATED)│
    └──────────┘           └──────────┘           └──────────┘
```

### 1.2 Tại sao cần 2 Sniffers?

| Vị trí | Thấy được | Detect |
|--------|-----------|--------|
| **Trước Nginx** | Raw TCP (encrypted TLS) | ✅ SYN Flood, ✅ Port Scan |
| **Sau Nginx** | HTTP plaintext | ✅ Brute Force, ✅ SQLi, ✅ XSS |

**Kết luận:** Không có vị trí nào detect được cả 5 loại với 1 sniffer → Cần 2 sniffers.

### 1.3 5 Loại tấn công cần detect

| # | Tấn công | Sniffer | Layer |
|---|----------|---------|-------|
| 1 | SYN Flood | #1 | Network (TCP) |
| 2 | Port Scanning | #1 | Network (TCP) |
| 3 | Brute Force | #2 | Application (HTTP) |
| 4 | SQL Injection | #2 | Application (HTTP) |
| 5 | XSS | #2 | Application (HTTP) |

---

## 2. HAI SNIFFER - PHÂN CÔNG NHIỆM VỤ

### 2.1 SNIFFER #1: NETWORK LAYER (Trước Nginx)

| Thuộc tính | Giá trị |
|------------|---------|
| **Vị trí** | Trên Firewall node, interface hướng Internet |
| **Interface** | `eth-internet` hoặc `fw-eth0` |
| **BPF Filter** | `tcp` |
| **Thấy được** | Raw TCP packets (SYN, ACK, RST, FIN) |
| **Không thấy** | HTTP payload (encrypted by TLS) |
| **Mục đích** | Detect SYN Flood, Port Scanning |

### 2.2 SNIFFER #2: APPLICATION LAYER (Sau Nginx)

| Thuộc tính | Giá trị |
|------------|---------|
| **Vị trí** | Trên AI Agent node, interface từ Nginx |
| **Interface** | `eth-nginx` hoặc `agent-eth0` |
| **BPF Filter** | `tcp port 80 or tcp port 8080` |
| **Thấy được** | HTTP plaintext với X-Forwarded-For |
| **Mục đích** | Detect Brute Force, SQLi, XSS |

### 2.3 Tại sao không cần TCP Reassembly?

- Nginx dùng HTTP/1.0 + `Connection: close`
- Mỗi request = 1 TCP connection
- SQLi/XSS thường nằm ở URL/query string (packet đầu tiên)
- POST body nhỏ (< 1400 bytes) nằm gọn trong 1 packet

**Kết luận:** Không cần TCP Reassembly cho use case này.

---

## 3. VECTOR 20 FEATURES

### 3.1 NHÓM A: NETWORK FEATURES (5) - Từ Sniffer #1

| # | Feature | Công thức | Detect |
|---|---------|-----------|--------|
| F1 | `syn_count_1s` | Count packets có flag SYN trong 1s per src_ip | SYN Flood |
| F2 | `syn_ack_ratio` | SYN / (SYN+ACK) trong 1s | SYN Flood |
| F3 | `distinct_src_ports_1s` | Count unique src_port per src_ip trong 1s | Spoofing |
| F4 | `distinct_dst_ports_1s` | Count unique dst_port per src_ip trong 1s | Port Scan |
| F5 | `rst_count_1s` | Count packets có flag RST trong 1s | Failed conns |

### 3.2 NHÓM B: BEHAVIORAL FEATURES (5) - Từ Sniffer #2

| # | Feature | Công thức | Detect |
|---|---------|-----------|--------|
| F6 | `request_count_1s` | Count HTTP requests per client_ip trong 1s | Brute Force |
| F7 | `unique_endpoints_1s` | Count unique URL paths per client_ip | Scanning |
| F8 | `avg_interval_ms` | Mean time between requests | Bot detection |
| F9 | `error_rate_1s` | 4xx+5xx responses / total responses | Brute Force |
| F10 | `repeated_endpoint_ratio` | Max(endpoint_count) / total requests | Brute Force |

### 3.3 NHÓM C: PAYLOAD FEATURES (10) - Từ Sniffer #2

| # | Feature | Công thức | Detect |
|---|---------|-----------|--------|
| F11 | `payload_length` | len(HTTP body + query string) | Anomaly |
| F12 | `path_depth` | Count `/` trong URL path | Traversal |
| F13 | `param_count` | Count query parameters | Injection |
| F14 | `sqli_keyword_score` | Match: UNION, SELECT, OR, AND, DROP... | SQLi |
| F15 | `sqli_pattern_score` | Regex: `' OR 1=1`, `--`, `/**/`... | SQLi |
| F16 | `xss_keyword_score` | Match: script, onerror, onclick... | XSS |
| F17 | `xss_pattern_score` | Regex: `<script>`, `javascript:`... | XSS |
| F18 | `entropy_score` | Shannon entropy của payload | Obfuscation |
| F19 | `special_char_ratio` | Count `'";{}[]()` / total chars | Injection |
| F20 | `encoding_layers` | Số lần URL/HTML decode cần thiết | Evasion |

### 3.4 Tổng hợp Feature Groups

| Nhóm | Features | Số lượng | Source |
|------|----------|----------|--------|
| Network | F1-F5 | 5 | Sniffer #1 |
| Behavioral | F6-F10 | 5 | Sniffer #2 |
| Payload | F11-F20 | 10 | Sniffer #2 |
| **TỔNG** | | **20** | |

---

## 4. DATA FLOW VÀ AGGREGATION

### 4.1 Aggregation Key

```
┌─────────────────────────────────────────────────────────────┐
│                     KEY MAPPING                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Sniffer #1:  src_ip = 10.0.10.10  (client thật)           │
│                   │                                         │
│                   │  PHẢI MATCH                             │
│                   ▼                                         │
│  Sniffer #2:  X-Forwarded-For = 10.0.10.10                 │
│               (parsed từ HTTP header)                       │
│                                                             │
│  Aggregator dùng CLIENT IP làm key để merge                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Sliding Window 1 Second

| Thuộc tính | Giá trị |
|------------|---------|
| Window size | 1 second |
| Slide step | per-packet (continuous) |
| Cleanup | remove entries older than current_time - 1s |
| Timer | `time.monotonic()` (không bị ảnh hưởng bởi NTP sync) |
| Memory limit | maxlen = 10000 packets per client |

### 4.3 Data Structures

#### NetworkBucket (Sniffer #1)

```
NetworkBucket {
    src_ip: str                    # "10.0.10.10"
    syn_times: deque[float]        # timestamps of SYN packets
    ack_times: deque[float]        # timestamps of ACK packets
    rst_times: deque[float]        # timestamps of RST packets
    src_ports: deque[(float, int)] # (timestamp, port)
    dst_ports: deque[(float, int)] # (timestamp, port)
    
    def get_features() -> [F1, F2, F3, F4, F5]
    def cleanup(current_time)
}
```

#### ApplicationBucket (Sniffer #2)

```
ApplicationBucket {
    client_ip: str                 # from X-Forwarded-For
    request_times: deque[float]    # timestamps
    endpoints: deque[(float, str)] # (timestamp, URL path)
    status_codes: deque[(float, int)]
    last_payload_features: dict    # F11-F20 của request cuối
    
    def get_behavioral() -> [F6, F7, F8, F9, F10]
    def get_payload() -> [F11...F20]
    def cleanup(current_time)
}
```

---

## 5. INTER-PROCESS COMMUNICATION (IPC)

### 5.1 Architecture

```
┌──────────────────┐                    ┌──────────────────┐
│   SNIFFER #1     │                    │   SNIFFER #2     │
│  (Firewall node) │                    │  (AI Agent node) │
│                  │                    │                  │
│  Produces:       │                    │  Produces:       │
│  NetworkFeatures │                    │  AppFeatures     │
│  (5 features)    │                    │  (15 features)   │
│                  │                    │                  │
└────────┬─────────┘                    └────────┬─────────┘
         │                                       │
         │ ZeroMQ PUSH                          │ Local
         │ or Redis LPUSH                       │
         ▼                                       ▼
┌─────────────────────────────────────────────────────────────┐
│                       AGGREGATOR                            │
│                   (on AI Agent node)                        │
│                                                             │
│   Merge logic:                                              │
│   - Match by client_ip                                      │
│   - Nếu |network_time - app_time| < 100ms → merge          │
│   - Nếu timeout → dùng default values [0,0,0,0,0]          │
│                                                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                   ┌──────────────┐
                   │  PPO AGENT   │
                   │  20 features │
                   └──────────────┘
```

### 5.2 Message Format từ Sniffer #1

```json
{
    "type": "network",
    "timestamp": 1707580742.123,
    "src_ip": "10.0.10.10",
    "features": {
        "syn_count_1s": 45,
        "syn_ack_ratio": 0.9,
        "distinct_src_ports": 12,
        "distinct_dst_ports": 1,
        "rst_count_1s": 2
    }
}
```

### 5.3 Message Format từ Sniffer #2

```json
{
    "type": "application",
    "timestamp": 1707580742.125,
    "client_ip": "10.0.10.10",
    "request_id": "abc123",
    "features": {
        "request_count_1s": 5,
        "unique_endpoints_1s": 1,
        "avg_interval_ms": 200,
        "error_rate_1s": 0.4,
        "repeated_endpoint_ratio": 1.0,
        "payload_length": 156,
        "path_depth": 1,
        "param_count": 1,
        "sqli_keyword_score": 3,
        "sqli_pattern_score": 2,
        "xss_keyword_score": 0,
        "xss_pattern_score": 0,
        "entropy_score": 4.2,
        "special_char_ratio": 0.15,
        "encoding_layers": 1
    }
}
```

### 5.4 IPC Options

| Option | Ưu điểm | Nhược điểm |
|--------|---------|------------|
| **ZeroMQ** | Fast, low latency | Cần install thêm |
| **Redis** | Có sẵn persistence, pub/sub | Thêm dependency |
| **Unix Socket** | Simple, fast | Chỉ local |
| **TCP Socket** | Cross-machine | Cần handle connection |

**Đề xuất:** ZeroMQ PUSH/PULL pattern cho simplicity và performance.

---

## 6. PPO-RL AGENT INPUT/OUTPUT

### 6.1 Input Vector (20-dim, normalized)

```
Vector = [
    # Network (5) - từ Sniffer #1
    norm(syn_count_1s, 0, 1000),        # F1
    syn_ack_ratio,                       # F2 (already 0-1)
    norm(distinct_src_ports, 0, 100),   # F3
    norm(distinct_dst_ports, 0, 65535), # F4
    norm(rst_count_1s, 0, 500),         # F5
    
    # Behavioral (5) - từ Sniffer #2
    norm(request_count_1s, 0, 100),     # F6
    norm(unique_endpoints, 0, 50),       # F7
    norm(avg_interval_ms, 0, 5000),     # F8
    error_rate_1s,                       # F9 (already 0-1)
    repeated_endpoint_ratio,             # F10 (already 0-1)
    
    # Payload (10) - từ Sniffer #2
    norm(payload_length, 0, 10000),     # F11
    norm(path_depth, 0, 10),            # F12
    norm(param_count, 0, 20),           # F13
    norm(sqli_keyword_score, 0, 10),    # F14
    norm(sqli_pattern_score, 0, 10),    # F15
    norm(xss_keyword_score, 0, 10),     # F16
    norm(xss_pattern_score, 0, 10),     # F17
    norm(entropy_score, 0, 8),          # F18
    special_char_ratio,                  # F19 (already 0-1)
    norm(encoding_layers, 0, 5)         # F20
]
```

### 6.2 Normalization Formula

```
norm(value, min, max) = (value - min) / (max - min)
                      = clamp to [0, 1]
```

### 6.3 Output Actions (4 actions)

| Action | ID | Mô tả | Implementation |
|--------|----|----|----------------|
| **ALLOW** | 0 | Forward request bình thường | Không làm gì |
| **BLOCK** | 1 | Chặn IP | iptables DROP + timeout |
| **RATE_LIMIT** | 2 | Giới hạn request rate | Nginx limit / delay 500ms |
| **HONEYPOT** | 3 | Redirect đến fake server | DNAT hoặc proxy routing |

### 6.4 PPO Model Architecture

```
Input Layer:  20 neurons
Hidden Layer 1: 64 neurons, ReLU
Hidden Layer 2: 64 neurons, ReLU
Output Layer: 4 neurons (action probabilities)
```

### 6.5 Reward Function

| Scenario | Reward | Lý do |
|----------|--------|-------|
| Correct block attack | +1.0 | True positive |
| Correct allow benign | +0.5 | True negative |
| Block benign (false positive) | -1.0 | UX impact |
| Allow attack (false negative) | -2.0 | Security breach |
| Redirect to honeypot | +0.5 | Learn + protect |
| Rate limit (any) | +0.2 | Cautious approach |

---

## 7. TRIGGER LOGIC

### 7.1 Khi nào gọi Agent?

#### IMMEDIATE TRIGGER (< 5ms)

Trigger ngay khi:
- `sqli_keyword_score > 0`
- `sqli_pattern_score > 0`
- `xss_keyword_score > 0`
- `xss_pattern_score > 0`

**Lý do:** Potential attack, cần quyết định ngay.

#### THRESHOLD TRIGGER

Trigger khi vượt ngưỡng:
- `syn_count_1s > 50`
- `request_count_1s > 20`
- `error_rate_1s > 0.5`
- `distinct_dst_ports > 10`

**Lý do:** Anomaly detected.

#### PERIODIC TRIGGER (mỗi 100ms)

- Batch evaluation cho tất cả active clients
- Dùng cho rate limiting decisions

#### NO TRIGGER (skip agent)

- Normal traffic, all features trong range bình thường
- Default action: ALLOW

### 7.2 Latency Budget

| Component | Target | Max |
|-----------|--------|-----|
| Sniffer #1 capture | < 1ms | 2ms |
| Sniffer #1 → Aggregator | < 5ms | 10ms |
| Sniffer #2 capture | < 1ms | 2ms |
| Feature extraction | < 2ms | 5ms |
| Aggregation + merge | < 2ms | 5ms |
| PPO inference | < 5ms | 10ms |
| Action execution | < 5ms | 10ms |
| **TOTAL** | **< 21ms** | **44ms** |

**Target:** Total latency < 50ms để không ảnh hưởng UX.

---

## 8. CONTAINERNET TOPOLOGY

### 8.1 Nodes và IPs

| Node | IP | Role |
|------|----|----|
| attacker | 10.0.10.10/24 | Client/Attacker |
| firewall | 10.0.10.254/24, 192.168.x.1/24 | Firewall + Sniffer #1 |
| nginx | 192.168.10.2/24 | Reverse Proxy (TLS termination) |
| agent | 192.168.10.3/24 | AI Agent + Sniffer #2 |
| webserver | 192.168.10.10/24 | Target (DMZ) |
| honeypot | 192.168.30.10/24 | Fake server (Isolated) |
| wazuh | 192.168.20.100/24 | SIEM/Management |

### 8.2 Switches

| Switch | Zone | Connections |
|--------|------|-------------|
| s1 | Internet | attacker ↔ firewall |
| s2 | DMZ | firewall ↔ nginx ↔ agent ↔ webserver |
| s3 | Isolated | agent ↔ honeypot |
| s4 | Management | agent ↔ wazuh |

### 8.3 Interface Mapping cho Sniffer

| Sniffer | Interface | Direction | Filter |
|---------|-----------|-----------|--------|
| #1 | firewall-eth0 | Inbound từ Internet | `tcp` |
| #2 | agent-eth0 | Inbound từ Nginx | `tcp port 80 or tcp port 8080` |

### 8.4 Traffic Flow

```
[Attacker] 
    │
    │ HTTPS (port 443)
    ▼
[Firewall] ←── Sniffer #1 (raw TCP)
    │
    │ Forward to Nginx
    ▼
[Nginx] 
    │ TLS Termination
    │ Add X-Forwarded-For header
    │
    │ HTTP plaintext (port 80/8080)
    ▼
[AI Agent] ←── Sniffer #2 (HTTP parsing)
    │
    │ Decision: allow/block/rate-limit/honeypot
    │
    ├──────────────┬──────────────┐
    ▼              ▼              ▼
[Webserver]    [Block]      [Honeypot]
```

---

## 9. ACTION EXECUTION

### 9.1 BLOCK Mechanism

#### Option 1: SSH Command
```bash
ssh firewall "iptables -A INPUT -s {ip} -j DROP"
```

#### Option 2: REST API
```bash
POST http://firewall:8080/block
{"ip": "10.0.10.10", "duration": 300}
```

#### Option 3: Redis Pub/Sub
```
Agent: PUBLISH firewall:block "10.0.10.10"
Firewall: SUBSCRIBE firewall:block → apply iptables
```

#### Unblock Logic
- Automatic timeout: 5 minutes (configurable)
- Manual override via Wazuh dashboard

### 9.2 RATE_LIMIT Mechanism

#### Nginx Dynamic Config

```nginx
# Rate limit zone per IP
limit_req_zone $binary_remote_addr zone=strict:10m rate=5r/s;

# Apply khi Agent quyết định
location / {
    limit_req zone=strict burst=10 nodelay;
}
```

#### Alternative: Response Delay

```python
# Agent gửi signal để nginx delay response
time.sleep(0.5)  # 500ms delay
```

### 9.3 HONEYPOT Redirect Mechanism

#### Option A: iptables DNAT (Recommended)

```bash
iptables -t nat -A PREROUTING -s {ip} -j DNAT --to-destination 192.168.30.10
```

#### Option B: Nginx Upstream Switch

```nginx
upstream backend {
    server 192.168.10.10:8080;  # Real
}

upstream honeypot {
    server 192.168.30.10:8080;  # Fake
}

# Switch based on IP (via Lua hoặc map)
```

#### Option C: Agent-level Proxy

Agent node acts as proxy, routes suspicious IPs to honeypot.

---

## 10. WAZUH INTEGRATION

### 10.1 Log Events to Send

| Event Type | Trigger | Data |
|------------|---------|------|
| agent_decision | Mỗi decision | action, reason, features |
| attack_detected | Khi detect attack | attack_type, severity, client_ip |
| ip_blocked | Khi block IP | ip, duration, reason |
| honeypot_interaction | Khi có traffic đến honeypot | request details |
| system_health | Periodic | latency, memory, queue size |

### 10.2 Log Format (JSON Syslog)

```json
{
    "timestamp": "2026-02-10T21:19:02.933Z",
    "type": "agent_decision",
    "client_ip": "10.0.10.10",
    "action": "block",
    "reason": "sqli_detected",
    "features": {
        "sqli_keyword_score": 5,
        "sqli_pattern_score": 3,
        "request_count_1s": 12
    },
    "confidence": 0.95
}
```

### 10.3 Transport

- Protocol: Syslog UDP hoặc TCP
- Destination: 192.168.20.100:514
- Format: JSON trong syslog message

### 10.4 Wazuh Custom Rules

```xml
<rule id="100001" level="10">
    <decoded_as>json</decoded_as>
    <field name="type">attack_detected</field>
    <description>RL Agent detected attack</description>
</rule>

<rule id="100002" level="7">
    <decoded_as>json</decoded_as>
    <field name="action">block</field>
    <description>RL Agent blocked IP</description>
</rule>
```

---

## 11. IMPLEMENTATION ROADMAP

### PHASE 1: FOUNDATION (1-2 tuần)

| Task | Mô tả | Status |
|------|-------|--------|
| 1.1 | Containernet topology setup với tất cả nodes | ⬜ |
| 1.2 | Sniffer #1: 5 network features (F1-F5) | ⬜ |
| 1.3 | Sniffer #2: Parse X-Forwarded-For, 15 features | ⬜ |

### PHASE 2: AGGREGATION (1 tuần)

| Task | Mô tả | Status |
|------|-------|--------|
| 2.1 | Aggregator service (receive from both sniffers) | ⬜ |
| 2.2 | Sliding window 1s per client | ⬜ |
| 2.3 | Feature normalization [0, 1] | ⬜ |

### PHASE 3: PPO AGENT (2-3 tuần)

| Task | Mô tả | Status |
|------|-------|--------|
| 3.1 | PPO model architecture (20-in, 4-out) | ⬜ |
| 3.2 | Reward function design | ⬜ |
| 3.3 | Training environment + dataset | ⬜ |

### PHASE 4: ACTIONS (1 tuần)

| Task | Mô tả | Status |
|------|-------|--------|
| 4.1 | Block mechanism (Agent → Firewall) | ⬜ |
| 4.2 | Rate limit mechanism (Nginx) | ⬜ |
| 4.3 | Honeypot redirect | ⬜ |

### PHASE 5: INTEGRATION (1-2 tuần)

| Task | Mô tả | Status |
|------|-------|--------|
| 5.1 | Wazuh logging integration | ⬜ |
| 5.2 | End-to-end testing (5 attack types) | ⬜ |
| 5.3 | Performance tuning | ⬜ |

### Tổng thời gian ước tính: 6-9 tuần

---

## 12. CHECKLIST TỔNG HỢP

| # | Task | Priority | Status |
|---|------|----------|--------|
| 1 | Containernet topology với 2 sniff points | HIGH | ⬜ |
| 2 | Sniffer #1: 5 network features (SYN/Port) | HIGH | ⬜ |
| 3 | Sniffer #2: 15 app features (Brute/SQLi/XSS) | HIGH | ⬜ |
| 4 | IPC: ZeroMQ giữa sniffers và aggregator | HIGH | ⬜ |
| 5 | Aggregator: merge by client IP, sliding window | HIGH | ⬜ |
| 6 | Normalization: scale [0,1] cho 20 features | MEDIUM | ⬜ |
| 7 | PPO model: 20-in, 4-out | HIGH | ⬜ |
| 8 | Reward function design | MEDIUM | ⬜ |
| 9 | Block action → Firewall | HIGH | ⬜ |
| 10 | Rate limit action → Nginx | MEDIUM | ⬜ |
| 11 | Honeypot redirect | MEDIUM | ⬜ |
| 12 | Wazuh logging | LOW | ⬜ |
| 13 | Test 5 attack types | HIGH | ⬜ |
| 14 | Performance tuning | LOW | ⬜ |

---

## PHỤ LỤC A: EXISTING CODE MAPPING

### Code hiện có trong dự án

| File | Mô tả | Tái sử dụng |
|------|-------|-------------|
| `System/core/sniffer.py` | Packet capture | Sửa cho multi-interface |
| `System/core/packet_parser.py` | Parse packets | Giữ nguyên |
| `System/feature/payload_features.py` | 21 payload features | Chọn 10 features cần thiết |
| `System/feature/behavioral_features.py` | Behavioral features | Sử dụng cho F6-F10 |
| `System/feature/payload_context.py` | SQLi/XSS patterns | Sử dụng cho F14-F17 |
| `System/core/flow_manager.py` | Flow tracking | Sửa key = X-Forwarded-For |
| `System/core/flow_state.py` | Flow state | Giữ nguyên |

### Features đã có vs Features cần thêm

| Feature Group | Đã có | Cần thêm |
|---------------|-------|----------|
| Network (F1-F5) | 0 | 5 (mới hoàn toàn) |
| Behavioral (F6-F10) | 3-4 | 1-2 |
| Payload (F11-F20) | 8-10 | 0-2 |

---

## PHỤ LỤC B: ATTACK SIGNATURES

### B.1 SYN Flood Indicators

```
syn_count_1s > 100
syn_ack_ratio > 0.8
distinct_src_ports > 50 (spoofed)
rst_count_1s > 50
```

### B.2 Port Scan Indicators

```
distinct_dst_ports > 10 trong 1s
request_count_1s thấp (probing)
syn_ack_ratio cao (không có response)
```

### B.3 Brute Force Indicators

```
request_count_1s > 20
repeated_endpoint_ratio > 0.8 (cùng /login)
error_rate_1s > 0.5 (401/403)
avg_interval_ms < 100 (automated)
```

### B.4 SQLi Indicators

```
sqli_keyword_score > 2 (UNION, SELECT, OR)
sqli_pattern_score > 1 (' OR 1=1, --, /**/)
special_char_ratio > 0.1
encoding_layers > 1 (evasion)
```

### B.5 XSS Indicators

```
xss_keyword_score > 2 (script, onerror)
xss_pattern_score > 1 (<script>, javascript:)
entropy_score cao (obfuscated)
encoding_layers > 1 (evasion)
```

---

## PHỤ LỤC C: COMMANDS REFERENCE

### Containernet

```bash
# Start topology
sudo python3 topology.py

# Open CLI
mininet> xterm firewall
mininet> xterm agent

# Test connectivity
mininet> attacker ping webserver
```

### Sniffer

```bash
# Sniffer #1 on firewall
tcpdump -i fw-eth0 -w /tmp/capture.pcap tcp

# Sniffer #2 on agent
tcpdump -i agent-eth0 -w /tmp/http.pcap 'tcp port 80'
```

### iptables (Block)

```bash
# Block IP
iptables -A INPUT -s 10.0.10.10 -j DROP

# Unblock
iptables -D INPUT -s 10.0.10.10 -j DROP

# DNAT to honeypot
iptables -t nat -A PREROUTING -s 10.0.10.10 -j DNAT --to-destination 192.168.30.10
```

### Attack Simulation

```bash
# SYN Flood
hping3 -S --flood -p 80 10.0.10.254

# Port Scan
nmap -sS -p 1-1000 10.0.10.254

# Brute Force
hydra -l admin -P passwords.txt http://10.0.10.254/login

# SQLi
curl "http://10.0.10.254/search?q=' OR 1=1 --"

# XSS
curl "http://10.0.10.254/search?q=<script>alert(1)</script>"
```

---

**END OF DOCUMENT**

*Để convert sang PDF, sử dụng:*
- VS Code: Extension "Markdown PDF"
- Command line: `pandoc OPTION_B_IMPLEMENTATION_GUIDE.md -o OPTION_B_IMPLEMENTATION_GUIDE.pdf`
- Online: https://markdowntopdf.com
