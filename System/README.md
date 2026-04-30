# System — NIDS Sniffer & 20-Feature Extractor

Module Network Intrusion Detection System (NIDS) đứng trước AI RL agent.
Capture packets từ network interface, mỗi 1 second window tổng hợp 20 features
và ghi ra `sniffer_output.jsonl` để AI agent đọc, chuẩn hoá rồi ra quyết định
firewall (Allow / RateLimit / Redirect / Block).

---

## 0. TL;DR

- **Vai trò**: NIDS realtime (1 Hz) — feed sensor data cho AI RL agent
- **Entry point**: `main.py` (interactive menu, 4 modes)
- **Output**: `sniffer_output.jsonl` — mỗi line = 1 (src_ip × 1s window) với 20 features
- **Consumer**: `AI RL/infer.py` tail file → 34D obs (20D + 10D temporal + 4D effect) → PPO predict
- **Window size**: 1.0s (cố định, không đổi — toàn bộ normalize bounds calibrate cho 1s)

---

## 1. Vai trò trong pipeline

```
+----------------------------------------------------------------+
|  ATTACKER (10.0.10.10)  -->  ROUTER (Mininet)  -->  WEBSERVER  |
|                              |                                  |
|                              +-- NIDS Sniffer (System/main.py) |
|                              |    capture r-ext, 1s window      |
|                              |    -> /tmp/sniffer_output.jsonl  |
|                              |       (20 features per src_ip)   |
|                              |                                  |
|                              +-- AI Agent (AI RL/infer.py)     |
|                              |    tail JSONL -> 34D obs         |
|                              |    PPO predict -> action         |
|                              |    -> iptables rule              |
|                              |                                  |
|                              +-- Wazuh agent                    |
|                                   tail actions_wazuh.log        |
+----------------------------------------------------------------+
```

---

## 2. Cấu trúc folder

```
System/
├── main.py                     Entry point — interactive menu (realtime / PCAP / CSV)
├── features_catalog.csv        Spec 64 raw + 30 derived (historical reference)
├── pytest.ini                  Pytest config + markers
├── run_tests.py                Test runner CLI (interactive)
├── config/
│   ├── data_params.py          FEATURE_ORDER, FEATURE_CLIP_BOUNDS, normalize_feature_vector()
│   ├── nids_config.py          NIDSConfig dataclass (queue size, flow timeout, ...)
│   ├── logger_config.py        Logging setup
│   └── wamm_config.py          WAMM model paths (legacy)
├── core/                       Packet capture + flow management
│   ├── sniffer.py              NetworkSniffer — Scapy sniff() wrapper
│   ├── packet_parser.py        PacketLayerExtractor → LayerInfo struct
│   ├── packet_queue.py         Thread-safe bounded queue (max=10000)
│   ├── flow_manager.py         FlowManager — flows by 5-tuple, bidirectional
│   ├── flow_state.py           FlowState — per-flow deques (maxlen=3000)
│   ├── feature_merger.py       Legacy merger (không dùng trong realtime)
│   ├── crs_loader.py           Load OWASP ModSecurity CRS rules
│   ├── tshark_l7.py            TsharkL7Reader — HTTPS decrypt qua SSLKEYLOGFILE
│   ├── layer_info.py           LayerInfo data class
│   └── exception.py            Custom exceptions
├── feature/                    Plugin-based 20 feature calculators
│   ├── base.py                 FeatureBase ABC + FeatureRegistry + decorator
│   ├── context.py              FeatureContext (caching cho payload scoring)
│   ├── calculator.py           FlowFeatureCalculator — orchestrator
│   ├── wamm_classifier.py      WammClassifier (legacy, vẫn init backward compat)
│   ├── calculators/            5 file × 20 features
│   │   ├── network_features.py         F1-F5
│   │   ├── application_features.py     F6-F8
│   │   ├── network_features_ext.py     F9-F11
│   │   ├── sqli_features.py            F12-F17
│   │   ├── xss_features.py             F18-F20
│   │   └── _archive/                   Old implementations
│   └── _archive/                       Deprecated modules (Kruegel, behavioral, ...)
├── test/                       Pytest test suite
│   ├── conftest.py             Shared fixtures
│   ├── helpers.py              Test utilities
│   ├── test_features_all.py    20-feature validation
│   ├── test_kruegel_features.py  Legacy Kruegel ML tests
│   ├── test_wamm_classifier.py   WAMM unit tests
│   └── _archive/               Old tests (30-feature system, ...)
├── tools/                      Utility scripts
│   ├── pcap_slicer.py          Chia PCAP theo time/packet count
│   ├── csv_slicer.py           Chia Wireshark CSV
│   ├── test_features_from_csv.py   Offline feature extraction từ CSV
│   ├── test_features_to_json.py    Test với JSON output
│   └── wamm_train.py           Train WAMM XGBoost (legacy)
├── docs/
│   ├── SYSTEM_ARCHITECTURE_OVERVIEW_VI.md   Tài liệu kiến trúc tiếng Việt
│   ├── API_DOCUMENTATION.md                 Plugin API + 20 features by category
│   ├── 2003_kruegel_vigna_ccs03.pdf         Kruegel & Vigna 2003
│   ├── s41598-023-48845-4.pdf               Scientific Reports 2023
│   └── 2512.23610v2.pdf                     arXiv 2025
└── dataset/
    └── LSNM2024 Dataset/1320981.pdf         Reference paper cho LSNM2024
```

---

## 3. Entry point — `main.py`

Interactive menu 4 modes. CLI duy nhất: `python3 main.py`.

| Mode | Mô tả | Hàm chính |
|---|---|---|
| 1. Realtime | Capture live traffic từ network interface | `_run_realtime()` |
| 2. PCAP | Replay file PCAP offline | `_run_pcap()` |
| 3. CSV | Replay Wireshark CSV export offline | `_run_csv()` |
| 4. Settings | Chỉnh window size, normalize, ... | menu utils |

### `_run_realtime(interface, window_size, output_file, fmt, keylog_file)` (`main.py:164-421`)

Hàm chính cho production. Mininet topology (`containernet/test2.py`) gọi trực tiếp:

```python
_run_realtime(
    interface='r-ext',
    window_size=1.0,
    output_file='/tmp/sniffer_output.jsonl',
    fmt='jsonl',
    keylog_file='/tmp/tls_keys.log',
)
```

**Flow:**
1. Khởi tạo `PacketQueue(max=10000)`, `PacketLayerExtractor`, `FlowManager`, `WammClassifier`, `NetworkSniffer`
2. Spawn 2 daemon thread:
   - `_capture()` — Scapy `sniff()` BPF filter `"tcp"`, `timeout=20s` để periodic restart tránh stuck
   - `_analyze()` — pop từ queue → parse packet → feed `FlowManager`
3. Window loop main thread: mỗi `window_size` giây gọi `_process_window(win_end)`
   - Group flows by `src_ip`
   - Mỗi src_ip: `FlowFeatureCalculator.calculate_all(flows)` → list 20 float
   - Gắn meta L7 enrichment + ghi 1 dòng JSON/CSV
4. Optional: `TsharkL7Reader` start subprocess tshark + SSLKEYLOGFILE → enrich HTTPS L7
5. In stats mỗi window: `Cap` (captured), `Proc` (processed), `Drop` (queue full), `Err`, `Rows` (output rows)

---

## 4. Output format `sniffer_output.jsonl`

Mỗi dòng là 1 JSON object = 1 (src_ip × 1s window). Keys cố định, theo thứ tự:

```json
{
  "timestamp": 1777048182.65,
  "src_ip": "10.0.10.10",
  "meta_https_data_packets": 5,
  "meta_https_unenriched_packets": 2,
  "meta_http_enriched_packets": 3,
  "meta_l7_confident": true,
  "F1 - PacketRate": 150.5,
  "F2 - SynAckRatio": 0.8,
  "F3 - InterArrivalTime": 0.0066,
  "F4 - RstRatio": 0.0,
  "F5 - DistinctPorts": 1.0,
  "F6 - URLConcentration": 1.0,
  "F7 - HttpIatUniformity": 0.92,
  "F8 - RequestSizeUniformity": 0.88,
  "F9 - AvgPayloadSize": 412.0,
  "F10 - FwdBwdRatio": 1.05,
  "F11 - PacketsPerPort": 150.5,
  "F12 - SqlSpecialChar": 0.18,
  "F13 - CrsSquliScore": 7.0,
  "F14 - SqlUnionSelect": 1.0,
  "F15 - SqlComment": 1.0,
  "F16 - SqlStackedQuery": 0.0,
  "F17 - SqlSelectCount": 3.0,
  "F18 - CrsXssScore": 0.0,
  "F19 - JsFunctionCall": 0.0,
  "F20 - HtmlEventHandler": 0.0
}
```

| Key | Ý nghĩa |
|---|---|
| `timestamp` | `win_end` round 6 decimals (epoch seconds) |
| `src_ip` | Source IP của flows trong window |
| `meta_https_data_packets` | Số HTTPS data packets observed |
| `meta_https_unenriched_packets` | HTTPS packets KHÔNG decrypt được (thiếu keylog hoặc tshark fail) |
| `meta_http_enriched_packets` | HTTP packets có L7 metadata (URI, method, ...) |
| `meta_l7_confident` | True nếu L7 enrichment đáng tin (đủ keylog + tshark healthy) |
| `F1` … `F20` | 20 raw feature values, round 4 decimals |

Ghi chú: keys "F1 - PacketRate", ... được sinh bởi `FlowFeatureCalculator.get_feature_labels()`
(`feature/calculator.py:291`). AI RL agent (`infer.py`) chỉ extract 20 giá trị `F*` và bỏ qua
4 meta key.

---

## 5. 20 Features — bảng đầy đủ

Bảng tổng hợp công thức + dấu hiệu attack điển hình:

| # | Code | Tên | Công thức / Mô tả | Range | Dấu hiệu attack |
|---|---|---|---|---|---|
| 1 | F1 | PacketRate | `total_pkt / window_size` | [0, ∞) | DDoS Flood: > 1000 pkt/s |
| 2 | F2 | SynAckRatio | `fwd_SYN / max(fwd_ACK, 1)` | [0, ∞) | SYN Flood: > 10 |
| 3 | F3 | InterArrivalTime | `mean(IAT)` giữa các packet | [0, ∞)s | Bot/Flood: < 0.001s |
| 4 | F4 | RstRatio | `bwd_RST / bwd_pkt` | [0, 1] | Port Scan: > 0.5 |
| 5 | F5 | DistinctPorts | `len(unique dst_port)` | [0, ∞) | Port Scan: > 50 |
| 6 | F6 | URLConcentration | `max_url_count / total_req` | [0, 1] | Brute Force: > 0.9 |
| 7 | F7 | HttpIatUniformity | `1 / (1 + CV(IAT_HTTP))` | (0, 1] | Bot timing: ≈ 1 |
| 8 | F8 | RequestSizeUniformity | `1 / (1 + CV(payload_sizes))` | (0, 1] | Bot payload: ≈ 1 |
| 9 | F9 | AvgPayloadSize | `sum(payload) / num_pkt` | [0, ∞)B | SYN Flood: 0 |
| 10 | F10 | FwdBwdRatio | `fwd_pkt / bwd_pkt` | [0, ∞) | Unidirectional flood: > 100 |
| 11 | F11 | PacketsPerPort | `fwd_pkt / distinct_dst_port` | [0, ∞) | Port Scan density: < 5 |
| 12 | F12 | SqlSpecialChar | tỷ lệ ký tự `' ; --` trong payload | [0, 1] | SQLi: > 0.15 |
| 13 | F13 | CrsSquliScore | OWASP CRS 942 paranoia=2 score | [0, N] | SQLi: > 3 |
| 14 | F14 | SqlUnionSelect | binary `UNION ... SELECT` detect | {0, 1} | UNION-based SQLi |
| 15 | F15 | SqlComment | binary `--` / `#` / `/**/` detect | {0, 1} | Comment injection |
| 16 | F16 | SqlStackedQuery | binary `; DROP/DELETE/...` detect | {0, 1} | Stacked SQLi |
| 17 | F17 | SqlSelectCount | `count(SELECT)` trong payload | [0, N] | SQLi chaining: > 1 |
| 18 | F18 | CrsXssScore | OWASP CRS 941 paranoia=2 score | [0, N] | XSS: > 3 |
| 19 | F19 | JsFunctionCall | binary `alert()`/`eval()`/... detect | {0, 1} | XSS JS injection |
| 20 | F20 | HtmlEventHandler | binary `onerror=`/`onload=`/... detect | {0, 1} | XSS event handler |

Source: `config/data_params.py:44` (`FEATURE_ORDER`) + 5 file calculator trong `feature/calculators/`.

### Normalize sang [0, 1]

`config/data_params.py:normalize_feature_vector(raw_vector) -> np.ndarray[20]` chuẩn hoá raw → [0, 1]:
- Clip theo `FEATURE_CLIP_BOUNDS` (ví dụ F1 cap 500 pkt/s, F13 cap 20, F18 cap 4)
- Áp log scale cho F1, F2, F3, F5, F10, F11 (`FEATURE_LOG_SCALE`)
- Min-max scale phần còn lại

AI RL agent dùng vector chuẩn hoá này làm 20D đầu tiên của 34D observation.

---

## 6. Folder `core/` — packet capture & flow management

| File | Vai trò chính |
|---|---|
| `sniffer.py` | `NetworkSniffer.start_live(iface, callback, bpf, timeout)` + `start_pcap(path, callback)`. Wrapper Scapy `sniff()` với `store=0` để tiết kiệm RAM, BPF filter `"tcp"`, timeout=20s tránh callback bị block |
| `packet_parser.py` | `PacketLayerExtractor.extract(pkt) -> LayerInfo`. `HttpPayloadExtractor` ghép composite payload (URI + User-Agent + Body) cho rule scan |
| `packet_queue.py` | Thread-safe bounded `queue.Queue(maxsize=10000)` giữa capture và analyze thread |
| `flow_manager.py` | `FlowManager.add_packet(layer)`. Quản lý flow theo 5-tuple `(src_ip, dst_ip, src_port, dst_port, proto)`, bidirectional fwd/bwd. Constants: `MAX_FLOWS=50000`, `FLOW_TIMEOUT=120s`. `slide_window_packets()` cleanup theo timestamp |
| `flow_state.py` | `FlowState`: deque fwd/bwd (`maxlen=3000`), TCP flags counts, HTTP status counts, dst_ports set. Property `analysis_window_size` để feature calculator biết kích thước cửa sổ |
| `feature_merger.py` | Legacy merger gộp network + log features. KHÔNG dùng trong realtime mode (production) |
| `crs_loader.py` | Load OWASP ModSecurity CRS rules từ root project (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`, `REQUEST-941-APPLICATION-ATTACK-XSS.conf`). Paranoia level configurable (PL2 dùng cho production) |
| `tshark_l7.py` | `TsharkL7Reader.start(keylog_file)` spawn subprocess tshark + SSLKEYLOGFILE để decrypt HTTPS. `drain_events()` trả list `(timestamp, http_uri, method, ...)`. Health check trong main loop, restart nếu chết |
| `layer_info.py` | Data class: timestamp, src/dst IP, TCP ports/flags/seq/ack, HTTP method/URI/host/UA/status, payload bytes |
| `exception.py` | Custom exceptions |

---

## 7. Folder `feature/` — plugin-based 20 features

### Architecture

```
config/data_params.py:FEATURE_ORDER (canonical 20 keys)
                    │
                    ▼
feature/base.py
  ├── FeatureMetadata          (code, name, description, category, depends_on)
  ├── FeatureBase (ABC)        — calculate(flows: List[FlowState]) -> float
  ├── FeatureRegistry          — singleton, auto-register qua decorator
  └── @register_feature(meta)  — decorator
                    │
                    ▼
feature/calculators/*.py       — import gây trigger decorator
  └── (20 class) F1_PacketRate, F2_SynAckRatio, ..., F20_HtmlEventHandler
                    │
                    ▼
feature/calculator.py
  └── FlowFeatureCalculator
        .calculate_all(flows)  -> List[float] theo FEATURE_ORDER
        .get_feature_labels()  -> ['F1 - PacketRate', ..., 'F20 - HtmlEventHandler']
```

### File calculator (5 file × 20 features)

| File | Phụ trách | Phụ thuộc |
|---|---|---|
| `network_features.py` | F1, F2, F3, F4, F5 | TCP layer (flags, ports, timestamps) |
| `application_features.py` | F6, F7, F8 | HTTP request (URI, payload size, IAT) |
| `network_features_ext.py` | F9, F10, F11 | TCP + payload size |
| `sqli_features.py` | F12, F13, F14, F15, F16, F17 | HTTP payload + CRS 942 rules |
| `xss_features.py` | F18, F19, F20 | HTTP payload + CRS 941 rules |

### Module legacy (vẫn còn nhưng không tham gia tính 20 features)

- `wamm_classifier.py` — `WammClassifier` (XGBoost payload classifier). Vẫn được khởi tạo
  trong `_run_realtime()` (`main.py:189`) cho backward compat. Nếu thiếu model file thì
  graceful degrade (return default values). Không nằm trong 20 features production.
- `_archive/` — `kruegel_features.py`, `behavioral_features.py`, `payload_features.py`,
  `context_features.py`, `sqli_features_old.py`, `xss_features_old.py`. Giữ làm reference cho
  bản 30-feature trước đây.

---

## 8. Folder `config/`

### `data_params.py` (CRITICAL)

Module trung tâm về spec 20 features. Mọi consumer (NIDS, AI RL env, infer) đều import từ đây.

| Symbol | Ý nghĩa |
|---|---|
| `WINDOW_SIZE_SECONDS = 1.0` | Window cố định. Đổi sẽ phá normalize bounds của F1, F3, F7, F8 |
| `FEATURE_ORDER: list[str]` | 20 keys canonical (`['F1', 'F2', ..., 'F20']`) — index ↔ obs vector |
| `OBS_DIM = 20` | `len(FEATURE_ORDER)` |
| `FEATURE_CLIP_BOUNDS: dict` | Per-feature clip cap (F1=500, F2=20, F10=100, F11=500, F13=20, F17=10, F18=4, ...) |
| `FEATURE_LOG_SCALE: set` | `{F1, F2, F3, F5, F10, F11}` — apply `log1p` trước scale |
| `normalize_feature_vector(raw, ...)` | Clip + log + scale → `np.ndarray[20]` ∈ [0, 1] |
| `ANONYMIZE_SRC_IP_FOR_TRAINING: bool` | Flag bỏ src_ip khi xuất training data |

### `nids_config.py`

`NIDSConfig` frozen dataclass — settings runtime:

```python
NIDSConfig(
    MAX_PACKETS_PER_FLOW = 3000,
    FLOW_TIMEOUT         = 120,     # giây
    CLEANUP_INTERVAL     = 100000,  # packets
    MAX_FLOWS            = 50000,
    MAX_QUEUE_SIZE       = 10000,
    LOG_MAX_SIZE         = 10 * 1024 * 1024,  # 10MB
)
```

Methods: `from_dict(d)`, `from_env()`, `merge(other)` để override khi cần.

### `logger_config.py`

Standard Python logging setup (handlers, format, level).

### `wamm_config.py`

WAMM model paths (TF-IDF vectorizer + XGBoost). Legacy, không dùng trong production.

---

## 9. Cách chạy

### 9.1. Chạy realtime trong môi trường Mininet (production)

`containernet/test2.py` tự gọi sniffer khi setup router namespace. Không cần thao tác thủ công.

### 9.2. Chạy standalone (debug interface khác)

```bash
sudo python3 System/main.py
# Menu → 1 (Realtime) → nhập:
#   interface (vd: eth0)
#   window_size (default 1.0)
#   output path (vd: /tmp/sniffer_output.jsonl)
#   format (jsonl / csv)
#   keylog file (optional, để decrypt HTTPS)
```

### 9.3. Chạy offline trên PCAP

```bash
sudo python3 System/main.py
# Menu → 2 (PCAP) → nhập pcap path + output path
```

### 9.4. Chạy offline trên CSV (Wireshark export)

```bash
python3 System/main.py
# Menu → 3 (CSV)
```

### 9.5. Chạy test

```bash
cd System
python3 run_tests.py            # interactive menu
# hoặc:
pytest test/                    # all
pytest -m unit                  # markers
pytest -m sqli
pytest -m kruegel
```

Markers config trong `pytest.ini`: `unit`, `sqli`, `kruegel`, `dataset`, `wamm`.

---

## 10. Folder `tools/`

| File | Mục đích | Cách chạy |
|---|---|---|
| `pcap_slicer.py` | Chia PCAP theo time hoặc số packet | `python3 pcap_slicer.py <input.pcap> --by-time 60` |
| `csv_slicer.py` | Chia Wireshark CSV theo window | `python3 csv_slicer.py <input.csv> --window 1.0` |
| `test_features_from_csv.py` | Extract 20 features từ CSV (offline test) | `python3 test_features_from_csv.py <csv>` |
| `test_features_to_json.py` | Feature extraction test với JSON output | `python3 test_features_to_json.py` |
| `wamm_train.py` | Train WAMM XGBoost classifier (legacy) | (không dùng cho production) |

---

## 11. Folder `docs/`

| File | Nội dung |
|---|---|
| `SYSTEM_ARCHITECTURE_OVERVIEW_VI.md` (49KB) | Tài liệu kiến trúc tiếng Việt: 2-layer (network + flow + feature + AI), bidirectional tracking, sliding window, breakdown 20 features, use cases |
| `API_DOCUMENTATION.md` (21KB) | Plugin API: `FeatureRegistry`, `@register_feature` decorator, hướng dẫn viết feature mới, backward compat notes |
| `2003_kruegel_vigna_ccs03.pdf` | Kruegel & Vigna 2003 — web anomaly detection (cơ sở cho `_archive/kruegel_features.py`) |
| `s41598-023-48845-4.pdf` | Scientific Reports 2023 — IDS related |
| `2512.23610v2.pdf` | arXiv 2025 — RL defense related |

---

## 12. Folder `dataset/`

- `LSNM2024 Dataset/1320981.pdf` — paper reference cho dataset LSNM2024 dùng để
  benchmark hiệu năng CRS rules (3000 normal + 2809 attack samples — note trong
  `feature/calculators/sqli_features.py`).

---

## 13. Quyết định / lưu ý quan trọng

- **`WINDOW_SIZE_SECONDS = 1.0` cố định**. Đổi sẽ phá normalize bounds của F1 (PacketRate),
  F3 (IAT), F7 (HttpIatUniformity), F8 (RequestSizeUniformity) — RL model sẽ predict sai.
- **20 features là số production**. `features_catalog.csv` (179 rows) liệt kê 64 raw + 30
  derived nhưng đó là spec lịch sử; production chỉ dùng 20 keys trong `FEATURE_ORDER`.
- **CRS-based detection (F13, F18) ưu tiên hơn ML**. Paranoia level=2, deterministic và
  explainable. Thay thế WAMM/Kruegel vì đơn giản hơn và đủ độ chính xác cho proof-of-concept.
- **Bidirectional flow tracking là bắt buộc**. F4 (server RST), F10 (Fwd/Bwd ratio) phụ thuộc
  vào việc phân biệt fwd/bwd; nếu chỉ track 1 chiều sẽ mất toàn bộ tín hiệu này.
- **HTTPS L7 enrichment optional**. Cần `SSLKEYLOGFILE` + tshark; thiếu vẫn chạy được nhưng
  F6-F8, F12-F20 sẽ thiếu data từ HTTPS flows (vì decrypt không được).
- **WAMM deprecated nhưng vẫn được init**. `WammClassifier()` ở `main.py:189` truyền vào
  `FlowFeatureCalculator` cho backward compat. Không tham gia tính 20 features production.

---

## 14. Tham khảo

- AI agent đọc output: [`../AI RL/README.md`](../AI%20RL/README.md)
- Mininet topology dùng sniffer này: [`../containernet/README.md`](../containernet/README.md)
- Architecture chi tiết: [`docs/SYSTEM_ARCHITECTURE_OVERVIEW_VI.md`](docs/SYSTEM_ARCHITECTURE_OVERVIEW_VI.md)
- Plugin API + hướng dẫn viết feature mới: [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md)
- Spec 20 features (canonical): [`config/data_params.py`](config/data_params.py)
