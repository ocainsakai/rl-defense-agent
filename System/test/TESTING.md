# Huong dan su dung Test Suite - RL Defense Agent

## Tong quan

Test suite gom **119 tests** trong **13 files**, su dung **pytest** voi he thong markers va fixtures.

```
System/
├── pytest.ini              # Config pytest (markers, testpaths)
├── run_tests.py            # CLI menu tuong tac
├── test/
│   ├── __init__.py
│   ├── conftest.py         # Fixtures + path setup (dung chung)
│   ├── helpers.py          # Packet builders + dataset loaders
│   ├── test_packet_parser.py
│   ├── test_flow_state.py
│   ├── test_flow_manager.py
│   ├── test_features.py
│   ├── test_full_pipeline.py
│   ├── test_behavioral_features.py
│   ├── test_sqli_simple.py
│   ├── test_sqli_detection.py
│   ├── test_sqli_analysis.py
│   ├── test_sqli_full_pipeline.py
│   ├── test_csic_dataset.py
│   ├── test_csic_full_pipeline.py
│   └── test_kruegel_features.py
└── dataset/
    ├── sqli.csv              # 4200 records (UTF-16)
    └── csic_database.csv     # 61065 records (UTF-8)
```

---

## 1. Chay nhanh

Tat ca lenh chay tu thu muc `System/`:

```bash
cd System
```

### CLI Menu (tuong tac)
```bash
python run_tests.py
```
Hien menu de chon nhom test, chon file, tim theo keyword.

### Lenh pytest truc tiep

```bash
# Chay TAT CA tests
pytest

# Verbose - hien ten tung test
pytest -v

# Verbose + hien print output
pytest -v -s

# Chay nhanh (bo qua tests can dataset CSV)
pytest -m "not dataset"
```

---

## 2. Markers - Chon nhom test

Moi test duoc gan 1 hoac nhieu markers. Dung `-m` de loc:

| Marker        | Mo ta                                      | So tests | Toc do   |
|---------------|-------------------------------------------|----------|----------|
| `unit`        | Unit tests (parser, flow, features)        | ~50      | Nhanh    |
| `integration` | Full pipeline tests                        | ~20      | Nhanh    |
| `sqli`        | SQLi detection tests                       | ~25      | Nhanh*   |
| `kruegel`     | Kruegel-Vigna anomaly models               | ~30      | Nhanh    |
| `dataset`     | Tests can file CSV (sqli.csv, csic_database.csv) | ~10 | Cham     |

(*) Mot so sqli tests co marker `dataset` nen can file CSV.

### Vi du chay theo marker

```bash
# Chi chay unit tests
pytest -v -m unit

# Chi chay SQLi tests
pytest -v -m sqli

# Chi chay Kruegel tests
pytest -v -m kruegel

# Chi chay integration tests
pytest -v -m integration

# Chi chay dataset tests (can CSV files)
pytest -v -m dataset

# Tat ca NGOAI TRU dataset (nhanh nhat)
pytest -v -m "not dataset"

# Ket hop: sqli NHUNG KHONG can dataset
pytest -v -m "sqli and not dataset"
```

---

## 3. Chay 1 file hoac 1 test cu the

```bash
# Chay 1 file
pytest test/test_packet_parser.py -v

# Chay 1 class trong file
pytest test/test_features.py::TestF11SqliKeyword -v

# Chay 1 test cu the
pytest test/test_features.py::TestF11SqliKeyword::test_union_select_detection -v

# Tim test theo ten (keyword matching)
pytest -k "sqli" -v
pytest -k "test_ip_layer" -v
pytest -k "port_scan" -v
pytest -k "kruegel and attack" -v
```

---

## 4. Output va Debug

```bash
# Hien print() output (mac dinh pytest an)
pytest -s

# Traceback day du khi test fail
pytest --tb=long

# Traceback ngan gon
pytest --tb=short

# Chi hien ten test FAIL (khong hien PASS)
pytest --tb=short -q

# Dung lai ngay khi gap test FAIL dau tien
pytest -x

# Dung lai sau 3 tests FAIL
pytest --maxfail=3

# Hien thoi gian chay tung test (tim test cham)
pytest --durations=10

# Ket hop: verbose + output + dung khi fail
pytest -v -s -x --tb=long
```

---

## 5. Chi tiet 13 file test

### Core (Unit tests - khong can dataset)

| File | Noi dung | Marker |
|------|----------|--------|
| `test_packet_parser.py` | Parse IP/TCP/UDP layers, flags, payload, timestamp | `unit` |
| `test_flow_state.py` | TCP flag counts, payload, sliding window | `unit` |
| `test_flow_manager.py` | Bidirectional flows, cleanup, port scan | `unit` |
| `test_features.py` | 14 features: SYN/ACK ratio, RST, ports, SQLi, XSS | `unit` |

### Pipeline (Integration tests - khong can dataset)

| File | Noi dung | Marker |
|------|----------|--------|
| `test_full_pipeline.py` | TCP handshake, HTTP, SQLi, port scan, UDP end-to-end | `integration` |

### SQLi Detection

| File | Noi dung | Marker | Can dataset? |
|------|----------|--------|-------------|
| `test_sqli_simple.py` | 10 attack + 5 normal payloads co dinh | `sqli` | Khong |
| `test_sqli_detection.py` | Detection rate tren sqli.csv | `sqli, dataset` | Co |
| `test_sqli_analysis.py` | Recall baseline >= 40%, phan tich missed attacks | `sqli, dataset` | Co |
| `test_sqli_full_pipeline.py` | Full pipeline metrics, recall >= 30% | `integration, sqli, dataset` | Co |

### CSIC HTTP Dataset

| File | Noi dung | Marker | Can dataset? |
|------|----------|--------|-------------|
| `test_csic_dataset.py` | PayloadContextScorer accuracy, SQLi/XSS indicators | `dataset` | Co |
| `test_csic_full_pipeline.py` | 14 features qua pipeline, SQLi/XSS detection | `integration, dataset` | Co |

### Behavioral & Kruegel

| File | Noi dung | Marker | Can dataset? |
|------|----------|--------|-------------|
| `test_behavioral_features.py` | Extract features, JSON output + test voi sqli.csv | `unit, dataset` | 1 test co |
| `test_kruegel_features.py` | 6 anomaly models + full pipeline + detection matrix | `kruegel` | Khong |

---

## 6. Fixtures co san (conftest.py)

Fixtures duoc inject tu dong vao test qua tham so. Khong can setUp():

```python
# Vi du su dung fixture
class TestMyFeature:
    def test_something(self, parser, flow_manager):
        # parser va flow_manager duoc inject tu dong
        pkt = make_tcp_packet(...)
        info = parser.extract(pkt, packet_number=0)
        flow_manager.process_packet(info)
```

| Fixture | Kieu tra ve | Mo ta |
|---------|------------|-------|
| `parser` | `PacketLayerExtractor` | Realtime timestamps |
| `parser_pcap` | `PacketLayerExtractor` | PCAP timestamps |
| `parser_http` | `PacketLayerExtractor` | HTTP parsing enabled |
| `parser_full` | `PacketLayerExtractor` | PCAP + HTTP parsing |
| `flow_manager` | `FlowManager` | window=60s, timeout=120s |
| `feature_calc` | `FlowFeatureCalculator` | Calculator instance |
| `pipeline` | `dict` | `{'parser', 'fm', 'calc'}` - full pipeline |
| `sqli_csv_path` | `str` | Path to sqli.csv (auto-skip neu khong co) |
| `csic_csv_path` | `str` | Path to csic_database.csv (auto-skip neu khong co) |

---

## 7. Helpers co san (helpers.py)

### Packet Builders

```python
from helpers import make_tcp_packet, make_udp_packet, make_http_packet

# TCP packet voi flags
pkt = make_tcp_packet(src_ip="192.168.1.1", dst_ip="10.0.0.1",
                      sport=5000, dport=80, flags="S")

# UDP packet
pkt = make_udp_packet(dport=53, payload=b"dns query")

# HTTP packet (tu dong tao GET/POST request)
pkt = make_http_packet("' OR 1=1--", method="GET")
pkt = make_http_packet("user=admin&pass=123", method="POST")

# Reconstruct tu CSIC CSV fields
from helpers import reconstruct_http_packet
pkt = reconstruct_http_packet(method="GET", url="/search?q=test", content="")
```

### Dataset Loaders

```python
from helpers import load_sqli_csv, load_csic_csv

# Load sqli.csv (UTF-16 encoded)
records = load_sqli_csv("dataset/sqli.csv")           # [(sentence, label), ...]
records = load_sqli_csv("dataset/sqli.csv", limit=100) # Chi 100 records dau

# Load CSIC dataset
records = load_csic_csv("dataset/csic_database.csv")
records = load_csic_csv("dataset/csic_database.csv", limit=200, balanced=True)
#   balanced=True: lay deu normal + attack (vi 36k normals nam truoc 25k attacks)

# CSICRecord attributes
for r in records:
    r.label       # "Normal" hoac "Anomalous"
    r.is_attack   # True/False
    r.method      # "GET" / "POST"
    r.url         # "/search?q=hello"
    r.content     # POST body
    r.get_payload()  # Extract payload tu URL + body
```

---

## 8. Viet test moi

### Template co ban

```python
import pytest
from helpers import make_tcp_packet

@pytest.mark.unit  # Chon marker phu hop
class TestMyNewFeature:
    """Mo ta nhom test."""

    def test_basic_case(self, parser, flow_manager):
        """Mo ta test case."""
        pkt = make_tcp_packet(flags="S")
        info = parser.extract(pkt, packet_number=0)
        flow_manager.process_packet(info)

        flows = flow_manager.get_all_flows()
        assert len(flows) == 1

    @pytest.mark.parametrize("payload,expected", [
        ("normal text", False),
        ("' OR 1=1--", True),
    ])
    def test_parametrized(self, payload, expected):
        """Test nhieu inputs."""
        result = detect(payload)
        assert result == expected
```

### Them dataset test

```python
@pytest.mark.dataset
class TestWithDataset:
    def test_on_sqli_csv(self, sqli_csv_path):
        from helpers import load_sqli_csv
        records = load_sqli_csv(sqli_csv_path, limit=100)
        # ... test logic
```

### Danh dau test biet truoc se fail

```python
PAYLOADS = [
    "normal attack payload",
    pytest.param("tricky payload",
                 marks=pytest.mark.xfail(reason="Pattern khong match")),
]
```

---

## 9. Ket qua hien tai

```
117 passed, 2 xfailed

SQLi Dataset (sqli.csv):     Precision 97%  |  Recall 65%  |  F1 78%
CSIC Dataset (csic_database): Precision 99%  |  Recall 15%  |  F1 26%
```

- **xfail**: 2 SQLi payloads ma he thong chua co pattern de phat hien
- **CSIC recall thap**: CSIC chua nhieu loai tan cong (path traversal, parameter tampering...) ngoai SQLi/XSS

---

## 10. Troubleshooting

| Van de | Nguyen nhan | Cach fix |
|--------|------------|----------|
| `ModuleNotFoundError` | Chay tu sai thu muc | `cd System` truoc khi chay |
| `SKIPPED` dataset tests | Thieu file CSV trong `dataset/` | Kiem tra `dataset/sqli.csv` va `dataset/csic_database.csv` |
| `_csv.Error: line contains NUL` | Doc sqli.csv bang UTF-8 | Da fix: helpers.py mac dinh dung UTF-16 |
| `No attack records` | CSIC dataset normal records nam truoc | Da fix: dung `balanced=True` |
| Tests cham | Dang chay dataset tests | Dung `-m "not dataset"` de bo qua |
