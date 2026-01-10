# Tài liệu kỹ thuật – Hệ thống trích xuất đặc trưng NIDS (Flow-based)

Ngày cập nhật: 2026-01-10

## 1) Mục tiêu & phạm vi
Hệ thống này thực hiện **trích xuất đặc trưng (feature extraction)** từ lưu lượng mạng để phục vụ:
- Phát hiện xâm nhập (IDS) theo thời gian thực
- Phân tích offline từ file PCAP
- Tạo dữ liệu đầu vào cho huấn luyện/đánh giá mô hình AI

Đầu ra chính là **vector 6 đặc trưng** (F1…F6) theo cửa sổ thời gian (sliding window), xuất ra CSV.

## 2) Tổng quan kiến trúc
Các module chính:
- [main.py](main.py): entrypoint CLI; hỗ trợ bắt live hoặc đọc PCAP; xuất CSV theo 2 mode.
- [main_pcap.py](main_pcap.py): phân tích PCAP theo **flow-level** và xuất CSV dạng “tương tự CICFlowMeter”.
- [core/sniffer.py](core/sniffer.py): bắt gói tin bằng Scapy (`sniff`) (live/offline).
- [core/packet_parser.py](core/packet_parser.py): parse packet → cấu trúc chuẩn hóa [core/layer_info.py](core/layer_info.py).
- [core/flow_manager.py](core/flow_manager.py): quản lý flows theo 5-tuple, theo dõi 2 chiều (forward/backward).
- [core/flow_state.py](core/flow_state.py): lưu trạng thái flow (deque packets) và API phục vụ tính feature.
- [core/processor.py](core/processor.py): orchestration `LayerInfo -> FlowManager -> FlowFeatureCalculator`.
- [feature/feature_flow.py](feature/feature_flow.py): định nghĩa 6 features dựa trên FlowState.
- [feature/payload_context.py](feature/payload_context.py): logic chấm điểm payload (F6) có anti-evasion.
- [config/ai_config.py](config/ai_config.py): “normalization contract” (thứ tự feature, ngưỡng max, hàm chuẩn hóa).

### 2.1) Luồng xử lý dữ liệu (pipeline)

```text
Scapy Packet
   │
   ▼
PacketLayerExtractor (packet_parser.py)
   │  parse 1 lần -> LayerInfo (layer_info.py)
   ▼
FlowManager (flow_manager.py)
   │  map 5-tuple + xác định direction (fwd/bwd)
   ▼
FlowState (flow_state.py)
   │  lưu deque fwd_packets / bwd_packets theo sliding window
   ▼
FlowFeatureCalculator (feature_flow.py)
   │  tính F1..F6 từ danh sách flows của 1 src_ip
   ▼
Vector [F1..F6] -> CSV
```

**Điểm thiết kế quan trọng:**
- Hệ thống dùng **bidirectional flow tracking** (tách forward/backward) để phát hiện tốt hơn các tình huống như:
  - victim trả RST về khi scan port (RST nằm ở chiều backward)
  - lỗi HTTP (4xx/5xx) thường nằm ở response (backward)
- Dữ liệu được giữ trong **sliding window** (mặc định 1s), giúp đặc trưng phản ứng nhanh và giới hạn RAM.

## 3) Mô hình dữ liệu & flow

### 3.1) LayerInfo (đơn vị “packet đã parse”)
Cấu trúc [core/layer_info.py](core/layer_info.py) chuẩn hóa dữ liệu từ Scapy, gồm:
- IP: `src_ip`, `dst_ip`, `ttl`, `protocol`, …
- TCP/UDP/ICMP: ports, flags, seq/ack, …
- Payload: `payload_bytes`, `payload_length`
- L7 (tuỳ bật/tắt): HTTP method/URI/host/user-agent/status; DNS query

Thiết kế `Optional[...]` giúp chịu lỗi tốt (packet thiếu layer / malformed).

### 3.2) Định nghĩa flow và xác định direction
Flow key là **5-tuple**:

$$(src\_ip, dst\_ip, src\_port, dst\_port, protocol)$$

Trong [core/flow_manager.py](core/flow_manager.py):
- Nếu packet match `flow_key` → cùng chiều
- Nếu packet match `reverse_key` (đảo src/dst + đảo ports) → là packet chiều ngược
- Direction xác định theo CICFlowMeter-style: so sánh `packet.src_ip` với `flow.src_ip` để quyết định **FORWARD** hay **BACKWARD**

FlowState [core/flow_state.py](core/flow_state.py) lưu:
- `fwd_packets`: packet từ src→dst
- `bwd_packets`: packet từ dst→src

### 3.3) Sliding window & cleanup
- Mỗi FlowState giữ deque tối đa 3000 packet/chiều và cleanup theo cutoff `current_time - window_size`.
- FlowManager dọn flow hết hạn theo `flow_timeout` và chạy theo `cleanup_interval`.
- Với PCAP offline, FlowManager dùng **timestamp của packet** (không dùng system time) để đảm bảo đúng theo thời gian capture.

## 4) Định nghĩa 6 đặc trưng (F1…F6)
File định nghĩa: [feature/feature_flow.py](feature/feature_flow.py)

**Thứ tự vector bắt buộc** theo [config/ai_config.py](config/ai_config.py):
`[F1, F2, F3, F4, F5, F6]`

### 4.1) Chuẩn hoá (Normalization contract)
- F1–F5 được chuẩn hoá bằng:

$$x_{norm} = clamp(\frac{x_{raw}}{MAX}, 0, 1)$$

- F6 là rời rạc theo miền giá trị:
  - `CONTEXT_SAFE = -1.0`
  - `CONTEXT_NEUTRAL = 0.0`
  - `CONTEXT_MALICIOUS = 1.0`

Ngưỡng MAX được cấu hình trong [config/ai_config.py](config/ai_config.py) (ví dụ `MAX_PACKET_RATE=3000`, `MAX_PAYLOAD_LEN=1500`).

### 4.2) F1 – Packet Rate
Ý nghĩa: cường độ traffic trong cửa sổ.

Raw:
- Tổng packets của **tất cả flows** thuộc cùng `src_ip` trong window chia cho `window_size`.

$$F1_{raw} = \frac{\sum packets}{window\_size}$$

Norm: chia `MAX_PACKET_RATE`.

### 4.3) F2 – SYN Ratio
Ý nghĩa: phát hiện SYN flood/handshake bất thường.

Raw (từ **forward packets**):

$$F2_{raw} = \frac{SYN}{SYN+ACK}$$

Norm: vì miền tự nhiên đã nằm trong [0,1], `MAX_SYN_RATIO = 1.0`.

### 4.4) F3 – Distinct Destination Ports (Inter-flow)
Ý nghĩa: phát hiện port scan (một source thử nhiều cổng).

Raw:
- Hợp các `dst_port` từ **tất cả flows** của cùng `src_ip` trong window.

$$F3_{raw} = |\{dst\_port\}|$$

Norm: chia `MAX_DISTINCT_PORTS`.

### 4.5) F4 – Payload Length (outlier-aware)
Ý nghĩa: phát hiện payload bất thường (vd buffer overflow/fuzzing) bằng thống kê payload.

Raw:
- Tính trên **forward payload lengths**.
- Nếu có outlier: `max > 3×avg` và `max > 500` bytes → trả `max`.
- Ngược lại trả `avg`.

Norm: chia `MAX_PAYLOAD_LEN`.

### 4.6) F5 – Fail Rate (bidirectional)
Ý nghĩa: phản ánh tỷ lệ “kết nối thất bại”/phản hồi lỗi.

Raw (Enhanced):
- Đếm thất bại từ **backward packets**:
  - TCP RST từ server/victim (port closed)
  - HTTP status >= 400 từ response (nếu có `http_status`)

Ghi chú:
- `http_status` chỉ có khi PacketLayerExtractor bật `enable_http_parsing=True` (xem [core/packet_parser.py](core/packet_parser.py)). Nếu tắt HTTP parsing thì F5 thực tế chỉ dựa trên RST (và các tín hiệu L4 khác nếu được bổ sung).

$$F5_{raw} = \frac{failures}{total\_packets}$$

Norm: `MAX_FAIL_RATE = 1.0`.

### 4.7) F6 – Context Score (signature-based)
Ý nghĩa: phát hiện dấu hiệu nội dung độc hại trong payload (SQLi, XSS, command injection, traversal, webshell, SSRF…).

FlowFeature6 trong [feature/feature_flow.py](feature/feature_flow.py):
- Chỉ xét flow có `dst_port` thuộc nhóm HTTP ports `{80,443,808,8443,8000}`.
- Duyệt forward payloads, gọi `score_payload(payload_bytes)`.
- Ưu tiên:
  - nếu có payload “malicious” → trả `+1.0`
  - else nếu có payload “safe upload/content-type” → trả `-1.0`
  - else → `0.0`

Payload scoring implement trong [feature/payload_context.py](feature/payload_context.py):
- Anti-evasion chính:
  - Giới hạn độ dài xử lý (DoS guard)
  - Multi-point sampling (đầu/giữa/cuối payload)
  - Heuristic padding attack (nhiều whitespace/byte lặp)
  - Normalize Unicode + URL decode/HTML unescape (giới hạn số vòng)
  - Regex patterns được compile trước

## 5) Các chế độ chạy & định dạng output

### 5.1) Live capture (real-time) – [main.py](main.py)
Chạy (Windows cần quyền Administrator và Npcap):
- `python main.py -i "Ethernet" -o output.csv`
- `python main.py -i "Wi-Fi" --mode aggregate`

Hai mode:
- `per-packet`: mỗi packet = 1 dòng CSV
- `aggregate`: gom theo cửa sổ 1s và ghi 1 dòng
  - chiến lược aggregate: **lấy MAX theo từng feature trong window** (attack thường tạo giá trị cao, tránh bị “pha loãng” nếu lấy mean)

Header trong `main.py` gồm 5-tuple + 6 feature.

Ghi chú quan trọng về “RAW vs normalized”:
- `FeatureVectorBuilder.process_layer_info()` (xem [core/processor.py](core/processor.py)) trả về vector **đã normalize** cho F1–F5, và F6 rời rạc.
- Nếu bạn cần “RAW values” thật sự để so sánh (vd CICFlowMeter), có thể chuyển sang dùng `FlowFeatureCalculator.calculate_all_raw(...)`.

Ghi chú về HTTP parsing:
- Live mode trong `realtime_capture()` khởi tạo `PacketLayerExtractor(enable_http_parsing=False, ...)`, vì vậy F5 không có nguồn `http_status` để đếm 4xx/5xx.

### 5.2) PCAP mode trong [main.py](main.py)
Chạy:
- `python main.py -p capture.pcap -o output.csv`
- `python main.py -p capture.pcap -o output.csv --mode aggregate`

Mục tiêu chính: tạo CSV nhanh cho phân tích/AI.

Ghi chú về HTTP parsing:
- PCAP mode trong `pcap_capture()` cũng đang dùng `PacketLayerExtractor(enable_http_parsing=False, ...)`, nên F5 không đếm HTTP 4xx/5xx trong output của mode này.

### 5.3) PCAP flow-level tool – [main_pcap.py](main_pcap.py)
Chạy:
- `python main_pcap.py -p attack_test.pcap -o output.csv`

Đặc điểm:
- Parse PCAP với `enable_http_parsing=True` (để lấy HTTP status cho F5)
- FlowManager được cấu hình window/timeout rất lớn để tránh cleanup trong khi đọc toàn bộ PCAP
- Xuất mỗi **flow** = 1 row, kèm các thống kê flow (duration, fwd/bwd pkts, …)

## 6) Kỹ thuật xử lý data & đánh giá (data processing techniques)

### 6.1) Làm sạch & chịu lỗi
- Bỏ qua packet lỗi/malformed trong parser.
- `LayerInfo` tự sanitize (`__post_init__`) để tránh crash do kiểu dữ liệu bất thường (flags bytes→str, payload đảm bảo bytes).

### 6.2) Kiểm soát RAM/hiệu năng
- Live sniff dùng `store=0` trong [core/sniffer.py](core/sniffer.py) để không giữ packet trong RAM.
- FlowState dùng deque giới hạn `maxlen` và sliding-window cleanup.
- Cleanup flows theo `flow_timeout` để tránh memory leak khi chạy lâu.

### 6.3) Validation/benchmark (không tạo traffic thật)
- [tools/scenario_validator.py](tools/scenario_validator.py): tạo chuỗi LayerInfo synthetic để kiểm tra phản ứng F1–F6 theo kịch bản (SYN flood, UDP flood, port scan + RST, SQLi, safe upload…).
- [tools/feature_benchmark.py](tools/feature_benchmark.py): benchmark dạng PASS/FAIL để phát hiện drift sai logic.

### 6.4) So sánh với CICFlowMeter
- [tools/compare_with_cic.py](tools/compare_with_cic.py): xuất các thống kê flow-level (flags, payload mean, counts…) để đối chiếu với CICFlowMeter.
- [tools/compare_csv_columns.py](tools/compare_csv_columns.py): so sánh headers và mapping cột.

## 7) Phụ thuộc (dependencies)
Xem [test_output/requirements.txt](test_output/requirements.txt):
- `scapy>=2.5.0`
- `numpy>=1.21.0`

## 8) Gợi ý mở rộng
- Thêm feature mới: tạo class `FlowFeatureX_*` trong [feature/feature_flow.py](feature/feature_flow.py) và thêm vào `FlowFeatureCalculator.calculators`.
- Tuning ngưỡng MAX/chuẩn hoá: chỉnh trong [config/ai_config.py](config/ai_config.py).

---

Nếu bạn muốn, mình có thể tạo thêm một bản “tài liệu báo cáo” ngắn hơn (2–3 trang) từ tài liệu kỹ thuật này (tập trung vào luồng xử lý data + giải thích 6 feature + kết quả/đánh giá).