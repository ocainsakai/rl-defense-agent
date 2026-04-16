# Benchmark Methodology — CIC-IDS2018 Evaluation

> **Đối tượng đọc:** Hội đồng muốn hiểu từng bước từ file PCAP gốc tải về đến con số kết quả cuối cùng.

---

## 1. Dataset sử dụng

**CIC-IDS2018** (Canadian Institute for Cybersecurity, 2018)  
Link tải: https://www.unb.ca/cic/datasets/ids-2018.html

File sử dụng: **Thursday-22-02-2018** — chứa 3 loại tấn công thực tế:

| Tên tấn công | Thời gian (EST) | Attacker IP | Tool được dùng |
|---|---|---|---|
| Brute Force Web | 10:17 → 11:24 | 18.218.115.60 | HTTP brute force |
| Brute Force XSS | 13:50 → 14:29 | 18.218.115.60 | XSS payload injection |
| SQL Injection | 16:15 → 16:29 | 18.218.115.60 | SQLmap |

Ngoài 3 attack window trên, traffic còn lại từ các IP khác trong cùng file được coi là **benign** (tối đa 500 rows, lấy ngẫu nhiên).

---

## 2. Pipeline đầy đủ: từ PCAP đến kết quả

```
[1] File PCAP gốc (~nhiều GB, trên shared folder /mnt/hgfs)
         │
         ▼  [tshark filter]
[2] Mini PCAP (chỉ chứa traffic của attacker IP + time window ±5 phút)
         │
         ▼  [Scapy packet parsing + tshark L7 HTTP enrichment]
[3] NIDS JSONL (mỗi dòng = 1 giây traffic từ 1 IP, 20 features F1-F20)
         │
         ▼  [label_rows(): gán nhãn theo attack window]
[4] Labeled JSONL (thêm gt_label, gt_action, window_id, window_t0)
         │
         ▼  [IDSDefenseAgent.predict() — chạy PPO model]
[5] Results (thêm pred_action cho mỗi row)
         │
         ▼  [compute_metrics()]
[6] Kết quả: accuracy / recall / mitigate_rate / confusion matrix / timeline
```

---

## 3. Bước 1 — Lọc PCAP bằng tshark

**File:** `datasets/CSE-CIC-IDS2018/pcap_benchmark.py` → hàm `create_filtered_pcap()`

```python
def create_filtered_pcap(src_pcap, dst_pcap, attacker_ips, time_start, time_end):
    # Xây dựng filter tshark:
    # - Chỉ lấy packet từ/đến attacker IP
    # - Chỉ lấy trong khoảng thời gian [time_start-5min, time_end+5min]
    ip_filter  = " or ".join(f"ip.addr=={ip}" for ip in attacker_ips)
    time_filter = f"frame.time_epoch >= {time_start} and frame.time_epoch <= {time_end}"
    full_filter = f"({ip_filter}) and ({time_filter})"

    cmd = ["tshark", "-r", src_pcap, "-Y", full_filter, "-w", dst_pcap]
    subprocess.run(cmd, ...)
```

**Lý do cần bước này:** File PCAP gốc CIC-IDS2018 có kích thước hàng chục GB. Việc lọc trước giúp giảm xuống còn vài trăm MB, tăng tốc đáng kể các bước sau.

**Kết quả:** `pcap_cache/Thursday_22_02_2018_filtered.pcap`  
*(Thursday là `pcap_large=False` nên skip bước filter — dùng thẳng file gốc từ /mnt/hgfs)*

---

## 4. Bước 2 — Trích xuất 20D features bằng Scapy + tshark L7

**File:** `datasets/CSE-CIC-IDS2018/pcap_benchmark.py` → hàm `extract_nids_features()`

Pipeline trích xuất chia làm 2 phần:

### 4.1 — Tshark trích xuất HTTP events (L7)

```python
def load_tshark_http_events(pcap_file):
    # Chạy tshark offline để lấy tất cả HTTP request trong pcap:
    # - frame.time_epoch: thời điểm packet
    # - ip.src: IP nguồn
    # - tcp.srcport: port nguồn
    # - http.request.uri: URL được request
    # - http.request.line: HTTP headers (dùng để tính F8, F19, F20)
    cmd = ["tshark", "-r", pcap_file,
           "-Y", "http.request",
           "-T", "fields",
           "-e", "frame.time_epoch",
           "-e", "ip.src",
           "-e", "tcp.srcport",
           "-e", "http.request.uri",
           "-e", "http.request.line"]
    ...
```

Đây là lý do cần `SSLKEYLOGFILE` khi test live (để tshark decrypt HTTPS). Trong benchmark offline, dataset CIC-IDS2018 dùng HTTP thuần (port 80) nên không cần SSL key.

### 4.2 — Scapy đọc từng packet, tính features theo window 1 giây

```python
# Với mỗi packet trong pcap:
# - Group theo (src_ip, 1-second window)
# - Tính 20 features theo FEATURE_ORDER trong System/config/data_params.py
#
# F1  PacketRate       = số packet trong window / 1s
# F2  SynAckRatio      = (SYN count) / (ACK count + 1)
# F3  InterArrivalTime = mean(khoảng cách giữa các packet liên tiếp)
# F4  RstRatio         = (RST count) / (total packet count)
# F5  DistinctPorts    = số lượng dst_port khác nhau trong window
# F6  URLConcentration = tỉ lệ URL phổ biến nhất / tổng request (từ tshark HTTP)
# F7  HttpIatUniformity= 1 - CV(inter-request time) (từ tshark HTTP)
# F8  RequestSizeUnif  = 1 - CV(HTTP request size) (từ tshark HTTP)
# F9  AvgPayloadSize   = mean(payload bytes per packet)
# F10 FwdBwdRatio      = forward packet count / backward packet count
# F11 PacketsPerPort   = total packets / distinct dst_ports
# F12 SqlSpecialChar   = presence of ' " ; -- trong URL (từ tshark HTTP)
# F13 CrsSqliScore     = OWASP CRS SQLi anomaly score (từ tshark HTTP)
# F14 SqlUnionSelect   = UNION SELECT pattern (từ tshark HTTP)
# F15 SqlComment       = -- hoặc # comment pattern
# F16 SqlStackedQuery  = ; + next query pattern
# F17 SqlSelectCount   = SELECT COUNT pattern
# F18 CrsXssScore      = OWASP CRS XSS anomaly score (từ tshark HTTP)
# F19 JsFunctionCall   = javascript:, eval(), alert() trong URL
# F20 HtmlEventHandler = onload=, onclick=, onerror= trong URL
```

Sau bước này, mỗi dòng trong JSONL có dạng:
```json
{
  "timestamp": 1519300680.0,
  "src_ip": "18.218.115.60",
  "F1 - PacketRate": 6.0,
  "F2 - SynAckRatio": 1.0,
  "F3 - InterArrivalTime": 0.12,
  ...
  "F13 - CrsSqliScore": 6.49,
  "F18 - CrsXssScore": 2.06,
  ...
}
```

**Kết quả:** `pcap_cache/Thursday_22_02_2018_nids.jsonl` — **5.4 MB**, 6691+ rows  
*(File này được cache — không cần chạy lại nếu đã tồn tại)*

---

## 5. Bước 3 — Gán nhãn (label_rows)

**File:** `pcap_benchmark.py` → hàm `label_rows()`

```python
def label_rows(jsonl_file, attacker_ips, attack_windows, benign_cap):
    for row in jsonl:
        ts     = row["timestamp"]
        src_ip = row["src_ip"]

        if src_ip in attacker_ips:
            # Tìm attack window chứa timestamp này
            for (t_start, t_end, label, action, name) in attack_windows:
                if t_start <= ts <= t_end:
                    gt_label  = label   # "brute_force", "xss", hoặc "sqli"
                    gt_action = action  # "Redirect"
                    break
            # Nếu attacker IP nhưng ngoài window → bỏ qua (ambiguous)

        else:
            # IP không phải attacker → benign
            # Bỏ qua nếu đang trong attack window (reply traffic từ server)
            # Giới hạn tối đa benign_cap=500 rows
            gt_label  = "benign"
            gt_action = "Allow"
```

**Attack windows được định nghĩa trong code:**
```python
"windows": [
    # (t_start_epoch, t_end_epoch, label, expected_action, name)
    (1519305420, 1519309440, "brute_force", "Redirect", "Brute Force-Web"),
    (1519318200, 1519321140, "xss",         "Redirect", "Brute Force-XSS"),
    (1519326900, 1519327740, "sqli",        "Redirect", "SQL Injection"),
]
```

**Kết quả sau labeling:**
```
benign:      500 rows  (gt_action = Allow)
brute_force: 3940 rows (gt_action = Redirect)
xss:         2202 rows (gt_action = Redirect)
sqli:          49 rows (gt_action = Redirect)  ← 14 phút, ít rows
─────────────────────────────────────────────
Total:       6691 rows
```

---

## 6. Bước 4 — Chạy model (IDSDefenseAgent.predict)

**File:** `pcap_benchmark.py` → hàm `run_model_on_labeled()`

Với mỗi row đã labeled, gọi:
```python
pred_action, action_name, info = agent.predict(row)
```

Bên trong `IDSDefenseAgent.predict()` (file `AI RL/infer.py`):
```python
# 1. Parse 20 features từ JSONL keys → raw[0..19]
obs, raw = parse_nids_row(row)

# 2. Normalize: log-scale F1/F2/F3/F5/F10/F11, linear F9/F13/F17/F18, pass-through còn lại
#    (dùng FEATURE_CLIP_BOUNDS từ System/config/data_params.py)
obs = normalize_observation(raw)   # → numpy array shape (30,) = 20D NIDS + 10D temporal

# 3. PPO model predict
rl_action, _ = model.predict(obs, deterministic=True)

# 4. Policy override: nếu RL nói Block nhưng có SQLi/XSS features → đổi thành Redirect
if rl_action == 3 and (xss_score > 0.1 or sqli_score > 0.1):
    rl_action = 2  # Block → Redirect

# 5. IPStateTracker: quản lý escalation Redirect→Block sau REDIRECT_TTL_SECONDS
final_action, changed = tracker.update(src_ip, rl_action, ts, raw)
```

### 4 chế độ đánh giá (eval_mode) — Khung 3-layer

**`raw-ppo` (Layer 1)** — đo thuần túy PPO model, không có bất kỳ override hay tracker:
```python
# Không reset không cần tracker, gọi thẳng model.predict():
obs20 = parse_nids_row(row)        # 20D NIDS features
obs30 = concat([obs20, default_temporal])  # + 10D temporal mặc định (last_action=Allow, no damage)
rl_action = model.predict(obs30)   # output trực tiếp từ PPO
# KHÔNG apply safety_net.apply_safety_overrides()
# KHÔNG apply guard_tracker.update()
```
> Đây là đánh giá PPO thuần — trả lời "model học được gì nếu đứng một mình?"  
> `default_temporal` = InferenceTemporalState() mặc định: last_action=Allow, damage_ema=0, sigmoid(0)=0.5  
> Đại diện cho "IP mới, chưa có lịch sử" — model có thể không phát hiện tấn công ngay lần đầu.

**`stateless` (Layer 2)** — reset state trước mỗi predict, đánh giá AI agent per-window:
```python
# Trước mỗi predict:
agent.temporal_states.pop(src_ip, None)
agent.guard_tracker._state.pop(src_ip, None)
# → mỗi 1s window được đánh giá độc lập với state mới
# → PPO + safety_net.apply_safety_overrides() (Allow→Redirect khi F6/F13 cao)
# → KHÔNG có Redirect→Block escalation (state reset)
# → đây là số liệu thể hiện khả năng classify của AI agent hoàn chỉnh
```
> **Lưu ý:** `stateless` đo **AI agent** (PPO + safety_net override), không phải raw PPO.  
> safety_net vẫn active: nếu PPO ra Allow nhưng F13>threshold → đổi thành Redirect.  
> Trong báo cáo gọi là "AI agent accuracy" (Layer 2).

**`window-reset` (Layer 3)** — reset state tại đầu mỗi attack window:
```python
# Reset một lần duy nhất khi gặp window mới:
if (src_ip, window_id) not in seen_windows:
    agent.temporal_states.pop(src_ip, None)
    agent.guard_tracker._state.pop(src_ip, None)
    seen_windows.add((src_ip, window_id))
# → giả lập: attacker bắt đầu tấn công, hệ thống phản ứng từ t=0
# → thấy được: 0-15s Redirect, 15s+ → escalate lên Block
```

**`stateful`** — giữ state liên tục suốt toàn bộ dataset, giống production:
```python
# Không reset state. Chỉ expire_stale() khi IP im lặng >= BLOCK_IDLE_TTL
# → brute_force escalates Redirect→Block và giữ Block cho cả 67 phút
# → accuracy thấp nhưng mitigate_rate=100% vì Block vẫn là chặn được
```

---

## 7. Bước 5 — Tính metrics (compute_metrics)

```python
for row in results:
    gt   = row["gt_action"]    # Allow / Redirect / Block
    pred = row["pred_action_name"]

    # Per-class counts
    per_label[label]["total"]  += 1
    per_label[label][f"pred_{pred}"] += 1
    if pred == gt:
        per_label[label]["correct"] += 1

    # Mitigate = attacker traffic bị CẶN lại (bất kể bằng hành động nào)
    if label != "benign" and pred != "Allow":
        per_label[label]["mitigated"] += 1

# Recall = correct / total   (đúng CHÍNH XÁC action so với expected)
# Mitigate rate = mitigated / total  (bị chặn bằng BẤT KỲ hành động nào != Allow)
```

**Lý do recall thấp ở stateful/window-reset:**  
`gt_action = "Redirect"` nhưng sau khi Redirect 15-60s, system escalate lên Block → `pred = "Block"` → `pred != gt` → `correct=False`. Tuy nhiên `mitigate=True` vì Block vẫn là chặn được attacker.

---

## 8. Kết quả benchmark (Thursday-22-02-2018)

### 8.0 Tóm tắt 3-layer

```
Chạy: python3 pcap_benchmark.py --day Thursday --skip-extract --eval-mode all
```

| Layer | Benign FP | BruteForce recall | XSS recall | SQLi recall | Avg Mitigate% |
|---|---|---|---|---|---|
| **L1 Raw PPO** | 1.4% | 3.0% | 3.5% | 40.8% | 15.8% |
| **L2 AI Agent** (stateless) | 1.4% | **99.9%** | **89.3%** | **69.4%** | 86.2% |
| **L3 Window-Reset** | 1.2% | 0.3% | 0.7% | 8.2% | **100.0%** |

**Đọc bảng này:**
- L1 → L2: safety_net override cứu BruteForce từ 3%→99.9%, XSS từ 3.5%→89.3%. Đây là rule-based override hỗ trợ PPO.
- L2 → L3: Recall drop (vì Redirect escalate thành Block sau 15s), nhưng mitigate_rate tăng lên 100%.
- PPO một mình không đủ (L1=3-41% attack recall) vì thiếu accumulated temporal signal cho IP mới.

### 8.1 Layer 1 — Raw PPO

| Label | N | Recall | Mitigate% | Pred distribution |
|---|---|---|---|---|
| benign | 500 | 98.6% Allow | N/A | Allow:493, Block:2, RL:3, Redir:2 |
| brute_force | 3940 | 3.0% Redirect | 3.0% | Allow:3823, Redirect:117 |
| xss | 2202 | 3.5% Redirect | 3.5% | Allow:2124, RL:1, Redirect:77 |
| sqli | 49 | 40.8% Redirect | 40.8% | Allow:29, Redirect:20 |

**Giải thích tại sao L1 thấp:** PPO được huấn luyện với temporal state tracking — với IP chưa có lịch sử (default temporal = last_action=Allow, damage_ema=0), model không có "signal" để escalate. Đây là hành vi có chủ ý: không block IP mới mà chưa thấy pattern nguy hiểm.

### 8.2 Layer 2 — AI Agent (stateless)

| Label | N | Recall | Mitigate% | Pred distribution |
|---|---|---|---|---|
| benign | 500 | **98.6%** Allow | N/A | Allow:493, Block:2, RateLimit:3, Redirect:2 |
| brute_force | 3940 | **99.9%** Redirect | 99.9% | Redirect:3934, Allow:6 |
| xss | 2202 | **89.3%** Redirect | 89.3% | Redirect:1967, Allow:235 |
| sqli | 49 | **69.4%** Redirect | 69.4% | Redirect:34, Allow:15 |

**Override audit (stateless):**
- `safety_net_overrides = 5721 (85.5%)` — safety_net.apply_safety_overrides() đổi Allow→Redirect cho 85.5% rows (attack rows với F13/F6 cao)
- `raw_ppo_diff = 0` — raw PPO và info['rl_action'] luôn giống nhau (browse_guard không fire với HTTP PCAP data)

**Nhận xét:**
- BruteForce 99.9%: F6=0.888, F13=0.855 → safety_net nhận dạng và force Redirect
- XSS 89.3%, miss 235 rows: `_apply_benign_browse_guard()` fire khi F6≥0.95 nhưng F18≈0 (window thiếu XSS payload) → Allow nhầm
- SQLi 69.4%, n=49: một số rows có F13 dưới threshold → Allow
- Benign FP = 1.4% (7/500 rows bị Redirect/Block/RateLimit nhầm)

### 8.3 Layer 3 — Window-Reset (system response timeline)

| Label | Mitigate% | Timeline detail |
|---|---|---|
| benign | N/A | 98.8% Allow |
| brute_force | **100%** | 0-15s: Redirect:10 → 60s+: Block:3929 |
| xss | **100%** | 60-300s: Redirect:16 → 300s+: Block:2040 |
| sqli | **100%** | 60-300s: Redirect:4, Block:23 → 300s+: Block:22 |

**Nhận xét:** Mọi attacker đều bị mitigate 100% sau khi Redirect escalate lên Block. Recall thấp (Redirect→Block tính là sai vì gt=Redirect) nhưng đây là hành vi đúng theo thiết kế.

### 8.4 Stateful — production simulation (tham khảo)

| Label | Mitigate% | Nhận xét |
|---|---|---|
| benign | N/A | 98.8% Allow |
| brute_force | **100%** | Block 3929/3940 rows sau khi escalate |
| xss | **100%** | Block 2186/2202 rows |
| sqli | **100%** | Block 45/49 rows |

---

## 9. Lệnh chạy đầy đủ (reproduce từ đầu)

```bash
# Bước 0: Cài đặt
pip3 install -r "AI RL/requirements.txt"
pip3 install "numpy<2"

# Bước 1+2: Tạo NIDS JSONL từ PCAP (chỉ cần chạy 1 lần, có cache)
# Cần PCAP gốc tại /mnt/hgfs/Dataset/Thursday-22-02-2018_pcap/pcap/UCAP172.31.69.28
cd /path/to/rl-defense-agent
python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py --day Thursday

# Bước 3-6: 3-layer benchmark trên JSONL đã cache (không cần PCAP)
python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py \
  --day Thursday --skip-extract --eval-mode all

# Kết quả lưu tại:
# datasets/CSE-CIC-IDS2018/pcap_cache/benchmark_results_all_modes.json

# Hoặc chạy từng mode riêng:
python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py --day Thursday --skip-extract --eval-mode raw-ppo
python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py --day Thursday --skip-extract --eval-mode stateless
python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py --day Thursday --skip-extract --eval-mode window-reset

# Sensitivity check với benign_cap lớn hơn:
python3 datasets/CSE-CIC-IDS2018/pcap_benchmark.py \
  --day Thursday --skip-extract --eval-mode stateless --benign-cap 2000
```

**`--skip-extract`**: bỏ qua bước 1+2 (tshark filter + Scapy extract), dùng JSONL đã cache.  
Nếu không có `--skip-extract`, script sẽ chạy lại từ PCAP — cần PCAP gốc trên `/mnt/hgfs`.  
**`--eval-mode all`**: chạy L1+L2+L3 tuần tự và in 3-layer summary.  
**`--benign-cap N`**: override số benign rows tối đa (default: 500 theo config Thursday).

---

## 10. Giới hạn của benchmark hiện tại

| Giới hạn | Giải thích |
|---|---|
| Chỉ có Thursday | Brute Force + XSS + SQLi. DDoS và Port Scan chưa có (đang bổ sung từ Mininet capture) |
| L1 attack recall thấp (3-41%) | PPO học cần accumulated temporal signal; với IP mới (default temporal), model Allow để "observe" trước. Safety_net override cần thiết cho first-window detection. |
| XSS L2 miss 10.7% | `_apply_benign_browse_guard()` nhận nhầm XSS windows có F18≈0 là benign page fetch → Allow |
| SQLi chỉ 49 rows | Window 14 phút, cỡ mẫu nhỏ, số 69.4% dễ dao động, không nên kết luận mạnh |
| mitigate_rate định nghĩa rộng | pred != Allow = mitigate, bao gồm RateLimit/Redirect/Block. 100% mitigate ≠ 100% đúng action |
| Benign capped 500 rows | Sample 500/total benign. Có thể tăng lên 2000 bằng `--benign-cap 2000` |
| 1 attacker IP | Thursday chỉ có 18.218.115.60. Model detect từ feature pattern (F1-F20), không phải IP → kết quả có thể generalize |
| L3 recall thấp | Thiết kế đúng — Redirect→Block sau 15s là behavior có chủ ý. Dùng mitigate_rate, không dùng recall, để đánh giá L3 |
| Distribution shift với DDoS | Model train từ hping3-like MockIPBehavior; LOIC-HTTP có TCP handshake hoàn chỉnh → F2 khác → DDoS detection cần in-distribution test với Mininet |