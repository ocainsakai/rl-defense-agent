# Bug: Curl bình thường bị RateLimit (F6/F9 = 0 do tshark chưa decrypt kịp)

## Mô tả

Khi chạy curl HTTPS bình thường lần thứ 2 trở đi, NIDS ra quyết định **RateLimit** thay vì Allow.

```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk "https://192.168.10.10/" | grep -o "Tech Store"
# Lần 1: Allow ✓
# Lần 2: RateLimit ✗
```

## Nguyên nhân gốc rễ

**tshark không decrypt kịp HTTPS trong 1 số window** → các feature L7 (F6, F9) = 0.

| Feature | Lần 1 (Allow) | Lần 2 (RateLimit) |
|---|---|---|
| F1 - PacketRate | 19.0 | 19.0 |
| F6 - URLConcentration | **1.0** (tshark decrypt được) | **0.0** (chưa decrypt kịp) |
| F9 - AvgPayloadSize | **1.18** | **0.0** |

Model học pattern: **F6=0 + F9=0 + F1≈18-19 pps = noisy user** → RateLimit.

Nhưng thực tế: F6=0 có 2 nghĩa mơ hồ:
1. Traffic không có HTTP (ví dụ raw TCP scan) — bình thường là 0
2. NIDS chưa decrypt kịp HTTPS trong window đó — **missing data, không phải không có URL**

Model không phân biệt được 2 trường hợp này → false positive.

## Reproduction

```
F1=19.0, F6=0.0, F7=0.0, F8=0.0, F9=0.0  →  model: RateLimit  ✗
F1=19.0, F6=1.0, F7=0.0, F8=0.0, F9=1.18 →  model: Allow      ✓
```

Test xác nhận: model output RateLimit khi F6 < 0.3 với F1 ≈ 18-19 pps.

```python
# Threshold: F6 >= 0.3 → Allow; F6 < 0.3 → RateLimit (với F1 khoảng 15-25 pps)
for f6 in [0.0, 0.1, 0.2, 0.3, 0.4]:
    # F6=0.0 → RateLimit
    # F6=0.3 → Allow
```

## Hướng sửa (chưa implement)

### Option 1: Policy override trong `infer.py` (nhanh nhất)

Trong `predict()`, sau khi model ra quyết định, thêm rule:

```python
# Nếu không có tín hiệu tấn công nào AND F1 thấp → override về Allow
if rl_action == 1:  # RateLimit
    has_attack = (
        raw[0] > 50 or   # F1 PacketRate cao
        raw[1] > 5 or    # F2 SynAckRatio cao
        raw[5] > 0.5 or  # F6 URLConcentration (nếu có)
        max(raw[11:17]) > 0.1 or  # SQLi
        max(raw[17:20]) > 0.1     # XSS
    )
    if not has_attack and raw[0] < 30:
        rl_action = 0  # Override về Allow — benign traffic bị nhầm
```

### Option 2: Retrain với thêm noise vào benign data

Trong `MockIPBehavior._init_base_state()` cho `'benign'`:
- Thêm các sample với F6=0 (simulate window chưa decrypt)
- Đảm bảo model học được rằng F6=0 + F1 thấp + không có attack signal = benign

### Option 3: Xử lý ở NIDS sniffer

Trong `System/core/tshark_l7.py`: nếu tshark chưa decrypt kịp 1 window, điền F6 bằng giá trị từ window trước (carry-forward) thay vì để 0.

## Workaround tạm thời

Giảm `CLEAN_WINDOWS_TO_DOWNGRADE[1]` từ 5 → 2 trong `infer.py` (đã làm):
```python
1: 2,   # RateLimit: 2 consecutive clean windows (2s) — fast recovery
```
→ Nếu bị RateLimit nhầm, chỉ cần chờ ~2s là tự về Allow.

## Files liên quan

- `AI RL/infer.py` — `predict()` method, policy override section (~line 453)
- `AI RL/env_ids.py` — `MockIPBehavior._init_base_state()`, benign base_state (~line 396)
- `System/core/tshark_l7.py` — L7 feature extraction
