# Phân tích chi tiết lệch giữa báo cáo và code hiện tại

## Tổng quan
Báo cáo ghi nhận 34D observation với 3 thành phần: 20D sensor + 10D temporal + 4D effect. Tuy nhiên, có 3 điểm lệch chính giữa mô tả và implementation hiện tại.

---

## 1. Lệch điểm cao nhất: Mô tả "Bộ nhớ 10 bước" không khớp "Temporal State" thực tế

### 🔴 Vấn đề trong báo cáo

**Vị trí:** Tóm tắt (dòng 38), Mục 3.1.4 (dòng 687-689)

**Nội dung hiện tại:**
> "bộ nhớ phiên lưu lượng 10 bước gần nhất"
> "10 chiều trạng thái temporal theo IP (bộ nhớ phiên lưu lượng 10 bước gần nhất)"

**Sai lầm:**
- Mô tả hiểu nhầm "10 chiều" = "10 bước lưu trữ thô"
- Thực tế: 10D là tập hợp **các chỉ số tổng hợp**, không phải "10 timestep của vector 20D"

### ✅ Sự thật trong code

**File:** `AI RL/env_ids.py` (dòng 905-1130)

**PerIPTemporalState bao gồm 10 chiều:**

```python
# One-hot last action (4D)
last_action: int                    # → one_hot[4]

# Action persistence (1D)
action_hold_steps: int              # bộ đếm bước giữ hành động hiện tại

# Damage tracking (2D)
damage_ema: float                   # trung bình động EMA(service_damage)
damage_trend: float                 # xu hướng thay đổi ΔF24

# Session window (1D)
window_len: int                     # số bước trong cửa sổ mềm (0..15)

# Escalation evidence (1D)
escalation_score: float             # điểm bằng chứng tấn công L7 [0,1]

# Miss budget (1D)
miss_count: int                     # số lần bỏ lỡ trong cửa sổ (0..3)
```

**Công thức chuyển sang [0,1]^10 (hàm `to_obs()` dòng 1109):**

```python
one_hot = [0,0,0,0]; one_hot[last_action] = 1.0  # 4D

return one_hot + [
    min(action_hold_steps / 15.0, 1.0),           # chuẩn hóa [1D]
    min(damage_ema, 1.0),                         # EMA damage [1D]
    1.0 / (1.0 + np.exp(-10 * damage_trend)),     # sigmoid(trend) [1D]
    min(window_len / 15.0, 1.0),                  # điền cửa sổ [1D]
    min(escalation_score, 1.0),                   # điểm leo thang [1D]
    min(miss_count / 3.0, 1.0),                   # ngân sách bỏ lỡ [1D]
]  # = 10D tổng cộng
```

### 📊 So sánh

| Thành phần | Báo cáo nói | Code thực hiện | Ghi chú |
|---|---|---|---|
| Định nghĩa | "10 bước lưu trữ thô" | 10 chỉ số tổng hợp | ❌ Diễn đạt sai |
| Ý tưởng | Lịch sử one-to-one | Đặc trưng tổng quát của phiên | ✓ Đúng ý tưởng |
| Kích thước | Rõ ràng 10 bước × 1 | Rõ ràng 10 chiều nhưng khác | ❌ Nhầm lẫn |

### 🔧 Cách sửa

**Thay thế diễn đạt từ:**
> "bộ nhớ phiên lưu lượng 10 bước gần nhất"

**Thành:**
> "10 chiều trạng thái temporal per-IP gồm: mã hóa one-hot hành động gần nhất (4D), bộ đếm bước giữ hành động (1D), trung bình động và xu hướng tổn thất dịch vụ (2D), độ điền cửa sổ mềm 15 bước (1D), điểm bằng chứng leo thang (1D), ngân sách bỏ lỡ (1D)"

---

## 2. Lệch điểm trung bình: "Escalation sau 15 bước cứng" không khớp "block_ready_latched tùy điều kiện"

### 🔴 Vấn đề trong báo cáo

**Vị trí:** Tóm tắt (dòng 38), Mục 3.1.6 (dòng 727-728)

**Nội dung hiện tại:**
> "Redirect được duy trì trong cửa sổ 15 bước để tích lũy bằng chứng trước khi nâng cấp lên chặn"

**Sai lầm:**
- Mô tả như bộ đếm cứng: luôn 15 bước → Block
- Thực tế: 
  - Cửa sổ **tối đa** 15 bước
  - Block sẵn sàng **từ 12 bước** nếu bằng chứng đủ
  - Inference có thể bỏ qua (model tự quyết)

### ✅ Sự thật trong code

**File:** `AI RL/env_ids.py` (dòng 83-92)

```python
SOFT_SESSION_WINDOW = 15              # max window length
BLOCK_READY_MIN_WINDOW   = 12         # v13: 15→12 — block có thể sẵn sàng từ 12
BLOCK_READY_MIN_REDIRECT = 6
BLOCK_READY_MIN_PRESENCE = 8
BLOCK_READY_MIN_HONEYPOT = 5
```

**Hàm check latch (dòng 987-1006):**

```python
def _maybe_latch_block_ready(self, has_presence: bool):
    if not self.session_active or self.block_ready_latched:
        return
    if (
        self.window_len >= BLOCK_READY_MIN_WINDOW and     # ← 12, không phải 15!
        self.redirect_hits >= BLOCK_READY_MIN_REDIRECT and
        self.presence_hits >= BLOCK_READY_MIN_PRESENCE and
        self.honeypot_hits >= BLOCK_READY_MIN_HONEYPOT and
        self.miss_count <= MISS_BUDGET and
        has_presence and
        self.escalation_score >= ESCALATION_SCORE_BLOCK_THRESHOLD  # ← điểm >= 0.60
    ):
        self.block_ready_latched = True  # ← cờ, không bắt buộc block ngay
```

### 🎯 Inference behavior

**File:** `AI RL/infer.py` (dòng 1156-1167)

```python
# soft_guard_mode=assist: promote to Block if session evidence is complete.
# Only fires when block_ready_latched=True AND attacker still present (F23>=0.5).
if (self.soft_guard_mode == 'assist'
        and final_action < 3
        and tstate.block_ready_latched               # ← cở đã latch
        and len(effect_prev) >= 3
        and float(effect_prev[2]) >= PRESENCE_THRESHOLD):
    final_action = 3                                  # ← promote to Block
    soft_guard_promoted = True
```

**Mặc định:**
```python
self.soft_guard_mode = 'off'  # ← default: model tự quyết
```

### 📊 So sánh

| Khía cạnh | Báo cáo nói | Code thực hiện | Kết quả |
|---|---|---|---|
| Độ dài cửa sổ | "15 bước" | "15 bước max, 12 bước để block ready" | ❌ Chưa đầy đủ |
| Block ready | "nâng cấp lên chặn" | "latch cờ, chờ assist/model" | ❌ Hiểu nhầm |
| Mandatory | "bắt buộc" | "suggestion, tùy soft_guard_mode" | ❌ Hiểu sai |

### 🔧 Cách sửa

**Thay:**
> "hành động chuyển hướng được duy trì trong cửa sổ 15 bước để tích lũy bằng chứng trước khi nâng cấp lên chặn"

**Thành:**
> "phòng thủ L7 sử dụng cơ chế soft escalation: hành động Chuyển hướng tích lũy bằng chứng (Redirect hit ratio, Honeypot ratio, Presence hits, miss budget) trong cửa sổ mềm 15 bước; từ bước 12, nếu điểm leo thang ≥ 0.60 và các ngưỡng tối thiểu đạt, cờ block_ready_latched bật; việc nâng cấp thành Block tùy thuộc model hoặc soft_guard_mode=assist (hỗ trợ) nếu kẻ tấn công vẫn hoạt động"

---

## 3. Lệch điểm thấp: "34D luôn luôn" vs "v1/v2/v3 tùy model"

### 🔴 Vấn đề trong báo cáo

**Vị trị:** Mục 3.3.5 (dòng 627)

**Nội dung hiện tại:**
> "Kết quả là vector 34 chiều hoàn chỉnh trước khi đưa vào agent"

**Sai lầm:**
- Mô tả inference và training như luôn 34D
- Thực tế: 
  - Training v13 = 34D (Gymnasium env)
  - Inference v3 = 34D (PPO.predict)
  - Inference v2 = 30D (backward compat)
  - Inference v1 = 20D (legacy)

### ✅ Sự thật trong code

**Training:** `AI RL/env_ids.py` (dòng 1412-1413)

```python
self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(34,), dtype=np.float32)
```

**Inference auto-detect:** `AI RL/infer.py` (dòng 792-800)

```python
# Detect model version from observation space
obs_dim = self.model.observation_space.shape[0]
if obs_dim == 34:
    self.model_version = 'v3'
elif obs_dim == 30:
    self.model_version = 'v2'
else:
    self.model_version = 'v1'
print(f"[+] Model version: {self.model_version} ({obs_dim}D observation)")
```

**Xây dựng 34D (v3):** `AI RL/infer.py` (dòng 1126-1131)

```python
obs_34d = np.concatenate([
    obs_20d,
    np.array(temporal_10d, dtype=np.float32),
    np.array(effect_prev,  dtype=np.float32),
])
```

### 📊 So sánh

| Phiên bản | Obs chiều | Training | Inference | Hỗ trợ |
|---|---|---|---|---|
| v1 | 20D | — | ✓ có (legacy) | Backward compat |
| v2 | 30D | — | ✓ có | Backward compat |
| v3 | 34D | ✓ (Gymnasium) | ✓ (mới) | ✓ (chính thức) |

### 🔧 Cách sửa

**Thêm rõ ràng trong Mục 3.3.5:**

> "Đầu ra pipeline chuẩn hóa là vector 20 chiều [0,1]²⁰. Trong **training (Gymnasium)**, hệ thống ghép thêm 10D trạng thái temporal per-IP và 4D feedback vòng kín từ bước trước, tạo vector quan sát 34 chiều. Trong **inference**, hệ thống auto-detect phiên bản mô hình: v3 dùng 34D (20+10+4), v2 dùng 30D (20+10 - không effect), v1 dùng 20D (legacy). Điều này đảm bảo tương thích ngược với các mô hình cũ."

---

## 4. Tổng kết điểm cần sửa

| Mức độ | Mục | Hiện tại | Cần sửa |
|---|---|---|---|
| 🔴 High | 3.1.4, Tóm tắt | "10 bước lưu trữ" | Định nghĩa rõ 10 chỉ số tổng hợp |
| 🔴 High | 3.1.6, Tóm tắt | "15 bước chắc chắn block" | "12→ ready, tùy assist mode" |
| 🟡 Med | 3.3.5 | "34D luôn" | "34D training, v1/2/3 inference" |
| 🟡 Med | Tóm tắt | Điểm hành động giải thích | Thêm soft_guard_mode explanation |

---

## 5. Thứ tự ưu tiên sửa

1. **High priority:** Sửa 3 điểm lệch chính trong mục 3.1.4, 3.1.6, 3.3.5
2. **Medium:** Thêm giải thích soft_guard_mode ở Mục 4.4.1 (Đánh giá Tổng thể)
3. **Optional:** Cập nhật Tóm tắt nếu quá dài, hoặc giữ nguyên vì đã nêu "soft escalation"

