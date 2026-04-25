# inspect_train.py — Q&A đầy đủ và Hướng dẫn sử dụng

> Tổng hợp các câu hỏi và giải thích về tool `inspect_train.py` + `inspect_launch.py`
> và các khái niệm RL liên quan (state, step, episode, weights update, policy distribution).
>
> Mục đích: chuẩn bị cho hội đồng phản biện. Trả lời mọi câu hỏi "AI thấy gì? quyết định ra sao?"

---

## Mục lục

1. [Tool inspect_train.py — bối cảnh & verification](#1-tool-inspect_trainpy--bối-cảnh--verification)
2. [Cách sử dụng (CLI + Launcher tương tác)](#2-cách-sử-dụng-cli--launcher-tương-tác)
3. [Khái niệm cơ bản — STATE, STEP, EPISODE](#3-khái-niệm-cơ-bản--state-step-episode)
4. [Mode ROLLOUT vs TRAIN — khác biệt cốt lõi](#4-mode-rollout-vs-train--khác-biệt-cốt-lõi)
5. [Cách chọn STEPS cho đúng tình huống](#5-cách-chọn-steps-cho-đúng-tình-huống)
6. [Cơ chế env training — IP, Type, Round-robin, Escalation](#6-cơ-chế-env-training--ip-type-round-robin-escalation)
7. [4D Effect — vì sao thường thấy [0,0,0,0]](#7-4d-effect--vì-sao-thường-thấy-0000)
8. [Update Weights là gì? — chi tiết PPO backprop](#8-update-weights-là-gì--chi-tiết-ppo-backprop)
9. [Policy distribution — vì sao mỗi state có probs khác nhau](#9-policy-distribution--vì-sao-mỗi-state-có-probs-khác-nhau)
10. [Tóm tắt nhanh — bảng quyết định](#10-tóm-tắt-nhanh--bảng-quyết-định)

---

## 1. Tool inspect_train.py — bối cảnh & verification

### 1.1 Tại sao cần tool này?

Hội đồng cần thấy **rõ ràng & xác thực** điều gì đang xảy ra bên trong vòng training của RL agent:

> Mỗi step → AI nhìn thấy obs gì → policy nghiêng về action nào → chọn action thật là gì → env trả reward bao nhiêu → next_state thay đổi ra sao.

**Vấn đề trước đây:** Không có tool nào hiển thị step-by-step rollout. `verify_rl_decision.py` chỉ show 1 quyết định cuối, `demo_live_train.py` chỉ poll trajectory cố định qua các checkpoint.

### 1.2 Cấu trúc tool

```
┌─────────────────────────────────────────────────────────────┐
│ inspect_train.py                                            │
│                                                             │
│  StepLoggerWrapper (gym.Wrapper)                            │
│    │ wrap IDSDefenseEnv                                     │
│    │ mỗi env.step() → capture (obs, action, probs,          │
│    │ reward, info, next_obs, temporal_state) → JSONL        │
│    ▼                                                        │
│  DashboardRenderer (rich.Live multi-panel)                  │
│    │ 7 ô: header / sensor 20D / temporal 10D / effect 4D /  │
│    │       policy probs / reward breakdown / next state /   │
│    │       trajectory footer                                │
│    ▼                                                        │
│  HTML Report Generator                                      │
│    │ JSONL → Chart.js dashboard (donut + line + cards)     │
│    ▼                                                        │
│  Output: AI RL/runs/inspect/{ts}_{mode}_steps.jsonl        │
│          AI RL/runs/inspect/{ts}_{mode}_report.html        │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 Verification — chứng minh KHÔNG "code trick"

Khi hội đồng hỏi "có phải bạn fake reward không?" — trả lời:

```bash
cd "AI RL"
# Bước 1: chạy inspect_train, capture JSONL
python3 inspect_train.py --mode rollout --steps 30 --no-live --seed 42

# Bước 2: replay action sequence qua raw env, so reward
python3 -c "
import json, sys
sys.path.insert(0, '.')
from env_ids import IDSDefenseEnv

recs = [json.loads(l) for l in open('runs/inspect/20260426_022426_rollout_steps.jsonl')]
actions = [r['action'] for r in recs]
expected = [r['reward'] for r in recs]

env = IDSDefenseEnv(mode='mock')
obs, _ = env.reset(seed=42)
raw = []
for a in actions:
    obs, r, d, t, _ = env.step(a)
    raw.append(float(r))
    if d or t: obs, _ = env.reset()

diff = max(abs(a-b) for a,b in zip(expected, raw))
print(f'Max diff: {diff:.2e}')
print('Match' if diff < 1e-6 else 'MISMATCH')
"
```

**Kết quả thực tế đã verify:** `Max diff: 0.00e+00` → tool dùng đúng `IDSDefenseEnv.step()`, không simulate riêng.

---

## 2. Cách sử dụng (CLI + Launcher tương tác)

### 2.1 Cách 1 — Launcher tương tác (recommended cho lần đầu)

```bash
cd "AI RL"
python3 inspect_launch.py
```

Sẽ hỏi 5 bước theo thứ tự:

| Bước | Câu hỏi | Lựa chọn |
|---|---|---|
| 1 | Mode | rollout / train |
| 2 | Checkpoint | List tất cả checkpoint có sẵn + chú thích từng cái |
| 3 | Steps | 16 / 32 / 100 / 320 / 1000 + giải thích từng option |
| 4 | Display | Live fast (120ms) / Demo speed (800ms) / Very slow (1500ms) / Headless |
| 5 | Deterministic | Argmax hay sample softmax (chỉ rollout) |

→ Hiển thị lệnh tương đương trước khi chạy. Có thể `n` để cancel và copy lệnh thủ công.

### 2.2 Cách 2 — CLI trực tiếp (khi đã quen)

```bash
# Demo trước hội đồng — chậm 800ms/step, deterministic, 30 step
python3 inspect_train.py --mode rollout --steps 30 --delay-ms 800 --deterministic

# Headless lấy HTML report
python3 inspect_train.py --mode rollout --steps 200 --no-live

# Hook training thật từ checkpoint 40k
python3 inspect_train.py --mode train --steps 4096 \
    --base-checkpoint runs/run_34d_v13/checkpoints/model_40000_steps

# Test nhanh không HTML
python3 inspect_train.py --mode rollout --steps 50 --no-html
```

### 2.3 Tham số đầy đủ

| Flag | Default | Ý nghĩa |
|---|---|---|
| `--mode` | `rollout` | `rollout` (load + step) hoặc `train` (hook PPO.learn) |
| `--checkpoint` | `model_480000_steps` | Path checkpoint cho rollout |
| `--base-checkpoint` | None | Checkpoint để fine-tune từ (cho train mode) |
| `--steps` | `100` | Số env steps capture |
| `--seed` | `42` | Env reset seed |
| `--deterministic` | False | Argmax thay vì sample softmax |
| `--delay-ms` | `120` | Delay/step để dễ đọc dashboard (ms) |
| `--no-live` | False | Skip dashboard, chỉ JSONL + HTML |
| `--no-html` | False | Skip HTML report |
| `--out-dir` | `runs/inspect` | Output directory |

### 2.4 Output

```
AI RL/runs/inspect/{timestamp}_{mode}_steps.jsonl   ← raw data, verify được
AI RL/runs/inspect/{timestamp}_{mode}_report.html   ← dashboard browser
```

Mở HTML: `xdg-open "AI RL/runs/inspect/*_report.html"` hoặc kéo thả vào browser.

---

## 3. Khái niệm cơ bản — STATE, STEP, EPISODE

### 3.1 Sơ đồ chồng lên nhau

```
┌─ EPISODE 1 (320 steps) ────────────────────────────────────────┐
│  ┌─ STEP 1 ──┐  ┌─ STEP 2 ──┐  ...  ┌─ STEP 320 ─┐             │
│  │ STATE_1   │  │ STATE_2   │       │ STATE_320  │             │
│  │ (34 số)   │  │ (34 số)   │       │  (34 số)   │             │
│  │ ↓ action  │  │ ↓ action  │       │ ↓ action   │             │
│  │ ↓ reward  │  │ ↓ reward  │       │ ↓ reward   │             │
│  └───────────┘  └───────────┘       └────────────┘             │
│  done=False     done=False    ...   done=TRUE                  │
└────────────────────────────────────────────────────────────────┘
                          ↓ env.reset()
┌─ EPISODE 2 (320 steps) — tất cả state về [0,0,...] ────────────┐
```

### 3.2 STATE (= observation)

**Là 34 con số AI nhìn thấy tại 1 thời điểm.**

```python
state = obs = np.array([
    0.12, 0.05, 0.04, ...,  # 20D sensor features (F1-F20)
    0.00, 0.00, 1.00, ...,  # 10D temporal state
    0.00, 0.00, 0.00, 0.00  # 4D effect_{t-1}
])
```

State = **snapshot bộ nhớ env tại 1 thời điểm**. AI nhìn vào → quyết định.

### 3.3 STEP

**Là 1 lần tương tác:** `obs → action → reward → next_obs`.

```python
state = env.get_obs()
action = model.predict(state)
next_state, reward, done, ... = env.step(action)
```

→ 1 step = 1 dòng JSONL. 1 step = 1 panel dashboard.

### 3.4 EPISODE

**Là 1 chu kỳ training trọn vẹn.** Bắt đầu bằng `env.reset()`, kết thúc khi `done=True` (sau 320 step).

Khi episode kết thúc:
- env reset toàn bộ state → state mới = `[0, 0, ..., 0]`
- temporal state các IP reset về 0
- cumulative_damage reset về 0

### 3.5 Bảng so sánh

| Khái niệm | Là gì | Đo bằng | Ví dụ |
|---|---|---|---|
| **STATE** | Vector số AI nhìn | 34 floats | `[0.12, 0.05, ..., 0.0]` |
| **STEP** | 1 lần tương tác | 1 đơn vị thời gian | step=47 trong 200 |
| **EPISODE** | 1 chu kỳ trọn vẹn | 320 steps | episode=2/3 |

### 3.6 Analogy thực tế (cờ vua)

| Game vs AI | RL training |
|---|---|
| 1 ván cờ từ khai cuộc → tàn cuộc | **1 EPISODE** |
| 1 lượt đi (1 nước) | **1 STEP** |
| Vị trí bàn cờ tại lượt đó | **1 STATE** |
| Nước đi AI chọn | **1 ACTION** |
| Điểm AI nhận | **1 REWARD** |

### 3.7 Tìm thấy ở đâu trong tool?

JSONL record:
```json
{
  "episode": 0,           ← episode thứ mấy (0-indexed)
  "step_in_ep": 47,       ← step thứ mấy TRONG episode (0-319)
  "global_step": 47,      ← step thứ mấy TỪ ĐẦU run
  "obs_prev": [0.12, ...] ← STATE trước action (34 số)
  "obs_next": [0.15, ...] ← STATE sau action (34 số)
  "action": 2,            ← AI chọn Redirect
  "reward": 0.36,
  "done": false
}
```

Dashboard:
- Header: `Episode 1 | Step 48/320`
- 3 panel OBSERVATION: STATE chia 3 phần (sensor / temporal / effect)
- Panel POLICY: AI nhìn STATE → ra probs → chọn ACTION
- Panel REWARD: env phản hồi
- Panel NEXT STATE: thông tin next_state

---

## 4. Mode ROLLOUT vs TRAIN — khác biệt cốt lõi

### 4.1 Khác biệt CỐT LÕI (1 điều quan trọng nhất)

| | rollout | train |
|---|---|---|
| **Update weights?** | ❌ KHÔNG | ✓ CÓ (mỗi 2048 step → 96 lần update) |

Cả hai đều: load env → reset → loop step → log. **Cùng** `IDSDefenseEnv`, **cùng** `step()`, **cùng** features, **cùng** reward formula. **Bối cảnh AI thấy là y hệt.**

### 4.2 Rollout (mode đọc-only)

```
Load checkpoint → env.step() N lần → log
                                    ↑ KHÔNG có gradient update
```

- **Model FREEZE** — weights không thay đổi
- Chỉ để **xem model đã train ra quyết định ra sao** trên scenario mock
- Nhanh: 100 steps ~10s, 1000 steps ~90s
- Deterministic được: cùng seed → cùng kết quả

### 4.3 Train (mode học thật)

```
Load (hoặc init) PPO → env.step() N lần → buffer đầy 2048 → BACKPROP → update weights
                                                            ↑ gradient update thật
```

- **Model THAY ĐỔI** — weights được update qua PPO loss
- Mỗi 2048 step (rollout buffer SB3): pause → tính advantage → backprop 6 epoch → resume
- Chậm: 500 steps ~30-60s
- Stochastic bắt buộc: PPO cần entropy để explore
- **Lưu ý:** `--steps < 2048` thì PPO **không update lần nào** (chưa đủ buffer)

### 4.4 3 hệ quả phụ (đến từ việc có/không update)

#### Hệ quả 1: Rollout deterministic được, train không

```
rollout: weights frozen → cùng seed → cùng kết quả luôn
train:   weights thay đổi mỗi 2048 step → khác nhau giữa các lần chạy
```

→ Demo cần reproducible: dùng **rollout + --deterministic**.

#### Hệ quả 2: Rollout policy tĩnh, train policy chạy đua với chính nó

Trong rollout 200 step:
```
Step 1:   probs(sqli) = {Allow:0.05, Redirect:0.78, Block:0.05, ...}
Step 100: probs(sqli) = {Allow:0.05, Redirect:0.78, Block:0.05, ...}  ← y hệt
Step 200: probs(sqli) = {Allow:0.05, Redirect:0.78, Block:0.05, ...}  ← y hệt
```

Trong train 2500 step:
```
Step 1-2047:    rollout, probs cố định
Step 2048:      PPO update 96 lần → weights thay đổi
Step 2049-4095: rollout với policy MỚI, probs khác step 1
              → {Allow:0.03, Redirect:0.82, Block:0.07, ...}
```

#### Hệ quả 3: Tốc độ khác hẳn

| Mode | 100 steps | 500 steps | 4000 steps |
|---|---|---|---|
| rollout | ~10s | ~40s | ~5 phút |
| train (n_envs=1) | ~30s | ~60s | ~3-5 phút |

### 4.5 Bảng tổng so sánh

| Khía cạnh | rollout | train |
|---|---|---|
| Env step() | ✓ | ✓ (giống nhau) |
| AI nhìn obs 34D | ✓ | ✓ (giống nhau) |
| AI quyết action | ✓ | ✓ (giống nhau) |
| Env trả reward | ✓ | ✓ (giống nhau) |
| Log JSONL | ✓ | ✓ (giống nhau) |
| Dashboard render | ✓ | ✓ (giống nhau) |
| **Update weights** | ❌ | ✓ |
| Deterministic được | ✓ | ❌ |
| Probs evolve theo thời gian | ❌ | ✓ |
| Tốc độ | Nhanh | Chậm |

### 4.6 Khi nào dùng cái nào?

**Rollout (90% trường hợp):**
- "AI đã train rồi quyết định ra sao trên scenario này?"
- Demo trước hội đồng (cần deterministic, nhanh)
- So sánh nhiều checkpoint
- Sinh HTML report

**Train (10% trường hợp, hiếm):**
- "Tôi muốn show AI ĐANG học từ rollout buffer"
- Cần `--steps ≥ 4096` mới thấy ≥1 update thật
- Demo "policy evolve qua thời gian"

### 4.7 Tóm 1 câu

> **Rollout = "show model đã có". Train = "show model đang học". Còn lại — env, obs, reward, log — y hệt nhau.**

---

## 5. Cách chọn STEPS cho đúng tình huống

### 5.1 Bảng quyết định

| Mục tiêu demo | Steps cần | Lý do |
|---|---|---|
| Show 16 IP types khác nhau | **16** | 1 cycle đầy đủ — thấy hết Allow/Rate/Redirect/Block trên các IP type |
| Show effect 4D ≠ 0 | **≥17** | Cycle 1 luôn `effect_prev=[0,0,0,0]`. Từ cycle 2 mới có feedback |
| Show temporal state tích lũy | **≥48** | Cần ≥3 cycle để `redirect_hits` lên ≥3, escalation_score>0 |
| Show Redirect → Block escalation | **≥200** | Cần ~12 visit/IP để `block_ready_latched=True` |
| Show 1 episode đầy đủ | **320** | Đúng `episode_length` — escalate đến cuối, rồi reset |
| Show 2 episode (reset boundary) | **640** | Có 1 lần `done=True` ở step 320, temporal reset về 0 |
| Demo nhanh trước hội đồng | **30-50** | Đủ thấy diversity 16 IPs + bắt đầu cycle 2 |
| Show pattern Block xảy ra thật | **≥250** | Block cần block_ready latched, latch sau cycle ~12 |
| Capture cho HTML report scrollable | **100-200** | HTML render cap 200 step cards |

### 5.2 Logic chọn nhanh

| Câu hỏi | Steps |
|---|---|
| "Tôi chỉ muốn thấy AI quyết định gì trên 16 type" | **16-30** |
| "Tôi muốn thấy effect 4D phản hồi" | **32-50** |
| "Tôi muốn thấy escalation Redirect→Block" | **200-320** |
| "Tôi muốn thấy episode reset (về [0,0,0,0])" | **640+** |
| "Tôi muốn analytics đầy đủ qua HTML" | **200 + headless** |

### 5.3 Quy tắc step → time

| Mode | Steps | Wall time (CPU) |
|---|---|---|
| rollout | 30 | ~3s |
| rollout | 100 | ~8s |
| rollout | 320 | ~25s |
| rollout | 1000 | ~75s |
| train | 100 | ~30s (chưa update — buffer chưa đầy 2048) |
| train | 2048+ | ~90s + (mỗi 2048 = 1 update batch) |

### 5.4 Kịch bản chọn cho 3 tình huống thực tế

#### Tình huống A: "Show AI thấy gì khi gặp sqli"
```
mode: rollout | ckpt: 480k | steps: 16 | display: demo speed (800ms) | deterministic: yes
```

#### Tình huống B: "Show escalation Redirect→Block hoạt động"
```
mode: rollout | ckpt: 480k | steps: 320 | display: fast (120ms) | deterministic: no
```

#### Tình huống C: "Show AI đang HỌC từ rollout"
```
mode: train | ckpt: 40k (early, chưa hội tụ) | steps: 4096 | display: fast
```

---

## 6. Cơ chế env training — IP, Type, Round-robin, Escalation

### 6.1 Câu hỏi cốt: AI học escalation bằng cách nào?

> Ban đầu là benign rồi noisy từ từ redirect rồi block — quan trọng là từng giai đoạn đó là nó thuộc cái kiểu tấn công đó luôn hay lấy feature từ benign rồi đổi IP?

**Trả lời ngắn:** Mỗi IP có **type cố định vĩnh viễn**. AI học escalation qua **2 layer**:
- Layer 1: **Cross-IP** — học mapping {feature pattern → action} qua 16 IP khác type
- Layer 2: **Intra-IP** — học timing chuyển phase Redirect→Block qua nhiều visits cùng 1 IP

### 6.2 Round-robin 16 IP cố định

```python
# env_ids.py:1464-1483
ip_list = [
  192.168.1.10 (benign), ..., 192.168.1.15 (benign),  # 4 benign
  192.168.1.13, 192.168.1.14 (noisy_normal),          # 2 noisy
  10.0.0.100   (scan),                                # 1 scan
  10.0.0.102   (syn_flood),                           # 1 syn_flood
  10.0.0.103, 10.0.0.107 (brute_force),               # 2 brute_force
  10.0.0.104, 10.0.0.108 (brute_force_ka),            # 2 brute_force_ka
  10.0.0.105, 10.0.0.109 (sqli),                      # 2 sqli
  10.0.0.106, 10.0.0.110 (xss),                       # 2 xss
]
```

**Mỗi IP có type cố định trong suốt episode.** IP `10.0.0.105` LUÔN sinh feature SQLi (F12-F17 cao), không bao giờ "đổi sang benign".

### 6.3 Step cycling

Default `session_block_size=0` → mỗi step model thấy 1 IP khác nhau theo round-robin:

```
Step 1: 192.168.1.10 (benign)    → F1=15, F18=0      → chọn Allow
Step 2: 192.168.1.11 (benign)    → ...                → chọn Allow
...
Step 8: 10.0.0.105 (sqli)         → F13=8.2, F14=1   → chọn Redirect
Step 16: 10.0.0.110 (xss)         → quay lại đầu
Step 17: 192.168.1.10 (benign)    → cycle 2 bắt đầu
...
Step 320 (episode end): reset toàn bộ temporal state
```

### 6.4 Layer 1: Học action cho TYPE (cross-IP)

Mỗi IP cố định 1 type → 16 IP = 8 traffic types khác nhau:

```
Step 1-4   benign IPs    → học "F1 thấp + F18=0 → Allow"
Step 5-6   noisy IPs     → học "F5 cao + payload nhỏ → RateLimit"
Step 7-8   scan/syn      → học "F2 cao + F5 cao → Block"
Step 9-12  brute IPs     → học "F6=1 + F7 cao → Redirect"
Step 13-14 sqli IPs      → học "F13>5 + F14=1 → Redirect"
Step 15-16 xss IPs       → học "F18>2 + F19=1 → Redirect"
```

→ Model học mapping `{feature pattern → action}` bằng cách thấy nhiều IP khác type liên tiếp.

### 6.5 Layer 2: Học ESCALATION (intra-IP, qua nhiều visit)

Riêng 1 IP cùng type, qua 20 visits trong episode, học Redirect → Block:

```
IP 10.0.0.105 (sqli):
  Visit 1-11: Redirect → reward dương vừa, temporal tích lũy
  Visit 12+:  block_ready_latched=True
              ├─ vẫn Redirect → reward -0.35 (phạt vì không leo thang)
              └─ chuyển Block → reward +0.45 (thưởng vì timing đúng)
```

→ Model học timing chuyển phase qua repeated visits.

### 6.6 AI hoàn toàn KHÔNG biết IP

Observation 34D không chứa IP, không có hash IP, không có index IP — chỉ có:

```
[0..19]   20D sensor features  ← features từ MockIPBehavior
[20..29]  10D temporal state    ← per-IP nhưng đưa vào obs là vector số
[30..33]  4D effect_t-1         ← post-action feedback
```

→ AI chỉ thấy **34 con số**. Không biết "tôi đang xử lý IP nào".

**Hệ quả:** Cùng pattern feature → cùng decision, bất kể IP. Nếu thay 16 IP bằng 16 ID khác hoàn toàn — model train ra y hệt, vì obs không thay đổi.

### 6.7 IP chỉ tồn tại trong env

| Khái niệm | Vai trò |
|---|---|
| IP | Identifier env để route feature + temporal — **AI không thấy** |
| ip_type | Quyết định MockIPBehavior nào sinh feature — **AI không thấy trực tiếp** |
| 20D sensor | **AI nhìn**, learn pattern → action |
| 10D temporal | **AI nhìn**, learn timing escalation |
| 4D effect | **AI nhìn**, learn closed-loop response |

→ Bản chất AI là **pattern recognizer trên 34D vector**. IP chỉ là cấu trúc nội bộ.

### 6.8 Demo trajectory KHÔNG đại diện training

`demo_xss_finetune.py` / `demo_live_train.py` có constructed trajectory:

```python
SCRIPT = (
    [(0, beh_benign, 'benign')] * 5  +    # t01-05: dùng MockIPBehavior('benign')
    [(1, beh_noisy,  'noisy')]  * 3  +    # t06-08: dùng MockIPBehavior('noisy_normal')
    [(0, beh_xss,    'start')]  * 1  +    # t09:    DỔI sang MockIPBehavior('xss')
    [(2, beh_xss,    'redirect')] * 12 +  # t10-21: vẫn xss
    [(3, beh_xss,    'block')]  * 1       # t22:    xss + Block
)
```

**Đây KHÔNG phải training data.** Đây là **kịch bản nhân tạo** chỉ dùng để VISUALIZATION — show model "đoán đúng phase chưa". IP **không đổi** nhưng `behavior` được swap thủ công để mô phỏng kịch bản "attacker giả vờ bình thường rồi tấn công".

Training thật dùng round-robin 16 IP fixed-type với leo thang per-IP qua 20 visits.

---

## 7. 4D Effect — vì sao thường thấy [0,0,0,0]

### 7.1 Có 3 lý do hợp lệ

#### Lý do 1: First visit của IP trong episode (phổ biến nhất)

`effect_prev` trong obs là **effect_{t-1}** — kết quả từ lần visit TRƯỚC của IP đó. Khi IP được visit LẦN ĐẦU trong episode, chưa có lần trước → init = `[0, 0, 0, 0]`.

**Round-robin 16 IPs → cycle 1 (steps 1-16) tất cả đều là first visit → effect_prev = [0,0,0,0] cho cả 16 IP.**

```
Step 1  IP=192.168.1.10 visit 1 → effect_prev=[0,0,0,0]
Step 2  IP=192.168.1.11 visit 1 → effect_prev=[0,0,0,0]
...
Step 16 IP=10.0.0.110   visit 1 → effect_prev=[0,0,0,0]
Step 17 IP=192.168.1.10 visit 2 → effect_prev=[0.92, 0.03, 1.0, 0.10]  ← từ step 1
Step 18 IP=192.168.1.11 visit 2 → effect_prev=[...]
...
```

→ Nếu chạy `--steps 16` thì **tất cả đều thấy [0,0,0,0]**, đúng theo logic env.

#### Lý do 2: Episode mới reset

Mỗi 320 steps, env tự reset → `ip_effect_state` reset về `[0,0,0,0]`:

```python
# env_ids.py:1537-1539
self.ip_effect_state = {
    ip: [0.0, 0.0, 0.0, 0.0] for ip in self.ip_list
}
```

#### Lý do 3: Action trước đó là Block

Block làm iptables DROP toàn bộ → simulate_effect trả `[0, 0, 0, 0]`:

```python
# env_ids.py:1169-1170
else:              # Block — iptables DROP, nginx sees nothing
    f21 = 0.0; f22 = 0.0; f23 = 0.0
f24 = ... f23 ... → = 0
```

→ Nếu model Block IP ở visit N, thì visit N+1 effect_prev = `[0,0,0,0]`.

### 7.2 Cách verify

```bash
cd "AI RL"
python3 inspect_train.py --mode rollout --steps 50 --no-live --seed 42
python3 -c "
import json, os
recs = [json.loads(l) for l in open('runs/inspect/'+sorted(os.listdir('runs/inspect'))[-2])]
for r in recs:
    e = r['effect_prev']
    nonzero = '★' if any(v > 0 for v in e) else ' '
    print(f'{nonzero} step={r[\"global_step\"]+1:3d} IP={r[\"acting_ip\"]:18s} ({r[\"acting_ip_type\"]:12s}) action={r[\"action_name\"]:9s} effect_prev={[round(v,2) for v in e]}')
"
```

Sẽ thấy: 16 step đầu toàn `[0,0,0,0]`, sau đó star (`★`) bắt đầu xuất hiện.

### 7.3 Kết luận

Không phải bug. Effect 4D **chỉ có ý nghĩa từ visit thứ 2 trở đi** — đó là điểm "delayed closed-loop feedback" mà env design.

---

## 8. Update Weights là gì? — chi tiết PPO backprop

### 8.1 "Update weights" = thay đổi các con số bên trong neural network

PPO không chỉ "tăng tỷ lệ Redirect, giảm tỷ lệ Allow". Nó update **toàn bộ ma trận trọng số** của 2 neural network.

### 8.2 Cấu trúc weights của PPO model

```
Policy Network (actor) — quyết định action:
  obs(34D) → Linear(34→256) → ReLU → Linear(256→128) → ReLU → Linear(128→4) → softmax → probs(4)
                  ↑                       ↑                        ↑
              W1: 34×256             W2: 256×128             W3: 128×4

Value Network (critic) — ước lượng V(state):
  obs(34D) → Linear(34→256) → ReLU → Linear(256→256) → ReLU → Linear(256→128) → ReLU → Linear(128→1)
```

**Tổng số weights** ≈ 8,704 (policy) + 100,225 (value) = **~108k floating point numbers**.

→ "Update weights" = thay đổi đồng thời ~108k con số này theo gradient.

### 8.3 Chu kỳ rollout → backprop của PPO

#### Bước 1: Rollout (collect trajectories)

```python
for step in range(2048):           # n_steps = rollout buffer size
    obs_t                          # state hiện tại
    probs_t = π(obs_t; W)          # policy forward pass
    a_t = sample(probs_t)          # sample action
    V_t = V(obs_t; W')             # value forward pass
    obs_{t+1}, r_t = env.step(a_t)
    buffer.append((obs_t, a_t, log_prob_t, V_t, r_t))
```

#### Bước 2: Compute advantages (GAE)

```
A_t = r_t + γ·V(s_{t+1}) - V(s_t)              # 1-step TD error
GAE_t = A_t + γλ·A_{t+1} + (γλ)²·A_{t+2} + ... # weighted sum
returns_t = GAE_t + V(s_t)                      # target cho value network
```

- `A_t > 0` → action `a_t` tốt hơn average → **tăng** xác suất `π(a_t|s_t)`
- `A_t < 0` → action `a_t` xấu hơn average → **giảm** xác suất `π(a_t|s_t)`

#### Bước 3: Backprop — đây là chỗ "update weights" thật sự

PPO loss có 3 thành phần:

```
L_total = L_policy + c1 · L_value - c2 · L_entropy
```

**L_policy (clipped surrogate):**
```
ratio_t = π_new(a_t|s_t) / π_old(a_t|s_t)
L_policy = -min(ratio_t · A_t, clip(ratio_t, 1-0.15, 1+0.15) · A_t)
```

→ Mục tiêu: tăng probs action tốt, giảm probs action xấu, **không quá 15%** mỗi update.

**L_value (critic):**
```
L_value = (V_new(s_t) - returns_t)²
```

**L_entropy:**
```
L_entropy = -Σ_a π(a|s) · log π(a|s)
```

→ Khuyến khích policy giữ random để tiếp tục explore.

#### Bước 4: Gradient descent

```python
∇L = backward()                    # PyTorch tính gradient cho 108k weights
W ← W - lr · ∇L                    # gradient descent, lr=3e-4
```

PPO làm bước 3-4 **6 lần** (`n_epochs=6`) trên cùng 2048 mẫu, mỗi epoch chia mini-batch 128 mẫu.

→ **Tổng:** mỗi rollout 2048 step → 6 epoch × (2048/128) = **96 lần update** weights.

### 8.4 Hệ quả thực tế lên policy

Sau 1 batch update (96 gradient steps):

```
TRƯỚC update:
  obs sqli → π(Allow)=0.3, π(RateLimit)=0.4, π(Redirect)=0.25, π(Block)=0.05

Trong rollout: model chọn Redirect → reward +0.5 → A>0
              model chọn Allow → reward -0.4 → A<0

SAU update:
  obs sqli → π(Allow)=0.20, π(RateLimit)=0.35, π(Redirect)=0.40, π(Block)=0.05
                  ↓ giảm                              ↑ tăng
```

**Quan trọng:** Update **state-dependent**. Cùng `obs sqli` → giờ ra probs khác. Cùng `obs benign` → có thể không thay đổi gì nếu reward đã tốt.

### 8.5 Tóm tắt

| Câu hỏi | Trả lời |
|---|---|
| Update weights là gì? | Thay đổi ~108k floating point bên trong 2 NN (actor + critic) |
| Update theo cách gì? | Gradient descent: `W ← W - lr · ∇L` |
| Có phải tăng/giảm tỷ lệ action chung không? | **Không.** Update **state-dependent** |
| Update bao nhiêu lần mỗi rollout? | 96 lần (6 epoch × 16 mini-batch / rollout 2048 step) |
| Hệ quả lên policy? | Mapping obs→probs **thay đổi cho từng state cụ thể** |

---

## 9. Policy distribution — vì sao mỗi state có probs khác nhau

### 9.1 Bản chất của policy

Policy là **function** `π: obs → probs`. Mỗi obs khác → đi qua neural network → ra probs khác.

Khác hẳn classifier kiểu "70% ảnh là mèo" — policy là **state-dependent mapping**.

### 9.2 Ví dụ cụ thể (từ JSONL của tool)

Cùng 1 model 480k, không update weights, qua các state khác nhau:

```
STATE A — IP benign, F1=0.05, F18=0, no temporal
  obs = [0.05, 0.0, ..., 0.0]
  probs = {Allow: 0.87, RateLimit: 0.07, Redirect: 0.05, Block: 0.01}
  ← AI thấy clean traffic → confident Allow

STATE B — IP noisy, F5=0.4, F11=0.3, no temporal
  obs = [0.12, 0.0, ..., 0.4, 0.3, ..., 0.0]
  probs = {Allow: 0.10, RateLimit: 0.78, Redirect: 0.12, Block: 0.00}
  ← AI thấy noisy → RateLimit

STATE C — IP sqli, F13=0.41, F14=1.0, no temporal
  obs = [0.20, ..., 0.41, 1.0, ..., 0.0]
  probs = {Allow: 0.05, RateLimit: 0.10, Redirect: 0.78, Block: 0.07}
  ← AI thấy sqli signature → Redirect

STATE D — IP sqli (giống C) + temporal: redirect_hits=12, escalation=0.85
  obs = [0.20, ..., 0.41, 1.0, ..., 1.0 (block_ready), ...]
  probs = {Allow: 0.02, RateLimit: 0.05, Redirect: 0.18, Block: 0.75}
  ← AI thấy sqli + đã saturated → switch sang Block
```

→ **4 state khác nhau → 4 phân bố probs khác hoàn toàn.** Cùng 1 model, không cần update weights.

### 9.3 Vì sao có hiện tượng này?

Policy network là **function** của obs:

```
obs (34 số) → Linear → ReLU → Linear → ReLU → Linear → softmax → probs (4 số)
```

Mỗi obs đi vào ra logits khác → softmax cho probs khác. Bản chất là **bảng tra liên tục** với input là 34D vector.

**Không có "xác suất phân bố tổng" của policy.** Phân bố probs **tồn tại trên từng state cụ thể**, không phải tổng quát.

### 9.4 Hệ quả

- Cùng obs → cùng probs (deterministic function nếu không có dropout)
- Khác obs → có thể ra probs hoàn toàn khác
- 1 model = 1 hàm `obs → probs`, không phải 1 phân bố cố định
- Ví dụ trên A,B,C,D đến từ cùng 1 model — chỉ khác state đầu vào

---

## 10. Tóm tắt nhanh — bảng quyết định

### 10.1 Cheat sheet sử dụng

| Tình huống | Lệnh |
|---|---|
| Lần đầu chạy, không nhớ flag | `python3 inspect_launch.py` |
| Demo "AI quyết định ra sao" trước hội đồng | `python3 inspect_train.py --mode rollout --steps 30 --delay-ms 800 --deterministic` |
| Show escalation Redirect→Block | `python3 inspect_train.py --mode rollout --steps 320` |
| Show effect 4D ≠ 0 | `python3 inspect_train.py --mode rollout --steps 50` |
| Chỉ lấy HTML report | `python3 inspect_train.py --mode rollout --steps 200 --no-live` |
| Show AI đang HỌC | `python3 inspect_train.py --mode train --steps 4096 --base-checkpoint runs/run_34d_v13/checkpoints/model_40000_steps` |
| Verify không "code trick" | Chạy rollout → so reward total với raw env (script ở section 1.3) |

### 10.2 Cheat sheet khái niệm

| Câu hỏi | Trả lời 1 dòng |
|---|---|
| State là gì? | 34 con số AI nhìn = 20D sensor + 10D temporal + 4D effect |
| Step là gì? | 1 lần `obs → action → reward → next_obs` |
| Episode là gì? | 1 chu kỳ trọn vẹn 320 step, kết thúc bằng `done=True` + `env.reset()` |
| Rollout vs Train? | Rollout không update weights, train có (mỗi 2048 step) |
| Update weights là gì? | Thay đổi ~108k số trong 2 NN qua gradient descent |
| Có phải tăng/giảm tỷ lệ action chung? | Không, update **state-dependent** |
| Mỗi state có probs khác? | Có, vì policy là function `obs → probs` |
| AI có biết IP không? | Không. AI chỉ thấy 34D obs, IP là khái niệm env nội bộ |
| Mỗi IP có đa năng không? | Không. Mỗi IP có type cố định vĩnh viễn |
| Vì sao effect 4D thường = [0,0,0,0]? | Cycle 1, episode reset, hoặc action trước = Block |

### 10.3 Phản biện hội đồng + cách trả lời

| Câu hỏi hội đồng | Trả lời |
|---|---|
| "AI thấy gì?" | Mở dashboard/HTML, panel OBSERVATION 3 phần (sensor/temporal/effect) |
| "Có phải fake reward?" | Verify: replay actions từ JSONL qua raw env → max diff = 0.00e+00 |
| "Reward có đầy đủ không?" | 4 component: action_bonus, action_cost, service_damage, shaping_other (đã exposed trong info dict) |
| "Mỗi step capture đúng env không?" | Cùng `IDSDefenseEnv.step()` của training, không simulate riêng |
| "Có thể reproduce kết quả không?" | Có, dùng `--mode rollout --deterministic --seed 42` |
| "Khác gì với verify_rl_decision.py?" | Tool đó chỉ show 1 quyết định cuối, đây show từng step trong sequence |

---

## Phụ lục: Files liên quan

| File | Mục đích |
|---|---|
| [`AI RL/inspect_train.py`](../inspect_train.py) | Tool chính — capture step + render dashboard |
| [`AI RL/inspect_launch.py`](../inspect_launch.py) | Launcher tương tác — hỏi options từng bước |
| [`AI RL/env_ids.py`](../env_ids.py) | Source of truth: env, reward, temporal state |
| [`AI RL/train.py`](../train.py) | PPO training entrypoint |
| [`AI RL/verify_rl_decision.py`](../verify_rl_decision.py) | Pattern extract policy probs (tham khảo) |
| [`AI RL/runs/inspect/`](../runs/inspect/) | Output JSONL + HTML reports |

---

*Tài liệu này tổng hợp tất cả Q&A đã thảo luận về tool `inspect_train.py` từ lúc tool được build đến nay.*
