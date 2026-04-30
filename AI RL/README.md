# AI RL — Reinforcement Learning Defense Agent

Phần trung tâm của project: huấn luyện và triển khai PPO agent cho phòng thủ
mạng thích ứng. Bao gồm môi trường training, inference production, framework
benchmark, và bộ tools phân tích.

---

## 0. Tóm tắt nhanh

| Thành phần | Giá trị |
|---|---|
| Algorithm | PPO (Proximal Policy Optimization) — Stable-Baselines3 |
| Observation space | 34D = 20D NIDS sensor + 10D temporal state + 4D effect feedback |
| Action space | 4 discrete: Allow / RateLimit / Redirect / Block |
| Episode length | 320 steps (16 IPs round-robin × 20 visits/IP) |
| Training default | 500,000 timesteps, 4 parallel envs, ~3 phút CPU |
| Model production | `runs/run_34d_v13/best_model.zip` (eval reward 58.68 tại step 500k) |
| Pipeline inference | NIDS JSONL → PPO → SafetyNet → IPStateTracker → iptables |

---

## 1. Cấu trúc folder

```
AI RL/
├── env_ids.py                  Training environment (IDSDefenseEnv)
├── env_ids_harder.py           Harder variant cho benchmark
├── train.py                    PPO training script (production)
├── infer.py                    Production inference + iptables enforcement
├── inspect_train.py            Step-by-step training visualizer
├── inspect_launch.py           Interactive launcher cho inspect_train
├── analyze_log.py              Phân tích segment trong actions.log
├── demo_live_train.py          Replay policy evolution qua checkpoints
├── demo_xss_finetune.py        Controlled fine-tuning trên XSS real data
├── verify_rl_decision.py       Verify model probability cho 1 decision
├── actions.log                 Full audit log (JSONL — debug/analysis)
├── actions_wazuh.log           Stripped log cho Wazuh ingestion
├── runs/                       Training outputs
│   ├── run_34d_v13/            Production model hiện tại
│   └── run_finetune_xss/       Fine-tuned model từ XSS real data
├── Benchmark/                  Algorithm comparison framework (PPO/A2C/DQN)
└── Documents/                  Methodology, walkthroughs, Q&A docs
```

---

## 2. Model production — `runs/run_34d_v13/`

| File | Size | Mô tả |
|---|---|---|
| `best_model.zip` | 1.8 MB | Model tốt nhất theo EvalCallback metric (mean reward 58.68 tại step 500,000). **Dùng cho inference production.** |
| `final_model.zip` | 1.8 MB | State cuối training (step 500k, sau gradient update cuối) |
| `best_model_persistent.zip` | 1.8 MB | Model tốt nhất theo PersistentEvalCallback (escalation tracking metric, tương đương step 160k) |
| `checkpoints/` | 22 MB | 12 snapshots: `model_40000_steps.zip` đến `model_480000_steps.zip` (mỗi 40k steps) |
| `tb/PPO_1/` | ~2 MB | TensorBoard event logs |
| `evaluations.npz` | 26 KB | Numpy arrays: timesteps, mean_rewards qua 25 lần evaluation (20k → 500k) |
| `policy_evolution_trajectory.png` | 140 KB | Heatmap visualize policy probabilities qua các checkpoints |
| `policy_evolution_trajectory_34d.csv` | 36 cột | Trajectory features (20D NIDS + 10D temporal + 4D effect + action probs) |

**Mở TensorBoard:**
```bash
tensorboard --logdir "AI RL/runs/run_34d_v13/tb/"
# Truy cập: http://localhost:6006
```

**Reward curve (eval) qua 25 checkpoints:**

| Step | 20k | 100k | 200k | 300k | 400k | 500k |
|---|---|---|---|---|---|---|
| Mean reward | -0.30 | 27.69 | 50.76 | 52.41 | 57.47 | **58.68** |

---

## 3. Hai file logs

### `actions.log` — Full audit (JSONL)

**Producer:** `infer.py`, hàm `watch_jsonl()` ghi mỗi quyết định AI

**Format mỗi dòng:**
```json
{
  "timestamp": 1777044042.338,
  "window_ts": 1777044042.0,
  "src_ip": "10.0.10.10",
  "rl_action": 0,
  "rl_action_name": "Allow",
  "final_action": 0,
  "final_action_name": "Allow",
  "model_version": "v3",
  "t_window_len": 0,
  "t_redirect_hits": 0,
  "t_presence_hits": 0,
  "t_honeypot_hits": 0,
  "t_escalation_score": 0.0,
  "t_block_ready": false,
  "soft_guard_promoted": false,
  "action_probs": {"Allow": 0.80, "RateLimit": 0.12, "Redirect": 0.06, "Block": 0.01},
  "normalized_obs": [0.47, 0.15, ...]
}
```

**Dùng cho:**
- Debug AI decision (so sánh `rl_action` vs `final_action` để xem Override fire)
- Input cho `analyze_log.py`, `inspect_train.py`, `verify_rl_decision.py`
- Forensic analysis sau incident

### `actions_wazuh.log` — Wazuh-friendly (stripped)

**Producer:** Cùng `infer.py`, gọi `_build_wazuh_log()` strip 2 fields

**Khác `actions.log`:**
- Loại bỏ `action_probs` (dict 4 keys, dễ gây array parsing issue trong Wazuh Indexer)
- Loại bỏ `normalized_obs` (34-element float array)

**Dùng cho:**
- Wazuh agent tail file → forward về Wazuh Manager
- Dashboard Wazuh visualize action distribution, escalation events
- Alert rules trigger khi `final_action_name == "Block"` hoặc `soft_guard_promoted == true`

---

## 4. Tools — chi tiết từng file

### 4.1. `train.py` — PPO Training

**Lệnh chạy:**
```bash
python3 train.py
# hoặc tùy chỉnh:
python3 train.py --timesteps 500000 --n_envs 4 --eval_freq 5000 --checkpoint_freq 10000 --seed 42
```

**Hyperparameters:**
- `learning_rate=3e-4` (linear schedule giảm về 6e-5)
- `n_steps=2048` (rollout buffer)
- `batch_size=128`, `n_epochs=6`
- `gamma=0.995`, `gae_lambda=0.95`
- `clip_range=0.15`, `ent_coef=0.05`
- Network architecture: `pi=[256, 128]`, `vf=[256, 256, 128]`

**Callbacks:**
- `EvalCallback` → save `best_model.zip` khi mean reward đạt cực đại
- `PersistentEvalCallback` → save `best_model_persistent.zip` khi escalation metrics tốt
- `CheckpointCallback` → save `model_{step}_steps.zip` mỗi 10k steps

**Output:** `runs/run_{timestamp}_seed{N}/`

---

### 4.2. `infer.py` — Production Inference

**Lệnh chạy:**
```bash
sudo python3 infer.py \
  --watch /tmp/sniffer_output.jsonl \
  --model runs/run_34d_v13/best_model \
  --demo-safe
```

#### Pipeline tổng quát (mỗi dòng JSONL từ NIDS)

```
NIDS row (1 src_ip × 1s window)
    │
    ▼
[1] parse_nids_row()              -> 20D normalized sensor (= obs[0..19])
    │
    ▼
[2] Get/create PersistenceTemporalState[src_ip]
    │
    ▼
[3] effect_prev = NginxEffectCollector.get_effect(src_ip, current_wts - 1.0, raw_20d)
                                  -> 4D [F21, F22, F23, F24]   (= obs[30..33])
    │
    ▼
[4] tstate.observe_effect(effect_prev)        # cập nhật damage_ema, effect_trend, ...
    temporal_10d = tstate.to_obs()            -> 10D            (= obs[20..29])
    │
    ▼
[5] obs_34d = concat(sensor_20d, temporal_10d, effect_prev)   shape (34,) float32
    │
    ▼
[6] rl_action = model.predict(obs_34d, deterministic=True)    -> int ∈ {0,1,2,3}
    │
    ▼
[7] SafetyNet.apply_safety_overrides(...)     -> final_action
    │
    ▼
[8] tstate.stage_action(final_action, l7_signal)   # cập nhật last_action, session_active
    SafetyNet.update(src_ip, final_action, ts)     # track iptables change
    │
    ▼
[9] iptables_executor(src_ip, final_action)   # apply qua nsenter vào router namespace
    │
    ▼
[10] log_action(...)  -> actions.log + actions_wazuh.log
```

#### Cách tạo 14D = 10D temporal + 4D effect

##### 10D temporal — `PersistenceTemporalState.to_obs()` (mirror env_ids.py)

`PersistenceTemporalState` (`infer.py:315`) **kế thừa trực tiếp** `PerIPTemporalState`
(`env_ids.py:904`) — không thêm/sửa field, không override method. Đây là điều kiện bắt
buộc để semantic 10D ở train ≡ ở infer (model predict đúng).

`to_obs()` trả về list 10 float ∈ [0, 1] theo thứ tự sau (= `obs[20..29]`):

| Index | Tên | Công thức | Ý nghĩa |
|---|---|---|---|
| 20 | last_action_onehot[0] | `1.0 if last_action == Allow else 0.0` | Allow flag |
| 21 | last_action_onehot[1] | `1.0 if last_action == RateLimit else 0.0` | RateLimit flag |
| 22 | last_action_onehot[2] | `1.0 if last_action == Redirect else 0.0` | Redirect flag |
| 23 | last_action_onehot[3] | `1.0 if last_action == Block else 0.0` | Block flag |
| 24 | action_hold_norm | `min(action_hold_steps / 15, 1.0)` | Đã giữ action hiện tại bao lâu |
| 25 | damage_ema | `min(damage_ema, 1.0)` | EMA(F24) — service damage trung bình |
| 26 | effect_trend | `sigmoid(10 * damage_trend)` | Damage tăng/giảm so step trước |
| 27 | soft_window_fill_norm | `min(window_len / 15, 1.0)` | % cửa sổ soft-session đã đầy |
| 28 | escalation_score_norm | `min(escalation_score, 1.0)` | Soft evidence (redirect+presence+honeypot+pressure-miss) ∈ [0,1] |
| 29 | miss_budget_used_norm | `min(miss_count / 3, 1.0)` | Số lần tolerate L7-miss |

**Khi nào reset?** `_reset_soft_session()` chạy khi action chuyển khỏi escalation track
(hoặc Block thành công). `stage_action()` start session khi `last_action=Redirect` và
L7 signal đủ mạnh (`SESSION_START_L7_THRESHOLD`).

**Khi nào latch `block_ready=True`?** Khi đồng thời:
`window_len ≥ 12` ∧ `redirect_hits ≥ 8` ∧ `presence_hits ≥ 8` ∧ `honeypot_hits ≥ 6`
∧ `miss ≤ 3` ∧ `escalation_score ≥ 0.6` (constants từ env_ids.py).

##### 4D effect — `NginxEffectCollector.get_effect()`

`NginxEffectCollector` (`infer.py:696`) tail incremental `nginx access.log` (mặc định
`/var/log/nginx/access.log`), parse mỗi line → bucket theo `(src_ip, window_ts)` với
`window_ts = floor(ts / 1s) * 1s`. Phân loại đích bằng `Upstream-Addr` header
(`NGINX_WEB_UP` vs `NGINX_HONEY_UP`).

`get_effect(src_ip, window_ts, sensor_20d)` trả về `[F21, F22, F23, F24]`:

| Index | Tên | Công thức | Ý nghĩa |
|---|---|---|---|
| 30 | F21 WebHitRatio | `b['w'] / b['t']` (web hits / total hits) | Tỉ lệ traffic chạm webserver thật |
| 31 | F22 HoneypotHitRatio | `b['h'] / b['t']` (honeypot hits / total hits) | Tỉ lệ traffic chạm honeypot |
| 32 | F23 PresenceRatio | `1.0` nếu có hit trong window, `0` nếu không | Có hoạt động L7 hay không |
| 33 | F24 ServiceDamage | `min(0.7·ac·F21 + 0.3·ac·F23·(1-F22), 1.0)` với `ac = attack_conf(F1,F2,F5,F11,SQLi,XSS)` | Damage thực tế lên webserver |

**Causal contract: delayed 1 step.** `effect_prev` gọi `get_effect(src_ip, current_wts - 1.0, ...)`
— tức effect ở step trước, không phải step hiện tại. Lý do: action ở step `t` mới sinh
ra effect ở step `t+1`, model phải quan sát hậu quả của hành động cũ chứ không tự
nhìn thấy hành động hiện tại trong cùng window.

#### SafetyNet overrides

`SafetyNet.apply_safety_overrides()` (`infer.py:361`) — thin wrapper, KHÔNG còn state
machine cho temporal logic (đã chuyển vào model qua 10D temporal obs). Chỉ giữ 3 overrides:

| Override | Điều kiện | Hành động | Lý do |
|---|---|---|---|
| 0 | L7 signal cao (SQLi/XSS/brute) nhưng RL chọn `Allow` hoặc `RateLimit` | `final = Redirect` | Cold-start: model v7 không học được brute do F1 thấp; cần force Redirect để start escalation |
| 1 | RL chọn `Block` nhưng `block_ready_latched=False` và không có DDoS signal | `final = Redirect` | Tránh Block sớm cho L7 attack — Redirect để honeypot thu thập payload |
| 2 (block-hold) | `last_action=Block` ∧ RL chọn xuống ∧ `damage_ema > 0.3` | `final = Block` | Damage còn cao thì giữ Block, không release vội |

`soft_guard` (assist mode) bổ sung: khi `block_ready_latched=True` mà RL vẫn chọn
Redirect thì promote lên Block (rule-based escalation). Field `soft_guard_promoted=true`
log lại sự kiện này.

Sau tất cả overrides:
- `tstate.stage_action(final_action, l7_signal)` — update `last_action`, có thể start/end session
- `SafetyNet.update(src_ip, final_action, ts)` — quyết định có cần đổi iptables không
- `iptables_executor()` — apply qua `nsenter -n -t {ROUTER_PID}` vào router namespace

#### Auto-expire (idle TTL)

`SafetyNet.expire_stale()` chạy mỗi 5s (`EXPIRE_CHECK_INTERVAL`) quét các IP im lặng:
- `Block` quá `BLOCK_IDLE_TTL=60s` → release (xoá iptables DROP rule)
- `RateLimit` quá `RATELIMIT_IDLE_TTL=15s` → release

#### Output

- `actions.log` (full audit) + `actions_wazuh.log` (stripped) — xem section 3
- iptables thật trên router namespace:
  - `Block`: `iptables -I FORWARD 1 -s {ip} -j DROP`
  - `RateLimit`: `iptables -I FORWARD 1 -s {ip} -m hashlimit --hashlimit-above 10/sec -j DROP`
  - `Redirect`: `iptables -t nat -I PREROUTING 1 -i r-ext -s {ip} -d 192.168.10.10 -p tcp --dport 443 -j REDIRECT --to-ports 4443`

---

### 4.3. `inspect_train.py` — Step-by-step Visualizer

Tool dashboard cho phép xem từng step training/rollout: state observation,
policy probabilities, chosen action, reward breakdown, next state.

**Lệnh chạy:**
```bash
# Mode rollout (load checkpoint, step env)
python3 inspect_train.py --mode rollout \
  --checkpoint runs/run_34d_v13/checkpoints/model_480000_steps \
  --steps 200 --delay-ms 800

# Mode train (hook vào PPO.learn để quan sát training thật)
python3 inspect_train.py --mode train \
  --base-checkpoint runs/run_34d_v13/checkpoints/model_40000_steps \
  --steps 4096
```

**Output:**
- Live dashboard rich.Live trong terminal (7 panels)
- `runs/inspect/{timestamp}_steps.jsonl` — raw data
- `runs/inspect/{timestamp}_report.html` — HTML report với:
  - Action distribution donut chart (Chart.js)
  - Cumulative reward line chart
  - Action trajectory timeline
  - Per-step cards với pagination (50/100/200/All)
  - Filter buttons: All, Allow, RateLimit, Redirect, Block, Escalation Redirect→Block, block_ready=True
  - IP filter dropdown grouped by traffic type

---

### 4.4. `inspect_launch.py` — Interactive Launcher

Wrapper user-friendly cho `inspect_train.py`. Hỏi 5 bước qua menu rồi chạy.

**Lệnh chạy:**
```bash
python3 inspect_launch.py
```

**Quy trình:**
1. Mode: rollout / train
2. Checkpoint: list 12 checkpoints + ghi chú (40k early, 480k recommend, 500k aggressive)
3. Số steps: 16 / 32 / 100 / 320 / 1000
4. Display: Live fast (120ms) / Demo speed (800ms) / Very slow (1500ms) / Headless
5. Deterministic: argmax hay sample softmax

In equivalent CLI rồi chạy `inspect_train.py`.

---

### 4.5. `analyze_log.py` — Segment Analyzer

Phân tích phân bố action + SafetyNet escalation events trong một đoạn dòng
của `actions.log`.

**Lệnh chạy:**
```bash
python3 analyze_log.py 545 650
```

**Output (terminal):**
- Bảng action distribution: Count, %, P_avg, P_min, P_max
- SafetyNet ESC count + tỷ lệ
- Chi tiết từng ESC event: line number, RL action vs Final action, action_probs,
  temporal state (redirect_hits, presence_hits, honeypot_hits, escalation_score, block_ready)

---

### 4.6. `demo_live_train.py` — Policy Evolution Replay

Replay 23-window attack trajectory qua các checkpoint từ 40k đến 480k để
chứng minh policy evolution: model trẻ chỉ Redirect, model hội tụ học được Block.

**Lệnh chạy:**
```bash
python3 demo_live_train.py
# hoặc bắt đầu từ checkpoint cụ thể:
python3 demo_live_train.py --from 120000 --delay 2.0
```

**Output:**
- Live rich dashboard hiển thị action chuyển đổi qua thời gian
- `runs/run_34d_v13/policy_evolution_trajectory.png` — heatmap
- `runs/run_34d_v13/policy_evolution_trajectory_34d.csv` — 34D trajectory đầy đủ

---

### 4.7. `demo_xss_finetune.py` — Controlled Fine-tuning

Demo controlled fine-tuning: load model 40k base, fine-tune trên XSS real data,
chứng minh model học từ evidence thật.

**Lệnh chạy:**
```bash
python3 demo_xss_finetune.py
# hoặc tùy chỉnh:
python3 demo_xss_finetune.py --replay-steps 10000 --mock-steps 30000
# Skip training (chỉ show BEFORE metrics):
python3 demo_xss_finetune.py --no-train
```

**Quy trình:**
1. Phase 1: Replay fine-tune 10k steps trên `xss_real.jsonl` (real XSS từ xsser)
2. Phase 2: Mock stabilize 30k steps trên IDSDefenseEnv (chống catastrophic forgetting)
3. Total ~80k steps khớp với checkpoint v13/80k cho fair comparison

**Output:**
- BEFORE/AFTER trajectory timeline (22 windows XSS escalation)
- Regression check trên benign/sqli/syn_flood (đảm bảo không drift)
- `runs/run_finetune_xss/finetuned.zip` — adapted model

---

### 4.8. `env_ids.py` — Training Environment

`IDSDefenseEnv` (Gymnasium custom env) cho RL training.

**Đặc điểm:**
- Observation space: 34D = 20D sensor + 10D temporal + 4D effect (Box [0, 1])
- Action space: Discrete(4) — Allow/RateLimit/Redirect/Block
- Reward composite:
  - `action_bonus` (state-dependent, dựa trên features + action match)
  - `action_cost` (Allow=0, RateLimit=0.01, Redirect=0.04, Block=0.15)
  - `service_damage = -0.12 * F24`
  - `persistent_bonus = +0.45` khi Block + `block_ready_latched=True`
  - `premature_block_penalty = -0.20` khi Block sớm
  - Stability/oscillation/ramp bonuses
- 16 mock IPs round-robin: 4 benign + 2 noisy + 1 scan + 1 syn_flood + 8 L7 (brute/sqli/xss)
- Episode length: 320 steps
- Closed-loop: `simulate_effect(action, sensor)` → 4D effect feed vào obs window kế tiếp

**Mode operation:**
- `mode='mock'` (default) — `MockIPBehavior` sinh features per ip_type
- `mode='replay'` — `ReplayBehavior` dùng `xss_real.jsonl` thực tế

---

### 4.9. `env_ids_harder.py` — Harder Variant

Variant của `env_ids.py` cho benchmark, kế thừa cùng kiến trúc nhưng harder
randomization để stress-test các algorithms.

**Khác biệt với env_ids.py:**
- `missing_prob = 0.08` (vs default 0.01) — nhiều features missing/zero
- `drift_max = 0.35` (vs 0.12) — concept drift mạnh hơn cuối episode

**Mục đích:** So sánh PPO vs A2C vs DQN under harder conditions trong
framework `Benchmark/`.

---

### 4.10. `verify_rl_decision.py` — Decision Verification

Verify rằng decision của model đến từ neural network (không phải rule-based).
Lấy obs từ Block event cuối trong `actions.log`, re-run `model.predict()`.

**Lệnh chạy:**
```bash
# Verify Block event cuối cùng
python3 verify_rl_decision.py --model runs/run_34d_v13/best_model

# Watch realtime
python3 verify_rl_decision.py --watch

# Show progression P(Block) tăng dần qua các window
python3 verify_rl_decision.py --progression
```

**Output:** 4-step verification trong terminal:
1. Logged probs từ actions.log
2. Re-run model.predict() với cùng obs
3. So sánh — chứng minh deterministic (cùng obs → cùng probs)
4. 34D obs breakdown (20D sensor + 10D temporal + 4D effect)

---

## 5. Folder `Benchmark/` — Algorithm Comparison

Framework so sánh PPO/A2C/DQN/rule_based trên cùng môi trường, multiple seeds,
multiple eval modes.

### 5.1. Cấu trúc

```
Benchmark/
├── train_ppo_default.py        Train PPO với SB3 strict defaults
├── train_a2c.py                Train A2C
├── train_dqn.py                Train DQN
├── evaluate_all.py             Orchestrator: 3 algos × 5 seeds × 4 eval modes
├── metrics.py                  Compute 18 metrics per evaluation
├── plot_results.py             Generate charts từ results
├── run_benchmark.sh            Full pipeline script (~60 phút)
├── models/                     15 trained models + best checkpoints
│   ├── ppo_seed{42,123,456,789,1337}.zip
│   ├── a2c_seed{...}.zip
│   ├── dqn_seed{...}.zip
│   └── {algo}_seed{N}_best/    SB3 EvalCallback best
├── results/
│   └── benchmark_results.json  Master output (mean reward, t-tests, Cohen's d)
└── charts/
    ├── main/                   Charts cho báo cáo chính
    └── appendix/               Charts cho appendix
```

### 5.2. Algorithms compared

| Algorithm | Type | Library |
|---|---|---|
| **PPO** | On-policy | Stable-Baselines3 (primary) |
| A2C | On-policy | Stable-Baselines3 (baseline) |
| DQN | Off-policy | Stable-Baselines3 (baseline) |
| rule_based | Deterministic thresholds | Custom (threshold check: PacketRate > 0.6 → Block, SqlScore > 0.1 → Redirect) |

### 5.3. Lệnh chạy

```bash
cd "AI RL/Benchmark"

# Full pipeline (train + evaluate + plot)
./run_benchmark.sh

# Hoặc chạy từng bước:
python3 train_ppo_default.py --seed 42       # train 1 algo, 1 seed (~5 phút)
python3 evaluate_all.py                       # eval 60 combinations
python3 plot_results.py                       # render charts
```

### 5.4. Eval modes

| Mode | Mô tả |
|---|---|
| `round_robin` | IID — 16 IPs round-robin, mỗi step IP khác nhau |
| `round_robin_stress` | Round-robin + noise (missing_prob, drift) |
| `session_20` | Closed-loop — mỗi IP chạy 20 steps liên tiếp |
| `session_20_stress` | Session-20 + noise |

### 5.5. Metrics

`metrics.py` compute 18 metrics per evaluation, key metrics:
- `mean_reward`, `std_reward`
- `exact_response_rate` — % action match expected
- `honeypot_capture_rate` — % traffic vào honeypot
- `benign_intervention_rate` — % benign traffic bị action ≠ Allow (FP rate)
- `service_damage_auc` — tích phân damage qua time

`benchmark_results.json` chứa:
- Per-(algo, seed, mode): full metrics
- `_statistics`: pairwise t-tests (PPO vs A2C, PPO vs DQN, ...) + Cohen's d effect size

---

## 6. Workflow điển hình

### 6.1. Training từ đầu

```bash
cd "AI RL"

# 1. Train PPO 500k steps
python3 train.py --timesteps 500000 --seed 42
# → runs/run_{timestamp}_seed42/best_model.zip

# 2. Verify behavior với inspect_train
python3 inspect_launch.py
# → chọn mode rollout, checkpoint mới, 200 steps

# 3. Visualize evolution qua checkpoints
python3 demo_live_train.py
```

### 6.2. Production deployment

```bash
# Terminal 1: NIDS sniffer (System/main.py)
cd System
sudo python3 main.py
# → realtime mode → /tmp/sniffer_output.jsonl

# Terminal 2: Inference agent
cd "AI RL"
sudo python3 infer.py \
  --watch /tmp/sniffer_output.jsonl \
  --model runs/run_34d_v13/best_model \
  --demo-safe
# → ghi actions.log + actions_wazuh.log + apply iptables

# Terminal 3 (optional): Wazuh agent monitor actions_wazuh.log
# (xem ../Wazuh/INSTALLATION.md)
```

### 6.3. Demo trước hội đồng

```bash
# 1. Chạy demo attack (containernet/demo_*.sh)
sudo bash ../containernet/containernet/demo_brute_escalation.sh
# → quan sát Allow → RateLimit → Redirect → Block

# 2. Phân tích kết quả
python3 analyze_log.py {start_line} {end_line}

# 3. Verify decision đến từ NN
python3 verify_rl_decision.py --model runs/run_34d_v13/best_model

# 4. Step-by-step visualizer (HTML report)
python3 inspect_launch.py
```

---

## 7. Documentation tham khảo

| File | Nội dung |
|---|---|
| [`Documents/BENCHMARK_METHODOLOGY.md`](Documents/BENCHMARK_METHODOLOGY.md) | 3-layer benchmark methodology (L1 raw PPO, L2 stateless, L3 window-reset) + kết quả chi tiết trên CIC-IDS2017/2018/DDoS2019 |
| [`Documents/INSPECT_TRAIN_QA.md`](Documents/INSPECT_TRAIN_QA.md) | Q&A về `inspect_train.py` + RL concepts (state, step, episode, weights update, policy distribution) |

Ngoài ra `Documents/` còn chứa references PDF: NIST SP 800-61r2/82r2, RFC 793/4987/7230, KLTN_SP26_Group3 (báo cáo đồ án), và "Trả lời hội đồng".

---

## 8. Limitations đã biết

1. **Sim-to-real gap (SQLi pure):** Mock env không saturate features nhanh như sqlmap thực tế.
   Khi gặp SQLi sustained, model muốn Block từ window 8-9 (sớm hơn `block_ready_latched=True`
   ở window 12). Override 1 trong `infer.py` chặn để đảm bảo timing đúng. Không gây sai
   final action, chỉ tạo noise trong log audit.

2. **PortScan FW-Off:** L1 raw PPO chỉ 70% mitigate (sim-to-real). L3 full system với
   IPStateTracker Block-hold bù đắp lên 89%.

**Future work:** Domain randomization training, retrain với attack intensity variable,
tăng `premature_block_penalty` để giảm AI Block sớm.
