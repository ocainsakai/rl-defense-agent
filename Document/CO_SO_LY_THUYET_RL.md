# Cơ sở Lý thuyết — RL Defense Agent

> Tài liệu này trình bày nền tảng lý thuyết cho hệ thống phòng thủ mạng dựa trên Học tăng cường (Reinforcement Learning - RL), áp dụng thuật toán **Proximal Policy Optimization (PPO)** trên môi trường mạng mô phỏng Mininet. Mục tiêu: cung cấp khung tham chiếu học thuật chính xác cho Chương 2 (Cơ sở lý thuyết) và đối đáp phản biện hội đồng.
>
> **Tham khảo chính**: Russell & Norvig, *Artificial Intelligence: A Modern Approach* (4th ed.); Sutton & Barto, *Reinforcement Learning: An Introduction* (2nd ed.); Schulman et al. (2017) *Proximal Policy Optimization Algorithms*; Schulman et al. (2016) *High-Dimensional Continuous Control Using Generalized Advantage Estimation*.

---

## 1. Phân loại kiến trúc Agent (theo AIMA Ch. 2)

Russell & Norvig phân kiến trúc agent thành 5 cấp độ theo độ phức tạp tăng dần:

| Kiến trúc | Đặc điểm | Hạn chế |
|---|---|---|
| Simple Reflex | `if percept then action` | Không xử lý được môi trường quan sát một phần |
| Model-Based Reflex | Giữ internal state + transition/sensor model, vẫn dùng condition-action rules | Không có mục tiêu/hàm tối ưu, không học |
| Goal-Based | Thêm biểu diễn goal, search/plan để đạt goal | Không so sánh được nhiều goal cạnh tranh |
| Utility-Based | Thêm hàm utility, chọn hành động max expected utility | Utility phải được cho sẵn |
| **Learning Agent** | Critic + Learning element + Performance element + Problem generator; **cải thiện hiệu năng theo kinh nghiệm** | Cần cơ chế feedback và đủ dữ liệu |

**Vị trí của hệ RL Defense Agent**: Đây là **Learning Agent** theo AIMA. Cụ thể:

- **Performance element** = policy network $\pi_\theta$ (Actor của PPO) — ánh xạ observation → action.
- **Critic** = value network $V_\phi$ — ước lượng giá trị trạng thái, cung cấp tín hiệu huấn luyện.
- **Learning element** = thuật toán PPO cập nhật $\theta, \phi$ theo gradient.
- **Problem generator** = môi trường huấn luyện (`IDSDefenseEnv` với mock/replay mode) sinh ra các kịch bản đa dạng để agent khám phá.

**Lưu ý terminology**: không gọi hệ là "Model-Based Reflex Agent" — hệ không có condition-action rule thủ công, mà học policy qua gradient.

---

## 2. Đặc tính môi trường (AIMA Ch. 2, task environment properties)

Môi trường phòng thủ mạng được đặc trưng như sau:

| Thuộc tính | Giá trị | Hệ quả thiết kế |
|---|---|---|
| Observability | **Partially observable** | Không quan sát trực tiếp ý định attacker; chỉ thấy hiện tượng mạng |
| Determinism | **Stochastic** | Cùng action có thể cho kết quả khác nhau do noise mạng, TCP retry, timing |
| Episodicity | **Sequential** | Hành động hiện tại ảnh hưởng đến quan sát tương lai |
| Dynamics | **Dynamic** | Môi trường thay đổi ngay cả khi agent không hành động |
| State representation | **Continuous** (observation) × **Discrete** (action) | 34D ℝ quan sát, 4 action rời rạc |
| Số tác nhân | **Multi-agent, adversarial** | Có attacker đối kháng; môi trường non-stationary |
| Known/Unknown | **Unknown** | Động lực môi trường không cho trước, phải học |

Bảy đặc tính trên phù hợp chính xác với khung **Partially Observable Markov Decision Process (POMDP)**, hợp thức hóa việc dùng Deep RL.

---

## 3. Hình thức hóa bài toán

### 3.1. POMDP — framework lý thuyết đúng

POMDP được định nghĩa bởi tuple 7 thành phần:

$$\langle \mathcal{S}, \mathcal{A}, \mathcal{O}, T, Z, R, \gamma \rangle$$

| Ký hiệu | Ý nghĩa |
|---|---|
| $\mathcal{S}$ | State space — trạng thái thực của mạng (intent attacker, state các connection, v.v.) |
| $\mathcal{A}$ | Action space = {Allow, RateLimit, Redirect, Block} |
| $\mathcal{O}$ | Observation space — không gian 34D quan sát được |
| $T(s'\mid s,a)$ | Transition model |
| $Z(o\mid s',a)$ | Observation/sensor model — xác suất quan sát $o$ khi state thực là $s'$ |
| $R(s,a)$ | Reward |
| $\gamma \in [0,1]$ | Discount factor |

Giải POMDP chính tắc cần duy trì **belief state** $b(s) \in \Delta(\mathcal{S})$ và cập nhật qua Bayes:

$$b'(s') = \eta \cdot Z(o\mid s',a) \sum_{s \in \mathcal{S}} T(s'\mid s,a)\, b(s)$$

với $\eta$ là hằng số chuẩn hóa. Policy tối ưu trên belief space: $\pi^*(b)$.

### 3.2. Xấp xỉ POMDP → MDP qua sufficient statistic

Giải POMDP chính xác là **intractable** với $|\mathcal{S}|$ lớn. Thực tế hệ dùng chiến lược **hand-engineered sufficient statistic** — thay belief state bằng vector 34D cố định, giả định đủ thông tin để xấp xỉ Markov:

$$o_t = \underbrace{[F_1, \ldots, F_{20}]}_{\text{20D sensor (1s window)}} \,\Vert\, \underbrace{[\tau_1, \ldots, \tau_{10}]}_{\text{10D temporal agent-internal}} \,\Vert\, \underbrace{[F_{21}, \ldots, F_{24}]}_{\text{4D effect}_{t-1}}$$

Trong đó:

- **20D sensor** (`FEATURE_ORDER` trong `System/config/data_params.py`): network (F1–F11), SQLi (F12–F17), XSS (F18–F20). Chuẩn hóa qua `normalize_feature_vector()`.
- **10D temporal**: `PersistenceTemporalState` — damage EMA, action history (last_action one-hot), block_ready_latched, session flags. Tính trong bộ nhớ `infer.py`, không đo từ mạng.
- **4D effect** = $[F_{21}, F_{22}, F_{23}, F_{24}]$ = [WebHitRatio, HoneypotHitRatio, PresenceRatio, ServiceDamage]. **Delayed 1 step** (effect_{t-1}) — tránh leakage. Tính từ nginx access.log qua `NginxEffectCollector`.

**Ràng buộc causal**: $o_t$ chỉ chứa $\text{effect}_{t-1}$, **không** chứa $\text{effect}_t$ — agent không được nhìn trước hậu quả của action đang chọn.

**Giả định xấp xỉ Markov**: $P(o_{t+1} \mid  o_t, a_t) \approx P(o_{t+1} \mid  o_t, a_t, o_{t-1}, a_{t-1}, \ldots)$. Giả định này **không được chứng minh toán học**, chỉ được biện minh empirically qua hiệu năng mô hình trên tập test.

### 3.3. MDP sau xấp xỉ

Sau khi gập POMDP thành MDP xấp xỉ, bài toán được mô tả bởi tuple $\langle \mathcal{O}, \mathcal{A}, P, R, \gamma \rangle$:

- $\mathcal{O} \subset \mathbb{R}^{34}$ (normalized to $[0,1]^{34}$ qua normalization + clipping).
- $\mathcal{A} = \{0, 1, 2, 3\}$ = {Allow, RateLimit, Redirect, Block}.
- $P$: ẩn (model-free RL — không học).
- $R$: xem Mục 7.2.
- $\gamma = 0.99$ (default stable-baselines3).

---

## 4. Reinforcement Learning — khung toán học

### 4.1. Return và value functions

**Return** (biến ngẫu nhiên, không phải kỳ vọng):

$$G_t = R_{t+1} + \gamma R_{t+2} + \gamma^2 R_{t+3} + \cdots = \sum_{k=0}^{\infty} \gamma^k R_{t+k+1}$$

**State-value function** (theo policy $\pi$):

$$V^\pi(s) = \mathbb{E}_\pi[G_t \mid S_t = s]$$

**Action-value function**:

$$Q^\pi(s,a) = \mathbb{E}_\pi[G_t \mid S_t = s, A_t = a]$$

**Advantage function**:

$$A^\pi(s,a) = Q^\pi(s,a) - V^\pi(s)$$

Đo lường action $a$ tốt hơn/kém hơn trung bình tại state $s$ bao nhiêu.

### 4.2. Bellman equations

$$V^\pi(s) = \sum_a \pi(a\mid s)\left[R(s,a) + \gamma \sum_{s'} P(s'\mid s,a) V^\pi(s')\right]$$

$$Q^\pi(s,a) = R(s,a) + \gamma \sum_{s'} P(s'\mid s,a) \sum_{a'} \pi(a'\mid s') Q^\pi(s',a')$$

### 4.3. Mục tiêu tối ưu

Tìm policy $\pi^*$ tối đa hóa **expected return**:

$$\pi^* = \arg\max_\pi J(\pi), \quad J(\pi) = \mathbb{E}_{\tau \sim \pi}\left[\sum_{t=0}^{T} \gamma^t R_{t+1}\right]$$

với $\tau = (s_0, a_0, r_1, s_1, a_1, r_2, \ldots)$ là trajectory sinh bởi $\pi$.

---

## 5. Policy Gradient và Actor-Critic

### 5.1. Policy Gradient Theorem (Sutton 1999)

Với policy $\pi_\theta$ tham số hóa bởi $\theta$:

$$\nabla_\theta J(\theta) = \mathbb{E}_{\pi_\theta}\left[\nabla_\theta \log \pi_\theta(a\mid s) \cdot Q^{\pi_\theta}(s,a)\right]$$

Trong thực hành, thay $Q$ bằng **advantage** $A^\pi$ để giảm variance (baseline subtraction):

$$\nabla_\theta J(\theta) = \mathbb{E}\left[\nabla_\theta \log \pi_\theta(a\mid s) \cdot A^\pi(s,a)\right]$$

### 5.2. Kiến trúc Actor-Critic

- **Actor**: $\pi_\theta(a\mid s)$ — mạng neural quyết định action (tham số $\theta$).
- **Critic**: $V_\phi(s)$ — mạng neural ước lượng value function (tham số $\phi$), dùng để tính advantage.

### 5.3. Vấn đề của Vanilla Policy Gradient

- **Cập nhật quá đà** (destructively large step): một step gradient lớn có thể đưa policy ra khỏi vùng ổn định → reward sụp đổ, khó phục hồi.
- **On-policy data inefficiency**: mỗi rollout chỉ dùng được 1 lần, phải tạo rollout mới sau mỗi update.

→ Dẫn đến **TRPO** (Trust Region Policy Optimization, Schulman 2015) và sau đó là **PPO** (Schulman 2017).

---

## 6. Proximal Policy Optimization (PPO)

### 6.1. Tư tưởng cốt lõi

PPO cải tiến Vanilla PG bằng cách **giới hạn độ lớn cập nhật policy** giữa hai lần iteration, tránh catastrophic drop. Khác TRPO (dùng KL-constraint cứng + second-order optimization), PPO dùng **clipped surrogate objective** — first-order, implement đơn giản, hiệu năng tương đương.

### 6.2. Probability ratio

Định nghĩa tỷ lệ xác suất giữa policy mới và cũ:

$$r_t(\theta) = \frac{\pi_\theta(a_t\mid s_t)}{\pi_{\theta_{old}}(a_t\mid s_t)}$$

- $r_t(\theta) = 1$ khi policy không thay đổi.
- $r_t(\theta) > 1$ khi policy mới tăng xác suất chọn $a_t$ tại $s_t$.

### 6.3. Clipped Surrogate Objective

$$L^{CLIP}(\theta) = \hat{\mathbb{E}}_t\left[\min\left(r_t(\theta)\hat{A}_t,\; \text{clip}(r_t(\theta), 1-\epsilon, 1+\epsilon)\hat{A}_t\right)\right]$$

Với $\epsilon$ là hyperparameter (thường $\epsilon = 0.2$).

**Phân tích vai trò của $\min$ và $\text{clip}$ — hai trường hợp asymmetric**:

| $\hat{A}_t$ | Hướng cập nhật mong muốn | Giới hạn áp dụng |
|---|---|---|
| $\hat{A}_t > 0$ (action tốt) | Tăng $\pi_\theta(a_t\mid s_t)$ → $r_t$ tăng | Clip **trên** ở $1+\epsilon$: không cho policy dịch chuyển quá xa theo hướng tốt |
| $\hat{A}_t < 0$ (action tệ) | Giảm $\pi_\theta(a_t\mid s_t)$ → $r_t$ giảm | Clip **dưới** ở $1-\epsilon$: không cho policy dịch chuyển quá xa theo hướng trừng phạt |

Operator $\min$ tạo **pessimistic lower bound**: khi clip làm objective *tốt hơn* un-clipped, $\min$ lấy un-clipped; khi clip làm objective *tệ hơn*, $\min$ lấy clipped. Kết quả là objective luôn là cận dưới bi quan của surrogate thật — ngăn update quá đà theo cả hai hướng.

### 6.4. Value function loss và entropy bonus

PPO trong thực tế tối ưu hàm tổng:

$$L^{CLIP+VF+S}(\theta, \phi) = \hat{\mathbb{E}}_t\left[L^{CLIP}_t(\theta) - c_1 \underbrace{L^{VF}_t(\phi)}_{\text{critic loss}} + c_2 \underbrace{S[\pi_\theta](s_t)}_{\text{entropy bonus}}\right]$$

- **Value loss** $L^{VF}_t(\phi) = (V_\phi(s_t) - V^{target}_t)^2$: huấn luyện critic để khớp return, cần cho advantage estimation.
- **Entropy bonus** $S[\pi_\theta](s) = -\sum_a \pi_\theta(a\mid s) \log \pi_\theta(a\mid s)$: khuyến khích exploration, tránh policy collapse sớm.
- $c_1, c_2$ là hệ số trộn (default stable-baselines3: $c_1 = 0.5$, $c_2 = 0.01$).

### 6.5. Generalized Advantage Estimation (GAE)

$\hat{A}_t$ không tính trực tiếp từ $Q - V$ (vì không có Q-model), mà qua **GAE** (Schulman 2016):

$$\hat{A}_t^{GAE(\gamma,\lambda)} = \sum_{l=0}^{\infty} (\gamma\lambda)^l \delta_{t+l}$$

với TD-error:

$$\delta_t = R_{t+1} + \gamma V_\phi(s_{t+1}) - V_\phi(s_t)$$

- $\lambda \in [0,1]$ điều chỉnh bias–variance trade-off: $\lambda = 0$ → TD(0) (bias cao, variance thấp); $\lambda = 1$ → Monte Carlo (bias thấp, variance cao).
- stable-baselines3 default: $\lambda = 0.95$.

### 6.6. Thuật toán PPO tóm lược (dạng pseudocode)

```
for iteration = 1, 2, ... do
  for actor = 1, ..., N do
    Chạy policy π_{θ_old} trong T timesteps → thu (s_t, a_t, r_t, s_{t+1})
    Tính advantage ước lượng Â_1, ..., Â_T qua GAE
  Optimize L^{CLIP+VF+S} trong K epochs, minibatch size M
  θ_old ← θ
```

---

## 7. Áp dụng cụ thể cho RL Defense Agent

### 7.1. State và action space

- **State space**: $\mathcal{O} = [0,1]^{34}$ (sau normalization).
- **Action space**: $\mathcal{A} = \{0, 1, 2, 3\}$:
  - 0 = **Allow**: không áp rule.
  - 1 = **RateLimit**: `iptables -m hashlimit` giới hạn tốc độ.
  - 2 = **Redirect**: `iptables -t nat REDIRECT` chuyển hướng sang honeypot port 4443; tự động escalate sang Block sau 60s nếu traffic vẫn dai dẳng.
  - 3 = **Block**: `iptables DROP` trên cả INPUT và FORWARD chain.

### 7.2. Hàm reward

Reward (`_compute_reward` trong `env_ids.py`):

$$r_t = \text{bonus}(a_t) - \text{cost}(a_t) - 0.12 \cdot F_{24}^{(t)} + r_{shaping}$$

Thành phần:

- **Action bonus** — phần thưởng khi match đúng loại attack (ví dụ Block match DDoS, Redirect match SQLi/XSS).
- **Action cost** — phạt chi phí vận hành: Allow = 0, RateLimit < Redirect < Block.
- $-0.12 \cdot F_{24}$ — phạt theo ServiceDamage (mức độ dịch vụ bị ảnh hưởng).
- **Shaping terms**: anti-oscillation penalty (phạt đổi action liên tục), persistence bonus (thưởng duy trì defense khi attack dai dẳng), stability bonus.

### 7.3. Training modes

- **mock**: dùng `MockIPBehavior` + `simulate_effect()` để sinh observation tổng hợp. Closed-loop feedback là giả lập (4D effect sinh bởi công thức tất định theo action).
- **replay**: đọc `training_data.jsonl` (thu bằng `infer.py --label`). Features đến từ NIDS thật, nhưng 4D effect có thể từ storage hoặc zero. Dùng cho fine-tuning.

### 7.4. Hyperparameters

| Tham số | Giá trị | Ghi chú |
|---|---|---|
| Total timesteps | 500,000 | Default cho 34D obs |
| Parallel envs | 4 | `--n_envs` |
| Clip range $\epsilon$ | 0.2 | PPO default |
| Discount $\gamma$ | 0.99 | - |
| GAE $\lambda$ | 0.95 | - |
| Learning rate | 3e-4 | Adam, default SB3 |
| $c_1$ (value) | 0.5 | - |
| $c_2$ (entropy) | 0.01 | - |
| Window size | 1.0s | Cố định (review 2026-01) |

---

## 8. Giới hạn lý thuyết và điểm yếu cần thừa nhận

Khi trả lời hội đồng, nên **chủ động thừa nhận** các giới hạn sau thay vì để bị chất vấn:

### 8.1. Giả định Markov không được chứng minh chặt

34D observation là sufficient statistic **xấp xỉ**, không phải sufficient statistic theo nghĩa chính tắc của POMDP theory. Nếu 1 giây là không đủ context, policy sẽ suboptimal.

### 8.2. Time horizon ngắn

Cửa sổ 1 giây (và EMA tick theo giây) **không phù hợp** cho các attack trải dài phút/giờ (Slowloris, low-rate DDoS, credential stuffing chậm). Hệ hiện tại chỉ chứng minh hiệu quả trên attack volumetric ngắn hạn. Mở rộng sang low-and-slow yêu cầu:

- Tăng window hoặc stack multi-scale windows.
- Dùng RNN/LSTM thay cho 10D hand-crafted temporal.
- Mở rộng 10D temporal để chứa features thời gian dài (moving average theo phút).

### 8.3. Non-stationarity adversary

Attacker có thể thích ứng: khi thấy rule bị Block, đổi source IP, dùng slow pattern, v.v. PPO huấn luyện trên distribution cố định → không bảo đảm robustness khi adversary dịch chuyển distribution. Hướng mở rộng: **multi-agent RL** hoặc **robust RL** (min–max over adversarial perturbations).

### 8.4. Sample inefficiency

PPO là **on-policy** → mỗi rollout chỉ dùng được một lần. Training cần 500k timesteps trên mô phỏng để hội tụ. Trong production, không thể retrain online mỗi lần đổi topology. Hướng mở rộng: **off-policy** (SAC, TD3) hoặc **offline RL** (CQL, IQL) trên dữ liệu log.

### 8.5. Partial observability thật sự không được giải chính tắc

Không có belief state, không có RNN tracking belief. Mọi kết quả dựa trên giả thuyết 34D đủ thông tin. Nếu hội đồng hỏi "vì sao không dùng LSTM policy?" — câu trả lời trung thực: trade-off thực hành (đơn giản, ít overfit với mẫu nhỏ, dễ debug) thay vì lý thuyết tối ưu.

---

## 9. Tài liệu tham khảo chính

- Russell, S. & Norvig, P. (2020). *Artificial Intelligence: A Modern Approach* (4th ed.). Pearson.
- Sutton, R. S. & Barto, A. G. (2018). *Reinforcement Learning: An Introduction* (2nd ed.). MIT Press.
- Schulman, J., Wolski, F., Dhariwal, P., Radford, A., & Klimov, O. (2017). Proximal Policy Optimization Algorithms. *arXiv:1707.06347*.
- Schulman, J., Moritz, P., Levine, S., Jordan, M., & Abbeel, P. (2016). High-Dimensional Continuous Control Using Generalized Advantage Estimation. *ICLR 2016*.
- Schulman, J., Levine, S., Abbeel, P., Jordan, M., & Moritz, P. (2015). Trust Region Policy Optimization. *ICML 2015*.
- Kaelbling, L. P., Littman, M. L., & Cassandra, A. R. (1998). Planning and acting in partially observable stochastic domains. *Artificial Intelligence*, 101(1–2), 99–134.
