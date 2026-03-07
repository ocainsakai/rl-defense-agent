# AI RL — IDS Defense Agent (PPO)

Hệ thống phòng thủ mạng tự động dựa trên Reinforcement Learning (PPO).
Agent đọc output từ NIDS Sniffer (20 features/giây), đưa ra quyết định phòng thủ và thực thi iptables trên router Mininet.

---

## Kiến trúc tổng quan

```
[Attacker 10.0.10.10]
        │
        ▼ (eth1 → r-ext)
   [Router]
        │
        ├──► NIDS Sniffer (sniff r-ext, 1s window)
        │              │
        │     /tmp/sniffer_output.jsonl
        │              │
        │         [infer.py]  ◄── policy_model.zip
        │              │
        │    [iptables via nsenter]
        │
        ├──► [Webserver 192.168.10.10:8080]   ← traffic bình thường
        └──► [Honeypot  192.168.30.10:8081]   ← target của Redirect
```

### Action mapping

| Action | Tên | Ý nghĩa | Khi nào trigger |
|---|---|---|---|
| 0 | Allow | Cho qua | Traffic bình thường |
| 1 | RateLimit | Giới hạn tốc độ | Noise / grayzone |
| 2 | Redirect | Chuyển sang Honeypot (port 4443) | Brute Force / SQLi / XSS |
| 3 | Block | DROP toàn bộ | DDoS / Port Scan |

> Redirect tự động escalate lên Block sau **60 giây** nếu traffic vẫn tiếp tục.

---

## Cài đặt

```bash
pip3 install -r requirements.txt
pip3 install "numpy<2"   # bắt buộc — stable-baselines3 không tương thích numpy 2.x
```

---

## Cấu trúc thư mục

```
AI RL/
├── env_ids.py          # Môi trường RL (20D obs space, reward function, MockIPBehavior)
├── train.py            # Script training PPO
├── infer.py            # Inference engine (đọc NIDS JSONL → quyết định → iptables)
├── policy_model.zip    # Model mặc định (best model từ training)
├── requirements.txt    # Python dependencies
├── runs/
│   └── run_20260305_081620_seed42/
│       ├── best_model.zip      ← model tốt nhất của run này
│       └── checkpoints/        ← checkpoints theo từng bước
└── Documents/          # Tài liệu đồ án
```

---

## Khởi động hệ thống (Live Demo)

### Bước 1 — Khởi động Mininet topology

Mở terminal mới:

```bash
cd /path/to/rl-defense-agent/containernet/containernet
sudo python3 test2.py
```

Đợi đến khi thấy `containernet>` prompt.
Sniffer tự động chạy trên interface `r-ext` → ghi ra `/tmp/sniffer_output.jsonl`.

### Bước 2 — Khởi động Web App (tùy chọn)

> Web app **không bắt buộc** để AI chạy và đưa ra quyết định.
> NIDS chỉ đọc HTTP request (không cần response), AI vẫn detect và block/redirect bình thường.
>
> Chỉ cần start nếu muốn demo end-to-end: attacker thấy nội dung honeypot thay vì webserver thật.

Trong cửa sổ `containernet>`, mở terminal riêng cho từng node:

```
xfce4 webserver honeypot
```

Trong cửa sổ **webserver**:
```bash
python3 /home/binhhl/Downloads/rl-defense-agent/containernet/web/web.py
```

Trong cửa sổ **honeypot**:
```bash
python3 /home/binhhl/Downloads/rl-defense-agent/containernet/web/web_honeypot.py
```

### Bước 3 — Khởi động AI Inference

Mở terminal mới:

```bash
cd "/path/to/rl-defense-agent/AI RL"
sudo -E python3 infer.py --watch /tmp/sniffer_output.jsonl
```

> `sudo -E` giữ môi trường Python của user (có stable-baselines3).

Mặc định dùng `policy_model.zip`. Chỉ định model cụ thể:

```bash
sudo -E python3 infer.py --watch /tmp/sniffer_output.jsonl \
  --model runs/run_20260305_081620_seed42/best_model
```

Dry-run (xem quyết định mà không thực thi iptables):

```bash
sudo -E python3 infer.py --watch /tmp/sniffer_output.jsonl --no-enforce
```

---

## Test AI hoạt động đúng

Tất cả lệnh tấn công chạy trong `containernet>`.
**Lưu ý:** `SSLKEYLOGFILE=/tmp/tls_keys.log` bắt buộc với HTTPS để NIDS giải mã TLS và tính được features L7 (F6–F20).

### Test 1 — Traffic bình thường (expect: Allow)

```
attacker SSLKEYLOGFILE=/tmp/tls_keys.log curl -k https://192.168.10.10/
attacker SSLKEYLOGFILE=/tmp/tls_keys.log curl -k https://192.168.10.10/products
attacker SSLKEYLOGFILE=/tmp/tls_keys.log curl -k https://192.168.10.10/about
```

> Dùng nhiều URL khác nhau để F6 (URLConcentration) thấp → AI nhận diện là bình thường.

### Test 2 — Brute Force HTTP (expect: Redirect → Block sau 60s)

```
attacker SSLKEYLOGFILE=/tmp/tls_keys.log python3 \
  /path/to/rl-defense-agent/containernet/containernet/brute_keepalive.py
```

### Test 3 — SYN Flood / DDoS (expect: Block)

```
attacker hping3 -S --flood -p 443 192.168.10.10
```

### Test 4 — SQL Injection (expect: Redirect)

```
attacker SSLKEYLOGFILE=/tmp/tls_keys.log sqlmap \
  -u "https://192.168.10.10/search?q=1" --batch --level=1 --risk=1
```

### Test 5 — XSS (expect: Redirect)

```
attacker SSLKEYLOGFILE=/tmp/tls_keys.log xsser \
  --url "https://192.168.10.10/search?q=XSS" -s --no-check-certificate
```

---

## Kiểm tra iptables (xác nhận AI đã thực thi)

Trong `containernet>`:

```
# Xem FORWARD chain (Block rules)
router iptables -L FORWARD -n --line-numbers

# Xem NAT PREROUTING (Redirect rules)
router iptables -t nat -L PREROUTING -n --line-numbers
```

Kết quả khi Block đang active:
```
1   DROP      all  --  10.0.10.10   0.0.0.0/0
```

Kết quả khi Redirect đang active:
```
1   REDIRECT  tcp  --  10.0.10.10   192.168.10.10   tcp dpt:443  redir ports 4443
```

### Gỡ rule (reset về ban đầu)

```
router iptables -D FORWARD 1
router iptables -t nat -D PREROUTING 1
```

---

## Training lại model

```bash
cd "/path/to/rl-defense-agent/AI RL"
python3 train.py
```

Model tốt nhất được lưu tại `runs/<run_id>/best_model.zip`.
Copy để dùng làm default:

```bash
cp runs/<run_id>/best_model.zip policy_model.zip
```

Xem training curves bằng TensorBoard:

```bash
python3 -m tensorboard.main --logdir "/path/to/rl-defense-agent/AI RL/runs"
# Mở http://localhost:6006
```

---

## Troubleshooting

| Lỗi | Nguyên nhân | Giải pháp |
|---|---|---|
| `ModuleNotFoundError: stable_baselines3` | sudo dùng Python của root | Dùng `sudo -E python3` |
| `nsenter: Permission denied` | Chưa có quyền root | Dùng `sudo -E python3` |
| AI luôn Redirect traffic bình thường | F6 cao vì chỉ hit 1 URL | Dùng nhiều URL khác nhau khi test bình thường |
| `Model not found` | Sai đường dẫn model | Kiểm tra `policy_model.zip` tồn tại hoặc dùng `--model` |

---

## Thông tin đồ án

- **Supervisor:** Mai Hoàng Đỉnh (dinhmh@fe.edu.vn)
- **Team Lead:** Hồ Lê Bình (binhhlse183564@fpt.edu.vn)
