# RL Defense Agent (Capstone Project IAP491)

**Đề tài:** Nghiên cứu và phát triển AI Agent có khả năng tự phòng thủ thích ứng
trong môi trường mạng mô phỏng dựa trên kỹ thuật Reinforcement Learning.

---

## Giảng viên hướng dẫn

**GVHD: Mai Hoàng Đỉnh**

## Thành viên nhóm

| Vai trò | Họ tên | MSSV | Phụ trách |
|------|---------------|---------------|-----------------|
| **Leader** | **Hồ Lê Bình** | **SE183564** | AI Core, RL Algorithms, Core logic |
| Member | Nguyễn Hoàng Trí | SE183413 | Infrastructure, Attack Sim |
| Member | Phạm Tuấn Anh | SE183403 | SIEM (Wazuh), Dashboard |
| Member | Trịnh Nguyễn Yến Vy | SE183776 | Integration, Sniffer, Logging |

---

## 1. Tổng quan hệ thống

Dự án xây dựng một **AI Defense Agent thích ứng** được huấn luyện bằng
Reinforcement Learning (PPO). Agent vận hành trong một môi trường mạng mô phỏng
để tự động phát hiện và đối phó các tấn công mạng (DoS, Scanning, Brute-force,
SQLi, XSS) trong khi vẫn duy trì dịch vụ cho người dùng hợp lệ.

Agent có 4 hành động (action space):

| Action | Ý nghĩa | Cơ chế thực thi |
|--------|---------|------------------|
| `Allow` | Cho phép traffic đi qua | Không can thiệp |
| `RateLimit` | Giới hạn tốc độ | iptables `hashlimit` (10/sec) |
| `Redirect` | Chuyển hướng sang Honeypot | iptables NAT REDIRECT 443 → 4443 |
| `Block` | Chặn hoàn toàn | iptables DROP (FORWARD) |

---

## 2. Kiến trúc tổng quan

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
|                              |    34D obs = 20D + 10D + 4D      |
|                              |    PPO predict -> action         |
|                              |    -> iptables (Allow/RL/Redir/  |
|                              |       Block)                     |
|                              |                                  |
|                              +-- Wazuh Agent                    |
|                                   tail actions_wazuh.log        |
|                                   -> Manager + Dashboard        |
+----------------------------------------------------------------+
```

**Pipeline data:**

1. NIDS Sniffer tail interface `r-ext` → mỗi 1s ghi 20 features per IP vào JSONL
2. AI Agent tail JSONL → build 34D obs (20D NIDS + 10D temporal + 4D effect) → PPO predict
3. SafetyNet override + apply iptables rule trên router namespace
4. Wazuh tail `actions_wazuh.log` → Manager → Dashboard visualize + alert

---

## 3. Bản đồ folder

| Folder | Vai trò | README |
|--------|---------|---------|
| [`AI RL/`](AI%20RL/README.md) | Training PPO + inference + benchmark + tools | [README](AI%20RL/README.md) |
| [`System/`](System/README.md) | NIDS Sniffer + 20 features extraction | [README](System/README.md) |
| [`containernet/`](containernet/README.md) | Mininet topology + router + nginx + demo scripts | [README](containernet/README.md) |
| [`Wazuh/`](Wazuh/README.md) | SIEM integration: decoder, rules, dashboard | [README](Wazuh/README.md) |
| [`datasets/`](datasets/) | Public datasets: CIC-IDS2017, CIC-DDoS2019, CSE-CIC-IDS2018 | per-dataset READMEs |
| [`Document/`](Document/) | Tài liệu tham khảo (papers, reports, references) | — |
| `start_demo.sh` | Wizard 8 bước khởi động demo end-to-end | — |

---

## 4. Quick start

### 4.1. Cài đặt môi trường

```bash
# Python dependencies cho AI RL agent
cd "AI RL" && pip3 install -r requirements.txt

# Containernet đã pre-built trong containernet/containernet/
# Wazuh: theo Wazuh/INSTALLATION.md (cài Manager + Indexer + Dashboard + Agent)
```

### 4.2. Chạy demo end-to-end (khuyến nghị)

```bash
sudo bash start_demo.sh
```

Wizard 8 bước có hướng dẫn chi tiết:
1. Dọn dẹp môi trường
2. Khởi động Mininet topology (test2.py)
3. 4 node terminals tự mở (router, attacker, webserver, honeypot)
4. Khởi động Webserver (port 8080)
5. Khởi động Honeypot (port 8081)
6. Khởi động AI Defense Agent (`infer.py`)
7. Monitor iptables real-time
8. Demo menu (sqlmap, xsser, brute-force, port-scan, ...)

### 4.3. Train lại model

```bash
cd "AI RL"
python3 train.py --timesteps 500000 --seed 42
# Output: runs/run_{timestamp}_seed42/best_model.zip
```

### 4.4. Benchmark (PPO vs A2C vs DQN)

```bash
cd "AI RL/Benchmark"
./run_benchmark.sh
# Output: results/benchmark_results.json + charts/
```

---

## 5. Model production

| Item | Giá trị |
|------|---------|
| Path | `AI RL/runs/run_34d_v13/best_model.zip` |
| Algorithm | PPO (Stable-Baselines3) |
| Training | 500,000 timesteps, seed 42, ~3 phút CPU |
| Eval reward | 58.68 (mean qua 25 evaluations) |
| Observation | 34D = 20D NIDS + 10D temporal + 4D effect (nginx feedback) |
| Action | Discrete(4): Allow / RateLimit / Redirect / Block |
| Action distribution thực tế | Allow ~47%, Redirect ~41%, Block ~12%, RateLimit ~0% |

Chi tiết: [`AI RL/README.md` § 2](AI%20RL/README.md)

---

## 6. Stack công nghệ

- **RL**: PPO — Stable-Baselines3, Gymnasium
- **Network simulation**: Containernet + Mininet
- **NIDS**: Scapy + ModSecurity CRS-3 (offline rule scoring) + tshark (HTTPS L7)
- **Firewall**: iptables (DROP, hashlimit, NAT REDIRECT)
- **Reverse proxy**: Nginx (443 → webserver, 4443 → honeypot)
- **SIEM**: Wazuh (Manager + Indexer + Dashboard)
- **Visualization**: rich, matplotlib, Wazuh Dashboard, TensorBoard

---

## 7. Tài liệu chi tiết

| Tài liệu | Nội dung |
|----------|----------|
| [`AI RL/README.md`](AI%20RL/README.md) | RL agent: train, infer (cách build 34D), benchmark, model production |
| [`System/README.md`](System/README.md) | NIDS sniffer: 20 features, plugin architecture, output format |
| [`containernet/README.md`](containernet/README.md) | Mininet topology, router 3-layer enforcement, nginx, demo scripts |
| [`Wazuh/README.md`](Wazuh/README.md) | SIEM overview, decoder + rules, dashboard |
| [`Wazuh/INSTALLATION.md`](Wazuh/INSTALLATION.md) | Hướng dẫn cài Wazuh stack chi tiết |
| [`AI RL/Documents/BENCHMARK_METHODOLOGY.md`](AI%20RL/Documents/BENCHMARK_METHODOLOGY.md) | 3-layer benchmark methodology + kết quả CIC-IDS2017/2018/DDoS2019 |
| [`AI RL/Documents/INSPECT_TRAIN_QA.md`](AI%20RL/Documents/INSPECT_TRAIN_QA.md) | Q&A về RL concepts + công cụ inspect_train |

### References học thuật (`Document/References/`)

- NIST SP 800-189 — Resilient Interdomain Traffic Exchange
- DBIR 2025 — Verizon Data Breach Investigations Report
- IBM Cost of a Data Breach Report 2025
- Paxson — Network Intrusion Detection: Evasion, Traffic Normalization
- Wang et al. (2002) — SYN-ACK Ratio for SYN Flood Detection
- RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations
- 2018CFIS_SAE — CFIS approach SAE-based IDS

### Tài liệu OWASP / CRS

- `crs-paranoia-levels-vi.csv` — paranoia levels của ModSecurity CRS-3
- `crs-rules-list-vi.csv` — danh sách rules
- `crs-rules-overview-vi.md` — tổng quan rule engine
- `REQUEST-941-APPLICATION-ATTACK-XSS.conf` — rule XSS
- `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` — rule SQLi

---
