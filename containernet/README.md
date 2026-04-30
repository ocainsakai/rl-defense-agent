# Containernet — Mô phỏng hạ tầng mạng + Demo attack scripts

Folder này dựng **toàn bộ môi trường mạng giả lập** (Mininet/Containernet) để
chạy end-to-end pipeline: attacker → router (sniffer + nginx + iptables) → 
webserver/honeypot, với RL agent enforce iptables runtime.

---

## 1. Cấu trúc folder

```
containernet/
├── src/                         (placeholder — chỉ chứa .DS_Store)
├── web/                         Backend apps (chạy trên webserver/honeypot nodes)
│   ├── web.py                   Webserver thật (listen 192.168.10.10:8080)
│   ├── web_honeypot.py          Honeypot decoy (listen 192.168.30.10:8081)
│   └── web_log.txt              Error log
└── containernet/                Mininet topology + demo scripts
    ├── test2.py                 Topology + Sniffer + Nginx + iptables baseline (404 dòng)
    ├── brute_keepalive.py       Brute-force tool dùng HTTP keep-alive
    ├── demo_menu.sh             Menu interactive 7 kịch bản tấn công
    ├── demo_brute_escalation.sh Demo escalation 4 phase (brute force)
    ├── demo_sqli_escalation.sh  Demo escalation cho SQLi
    ├── clear_crash.sh           Cleanup containers + Mininet state
    │
    └── (mininet/, util/, ansible/, assets/, doc/  — Containernet upstream library)
```

---

## 2. Hạ tầng chi tiết (`test2.py`)

### 2.1. Topology — 5 Mininet nodes + 1 host thực

```
Network ranges:
  10.0.10/24    attacker network
  10.0.99/24    management network (host thực ↔ router)
  192.168.10/24 webserver network
  192.168.20/24 wazuh management network
  192.168.30/24 honeypot network

       +-----------------------------+
       | root (host VM thực)         |
       | 10.0.99.1 / root-mgmt       |
       +-------------+---------------+
                     |
                     | r-mgmt (10.0.99.254)
                     v
       +-----------------------------+
       | router (LinuxRouter)        |
       |  - ip_forward=1             |
       |  - rp_filter=2 (loose)      |
       |  - nginx reverse proxy      |
       |  - sniffer NIDS             |
       |  - iptables enforcement     |
       +--+--------+--------+--------+
          |        |        |        |
   r-ext  |  r-web |r-wazuh |r-honey |
   (10.0  |(192.   |(192.   |(192.   |
   .10.254|168.10. |168.20. |168.30. |
   )      |1)      |1)      |1)      |
          |        |        |        |
          v        v        v        v
   +---------+ +---------+ +-------+ +----------+
   |attacker | |webserver| | wazuh | | honeypot |
   |10.0.10  | |192.168. | |192.   | |192.168.  |
   |.10/24   | |10.10/24 | |168.20 | |30.10/24  |
   |         | | :8080   | |.20/24 | | :8081    |
   |         | | (web.py)| |       | | (web_    |
   |         | |         | |       | | honeypot)|
   +---------+ +---------+ +-------+ +----------+
```

### 2.2. Vai trò từng node

| Node | IP | Interface | Vai trò |
|---|---|---|---|
| **router** | nhiều IP | r-ext, r-mgmt, r-web, r-wazuh, r-honey | Linux router với IP forwarding. Chạy nginx reverse proxy + iptables enforcement + NIDS sniffer. **Trung tâm enforcement của RL agent.** |
| **attacker** | 10.0.10.10 | eth1 | Container chạy curl/sqlmap/xsser/hping3/nmap để demo các tấn công. Default route via router (10.0.10.254). |
| **webserver** | 192.168.10.10 | eth1 | Container chạy `web/web.py` lắng nghe port 8080 — webserver thật (Tech Store, MySQL backend). |
| **honeypot** | 192.168.30.10 | eth1 | Container chạy `web/web_honeypot.py` lắng nghe port 8081 — decoy server (T3ch Stor3 fake) thu credential + payload attacker. |
| **wazuh** | 192.168.20.20 | eth1 | Container chạy Wazuh Manager (optional). |
| **root** | 10.0.99.1 | root-mgmt | Host VM thật (out-of-namespace) — quản lý lab, có thể curl từ host trực tiếp. |

### 2.3. Router — chi tiết enforcement (3 layer)

Router là **single chokepoint** — toàn bộ traffic attacker → backend đều qua đây.
Nó kết hợp 3 layer:

#### Layer A — IP forwarding + rp_filter loose

```python
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=2     # loose mode (cho phép asymmetric routing)
```

#### Layer B — iptables baseline (chạy 1 lần khi `test2.py` start)

**Default policy:** `FORWARD DROP` — chặn mặc định, chỉ cho phép qua các rule cụ thể.

```bash
# Cho phép connection đã established (response trả về)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow management từ host
iptables -A FORWARD -s 10.0.99.0/24 -d <subnets> -j ACCEPT

# Block attacker → wazuh (kể cả wazuh → attacker)
iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.20.20 -j DROP
iptables -A FORWARD -s 192.168.20.20 -d 10.0.10.0/24 -j DROP

# Allow internal nodes → Wazuh (cho log forwarding)
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.20.20 -j ACCEPT
iptables -A FORWARD -s 192.168.30.0/24 -d 192.168.20.20 -j ACCEPT

# Allow attacker → webserver/honeypot subnets (routing cơ bản)
iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.10.0/24 -j ACCEPT
iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.30.0/24 -j ACCEPT

# Allow webserver/honeypot → out (response)
iptables -A FORWARD -s 192.168.10.0/24 -j ACCEPT
iptables -A FORWARD -s 192.168.30.0/24 -j ACCEPT

# INPUT: cho nginx tiếp nhận trên ports 80, 443, 4443
iptables -A INPUT -i r-ext -p tcp --dport 80   -j ACCEPT
iptables -A INPUT -i r-ext -p tcp --dport 443  -j ACCEPT
iptables -A INPUT -i r-ext -p tcp --dport 4443 -j ACCEPT
```

#### Layer C — RL agent runtime enforcement

`infer.py` (RL agent) inject rules động vào router qua `nsenter -n -t {ROUTER_PID}`:

| Action | iptables rule |
|---|---|
| **Block** | `iptables -I FORWARD 1 -s <attacker_ip> -j DROP` |
| **RateLimit** | `iptables -I FORWARD 1 -s <attacker_ip> -m hashlimit --hashlimit-above 10/sec --hashlimit-mode srcip --hashlimit-name rl -j DROP` |
| **Redirect** | `iptables -t nat -I PREROUTING 1 -i r-ext -s <attacker_ip> -d 192.168.10.10 -p tcp --dport 443 -j REDIRECT --to-ports 4443` |
| **Allow** | KHÔNG có rule (default forward) |

### 2.4. Nginx reverse proxy (chạy trên router)

Lắng nghe 3 ports trên router, forward vào backend tương ứng:

| Listen | Server name | Upstream | Mục đích |
|---|---|---|---|
| 80 | 192.168.10.10 | redirect 301 → https | HTTP → HTTPS upgrade |
| 443 | 192.168.10.10 | http://192.168.10.10:8080 (web.py) | **Normal users** → webserver thật |
| 4443 | 192.168.10.10 | http://192.168.30.10:8081 (web_honeypot.py) | **Attacker bị Redirect** → honeypot |

Self-signed TLS certs sinh tự động cho 2 hostnames (192.168.10.10, 192.168.30.10).
Access log chi tiết tại `/tmp/router-nginx/logs/access.log` (định dạng `lab_detail`
chứa SNI, TLS version, request_id để correlate).

### 2.5. Sniffer NIDS (chạy trên router)

Sniffer **đứng trước nginx** — capture trên interface `r-ext` (input của attacker), 
trước khi packet vào iptables FORWARD/nginx:

```python
# test2.py:374-383
sniffer_cmd = (
    "python3 -c \""
    "from main import _run_realtime; "
    "_run_realtime('r-ext', 1.0, '/tmp/sniffer_output.jsonl', 'jsonl', "
    "keylog_file='/tmp/tls_keys.log')"
    "\""
)
router.popen(['bash', '-c', sniffer_cmd])
```

- Module: `System/main.py` (NIDS sniffer chính của project)
- Interface: `r-ext` (eth phía attacker)
- Window: 1 giây
- Output: `/tmp/sniffer_output.jsonl` (mỗi giây 1 dòng JSON với F1-F20)
- TLS decrypt: dùng `/tmp/tls_keys.log` (attacker phải set `SSLKEYLOGFILE=/tmp/tls_keys.log`
  trong curl để ghi session keys vào)

### 2.6. Đường đi packet attacker → backend (full flow)

```
[attacker 10.0.10.10] eth1
      |
      v send: HTTPS GET https://192.168.10.10/
      |
[router r-ext interface 10.0.10.254]
      |
      +--> [SNIFFER tshark trên r-ext]   <-- capture L3/L4 + L7 (TLS decrypt)
      |        |
      |        v
      |    /tmp/sniffer_output.jsonl     <-- 20 features per 1s window
      |        |
      |        v
      |    [infer.py read JSONL]
      |        |
      |        +--> RL model decide action
      |        +--> SafetyNet override
      |        +--> IPStateTracker (escalation 15s)
      |        +--> nsenter inject iptables rule vào router
      |
      v continue to FORWARD chain
      |
[router iptables FORWARD chain]
      |
      |  IF có rule Block (-j DROP)            --> packet bị drop, attacker không vào
      |  IF có rule RateLimit (hashlimit)      --> drop quá rate
      |  IF có rule Redirect (nat PREROUTING)  --> REDIRECT --to-ports 4443
      |  ELSE                                  --> ACCEPT (theo baseline)
      |
      v 
[router nginx reverse proxy]
      |
      +--> port 443 (normal traffic)  ---> http://192.168.10.10:8080 (webserver)
      +--> port 4443 (redirected)    ---> http://192.168.30.10:8081 (honeypot)
      |
      v 
[backend response] -- conntrack ESTABLISHED -- attacker
```

### 2.7. Lệnh launch

```bash
cd containernet/containernet
sudo python3 test2.py
```

Kết quả:
- Mininet topology dựng xong, 5 containers chạy
- iptables baseline applied trên router
- Nginx reverse proxy đang listen
- Sniffer popen background trên router → ghi `/tmp/sniffer_output.jsonl`
- xfce4-terminal mở cho 4 nodes: webserver, honeypot, attacker, router
- Mininet CLI prompt cho phép gõ command

---

## 3. `web/` — Backend apps

### `web.py` — Webserver thật (chạy trên node `webserver`, port 8080)

Flask/Python webserver mô phỏng "Tech Store":
- Endpoints: `/`, `/login`, `/register`, `/search`, `/products`, `/contact`
- Connect MySQL backend (vulnerable to SQLi by design — để test detect)
- Logging access vào file local

### `web_honeypot.py` — Honeypot decoy (chạy trên node `honeypot`, port 8081)

Webserver giả lập "T3ch Stor3" (đánh vần lệch):
- Cùng schema endpoint với `web.py` (login, search, products)
- Log mọi credential + payload attacker gửi (intel collection)
- Trả response giống thật để attacker tin là webserver thật
- Khi attacker bị Redirect, traffic vào đây thay vì `web.py`

### `web_log.txt`

Error log của webserver thật.

---

## 4. `brute_keepalive.py` — Brute-force tool

Python script dùng `requests.Session()` keep-alive để brute force `/login`.

**Đặc điểm thiết kế:**
- HTTP keep-alive → 1 TCP connection cho nhiều request → trigger F7 (HttpIatUniformity ≈ 1.0)
- Delay cố định 100ms → ~10 req/s, IAT đều
- Session recycle mỗi 5 request → tạo TCP connection mới (trigger Override 0 Redirect)
- Wordlist 20 password, lặp 1200 lần (~ 2 phút)

**Lệnh chạy (manual):**
```bash
python3 brute_keepalive.py
```

(Thường được gọi qua `demo_brute_escalation.sh`.)

---

## 5. Demo scripts (`.sh`)

### 5.1. `demo_menu.sh` — Menu tương tác (chạy từ node attacker)

Menu cho 7 kịch bản tấn công + 2 utilities:

| Phím | Kịch bản | Tool dùng | Action mong đợi |
|---|---|---|---|
| KC1 | Noisy normal | 16 curl parallel | RateLimit |
| KC2 | Brute force | `brute_keepalive.py` | Redirect |
| KC3 | SQL Injection | `sqlmap --delay=1` | Redirect → Block |
| KC4 | XSS | `xsser` | Redirect |
| KC5 | SYN Flood DDoS | `hping3 -S --flood` | Block |
| KC6 | Port Scan | `nmap` | Block |
| KC7a | C2 Beaconing | curl periodic | Allow (OOD) |
| KC7b | Path Traversal | curl với `../` | Allow (OOD) |
| **v** | Verify | curl test → check response | Show kết quả (honeypot/webserver/blocked) |
| **r** | Reset | xóa iptables rules trên router | Cleanup giữa các demo |

Chạy:
```bash
sudo bash demo_menu.sh
```

### 5.2. `demo_brute_escalation.sh` — Brute force escalation 4 phase

Demo full leo thang Allow → RateLimit → Redirect → Block:

1. **Phase 1**: 1 req/2s, URL đa dạng → F6=0 → **Allow**
2. **Phase 2**: 0.15s/req (~67 pps), URL khác nhau → **RateLimit**
3. **Phase 3**: `brute_keepalive.py` → F6=1.0, F7=1.0 → **Redirect** → tích lũy 12 windows → **Block**

Script poll `actions.log` real-time, hiển thị temporal state mỗi window. Tự dừng
khi `final_action_name=Block`.

```bash
sudo bash demo_brute_escalation.sh
```

### 5.3. `demo_sqli_escalation.sh` — SQLi escalation

Demo cho SQL Injection:

1. **Phase 1**: 10 normal requests → **Allow**
2. **Phase 2**: 6 SQLi payloads (OWASP CRS 942 patterns) → F13>0.08 → **Redirect** (Override 0)
3. **Phase 3**: `sqlmap --delay=1` chạy continuous → tích lũy session 12 windows → 
   `block_ready_latched=True` → RL **Block**

Script verify final action bằng curl test (response = honeypot / webserver / blocked).

```bash
sudo bash demo_sqli_escalation.sh
```

### 5.4. `clear_crash.sh` — Cleanup

Cleanup môi trường khi Mininet/Containernet crash hoặc giữa các test session:

```bash
sudo bash clear_crash.sh
```

Thực hiện:
- `docker stop` + `docker rm` các containers `mn.*`
- `mn -c` flush Mininet network state
- Xóa veth interfaces còn sót

---

## 6. `src/` — Placeholder

Folder hiện tại chỉ chứa `.DS_Store` (macOS metadata). Reserved cho future
extensions (custom topology helpers, additional attack tools).

---

## 7. Workflow chạy demo end-to-end

Cần 3 terminal chính trên host:

```
Terminal 1 (host, sudo):     cd containernet/containernet
                              sudo python3 test2.py
                              # → mở 4 xfce4-terminal cho webserver/honeypot/attacker/router
                              # → /tmp/sniffer_output.jsonl bắt đầu được sinh

Terminal 2 (host, sudo):     cd "AI RL"
                              sudo python3 infer.py \
                                  --watch /tmp/sniffer_output.jsonl \
                                  --model runs/run_34d_v13/best_model \
                                  --demo-safe
                              # → đọc JSONL real-time, predict action, inject iptables vào router

Terminal 3 (xfce4 attacker): sudo bash demo_brute_escalation.sh
                              # hoặc demo_sqli_escalation.sh / demo_menu.sh
```

Quan sát:
- **Terminal 3 (attacker)** hiển thị AI state real-time (poll `actions.log`)
- **Terminal 4 — xfce4 router** (optional): `watch -n 1 'iptables -L FORWARD -n'` xem rules thay đổi
- **Terminal 2 (infer)** log từng quyết định + override
- Webserver/Honeypot terminal: thấy access log realtime

Sau demo:
```bash
# Reset iptables giữa các demo
# (option [r] trong demo_menu.sh)

# Cleanup hoàn toàn
sudo bash clear_crash.sh
```

---

## 8. Dependencies

**Hệ thống:**
- Containernet (Mininet variant với Docker support)
- Docker daemon
- Python 3.10+
- xfce4-terminal (cho terminal cho các node)
- nginx (chạy trên router container)
- openssl (sinh self-signed certs)
- tshark (TLS decryption + L7 parsing)

**Tools tấn công (chạy trong attacker container):**
- `curl`, `sqlmap`, `xsser`, `hping3`, `nmap`

**Python packages:**
- `requests` (cho `brute_keepalive.py`)

---

## 9. Troubleshooting

| Vấn đề | Giải pháp |
|---|---|
| `test2.py` báo `iptables: Permission denied` | Chạy với `sudo` |
| Containers không start | `sudo bash clear_crash.sh` rồi thử lại |
| Sniffer không sinh JSONL | Check `tshark` đã cài, interface `r-ext` tồn tại, `_run_realtime` import OK |
| Demo script báo `actions.log not found` | Cần chạy `infer.py` (Terminal 2) trước khi chạy demo |
| TLS decryption fail (F12-F20 = 0) | Verify `/tmp/tls_keys.log` exists + chmod 666 + attacker set `SSLKEYLOGFILE` |
| Demo hang sau Block | Đã fix bằng `setsid + kill -9 -PGID` trong `demo_*_escalation.sh` |
| Curl từ host không reach webserver | Check route `192.168.10.0/24 via 10.0.99.254` trên host |
| nginx không start | `router nginx -t -c /tmp/router-nginx/conf/nginx.conf` test config |

---

## 10. Tham khảo

- Source pipeline RL: [`../AI RL/README.md`](../AI%20RL/README.md)
- Wazuh integration: [`../Wazuh/README.md`](../Wazuh/README.md)
- NIDS sniffer: [`../System/`](../System/)
