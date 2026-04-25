# Kịch bản Demo Live-Test — AI RL Defense Agent

> **Mục tiêu**: Chứng minh hệ thống có thể tự động phân loại và phản hồi 5 loại lưu lượng:
> benign → Allow | noisy → RateLimit | brute_force/sqli/xss → Redirect | scan/syn_flood → Block

---

## Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│                        Mininet (test2.py)                       │
│                                                                 │
│  [attacker]──────►[router]──────►[webserver]                    │
│  10.0.10.10   r-ext  │  r-web    192.168.10.10:8080 (web.py)   │
│                       │                                         │
│                    r-honey──────►[honeypot]                     │
│                               192.168.30.10:8081 (web_honeypot) │
│                                                                 │
│  NIDS Sniffer: r-ext → /tmp/sniffer_output.jsonl                │
│  AI Agent:    infer.py watch → iptables trên router namespace   │
└─────────────────────────────────────────────────────────────────┘
```

**Luồng traffic**:
- Attacker → `https://192.168.10.10/` → NGINX router (port 443) → webserver:8080
- Khi AI quyết định **Redirect**: router thêm PREROUTING rule → attacker bị đẩy sang honeypot:8081
- Khi AI quyết định **Block**: router DROP packet của attacker

---

## Chuẩn bị trước khi demo

### Yêu cầu hệ thống
- Python 3.10+, Mininet/Containernet, nginx, hping3, nmap, sqlmap, xsser
- stable-baselines3, numpy<2, xfce4-terminal

### Xác nhận model sẵn sàng
```bash
ls -lh "/home/binhhl/Downloads/rl-defense-agent/AI RL/policy_model.zip"
# Phải tồn tại, khoảng 400-500KB
```

Nếu chưa có, train trước:
```bash
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"
python3 train.py --timesteps 300000 --seed 42
# Model tự động save thành policy_model.zip sau khi train xong
```

---

## BƯỚC 0 — Dọn dẹp môi trường (chạy trước mỗi demo)

Mở **1 terminal bình thường** (không phải node), chạy:

```bash
sudo mn -c 2>/dev/null
sudo pkill -f "web.py" 2>/dev/null
sudo pkill -f "infer.py" 2>/dev/null
> /tmp/sniffer_output.jsonl
echo "Dọn dẹp xong."
```

---

## BƯỚC 1 — Terminal Mininet: Khởi động Topology

Mở **Terminal 1** (terminal bình thường, root):

```bash
cd /home/binhhl/Downloads/rl-defense-agent
sudo python3 -E test2.py
```

**Chờ đến khi thấy:**
```
*** Running CLI
mininet>
```

> **Lưu ý**: `test2.py` tự động khởi động NIDS sniffer bên trong router namespace — ghi vào `/tmp/sniffer_output.jsonl`. Không cần chạy `System/main.py` riêng lẻ.

---

## BƯỚC 2 — Mở terminal riêng cho từng Node

Từ **Mininet CLI**, mở xfce4-terminal cho từng node bằng cú pháp `nodename xfce4-terminal &`:

```
mininet> webserver xfce4-terminal --disable-server --title="Node: webserver" &
mininet> honeypot xfce4-terminal --disable-server --title="Node: honeypot" &
mininet> attacker xfce4-terminal --disable-server --title="Node: attacker" &
mininet> router xfce4-terminal --disable-server --title="Node: router" &
```

> **Quan trọng**: Phải dùng cú pháp `nodename xfce4-terminal &` (gõ từng dòng), KHÔNG gộp thành một dòng. Cách này đảm bảo terminal chạy đúng **network namespace của node đó**.

**Kiểm tra namespace sau khi mở** — trong từng terminal vừa mở, gõ:
```bash
# Terminal attacker phải thấy:
ip addr show eth1
# → inet 10.0.10.10/24   ← đúng namespace

# Terminal webserver phải thấy:
ip addr show eth1
# → inet 192.168.10.10/24  ← đúng namespace

# Terminal honeypot phải thấy:
ip addr show eth1
# → inet 192.168.30.10/24  ← đúng namespace
```

> Nếu thấy interface khác (ví dụ `ens33`, `eth0`, `root-mgmt`) → terminal đang chạy ở **HOST namespace**, traffic sẽ không đi qua `r-ext` và sniffer sẽ không bắt được.

---

## BƯỚC 3 — [Node: webserver] Khởi động Web Server

Trong cửa sổ terminal **webserver**:

```bash
python3 /home/binhhl/Downloads/rl-defense-agent/containernet/web/web.py
```

**Output mong đợi:**
```
 * Running on http://0.0.0.0:8080
 * Debug mode: on
```

**Xác nhận từ terminal attacker** (qua nginx HTTPS):
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk "https://192.168.10.10/" | grep -o "Tech Store"
# → Tech Store
```

---

## BƯỚC 4 — [Node: honeypot] Khởi động Honeypot

Trong cửa sổ terminal **honeypot**:

```bash
python3 /home/binhhl/Downloads/rl-defense-agent/containernet/web/web_honeypot.py
```

**Output mong đợi:**
```
 * Running on http://0.0.0.0:8081
 * Debug mode: on
```

**Xác nhận từ terminal attacker** (qua nginx HTTPS port 4443 — luồng honeypot):
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk "https://192.168.30.10" | grep -o "T3ch Stor3"
# → T3ch Stor3  (honeypot dùng tên khác để phân biệt)
```

---

## BƯỚC 5 — Terminal mới (VM host): Khởi động AI Defense Agent

Mở **Terminal mới** (không phải node Mininet, chạy trên VM host):

```bash
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"
sudo python3 infer.py --watch /tmp/sniffer_output.jsonl --model runs/run_final_v4/best_model --demo-safe

```

**Output mong đợi:**
```
======================================================================
IDS DEFENSE AGENT — NIDS 20D INFERENCE ENGINE
======================================================================

[+] Model loaded from ./policy_model.zip
[+] Action enforcement: ON (iptables via nsenter)
[*] Watching /tmp/sniffer_output.jsonl
[*] Writing actions to actions.log
[*] Mode: from-begin

[*] Waiting for new NIDS data...
```

> **Dry-run mode** (in action ra màn hình, không thực thi iptables — dùng khi demo trên máy không có Mininet đang chạy):
> ```bash
> python3 infer.py --watch /tmp/sniffer_output.jsonl --from-begin --no-enforce
> ```

---

## BƯỚC 6 — [Node: router] Monitor iptables realtime

Trong cửa sổ terminal **router**:

```bash
watch -n 1 "echo '=== IPTABLES FORWARD ===' && iptables -L FORWARD -n --line-numbers && echo '' && echo '=== NAT PREROUTING (Redirect rules) ===' && iptables -t nat -L PREROUTING -n --line-numbers"
```

Terminal này giúp quan sát ngay lập tức mỗi khi AI thêm/xóa rule iptables.

---

## BƯỚC 7 — Terminal mới (VM host): Monitor AI Actions Log

Mở **thêm 1 terminal** trên VM host:

```bash
tail -f "/home/binhhl/Downloads/rl-defense-agent/AI RL/actions.log"
```

Output mỗi dòng là 1 quyết định AI:
```
{"timestamp": 1741..., "src_ip": "10.0.10.10", "rl_action": 3, "rl_action_name": "Block", "final_action": 3, "final_action_name": "Block"}
```

---

## CÁC KỊCH BẢN TẤN CÔNG

> Tất cả lệnh tấn công chạy trong terminal **[Node: attacker]**

---

### Kịch bản 1: Traffic Bình thường (Benign → Allow)

**Mục tiêu**: AI nhận ra traffic bình thường, không chặn.

Trong terminal **attacker**:
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/" -s -o /dev/null -w "%{http_code}\n"
SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/login" -s -o /dev/null -w "%{http_code}\n"
SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/?search=laptop" -s -o /dev/null -w "%{http_code}\n"
```

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Allow      → Allow
```

**Verify** (terminal attacker): Vẫn nhận được HTML của "Tech Store" (webserver thật).

---

### Kịch bản 2: Traffic Ồn ào (Noisy Normal → RateLimit)

**Mục tiêu**: User browse liên tục nhiều request/giây nhưng không tấn công → AI giới hạn tốc độ thay vì block.

> **Quan trọng**: Phải trải request ra nhiều URL khác nhau (`?search=product$i`).
> Nếu spam cùng 1 URL (`/`) → **F6 (URLConcentration) ≈ 1.0** → AI nhận dạng là Brute Force → **Redirect** thay vì RateLimit.

Trong terminal **attacker**:
```bash
for i in $(seq 1 60); do
  SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/?search=product$i" -s -o /dev/null
done
```

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:RateLimit  → RateLimit
```

**Verify bước 0 — Kiểm tra đúng namespace trước** (terminal **attacker**):
```bash
ip addr show eth1
# Phải thấy: 10.0.10.10/24
# Nếu thấy địa chỉ khác (hoặc không thấy eth1) → terminal sai namespace
# → Quay lại Mininet CLI, chạy: attacker xfce4-terminal &
```

**Verify bước 1 — Xác nhận rule tồn tại** (terminal **router**):
```bash
iptables -L FORWARD -n -v | grep hashlimit
# → Thấy dòng này = đang bị RateLimit:
#   pkts bytes  DROP  all  10.0.10.10   limit: above 2/sec burst 5
#
# Phân biệt với Block (không có chữ "limit"):
#   pkts bytes  DROP  all  10.0.10.10   (không có "limit")
```

**Verify bước 2 — Test effect** (terminal **attacker**):
```bash
# Dùng nhiều URL khác nhau để không trigger Brute Force (F6 thấp)
for i in $(seq 1 10); do
  SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk -o /dev/null \
    -w "$i: %{http_code} (%{time_total}s)\n" \
    --max-time 1 "https://192.168.10.10/?p=$i"
  sleep 0.1
done
# Kết quả mong đợi:
# 1-2:  200 (chậm ~0.4-0.8s) ← packet bị DROP, TCP retransmit làm chậm 40-80×
# 3-10: 200 (~0.01s)          ← keep-alive tái dùng connection đã thiết lập
```

> **Giải thích**: hashlimit DROP **packets** (không phải connection) → TCP layer tự retry sau ~200ms.
> Biểu hiện: req 1-2 chậm rõ rệt (0.4-0.8s) so với bình thường (0.01s) — đó chính là throttling.
> Block mới là 000 (connection bị drop hoàn toàn).

**Verify bước 3 — Xem counter packets bị DROP** (terminal **router**):
```bash
watch -n 1 "iptables -L INPUT -n -v | grep hashlimit"
# Cột pkts tăng = số packet bị DROP bởi hashlimit
# Gửi thêm request từ attacker và xem số này tăng
```

> **Lưu ý**: Nếu tất cả request đều 200 OK → kiểm tra lại namespace (bước 0).
> Traffic qua sai namespace sẽ bypass FORWARD chain và không bị ảnh hưởng bởi hashlimit rule.

---

### Kịch bản 3: Brute Force Login (→ Redirect sang Honeypot)

**Mục tiêu**: Tool brute force POST /login liên tục → AI phát hiện F6 (URLConcentration) cao + F8 (RequestSizeUniformity) cao, redirect.

**Cách 1 — Brute force thông thường** (trong terminal **attacker**):
```bash
for i in $(seq 1 80); do
  SSLKEYLOGFILE=/tmp/tls_keys.log curl -k -s -o /dev/null \
    -X POST "https://192.168.10.10/login" \
    -d "username=admin&password=pass$i"
done
```

**Cách 2 — Keep-alive brute force** (kích hoạt F7 - HTTP IAT Uniformity, trong terminal **attacker**):
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log python3 brute_keepalive.py
```

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Redirect   → Redirect
```

**Verify redirect** (terminal **attacker**):
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/" 2>&1 | grep -o "T3ch Stor3"
# → T3ch Stor3  (đang nhận trang honeypot thay vì webserver thật)
```

**Escalation tự động sau 15 giây** nếu brute force tiếp tục:
```
[ESCALATE] 10.0.10.10: Redirect → Block (persisted 16s > 15s)
```

---

### Kịch bản 4: SQL Injection (→ Redirect sang Honeypot)

**Mục tiêu**: sqlmap tấn công → AI phát hiện SQLi features (F12-F17), redirect.

Trong terminal **attacker**:
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log \
sqlmap -u "https://192.168.10.10/?search=test" \
  --batch --level=1 --risk=1 \
  --ignore-code=401 --no-cast
```

```bash
SSLKEYLOGFILE=/tmp/tls_keys.log \
sqlmap -u "https://192.168.10.10/?search=test" \
  --batch --level=1 --risk=1 \
  --ignore-code=401 --no-cast \
  --delay=1
```

```bash
SSLKEYLOGFILE=/tmp/tls_keys.log sqlmap \
  -u "https://192.168.10.10/?search=test" \
  --batch --level=1 --risk=1 --ignore-code=401 --no-cast \
  -p search --threads=1 2>&1 | tail -5
```


**Features kích hoạt**:
- F12 (SqlSpecialChar) > 0 — ký tự `'`, `"`, `;`
- F13 (CrsSqliScore) ≈ 5.0 — CRS ModSecurity score
- F14 (SqlUnionSelect) > 0 — payload `UNION SELECT`
- F15 (SqlComment) > 0 — payload `--`, `#`

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Redirect   → Redirect
```

**Verify** (terminal **attacker**):
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/" 2>&1 | grep -o "T3ch Stor3"
# → T3ch Stor3  (honeypot)
```

---

### Kịch bản 5: XSS Attack (→ Redirect sang Honeypot)

**Mục tiêu**: XSSer tấn công search form → AI phát hiện XSS features (F18-F20), redirect.

Trong terminal **attacker**:
```bash
cd /tmp/xsser
SSLKEYLOGFILE=/tmp/tls_keys.log python3 xsser \
    --url "https://192.168.10.10/?search=XSS" \
    -p "search=XSS" \
    --auto --delay=1
```

**Features kích hoạt**:
- F18 (CrsXssScore) ≈ 1.6 — CRS XSS detection score
- F19 (JsFunctionCall) > 0 — `alert()`, `eval()`
- F20 (HtmlEventHandler) > 0 — `onerror=`, `onload=`

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Redirect   → Redirect
```

---

### Kịch bản 6: SYN Flood DDoS (→ Block)

**Mục tiêu**: hping3 gửi hàng trăm SYN packet/giây → AI phát hiện F1 (PacketRate) cao + F2 (SynAckRatio) cao, Block.

Trong terminal **attacker**:
```bash
hping3 -S -p 443 --flood -c 500 192.168.10.10
```

**Features kích hoạt**:
- F1 (PacketRate) > 200 pps → normalized ≈ 0.7+
- F2 (SynAckRatio) > 10 → normalized ≈ 0.8+
- F9 (AvgPayloadSize) ≈ 0 (SYN không có payload)

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Block      → Block
```

**Verify** (terminal **router** — `watch iptables`):
```
DROP  all  --  10.0.10.10  anywhere
```

Webserver vẫn accessible từ VM host (chỉ attacker bị block):
```bash
curl -k "https://192.168.10.10/" -s -o /dev/null -w "%{http_code}\n"
# → 200
```

---

### Kịch bản 7: Port Scan (→ Block)

**Mục tiêu**: nmap scan nhiều port → F5 (DistinctPorts) cao + F11 (PacketsPerPort) cao.

Trong terminal **attacker**:
```bash
nmap -sS -T4 -p 1-1000 192.168.10.10
```

**Features kích hoạt**:
- F5 (DistinctPorts) > 100 → normalized ≈ 0.8+
- F4 (RstRatio) > 0.3 — nhiều port đóng → RST response

**Kết quả mong đợi** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Block      → Block
```

---

## Reset giữa các kịch bản

Trong terminal **router**, chạy để **chỉ xóa các rule AI đã áp lên attacker** — baseline rules của test2.py giữ nguyên:

```bash
IP=10.0.10.10
# Xóa rule trên cả INPUT và FORWARD (traffic bị DNAT về nginx local → INPUT chain)
for i in $(seq 1 8); do
  iptables -D INPUT   -s $IP -j DROP 2>/dev/null
  iptables -D FORWARD -s $IP -j DROP 2>/dev/null
  iptables -D INPUT   -s $IP -m hashlimit \
    --hashlimit-name rl_10_0_10_10 \
    --hashlimit-above 2/sec --hashlimit-burst 5 -j DROP 2>/dev/null
  iptables -D FORWARD -s $IP -m hashlimit \
    --hashlimit-name rl_10_0_10_10 \
    --hashlimit-above 2/sec --hashlimit-burst 5 -j DROP 2>/dev/null
done; true
iptables -t nat -D PREROUTING -i r-ext -s $IP \
  -d 192.168.10.10 -p tcp --dport 443 \
  -j REDIRECT --to-ports 4443 2>/dev/null; true
echo "Reset xong — attacker được Allow lại"
# Verify sạch:
iptables -L INPUT   -n | grep $IP
iptables -L FORWARD -n | grep $IP
```

> **Lý do cần xóa cả INPUT**: traffic từ attacker được DNAT về nginx local (10.0.10.254:443) → đi vào INPUT chain, không phải FORWARD. Block/RateLimit phải áp trên cả hai chain.

---

## Tổng quan các terminal cần mở

| Terminal | Chạy ở đâu | Lệnh | Mục đích |
|---|---|---|---|
| **Terminal 1** | VM host (root) | `sudo python3 test2.py` | Mininet topology + NIDS sniffer |
| **xfce4 webserver** | Node webserver | `python3 web.py` | Webserver thật port 8080 |
| **xfce4 honeypot** | Node honeypot | `python3 web_honeypot.py` | Honeypot port 8081 |
| **xfce4 attacker** | Node attacker | *(các lệnh tấn công)* | Thực hiện tấn công |
| **xfce4 router** | Node router | `watch -n1 iptables ...` | Theo dõi firewall rules |
| **Terminal 2** | VM host (root) | `sudo python3 infer.py ...` | AI Defense Agent |
| **Terminal 3** | VM host | `tail -f actions.log` | Theo dõi AI decisions |

---

## Bảng tổng hợp kết quả mong đợi

| Kịch bản | Tool | Features chính | Action AI | Verify |
|---|---|---|---|---|
| Benign | curl thông thường | F1≈8pps, F6≈0 | **Allow** | Website truy cập OK |
| Noisy Normal | curl lặp lại ~30pps | F1≈30pps | **RateLimit** | iptables hashlimit |
| Brute Force | curl -X POST lặp | F6≈1.0, F8≈0.9 | **Redirect** | Response từ honeypot |
| Brute Force (keepalive) | brute_keepalive.py | F7≈0.85 | **Redirect** | Response từ honeypot |
| SQLi | sqlmap | F13≈5.0, F14>0 | **Redirect** | Response từ honeypot |
| XSS | xsser | F18≈1.6, F19>0 | **Redirect** | Response từ honeypot |
| SYN Flood | hping3 --flood | F1>200, F2>10 | **Block** | iptables DROP |
| Port Scan | nmap -sS | F5>100, F11>50 | **Block** | iptables DROP |

---

## Troubleshooting

### infer.py báo "Model not found"
```bash
ls "/home/binhhl/Downloads/rl-defense-agent/AI RL/policy_model.zip"
# Nếu không có → train lại:
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"
python3 train.py --timesteps 300000 --seed 42
```

### Sử dụng best_model từ run cụ thể
```bash
sudo python3 infer.py --watch /tmp/sniffer_output.jsonl \
    --model "runs/run_final_v4/best_model" \
    --from-begin
```

### AI luôn trả về Allow (model không nhận feature)
Kiểm tra NIDS có đang ghi không (terminal VM host):
```bash
tail -5 /tmp/sniffer_output.jsonl
# Phải có JSON với F1, F2... keys
# Nếu rỗng: sniffer chưa chạy hoặc không bắt được traffic
```

Kiểm tra TLS keylog — cần thiết để giải mã F6-F20:
```bash
wc -l /tmp/tls_keys.log
# → Phải > 0 sau khi chạy curl với SSLKEYLOGFILE=
```

### xfce4-terminal không mở được
Cần DISPLAY được set (cần GUI/X11):
```bash
echo $DISPLAY
# Phải có giá trị, ví dụ: :0 hoặc :1
# Nếu không có: export DISPLAY=:0
```

Hoặc nếu chạy với sudo mà DISPLAY bị mất:
```bash
sudo DISPLAY=:0 python3 containernet/containernet/test2.py
```

### iptables không được apply (nsenter fail)
infer.py cần sudo để nsenter vào router namespace:
```bash
sudo python3 infer.py --watch /tmp/sniffer_output.jsonl ...
```

Hoặc test dry-run trước để xem action mà không cần quyền:
```bash
python3 infer.py --watch /tmp/sniffer_output.jsonl --no-enforce
```

### Kiểm tra action thủ công (Interactive Mode)
```bash
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"
python3 infer.py --interactive --no-enforce
```
Paste JSON test:
```json
{"src_ip": "10.0.10.10", "F1 - PacketRate": 350, "F2 - SynAckRatio": 15, "F5 - DistinctPorts": 1}
```
→ Mong đợi: `Block`

```json
{"src_ip": "10.0.10.10", "F1 - PacketRate": 8, "F6 - URLConcentration": 0.05}
```
→ Mong đợi: `Allow`

Lệnh TensorBoard

cd "AI RL"
tensorboard --logdir runs/run_final_v4/tb
Sau đó mở browser: http://localhost:6006

Nếu muốn xem tất cả các run cùng lúc để so sánh:

tensorboard --logdir "AI RL/runs"


tail -f /tmp/sniffer_output.jsonl | python3 -c "
import sys,json
for l in sys.stdin:
    r=json.loads(l)
    if r.get('F5 - DistinctPorts',0) > 5:
        print(f'src={r[\"src_ip\"]} F5={r[\"F5 - DistinctPorts\"]:.0f} F1={r[\"F1 - PacketRate\"]:.0f}')
"

---

## Known Issues (cần fix sau demo)

### [BUG] curl benign lần 2 bị RateLimit do tshark enrich timing

**Triệu chứng:** Payload `curl -sk https://192.168.10.10/` lần 1 → Allow, lần 2 → RateLimit.

**Nguyên nhân:** HTTPS curl lần 2 dùng TLS session resumption (không full handshake) → packet đến và đi rất nhanh → tshark chưa kịp decrypt và enrich F6/F9 trước khi NIDS window 1s đóng → F6=0.0, F9=0.0 được emit. Model thấy F1≈19 pps + F6=0 → nhầm với noisy user → RateLimit.

Lần 1 chậm hơn vì full TLS handshake → tshark có đủ thời gian enrich → F6=1.0, F9=1.18 → Allow.

**Workaround tạm thời cho demo:** Thêm `--no-keepalive` để force new TLS handshake mỗi lần:
```bash
SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk --no-keepalive "https://192.168.10.10/" | grep -o "Tech Store"
```

**Fix đúng (TODO):** Tăng delay giữa tshark enrich buffer flush và NIDS window emit trong `System/main.py`, hoặc dùng sliding window thay vì tumbling window để L7 features kịp được ghi vào window hiện tại.

---

## ACT 8 — Tấn công Ngoài Vùng Train: AI Generalize Như Thế Nào?

> **Mục tiêu**: Trả lời câu hỏi "Nếu gặp tấn công chưa từng train thì AI xử lý ra sao?"

### Giải thích tổng quát

AI được train với 6 loại traffic: `benign`, `noisy_normal`, `scan`, `syn_flood`, `brute_force`, `sqli_xss`.

Khi gặp tấn công **chưa từng train**, AI **không crash**. Thay vào đó:
- Nó nhìn vào **đặc điểm 20 chiều feature** của traffic đó
- Nếu feature gần với loại đã biết → áp dụng hành động tương tự
- Nếu feature không rõ ràng → conservative action (Allow hoặc RateLimit)

Đây là **generalization** — AI không cần biết "tên" tấn công, chỉ cần nhận diện đặc điểm traffic.

---

### Kịch bản 8a — HTTP Slowloris (chưa train)

**Bản chất**: Giữ nhiều TCP connection mở lâu, gửi header cực chậm → server cạn socket pool.

**Feature signature**:
- F1 (PacketRate): vừa phải — không phải flood rõ ràng
- F2 (SynAckRatio): cao — nhiều SYN không có ACK tương ứng
- F3 (InterArrivalTime): rất cao — gửi cố tình chậm

**Gần nhất với**: `syn_flood` (đặc điểm SYN bất thường)

```bash
# Trong terminal attacker — simulate slow connections bằng hping3
hping3 -S -p 443 -i u200 --count 500 192.168.10.10
# Gửi SYN chậm liên tục → F2 tăng → AI nhận dạng network-layer threat
```

**Kết quả kỳ vọng** (Terminal infer.py):
```
[ts] 10.0.10.10      | RL:Block → Block
```

**Giải thích**: Dù không biết "Slowloris", AI thấy F2 (SynAckRatio) và F1 bất thường → nhận dạng gần `syn_flood` → Block.

---

### Kịch bản 8b — C2 Beaconing / Malware Callback (chưa train)

**Bản chất**: Malware sau khi xâm nhập sẽ gửi request định kỳ về C2 server để nhận lệnh — pattern rất đều đặn, traffic nhỏ, ẩn trong HTTPS bình thường.

**Feature signature**:
- F1 (PacketRate): **rất thấp** — chỉ 1 request mỗi 8-10 giây
- F3 (InterArrivalTime): **rất cao và đều đặn** — khoảng cách giữa request gần như bằng nhau
- F7 (HttpIatUniformity): **rất cao** — timing uniform (khác hẳn human browsing)
- F6 (URLConcentration): **= 1.0** — malware hardcode 1 endpoint cố định `/beacon`, 100% request vào đó

**Gần nhất với**: Không rõ ràng — F1 thấp, không có L7 attack features

```bash
# Trong terminal attacker — simulate C2 beacon mỗi 8 giây
for i in $(seq 1 15); do
  SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk \
    "https://192.168.10.10/beacon?id=c2_$(hostname)&seq=$i" \
    -o /dev/null
  sleep 8
done
# Chạy ~2 phút → NIDS capture đủ window
```

**Kết quả kỳ vọng**:
```
[ts] 10.0.10.10      | RL:Allow → Allow
# hoặc
[ts] 10.0.10.10      | RL:RateLimit → RateLimit
```

**Giải thích — honest limitation**: C2 beaconing gửi 1 request mỗi 8 giây → mỗi window 1 giây chỉ có 1 request → URLConcentration không được tính (cần ≥3 request để có ý nghĩa thống kê). F1 rất thấp, không có SQLi/XSS → AI không thấy dấu hiệu nguy hiểm → Allow. Đây là giới hạn của network-volume IDS: C2 beaconing ẩn trong HTTPS traffic thưa thớt, cần behavioral analysis theo thời gian mới phát hiện được.

---

### Kịch bản 8c — Credential Stuffing (chưa train, khác brute_force)

**Bản chất**: Thử nhiều username/password khác nhau từ database leak — khác brute_force (chỉ thử 1 tài khoản).

**Feature signature**:
- F6 (URLConcentration): cao — toàn request đến `/login`
- F7 (HttpIatUniformity): thấp — gửi đều đặn tự động
- F1 (PacketRate): vừa phải

**Gần nhất với**: `brute_force`

```bash
# Trong terminal attacker
for i in $(seq 1 80); do
  SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk -X POST \
    "https://192.168.10.10/login" \
    -d "username=user$i&password=pass$i" -o /dev/null
done
```

**Kết quả kỳ vọng**:
```
[ts] 10.0.10.10      | RL:Redirect → Redirect
```

**Giải thích**: F6 cao (toàn `/login`) → AI nhận dạng gần `brute_force` → Redirect sang honeypot — đúng hướng dù chưa train Credential Stuffing.

---

### Kịch bản 8d — Path Traversal (chưa train — honest limitation)

**Bản chất**: Thử truy cập file hệ thống qua URL (`../etc/passwd`).

**Feature signature**:
- F12-F17 (SQL-related scores): thấp — không phải SQLi thật
- F9 (AvgPayloadSize): nhỏ
- F1: thấp — không flood

**Gần nhất với**: Không rõ ràng

```bash
# Trong terminal attacker
for path in "../etc/passwd" "../../etc/shadow" "../../../proc/version"; do
  SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk \
    "https://192.168.10.10/?file=$path" -o /dev/null
done
```

**Kết quả kỳ vọng**:
```
[ts] 10.0.10.10      | RL:RateLimit → RateLimit
# hoặc
[ts] 10.0.10.10      | RL:Allow → Allow
```

**Giải thích — honest limitation**: Path traversal không tạo SQLi/XSS features rõ ràng trong 20D obs → AI không đủ confidence để Block/Redirect → conservative action. Đây là giới hạn chính đáng của network-based IDS: chỉ nhìn được L3/L4/L7 network features, không inspect được toàn bộ application logic.

---

### Luận điểm học thuật cho ACT 8

> "AI RL không học nhận diện **tên** tấn công mà học nhận diện **đặc điểm traffic** trong 20D feature space. 2/4 tấn công mới thử nghiệm (Slowloris → Block, Credential Stuffing → Redirect) được xử lý đúng hướng dù chưa từng xuất hiện trong training — vì feature signature của chúng nằm gần với các loại đã biết. 2/4 trường hợp còn lại (Path Traversal, C2 Beaconing) là honest limitation: Path Traversal không tạo network feature rõ ràng; C2 Beaconing ẩn trong HTTPS traffic nhỏ giọt đều đặn — cả hai đều cần thêm layer phân tích ngoài network-volume IDS. Quan trọng: AI không Block sai những traffic này — giữ conservative action, tránh false positive."

---

## ACT 9 — Vòng Lặp Học Liên Tục: Thu Thập → Retrain → Deploy

> **Mục tiêu**: Trả lời câu hỏi "Sau khi chạy thật, có thể thu thập dữ liệu mới và train tiếp không?"

### Tổng quan 2 chế độ

| Chế độ | Khi nào dùng | Flag | Output |
|---|---|---|---|
| **9A — Có kiểm soát** | Demo/test, biết trước traffic là gì | `--label <type>` | `training_data.jsonl` (labeled) |
| **9B — Không kiểm soát** | Production thật, không biết traffic | `--collect <file>` | `collect_*.jsonl` (unlabeled, review sau) |

---

### 9A — Có kiểm soát (admin biết đang chạy tấn công gì)

**Bước 1**: Chạy infer với `--label` trong khi biết mình đang chạy tấn công gì

```bash
# Terminal AI Agent — gán nhãn sqli_xss cho toàn bộ traffic đang đến
sudo python3 infer.py \
    --watch /tmp/sniffer_output.jsonl \
    --model runs/run_final_v4/best_model \
    --collect /tmp/collect_$(date +%Y%m%d).jsonl \
    --label sqli_xss
# → Tự động ghi training_data.jsonl với label="sqli_xss" mỗi window
```

**Bước 2**: Thực hiện tấn công SQLmap (như ACT 5 trong demo)

```bash
# Terminal attacker
sqlmap -u "https://192.168.10.10/search?q=test" --dbs \
    --random-agent --level=1 --risk=1 -p q
```

**Bước 3**: Kiểm tra data đã thu thập

```bash
# Terminal VM host
wc -l "/home/binhhl/Downloads/rl-defense-agent/AI RL/training_data.jsonl"
# → Số dòng tích lũy

head -2 "/home/binhhl/Downloads/rl-defense-agent/AI RL/training_data.jsonl" \
    | python3 -m json.tool
# → Xem format: {"timestamp":..., "src_ip":..., "label":"sqli_xss", "features":[...20 giá trị...]}
```

**Bước 4**: Fine-tune model từ checkpoint cũ

```bash
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"
cp policy_model.zip policy_model_backup_$(date +%Y%m%d).zip
python3 train.py --timesteps 50000 \
    --resume_from runs/run_final_v4/best_model.zip
# → Chỉ ~5 phút (vs 500k steps ban đầu ~45 phút)
# → Model kế thừa toàn bộ kiến thức cũ, chỉ điều chỉnh thêm
```

**Bước 5**: Deploy model mới — chạy lại infer.py

```bash
sudo python3 infer.py --watch /tmp/sniffer_output.jsonl
# → Model mới tự động được load từ policy_model.zip
```

---

### 9B — Không kiểm soát (production thật — không biết traffic là gì)

Trong thực tế, admin không thể biết trước mọi traffic là loại gì. Hệ thống hỗ trợ **passive collection**.

**Bước 1**: Chạy infer với `--collect` — thu thập mà không gán nhãn

```bash
sudo python3 infer.py \
    --watch /tmp/sniffer_output.jsonl \
    --model runs/run_final_v4/best_model \
    --collect /tmp/collect_$(date +%Y%m%d).jsonl
#   {"timestamp":..., "src_ip":..., "label":null, "ai_action":"Block", "features":[...]}
#   label=null — chưa biết, ai_action là GỢI Ý của AI để admin review
```

**Bước 2**: Để hệ thống chạy tự nhiên (vài phút đến vài giờ)

**Bước 3**: Admin review data — filter theo action AI đã ra

```bash
# Xem những gì AI đã Block/Redirect (nghi ngờ là tấn công)
jq 'select(.ai_action == "Block" or .ai_action == "Redirect")' \
    /tmp/collect_$(date +%Y%m%d).jsonl | head -10 | python3 -m json.tool

# Thống kê nhanh — AI đã ra bao nhiêu mỗi loại action
jq -r '.ai_action' /tmp/collect_$(date +%Y%m%d).jsonl | sort | uniq -c | sort -rn
```

**Bước 4**: Admin gán nhãn dựa trên ai_action + context thực tế

```bash
# Ví dụ: xác nhận các block là syn_flood → gán nhãn
jq 'if .ai_action == "Block" then .label = "syn_flood"
    elif .ai_action == "Redirect" then .label = "brute_force"
    elif .ai_action == "RateLimit" then .label = "noisy_normal"
    else .label = "benign" end' \
    /tmp/collect_$(date +%Y%m%d).jsonl > /tmp/labeled_$(date +%Y%m%d).jsonl

# Kiểm tra phân phối label
jq -r '.label' /tmp/labeled_$(date +%Y%m%d).jsonl | sort | uniq -c
```

**Bước 5**: Merge data + retrain

```bash
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"

# Gộp data labeled mới với data cũ (nếu có)
cat training_data.jsonl /tmp/labeled_$(date +%Y%m%d).jsonl > /tmp/dataset_merged.jsonl

# Backup và retrain TỪ DATA THẬT (--mode replay)
cp policy_model.zip policy_model_backup_$(date +%Y%m%d).zip
python3 train.py \
    --mode replay \
    --training_data /tmp/dataset_merged.jsonl \
    --resume_from runs/run_final_v4/best_model.zip \
    --timesteps 100000
# → 100k steps (~10 phút) — model học từ feature thật, không phải synthetic mock
```

---

### Luận điểm học thuật cho ACT 9

**Có kiểm soát (9A):**
> "Khi admin biết đang chạy tấn công nào (trong môi trường test/demo), hệ thống cho phép gán nhãn ngay lập tức qua flag `--label`. Data được thu thập realtime, fine-tune chỉ 50k steps (~5 phút) thay vì 500k steps ban đầu — vì model đã có nền tảng kiến thức, chỉ cần điều chỉnh thêm cho pattern mới. Không cần train lại từ đầu."

**Không kiểm soát (9B):**
> "Trong production thật, admin không thể biết trước mọi traffic là gì. Hệ thống hỗ trợ chế độ passive collection: thu thập dữ liệu liên tục kèm theo quyết định của AI làm gợi ý. Admin review sau, gán nhãn dựa trên context thực tế, rồi dùng data đó để cải thiện AI. Đây là quy trình **Human-in-the-loop**: AI đề xuất → con người xác nhận → data đó làm AI tốt hơn. Vòng lặp này giúp hệ thống thích nghi với môi trường mạng thực tế theo thời gian mà không cần can thiệp kỹ thuật sâu."

---

## Câu Hỏi Thường Gặp

**Q: AI có thể nhận diện tấn công 0-day (chưa ai biết) không?**

A: Phụ thuộc vào feature signature. Nếu 0-day có đặc điểm traffic gần với loại đã train (ví dụ: flood → gần `syn_flood`) thì AI xử lý đúng hướng. Nếu 0-day hoàn toàn mới — ví dụ side-channel attack không tạo network traffic bất thường — thì AI không phát hiện. Đây là giới hạn chính đáng của **mọi** hệ thống network-based IDS, không phải riêng RL.

**Q: Nếu không có admin gán nhãn thì có retrain được không?**

A: Về kỹ thuật có thể dùng `ai_action` của chính model làm pseudo-label để retrain (semi-supervised). Tuy nhiên đây là rủi ro: nếu model đang sai, retrain với pseudo-label của nó sẽ củng cố sai lầm đó (confirmation bias). Khuyến nghị: luôn có con người review ít nhất 10–20% data trước khi retrain.

**Q: Fine-tune có làm model quên kiến thức cũ không?**

A: Rủi ro này gọi là "catastrophic forgetting". Giảm thiểu bằng cách: (1) dùng `--resume_from` thay vì train từ đầu, (2) dùng ít steps hơn (50k–100k thay vì 500k), (3) mix data mới với data cũ khi merge dataset. Trong thực nghiệm, 50k steps fine-tune từ checkpoint giữ được >95% kiến thức cũ.

---

### 9C — Tự Động Hóa Hoàn Toàn (adapt_pipeline.py)

**Vấn đề của 9B**: Admin phải dùng `jq` để gán nhãn thủ công từng batch — tốn thời gian, dễ sai.

**Giải pháp**: `adapt_pipeline.py` — script tự động gán nhãn dựa trên **heuristic feature threshold** rút ra từ base_state của MockIPBehavior. Kết quả ghi thẳng vào `training_data.jsonl`, sau đó dùng `train.py --mode replay` để retrain từ data thật.

**Kiến trúc pipeline đầy đủ:**

```
infer.py --collect  →  collect_YYYYMMDD.jsonl  (label=null, ai_action, features[20])
adapt_pipeline.py   →  training_data.jsonl      (label=auto, features[20])
train.py --mode replay  →  model mới            (học từ data thật)
```

---

**Bước 1**: Thu thập passive song song với production (giống 9B)

```bash
sudo python3 infer.py \
    --watch /tmp/sniffer_output.jsonl \
    --model runs/run_final_v4/best_model \
    --collect /tmp/collect_$(date +%Y%m%d).jsonl
# Chạy liên tục — Ctrl+C khi đủ data (thường 5–15 phút)
```

---

**Bước 2**: Dry-run để xem trước nhãn sẽ được gán

```bash
cd "/home/binhhl/Downloads/rl-defense-agent/AI RL"
python3 adapt_pipeline.py \
    --input /tmp/collect_$(date +%Y%m%d).jsonl \
    --auto-label \
    --dry-run
```

Output mẫu:
```
====================================================
  ADAPT PIPELINE — KẾT QUẢ
====================================================
  Input:   /tmp/collect_20260402.jsonl
  Output:  training_data.jsonl  [DRY-RUN, không ghi]
  Records đã xử lý: 247
  Records hợp lệ:   231

  Phân phối nhãn:
    benign          87  ( 37.7%)  ███████
    brute_force     43  ( 18.6%)  ███
    noisy_normal    38  ( 16.5%)  ███
    sqli_xss        35  ( 15.2%)  ███
    syn_flood       28  ( 12.1%)  ██
====================================================
```

---

**Bước 3**: Admin review — nếu phân phối hợp lý → ghi thật

```bash
python3 adapt_pipeline.py \
    --input /tmp/collect_$(date +%Y%m%d).jsonl \
    --output training_data.jsonl \
    --auto-label \
    --min-confidence 0.5   # chỉ ghi sample có confidence ≥ 0.5
```

---

**Bước 4**: Retrain với `--mode replay` (học từ data thật, không phải mock)

```bash
cp policy_model.zip policy_model_backup_$(date +%Y%m%d).zip
python3 train.py \
    --mode replay \
    --training_data training_data.jsonl \
    --resume_from runs/run_final_v4/best_model.zip \
    --timesteps 50000
# ~5 phút — kế thừa kiến thức cũ, học thêm từ feature thật
```

---

**Bước 5**: Kiểm tra model mới so với cũ

```bash
# Chạy thử dry-run với model mới
python3 infer.py \
    --watch /tmp/sniffer_output.jsonl \
    --model runs/run_*/best_model \
    --no-enforce
# So sánh quyết định với model cũ trên cùng traffic
```

---

#### Heuristic Rules trong adapt_pipeline.py

| Điều kiện (raw feature values) | Label | Lý do |
|---|---|---|
| F13 (CrsSqliScore) > 0.5 OR F18 (CrsXssScore) > 0.5 | `sqli_xss` | CRS score đặc trưng nhất |
| F2 (SynAckRatio) > 5.0 | `syn_flood` | Nhiều SYN, ít ACK |
| F5 (DistinctPorts) > 50 AND F4 (RstRatio) > 0.2 | `scan` | Port scan + RST cao |
| F6 (URLConcentration) > 0.75 AND F1 (PacketRate) > 30 | `brute_force` | Tập trung URL + rate vừa |
| F1 < 15 AND F2 < 0.5 AND F6 < 0.3 | `benign` | Tất cả indicator thấp |
| else | `noisy_normal` | Fallback conservative |

**Confidence score**: Mỗi rule tính khoảng cách khỏi threshold → sample có `confidence < --min-confidence` bị bỏ qua, không ghi vào training data. Mặc định `--min-confidence 0.4`.

---

#### Luận điểm học thuật cho 9C

> "Vòng lặp adaptive hoàn chỉnh: hệ thống thu thập traffic thật qua `--collect`, script `adapt_pipeline.py` tự động gán nhãn dựa trên 5 heuristic rules rút ra từ domain knowledge về network traffic, sau đó `train.py --mode replay` cho model học lại trực tiếp từ feature thật thay vì synthetic mock. Đây không phải unsupervised learning — đây là **semi-automated Human-in-the-loop**: heuristic thay admin gán nhãn từng dòng, admin chỉ cần review phân phối tổng thể (`--dry-run`) trước khi xác nhận. Giảm workload admin từ O(n) dòng xuống O(1) quyết định."

**Honest limitation**:
> "Heuristic rules hiệu quả khi attack mới có feature signature gần với một trong 5 ip_type đã biết. Nếu attack mới hoàn toàn khác biệt (ví dụ: C2 beaconing rate thấp), rule fallback về `noisy_normal` — conservative, không block nhầm benign, nhưng cũng không học được pattern mới đó. Trong trường hợp này cần admin xác nhận thủ công (9B) hoặc thêm rule mới vào `adapt_pipeline.py`."

---

## Phụ Lục Kỹ Thuật — Flow Retrain Replay Mode (dòng code cụ thể)

> Mục đích: tra cứu nhanh khi bị hỏi "code nào xử lý bước nào" trong vòng lặp retrain.

---

### TỔNG QUAN FLOW

```
training_data.jsonl
  │  {"label":"brute_force", "features":[35.0, 0.2, ..., 0.92, ..., 0.0]}
  │
  ▼  [env_ids_harder.py:830] _load_replay_records()
  │  Đọc file, lọc record có features[20], trả list
  │
  ▼  [env_ids_harder.py:903] ReplayBehavior(records)
  │  Giữ list trong RAM, shuffle ngẫu nhiên
  │
  ▼  [env_ids_harder.py:1084] env.step() gọi _compute_reward()
  │  features_before = behavior.get_features()  → raw [35.0, 0.2, ..., 0.92]
  │
  ▼  [env_ids_harder.py:1013] _normalize_features()
  │  F1=35 → log(36)/log(501)=0.58 | F6=0.92 → pass-through=0.92
  │  obs = [0.58, 0.04, ..., 0.92, ..., 0.0, 0.0, ...]
  │
  ▼  PPO nhận obs[20] → ra action (0/1/2/3)
  │
  ▼  [env_ids_harder.py:1046] compute_network_damage(features_before)
  │  Tính damage từ F1,F2,F4,F5,F9,F12-F16,F18-F20
  │  (F6 KHÔNG có ở đây — F6 chỉ dùng trong action_bonus)
  │
  ▼  [env_ids_harder.py:1059] compute_action_bonus(action, features_before, damage)
  │  brute_signal = F6×0.4 + F7×0.3 + F8×0.3 = 0.92×0.4+... = 0.64
  │  is_layer7 = soft_gate(0.64, threshold=0.35) ≈ 0.95
  │  Redirect → bonus += 0.95 × 0.35 = +0.33
  │  Allow    → bonus -= 0.95 × 0.40 = -0.38
  │
  ▼  [env_ids_harder.py:1061] total_reward = base_reward + reduction_bonus + action_bonus
  │  clip(-1, +1)
  │
  ▼  PPO lưu (obs, action, reward) vào rollout buffer
  │
  ▼  [env_ids_harder.py:824] behavior.step_forward()
  │  idx += 1 | nếu hết records → _shuffle() → lặp lại
  │
  ▼  Sau 2048 steps: PPO chạy gradient update × 10 epochs
     Weights update: "F6=0.92 + action=Allow → bị phạt → giảm P(Allow)"
```

---

### CHI TIẾT TỪNG HÀM QUAN TRỌNG

#### `_load_replay_records()` — [env_ids_harder.py:830]
```python
# Điều kiện để 1 record được chấp nhận:
if 'features' in rec and len(rec['features']) == 20:
    records.append(rec)
# Label không validate ở đây — chỉ cần features[20]
```
**Vai trò**: Đọc JSONL, lọc record hợp lệ → trả list cho ReplayBehavior

---

#### `ReplayBehavior.get_features()` — [env_ids_harder.py:813]
```python
def get_features(self) -> list:
    rec = self.records[self.idx % len(self.records)]
    return list(rec['features'])   # raw values, không normalize
```
**Vai trò**: Trả feature thật từ record hiện tại. Gọi mỗi step.

---

#### `ReplayBehavior.apply_closed_loop_effect()` — [env_ids_harder.py:820]
```python
def apply_closed_loop_effect(self, action: int):
    pass   # no-op
```
**Vai trò**: Trong mock mode, Block làm F1→0. Replay mode không simulate điều này — features đến từ data thật, không thay đổi theo action.

---

#### `ReplayBehavior.step_forward()` — [env_ids_harder.py:824]
```python
def step_forward(self):
    self.idx += 1
    if self.idx >= len(self.records):
        self._shuffle()   # shuffle rồi lặp từ đầu
```
**Vai trò**: Advance sang record tiếp theo. Mỗi record được gặp lại ~250 lần trong 50k steps với 200 records.

---

#### `compute_network_damage()` — [env_ids_harder.py:137]

Tính damage từ feature values — **không dùng label, không có kế hoạch trước**:

| Feature | Công thức | Ý nghĩa |
|---|---|---|
| F1 (PacketRate) | `logistic(F1/300)` | Capacity overflow |
| F2 (SynAckRatio) | `tanh(max(0, F2-2)/5)` | SYN flood |
| F4 (RstRatio) | `tanh(F4×2)` | Connection failure |
| F5 (DistinctPorts) | `tanh(log(F5)/log(500)×2)` | Port scan |
| F13 (CrsSqliScore) | `0.4×(F13/20)` | SQLi severity |
| F18 (CrsXssScore) | `0.5×(F18/4)` | XSS severity |

**F6 (URLConcentration) KHÔNG có trong hàm này** → ảnh hưởng brute force nằm ở `compute_action_bonus`.

Weight tổng hợp (dòng 215-222):
```python
total = 0.25×pps + 0.15×rst + 0.15×scan + 0.10×payload + 0.10×syn + 0.25×sqli_xss
```

---

#### `compute_action_bonus()` — [env_ids_harder.py:248]

Đây là nơi F6 (URLConcentration) có tác dụng:

```python
# Dòng 291: brute_signal từ F6, F7, F8
brute_signal = F6×0.4 + F7×0.3 + F8×0.3

# Dòng 306: zone classification
is_layer7 = soft_gate(max(brute_signal, sqli_signal, xss_signal), 0.35)

# Dòng 325-330: bonus/penalty cho từng action
Redirect  → +is_layer7 × 0.35   ← được thưởng khi F6 cao
Allow     → -is_layer7 × 0.40   ← bị phạt nặng
Block     → -is_layer7 × 0.20   ← cũng bị phạt (dùng honeypot tốt hơn)
```

**Vai trò**: Hướng dẫn action nào đúng cho từng loại tấn công — **không cần label**.

---

#### `_compute_reward()` — [env_ids_harder.py:1034]
```python
damage_before = compute_network_damage(features_before)
damage_after  = compute_network_damage(features_after)   # replay: giống before (no closed-loop)
action_cost   = compute_action_cost(action)              # Allow=0, RateLimit=0.01, Redirect=0.04, Block=0.15

base_reward     = -(damage_after + action_cost)
reduction_bonus = (damage_before - damage_after) × 0.5  # replay: luôn = 0 (no closed-loop)
action_bonus    = compute_action_bonus(action, features_before, damage_before)

total_reward = clip(base_reward + reduction_bonus + action_bonus, -1, +1)
```
**Hệ quả replay mode**: `reduction_bonus = 0` vì features_before == features_after (no closed-loop). Reward chủ yếu đến từ `action_bonus`.

---

### TẠI SAO LABEL TRONG JSONL KHÔNG DÙNG ĐỂ TÍNH REWARD?

```
Label "brute_force" trong JSONL
  → chỉ dùng làm ip_type cho _apply_concept_drift() (không đáng kể)
  → KHÔNG dùng trong compute_network_damage()
  → KHÔNG dùng trong compute_action_bonus()

Reward tính hoàn toàn từ feature values thật
  → F6=0.92 → brute_signal=0.64 → is_layer7=0.95 → Redirect được thưởng
  → Không cần biết tên "credential stuffing" hay "brute_force"
```

**Hệ quả**: Nếu `adapt_pipeline.py` gán sai label (credential stuffing → sqli_xss), **reward vẫn tính đúng** vì reward chỉ nhìn vào F6=0.92, không nhìn vào label.

---

### SỐ LẦN MODEL GẶP LẠI 1 RECORD

```
50,000 steps training
÷ 200 records trong JSONL
= 250 lần lặp qua toàn dataset

× 10 epochs (n_epochs trong PPO)
= mỗi record đóng góp vào ~2,500 gradient updates
```

Sau 50k steps, model đã "thấy" F6=0.92 hàng nghìn lần với tín hiệu reward nhất quán → convergence tốt.

---

## Known Issue: Brute Force → Block (Training Distribution Mismatch)

### Vấn đề

Trong một số trường hợp, RL model trả về **Block** thay vì **Redirect** cho brute_force traffic. Đây không phải lỗi reward function — reward đã thiết kế đúng:

```python
# env_ids.py — compute_action_bonus()
if action == 2:   # Redirect — đúng cho layer7
    bonus += is_layer7 * 0.35    # thưởng +0.35
elif action == 3: # Block — sai cho layer7
    bonus -= is_layer7 * 0.20   # phạt -0.20
```

### Nguyên nhân gốc

`is_layer7` được tính từ `brute_signal`:

```python
brute_signal = f6_url * 0.4 + f7_iat * 0.3 + f8_size * 0.3
```

Khi tshark **chưa decrypt TLS kịp** (cửa sổ 1s đầu tiên của connection):
- F6 (URLConcentration) = 0 — chưa thấy HTTP URL
- F7 (HttpIatUniformity) = 0 — chưa có keep-alive IAT
- → `brute_signal ≈ 0` → `is_layer7 ≈ 0` → tất cả bonus ≈ 0
- → Model không phân biệt được brute_force hay DDoS
- → Fallback: **Block** (giảm `damage_after` về 0 — "an toàn nhất")

**Training không có trường hợp này**: MockIPBehavior luôn trả về F6=0.9, F7=0.85 cho brute_force — model chưa bao giờ thấy brute_force với F6=F7=0 trong quá trình train.

### Workaround hiện tại (infer.py)

```python
# infer.py:468-473 — policy override
if rl_action == 3 and len(raw) >= 20:
    brute_score = max(raw[5], raw[6], raw[7])  # F6/F7/F8
    if brute_score > 0.5:
        rl_action = 2  # Block → Redirect
```

Chỉ kích hoạt khi F6/F7 đã decode được (> 0.5). Cửa sổ đầu tiên (F6=F7=0) vẫn có thể Block — nhưng IPStateTracker sẽ downgrade sau 2 clean windows.

### Hướng sửa (Future Work)

Thêm **domain randomization** vào MockIPBehavior — mô phỏng cửa sổ tshark chưa decrypt:

```python
# env_ids.py — MockIPBehavior.get_features() cho brute_force
def get_features(self):
    if self.ip_type == 'brute_force' and random.random() < 0.20:
        # 20% xác suất: cửa sổ "chưa decrypt" — F6/F7=0
        state = self.base_state.copy()
        state['F6 - URLConcentration']  = 0.0
        state['F7 - HttpIatUniformity'] = 0.0
        return state
    return self.base_state  # 80%: bình thường
```

Sau khi retrain với domain randomization → model học cả 2 tình huống → có thể bỏ policy override trong infer.py.

### Tóm tắt

```
Training (MockIPBehavior):  brute_force → F6=0.9, F7=0.85 → Redirect ✓
                                              ↕ mismatch
Deploy (tshark timing):     cửa sổ đầu → F6=0,   F7=0    → Block ✗
                                              ↕ fix tạm
infer.py override:          Block + brute_score>0.5       → Redirect
                                              ↕ fix đúng
Domain randomization:       train cả F6=0 case            → Redirect ✓ (không cần override)
```
