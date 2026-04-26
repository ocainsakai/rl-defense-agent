# Wazuh Installation + RL Defense Integration

Hướng dẫn cài Wazuh stack và setup integration với `actions_wazuh.log` của RL agent.

**Tested on:** Ubuntu 22.04 LTS, Wazuh 4.7.x

---

## 1. Cài Wazuh stack

### Cách 1 — All-in-one assistant (nhanh nhất, ~10 phút)

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Sau khi xong:
- Wazuh Dashboard: `https://<server-ip>` (default user `admin`, password show ở cuối install)
- Wazuh Manager API: port 55000
- Wazuh Indexer (OpenSearch): port 9200

### Cách 2 — Docker compose (portable)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up -d
```

→ Dashboard tại `https://localhost`.

---

## 2. Cài Wazuh Agent trên máy chạy RL Defense

Trên cùng máy chạy `infer.py` (sinh ra `actions_wazuh.log`):

```bash
# Cài agent (đăng ký với manager)
WAZUH_MANAGER="<IP-của-Wazuh-Manager>" \
  apt install wazuh-agent

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

Verify agent connected:
```bash
sudo /var/ossec/bin/agent_control -l
# → thấy agent status ACTIVE
```

---

## 3. Setup integration — agent monitor `actions_wazuh.log`

### 3.1 Apply ossec_agent.conf snippet

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Tìm thẻ `<ossec_config>` → thêm phần `<localfile>` từ file [`config/ossec_agent.conf`](config/ossec_agent.conf):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/PATH/TO/rl-defense-agent/AI RL/actions_wazuh.log</location>
  <label key="source">rl_defense_agent</label>
  <label key="version">v3</label>
</localfile>
```

→ **Đổi PATH** thành đường dẫn tuyệt đối đến `actions_wazuh.log` trên máy bạn.

### 3.2 Apply custom decoder

Trên **Wazuh Manager** (không phải agent):

```bash
sudo cp config/custom_decoder.xml /var/ossec/etc/decoders/local_rl_decoder.xml
sudo chown wazuh:wazuh /var/ossec/etc/decoders/local_rl_decoder.xml
```

### 3.3 Apply custom rules (optional — cho alerting)

```bash
sudo cp config/custom_rules.xml /var/ossec/etc/rules/local_rl_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rl_rules.xml
```

### 3.4 Restart services

```bash
# Trên Wazuh Manager:
sudo systemctl restart wazuh-manager

# Trên Wazuh Agent:
sudo systemctl restart wazuh-agent
```

---

## 4. Verify integration

### 4.1 Check log đang được agent đọc

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep actions_wazuh
# → thấy "Analyzing file: '/PATH/.../actions_wazuh.log'"
```

### 4.2 Push test event vào log

```bash
# Trên máy có RL agent
echo '{"timestamp":1777048999,"src_ip":"10.0.10.10","rl_action_name":"Block","final_action_name":"Block","t_window_len":12,"t_block_ready":true}' \
  >> "/PATH/TO/rl-defense-agent/AI RL/actions_wazuh.log"
```

### 4.3 Tìm event trên Wazuh Dashboard

```
Dashboard → Security events → Filter:
  rule.id: 100001
  OR data.src_ip: "10.0.10.10"
```

→ Thấy event với decoded fields (src_ip, rl_action_name, final_action_name, ...).

---

## 5. Import dashboard pre-built

```
Wazuh Dashboard UI:
  Stack Management → Saved Objects
  → Click "Import"
  → Upload: dashboard/rl_defense_dashboard.ndjson
  → Done
```

→ Vào **Dashboard** menu → tìm "RL Defense Agent" → mở ra thấy sẵn các visualization.

---

## 6. Troubleshooting

### Agent không thấy log file
```bash
sudo /var/ossec/bin/wazuh-control status
sudo tail -f /var/ossec/logs/ossec.log
# Check permission: agent process (user wazuh) phải read được file
sudo chmod 644 "/PATH/TO/actions_wazuh.log"
```

### Decoder không match
```bash
# Test decoder với sample log:
echo '{"src_ip":"10.0.10.10","rl_action_name":"Block"}' | \
  sudo /var/ossec/bin/wazuh-logtest
```

### Dashboard import lỗi
- Verify Wazuh Dashboard version >= 4.7.0
- Reimport sau khi clear browser cache

---

## 7. Reproduce với sample log

Nếu chưa có RL agent đang chạy, push sample log vào file Wazuh đang monitor:

```bash
sudo cp sample_log/actions_wazuh_sample.jsonl \
  "/PATH/TO/rl-defense-agent/AI RL/actions_wazuh.log"

# Wazuh agent sẽ tail đọc dần → dashboard cập nhật real-time
```

→ Mở dashboard → thấy 50 events từ sample.
