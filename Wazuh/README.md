# Wazuh — RL Defense Agent Integration

Tích hợp **Wazuh SIEM** với **RL Defense Agent** để monitor, visualize và alert
dựa trên log quyết định của AI agent (`actions_wazuh.log`).

Folder này chứa: tài liệu vai trò, custom decoder/rules, dashboard pre-built,
sample log để hội đồng dựng lại Wazuh dashboard nhanh.

---

## 1. Vai trò Wazuh trong dự án

```
+----------------------------------------------------------------+
|                    RL DEFENSE AGENT                             |
|                                                                 |
|  NIDS Sniffer (System/main.py) -> /tmp/sniffer_output.jsonl    |
|         |                                                       |
|         v                                                       |
|  Inference (AI RL/infer.py)                                    |
|         | mỗi quyết định AI ghi 1 dòng JSON                   |
|         v                                                       |
|  AI RL/actions_wazuh.log         <- FILE WAZUH MONITOR         |
+----------------------------------+------------------------------+
                                   | Wazuh agent tail file
                                   v
+----------------------------------------------------------------+
|                       WAZUH STACK                               |
|                                                                 |
|   Wazuh Agent  ->  Wazuh Manager  ->  Wazuh Indexer  ->  Dashboard
|   (tail log)       (decode + rule       (OpenSearch)        (visualize)
|                     match)                                      |
+----------------------------------------------------------------+
```

**Lý do dùng Wazuh:**
- **Tách biệt** AI raw log (JSONL) khỏi visualization layer
- **Centralized monitoring** — nhiều test session đẩy log về 1 chỗ
- **Searchable + filterable** — query theo `src_ip`, `final_action`, `t_block_ready`, time range
- **Visual dashboards** — pie chart, timeline, drill-down từng decision
- **Alerting** — trigger notification khi Block fire / soft_guard_promoted

---

## 2. Cấu trúc folder

```
Wazuh/
├── README.md                          File này (overview + vai trò)
├── INSTALLATION.md                    Hướng dẫn cài đặt step-by-step
├── config/
│   ├── ossec_agent.conf               Snippet <localfile> cho Wazuh agent
│   ├── custom_decoder.xml             Parse JSONL của actions_wazuh.log
│   └── custom_rules.xml               7 alert rules (Block, Override, Soft guard, Burst)
├── dashboard/
│   └── rl_defense_dashboard.ndjson    Wazuh Dashboard export (8 viz + 1 dashboard + 1 index-pattern)
└── sample_log/
    └── actions_wazuh_sample.jsonl     50 dòng đầu để demo format + test integration
```

---

## 3. Format `actions_wazuh.log`

Producer: `AI RL/infer.py` ghi 1 dòng JSON mỗi quyết định.

```json
{
  "timestamp": 1777048182.65,
  "src_ip": "10.0.10.10",
  "rl_action_name": "Redirect",
  "final_action_name": "Redirect",
  "model_version": "v3",
  "t_window_len": 8,
  "t_redirect_hits": 8,
  "t_presence_hits": 8,
  "t_honeypot_hits": 7,
  "t_escalation_score": 0.83,
  "t_block_ready": false,
  "soft_guard_promoted": false
}
```

**Khác biệt với `actions.log` (full audit):**
- KHÔNG có `action_probs` (dict 4 keys) — tránh array parsing issue trong Wazuh Indexer
- KHÔNG có `normalized_obs` (34D float array) — tương tự

| Field | Ý nghĩa |
|---|---|
| `src_ip` | IP attacker |
| `rl_action_name` | Action AI đề xuất (Allow / RateLimit / Redirect / Block) |
| `final_action_name` | Action cuối sau SafetyNet override |
| `t_window_len` | Số window tích lũy trong session (max 15) |
| `t_redirect_hits` | Số lần Redirect trong session |
| `t_escalation_score` | Tổng evidence score (0-1) |
| `t_block_ready` | True khi đủ điều kiện Block (window>=12 + score>=0.6 + ...) |
| `soft_guard_promoted` | True khi rule-based escalate Block thay AI |

---

## 4. Custom decoder + rules

### Decoder (`config/custom_decoder.xml`)

Decoder cha cho mọi event từ RL agent. Wazuh tự động extract các JSON top-level
keys thành `data.*` (`data.src_ip`, `data.final_action_name`, ...).

### Rules (`config/custom_rules.xml`)

7 alert rules với rule IDs 100001-100010:

| Rule ID | Level | Trigger | Mục đích |
|---|---|---|---|
| 100001 | 0 | Mọi event RL | Parent rule (không alert) |
| 100002 | 8 | `final_action_name=Block` | Alert mỗi lần Block thành công |
| 100003 | 5 | `rl_action=Block` AND `final=Redirect` | Override 1 fire (RL muốn Block sớm) |
| 100004 | 6 | `soft_guard_promoted=true` | Rule-based escalation thay AI |
| 100005 | 3 | `t_block_ready=true` | Threshold reached (informational) |
| 100006 | 4 | `rl=Allow/RateLimit` AND `final=Redirect` | Override 0 fire (L7 cold-start) |
| 100010 | 10 | >5 Block events trong 60s | Multiple Block burst (possible attack) |

---

## 5. Dashboard

`dashboard/rl_defense_dashboard.ndjson` — pre-built dashboard cho Wazuh Dashboard
(Stack Management → Saved Objects → Import).

Sau khi import, dashboard "RL Defense Agent" có:

1. **Action distribution donut** — Allow / RateLimit / Redirect / Block
2. **Timeline events** — bar chart actions theo thời gian
3. **Block events table** — list mọi Block với `src_ip` + timestamp
4. **Override events** — list `rl_action != final_action`
5. **Escalation score trend** — line chart `t_escalation_score`
6. **Top attacker IPs** — top 10 `src_ip` nhiều decision nhất

Tổng: 8 visualizations + 1 dashboard + 1 index-pattern.

---

## 6. Quick start

### 6.1. Cài đặt đầy đủ (production-style)

Theo [`INSTALLATION.md`](INSTALLATION.md) — bao gồm:
1. Cài Wazuh stack (Manager + Indexer + Dashboard)
2. Cài Wazuh Agent trên máy chạy `infer.py`
3. Apply config (ossec.conf, decoder, rules)
4. Import dashboard NDJSON
5. Verify integration

### 6.2. Test nhanh với sample log (không cần `infer.py` chạy)

```bash
# Push 50 dòng sample vào file Wazuh đang monitor
sudo cp Wazuh/sample_log/actions_wazuh_sample.jsonl \
  "/PATH/TO/rl-defense-agent/AI RL/actions_wazuh.log"

# Mở Wazuh Dashboard -> "RL Defense Agent"
# -> Thấy 50 events hiển thị trong các viz
```

---

## 7. Cách dùng package này (3 cấp độ)

### Cấp 1 — Đọc tài liệu (~5 phút)

- README.md + INSTALLATION.md
- Xem `sample_log/actions_wazuh_sample.jsonl` để hiểu input format
- Xem `config/custom_rules.xml` để biết các alert rules

### Cấp 2 — Setup Wazuh + dashboard (~30 phút)

- Theo INSTALLATION.md cài Wazuh stack
- Apply config trong `config/`
- Import `dashboard/rl_defense_dashboard.ndjson`
- Push sample log → thấy dashboard hiện data

### Cấp 3 — End-to-end với RL agent (~2 giờ)

- Cài cả `rl-defense-agent` (project chính) + Wazuh
- Chạy `infer.py` → AI ghi `actions_wazuh.log` → Wazuh real-time

---

## 8. Tham khảo

- Source RL agent: [`../AI RL/README.md`](../AI%20RL/README.md)
- NIDS sniffer: [`../System/`](../System/)
- Cài đặt chi tiết: [`INSTALLATION.md`](INSTALLATION.md)
