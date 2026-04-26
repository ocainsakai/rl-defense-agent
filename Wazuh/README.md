# Wazuh — RL Defense Agent Integration

> Tài liệu + cấu hình tích hợp **Wazuh SIEM** với **RL Defense Agent** để
> monitor / visualize / alert dựa trên log quyết định của AI agent.

**Project root:** `rl-defense-agent/` (folder cha)
**Folder này:** Wazuh integration package — cài đặt + config + dashboard + sample log.

---

## 1. Vai trò Wazuh trong dự án

```
┌────────────────────────────────────────────────────────────────┐
│              RL DEFENSE AGENT (../AI RL/, ../System/)            │
│                                                                 │
│  NIDS Sniffer (System/main.py) → /tmp/sniffer_output.jsonl     │
│         │                                                       │
│         ▼                                                       │
│  Inference (AI RL/infer.py)                                     │
│         │ mỗi quyết định AI ghi 1 dòng JSON                    │
│         ▼                                                       │
│  AI RL/actions_wazuh.log         ← FILE WAZUH MONITOR          │
└────────────────────────────────┬───────────────────────────────┘
                                 │ Wazuh agent tail file
                                 ▼
┌────────────────────────────────────────────────────────────────┐
│                       WAZUH STACK                               │
│                                                                 │
│   Wazuh Agent → Wazuh Manager → Wazuh Indexer → Dashboard      │
│   (tail log)    (decode +       (OpenSearch)    (visualize)    │
│                  rule match)                                    │
└────────────────────────────────────────────────────────────────┘
```

**Vai trò:**
- **Tách biệt** AI raw log (JSONL) khỏi visualization layer
- **Centralized monitoring** — nhiều test session đẩy log về 1 chỗ
- **Searchable + filterable** — query theo `src_ip`, `final_action`, `t_block_ready`, time
- **Visual dashboards** — pie chart, timeline, drill-down
- **Alerting** — trigger khi Block fire / soft_guard_promoted

---

## 2. Cấu trúc folder

```
Wazuh/
├── README.md                          # File này
├── INSTALLATION.md                    # Hướng dẫn cài Wazuh + setup integration
├── config/
│   ├── ossec_agent.conf               # Snippet <localfile> cho Wazuh agent
│   ├── custom_decoder.xml             # Parse JSONL của actions_wazuh.log
│   └── custom_rules.xml               # 7 alert rules (Block / Override / Soft guard / Burst)
├── dashboard/
│   └── rl_defense_dashboard.ndjson    # Wazuh Dashboard export (8 visualizations + 1 dashboard + 1 index-pattern)
└── sample_log/
    └── actions_wazuh_sample.jsonl     # 50 dòng đầu để demo format
```

---

## 3. Format log AI ghi (`actions_wazuh.log`)

Producer: `../AI RL/infer.py` ghi 1 dòng JSON mỗi quyết định.

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

**Key fields:**

| Field | Ý nghĩa |
|---|---|
| `src_ip` | IP attacker được AI quan sát |
| `rl_action_name` | Action AI propose (Allow/RateLimit/Redirect/Block) |
| `final_action_name` | Action sau SafetyNet override |
| `t_window_len` | Số window đã tích lũy (max 15) |
| `t_redirect_hits` | Số lần Redirect trong session |
| `t_escalation_score` | Tổng evidence score (0-1) |
| `t_block_ready` | True khi đủ điều kiện Block (window≥12 + score≥0.6 + ...) |
| `soft_guard_promoted` | True khi rule-based escalate Block thay AI |

---

## 4. Dashboard nội dung (đề xuất)

Wazuh Dashboard có thể visualize:

1. **Action distribution donut** — Allow / RateLimit / Redirect / Block
2. **Timeline events** — bar chart actions theo thời gian
3. **Block events table** — list mọi Block với src_ip + timestamp
4. **Override 1 events** — `rl=Block AND final=Redirect` (model muốn Block, rule chặn)
5. **Escalation score trend** — line chart `t_escalation_score` theo window
6. **Top attacker IPs** — top 10 src_ip nhiều decision nhất

---

## 5. Cách dùng package này (3 cấp độ)

### Cấp 1: Đọc tài liệu (NHANH NHẤT, ~5 phút)
- README + INSTALLATION
- Xem `sample_log/actions_wazuh_sample.jsonl` để hiểu input format
- Xem `config/custom_rules.xml` để biết các alert rules

### Cấp 2: Setup Wazuh + dashboard (~30 phút)
- Theo `INSTALLATION.md` cài Wazuh stack
- Apply config trong `config/`
- Import `dashboard/rl_defense_dashboard.ndjson`
- Push sample log → thấy dashboard hiện data

### Cấp 3: End-to-end với RL agent (~2 giờ)
- Cài `rl-defense-agent` + Wazuh
- Chạy `infer.py` → AI ghi log → Wazuh real-time

---

Tài liệu RL agent chi tiết: `../AI RL/Documents/`
