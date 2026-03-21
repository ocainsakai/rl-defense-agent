# Hướng dẫn Thu thập Log Production & Fine-tuning Offline

## Tổng quan

Khi `infer.py` chạy production, nó ghi 3 loại file log khác nhau.
Mỗi loại phục vụ một mục đích khác nhau cho việc fine-tune model sau này.

---

## Sơ đồ luồng dữ liệu

```
NIDS Sniffer (main.py)
        │
        ▼
sniffer_output.jsonl   ←── raw 20D features per flow window (1s)
        │
        ▼
   infer.py
        │
        ├──► actions.log              ← luôn ghi (production log)
        ├──► training_data.jsonl      ← chỉ ghi khi --label (labeled mode)
        └──► collect_unlabeled.jsonl  ← chỉ ghi khi --collect (passive mode)
```

---

## File 1: `actions.log` — Log quyết định của AI (luôn có)

**Tự động ghi mọi lúc**, không cần flag đặc biệt.

**Lệnh chạy:**
```bash
python3 infer.py --watch /tmp/sniffer_output.jsonl
```

**Nội dung mỗi dòng (JSON):**
```json
{
  "timestamp": 1741823045.2,
  "src_ip": "10.0.10.10",
  "rl_action": 2,
  "rl_action_name": "Redirect",
  "final_action": 3,
  "final_action_name": "Block"
}
```

| Field | Ý nghĩa |
|---|---|
| `rl_action` | Quyết định thô của AI model (0-3) |
| `rl_action_name` | Tên action AI chọn |
| `final_action` | Action thực sự được áp dụng (sau policy override + escalation) |
| `final_action_name` | Tên action cuối cùng |

**Dùng để fine-tune:** Xem AI có hay bị override không (`rl_action ≠ final_action`). Nếu override nhiều → reward function cần điều chỉnh.

---

## File 2: `training_data.jsonl` — Labeled Data (có gán nhãn)

**Chỉ ghi khi thêm flag `--label`**. Dùng khi admin biết chắc loại traffic đang chạy (VD: đang demo tấn công SQLi).

**Lệnh chạy:**
```bash
# Trong khi đang chạy tấn công SQLmap
python3 infer.py --watch /tmp/sniffer_output.jsonl --label sqli_xss

# Trong khi traffic bình thường
python3 infer.py --watch /tmp/sniffer_output.jsonl --label benign

# Các label hợp lệ:
# benign | brute_force | scan | syn_flood | sqli_xss | layer7_stealth
```

**Nội dung mỗi dòng:**
```json
{
  "timestamp": 1741823045.2,
  "src_ip": "10.0.10.10",
  "label": "sqli_xss",
  "features": [45.0, 0.0, 0.12, 0.0, 3.0, 0.95, 0.85, 0.90, 512.0, 1.2, 2.3,
               0.04, 5.0, 1.0, 1.0, 0.0, 2.0, 1.6, 1.0, 0.0]
}
```

| Field | Ý nghĩa |
|---|---|
| `label` | Loại traffic (gán thủ công bởi admin) |
| `features` | 20D raw feature vector (chưa normalize) |

**Dùng để fine-tune:** Dataset chất lượng cao, label chính xác. Dùng để retrain `env_ids.py` MockIPBehavior hoặc supervised pre-training.

---

## File 3: `collect_unlabeled.jsonl` — Passive Collection (chưa gán nhãn)

**Chỉ ghi khi thêm flag `--collect`**. Dùng trong production thật — thu thập tất cả traffic mà không cần biết loại. Admin review sau.

**Lệnh chạy:**
```bash
python3 infer.py --watch /tmp/sniffer_output.jsonl \
    --collect /var/log/ids/collect_$(date +%Y%m%d).jsonl
```

**Nội dung mỗi dòng:**
```json
{
  "timestamp": 1741823045.2,
  "src_ip": "10.0.10.10",
  "label": null,
  "ai_action": "Block",
  "features": [45.0, 0.0, 0.12, 0.0, 3.0, ...]
}
```

| Field | Ý nghĩa |
|---|---|
| `label` | `null` — admin tự điền sau |
| `ai_action` | AI đã quyết định gì — gợi ý cho admin khi review |
| `features` | 20D raw vector |

**Dùng để fine-tune:** Thu thập data thật từ production → admin gán nhãn → tạo labeled dataset cho lần retrain tiếp.

---

## Quy trình Fine-tuning Offline (tương lai)

### Bước 1 — Thu thập data production

```bash
# Chạy production với passive collection
python3 infer.py --watch /tmp/sniffer_output.jsonl \
    --collect /var/log/ids/collect_$(date +%Y%m%d).jsonl
```

Sau 1 tuần/1 tháng, sẽ có file `collect_20260401.jsonl`, `collect_20260402.jsonl`...

### Bước 2 — Admin gán nhãn

```bash
# Review các dòng có ai_action = Block/Redirect
# Điền label vào field "label": null → "sqli_xss" / "syn_flood" / ...
# Tool gợi ý: jq, hoặc script Python đơn giản
jq 'select(.ai_action == "Block")' collect_20260401.jsonl | head -50
```

### Bước 3 — Merge và chuẩn bị dataset

```bash
# Gộp tất cả file labeled thành 1
cat training_data_*.jsonl collect_labeled_*.jsonl > dataset_v2.jsonl

# Kiểm tra phân phối label
jq -r '.label' dataset_v2.jsonl | sort | uniq -c | sort -rn
```

### Bước 4 — Retrain hoặc Fine-tune

**Option A — Retrain từ đầu** (nếu data mới đủ lớn, ≥ 50k samples):
```bash
cd "AI RL"
# Cập nhật MockIPBehavior trong env_ids.py dựa trên phân phối data thật
python3 train.py --timesteps 500000 --seed 42
```

**Option B — Resume từ model cũ** (nếu muốn fine-tune nhanh):
```bash
python3 train.py --timesteps 100000 \
    --resume_from runs/run_final_v4/best_model.zip
```

---

## Chiến lược thu thập theo kịch bản

| Kịch bản | Lệnh | File output |
|---|---|---|
| Production thông thường | `--watch` (không thêm gì) | `actions.log` |
| Demo tấn công có kiểm soát | `--watch --label <type>` | `training_data.jsonl` |
| Production dài hạn thu thập dữ liệu | `--watch --collect /var/log/...` | `collect_unlabeled.jsonl` |
| Vừa chạy vừa thu thập có nhãn | `--watch --label benign --collect ...` | Cả 2 file |

---

## Lưu ý quan trọng

1. **`features` là raw (chưa normalize)** — giống hệt giá trị NIDS xuất ra. Khi dùng để retrain, phải qua `normalize_feature_vector()` từ `System/config/data_params.py`.

2. **`ai_action` trong collect file là gợi ý, không phải ground truth** — AI có thể sai. Admin phải review lại trước khi dùng làm label.

3. **Phân phối label phải cân bằng** — nếu 90% là `benign`, model sẽ bị bias. Cố gắng thu thập đủ mỗi loại tấn công.

4. **Rotate file theo ngày** — tránh file quá lớn:
   ```bash
   --collect /var/log/ids/collect_$(date +%Y%m%d).jsonl
   ```

5. **Backup trước khi retrain** — copy `policy_model.zip` ra ngoài trước khi chạy train mới.
