# ✅ HOÀN THÀNH SỬA CHỮA BÁOÁO

**Ngày hoàn thành:** Hôm nay  
**File báo cáo:** `Document/Drafts/review_notes/chapter_full_vietnamese_review_v2.md`

---

## 📋 TÓMLỤC CÁC ĐIỂM ĐÃ SỬA

### ✅ Điểm 1: Tóm tắt (Abstract) — **SỬA XONG**
**Vị trí:** Dòng 35-60 (Phần Tóm tắt / Abstract)

**Sửa từ (sai):**
- "bộ nhớ phiên lưu lượng 10 bước gần nhất" → **Sửa thành:** "10 chiều trạng thái temporal per-IP gồm mã hóa one-hot hành động gần nhất (4D), bộ đếm bước giữ hành động (1D), trung bình động và xu hướng tổn thất dịch vụ (2D), độ điền cửa sổ mềm 15 bước (1D), điểm bằng chứng leo thang (1D), ngân sách bỏ lỡ (1D)"

**Sửa từ (sai):**
- "hành động chuyển hướng được duy trì trong cửa sổ 15 bước để tích lũy bằng chứng trước khi nâng cấp lên chặn" → **Sửa thành:** "từ bước 12, nếu điểm leo thang ≥ 0.60 và các ngưỡng tối thiểu đạt, cờ block_ready_latched bật để gợi ý nâng cấp Block (tùy soft_guard_mode hoặc model tự quyết)"

---

### ✅ Điểm 2: Training/Inference versioning — **SỬA XONG**
**Vị trí:** Dòng 625-639 (Phần 3.3.4 - Training & Inference)

**Thêm vào (nội dung mới):**
```
**Training (Gymnasium env):** Đầu ra là vector 20 chiều giá trị thô. 
Chuẩn hóa về [0,1]²⁰, ghép nối 10D trạng thái temporal per-IP 
(one-hot 4D + normalized scalars 6D) và 4D effect_{t-1} (delayed 1 step). 
Kết quả là vector 34 chiều đầu vào cho PPO.step().

**Inference:** Hệ thống auto-detect phiên bản mô hình từ observation_space.shape:
  - **v3 (34D):** obs = concat[20D norm, 10D temporal, 4D effect] 
    → model.predict() → action
  - **v2 (30D, backward compat):** obs = concat[20D norm, 10D temporal] 
    (no effect) → model.predict() → action
  - **v1 (20D, legacy):** obs = 20D norm → model.predict() → action

Điều này đảm bảo các mô hình cũ vẫn hoạt động mà không cần retraining.
```

**Lợi ích:** Giải thích rõ về backward compatibility và version detection.

---

### ✅ Điểm 3: Không gian Trạng thái (State Space) — **SỬA XONG**
**Vị trí:** Dòng 673-705 (Phần 3.1.4 - Hình thức hóa Bài toán MDP)

**Sửa từ (sai - mô tả chung chung):**
> "**Không gian Trạng thái** S ⊂ [0,1]³⁴: Mỗi trạng thái là vector 34 chiều gồm ba thành phần: **(1) 20 chiều đặc trưng thống kê** ...; **(2) 10D trạng thái temporal theo IP** — mã hóa one-hot hành động gần nhất (4D), bộ đếm giữ hành động (1D), EMA tổn thất dịch vụ và xu hướng (2D), độ điền buffer leo thang (1D), điểm bằng chứng leo thang (1D), ngân sách bỏ lỡ đã dùng (1D); ..."

**Sửa thành (chi tiết - liệt kê 7 thành phần 10D):**
```markdown
**Không gian Trạng thái**: Mỗi trạng thái là vector 34 chiều gồm ba thành phần:

**(1) 20 chiều đặc trưng thống kê** — đặc trưng hành vi lưu lượng 
trong cửa sổ quan sát 1 giây, bao gồm đặc trưng mạng (F1–F11) 
và đặc trưng nội dung HTTP (F12–F20).

**(2) 10D trạng thái temporal per-IP** — gồm các chỉ số tổng hợp 
(không phải lưu trữ 10 bước thô):
   - **One-hot hành động gần nhất (4D):** [1,0,0,0] nếu last_action=0, 
     [0,1,0,0] nếu last_action=1, v.v.
   - **Bộ đếm giữ hành động chuẩn hóa (1D):** min(action_hold_steps / 15, 1.0)
   - **EMA tổn thất dịch vụ (1D):** min(damage_ema, 1.0) 
     — trung bình động của F24
   - **Xu hướng phi tuyến (1D):** sigmoid(damage_trend) 
     — tốc độ thay đổi damage
   - **Độ điền cửa sổ (1D):** min(window_len / 15, 1.0) 
     — bao nhiêu bước đã tích lũy trong phiên
   - **Điểm bằng chứng leo thang (1D):** min(escalation_score, 1.0) 
     — tỉ lệ Redirect/Honeypot/Presence/Pressure
   - **Ngân sách bỏ lỡ chuẩn hóa (1D):** min(miss_count / 3, 1.0) 
     — bao nhiêu lần bỏ lỡ trong phiên

**(3) 4D phản hồi vòng kín** (delayed 1 step — effect từ hành động trước):
   - **F21 WebHitRatio:** tỉ lệ hit đến webserver thật 
     (0=honeypot/block, 1=webserver)
   - **F22 HoneypotHitRatio:** tỉ lệ hit bị redirect sang honeypot
   - **F23 PresenceRatio:** 1.0 nếu có hit, 0.0 nếu cửa sổ im lặng 
     (IP đã dừng)
   - **F24 ServiceDamage:** composite damage score dựa trên 
     webserver reach + attack confidence

Chuẩn hóa về [0,1] đảm bảo ổn định số học cho gradient descent 
của mạng neural PPO.
```

**Lợi ích:** 
- Rõ ràng 10D **không phải** "10 bước lưu trữ thô" mà là "7 chỉ số tổng hợp"
- Chi tiết công thức và ý nghĩa từng thành phần 10D
- Giúp reader hiểu mô hình quan sát thực sự

---

### ✅ Điểm 4: Chuyển hướng & Escalation — **SỬA XONG**
**Vị trị:** Dòng 715 (Phần 3.1.6 - Ánh xạ Hành động)

**Sửa từ (sai - mơ hồ về timing):**
> "- **Chuyển hướng (a=2):** ... Cơ chế leo thang dùng phiên soft escalation theo cửa sổ mềm (15 bước), tích lũy bằng chứng presence/honeypot/ngưỡng bỏ lỡ cho phép và đặt cờ block_ready_latched khi đủ điều kiện, không dựa trên bộ đếm 60 giây cố định."

**Sửa thành (cụ thể - từng điều kiện rõ ràng):**
```
- **Chuyển hướng (a=2):** NAT REDIRECT về cổng 4443 (Honeypot) 
  — dành cho **Brute Force, SQLi, XSS**. Cho phép agent phân tích ý định 
  tấn công qua Honeypot thay vì Chặn ngay, bảo toàn cơ hội SOC xem xét. 
  
**Cơ chế leo thang:** Khi hành động = Redirect và L7_signal ≥ 0.35, 
hệ thống mở phiên soft escalation mới. Mỗi bước ghi lại cờ trạng thái 
gồm is_redirect, has_presence, has_honeypot, is_miss, pressure 
vào cửa sổ lăn 15 bước. 

Từ bước 12 trở đi (không phải 15 cứng), nếu redirect_hits ≥ 6 
AND presence_hits ≥ 8 AND honeypot_hits ≥ 5 AND miss_count ≤ 3 
AND escalation_score ≥ 0.60, cờ block_ready_latched bật. 

Việc nâng cấp Block chỉ xảy ra khi: 
  (1) soft_guard_mode='assist' AND block_ready_latched AND F23 ≥ 0.5, 
  hoặc (2) model PPO tự quyết (mặc định).
```

**Lợi ích:**
- Rõ ràng ngưỡng 12 bước (không phải 15 bước cứng)
- Chi tiết từng điều kiện để kích hoạt block_ready_latched
- Rõ ràng sự khác biệt giữa soft_guard_mode='assist' và mặc định

---

### ✅ Điểm 5: Đóng góp Phương pháp — **SỬA XONG**
**Vị trí:** Dòng 571-572 (Phần Tóm tắt, mục Đóng góp)

**Thêm vào/Sửa thành (chi tiết hơn):**
```
**Đóng góp phương pháp:** Dự án đề xuất không gian trạng thái 34 chiều gồm: 
(1) 20D đặc trưng lưu lượng (F1–F11 mạng + F12–F20 ứng dụng từ OWASP CRS); 
(2) 10D trạng thái temporal per-IP mã hóa lịch sử hành động qua one-hot(4D) 
+ bộ đếm hold + EMA/trend damage + window_fill + escalation_score + miss_budget 
— từ đó agent học được tính liên tục hành động, xu hướng tổn thất, 
và trạng thái phiên; 
(3) 4D phản hồi vòng kín (delayed 1 step) ghi lại hệ quả của hành động trước 
— webserver reachability, honeypot hit ratio, presence, service damage. 

Thiết kế này phủ rộng hơn các nghiên cứu tập trung đơn vào đặc trưng mạng, 
kích hoạt feedback loop giúp agent học causal reasoning. 

Tích hợp Ngẫu nhiên hóa miền trong huấn luyện qua các phân phối thực tế 
(Normal/LogNormal/Beta/Poisson) cũng là đóng góp phương pháp giúp tăng 
khả năng tổng quát hóa.
```

---

## 📊 BẢNG TÓMLỤC

| # | Phần | Vị trí | Trạng thái | Ghi chú |
|---|------|--------|-----------|--------|
| 1 | Tóm tắt (Abstract) | Dòng 35-60 | ✅ XONG | 10D temporal, từ bước 12, soft_guard_mode |
| 2 | Training/Inference versioning | Dòng 625-639 | ✅ XONG | v1/v2/v3 auto-detect |
| 3 | Không gian Trạng thái (3.1.4) | Dòng 673-705 | ✅ XONG | 7 thành phần 10D chi tiết |
| 4 | Chuyển hướng/Escalation (3.1.6) | Dòng 715 | ✅ XONG | 12 bước + 5 điều kiện + soft_guard_mode |
| 5 | Đóng góp Phương pháp | Dòng 571-572 | ✅ XONG | Chi tiết về 34D design |

---

## 🔍 KIỂM CHỨNG

Tất cả các sửa chữa đã được **xác nhận so khớp với code thực tế**:

### ✓ Code ground truth từ `env_ids.py`:
- Line 83: `SOFT_SESSION_WINDOW = 15` ✓
- Line 90: `BLOCK_READY_MIN_WINDOW = 12` ✓
- Lines 905-1130: `PerIPTemporalState` class với 7 scalar components ✓
- Lines 1412-1413: `observation_space = spaces.Box(0, 1, (34,))` ✓

### ✓ Code ground truth từ `infer.py`:
- Lines 792-800: Auto-detect v3/v2/v1 from `obs_dim` ✓
- Lines 1120-1135: Build 34D obs = [20D + 10D + 4D] ✓
- Lines 1156-1167: `soft_guard_mode='assist'` logic ✓
- Lines 475-523: Attack signal detection + escalation ✓

---

## 🎯 TÁC DỤNG CỦA CÁC SỬA CHỮA

1. **Rõ ràng khoa học:**
   - Không còn nhầm lẫn "10 chiều" với "10 bước lưu trữ"
   - Rõ ràng soft escalation dựa trên bằng chứng, không timing cố định

2. **Phù hợp với code:**
   - Toàn bộ mô tả đều khớp với implementation thực tế
   - Không còn tuyên bố sai lệch

3. **Hỗ trợ review/grading:**
   - Giáo sư/reviewer không bị nhầm lẫn
   - Báo cáo thể hiện hiểu biết sâu về design

4. **Hỗ trợ triển khai:**
   - Mô tả rõ về v1/v2/v3 versioning giúp maintain codebase
   - Mô tả chi tiết escalation logic hỗ trợ debugging/tuning

---

## 📝 HƯỚNG DẪN KIỂM CHỨNG CUỐI

Để xác nhận các sửa chữa, hãy:

1. **Mở báo cáo:** `Document/Drafts/review_notes/chapter_full_vietnamese_review_v2.md`
2. **Search từng phần:** Ctrl+F tìm "10 chiều trạng thái temporal", "từ bước 12", "v3 (34D)", "Không gian Trạng thái" 
3. **Đọc phần Tóm tắt (Abstract):** Dòng 35-60 để đảm bảo toàn bộ key details
4. **Kiểm tra Section 3.1.4:** Xem 7 thành phần 10D có liệt kê đầy đủ không
5. **Kiểm tra Section 3.1.6:** Xem "từ bước 12" và soft_guard_mode có rõ không

---

## ✨ KẾT LUẬN

**Tất cả 5 discrepancies chính đã được sửa xong và xác nhận khớp với code thực tế.**

Báo cáo hiện đây đã sẵn sàng để:
- ✅ Nộp cho giáo sư/review committee
- ✅ Lưu trữ tài liệu cuối cùng
- ✅ Hỗ trợ maintenance/debugging trong tương lai

**Status:** 🟢 HOÀN THÀNH - Ready for submission!

