# Checklist sửa chữa báo cáo

**Status:** ✅ Tóm tắt & Training/Inference đã sửa | ⏳ Còn cần sửa: 3.1.4 + 3.1.6 chi tiết

---

## Điểm 1: Tóm tắt (DONE ✅)

**Vị trí:** Dòng 38-48 (Tóm tắt)

**Đã sửa từ:**
> "bộ nhớ phiên lưu lượng 10 bước gần nhất"
> "hành động chuyển hướng được duy trì trong cửa sổ 15 bước để tích lũy bằng chứng trước khi nâng cấp lên chặn"

**Thành:**
> "10 chiều trạng thái temporal per-IP gồm mã hóa one-hot hành động gần nhất (4D), bộ đếm bước giữ hành động (1D), trung bình động và xu hướng tổn thất dịch vụ (2D), độ điền cửa sổ mềm 15 bước (1D), điểm bằng chứng leo thang (1D), ngân sách bỏ lỡ (1D)"
> "phòng thủ L7 sử dụng cơ chế soft escalation: hành động chuyển hướng tích lũy bằng chứng trong cửa sổ mềm 15 bước; từ bước 12, nếu điểm leo thang ≥ 0.60 và các ngưỡng tối thiểu đạt, cờ block_ready_latched bật để gợi ý nâng cấp Block (tùy soft_guard_mode hoặc model tự quyết)"

---

## Điểm 2: Training/Inference versioning (DONE ✅)

**Vị trị:** Mục 3.3.5 (Pipeline Suy diễn), dòng ~627

**Đã sửa thành:**
```markdown
**Training (Gymnasium env):** Đầu ra là vector 20 chiều giá trị thô. Chuẩn hóa về [0,1]²⁰, 
ghép nối 10D trạng thái temporal per-IP (one-hot 4D + normalized scalars 6D) và 4D effect_{t-1} 
(delayed 1 step). Kết quả là vector 34 chiều đầu vào cho PPO.step().

**Inference:** Hệ thống auto-detect phiên bản mô hình từ observation_space.shape:
  - **v3 (34D):** obs = concat[20D norm, 10D temporal, 4D effect] → model.predict() → action
  - **v2 (30D, backward compat):** obs = concat[20D norm, 10D temporal] (no effect) → model.predict() → action
  - **v1 (20D, legacy):** obs = 20D norm → model.predict() → action

Điều này đảm bảo các mô hình cũ vẫn hoạt động mà không cần retraining.
```

---

## Điểm 3: Không gian Trạng thái (⏳ TODO)

**Vị trị:** Mục 3.1.4, dòng ~673-682

**Cần sửa từ:**
```
**Không gian Trạng thái** S ⊂ [0,1]³⁴: Mỗi trạng thái là vector 34 chiều gồm ba thành phần: 
**(1) 20 chiều đặc trưng thống kê** — đặc trưng hành vi lưu lượng trong cửa sổ quan sát 1 giây, 
bao gồm đặc trưng mạng (F1–F11) và đặc trưng nội dung HTTP (F12–F20); 
**(2) 10D trạng thái temporal theo IP** — mã hóa one-hot hành động gần nhất (4D), bộ đếm giữ hành động (1D), 
EMA tổn thất dịch vụ và xu hướng (2D), độ điền buffer leo thang (1D), điểm bằng chứng leo thang (1D), 
ngân sách bỏ lỡ đã dùng (1D); 
**(3) 4D phản hồi vòng kín** (trạng thái hiệu ứng từ bước trước) — khả năng tiếp cận webserver, 
tỉ lệ bắt giữ honeypot, tín hiệu hiện diện dịch vụ, và mức độ tổn thất dịch vụ từ bước trước. 
Chuẩn hóa về [0,1] đảm bảo ổn định số học cho gradient descent của mạng neural PPO.

Chi tiết 10 chiều trạng thái thời gian và 4 chiều trạng thái hiệu ứng được trình bày ở Mục 3.3.8 và 3.3.9 
để đồng bộ với phần 20 chiều đặc trưng.
```

**Thành:**
```
**Không gian Trạng thái**: Mỗi trạng thái là vector 34 chiều gồm ba thành phần:

**(1) 20 chiều đặc trưng thống kê** — đặc trưng hành vi lưu lượng trong cửa sổ quan sát 1 giây, 
bao gồm đặc trưng mạng (F1–F11) và đặc trưng nội dung HTTP (F12–F20).

**(2) 10D trạng thái temporal per-IP** — gồm các chỉ số tổng hợp (không phải lưu trữ 10 bước thô):
   - **One-hot hành động gần nhất (4D):** [1,0,0,0] nếu last_action=0, [0,1,0,0] nếu last_action=1, v.v.
   - **Bộ đếm giữ hành động chuẩn hóa (1D):** min(action_hold_steps / 15, 1.0)
   - **EMA tổn thất dịch vụ (1D):** min(damage_ema, 1.0) — trung bình động của F24
   - **Xu hướng phi tuyến (1D):** sigmoid(damage_trend) — tốc độ thay đổi damage
   - **Độ điền cửa sổ (1D):** min(window_len / 15, 1.0) — bao nhiêu bước đã tích lũy trong phiên
   - **Điểm bằng chứng leo thang (1D):** min(escalation_score, 1.0) — tỉ lệ Redirect/Honeypot/Presence/Pressure
   - **Ngân sách bỏ lỡ chuẩn hóa (1D):** min(miss_count / 3, 1.0) — bao nhiêu lần bỏ lỡ trong phiên

**(3) 4D phản hồi vòng kín** (delayed 1 step — effect từ hành động trước):
   - **F21 WebHitRatio:** tỉ lệ hit đến webserver thật (0=honeypot/block, 1=webserver)
   - **F22 HoneypotHitRatio:** tỉ lệ hit bị redirect sang honeypot
   - **F23 PresenceRatio:** 1.0 nếu có hit, 0.0 nếu cửa sổ im lặng (IP đã dừng)
   - **F24 ServiceDamage:** composite damage score dựa trên webserver reach + attack confidence

Chuẩn hóa về [0,1] đảm bảo ổn định số học cho gradient descent của mạng neural PPO.
```

---

## Điểm 4: Chuyển hướng & Escalation (⏳ TODO)

**Vị trị:** Mục 3.1.6, dòng ~735-738

**Cần sửa từ:**
```
- **Chuyển hướng (a=2):** NAT REDIRECT về cổng 4443 (Honeypot) — dành cho **Brute Force, SQLi, XSS**. 
Cho phép agent phân tích ý định tấn công qua Honeypot thay vì Chặn ngay, bảo toàn cơ hội SOC xem xét. 
Cơ chế leo thang dùng phiên soft escalation theo cửa sổ mềm (15 bước), tích lũy bằng chứng presence/honeypot/ngưỡng bỏ lỡ cho phép 
và đặt cờ block_ready_latched khi đủ điều kiện, không dựa trên bộ đếm 60 giây cố định.
```

**Thành:**
```
- **Chuyển hướng (a=2):** NAT REDIRECT về cổng 4443 (Honeypot) — dành cho **Brute Force, SQLi, XSS**. 
Cho phép agent phân tích ý định tấn công qua Honeypot thay vì Chặn ngay, bảo toàn cơ hội SOC xem xét. 
**Cơ chế leo thang:** Khi hành động = Redirect và L7_signal ≥ 0.35, hệ thống mở phiên soft escalation mới. 
Mỗi bước ghi lại cờ trạng thái gồm is_redirect, has_presence, has_honeypot, is_miss, pressure vào cửa sổ lăn 15 bước. 
Từ bước 12 trở đi (không phải 15 cứng), nếu redirect_hits ≥ 6 AND presence_hits ≥ 8 AND honeypot_hits ≥ 5 AND miss_count ≤ 3 
AND escalation_score ≥ 0.60, cờ block_ready_latched bật. Việc nâng cấp Block chỉ xảy ra khi: 
(1) soft_guard_mode='assist' AND block_ready_latched AND F23 ≥ 0.5, hoặc (2) model PPO tự quyết (mặc định).
```

---

## Điểm 5: Đóng góp phương pháp (⏳ TODO)

**Vị trị:** Mục (trang 7), dòng ~571

**Cần sửa từ:**
```
**Đóng góp phương pháp:** Dự án đề xuất không gian trạng thái 34 chiều gồm 20 chiều đặc trưng lưu lượng 
(bao gồm F1–F11 mạng và F12–F20 ứng dụng dựa trên OWASP CRS), 10D trạng thái temporal theo IP 
(lịch sử hành động, điểm leo thang, bộ nhớ phiên), và 4D phản hồi vòng kín từ bước trước — 
phủ rộng hơn các nghiên cứu tập trung đơn vào đặc trưng mạng. 
Tích hợp Ngẫu nhiên hóa miền trong huấn luyện cũng là đóng góp phương pháp giúp tăng khả năng tổng quát hóa.
```

**Thành:**
```
**Đóng góp phương pháp:** Dự án đề xuất không gian trạng thái 34 chiều gồm: 
(1) 20D đặc trưng lưu lượng (F1–F11 mạng + F12–F20 ứng dụng từ OWASP CRS); 
(2) 10D trạng thái temporal per-IP mã hóa one-hot action + 6 chỉ số tổng hợp (hold norm, damage EMA, trend, 
window fill, escalation score, miss budget) cho phép agent học tính liên tục hành động, xu hướng tổn thất, 
và trạng thái phiên mà không cần lưu trữ thô 10 bước; 
(3) 4D phản hồi vòng kín ghi lại effect từ hành động trước (webserver reachability, honeypot ratio, presence, 
service damage) — kích hoạt feedback loop giúp agent học causal reasoning và hành động có hậu quả.
Tích hợp Ngẫu nhiên hóa miền qua phân phối thực tế (Normal/LogNormal/Beta/Poisson) cũng tăng khả năng tổng quát hóa.
```

---

## Hướng dẫn áp dụng

### Cách nhanh nhất:
1. Mở file báo cáo: `Document/Drafts/review_notes/chapter_full_vietnamese_review_v2.md`
2. **Ctrl+H** (Find & Replace) hoặc Search/Replace trong VS Code
3. Sao chép từng cặp "Cần sửa từ" / "Thành" và thay thế

### Cách manual:
1. Đọc phần REPORT_DISCREPANCIES_ANALYSIS.md để hiểu chi tiết
2. Tự sửa từng đoạn, đảm bảo format Markdown đúng

---

## Kiểm tra sau khi sửa

- [ ] Tóm tắt rõ: "10 chiều temporal" ≠ "10 bước lưu trữ"
- [ ] Tóm tắt rõ: "từ bước 12" ≠ "15 bước chắc chắn"
- [ ] 3.1.4: Không gian trạng thái chi tiết 4D one-hot + 6 scalars + 4D effect
- [ ] 3.1.6: Escalation từ bước 12 + điều kiện + soft_guard_mode
- [ ] 3.3.5: v1/v2/v3 versioning rõ ràng
- [ ] Toàn bộ file compile Markdown không lỗi

