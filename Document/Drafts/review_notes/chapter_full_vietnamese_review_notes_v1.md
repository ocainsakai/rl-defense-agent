# Review Notes v1

Scope: Round 1-3 issues and replacement text aligned with code.

## Round 1 (structure/template)
- Abstract length/abbrev rule: rewrite to 200–300 words, no undefined abbreviations, no URLs.
- TOC mismatch for Chapter 2: align headings to actual content or rework content to match TOC list.
- Remove internal notes like //NOTE, //MÔ TẢ SƠ TRONG SLIDE.
- List of Tables missing Table 3.2b and Table 4.6.
- Figure placeholder ![][image1] missing caption and not listed in List of Figures.

## Round 2 (code alignment)
### Reward formulation (replace Section 3.1.4 and 3.1.6 reward paragraph)
Replacement paragraph:
"Hàm phần thưởng sử dụng cấu trúc persistence-aware. Thành phần nền: 
$R_{base} = B_{action} - C_{action} - 0.12 \cdot service\_damage$, 
trong đó $service\_damage$ là mức tổn thất dịch vụ đo từ trạng thái effect bước sau. Ngoài ra hệ thống bổ sung shaping để tăng ổn định: phạt dao động khi hạ mức phòng thủ khi vẫn còn áp lực tấn công, thưởng nhỏ khi giữ hành động phù hợp theo ngữ cảnh, và thưởng giữ Redirect khi phiên L7 đang hoạt động nhưng chưa đủ bằng chứng Block."

### Rate limit + iptables chains (replace 3.1.6 + 3.1.7 action execution)
Replacement details:
- RateLimit: hashlimit 2/sec, burst 5.
- Apply to INPUT and FORWARD (DNAT to nginx causes INPUT hits).
- Redirect: NAT PREROUTING with REDIRECT to port 4443.
- Block: DROP on INPUT and FORWARD.

### Redirect escalation logic (replace 3.1.6/3.1.7 text about 60 seconds)
Replacement paragraph:
"Cơ chế leo thang L7 dùng phiên soft escalation theo cửa sổ mềm (15 bước). Hệ thống tích lũy bằng chứng (presence, honeypot hits, miss budget) và đặt cờ block_ready_latched khi đủ điều kiện, không dựa trên bộ đếm 60 giây cố định."

### SafetyNet overrides (add to 3.1.7)
Add a short paragraph:
"Ở inference, lớp SafetyNet áp dụng các guardrails hạ tầng: ép Redirect khi phát hiện tín hiệu L7 nhưng model chọn Allow/RateLimit, và giữ Block khi damage_ema vẫn cao để tránh dao động."

### Fixed window size (add to 3.2.3)
Add sentence:
"WINDOW_SIZE_SECONDS được cố định 1.0s trong code; thay đổi sẽ làm lệch chuẩn hóa và giảm độ chính xác của policy."

## Round 3 (results/discussion)
### Add metrics definition at 4.1
Replacement block:
"4.1.1 Định nghĩa chỉ số: Detection rate tính trên active-threat steps; FPR tính trên normal steps. Per-window là đánh giá từng cửa sổ 1s; per-session coi một phiên bị phát hiện nếu có ít nhất một cửa sổ vượt ngưỡng."

### Discussion shortening
- RQ1–RQ3: giữ 1–2 câu kết luận + 1 câu implication, tránh lặp số liệu.
- Move ablation caveat "không đo experimentally" sang Limitations.

---
End.
