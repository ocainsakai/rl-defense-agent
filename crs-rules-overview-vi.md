# 🛡️ OWASP CRS - Hướng dẫn tổng quan (Tiếng Việt)

> Tài liệu này giải thích cách hoạt động của OWASP Core Rule Set (CRS) dành cho người không chuyên kỹ thuật.

---

## 📖 CRS là gì?

**CRS (Core Rule Set)** là một bộ quy tắc bảo mật mã nguồn mở được phát triển bởi OWASP. Nó hoạt động như một "bộ lọc thông minh" đứng giữa người dùng và ứng dụng web của bạn, giúp phát hiện và ngăn chặn các cuộc tấn công phổ biến.

### Cách hoạt động đơn giản:

```
Người dùng gửi request → [CRS kiểm tra] → Hợp lệ? → Cho qua đến ứng dụng
                                        → Độc hại? → CHẶN và ghi log
```

---

## 🎯 Cơ chế tính điểm Anomaly (Điểm bất thường)

CRS sử dụng cơ chế **Anomaly Scoring** - tức là tính điểm bất thường cho mỗi request:

| Mức độ nghiêm trọng | Điểm số | Ý nghĩa |
|---------------------|---------|---------|
| **CRITICAL** | 5 | Phát hiện tấn công thực sự (SQL Injection, XSS...) |
| **ERROR** | 4 | Vi phạm nghiêm trọng giao thức |
| **WARNING** | 3 | Hành vi đáng ngờ |
| **NOTICE** | 2 | Vi phạm nhẹ |

### Ngưỡng chặn mặc định:
- **Request (Inbound)**: Tổng điểm ≥ **5** → Bị chặn
- **Response (Outbound)**: Tổng điểm ≥ **4** → Bị chặn

> 💡 **Ví dụ**: Nếu một request khớp với 1 rule CRITICAL (5 điểm), nó sẽ bị chặn ngay lập tức.

---

## 🔒 Các mức Paranoia (Độ nhạy)

Paranoia Level quyết định CRS sẽ "kỹ tính" đến mức nào khi kiểm tra:

| Mức | Mô tả | Đối tượng sử dụng | Cảnh báo giả |
|-----|-------|-------------------|--------------|
| **PL 1** | An toàn cơ bản | Website thông thường, blog | Hầu như không có |
| **PL 2** | Bảo mật tốt | Website có dữ liệu người dùng | Có thể có, cần điều chỉnh |
| **PL 3** | Bảo mật cao | Ngân hàng, tài chính | Nhiều, cần điều chỉnh kỹ |
| **PL 4** | Tối đa | Dữ liệu tuyệt mật, quân sự | Rất nhiều |

> ⚠️ **Lưu ý**: Mức cao hơn = bảo mật tốt hơn, nhưng cũng = nhiều cảnh báo giả hơn cần xử lý.

---

## 🔄 Luồng xử lý Request

```
┌─────────────────────────────────────────────────────────────────┐
│                    REQUEST TỪ NGƯỜI DÙNG                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  [Phase 1] KIỂM TRA HEADER                                      │
│  - Kiểm tra User-Agent, Host, Content-Type...                   │
│  - Phát hiện scanner, bot độc hại                               │
│  → Cộng điểm nếu phát hiện bất thường                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  [Phase 2] KIỂM TRA BODY                                        │
│  - Kiểm tra nội dung form, JSON, XML...                         │
│  - Phát hiện SQL Injection, XSS, RCE...                         │
│  → Cộng điểm nếu phát hiện bất thường                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  [ĐÁNH GIÁ] TỔNG ĐIỂM ≥ NGƯỠNG?                                 │
│  → CÓ: CHẶN REQUEST, ghi log                                    │
│  → KHÔNG: CHO QUA đến ứng dụng web                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    ỨNG DỤNG WEB XỬ LÝ                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  [Phase 3-4] KIỂM TRA RESPONSE                                  │
│  - Phát hiện rò rỉ dữ liệu nhạy cảm                             │
│  - Chặn nếu có thông tin credit card, SQL error...             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    TRẢ KẾT QUẢ CHO NGƯỜI DÙNG                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 Danh sách các file Rule

Chi tiết về từng nhóm rule được liệt kê trong file: **[crs-rules-list-vi.csv](./crs-rules-list-vi.csv)**

---

## 📌 Ví dụ thực tế

### ✅ Request hợp lệ (Cho qua)
```
GET /products?id=123
Host: example.com
User-Agent: Mozilla/5.0
```
→ Điểm: **0** → ✅ Cho qua

### ❌ SQL Injection (Bị chặn)
```
GET /products?id=1' OR '1'='1
Host: example.com
User-Agent: Mozilla/5.0
```
→ Rule 942xxx khớp → Điểm: **5** → ❌ Bị chặn

### ❌ XSS Attack (Bị chặn)
```
POST /comment
Content-Type: application/x-www-form-urlencoded

message=<script>document.cookie</script>
```
→ Rule 941xxx khớp → Điểm: **5** → ❌ Bị chặn

### ❌ Local File Inclusion (Bị chặn)
```
GET /file?path=../../../etc/passwd
Host: example.com
```
→ Rule 930xxx khớp → Điểm: **5** → ❌ Bị chặn

---

## 📚 Tài liệu tham khảo

- [OWASP CRS Official Documentation](https://coreruleset.org/docs/)
- [CRS GitHub Repository](https://github.com/coreruleset/coreruleset)

---

*Tài liệu được tạo để giúp người không chuyên hiểu về CRS - OWASP Core Rule Set*
