# Hướng Dẫn Sử Dụng Tài Liệu Tham Khảo

## Mục Lục
- [Giới thiệu](#giới-thiệu)
- [Cấu trúc file references.bib](#cấu-trúc-file-referencesbib)
- [Các loại tài liệu tham khảo](#các-loại-tài-liệu-tham-khảo)
- [Cách trích dẫn trong văn bản](#cách-trích-dẫn-trong-văn-bản)
- [Danh sách các tài liệu hiện có](#danh-sách-các-tài-liệu-hiện-có)
- [Hướng dẫn thêm tài liệu mới](#hướng-dẫn-thêm-tài-liệu-mới)
- [Biên dịch tài liệu](#biên-dịch-tài-liệu)

---

## Giới thiệu

File `references.bib` chứa tất cả các tài liệu tham khảo được sử dụng trong khóa luận tốt nghiệp. Các tài liệu này được quản lý theo định dạng **BibTeX** và được trích dẫn trong file LaTeX chính (`main.tex`).

---

## Cấu trúc file references.bib

Mỗi mục tham khảo có cấu trúc như sau:

```bibtex
@loại_tài_liệu{khóa_trích_dẫn,
  author       = {Tên tác giả},
  title        = {Tiêu đề tài liệu},
  year         = {Năm xuất bản},
  url          = {Đường dẫn URL},
  note         = {Ghi chú bổ sung}
}
```

**Giải thích:**
- `@loại_tài_liệu`: Xác định loại tài liệu (article, book, techreport,...)
- `khóa_trích_dẫn`: ID duy nhất để trích dẫn trong văn bản LaTeX
- Các trường thông tin: author, title, year, url,...

---

## Các loại tài liệu tham khảo

### 1. `@article` - Bài báo khoa học
Dùng cho các bài báo đăng trên tạp chí khoa học.

```bibtex
@article{nguyen2021deep,
  author  = {Nguyen, Thanh Thi and Reddi, Vijay Janapa},
  title   = {Deep Reinforcement Learning for Cyber Security},
  journal = {IEEE Transactions on Neural Networks and Learning Systems},
  volume  = {34},
  number  = {8},
  pages   = {3779--3795},
  year    = {2021}
}
```

### 2. `@book` - Sách
Dùng cho sách hoặc tài liệu dạng sách.

```bibtex
@book{suttonBarto2018,
  author    = {Sutton, Richard S. and Barto, Andrew G.},
  title     = {Reinforcement Learning: An Introduction},
  publisher = {MIT Press},
  edition   = {2nd},
  year      = {2018}
}
```

### 3. `@techreport` - Báo cáo kỹ thuật
Dùng cho các báo cáo từ tổ chức, công ty.

```bibtex
@techreport{verizonDBIR2024,
  author       = {{Verizon}},
  title        = {2024 Data Breach Investigations Report},
  institution  = {Verizon Communications Inc.},
  year         = {2024},
  url          = {https://www.verizon.com/...}
}
```

### 4. `@inproceedings` - Bài báo hội nghị
Dùng cho các bài báo trình bày tại hội nghị khoa học.

```bibtex
@inproceedings{lantzMininet2010,
  author    = {Lantz, Bob and Heller, Brandon and McKeown, Nick},
  title     = {A Network in a Laptop: Rapid Prototyping for SDN},
  booktitle = {Proceedings of the 9th ACM SIGCOMM Workshop},
  year      = {2010}
}
```

### 5. `@misc` - Tài liệu khác
Dùng cho website, tài liệu trực tuyến, phần mềm.

```bibtex
@misc{gymnasium2023,
  author       = {{Farama Foundation}},
  title        = {Gymnasium: A Standard Interface for RL Environments},
  year         = {2023},
  howpublished = {Online Documentation},
  url          = {https://gymnasium.farama.org/}
}
```

---

## Cách trích dẫn trong văn bản

### Trích dẫn cơ bản
```latex
\cite{khóa_trích_dẫn}
```

**Ví dụ:**
```latex
Theo báo cáo của Verizon \cite{verizonDBIR2024}, 80% các vụ xâm nhập...
```

### Trích dẫn nhiều nguồn
```latex
\cite{nguồn1, nguồn2, nguồn3}
```

**Ví dụ:**
```latex
Nhiều nghiên cứu đã chỉ ra rằng \cite{nguyen2021deep, lopez2020application}...
```

---

## Danh sách các tài liệu hiện có

| Khóa trích dẫn | Loại | Mô tả nội dung |
|----------------|------|----------------|
| `verizonDBIR2024` | Báo cáo | Báo cáo vi phạm dữ liệu 2024 của Verizon |
| `verizonDBIR2020` | Báo cáo | Báo cáo vi phạm dữ liệu 2020 của Verizon |
| `ibmPonemon2024` | Báo cáo | Chi phí vi phạm dữ liệu 2024 của IBM |
| `schulmanPPO2017` | Bài báo | Thuật toán PPO cho học tăng cường |
| `lantzMininet2010` | Hội nghị | Công cụ mô phỏng mạng Mininet |
| `gymnasium2023` | Tài liệu | Framework Gymnasium cho RL |
| `scapy2007` | Phần mềm | Công cụ xử lý gói tin Scapy |
| `flowFeatureSurvey2020` | Bài báo | Deep Learning cho an ninh mạng |
| `suttonBarto2018` | Sách | Sách giáo khoa học tăng cường |
| `ibmSOAR2023` | Tài liệu | Khái niệm SOAR của IBM |
| `honeypotSurvey2021` | Bài báo | Tổng quan về Honeypot và Honeynet |
| `alertFatigue2022` | Hội nghị | Nghiên cứu về Alert Fatigue trong SOC |
| `nguyen2021deep` | Bài báo | Deep RL cho an ninh mạng |
| `lopez2020application` | Bài báo | Deep RL cho phát hiện xâm nhập |
| `mitreAttack2023` | Tài liệu | MITRE ATT&CK Framework |

---

## Hướng dẫn thêm tài liệu mới

### Bước 1: Xác định loại tài liệu
Chọn loại phù hợp: `@article`, `@book`, `@techreport`, `@inproceedings`, hoặc `@misc`.

### Bước 2: Tạo khóa trích dẫn
- Sử dụng tên tác giả + năm: `nguyen2021`
- Hoặc tên viết tắt mô tả: `verizonDBIR2024`
- **Lưu ý:** Khóa phải là duy nhất trong file

### Bước 3: Điền thông tin
Thêm mục mới vào file `references.bib`:

```bibtex
@article{tenMoi2025,
  author  = {Tên Tác Giả},
  title   = {Tiêu đề bài báo},
  journal = {Tên tạp chí},
  year    = {2025},
  volume  = {1},
  pages   = {1--10},
  url     = {https://...}
}
```

### Bước 4: Sử dụng trong văn bản
Thêm trích dẫn trong file `main.tex`:
```latex
\cite{tenMoi2025}
```

---

## Biên dịch tài liệu

### Thứ tự biên dịch
Để cập nhật danh mục tài liệu tham khảo, chạy các lệnh theo thứ tự:

```bash
# Bước 1: Biên dịch LaTeX lần đầu
pdflatex main.tex

# Bước 2: Tạo danh mục tham khảo
bibtex main

# Bước 3: Biên dịch LaTeX lần 2 (liên kết tham khảo)
pdflatex main.tex

# Bước 4: Biên dịch LaTeX lần 3 (hoàn thiện)
pdflatex main.tex
```

### Sử dụng latexmk (khuyến nghị)
```bash
latexmk -pdf main.tex
```

---

## Một số lưu ý quan trọng

> ⚠️ **Lưu ý 1:** Luôn kiểm tra URL còn hoạt động trước khi thêm tài liệu mới.

> ⚠️ **Lưu ý 2:** Ưu tiên các nguồn có thể truy cập miễn phí (Open Access).

> ⚠️ **Lưu ý 3:** Ghi rõ ngày truy cập trong trường `note` cho các tài liệu trực tuyến.

> ⚠️ **Lưu ý 4:** Đảm bảo định dạng tên tác giả: "Họ, Tên" (ví dụ: "Nguyen, Van A")

---

## Liên hệ hỗ trợ

Nếu có thắc mắc về cách sử dụng tài liệu tham khảo hoặc định dạng BibTeX, tham khảo:
- [BibTeX Documentation](https://www.bibtex.org/)
- [Overleaf BibTeX Guide](https://www.overleaf.com/learn/latex/Bibliography_management_with_bibtex)

---

*Cập nhật lần cuối: Tháng 1/2026*
