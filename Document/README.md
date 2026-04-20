# Document Structure

Cấu trúc tài liệu đã được tổ chức lại theo loại file, ngôn ngữ và chương để dễ quản lý.

## 📁 Cấu trúc Thư mục

```
Document/
├── LaTeX/                    # 📌 LATEX FILES FOR OVERLEAF
│   ├── main.tex             # Main thesis file
│   ├── thesis_english.tex   # English thesis
│   ├── chapter_full_latex.tex
│   ├── paper_draft.tex      # Draft version
│   ├── references.bib       # Bibliography
│   ├── sample.bib
│   └── [auxiliary files]    # .aux, .bbl, .blg, .out, .toc
│
├── Markdown/
│   ├── English/
│   │   ├── chapter3_4_english.md
│   │   ├── THESIS_COMPLETION_SUMMARY.md
│   │   └── script_thuyet_trinh.md
│   └── Vietnamese/
│       ├── chapter3_4_vietnamese.md
│       ├── chapter_full_vietnamese.md
│       ├── TOM_TAT_NOI_DUNG.md (Summary)
│       ├── HUONG_DAN_TAI_LIEU_THAM_KHAO.md (Reference Guide)
│       ├── Chapter1_2.md
│       └── Yêu cầu + Sườn mẫu báo cáo.md
│
├── Drafts/
│   └── review_notes/        # Các version review cũ
│       ├── chapter_full_vietnamese_review_notes_v1.md
│       ├── chapter_full_vietnamese_review_notes_v2.md
│       └── chapter_full_vietnamese_review_v2.md
│
├── Resources/
│   ├── Images/              # Hình ảnh
│   │   └── Picture2.png
│   ├── PDFs/                # Tài liệu PDF
│   │   ├── main.pdf
│   │   └── Report-v1.1.pdf
│   └── Docx/                # Tài liệu Word
│       └── Yêu cầu + Sườn mẫu báo cáo.docx
│
├── References/              # Thư mục tài liệu tham khảo
│
├── Supporting_Materials/    # Tài liệu hỗ trợ
│   └── Model-based Reflex Agents/
│
└── Summary/                 # Tóm tắt và các tài liệu cuối cùng
```

## 🚀 Hướng dẫn sử dụng Overleaf

### Để upload lên Overleaf:

1. **Sao chép toàn bộ thư mục `LaTeX/`**
   ```bash
   # Hoặc nén thư mục LaTeX
   zip -r LaTeX.zip LaTeX/
   ```

2. **Upload vào Overleaf:**
   - Tạo project mới trong Overleaf
   - Chọn "Upload Project" 
   - Chọn file ZIP hoặc upload files từ thư mục `LaTeX/`

3. **Các files quan trọng:**
   - `main.tex` - File chính để compile
   - `references.bib` - File tài liệu tham khảo (đảm bảo được upload)
   - `chapter_full_latex.tex` - Chapter chính
   - `thesis_english.tex` - Phiên bản tiếng Anh

### Chú ý khi làm việc với Overleaf:
- Luôn giữ `main.tex` là entry point
- Kiểm tra `references.bib` đã được configure trong project settings
- Các file `.aux`, `.bbl` được sinh tự động trong Overleaf

## 📝 Các thư mục khác

- **Markdown/**: Các file markdown cho dễ đọc trên GitHub/VS Code
- **Drafts/**: Các phiên bản cũ và ghi chú review (có thể xóa khi không cần)
- **Resources/**: Hình ảnh, PDF, và các file hỗ trợ khác
- **Supporting_Materials/**: Tài liệu bổ sung về các mô hình

## 🧹 Dọn dẹp

Các file cũ đã được di chuyển vào `Drafts/review_notes/` để không làm rối thư mục chính. Có thể xóa nếu không còn cần thiết.

---

**Last updated:** April 21, 2026
