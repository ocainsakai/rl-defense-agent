# Hướng dẫn Upload lên Overleaf

## Phương pháp 1: Upload từ ZIP file (Nhanh nhất)

```bash
cd /path/to/Document
zip -r LaTeX.zip LaTeX/
```

Sau đó:
1. Vào Overleaf.com → New Project
2. Chọn "Upload Project"
3. Chọn file `LaTeX.zip` vừa tạo
4. Overleaf sẽ tự động giải nén và setup

---

## Phương pháp 2: Upload từng file thủ công

1. **Tạo project mới trong Overleaf**
   - Mở Overleaf.com
   - Click "New Project" → "Blank Project"

2. **Upload files từ thư mục `LaTeX/`:**
   - Click "Upload" → "Files"
   - Chọn các files này:
     - `main.tex` (QUAN TRỌNG - entry point)
     - `thesis_english.tex`
     - `chapter_full_latex.tex`
     - `paper_draft.tex`
     - `references.bib`
     - `sample.bib`

3. **Setup Bibliography:**
   - Project Settings → Bibliography tool: Biber (hoặc BibTeX)
   - Chọn file: `references.bib`

---

## Phương pháp 3: Sử dụng Git (Recommended cho long-term)

```bash
# Initialize git trong thư mục
cd /path/to/Document/LaTeX
git init
git add .
git commit -m "Initial LaTeX files"

# Push lên GitHub (nếu có)
# Sau đó sync với Overleaf thông qua GitHub integration
```

---

## ✅ Checklist trước khi compile trong Overleaf

- [ ] File `main.tex` có tồn tại
- [ ] File `references.bib` được configure đúng
- [ ] Tất cả các `\input{}` hoặc `\include{}` trong main.tex trỏ đến files có tồn tại
- [ ] Compiler được set thành: XeLaTeX hoặc pdfLaTeX
- [ ] Bibliography tool được enable

---

## Troubleshooting

### Error: "File not found"
- Kiểm tra path trong `\input{}` hoặc `\include{}` commands
- Đảm bảo tên file viết đúng (case-sensitive trên Linux)

### Error: "Bibliography not found"
- Chắc chắn `references.bib` được upload
- Vào Project Settings → Bibliography tool, chọn file đúng
- Click "Recompile" lại

### Error: "Undefined reference"
- Compile lại 2-3 lần (Overleaf cần nhiều passes để update references)
- Kiểm tra entries trong `.bib` file

---

**💡 Tips:**
- Lưu lại một bản backup từ Overleaf thường xuyên
- Sử dụng Git để version control
- Collaborate với team bằng Overleaf sharing features
