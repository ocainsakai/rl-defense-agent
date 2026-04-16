#!/bin/bash
# start_retrain.sh — Demo Vòng Lặp Học Liên Tục (ACT 9)
# Minh họa: Thu thập traffic thật → Gán nhãn → Retrain từ model cũ
# Usage: sudo bash start_retrain.sh

BASE="/home/binhhl/Downloads/rl-defense-agent"
AI_DIR="$BASE/AI RL"
CONTAIN_DIR="$BASE/containernet/containernet"

MODEL_PATH="$AI_DIR/runs/run_final_v4/best_model"
COLLECT_FILE="/tmp/collect_$(date +%Y%m%d).jsonl"
LABELED_FILE="$AI_DIR/training_data_retrain.jsonl"
BACKUP_MODEL="$AI_DIR/runs/run_final_v4/best_model_backup.zip"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Cần chạy với sudo: sudo bash start_retrain.sh${NC}"
    exit 1
fi

step() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

copy_cmd() {
    echo -e "  ${GREEN}$1${NC}"
    echo -n "$1" | DISPLAY=:0 xclip -selection clipboard 2>/dev/null
    echo -e "  ${CYAN}↑ Đã copy — Ctrl+Shift+V để paste${NC}"
}

wait_enter() {
    echo -ne "\n${YELLOW}>>> Nhấn Enter để tiếp tục...${NC}"
    read -r
}

clear
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   AI RL — DEMO VÒNG LẶP HỌC LIÊN TỤC   ║${NC}"
echo -e "${CYAN}║   Thu thập → Gán nhãn → Retrain          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Model hiện tại : ${YELLOW}$MODEL_PATH.zip${NC}"
echo -e "  Collect file   : ${YELLOW}$COLLECT_FILE${NC}"
echo -e "  Output label   : ${YELLOW}$LABELED_FILE${NC}"

# ──────────────────────────────────────────
# ĐIỀU KIỆN TIÊN QUYẾT
# ──────────────────────────────────────────
step "ĐIỀU KIỆN — Mininet + Webserver + Honeypot phải đang chạy"
echo -e "Script này chạy SAU khi đã hoàn thành start_demo.sh (Bước 1-4)."
echo ""
echo -e "Nếu chưa khởi động, chạy trước:"
copy_cmd "sudo bash $BASE/start_demo.sh"
echo ""
echo -e "${YELLOW}Xác nhận Mininet đang chạy? (Enter để tiếp tục, Ctrl+C để thoát)${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 1: Dọn file cũ
# ──────────────────────────────────────────
step "BƯỚC 1 — Dừng infer.py cũ + Dọn file collect"
echo "Đang dừng infer.py cũ (nếu đang chạy)..."
pkill -f "infer.py" 2>/dev/null && echo -e "${GREEN}✓ Đã dừng infer.py cũ.${NC}" \
    || echo -e "${CYAN}  (infer.py chưa chạy — bỏ qua)${NC}"
sleep 1
> "$COLLECT_FILE" 2>/dev/null || true
echo -e "${GREEN}✓ Đã xóa collect file cũ: $COLLECT_FILE${NC}"
echo -e "${YELLOW}  Mininet / webserver / honeypot / NIDS sniffer vẫn giữ nguyên.${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 2: Chạy AI với --collect
# ──────────────────────────────────────────
step "BƯỚC 2 — Mở terminal mới, chạy AI Agent ở chế độ THU THẬP"
echo -e "Khác với demo thường: thêm ${BOLD}--collect${NC} để ghi raw data."
echo ""
echo "Mở 1 terminal mới (Terminal: AI-Collect) và chạy:"
echo ""
copy_cmd "cd \"$AI_DIR\" && sudo python3 infer.py --watch /tmp/sniffer_output.jsonl --model runs/run_final_v4/best_model --collect $COLLECT_FILE"
echo ""
echo -e "Chờ thấy: ${YELLOW}[*] Waiting for new NIDS data...${NC}"
echo -e "${CYAN}→ Agent vừa phòng thủ, vừa ghi toàn bộ features + quyết định ra file${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 3: Sinh traffic tấn công
# ──────────────────────────────────────────
step "BƯỚC 3 — [Node: attacker] Sinh traffic để thu thập data"
echo -e "Trong terminal ${BOLD}Node: attacker${NC}, chạy các kịch bản sau:"
echo ""
echo -e "${CYAN}  Kịch bản 1 — SYN Flood (để thu syn_flood data):${NC}"
copy_cmd "hping3 -S -p 443 --flood -c 500 192.168.10.10"
wait_enter

echo -e "${CYAN}  Kịch bản 2 — Brute Force (để thu brute_force data):${NC}"
copy_cmd "bash $CONTAIN_DIR/brute_keepalive.py"
wait_enter

echo -e "${CYAN}  Kịch bản 3 — SQLmap (để thu sqli_xss data):${NC}"
copy_cmd "SSLKEYLOGFILE=/tmp/tls_keys.log sqlmap -u \"https://192.168.10.10/?search=test\" --batch --level=1 --risk=1 --ignore-code=401 --delay=1"
wait_enter

echo -e "${CYAN}  Kịch bản 4 — Traffic bình thường (để thu benign data):${NC}"
copy_cmd "for i in \$(seq 1 10); do SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk https://192.168.10.10/ -o /dev/null; sleep 3; done"
echo ""
echo -e "${YELLOW}Chờ cho đủ ~2 phút traffic mỗi loại, rồi nhấn Enter...${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 4: Kiểm tra data thu thập được
# ──────────────────────────────────────────
step "BƯỚC 4 — Kiểm tra data đã thu thập (tự động)"
echo "Đang kiểm tra $COLLECT_FILE ..."
echo ""

COUNT=$(wc -l < "$COLLECT_FILE" 2>/dev/null || echo 0)
echo -e "  Số records thu thập: ${YELLOW}$COUNT${NC}"
echo ""

if [ "$COUNT" -lt 5 ]; then
    echo -e "${RED}Chưa đủ data (cần ít nhất 5 records). Quay lại Bước 3.${NC}"
    wait_enter
fi

echo "Phân phối AI action đã ra:"
echo ""
copy_cmd "jq -r '.ai_action' $COLLECT_FILE | sort | uniq -c | sort -rn"
echo ""
echo -e "${CYAN}Chạy lệnh trên để xem phân phối trước khi tiếp tục.${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 5: Dry-run gán nhãn tự động
# ──────────────────────────────────────────
step "BƯỚC 5 — Dry-run: Xem nhãn tự động TRƯỚC KHI ghi file"
echo "Mở 1 terminal mới và chạy:"
echo ""
copy_cmd "python3 \"$AI_DIR/adapt_pipeline.py\" --input $COLLECT_FILE --output \"$LABELED_FILE\" --auto-label --dry-run"
echo ""
echo -e "Kết quả sẽ hiện:"
echo -e "  ${GREEN}✓ sqli_xss: 12 records (conf avg 0.82)${NC}"
echo -e "  ${GREEN}✓ syn_flood: 8 records (conf avg 0.91)${NC}"
echo -e "  ${YELLOW}  noisy_normal: 3 records (conf avg 0.45) ← heuristic không chắc${NC}"
echo ""
echo -e "${CYAN}→ Review nhãn dự đoán. Nếu ổn, nhấn Enter để ghi thật.${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 6: Gán nhãn thật
# ──────────────────────────────────────────
step "BƯỚC 6 — Gán nhãn thật vào $LABELED_FILE"
echo ""
copy_cmd "python3 \"$AI_DIR/adapt_pipeline.py\" --input $COLLECT_FILE --output \"$LABELED_FILE\" --auto-label --min-confidence 0.6"
echo ""
echo -e "Flag ${BOLD}--min-confidence 0.6${NC}: bỏ qua record heuristic không chắc chắn."
echo -e "Chỉ ghi những record có confidence ≥ 0.6 vào training data."
wait_enter

# ──────────────────────────────────────────
# BƯỚC 7: Backup model cũ
# ──────────────────────────────────────────
step "BƯỚC 7 — Backup model cũ (tự động)"
if [ -f "$MODEL_PATH.zip" ]; then
    cp "$MODEL_PATH.zip" "$BACKUP_MODEL"
    echo -e "${GREEN}✓ Backup: $BACKUP_MODEL${NC}"
else
    echo -e "${RED}Không tìm thấy model tại $MODEL_PATH.zip${NC}"
    echo -e "${YELLOW}Kiểm tra lại đường dẫn trước khi retrain.${NC}"
    wait_enter
fi
wait_enter

# ──────────────────────────────────────────
# BƯỚC 8: Retrain
# ──────────────────────────────────────────
step "BƯỚC 8 — Retrain từ model cũ (fine-tune 50k steps)"
echo -e "${BOLD}Quan trọng${NC}: --resume_from kế thừa toàn bộ kiến thức cũ."
echo -e "50k steps (~3 phút) thay vì 300k steps ban đầu."
echo ""
echo "Mở 1 terminal mới và chạy:"
echo ""
copy_cmd "cd \"$AI_DIR\" && python3 train.py --mode replay --training_data $LABELED_FILE --resume_from runs/run_final_v4/best_model.zip --timesteps 50000"
echo ""
echo -e "Theo dõi reward tăng dần trong log:"
echo -e "  ${YELLOW}ep_rew_mean: -0.42 → -0.28 → ... → gần 0${NC}"
echo ""
echo -e "${CYAN}Chờ training xong (~3-5 phút) rồi nhấn Enter...${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 9: Kiểm tra model mới
# ──────────────────────────────────────────
step "BƯỚC 9 — Tìm model mới và test"
echo "Model mới được lưu vào thư mục run mới nhất:"
echo ""
copy_cmd "ls -lt \"$AI_DIR/runs/\" | head -5"
echo ""
echo -e "Chạy lệnh trên để tìm run mới nhất, sau đó test:"
echo ""
echo -e "  ${GREEN}NEW_RUN=\$(ls -t \"$AI_DIR/runs/\" | head -1)${NC}"
echo -e "  ${GREEN}sudo python3 \"$AI_DIR/infer.py\" --watch /tmp/sniffer_output.jsonl \\${NC}"
echo -e "  ${GREEN}    --model \"$AI_DIR/runs/\$NEW_RUN/best_model\"${NC}"
echo ""
echo -e "${CYAN}→ Chạy lại kịch bản tấn công từ demo_menu.sh để so sánh hành vi${NC}"
wait_enter

# ──────────────────────────────────────────
# HOÀN THÀNH
# ──────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   VÒNG LẶP HỌC LIÊN TỤC HOÀN THÀNH     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} Data thu thập : $COLLECT_FILE"
echo -e "  ${GREEN}✓${NC} Data có nhãn  : $LABELED_FILE"
echo -e "  ${GREEN}✓${NC} Model backup  : $BACKUP_MODEL"
echo -e "  ${GREEN}✓${NC} Model mới     : runs/run_<timestamp>/best_model.zip"
echo ""
echo -e "${YELLOW}Nếu model mới tệ hơn → rollback:${NC}"
copy_cmd "cp \"$BACKUP_MODEL\" \"$MODEL_PATH.zip\""
echo ""
