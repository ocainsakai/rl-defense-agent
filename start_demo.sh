#!/bin/bash
# start_demo.sh — Hướng dẫn khởi động Demo AI RL Defense Agent
# Usage: sudo bash start_demo.sh

BASE="/home/binhhl/Downloads/rl-defense-agent"
AI_DIR="$BASE/AI RL"
CONTAIN_DIR="$BASE/containernet/containernet"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Cần chạy với sudo: sudo bash start_demo.sh${NC}"
    exit 1
fi

step() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

cmd() {
    echo -e "  ${GREEN}$1${NC}"
}

# In lệnh + copy vào clipboard, hiện thông báo "Đã copy"
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
echo -e "${CYAN}║   AI RL DEFENSE AGENT — KHỞI ĐỘNG DEMO  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"

# ──────────────────────────────────────────
# BƯỚC 0: Dọn dẹp (tự động)
# ──────────────────────────────────────────
step "BƯỚC 0 — Dọn dẹp môi trường (tự động)"
echo "Đang dọn dẹp..."
mn -c 2>/dev/null
pkill -f "web.py" 2>/dev/null
pkill -f "infer.py" 2>/dev/null
pkill -f "main.py" 2>/dev/null
# Xóa interface còn sót từ lần chạy trước
for iface in root-mgmt r-mgmt r-ext r-web r-honey; do
    ip link delete "$iface" 2>/dev/null
done
> /tmp/sniffer_output.jsonl
echo -e "${GREEN}✓ Dọn dẹp xong.${NC}"

# ──────────────────────────────────────────
# BƯỚC 1: Khởi động Mininet
# ──────────────────────────────────────────
step "BƯỚC 1 — Mở terminal mới, chạy Mininet"
echo "Mở 1 terminal mới (Terminal 1) và chạy:"
echo ""
copy_cmd "cd $CONTAIN_DIR && sudo python3 -E test2.py"
echo ""
echo -e "Chờ thấy: ${YELLOW}mininet>${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 2: Mở node terminals
# ──────────────────────────────────────────
step "BƯỚC 2 — Terminal các Node (tự động)"
echo -e "${GREEN}✓ test2.py tự động mở 4 terminal: webserver / honeypot / attacker / router${NC}"
echo ""
echo -e "${YELLOW}Verify attacker namespace: ip addr show eth1 → phải thấy 10.0.10.10/24${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 3: Webserver
# ──────────────────────────────────────────
step "BƯỚC 3 — [Node: webserver] Khởi động Web Server"
echo -e "Trong terminal ${BOLD}Node: webserver${NC}:"
echo ""
copy_cmd "python3 $BASE/containernet/web/web.py"
echo ""
echo -e "Chờ thấy: ${YELLOW}* Running on http://0.0.0.0:8080${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 4: Honeypot
# ──────────────────────────────────────────
step "BƯỚC 4 — [Node: honeypot] Khởi động Honeypot"
echo -e "Trong terminal ${BOLD}Node: honeypot${NC}:"
echo ""
copy_cmd "python3 $BASE/containernet/web/web_honeypot.py"
echo ""
echo -e "Chờ thấy: ${YELLOW}* Running on http://0.0.0.0:8081${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 5: AI Defense Agent
# ──────────────────────────────────────────
step "BƯỚC 5 — Mở terminal mới, chạy AI Defense Agent"
echo "Mở 1 terminal mới (Terminal 2) và chạy:"
echo ""
copy_cmd "cd \"$AI_DIR\" && sudo python3 infer.py --watch /tmp/sniffer_output.jsonl --model runs/run_34d_v13/best_model --demo-safe --soft-guard assist"
echo ""
echo -e "${YELLOW}Note: NIDS Sniffer đã tự chạy trong router namespace (khởi động bởi test2.py)${NC}"
echo -e "Chờ thấy: ${YELLOW}[*] Waiting for new NIDS data...${NC}"
wait_enter

# ──────────────────────────────────────────
# BƯỚC 6: Monitor iptables
# ──────────────────────────────────────────
step "BƯỚC 6 — [Node: router] Monitor iptables"
echo -e "Trong terminal ${BOLD}Node: router${NC}:"
echo ""
copy_cmd "watch -n 1 \"iptables -L FORWARD -n --line-numbers && echo '' && iptables -t nat -L PREROUTING -n --line-numbers\""
wait_enter

# ──────────────────────────────────────────
# BƯỚC 7: Monitor actions.log
# ──────────────────────────────────────────
step "BƯỚC 7 — Mở terminal mới, Monitor AI Actions Log"
echo "Mở 1 terminal mới (Terminal 3) và chạy:"
echo ""
copy_cmd "tail -f \"$AI_DIR/actions.log\""
wait_enter

# ──────────────────────────────────────────
# BƯỚC 8: Chạy Demo Menu
# ──────────────────────────────────────────
step "BƯỚC 8 — [Node: attacker] Chạy Demo Menu"
echo -e "Trong terminal ${BOLD}Node: attacker${NC}, chạy:"
echo ""
copy_cmd "bash $CONTAIN_DIR/demo_menu.sh"

echo ""
echo -e "\n${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   MÔI TRƯỜNG SẴN SÀNG — BẮT ĐẦU DEMO   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo ""
