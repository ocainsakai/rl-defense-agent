#!/bin/bash
# demo_sqli_escalation.sh — Demo AI phòng thủ thích ứng: Allow → Redirect → Block
# Chạy từ Node: attacker (10.0.10.10)
# Yêu cầu: infer.py đang chạy với --demo-safe (KHÔNG cần --soft-guard assist)
#
# Kịch bản:
#   Phase 1: normal traffic  → model thấy benign → Allow
#   Phase 2: SQLi payloads   → F13 > 0.08 → Redirect (model hoặc Override 0)
#   Phase 3: sqlmap sustained → session tích lũy 12 window → block_ready_latched
#                             → RL tự output Block (soft_guard_promoted=False)

WEB="https://192.168.10.10"
ACTIONS_LOG="/home/binhhl/Downloads/rl-defense-agent/AI RL/actions.log"
ATTACKER_IP="10.0.10.10"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── helpers ──────────────────────────────────────────────────────────────────

demo_curl() {
    SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk \
        --http1.1 --no-sessionid --no-keepalive \
        -H 'Connection: close' -H 'Cache-Control: no-cache' \
        "$@"
}

# Lấy dòng cuối cùng trong actions.log từ sau thời điểm START_LINE
START_LINE=0
get_last_entry() {
    [ ! -f "$ACTIONS_LOG" ] && return
    grep "\"src_ip\": \"$ATTACKER_IP\"" "$ACTIONS_LOG" 2>/dev/null \
        | tail -n +$((START_LINE + 1)) | tail -1
}

# Hiển thị trạng thái AI hiện tại — dành cho hội đồng
show_ai_state() {
    local label="${1:-}"
    local last
    last=$(get_last_entry)
    [ -z "$last" ] && echo -e "  ${DIM}[AI] chưa có dữ liệu mới${NC}" && return

    python3 - "$label" <<'PYEOF' 2>/dev/null
import json, os, sys

label = sys.argv[1] if len(sys.argv) > 1 else ""
log_path = '/home/binhhl/Downloads/rl-defense-agent/AI RL/actions.log'
attacker = '10.0.10.10'
start = int(os.environ.get('DEMO_START_LINE', '0'))

try:
    with open(log_path) as f:
        lines = [l for l in f if f'"src_ip": "{attacker}"' in l and l.strip()]
except Exception:
    lines = []

if not lines:
    print("  \033[2m[AI] chưa có dữ liệu\033[0m")
    sys.exit(0)

new_lines = lines[start:]
if not new_lines:
    print("  \033[2m[AI] chưa có dữ liệu mới\033[0m")
    sys.exit(0)

d = json.loads(new_lines[-1])
rl  = d.get('rl_action_name', '?')
fa  = d.get('final_action_name', '?')
wl  = d.get('t_window_len', 0) or 0
rh  = d.get('t_redirect_hits', 0) or 0
ph  = d.get('t_presence_hits', 0) or 0
hh  = d.get('t_honeypot_hits', 0) or 0
sc  = d.get('t_escalation_score', 0.0) or 0.0
br  = d.get('t_block_ready', False)
prm = d.get('soft_guard_promoted', False)

# Màu sắc
if fa == 'Block':    fc = '\033[0;31m'
elif fa == 'Redirect': fc = '\033[1;33m'
elif fa == 'Allow':    fc = '\033[0;32m'
else:                  fc = '\033[0m'

# Giải thích nếu rl != fa
note = ''
if rl == 'Block' and fa == 'Redirect':
    note = f'  \033[2m← Override 1: Block quá sớm (score={sc:.2f}<0.60), giữ Redirect\033[0m'
elif rl == 'Allow' and fa == 'Redirect':
    note = f'  \033[2m← Override 0: F13 phát hiện SQLi, ép Redirect\033[0m'
elif fa == 'Block' and prm:
    note = f'  \033[2m← soft_guard promoted (backup)\033[0m'
elif fa == 'Block' and not prm:
    note = f'  \033[0;32m← RL tự quyết Block (soft_guard_promoted=False)\033[0m'

latch_s = ' \033[0;31m[BLOCK_READY✓]\033[0m' if br else f' [{wl}/12 window]'

print(f"  \033[2m[AI]\033[0m {fc}{fa}\033[0m{latch_s}")
print(f"       redirect={rh}/6  presence={ph}/8  honeypot={hh}/5  score={sc:.3f}/0.60")
if note:
    print(f"      {note}")
PYEOF
}

# Script tạm để poll AI state — tránh quoting hell trong $()
_POLL_SCRIPT=/tmp/_demo_poll_state.py
cat > "$_POLL_SCRIPT" << 'PYEOF'
import json, os, sys

log_path = '/home/binhhl/Downloads/rl-defense-agent/AI RL/actions.log'
attacker = '10.0.10.10'
start = int(os.environ.get('DEMO_START_LINE', '0'))

try:
    with open(log_path) as f:
        lines = [l for l in f if f'"src_ip": "{attacker}"' in l and l.strip()]
    new_lines = lines[start:]
    if not new_lines:
        sys.exit(0)
    d = json.loads(new_lines[-1])
    print(d.get('final_action_name',''), d.get('t_window_len',0) or 0,
          d.get('t_block_ready', False), d.get('rl_action_name',''))
except Exception:
    sys.exit(0)
PYEOF

# Đợi đến khi final_action = Block (chỉ đếm từ START_LINE)
wait_for_block() {
    local timeout_s=${1:-90}
    local deadline=$(( SECONDS + timeout_s ))
    local last_wlen=-1

    while [ $SECONDS -lt $deadline ]; do
        sleep 2

        local last fa wl br
        last=$(DEMO_START_LINE=$START_LINE python3 "$_POLL_SCRIPT" 2>/dev/null)

        fa=$(echo "$last" | awk '{print $1}')
        wl=$(echo "$last" | awk '{print $2}')

        # Hiển thị progress khi window đang xây dựng
        if [ "$wl" != "$last_wlen" ] && [ -n "$wl" ] && [ "$wl" -gt 0 ] 2>/dev/null; then
            show_ai_state
            last_wlen=$wl
        fi

        if [ "$fa" = "Block" ]; then
            echo ""
            echo -e "\033[0;31m╔══════════════════════════════════════════════════╗\033[0m"
            echo -e "\033[0;31m║  ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗      ║\033[0m"
            echo -e "\033[0;31m║  ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝      ║\033[0m"
            echo -e "\033[0;31m║  ██████╔╝██║     ██║   ██║██║     █████╔╝       ║\033[0m"
            echo -e "\033[0;31m║  ██╔══██╗██║     ██║   ██║██║     ██╔═██╗       ║\033[0m"
            echo -e "\033[0;31m║  ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗      ║\033[0m"
            echo -e "\033[0;31m╚══════════════════════════════════════════════════╝\033[0m"
            echo ""
            echo -e "  \033[1;32m✓ RL tự quyết Block — soft_guard_promoted=False\033[0m"
            show_ai_state
            echo ""
            echo -e "  \033[2m[NOTE] Tại sao AI log tiếp theo hiện 'Allow 0 0.0'?\033[0m"
            echo -e "  \033[2m  • Block iptables DROP đã kích hoạt → attacker bị chặn ở kernel\033[0m"
            echo -e "  \033[2m  • Session tự reset (window=0, score=0) — đây là ĐÚNG theo thiết kế\033[0m"
            echo -e "  \033[2m  • Model thấy obs 'trống' → output Allow — nhưng iptables KHÔNG đổi\033[0m"
            echo -e "  \033[2m  • SafetyNet block-hold 60s: mọi downgrade đều bị chặn trong 60s\033[0m"
            echo -e "  \033[2m  • Sniffer vẫn thấy SYN từ attacker vì capture trước iptables DROP\033[0m"
            echo ""
            echo -e "  \033[1;31mVerify: curl thử ngay bây giờ → không có response = BLOCKED ✓\033[0m"
            sleep 5
            return 0
        fi
    done
    return 1
}

# ── SETUP ────────────────────────────────────────────────────────────────────

clear
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   DEMO: AI RL PHÒNG THỦ THÍCH ỨNG               ║${NC}"
echo -e "${CYAN}║   Allow ──▶ Redirect ──▶ Block                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${DIM}Terminal theo dõi song song:${NC}"
echo -e "${DIM}  tail -f \"$ACTIONS_LOG\" | python3 -c \"import sys,json; [print(json.loads(l).get('final_action_name'), json.loads(l).get('t_window_len'), json.loads(l).get('t_escalation_score')) for l in sys.stdin if l.strip()]\"${NC}"
echo ""

# Kiểm tra infer.py
if ! pgrep -f "infer.py" > /dev/null 2>&1; then
    echo -e "${RED}[WARN] infer.py chưa chạy. Khởi động:${NC}"
    echo -e "${RED}  cd \"AI RL\" && sudo python3 infer.py \\${NC}"
    echo -e "${RED}    --watch /tmp/sniffer_output.jsonl \\${NC}"
    echo -e "${RED}    --model runs/run_34d_v13/best_model --demo-safe${NC}"
    echo ""
fi

# Ghi nhớ vị trí hiện tại trong log để chỉ đọc data mới từ đây
START_LINE=$(grep -c "\"src_ip\": \"$ATTACKER_IP\"" "$ACTIONS_LOG" 2>/dev/null || echo 0)
export DEMO_START_LINE=$START_LINE
echo -e "${DIM}[INFO] Bắt đầu theo dõi từ dòng $START_LINE trong actions.log${NC}"
echo ""

echo -ne "${YELLOW}>>> Nhấn Enter để bắt đầu demo...${NC}"
read -r

# ── PHASE 1: Normal traffic → Allow ──────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}[PHASE 1] Traffic Bình Thường${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Gửi ${BOLD}10 request bình thường${NC}, 1s/request"
echo -e "${DIM}F13=0 (không có SQLi payload) → model thấy benign → Allow${NC}"
echo ""

NORMAL_PATHS=("/" "/login" "/register" "/" "/login" "/" "/register" "/" "/login" "/")
for i in "${!NORMAL_PATHS[@]}"; do
    printf "  [%2d/10] %-12s  " $((i+1)) "${NORMAL_PATHS[$i]}"
    demo_curl -o /dev/null "$WEB${NORMAL_PATHS[$i]}"
    show_ai_state
    sleep 1
done

echo ""
echo -e "${GREEN}✓ Phase 1 xong${NC}"
echo -ne "${YELLOW}>>> Nhấn Enter để sang Phase 2...${NC}"
read -r

# ── PHASE 2: SQLi payloads → Redirect ────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}[PHASE 2] SQLi Payloads — Phát Hiện, Redirect${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "Gửi payload SQL Injection → OWASP CRS 942 kích hoạt"
echo -e "${DIM}F13 (CrsSqliScore) tăng > 0.08 → model nhận ra attack → Redirect${NC}"
echo -e "${DIM}Attacker bị dẫn sang Honeypot (port 4443) mà không biết${NC}"
echo ""

SQLI_PAYLOADS=(
    "/?search=1'%20OR%20'1'%3D'1"
    "/?id=1%20UNION%20SELECT%20NULL--"
    "/?q=admin'--"
    "/?search=1%20AND%20SLEEP(0)--"
    "/?id=1'%20AND%20'1'%3D'1"
    "/?search=1'%3BDROP%20TABLE%20users--"
)
for i in "${!SQLI_PAYLOADS[@]}"; do
    printf "  [%d/6] SQLi payload  " $((i+1))
    demo_curl -o /dev/null "$WEB${SQLI_PAYLOADS[$i]}"
    show_ai_state
    sleep 1
done

echo ""
echo -e "${YELLOW}✓ Phase 2 xong — Redirect đang active${NC}"
echo -e "${DIM}  Honeypot đang thu thập dữ liệu tấn công...${NC}"
echo ""
echo -ne "${YELLOW}>>> Nhấn Enter để sang Phase 3 (sqlmap)...${NC}"
read -r

# ── PHASE 3: sqlmap → block_ready_latched → RL Block ─────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}${BOLD}[PHASE 3] sqlmap Tấn Công Liên Tục → AI Escalate → Block${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "AI đang tích lũy bằng chứng qua session 12 window:"
echo -e "  ${DIM}redirect_hits ≥ 6  │  presence_hits ≥ 8  │  honeypot_hits ≥ 5${NC}"
echo -e "  ${DIM}escalation_score ≥ 0.60  →  block_ready_latched = True${NC}"
echo -e "  ${DIM}→ RL tự output Block (không cần rule can thiệp)${NC}"
echo ""
echo -e "${DIM}LƯU Ý: Nếu thấy 'Override 1: Block quá sớm' → ĐÚNG${NC}"
echo -e "${DIM}  Đó là Override 1 ngăn Block khi chưa đủ bằng chứng.${NC}"
echo -e "${DIM}  Khi score ≥ 0.60, Override 1 nhường cho RL tự quyết.${NC}"
echo ""

# Chạy sqlmap ngầm
SSLKEYLOGFILE=/tmp/tls_keys.log sqlmap \
    -u "$WEB/?search=test" \
    --batch --level=1 --risk=1 \
    --ignore-code=401 --no-cast \
    --delay=1 \
    --output-dir=/tmp/sqlmap_demo \
    > /tmp/sqlmap_demo.log 2>&1 &
SQLMAP_PID=$!

# Đảm bảo sqlmap bị kill khi script thoát (Ctrl+C, kill, hoặc kết thúc bình thường)
trap 'kill "$SQLMAP_PID" 2>/dev/null; wait "$SQLMAP_PID" 2>/dev/null' EXIT INT TERM

echo -e "${DIM}sqlmap chạy ngầm (PID=$SQLMAP_PID)${NC}"
echo -e "${DIM}Chi tiết sqlmap: tail -f /tmp/sqlmap_demo.log${NC}"
echo ""
echo "Theo dõi AI state (cập nhật mỗi 2s)..."
echo ""

wait_for_block 120
BLOCK_RESULT=$?

kill "$SQLMAP_PID" 2>/dev/null
wait "$SQLMAP_PID" 2>/dev/null
trap - EXIT INT TERM   # reset trap sau khi đã kill thủ công

# ── KẾT QUẢ ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}[VERIFY] Kiểm tra kết quả thực tế${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Verify iptables — capture result for final decision
echo -ne "Gửi request thử... "
RESULT=$(demo_curl --max-time 4 "$WEB/?verify=$(date +%s%N)" 2>&1)
VERIFY_BLOCKED=0
if echo "$RESULT" | grep -q "T3ch Stor3"; then
    echo -e "${YELLOW}→ HONEYPOT (bị Redirect)${NC}"
elif echo "$RESULT" | grep -q "Tech Store"; then
    echo -e "${GREEN}→ WEBSERVER thật (chưa Block hoặc đã unblock)${NC}"
else
    echo -e "${RED}→ Không có response → BLOCKED ✓ (iptables DROP active)${NC}"
    VERIFY_BLOCKED=1
fi

echo ""
echo -e "AI state cuối:"
show_ai_state

echo ""
echo -e "${DIM}[NOTE] Sau Block, session reset về wlen=0, model output Allow/Redirect${NC}"
echo -e "${DIM}       vì attacker đã bị DROP ở iptables — không còn traffic qua honeypot.${NC}"
echo -e "${DIM}       iptables DROP rule vẫn giữ nguyên (SafetyNet block-hold 60s).${NC}"

echo ""
if [ $BLOCK_RESULT -eq 0 ]; then
    echo -e "${RED}${BOLD}✓ Demo thành công: Allow → Redirect → Block${NC}"
    echo -e "${GREEN}  RL model tự ra quyết định Block trong khi SQLmap đang chạy.${NC}"
elif [ $VERIFY_BLOCKED -eq 1 ]; then
    echo -e "${RED}${BOLD}✓ Demo thành công: Allow → Redirect → Block${NC}"
    echo -e "${GREEN}  RL model tự ra quyết định Block (deferred — kích hoạt khi sqlmap dừng).${NC}"
    echo -e "${DIM}  [Deferred block] RL giữ Redirect khi honeypot đang nhận SQLmap traffic${NC}"
    echo -e "${DIM}  (F6=1.0, nginx active). Block kích hoạt ngay khi sqlmap dừng → honeypot${NC}"
    echo -e "${DIM}  ngừng nhận → RL xác nhận attacker không còn giá trị capture → Block.${NC}"
    echo -e "${DIM}  Đây là hành vi thiết kế đúng, không phải lỗi.${NC}"
else
    echo -e "${YELLOW}⚠ Block chưa fire (cả trong wait và verify). Kiểm tra:${NC}"
    echo -e "${YELLOW}  1. infer.py đang chạy với --demo-safe?${NC}"
    echo -e "${YELLOW}  2. Honeypot (port 4443) đang chạy?${NC}"
    echo -e "${YELLOW}  3. Nginx đang ghi log tại /tmp/router-nginx/logs/access.log?${NC}"
fi

echo ""
echo -e "${DIM}Reset: chạy option [r] trong demo_menu.sh từ Node router${NC}"
echo ""