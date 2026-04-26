#!/bin/bash
# demo_brute_escalation.sh — Demo leo thang tốc độ Brute Force
# Allow → RateLimit → Redirect → Block
#
# Chạy từ Node: attacker (10.0.10.10)
# Yêu cầu: infer.py đang chạy

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

demo_curl() {
    SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk \
        --http1.1 --no-sessionid --no-keepalive \
        -H 'Connection: close' -H 'Cache-Control: no-cache' \
        "$@"
}

# ── Hiển thị AI state mới nhất từ actions.log ────────────────────────────────
START_LINE=0
show_ai_state() {
    python3 - <<PYEOF 2>/dev/null
import json, os, sys
log_path = '$ACTIONS_LOG'
attacker = '$ATTACKER_IP'
start    = int(os.environ.get('DEMO_START_LINE', '0'))

try:
    with open(log_path) as f:
        lines = [l for l in f if '"src_ip": "' + attacker + '"' in l and l.strip()]
except:
    lines = []

new_lines = lines[start:]
if not new_lines:
    print("  \033[2m[AI] chưa có dữ liệu mới\033[0m")
    sys.exit(0)

d = json.loads(new_lines[-1])
rl    = d.get('rl_action_name', '?')
final = d.get('final_action_name', '?')
wlen  = d.get('t_window_len', 0) or 0
score = d.get('t_escalation_score', 0.0) or 0.0
redir = d.get('t_redirect_hits', 0) or 0
pres  = d.get('t_presence_hits', 0) or 0
honey = d.get('t_honeypot_hits', 0) or 0
ready = d.get('t_block_ready', False)
prm   = d.get('soft_guard_promoted', False)
probs = d.get('action_probs', {})

colors = {'Allow':'\033[0;32m','RateLimit':'\033[0;33m','Redirect':'\033[1;33m','Block':'\033[0;31m'}
fc = colors.get(final, '\033[0m')

latch = ' \033[0;31m[BLOCK_READY✓]\033[0m' if ready else f' [{wlen}/12]'
note  = ''
if rl != final:
    note = f'  \033[2m← override (RL said {rl})\033[0m'
elif prm:
    note = f'  \033[2m← soft_guard promoted\033[0m'

prob_str = '  '.join(f"{k}={v:.0%}" for k,v in probs.items() if v > 0.05) if probs else ''
print(f"  \033[2m[AI]\033[0m {fc}{final}\033[0m{latch}  score={score:.3f}  r/p/h={redir}/{pres}/{honey}{note}")
if prob_str:
    print(f"       probs: {prob_str}")
PYEOF
}

# Poll để lấy final_action mới nhất
get_final_action() {
    python3 - <<PYEOF 2>/dev/null
import json, os
log_path = '$ACTIONS_LOG'
attacker = '$ATTACKER_IP'
start    = int(os.environ.get('DEMO_START_LINE', '0'))
try:
    with open(log_path) as f:
        lines = [l for l in f if '"src_ip": "' + attacker + '"' in l and l.strip()]
    new_lines = lines[start:]
    if new_lines:
        # Scan toàn bộ: Block và RateLimit đều có thể xuất hiện rồi biến mất
        has_ratelimit = False
        for l in new_lines:
            fa = json.loads(l).get('final_action_name')
            if fa == 'Block':
                print('Block')
                raise SystemExit
            if fa == 'RateLimit':
                has_ratelimit = True
        if has_ratelimit:
            print('RateLimit')
        else:
            print(json.loads(new_lines[-1]).get('final_action_name',''))
except SystemExit:
    pass
except:
    pass
PYEOF
}

wait_for_action() {
    local target="$1"
    local timeout_s=${2:-60}
    local deadline=$(( SECONDS + timeout_s ))
    while [ $SECONDS -lt $deadline ]; do
        local fa
        fa=$(DEMO_START_LINE=$START_LINE get_final_action)
        if [ "$fa" = "$target" ]; then return 0; fi
        sleep 1
    done
    return 1
}

wait_for_block() {
    local timeout_s=${1:-120}
    local deadline=$(( SECONDS + timeout_s ))
    while [ $SECONDS -lt $deadline ]; do
        sleep 2 &
        SLEEP_PID=$!
        # Ctrl+C trong sleep → kill sleep + thoát hàm
        trap 'kill $SLEEP_PID 2>/dev/null; return 130' INT
        wait $SLEEP_PID 2>/dev/null
        trap - INT

        local fa
        fa=$(DEMO_START_LINE=$START_LINE get_final_action)
        show_ai_state
        if [ "$fa" = "Block" ]; then
            # Dừng brute ngay — không để traffic tiếp tục làm rác actions.log
            kill "$BRUTE_PID" 2>/dev/null
            wait "$BRUTE_PID" 2>/dev/null
            echo ""
            echo -e "${RED}${BOLD}██████╗ ██╗      ██████╗  ██████╗██╗  ██╗${NC}"
            echo -e "${RED}${BOLD}██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝${NC}"
            echo -e "${RED}${BOLD}██████╔╝██║     ██║   ██║██║     █████╔╝ ${NC}"
            echo -e "${RED}${BOLD}██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ${NC}"
            echo -e "${RED}${BOLD}██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗${NC}"
            echo -e "${RED}${BOLD}╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝${NC}"
            echo -e "  ${GREEN}✓ RL tự quyết Block${NC}"
            return 0
        fi
    done
    return 1
}

# ── SETUP ────────────────────────────────────────────────────────────────────
clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  DEMO: Brute Force Leo Thang                         ║${NC}"
echo -e "${CYAN}║  Allow ──▶ RateLimit ──▶ Redirect+Block              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${DIM}Nguyên lý:${NC}"
echo -e "${DIM}  • Chậm  (1 req/2s, nhiều URL)    → F1 thấp, F6=0       → Allow${NC}"
echo -e "${DIM}  • Vừa   (4 req/0.5s, URL đa dạng) → F1≈80pps, F6 thấp  → RateLimit${NC}"
echo -e "${DIM}  • Nhanh (3+ req/s cùng /login)    → F6=1.0              → Redirect${NC}"
echo -e "${DIM}  • Liên tục (keep-alive brute)      → session tích lũy   → Block${NC}"
echo ""

if ! pgrep -f "infer.py" > /dev/null 2>&1; then
    echo -e "${RED}[WARN] infer.py chưa chạy!${NC}"
    echo -e "${RED}  cd \"AI RL\" && sudo python3 infer.py --watch /tmp/sniffer_output.jsonl --model runs/run_34d_v13/best_model --demo-safe${NC}"
    echo ""
fi

# Kiểm tra còn iptables rule cũ không — nếu có → IP bị Block ngay từ đầu → Phase 3 không thấy traffic
STALE_RULES=$(sudo nsenter -n -t "$(pgrep -f 'router'| head -1)" iptables -L FORWARD -n 2>/dev/null | grep -c "$ATTACKER_IP" || echo 0)
if [ "$STALE_RULES" -gt 0 ] 2>/dev/null; then
    echo -e "${RED}[WARN] Còn iptables rule cũ cho $ATTACKER_IP — chạy option [r] trong demo_menu.sh để reset trước!${NC}"
    echo ""
fi

START_LINE=$(grep -c "\"src_ip\": \"$ATTACKER_IP\"" "$ACTIONS_LOG" 2>/dev/null || echo 0)
export DEMO_START_LINE=$START_LINE
echo -e "${DIM}[INFO] Theo dõi từ dòng $START_LINE trong actions.log${NC}"
echo ""
echo -ne "${YELLOW}>>> Nhấn Enter để bắt đầu...${NC}"
read -r

# ── PHASE 1: Slow browsing → Allow ───────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}[PHASE 1] Duyệt web bình thường — kỳ vọng: Allow${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}1 request mỗi 2 giây, URL đa dạng → F6=0 (< 3 req/window) → Allow${NC}"
echo ""

BROWSE_PATHS=("/" "/about" "/products" "/contact" "/register" "/faq" "/" "/about")
for i in "${!BROWSE_PATHS[@]}"; do
    path="${BROWSE_PATHS[$i]}"
    printf "  [%d/8] GET %-12s  " $((i+1)) "$path"
    demo_curl -o /dev/null "$WEB$path"
    show_ai_state
    sleep 2
done

echo ""
echo -e "${GREEN}✓ Phase 1 xong${NC}"
echo -ne "${YELLOW}>>> Nhấn Enter để sang Phase 2 (RateLimit)...${NC}"
read -r

# ── PHASE 2: Noisy burst → RateLimit ─────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}[PHASE 2] Spam reload nhanh — kỳ vọng: RateLimit${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}Rate-controlled: curl chạy background, sleep 0.15s cố định → 6-7 req/s × 10 pkt ≈ 65 pps → RateLimit${NC}"
echo -e "${DIM}(tách curl khỏi sleep để response time không làm chậm rate)${NC}"
echo ""

# Background curl: sleep 0.15s kiểm soát rate, không phụ thuộc vào thời gian response curl
# 6.7 req/s × 10 pkt/req ≈ 67 pps → F1_norm = log1p(67)/log1p(500) ≈ 0.68 → RateLimit zone (0.664-0.801)
# Không dùng keep-alive → F7≈0, F6≈0 → brute_signal thấp → model dùng F1 để quyết định
PATHS=("/" "/login" "/register" "/products" "/about" "/contact" "/search" "/faq" "/faq" "/about")
CURL_PIDS=()
echo "  Gửi req background (0.15s/req, ~67 pps) — dừng khi ăn RateLimit..."
for i in $(seq 1 40); do
    path="${PATHS[$(( (i-1) % ${#PATHS[@]} ))]}"
    printf "  [%2d/40] GET %-12s  " $i "$path"
    demo_curl -o /dev/null "$WEB$path" &
    CURL_PIDS+=($!)
    sleep 0.15

    fa=$(DEMO_START_LINE=$START_LINE get_final_action)
    if [ "$fa" = "RateLimit" ]; then
        kill "${CURL_PIDS[@]}" 2>/dev/null
        wait "${CURL_PIDS[@]}" 2>/dev/null
        show_ai_state
        echo -e "  ${YELLOW}✓ RateLimit — dừng spam${NC}"
        break
    elif [ "$fa" = "Block" ]; then
        kill "${CURL_PIDS[@]}" 2>/dev/null
        wait "${CURL_PIDS[@]}" 2>/dev/null
        show_ai_state
        echo -e "  ${RED}⚠ Block triggered — tốc độ còn cao, giảm xuống nếu gặp lại${NC}"
        break
    elif (( i % 5 == 0 )); then
        show_ai_state
    else
        echo ""
    fi
done
kill "${CURL_PIDS[@]}" 2>/dev/null
wait "${CURL_PIDS[@]}" 2>/dev/null

echo ""
echo -e "${YELLOW}✓ Phase 2 xong${NC}"
# Cooldown: để traffic Phase 2 tắt hoàn toàn trước khi Phase 3 bắt đầu
echo -e "${DIM}[Cooldown 3s để traffic Phase 2 clear...]${NC}"
sleep 3
echo -ne "${YELLOW}>>> Nhấn Enter để sang Phase 3 (Redirect)...${NC}"
read -r

# ── PHASE 3: Keep-alive brute force → Redirect rồi tự leo thang Block ─────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}${BOLD}[PHASE 3] Brute Force Keep-alive → Redirect → Block${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}requests.Session keep-alive → F6=1.0, F7=1.0 (10 req/s, IAT đều 100ms)${NC}"
echo -e "${DIM}brute_signal > 0.6 → Override 0 force Redirect ngay, session recycle 0.5s → honeypot nhanh${NC}"
echo -e "${DIM}RL phát hiện → Redirect → honeypot tích lũy → tự leo thang Block${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Output brute_keepalive redirect vào tmpfile — terminal chỉ show AI state
# Dùng setsid để brute_keepalive.py chạy trong process group riêng
BRUTE_LOG=$(mktemp /tmp/brute_XXXXXX.log)
SSLKEYLOGFILE=/tmp/tls_keys.log setsid python3 "$SCRIPT_DIR/brute_keepalive.py" > "$BRUTE_LOG" 2>&1 &
BRUTE_PID=$!

cleanup_brute() {
    if [ -n "$BRUTE_PID" ] && kill -0 "$BRUTE_PID" 2>/dev/null; then
        # SIGKILL cả process group để Python không catch và hang
        kill -9 -- -"$BRUTE_PID" 2>/dev/null
        pkill -9 -f "brute_keepalive.py" 2>/dev/null
    fi
    BRUTE_PID=""
    rm -f "$BRUTE_LOG"
}
trap 'cleanup_brute; exit 0' EXIT INT TERM

echo -e "${DIM}brute_keepalive.py chạy trực tiếp (PID=$BRUTE_PID, ~3 phút tối đa)${NC}"
echo -e "${DIM}Theo dõi AI state — kỳ vọng: Redirect trước, Block sau khi tích đủ bằng chứng...${NC}"
echo -e "${DIM}(Ctrl+C để dừng bất cứ lúc nào)${NC}"
echo ""

wait_for_block 200
BLOCK_RESULT=$?

cleanup_brute
trap - EXIT INT TERM

# ── VERIFY ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}[VERIFY] Kiểm tra kết quả${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -ne "Thử curl ngay bây giờ... "
RESULT=$(demo_curl --max-time 4 "$WEB/?verify=$(date +%s%N)" 2>&1)
if echo "$RESULT" | grep -q "T3ch Stor3"; then
    echo -e "${YELLOW}→ HONEYPOT (vẫn Redirect)${NC}"
elif echo "$RESULT" | grep -q "Tech Store"; then
    echo -e "${GREEN}→ Webserver thật (chưa Block)${NC}"
else
    echo -e "${RED}→ Không có response → BLOCKED ✓${NC}"
fi

echo ""
if [ $BLOCK_RESULT -eq 0 ]; then
    echo -e "${RED}${BOLD}✓ Demo thành công: Allow → RateLimit → Redirect → Block (3 phases)${NC}"
else
    echo -e "${YELLOW}⚠ Block chưa fire trong thời gian chờ. Kiểm tra infer.py và honeypot.${NC}"
fi

echo ""
echo -e "${DIM}Reset: chạy option [r] trong demo_menu.sh từ Node router${NC}"
