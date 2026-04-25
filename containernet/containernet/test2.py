#!/usr/bin/python3
from mininet.net import Containernet
from mininet.node import Controller, Node
from mininet.cli import CLI
from mininet.log import info, setLogLevel
import os

REDIRECT_PORT = 4443  # nginx will listen here and proxy to honeypot:8081

def cleanup():
    info('*** Cleanup old mininet state & old mn.* containers (if any)\n')
    os.system('docker stop $(docker ps -aq --filter name=mn.) 2>/dev/null || true')
    os.system('docker rm $(docker ps -aq --filter name=mn.) 2>/dev/null || true')
    os.system('mn -c 2>/dev/null || true')

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('sysctl -w net.ipv4.conf.all.rp_filter=2')
        self.cmd('sysctl -w net.ipv4.conf.default.rp_filter=2')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def create_topology():
    cleanup()
    net = Containernet(controller=Controller)

    info('*** Adding controller\n')
    net.addController('c0')

    # ================== 1) CREATE NODES ==================
    info('*** Creating Nodes\n')
    router    = net.addHost('router', cls=LinuxRouter)
    attacker  = net.addHost('attacker')
    webserver = net.addHost('webserver')
    wazuh     = net.addHost('wazuh')
    honeypot  = net.addHost('honeypot')

    # Root host = VM Ubuntu thật (root namespace)
    root = net.addHost('root', inNamespace=False)

    # ================== 2) CREATE LINKS ==================
    info('*** Creating network links\n')
    net.addLink(attacker, router, intfName1='eth1',       intfName2='r-ext')
    net.addLink(root,     router, intfName1='root-mgmt',  intfName2='r-mgmt')
    net.addLink(router, webserver, intfName1='r-web',   intfName2='eth1')
    net.addLink(router, wazuh,     intfName1='r-wazuh', intfName2='eth1')
    net.addLink(router, honeypot,  intfName1='r-honey', intfName2='eth1')

    # ================== 3) START NETWORK ==================
    info('*** Starting network\n')
    net.start()

    # ================== 4) CONFIG IP & ROUTES ==================
    info('*** Config Router interfaces\n')

    router.cmd('ip addr flush dev r-ext 2>/dev/null || true')
    router.cmd('ip addr add 10.0.10.254/24 dev r-ext')
    router.cmd('ip link set r-ext up')

    router.cmd('ip addr flush dev r-mgmt 2>/dev/null || true')
    router.cmd('ip addr add 10.0.99.254/24 dev r-mgmt')
    router.cmd('ip link set r-mgmt up')

    router.cmd('ip addr flush dev r-web 2>/dev/null || true')
    router.cmd('ip addr add 192.168.10.1/24 dev r-web')
    router.cmd('ip link set r-web up')

    router.cmd('ip addr flush dev r-wazuh 2>/dev/null || true')
    router.cmd('ip addr add 192.168.20.1/24 dev r-wazuh')
    router.cmd('ip link set r-wazuh up')

    router.cmd('ip addr flush dev r-honey 2>/dev/null || true')
    router.cmd('ip addr add 192.168.30.1/24 dev r-honey')
    router.cmd('ip link set r-honey up')

    info('*** Configuring hosts IPs & default routes\n')

    attacker.cmd('ip addr flush dev eth1 2>/dev/null || true')
    attacker.cmd('ip addr add 10.0.10.10/24 dev eth1')
    attacker.cmd('ip link set eth1 up')
    attacker.cmd('ip route del default 2>/dev/null || true')
    attacker.cmd('ip route add default via 10.0.10.254')

    webserver.cmd('ip addr flush dev eth1 2>/dev/null || true')
    webserver.cmd('ip addr add 192.168.10.10/24 dev eth1')
    webserver.cmd('ip link set eth1 up')
    webserver.cmd('ip route del default 2>/dev/null || true')
    webserver.cmd('ip route add default via 192.168.10.1')

    wazuh.cmd('ip addr flush dev eth1 2>/dev/null || true')
    wazuh.cmd('ip addr add 192.168.20.20/24 dev eth1')
    wazuh.cmd('ip link set eth1 up')
    wazuh.cmd('ip route del default 2>/dev/null || true')
    wazuh.cmd('ip route add default via 192.168.20.1')

    honeypot.cmd('ip addr flush dev eth1 2>/dev/null || true')
    honeypot.cmd('ip addr add 192.168.30.10/24 dev eth1')
    honeypot.cmd('ip link set eth1 up')
    honeypot.cmd('ip route del default 2>/dev/null || true')
    honeypot.cmd('ip route add default via 192.168.30.1')

    info('*** VM access\n')
    root.cmd('ip addr flush dev root-mgmt 2>/dev/null || true')
    root.cmd('ip addr add 10.0.99.1/24 dev root-mgmt')
    root.cmd('ip link set root-mgmt up')

    # route replace to be idempotent
    root.cmd('ip route replace 10.0.10.0/24 via 10.0.99.254 dev root-mgmt')
    root.cmd('ip route replace 192.168.10.0/24 via 10.0.99.254 dev root-mgmt')
    root.cmd('ip route replace 192.168.20.0/24 via 10.0.99.254 dev root-mgmt')
    root.cmd('ip route replace 192.168.30.0/24 via 10.0.99.254 dev root-mgmt')

    # ================== 5) IPTABLES (BASELINE, NO REDIRECT RULE) ==================
    info('*** Configuring iptables on router\n')

    router.cmd('iptables -F')
    router.cmd('iptables -X')
    router.cmd('iptables -t nat -F')
    router.cmd('iptables -t nat -X')
    router.cmd('iptables -t mangle -F 2>/dev/null || true')
    router.cmd('iptables -t mangle -X 2>/dev/null || true')

    router.cmd('iptables -P INPUT ACCEPT')
    router.cmd('iptables -P OUTPUT ACCEPT')
    router.cmd('iptables -P FORWARD DROP')

    router.cmd('iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')

    # (A) Allow VM mgmt subnet -> ALL lab subnets
    router.cmd('iptables -A FORWARD -s 10.0.99.0/24 -d 10.0.10.0/24 -j ACCEPT')
    router.cmd('iptables -A FORWARD -s 10.0.99.0/24 -d 192.168.10.0/24 -j ACCEPT')
    router.cmd('iptables -A FORWARD -s 10.0.99.0/24 -d 192.168.20.0/24 -j ACCEPT')
    router.cmd('iptables -A FORWARD -s 10.0.99.0/24 -d 192.168.30.0/24 -j ACCEPT')

    # (B) Deny attacker -> Wazuh
    router.cmd('iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.20.20 -j DROP')
    # (C) Deny Wazuh initiating to attacker subnet
    router.cmd('iptables -A FORWARD -s 192.168.20.20 -d 10.0.10.0/24 -j DROP')
    # (D) Allow internal nodes -> Wazuh (logs)
    router.cmd('iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.20.20 -j ACCEPT')
    router.cmd('iptables -A FORWARD -s 192.168.30.0/24 -d 192.168.20.20 -j ACCEPT')
    # (E) Allow attacker -> Webserver & Honeypot subnet (routing)
    router.cmd('iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.10.0/24 -j ACCEPT')
    router.cmd('iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.30.0/24 -j ACCEPT')
    # (F) Allow Webserver & Honeypot
    router.cmd('iptables -A FORWARD -s 192.168.10.0/24 -j ACCEPT')
    router.cmd('iptables -A FORWARD -s 192.168.30.0/24 -j ACCEPT')

    def dnat_rule(in_if, src_cidr, vip, dport, to_port):
        return (f"iptables -t nat -A PREROUTING -i {in_if} -s {src_cidr} "
                f"-d {vip} -p tcp --dport {dport} "
                f"-j DNAT --to-destination 10.0.10.254:{to_port}")

    # WEB: 192.168.10.10
    router.cmd(dnat_rule('r-ext',  '10.0.10.0/24', '192.168.10.10', 80,  80))
    router.cmd(dnat_rule('r-ext',  '10.0.10.0/24', '192.168.10.10', 443, 443))
    router.cmd(dnat_rule('r-mgmt', '10.0.99.0/24', '192.168.10.10', 80,  80))
    router.cmd(dnat_rule('r-mgmt', '10.0.99.0/24', '192.168.10.10', 443, 443))

    # HONEYPOT: 192.168.30.10 (direct access optional)
    router.cmd(dnat_rule('r-ext',  '10.0.10.0/24', '192.168.30.10', 80,  80))
    router.cmd(dnat_rule('r-ext',  '10.0.10.0/24', '192.168.30.10', 443, 443))
    router.cmd(dnat_rule('r-mgmt', '10.0.99.0/24', '192.168.30.10', 80,  80))
    router.cmd(dnat_rule('r-mgmt', '10.0.99.0/24', '192.168.30.10', 443, 443))

    # allow INPUT 80/443 + 4443 (so you can redirect later without changing code)
    router.cmd("iptables -A INPUT -i r-ext  -p tcp --dport 80  -j ACCEPT")
    router.cmd("iptables -A INPUT -i r-ext  -p tcp --dport 443 -j ACCEPT")
    router.cmd(f"iptables -A INPUT -i r-ext  -p tcp --dport {REDIRECT_PORT} -j ACCEPT")
    router.cmd("iptables -A INPUT -i r-mgmt -p tcp --dport 80  -j ACCEPT")
    router.cmd("iptables -A INPUT -i r-mgmt -p tcp --dport 443 -j ACCEPT")
    router.cmd(f"iptables -A INPUT -i r-mgmt -p tcp --dport {REDIRECT_PORT} -j ACCEPT")

    # ================== 6) ROUTER NGINX: 443->WEB, 4443->HONEYPOT (READY) ==================
    info('*** Router NGINX: 443->webserver:8080, 4443->honeypot:8081\n')

    router.cmd('mkdir -p /tmp/router-nginx/{conf,logs,run,certs,cache}')

    # cert for WEB VIP (192.168.10.10) - used for both 443 and 4443 to avoid mismatch
    router.cmd(r"""cat > /tmp/router-nginx/certs/openssl-web.cnf <<'EOF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req
[dn]
C  = VN
ST = HCM
L  = HCM
O  = MininetLab
CN = 192.168.10.10
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = 192.168.10.10
EOF
""")
    router.cmd(
        "openssl req -x509 -nodes -days 365 "
        "-newkey rsa:2048 "
        "-keyout /tmp/router-nginx/certs/web.key "
        "-out /tmp/router-nginx/certs/web.crt "
        "-config /tmp/router-nginx/certs/openssl-web.cnf"
    )

    # cert for HONEYPOT
    router.cmd(r"""cat > /tmp/router-nginx/certs/openssl-honey.cnf <<'EOF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req
[dn]
C  = VN
ST = HCM
L  = HCM
O  = MininetLab
CN = 192.168.30.10
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = 192.168.30.10
EOF
""")
    router.cmd(
        "openssl req -x509 -nodes -days 365 "
        "-newkey rsa:2048 "
        "-keyout /tmp/router-nginx/certs/honey.key "
        "-out /tmp/router-nginx/certs/honey.crt "
        "-config /tmp/router-nginx/certs/openssl-honey.cnf"
    )

    router.cmd(fr"""cat > /tmp/router-nginx/conf/nginx.conf <<'EOF'
worker_processes  1;
events {{ worker_connections 1024; }}

http {{
  log_format lab_detail
    '$remote_addr - $remote_user [$time_local] '
    '"$request" $status $body_bytes_sent '
    'rt=$request_time urt=$upstream_response_time '
    'uaddr="$upstream_addr" ustatus="$upstream_status" '
    'host="$host" sni="$ssl_server_name" '
    'tls=$ssl_protocol/$ssl_cipher '
    'ref="$http_referer" ua="$http_user_agent" '
    'xff="$http_x_forwarded_for" '
    'cl="$http_content_length" ct="$http_content_type" '
    'reqid="$request_id"';

  access_log /tmp/router-nginx/logs/access.log lab_detail;
  error_log  /tmp/router-nginx/logs/error.log notice;
  proxy_temp_path /tmp/router-nginx/cache;
  client_header_timeout 300s;

  # ========== WEB VIP 192.168.10.10 ==========
  server {{
    listen 80;
    server_name 192.168.10.10;
    location / {{ return 301 https://$host$request_uri; }}
  }}

  # Normal users: 443 -> webserver:8080
  server {{
    listen 443 ssl;
    server_name 192.168.10.10;

    ssl_certificate     /tmp/router-nginx/certs/web.crt;
    ssl_certificate_key /tmp/router-nginx/certs/web.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;

    location / {{
      proxy_pass http://192.168.10.10:8080;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Request-ID $request_id;
      client_max_body_size 50m;
      proxy_connect_timeout 5s;
      proxy_read_timeout 60s;
    }}
  }}

  # 4443 -> honeypot:8081
  server {{
    listen {REDIRECT_PORT} ssl;
    server_name 192.168.10.10;

    # use WEB cert so https://192.168.10.10 still matches even when redirected internally
    ssl_certificate     /tmp/router-nginx/certs/web.crt;
    ssl_certificate_key /tmp/router-nginx/certs/web.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;

    location / {{
      proxy_pass http://192.168.30.10:8081;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Request-ID $request_id;
      client_max_body_size 50m;
      proxy_connect_timeout 5s;
      proxy_read_timeout 60s;
    }}
  }}

  # ========== HONEYPOT VIP 192.168.30.10 (direct access optional) ==========
  server {{
    listen 80;
    server_name 192.168.30.10;
    location / {{ return 301 https://$host$request_uri; }}
  }}

  server {{
    listen 443 ssl;
    server_name 192.168.30.10;

    ssl_certificate     /tmp/router-nginx/certs/honey.crt;
    ssl_certificate_key /tmp/router-nginx/certs/honey.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;

    location / {{
      proxy_pass http://192.168.30.10:8081;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Request-ID $request_id;
      client_max_body_size 50m;
      proxy_connect_timeout 5s;
      proxy_read_timeout 60s;
    }}
  }}
}}
EOF
""")

    router.cmd("nginx -s quit -c /tmp/router-nginx/conf/nginx.conf 2>/dev/null || true")
    router.cmd("nginx -t -c /tmp/router-nginx/conf/nginx.conf")
    router.cmd("nginx -p /tmp/router-nginx -c /tmp/router-nginx/conf/nginx.conf -g 'pid /tmp/router-nginx/run/nginx.pid;'")

    info('\n*** APPLY REDIRECT (MANUAL, run when you want to test)\n')
    info('  Redirect attacker (10.0.10.10) from WEB VIP 443 -> router:4443 (honeypot upstream)\n')
    info(f"    router iptables -t nat -I PREROUTING 1 -i r-ext -s 10.0.10.10 -d 192.168.10.10 -p tcp --dport 443 -j REDIRECT --to-ports {REDIRECT_PORT}\n")
    info('  Remove redirect rule (example):\n')
    info("    router iptables -t nat -D PREROUTING 1\n\n")

    info('*** TEST\n')
    info('  Start apps:\n')
    info('    webserver python3 app.py   (HTTP :8080)\n')
    info('    honeypot  python3 app.py   (HTTP :8081)\n\n')
    info('  From attacker:\n')
    info('    attacker curl -kI https://192.168.10.10/\n')
    info('  From host VM:\n')
    info('    curl -kI https://192.168.10.10/\n\n')
    info('  Router logs:\n')
    info('    router tail -f /tmp/router-nginx/logs/access.log\n\n')

    # ================== 7) START SNIFFER ON ROUTER (r-ext, before nginx) ==================
    # Pre-create keylog file with world-writable permissions so any user (sqlmap, Python tools)
    # can append TLS session keys without EACCES errors.
    os.system('touch /tmp/tls_keys.log && chmod 666 /tmp/tls_keys.log')
    os.system('> /tmp/sniffer_output.jsonl')

    info('*** Starting Sniffer on router (interface r-ext) with TLS decryption\n')
    sniffer_cmd = (
        "python3 -c \""
        "import sys; sys.path.insert(0, '/home/binhhl/Downloads/rl-defense-agent/System'); "
        "from main import _run_realtime; "
        "_run_realtime('r-ext', 1.0, '/tmp/sniffer_output.jsonl', 'jsonl', "
        "keylog_file='/tmp/tls_keys.log')"
        "\""
    )
    router.popen(['bash', '-c', sniffer_cmd])
    info('*** Sniffer + tshark L7 running -> /tmp/sniffer_output.jsonl\n')
    info('*** TLS keylog -> /tmp/tls_keys.log  (written by attacker curl)\n')
    info('\n*** ATTACK WITH TLS DECRYPTION (enables F6-F20):\n')
    info('    attacker SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/"\n')
    info('    attacker SSLKEYLOGFILE=/tmp/tls_keys.log curl -k "https://192.168.10.10/?id=1%27 OR 1=1--"\n')

    info('*** Opening node terminals\n')
    for node_name in ['webserver', 'honeypot', 'attacker', 'router']:
        net.get(node_name).cmd(
            f'xfce4-terminal --disable-server --title="Node: {node_name}" &'
        )

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
