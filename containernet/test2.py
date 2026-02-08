#!/usr/bin/python
from mininet.net import Containernet
from mininet.node import Controller, Node
from mininet.cli import CLI
from mininet.log import info, setLogLevel
import os

def cleanup():
    info('*** Delete up old containers\n')
    os.system('docker stop $(docker ps -aq --filter name=mn.) 2>/dev/null')
    os.system('docker rm $(docker ps -aq --filter name=mn.) 2>/dev/null')
    os.system('mn -c 2>/dev/null')

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        pass

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def create_topology():
    cleanup()
    net = Containernet(controller=Controller)
    
    info('*** Adding controller\n')
    net.addController('c0')
    
    # ============== 1. CREATE NODES ==============
    info('*** Creating Nodes\n')
    firewall = net.addDocker('firewall', dimage='ubuntu-nettools:20.04', environment={'DEBIAN_FRONTEND': 'noninteractive'}, dns=['8.8.8.8'])
    nginx_node = net.addDocker('nginx', diamges='ubuntu-nettools:20.04', environment=['DEBIAN_FRONTEND': 'noninteractive'], dns= ['8.8.8.8'] )
    router = net.addDocker('router', cls=LinuxRouter, dimages='ubuntu-nettools:20.04', enviroment=['DEBIAN_FRONTEND': 'noninteractive'], dns=['8.8.8.8'])
    attacker = net.addDocker('attacker', dimage='ubuntu-nettools:20.04', environment={'DEBIAN_FRONTEND': 'noninteractive'}, dns=['8.8.8.8'], volumes=["/home/tringuyen/tools:/root/share:rw"])
    webserver = net.addDocker('webserver', dimage='ubuntu-nettools:20.04', environment={'DEBIAN_FRONTEND': 'noninteractive'},dns=['8.8.8.8'])
    wazuh = net.addDocker('wazuh', dimage='ubuntu-nettools:20.04', environment={'DEBIAN_FRONTEND': 'noninteractive'},dns=['8.8.8.8'])
    honeypot = net.addDocker('honeypot', dimage='ubuntu-nettools:20.04', environment={'DEBIAN_FRONTEND': 'noninteractive'},dns=['8.8.8.8'])

    # ============== 2. CREATE LINKS ==============
    info('*** Creating network links\n')
    net.addLink(attacker, router, intfName1='eth1', intfName2='r-ext')
    net.addLink(router, webserver, intfName1='r-web', intfName2='eth1')
    net.addLink(router, wazuh, intfName1='r-wazuh', intfName2='eth1')
    net.addLink(router, honeypot, intfName1='r-honey', intfName2='eth1')
    net.addLink()
    # ============== 3. START NETWORK ==============
    info('*** Starting network\n')
    net.start()
    
    # --- Config Router ---
    info('*** Config Router\n')
    router.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    router.cmd('ip addr flush dev r-ext')
    router.cmd('ip addr add 10.0.10.254/24 dev r-ext')
    
    router.cmd('ip addr flush dev r-web')
    router.cmd('ip addr add 192.168.10.1/24 dev r-web')
    
    router.cmd('ip addr flush dev r-wazuh')
    router.cmd('ip addr add 192.168.20.1/24 dev r-wazuh')
    
    router.cmd('ip addr flush dev r-honey')
    router.cmd('ip addr add 192.168.30.1/24 dev r-honey')

    # --- Config Nodes ---
    info('*** Configuring Node IPs & Route\n')

    # Attacker
    attacker.cmd('ip addr flush dev eth1')
    attacker.cmd('ip addr add 10.0.10.10/24 dev eth1')
    attacker.cmd('ip route del default')
    attacker.cmd('ip route add default via 10.0.10.254')
    
    # WebServer
    webserver.cmd('ip addr flush dev eth1')
    webserver.cmd('ip addr add 192.168.10.10/24 dev eth1')
    webserver.cmd('ip route del default')
    webserver.cmd('ip route add default via 192.168.10.1')
    
    # Wazuh
    wazuh.cmd('ip addr flush dev eth1')
    wazuh.cmd('ip addr add 192.168.20.20/24 dev eth1')
    wazuh.cmd('ip route del default')
    wazuh.cmd('ip route add default via 192.168.20.1')
    
    # Honeypot
    honeypot.cmd('ip addr flush dev eth1')
    honeypot.cmd('ip addr add 192.168.30.10/24 dev eth1')
    honeypot.cmd('ip route del default')
    honeypot.cmd('ip route add default via 192.168.30.1')

    # ============== IPTABLES ==============
    info('*** Configuring iptables\n')
    router.cmd('iptables -t nat -F')
    router.cmd('iptables -F FORWARD')
    
    # NAT rules
    router.cmd('iptables -t nat -A POSTROUTING -o r-web -j MASQUERADE')
    router.cmd('iptables -t nat -A POSTROUTING -o r-wazuh -j MASQUERADE')
    router.cmd('iptables -t nat -A POSTROUTING -o r-honey -j MASQUERADE')
    
    # Rule 1: ALLOW established/related connections 
    router.cmd('iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')
    
    # Rule 2: DENY Attacker from accessing Wazuh
    router.cmd('iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.20.20 -j DROP')
    
    # Rule 3: DENY Wazuh from initiating connections to external network
    router.cmd('iptables -A FORWARD -s 192.168.20.20 -d 10.0.10.0/24 -j DROP')
    
    # Rule 4: ALLOW internal nodes to send logs TO Wazuh
    router.cmd('iptables -A FORWARD -d 192.168.20.20 -s 192.168.10.0/24 -j ACCEPT')  # Webserver
    router.cmd('iptables -A FORWARD -d 192.168.20.20 -s 192.168.30.0/24 -j ACCEPT')  # Honeypot
    
    # Rule 5: ALLOW Attacker to access Webserver and Honeypot 
    router.cmd('iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.10.0/24 -j ACCEPT')  # To Webserver
    router.cmd('iptables -A FORWARD -s 10.0.10.0/24 -d 192.168.30.0/24 -j ACCEPT')  # To Honeypot
    
    # Rule 6: ALLOW Webserver and Honeypot to access any network
    router.cmd('iptables -A FORWARD -s 192.168.10.0/24 -j ACCEPT')  # Webserver
    router.cmd('iptables -A FORWARD -s 192.168.30.0/24 -j ACCEPT')  # Honeypot
    
    # Default DROP
    router.cmd('iptables -A FORWARD -j DROP')

    
    info('*** Running CLI\n')
    CLI(net)
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()