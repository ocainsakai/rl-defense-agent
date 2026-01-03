import socket
import random
import time
import threading
import argparse
import sys
import ipaddress
from datetime import datetime
from typing import List, Dict
import json
from scapy.all import IP, TCP, sr1, send, ICMP

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class NetworkScanner:
    """
    Network Scanner
    
    Features:
    - TCP Connect Scan (-sT)
    - TCP SYN Scan (-sS)
    - UDP Scan (-sU)
    - Ping Sweep (-sn)
    - Port Range Scanning
    - Service Detection
    - OS Fingerprinting (basic)
    - Output formats (text, JSON)
    """
    
    def __init__(self, target: str, verbose: bool = False):
        """
        Initialize scanner
        
        Args:
            target: Target IP or hostname
            verbose: Enable verbose output
        """
        self.target = target
        self.verbose = verbose
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.scan_results = {}
        self.start_time = None
        self.end_time = None
        
        # Resolve hostname to IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.target_ip = target
        
        # Common ports
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443
        ]
        
        # Service fingerprints
        self.service_signatures = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            8080: "http-proxy",
            8443: "https-alt",
        }
    
    def _log(self, message: str, level: str = "INFO"):
        """Log message with timestamp"""
        if self.verbose or level != "DEBUG":
            timestamp = datetime.now().strftime("%H:%M:%S")
            color = {
                "INFO": Colors.BLUE,
                "SUCCESS": Colors.GREEN,
                "WARNING": Colors.WARNING,
                "ERROR": Colors.FAIL,
                "DEBUG": Colors.CYAN
            }.get(level, "")
            
            print(f"{color}[{timestamp}] {message}{Colors.END}")
    
    # TCP CONNECT SCAN (-sT)
    
    def tcp_connect_scan(self, port: int, timeout: float = 1.0) -> str:
        """
        TCP Connect Scan (full 3-way handshake)
        Most reliable but more detectable
        
        Args:
            port: Port to scan
            timeout: Connection timeout
            
        Returns:
            "open", "closed", or "filtered"
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                return "open"
            else:
                return "closed"
                
        except socket.timeout:
            return "filtered"
        except socket.error:
            return "filtered"
    
    def scan_tcp_connect(self, ports: List[int], threads: int = 10):
        """
        Scan multiple ports using TCP Connect
        
        Args:
            ports: List of ports to scan
            threads: Number of concurrent threads
        """
        self._log(f"Starting TCP Connect Scan on {self.target_ip}", "INFO")
        self.start_time = time.time()
        
        results = {}
        lock = threading.Lock()
        
        def scan_port(port):
            status = self.tcp_connect_scan(port)
            with lock:
                results[port] = status
                if status == "open":
                    self.open_ports.append(port)
                    service = self.service_signatures.get(port, "unknown")
                    self._log(f"Port {port}/tcp open  {service}", "SUCCESS")
                elif self.verbose and status == "closed":
                    self._log(f"Port {port}/tcp closed", "DEBUG")
        
        # Thread pool
        threads_list = []
        for port in ports:
            # Đếm số thread đang chạy
            active_threads = 0
            for t in threads_list:
                if t.is_alive():
                    active_threads += 1
            
            # Nếu đã đủ số thread tối đa, chờ 1 chút
            while active_threads >= threads:
                time.sleep(0.01)
                # Đếm lại số thread đang chạy
                active_threads = 0
                for t in threads_list:
                    if t.is_alive():
                        active_threads += 1
            
            t = threading.Thread(target=scan_port, args=(port,))
            t.start()
            threads_list.append(t)
        
        # Wait for all threads
        for t in threads_list:
            t.join()
        
        self.end_time = time.time()
        self.scan_results['tcp_connect'] = results
    # TCP SYN SCAN (-sS) [Stealth Scan]

    def tcp_syn_scan(self, port: int, timeout: float = 2.0) -> str:
        """
        TCP SYN Scan (half-open scan)
        Stealthier than connect scan
        Requires root/admin privileges
        
        Args:
            port: Port to scan
            timeout: Response timeout
            
        Returns:
            "open", "closed", or "filtered"
        """
            # Create SYN packet
        src_port = random.randint(1024, 65535)
        ip_packet = IP(dst=self.target_ip)
        syn_packet = TCP(sport=src_port, dport=port, flags="S", seq=1000)
            
            # Send and receive
        response = sr1(ip_packet/syn_packet, timeout=timeout, verbose=0)
            
        if response is None:
            return "filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                rst_packet = TCP(sport=src_port, dport=port, flags="R", seq=response.ack)
                send(ip_packet/rst_packet, verbose=0)
                return "open"
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                return "closed"
            
        return "filtered"

    
    def scan_tcp_syn(self, ports: List[int]):
        """
        Scan multiple ports using TCP SYN
        
        Args:
            ports: List of ports to scan
        """
        
        self._log(f"Starting TCP SYN Scan on {self.target_ip}", "INFO")
        self._log("This scan requires root privileges", "WARNING")
        self.start_time = time.time()
        
        results = {}
        
        for port in ports:
            status = self.tcp_syn_scan(port)
            results[port] = status
            
            if status == "open":
                self.open_ports.append(port)
                service = self.service_signatures.get(port, "unknown")
                self._log(f"Port {port}/tcp open  {service}", "SUCCESS")
            elif self.verbose and status == "closed":
                self._log(f"Port {port}/tcp closed", "DEBUG")
        
        self.end_time = time.time()
        self.scan_results['tcp_syn'] = results
    
    # UDP SCAN (-sU)
    
    def udp_scan(self, port: int, timeout: float = 2.0) -> str:
        """
        UDP Scan
        Slower and less reliable than TCP
        
        Args:
            port: Port to scan
            timeout: Response timeout
            
        Returns:
            "open", "closed", or "filtered"
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target_ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return "open"
            except socket.timeout:
                # No response might mean open or filtered
                sock.close()
                return "open|filtered"
            except socket.error:
                sock.close()
                return "closed"
                
        except Exception as e:
            return "filtered"
    
    def scan_udp(self, ports: List[int]):
        """
        Scan multiple UDP ports
        
        Args:
            ports: List of ports to scan
        """
        self._log(f"Starting UDP Scan on {self.target_ip}", "INFO")
        self.start_time = time.time()
        
        results = {}
        
        for port in ports:
            status = self.udp_scan(port)
            results[port] = status
            
            if "open" in status:
                service = self.service_signatures.get(port, "unknown")
                self._log(f"Port {port}/udp {status}  {service}", "SUCCESS")
            elif self.verbose:
                self._log(f"Port {port}/udp {status}", "DEBUG")
        
        self.end_time = time.time()
        self.scan_results['udp'] = results
    
    # PING SWEEP (-sn)
    
    def ping_host(self, timeout: float = 1.0) -> bool:
        """
        Ping host to check if alive
        
        Args:
            timeout: Ping timeout
            
        Returns:
            True if host is up
        """
    
    def _ping_socket(self, timeout: float) -> bool:
        """Ping using socket (TCP connect to port 80)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, 80))
            sock.close()
            return result == 0
        except:
            return False
    
    def _ping_scapy(self, timeout: float) -> bool:
        """Ping using ICMP (requires scapy)"""
        try:
            response = sr1(IP(dst=self.target_ip)/ICMP(), timeout=timeout, verbose=0)
            return response is not None
        except:
            return False
    
    def ping_sweep(self, network: str):
        """
        Ping sweep a network range
        
        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
        """
        self._log(f"Starting Ping Sweep on {network}", "INFO")
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            alive_hosts = []
            
            for ip in net.hosts():
                ip_str = str(ip)
                self.target_ip = ip_str
                
                if self.ping_host(timeout=0.5):
                    alive_hosts.append(ip_str)
                    self._log(f"Host {ip_str} is up", "SUCCESS")
                elif self.verbose:
                    self._log(f"Host {ip_str} is down", "DEBUG")
            
            return alive_hosts
            
        except Exception as e:
            self._log(f"Error in ping sweep: {e}", "ERROR")
            return []
    
    # SERVICE DETECTION (-sV)
    
    def detect_service(self, port: int, timeout: float = 2.0) -> Dict:
        """
        Detect service running on port
        Sends probe and analyzes banner
        
        Args:
            port: Port to probe
            timeout: Connection timeout
            
        Returns:
            Dict with service info
        """
        service_info = {
            'port': port,
            'service': self.service_signatures.get(port, 'unknown'),
            'version': None,
            'banner': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target_ip, port))
            
            # Try to grab banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
                
                # Parse common banners
                if 'SSH' in banner:
                    service_info['service'] = 'ssh'
                    service_info['version'] = banner
                elif 'FTP' in banner:
                    service_info['service'] = 'ftp'
                    service_info['version'] = banner
                elif 'HTTP' in banner or 'Server:' in banner:
                    service_info['service'] = 'http'
                    service_info['version'] = banner
                    
            except:
                # Some services don't send banner
                pass
            
            sock.close()
            
        except Exception as e:
            pass
        
        return service_info
    
    def scan_with_service_detection(self, ports: List[int]):
        """
        Scan ports and detect services
        
        Args:
            ports: List of ports to scan
        """
        self._log(f"Starting Service Detection on {self.target_ip}", "INFO")
        
        # First scan for open ports
        self.scan_tcp_connect(ports, threads=20)
        
        # Then detect services on open ports
        if self.open_ports:
            self._log("Detecting services on open ports...", "INFO")
            
            services = {}
            for port in self.open_ports:
                service_info = self.detect_service(port)
                services[port] = service_info
                
                if service_info['version']:
                    self._log(f"Port {port}/tcp: {service_info['service']} - {service_info['version']}", "SUCCESS")
                else:
                    self._log(f"Port {port}/tcp: {service_info['service']}", "SUCCESS")
            
            self.scan_results['services'] = services
    
    # OS DETECTION (Basic Fingerprinting)
    
    def detect_os(self) -> str:
        """
        Basic OS detection using TCP/IP stack fingerprinting
        
        Returns:
            Detected OS or "Unknown"
        """  
        try:
            # Send SYN packet and analyze response
            response = sr1(IP(dst=self.target_ip)/TCP(dport=80, flags="S"),
                          timeout=2, verbose=0)
            
            if response is None:
                return "Unknown (no response)"
            
            # Analyze TTL and Window size
            ttl = response.ttl
            window = response.window
            
            # Common OS fingerprints (simplified)
            if ttl <= 64:
                if window > 5000:
                    return "Linux/Unix"
                else:
                    return "Linux/Unix (embedded)"
            elif ttl <= 128:
                if window > 8000:
                    return "Windows"
                else:
                    return "Windows (older)"
            elif ttl <= 255:
                return "Cisco/Network Device"
            
            return f"Unknown (TTL:{ttl}, Win:{window})"
            
        except Exception as e:
            return "Unknown (error)"
    
    # OUTPUT & REPORTING
    
    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*80)
        print(f"{Colors.BOLD}PyScanner Scan Report{Colors.END}")
        print("="*80)
        print(f"Target: {self.target} ({self.target_ip})")
        
        if self.start_time and self.end_time:
            duration = self.end_time - self.start_time
            print(f"Scan Duration: {duration:.2f} seconds")
        
        print(f"\n{Colors.GREEN}Open Ports: {len(self.open_ports)}{Colors.END}")
        if self.open_ports:
            for port in sorted(self.open_ports):
                service = self.service_signatures.get(port, "unknown")
                print(f"  {port}/tcp  {service}")
        
        if self.closed_ports and self.verbose:
            print(f"\n{Colors.WARNING}Closed Ports: {len(self.closed_ports)}{Colors.END}")
        
        if self.filtered_ports and self.verbose:
            print(f"\n{Colors.FAIL}Filtered Ports: {len(self.filtered_ports)}{Colors.END}")
        
        print("="*80)
    
    def export_json(self, filename: str = "scan_results.json"):
        """
        Export results to JSON
        
        Args:
            filename: Output filename
        """
        report = {
            'target': self.target,
            'target_ip': self.target_ip,
            'scan_time': datetime.now().isoformat(),
            'duration': self.end_time - self.start_time if self.end_time else 0,
            'open_ports': self.open_ports,
            'scan_results': self.scan_results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Results exported to {filename}")
    

# COMMAND LINE INTERFACE

def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse port specification
    
    Examples:
        "80" -> [80]
        "1-100" -> [1, 2, 3, ..., 100]
        "80,443,8080" -> [80, 443, 8080]
    """
    ports = []
    
    for part in port_spec.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return ports


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='PyScanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan common ports
  python3 pyscanner.py 192.168.1.1
  
  # Scan specific ports
  python3 pyscanner.py 192.168.1.1 -p 80,443,8080
  
  # Scan port range
  python3 pyscanner.py 192.168.1.1 -p 1-1000
  
  # TCP SYN scan (requires root)
  sudo python3 pyscanner.py 192.168.1.1 -sS
  
  # UDP scan
  python3 pyscanner.py 192.168.1.1 -sU -p 53,161,162
  
  # Service detection
  python3 pyscanner.py 192.168.1.1 -sV
  
  # Ping sweep
  python3 pyscanner.py 192.168.1.0/24 -sn
  
  # Export results
  python3 pyscanner.py 192.168.1.1 -oJ results.json
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='common',
                       help='Port specification (default: common ports)')
    parser.add_argument('-sT', action='store_true',
                       help='TCP Connect scan (default)')
    parser.add_argument('-sS', action='store_true',
                       help='TCP SYN scan (requires root)')
    parser.add_argument('-sU', action='store_true',
                       help='UDP scan')
    parser.add_argument('-sn', action='store_true',
                       help='Ping scan (no port scan)')
    parser.add_argument('-sV', action='store_true',
                       help='Service/version detection')
    parser.add_argument('-O', action='store_true',
                       help='OS detection')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-T', '--timing', type=int, choices=[0,1,2,3,4,5],
                       default=3, help='Timing template (0-5, default: 3)')
    parser.add_argument('-oJ', '--output-json', help='Output to JSON file')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = NetworkScanner(args.target, verbose=args.verbose)
    
    # Parse ports
    if args.ports == 'common':
        ports = scanner.common_ports
    elif args.ports == 'all':
        ports = list(range(1, 65536))
    else:
        ports = parse_port_range(args.ports)
    
    # Adjust timing
    thread_count = {
        0: 1,    # Paranoid
        1: 5,    # Sneaky
        2: 10,   # Polite
        3: 20,   # Normal
        4: 50,   # Aggressive
        5: 100   # Insane
    }.get(args.timing, 20)
    
    try:
        # Execute scan based on options
        if args.sn:
            # Ping scan only
            if '/' in args.target:
                scanner.ping_sweep(args.target)
            else:
                is_up = scanner.ping_host()
                if is_up:
                    print(f"{Colors.GREEN}Host {args.target} is up{Colors.END}")
                else:
                    print(f"{Colors.FAIL}Host {args.target} appears down{Colors.END}")
        
        elif args.sS:
            # TCP SYN scan
            scanner.scan_tcp_syn(ports)
            scanner.print_summary()
        
        elif args.sU:
            # UDP scan
            scanner.scan_udp(ports)
            scanner.print_summary()
        
        elif args.sV:
            # Service detection
            scanner.scan_with_service_detection(ports)
            scanner.print_summary()
        
        else:
            # Default: TCP Connect scan
            scanner.scan_tcp_connect(ports, threads=thread_count)
            scanner.print_summary()
        
        # OS detection
        if args.O and not args.sn:
            os_guess = scanner.detect_os()
            print(f"\n{Colors.CYAN}OS Detection: {os_guess}{Colors.END}")
        
        # Export to json
        if args.output_json:
            scanner.export_json(args.output_json)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
