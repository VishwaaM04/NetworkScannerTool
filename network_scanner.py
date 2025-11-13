#!/usr/bin/env python3
"""
Network Scanner Tool
A command-line tool to scan open ports and detect active devices in a local network.
Integrates Nmap for advanced network scanning capabilities and Socket programming.
"""

import socket
import subprocess
import sys
import threading
import ipaddress
from datetime import datetime
from collections import defaultdict

class NetworkScanner:
    """Main Network Scanner Class"""
    
    def __init__(self):
        self.active_hosts = []
        self.open_ports = defaultdict(list)
        self.lock = threading.Lock()
        self.results = []
    
    def ping_host(self, host):
        """Ping a single host using ICMP"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(host)],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                with self.lock:
                    self.active_hosts.append(str(host))
                return True
        except (subprocess.TimeoutExpired, Exception):
            pass
        return False
    
    def scan_port(self, host, port):
        """Scan a single port on a host using socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((str(host), port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports[str(host)].append(port)
                return True
        except (socket.error, Exception):
            pass
        return False
    
    def scan_network_with_nmap(self, network, arguments="-sn"):
        """Scan network using Nmap"""
        try:
            cmd = ['nmap', arguments, str(network)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            return f"Nmap scan failed: {str(e)}"
    
    def scan_ports_threaded(self, host, ports, num_threads=20):
        """Scan multiple ports with threading"""
        threads = []
        for port in ports:
            if len(threads) >= num_threads:
                for thread in threads:
                    thread.join()
                threads = []
            
            thread = threading.Thread(target=self.scan_port, args=(host, port))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
    
    def scan_network_threaded(self, network, num_threads=50):
        """Scan network for active hosts with threading"""
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())
            threads = []
            
            for host in hosts:
                if len(threads) >= num_threads:
                    for thread in threads:
                        thread.join()
                    threads = []
                
                thread = threading.Thread(target=self.ping_host, args=(host,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            for thread in threads:
                thread.join()
        except Exception as e:
            print(f"Error scanning network: {str(e)}")
    
    def get_service_name(self, port):
        """Get service name for a port"""
        common_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT'
        }
        return common_services.get(port, 'Unknown')
    
    def generate_report(self):
        """Generate scan report"""
        report = f"\n{'='*60}\n"
        report += f"Network Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"{'='*60}\n\n"
        
        report += f"Active Hosts Found: {len(self.active_hosts)}\n"
        for host in sorted(self.active_hosts):
            report += f"  - {host}\n"
        
        if self.open_ports:
            report += f"\nOpen Ports by Host:\n"
            for host, ports in sorted(self.open_ports.items()):
                report += f"\n  {host}:\n"
                for port in sorted(ports):
                    service = self.get_service_name(port)
                    report += f"    Port {port:5d} - {service}\n"
        
        report += f"\n{'='*60}\n"
        return report

def main():
    """Main function"""
    print("\n" + "="*60)
    print("Network Scanner Tool v1.0")
    print("="*60)
    
    scanner = NetworkScanner()
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python3 network_scanner.py <network> [options]")
        print("\nExamples:")
        print("  python3 network_scanner.py 192.168.1.0/24")
        print("  python3 network_scanner.py 192.168.1.100 --ports 20-1000")
        print("  python3 network_scanner.py 192.168.1.0/24 --nmap")
        sys.exit(1)
    
    target = sys.argv[1]
    use_nmap = '--nmap' in sys.argv
    
    print(f"\nScanning target: {target}")
    
    if use_nmap:
        print("Using Nmap for scanning...")
        result = scanner.scan_network_with_nmap(target)
        print(result)
    else:
        print("Scanning active hosts...")
        scanner.scan_network_threaded(target)
        print(f"Found {len(scanner.active_hosts)} active host(s)")
        
        if '--ports' in sys.argv:
            port_range = sys.argv[sys.argv.index('--ports') + 1]
            try:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, end + 1))
                
                for host in scanner.active_hosts:
                    print(f"\nScanning ports on {host}...")
                    scanner.scan_ports_threaded(host, ports)
            except (ValueError, IndexError):
                print("Invalid port range format. Use: start-end")
    
    print(scanner.generate_report())

if __name__ == "__main__":
    main()
