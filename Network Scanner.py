#!/usr/bin/env python3
"""
NETWORK SCANNER - EDUCATIONAL TOOL
Author: Rohan Dharampal
Description: Scans local network for active devices
License: Educational Use Only
"""

import argparse
import socket
import sys
import os
from datetime import datetime
import json

# Optional imports
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class NetworkScanner:
    """Network scanner class by Rohan Dharampal."""
    
    def __init__(self):
        self.results = []
        self.start_time = None
        
    def display_banner(self):
        """Display program banner with author info."""
        print("═" * 60)
        print("           NETWORK SCANNER - EDUCATIONAL TOOL")
        print(" " * 20 + "by Rohan Dharampal")
        print("═" * 60)
        print("\n⚠️  IMPORTANT: FOR EDUCATIONAL PURPOSES ON OWNED NETWORKS ONLY")
        print("   Use only on networks you own or have explicit permission to scan.")
        print("   Author: Rohan Dharampal\n")
        
    def simple_ping_scan(self, target_ip, start=1, end=254, timeout=1):
        """Simple scanner using ICMP ping."""
        import subprocess
        import platform
        
        active_hosts = []
        
        print(f"[*] Scanning {target_ip}.{start}-{end} using ICMP ping...")
        
        for host in range(start, end + 1):
            ip = f"{target_ip}.{host}"
            
            # Platform-specific ping command
            if platform.system().lower() == "windows":
                command = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
            else:
                command = ["ping", "-c", "1", "-W", str(timeout), ip]
            
            # Run ping command
            try:
                with open(os.devnull, 'w') as devnull:
                    result = subprocess.run(command, stdout=devnull, stderr=devnull)
                
                if result.returncode == 0:
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except (socket.herror, socket.gaierror):
                        hostname = "N/A"
                    
                    # Try common ports to identify services
                    open_ports = self.check_common_ports(ip)
                    
                    active_hosts.append({
                        'ip': ip,
                        'hostname': hostname,
                        'open_ports': open_ports,
                        'status': 'Active'
                    })
                    
                    print(f"[+] {ip:15} | {hostname:25} | Ports: {', '.join(map(str, open_ports))}")
            except Exception as e:
                continue
        
        return active_hosts
    
    def check_common_ports(self, ip, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]):
        """Check common ports on a host."""
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
        
        return open_ports[:5]  # Return only first 5 open ports
    
    def scapy_arp_scan(self, network_range, timeout=2):
        """Advanced scanner using ARP requests (requires root)."""
        if not SCAPY_AVAILABLE:
            print("[-] Scapy not installed. Install with: pip install scapy")
            return []
        
        # Create ARP request
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        print(f"[*] Performing ARP scan on {network_range}...")
        
        try:
            answered, unanswered = srp(packet, timeout=timeout, verbose=0)
        except PermissionError:
            print("[-] Permission denied. ARP scan requires root/admin privileges.")
            print("[-] Try: sudo python scanner.py (Linux/macOS) or Run as Administrator (Windows)")
            return []
        
        devices = []
        for sent, received in answered:
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except (socket.herror, socket.gaierror):
                hostname = "Unknown"
            
            # Get MAC vendor (simplified)
            vendor = self.get_mac_vendor(received.hwsrc)
            
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': hostname,
                'vendor': vendor,
                'status': 'Active'
            })
            
            print(f"[+] {received.psrc:15} | {hostname:20} | {received.hwsrc} | {vendor}")
        
        return devices
    
    def get_mac_vendor(self, mac_address):
        """Simple MAC vendor lookup (first 3 bytes)."""
        # Simplified - in practice, use a proper OUI database
        oui = mac_address[:8].upper()
        common_vendors = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1A:11": "Google",
            "00:1D:0F": "Apple",
            "00:23:12": "Cisco",
            "00:26:BB": "Apple",
            "08:00:27": "VirtualBox",
            "A4:4C:C8": "Dell",
            "B8:27:EB": "Raspberry Pi",
            "C8:69:CD": "Apple",
            "DC:A6:32": "Raspberry Pi",
            "F0:9F:C2": "Ubiquiti"
        }
        return common_vendors.get(oui, "Unknown")
    
    def display_results(self, results):
        """Display scan results in a formatted table."""
        if not results:
            print("\n[-] No active devices found.")
            return
        
        print("\n" + "═" * 80)
        print(f"SCAN RESULTS - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("═" * 80)
        print(f"{'IP Address':<15} {'Hostname':<25} {'MAC Address':<20} {'Vendor':<20}")
        print("-" * 80)
        
        for device in results:
            ip = device.get('ip', 'N/A')
            hostname = device.get('hostname', 'N/A')[:24]
            mac = device.get('mac', 'N/A')
            vendor = device.get('vendor', 'N/A')[:19]
            print(f"{ip:<15} {hostname:<25} {mac:<20} {vendor:<20}")
        
        print("═" * 80)
        print(f"Total devices found: {len(results)}")
    
    def save_results(self, results, filename="scan_results.json"):
        """Save results to JSON file."""
        output = {
            "scan_info": {
                "author": "Rohan Dharampal",
                "timestamp": datetime.now().isoformat(),
                "purpose": "Educational network scanning",
                "disclaimer": "For use on owned networks only"
            },
            "devices": results,
            "summary": {
                "total_devices": len(results),
                "scan_duration": (datetime.now() - self.start_time).total_seconds()
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"[*] Results saved to {filename}")
    
    def run(self):
        """Main execution method."""
        self.start_time = datetime.now()
        
        # Display banner with author info
        self.display_banner()
        
        # Parse arguments
        parser = argparse.ArgumentParser(
            description='Network Scanner by Rohan Dharampal - Educational Tool',
            epilog='⚠️ Use only on networks you own or have permission to scan.'
        )
        parser.add_argument('--target', '-t', default='192.168.1',
                          help='Target network (e.g., 192.168.1)')
        parser.add_argument('--range', '-r', default='1-254',
                          help='Host range to scan (e.g., 1-100)')
        parser.add_argument('--method', '-m', choices=['ping', 'arp', 'both'],
                          default='ping', help='Scanning method')
        parser.add_argument('--output', '-o', default='scan_results.json',
                          help='Output file for results')
        parser.add_argument('--cidr', '-c', 
                          help='CIDR notation (e.g., 192.168.1.0/24)')
        
        args = parser.parse_args()
        
        # Parse range
        start, end = map(int, args.range.split('-'))
        
        # Execute scan based on method
        results = []
        
        if args.method in ['ping', 'both']:
            print(f"\n[*] Starting Ping Scan...")
            ping_results = self.simple_ping_scan(args.target, start, end)
            results.extend(ping_results)
        
        if args.method in ['arp', 'both'] and SCAPY_AVAILABLE:
            print(f"\n[*] Starting ARP Scan...")
            if args.cidr:
                network_range = args.cidr
            else:
                network_range = f"{args.target}.0/24"
            
            arp_results = self.scapy_arp_scan(network_range)
            # Merge results, avoiding duplicates
            for arp_dev in arp_results:
                if not any(dev['ip'] == arp_dev['ip'] for dev in results):
                    results.append(arp_dev)
        
        # Display results
        self.display_results(results)
        
        # Save results
        self.save_results(results, args.output)
        
        # Display summary
        duration = (datetime.now() - self.start_time).total_seconds()
        print(f"\n[*] Scan completed in {duration:.2f} seconds")
        print("\n" + "⚠️ " * 40)
        print("LEGAL DISCLAIMER: This tool is for educational purposes only.")
        print("Author: Rohan Dharampal")
        print("Use only on networks you own or have explicit permission to scan.")
        print("Unauthorized scanning may be illegal and unethical.")
        print("⚠️ " * 40)

def main():
    """Main entry point."""
    scanner = NetworkScanner()
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()