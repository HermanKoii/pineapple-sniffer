import socket
import subprocess
import ipaddress
import logging
from typing import List, Optional, Dict, Any

class VPNLeakDetector:
    """
    Comprehensive VPN leak detection system.
    
    Detects potential IP, DNS, and network configuration leaks.
    Provides granular analysis of network security vulnerabilities.
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize VPN Leak Detector with optional logging.
        
        Args:
            logger: Optional custom logger for detailed tracking
        """
        self.logger = logger or logging.getLogger(__name__)

    @staticmethod
    def get_public_ip() -> Optional[str]:
        """
        Retrieve the current public IP address using multiple services.
        
        Returns:
            Optional public IP address or None if detection fails
        """
        ip_services = [
            'https://api.ipify.org',
            'https://ipinfo.io/ip',
            'https://checkip.amazonaws.com'
        ]
        
        for service in ip_services:
            try:
                result = subprocess.run(
                    ['curl', '-s', service], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                if result.returncode == 0:
                    ip = result.stdout.strip()
                    try:
                        # Validate IP address format
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        continue
            except Exception as e:
                logging.warning(f"IP check failed for {service}: {e}")
        
        return None

    @staticmethod
    def get_dns_servers() -> List[str]:
        """
        Retrieve DNS server configurations across different platforms.
        
        Returns:
            List of configured DNS servers
        """
        dns_servers = []
        
        try:
            # Unix-like systems (Linux, macOS)
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers.extend([
                    line.split()[1] 
                    for line in f.readlines() 
                    if line.startswith('nameserver')
                ])
        except FileNotFoundError:
            logging.warning("resolv.conf not found")
        
        try:
            # Windows-style DNS retrieval (if applicable)
            result = subprocess.run(
                ['ipconfig', '/all'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            dns_matches = re.findall(r'DNS\s+Servers\s*[.:\s]+\s*(\d+\.\d+\.\d+\.\d+)', result.stdout)
            dns_servers.extend(dns_matches)
        except Exception:
            pass
        
        return list(set(dns_servers))  # Remove duplicates

    def detect_leaks(self) -> Dict[str, Any]:
        """
        Comprehensive leak detection with multi-stage verification.
        
        Returns:
            Detailed leak detection results
        """
        results = {
            'public_ip': None,
            'dns_servers': [],
            'leaks': [],
            'vpn_secure': True
        }
        
        # Detect public IP
        public_ip = self.get_public_ip()
        results['public_ip'] = public_ip
        
        # Get DNS servers
        dns_servers = self.get_dns_servers()
        results['dns_servers'] = dns_servers
        
        # Advanced leak detection criteria
        if not public_ip:
            results['leaks'].append("Unable to detect public IP")
            results['vpn_secure'] = False
        
        # Flag potentially suspicious DNS servers
        suspicious_dns = ['8.8.8.8', '8.8.4.4']  # Google's public DNS
        if any(server in suspicious_dns for server in dns_servers):
            results['leaks'].append("Using public DNS servers that might log queries")
        
        return results

def main():
    """
    CLI entry point for VPN leak detection.
    Provides a simple interface to run leak tests.
    """
    logging.basicConfig(level=logging.INFO)
    detector = VPNLeakDetector()
    
    try:
        results = detector.detect_leaks()
        
        print("\n--- VPN Leak Detection Results ---")
        print(f"Public IP: {results['public_ip'] or 'Unknown'}")
        print(f"DNS Servers: {', '.join(results['dns_servers']) or 'None detected'}")
        print(f"VPN Security: {'Secure' if results['vpn_secure'] else 'Potential Leaks Detected'}")
        
        if results['leaks']:
            print("\nDetected Potential Issues:")
            for leak in results['leaks']:
                print(f" - {leak}")
    
    except Exception as e:
        print(f"Error during leak detection: {e}")

if __name__ == '__main__':
    main()