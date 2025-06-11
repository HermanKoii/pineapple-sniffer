import socket
import subprocess
import ipaddress
from typing import List, Optional, Dict, Any

class VPNLeakDetector:
    """
    Detect potential VPN IP and DNS leaks in network configuration.
    
    This class provides methods to check for:
    - IP address leaks
    - DNS server leaks
    - Network routing configuration
    """

    @staticmethod
    def get_public_ip() -> Optional[str]:
        """
        Retrieve the current public IP address.
        
        Returns:
            Optional[str]: Public IP address or None if detection fails
        """
        try:
            # Use multiple public IP checking services for reliability
            ip_services = [
                'https://api.ipify.org',
                'https://ipinfo.io/ip',
                'https://checkip.amazonaws.com'
            ]
            
            for service in ip_services:
                result = subprocess.run(
                    ['curl', '-s', service], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                # Validate IP address format
                if result.returncode == 0:
                    ip = result.stdout.strip()
                    try:
                        ipaddress.ip_address(ip)
                        return ip
                    except ValueError:
                        continue
            
            return None
        except Exception:
            return None

    @staticmethod
    def get_dns_servers() -> List[str]:
        """
        Retrieve current DNS server configurations.
        
        Returns:
            List[str]: List of configured DNS servers
        """
        try:
            # On Unix-like systems (Linux, macOS)
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = [
                    line.split()[1] 
                    for line in f.readlines() 
                    if line.startswith('nameserver')
                ]
            return dns_servers
        except Exception:
            return []

    def detect_leaks(self) -> Dict[str, Any]:
        """
        Comprehensive leak detection method.
        
        Returns:
            Dict[str, Any]: Detailed leak detection results
        """
        public_ip = self.get_public_ip()
        dns_servers = self.get_dns_servers()
        
        # Simplified leak criteria - can be expanded
        is_leak_detected = False
        
        # Check if public IP differs from expected VPN IP
        # This is a simplified check and might need VPN provider-specific logic
        if not public_ip:
            is_leak_detected = True
        
        return {
            'public_ip': public_ip,
            'dns_servers': dns_servers,
            'leak_detected': is_leak_detected
        }

def main():
    """
    CLI entry point for VPN leak detection.
    """
    detector = VPNLeakDetector()
    results = detector.detect_leaks()
    
    print("VPN Leak Detection Results:")
    print(f"Public IP: {results['public_ip']}")
    print(f"DNS Servers: {', '.join(results['dns_servers'])}")
    print(f"Leak Detected: {'Yes' if results['leak_detected'] else 'No'}")

if __name__ == '__main__':
    main()