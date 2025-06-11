import subprocess
import re
import sys
from typing import Dict, List, Optional

class VPNConfigDetector:
    """
    A class to detect and analyze VPN network configurations.
    
    This class provides methods to inspect network interfaces,
    routing tables, and detect active VPN connections.
    """
    
    @staticmethod
    def get_network_interfaces() -> Dict[str, str]:
        """
        Retrieve network interface details.
        
        Returns:
            Dict of network interface names and their IP addresses.
        """
        try:
            # Use platform-independent command for network interfaces
            result = subprocess.run(['ip', 'addr'], 
                                    capture_output=True, 
                                    text=True, 
                                    check=True)
            
            interfaces = {}
            lines = result.stdout.split('\n')
            for i in range(len(lines)):
                # Flexible regex for interface name and IP
                interface_match = re.search(r'^\d+:\s+(\w+):', lines[i])
                if interface_match:
                    interface = interface_match.group(1)
                    # Look ahead to next lines for IP address
                    for j in range(i+1, min(i+4, len(lines))):
                        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', lines[j])
                        if ip_match:
                            interfaces[interface] = ip_match.group(1)
                            break
            
            return interfaces
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"DEBUG: Error in get_network_interfaces: {e}", file=sys.stderr)
            # Fallback for systems without 'ip' command
            return {}
    
    @staticmethod
    def get_routing_table() -> List[Dict[str, str]]:
        """
        Retrieve the system routing table.
        
        Returns:
            List of routing table entries with details.
        """
        try:
            result = subprocess.run(['ip', 'route'], 
                                    capture_output=True, 
                                    text=True, 
                                    check=True)
            
            routes = []
            for line in result.stdout.split('\n'):
                route_parts = line.split()
                if len(route_parts) >= 5:
                    route_entry = {
                        'destination': route_parts[0],
                        'via': route_parts[2] if len(route_parts) > 2 else '',
                        'dev': route_parts[4] if len(route_parts) > 4 else ''
                    }
                    routes.append(route_entry)
            
            return routes
        except (subprocess.CalledProcessError, FileNotFoundError):
            return []
    
    @classmethod
    def detect_vpn_connection(cls) -> Optional[Dict[str, str]]:
        """
        Detect if a VPN connection is active.
        
        Returns:
            Dictionary with VPN connection details, or None if no VPN detected.
        """
        interfaces = cls.get_network_interfaces()
        routes = cls.get_routing_table()
        
        # Common VPN interface names and checks
        vpn_interface_keywords = ['tun', 'tap', 'ppp', 'wg', 'vpn']
        
        # Check for known VPN interfaces
        for interface, ip in interfaces.items():
            if any(keyword in interface.lower() for keyword in vpn_interface_keywords):
                return {
                    'interface': interface,
                    'ip_address': ip
                }
        
        # Check routing table for potential VPN routes
        for route in routes:
            if any(keyword in str(route).lower() for keyword in vpn_interface_keywords):
                return route
        
        return None