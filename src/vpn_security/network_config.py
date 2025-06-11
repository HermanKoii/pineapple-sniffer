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
            
            # Very explicit regex for parsing network interfaces
            pattern = re.compile(
                r'^\\d+:\\s*(\\w+):.+\\n'  # Interface name
                r'(?:.*?\\n)*?'            # Optional intermediate lines
                r'\\s*inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+).*?(?:global|dynamic)\\s+(\\w+).*$',  # IP address with interface
                re.MULTILINE | re.DOTALL
            )
            
            interfaces = {}
            # Directly extract using findall for maximum flexibility
            matches = pattern.findall(result.stdout)
            for match in matches:
                interface_name = match[2]
                ip_address = match[1]
                interfaces[interface_name] = ip_address
            
            return interfaces
        
        except (subprocess.CalledProcessError, FileNotFoundError, AttributeError) as e:
            print(f"Error detecting network interfaces: {e}", file=sys.stderr)
            print(f"Raw output: {result.stdout if 'result' in locals() else 'No output'}", file=sys.stderr)
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
        
        # Common VPN interface names and checks
        vpn_interface_keywords = ['tun', 'tap', 'ppp', 'wg', 'vpn']
        
        # Check for known VPN interfaces
        for interface, ip in interfaces.items():
            if any(keyword in interface.lower() for keyword in vpn_interface_keywords):
                return {
                    'interface': interface,
                    'ip_address': ip
                }
        
        return None

    @staticmethod
    def validate_vpn_security(vpn_connection: Optional[Dict[str, str]]) -> List[str]:
        """
        Perform security validation for VPN connection.
        
        Args:
            vpn_connection (Optional[Dict[str, str]]): VPN connection details
        
        Returns:
            List of security warnings
        """
        if not vpn_connection:
            return []
        
        warnings = []
        
        # Check for weak protocols or potential vulnerabilities
        weak_protocols = ['pptp', 'l2tp']
        if any(proto in str(vpn_connection).lower() for proto in weak_protocols):
            warnings.append(f"Weak VPN protocol detected: {vpn_connection.get('interface', 'Unknown')}")
        
        return warnings