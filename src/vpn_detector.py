import subprocess
import re
from typing import Dict, Optional, List, Union

class PineappleDetector:
    """
    A class for detecting and validating VPN connection parameters.
    
    This class provides methods to check VPN connection security and extract
    relevant network configuration details.
    """

    @staticmethod
    def detect_vpn_connection() -> Optional[Dict[str, str]]:
        """
        Detect active VPN connection and extract its parameters.
        
        Returns:
            Optional dictionary with VPN connection details or None if no VPN is detected.
        
        Raises:
            Exception: If there's an error during VPN detection.
        """
        try:
            # Use a more robust method to detect VPN interfaces
            result = subprocess.run(
                ['ip', 'addr'], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            # Expanded list of VPN interface types
            vpn_interfaces = [
                'tun', 'tap', 'ppp', 'wg', 'wireguard', 'openvpn', 'ipsec', 
                'nordvpn', 'protonvpn', 'surfshark'
            ]
            
            for line in result.stdout.splitlines():
                for interface in vpn_interfaces:
                    # More precise regex to capture interface name
                    interface_match = re.search(r'\d+:\s*({}[\w@]*):'.format(interface), line)
                    state_match = re.search(r'state\s+(\w+)', line)
                    
                    if interface_match:
                        return {
                            'interface': interface_match.group(1),
                            'type': interface,
                            'state': state_match.group(1) if state_match else 'UNKNOWN'
                        }
            
            return None
        
        except subprocess.CalledProcessError as e:
            print(f"Error detecting VPN: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error in VPN detection: {e}")
            return None

    @staticmethod
    def validate_vpn_security(connection_info: Optional[Dict[str, str]]) -> List[str]:
        """
        Validate the security of a VPN connection.
        
        Args:
            connection_info: Dictionary containing VPN connection details.
        
        Returns:
            List of security recommendations or warnings.
        """
        if not connection_info:
            return ["No VPN connection detected"]
        
        recommendations = []
        
        # Enhanced security checks
        if connection_info.get('state', '').lower() != 'up':
            recommendations.append("VPN interface is not in an active state")
        
        # Type-specific recommendations
        vpn_type = connection_info.get('type', '').lower()
        if vpn_type in ['wireguard', 'nordvpn', 'protonvpn']:
            recommendations.append(f"Recommended VPN type: {vpn_type}")
        
        # General security recommendations
        recommendations.extend([
            "Use strong encryption protocols (AES-256, ChaCha20)",
            "Verify VPN provider's no-log policy",
            "Enable kill switch feature",
            "Use multi-hop/double VPN when possible"
        ])
        
        return recommendations

    @staticmethod
    def get_vpn_ip() -> Optional[str]:
        """
        Retrieve the current VPN IP address.
        
        Returns:
            VPN IP address or None if not found.
        """
        try:
            # Multiple fallback IP checking services
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
                    timeout=5,
                    check=True
                )
                
                # Basic IP validation
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            
            return None
        except subprocess.CalledProcessError:
            return None
        except Exception:
            return None