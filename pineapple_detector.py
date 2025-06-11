#!/usr/bin/env python3
"""
WiFi Pineapple & Network Security Detector
==========================================

A comprehensive security test for detecting WiFi Pineapple attacks, 
man-in-the-middle attacks, and system vulnerabilities.

...previous docstring remains the same...
"""

# Existing imports remain the same...
import platform
import re

class PineappleDetector:
    # Existing methods remain the same...

    def detect_vpn_configuration(self) -> Dict:
        """
        Detect and analyze VPN configuration on the system.
        
        Returns:
            Dict containing VPN configuration details:
            - active_vpn: boolean indicating if VPN is active
            - vpn_type: type of VPN detected (if any)
            - interface: VPN network interface
            - server_ip: VPN server IP address
            - security_warnings: list of potential security issues
        """
        self.log("Detecting VPN configuration...")
        
        vpn_result = {
            'active_vpn': False,
            'vpn_type': None,
            'interface': None,
            'server_ip': None,
            'security_warnings': []
        }
        
        # Platform-specific VPN detection
        os_name = platform.system().lower()
        
        try:
            if os_name == 'darwin':  # macOS
                result = self.run_command(['scutil', '--nc', 'list'])
                if result.get('success', False):
                    vpn_connections = result.get('stdout', '').split('\n')
                    for conn in vpn_connections:
                        if 'Connected' in conn:
                            vpn_result['active_vpn'] = True
                            vpn_result['vpn_type'] = self._extract_vpn_type(conn)
            
            elif os_name == 'linux':
                # Check network interfaces for typical VPN interfaces
                result = self.run_command(['ip', 'addr'])
                if result.get('success', False):
                    interfaces = result.get('stdout', '').split('\n')
                    vpn_interfaces = [
                        'tun', 'tap', 'ppp', 'wireguard', 'ipsec', 
                        'openvpn', 'l2tp', 'pptp'
                    ]
                    
                    for interface in interfaces:
                        if any(vpn_type in interface.lower() for vpn_type in vpn_interfaces):
                            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', interface)
                            if match:
                                vpn_result['active_vpn'] = True
                                vpn_result['interface'] = interface.split(':')[0].strip()
                                vpn_result['server_ip'] = match.group(1)
                                vpn_result['vpn_type'] = self._extract_vpn_type(interface)
            
            # Analyze VPN security
            if vpn_result['active_vpn']:
                self._analyze_vpn_security(vpn_result)
                
                # Log VPN detection result
                self.log(f"VPN detected: {vpn_result['vpn_type']} via {vpn_result['interface']}", 
                         "PASS" if not vpn_result['security_warnings'] else "WARN")
            else:
                self.log("No active VPN detected", "PASS")
        
        except Exception as e:
            self.log(f"Error detecting VPN configuration: {str(e)}", "ERROR")
        
        return vpn_result
    
    def _extract_vpn_type(self, connection_info: str) -> str:
        """
        Determine VPN protocol type from connection information.
        
        Args:
            connection_info (str): Network connection details
        
        Returns:
            str: Detected VPN type or 'Unknown'
        """
        vpn_types = {
            'pptp': 'Point-to-Point Tunneling Protocol',
            'l2tp': 'Layer 2 Tunneling Protocol',
            'ipsec': 'IPSec VPN',
            'wireguard': 'WireGuard',
            'openvpn': 'OpenVPN',
            'cisco': 'Cisco AnyConnect',
            'tap': 'TAP Adapter',
            'tun': 'TUN Adapter'
        }
        
        for key, name in vpn_types.items():
            if key in connection_info.lower():
                return name
        
        return 'Unknown VPN Protocol'
    
    def _analyze_vpn_security(self, vpn_result: Dict) -> None:
        """
        Analyze VPN security and populate potential security warnings.
        
        Args:
            vpn_result (Dict): VPN configuration details
        """
        warnings = []
        
        # Check for weak VPN protocols
        weak_protocols = ['pptp', 'l2tp']
        if any(proto in vpn_result['vpn_type'].lower() for proto in weak_protocols):
            warnings.append(f"Weak VPN Protocol: {vpn_result['vpn_type']} may have security vulnerabilities")
        
        # Additional security checks can be added here
        vpn_result['security_warnings'] = warnings

# Existing main() and other functions remain the same...