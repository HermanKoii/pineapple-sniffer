#!/usr/bin/env python3
"""
WiFi Pineapple & Network Security Detector
==========================================

A comprehensive security test for detecting WiFi Pineapple attacks, 
man-in-the-middle attacks, and system vulnerabilities.

Existing docstring remains the same...
"""

# Existing imports
import subprocess
import json
import datetime
import sys
import os
import argparse
import platform
import re
from typing import Dict, List, Optional, Tuple

from src.vpn_security.network_config import VPNConfigDetector

class PineappleDetector:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.test_domains = [
            'google.com',
            'github.com', 
            'apple.com',
            'cloudflare.com',
            'microsoft.com'
        ]
        self.dns_servers = {
            'google': '8.8.8.8',
            'cloudflare': '1.1.1.1',
            'current': None
        }
        self.results = {}
        self.threats_detected = []
        self.warnings = []
        
    def log(self, message, level="INFO"):
        """Log messages with timestamp."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        if level == "PASS":
            print(f"[{timestamp}] \u2705 {message}")
        elif level == "FAIL":
            print(f"[{timestamp}] \u274c {message}")
            self.threats_detected.append(message)
        elif level == "WARN":
            print(f"[{timestamp}] \u26a0\ufe0f  {message}")
            self.warnings.append(message)
        elif self.verbose or level == "ERROR":
            print(f"[{timestamp}] {level}: {message}")

    def detect_vpn_configuration(self) -> Dict:
        """
        Detect and analyze VPN configuration on the system.
        
        Returns:
            Dict containing VPN configuration details
        """
        self.log("Detecting VPN configuration...")
        
        # Use VPNConfigDetector from network_config
        vpn_connection = VPNConfigDetector.detect_vpn_connection()
        
        # Default VPN result
        vpn_result = {
            'active_vpn': False,
            'vpn_type': 'Unknown VPN Protocol',
            'interface': '',
            'server_ip': '',
            'security_warnings': []
        }
        
        if vpn_connection:
            vpn_result['active_vpn'] = True
            vpn_result['interface'] = vpn_connection.get('interface', '')
            vpn_result['server_ip'] = vpn_connection.get('ip_address', '')
            
            # Extract VPN type
            vpn_result['vpn_type'] = self._extract_vpn_type(vpn_result['interface'])
            
            # Validate VPN security
            vpn_result['security_warnings'] = VPNConfigDetector.validate_vpn_security(vpn_connection)
        
        return vpn_result
    
    def _extract_vpn_type(self, connection_info: str) -> str:
        """
        Determine VPN protocol type from connection information.
        
        Args:
            connection_info (str): Network connection details
        
        Returns:
            str: Detected VPN type or 'Unknown VPN Protocol'
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

# The rest of the original implementation remains the same
# ...