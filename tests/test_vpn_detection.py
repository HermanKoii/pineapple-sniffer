#!/usr/bin/env python3
import pytest
import sys
import os
from unittest.mock import patch  # Use unittest.mock instead of pytest.mock

# Ensure the main script is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pineapple_detector import PineappleDetector
from src.vpn_security.network_config import VPNConfigDetector

def test_vpn_configuration_detection_method_exists():
    """
    Verify that the detect_vpn_configuration method exists.
    """
    detector = PineappleDetector()
    assert hasattr(detector, 'detect_vpn_configuration'), "VPN configuration detection method is missing"

def test_vpn_configuration_detection_return_type():
    """
    Verify the return type of the VPN configuration detection method.
    """
    detector = PineappleDetector()
    result = detector.detect_vpn_configuration()
    
    # Check return type is dict
    assert isinstance(result, dict), "VPN detection must return a dictionary"
    
    # Check required keys
    required_keys = [
        'active_vpn', 
        'vpn_type', 
        'interface', 
        'server_ip', 
        'security_warnings'
    ]
    
    for key in required_keys:
        assert key in result, f"Missing required key: {key}"

def test_vpn_detection_handles_non_vpn_scenario():
    """
    Verify VPN detection works correctly when no VPN is active.
    """
    detector = PineappleDetector()
    result = detector.detect_vpn_configuration()
    
    # Expected behavior when no VPN is active
    assert 'active_vpn' in result
    assert result['active_vpn'] in [True, False], "active_vpn must be a boolean"

def test_vpn_type_extraction():
    """
    Test VPN type extraction logic.
    """
    detector = PineappleDetector()
    
    test_cases = [
        ('pptp connection details', 'Point-to-Point Tunneling Protocol'),
        ('wireguard interface', 'WireGuard'),
        ('ipsec tunnel', 'IPSec VPN'),
        ('random text', 'Unknown VPN Protocol')
    ]
    
    for input_text, expected_type in test_cases:
        result = detector._extract_vpn_type(input_text)
        assert result == expected_type, f"Failed to extract VPN type from '{input_text}'"

def test_vpn_security_analysis():
    """
    Verify VPN security analysis uses network config validation.
    """
    # Mock VPN connection detection
    with patch.object(VPNConfigDetector, 'detect_vpn_connection', 
                      return_value={'interface': 'pptp0', 'ip_address': '10.0.0.1'}):
        # Mock VPN security validation
        with patch.object(VPNConfigDetector, 'validate_vpn_security', 
                          return_value=['Weak VPN protocol detected']):
            
            detector = PineappleDetector()
            vpn_result = detector.detect_vpn_configuration()
            
            # Verify security warnings are captured
            assert 'security_warnings' in vpn_result
            assert len(vpn_result['security_warnings']) > 0

def test_vpn_detection_integration():
    """
    Integration test to verify complete VPN detection workflow.
    """
    detector = PineappleDetector()
    
    # Simulate different network scenarios
    test_scenarios = [
        {'interfaces': {'tun0': '10.8.0.1'}, 'expected_active': True},
        {'interfaces': {'eth0': '192.168.1.100'}, 'expected_active': False}
    ]
    
    for scenario in test_scenarios:
        with patch.object(VPNConfigDetector, 'get_network_interfaces', 
                          return_value=scenario['interfaces']):
            vpn_result = detector.detect_vpn_configuration()
            
            assert vpn_result['active_vpn'] == scenario['expected_active'], \
                f"Failed to detect VPN status for {scenario['interfaces']}"