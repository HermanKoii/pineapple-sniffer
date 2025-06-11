#!/usr/bin/env python3
import pytest
import sys
import os

# Ensure the main script is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pineapple_detector import PineappleDetector

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
    Verify VPN security analysis method works correctly.
    """
    detector = PineappleDetector()
    
    test_cases = [
        {
            'vpn_type': 'PPTP VPN',
            'expected_warnings': ['Weak VPN Protocol']
        },
        {
            'vpn_type': 'WireGuard',
            'expected_warnings': []
        }
    ]
    
    for case in test_cases:
        vpn_result = {
            'active_vpn': True,
            'vpn_type': case['vpn_type'],
            'interface': 'test_interface',
            'server_ip': '192.168.1.1',
            'security_warnings': []
        }
        
        detector._analyze_vpn_security(vpn_result)
        
        # If there are expected warnings, check they are present
        if case['expected_warnings']:
            assert any(warning in w for w in vpn_result['security_warnings'] 
                       for warning in case['expected_warnings']), \
                f"Failed to detect warning for {case['vpn_type']}"
        else:
            assert not vpn_result['security_warnings'], \
                f"Unexpected warnings for {case['vpn_type']}"