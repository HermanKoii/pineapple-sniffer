import pytest
import subprocess
from unittest.mock import patch
from src.vpn_detector import PineappleDetector

class TestPineappleDetector:
    @patch('subprocess.run')
    def test_detect_vpn_connection_with_vpn(self, mock_run):
        # Improved mock scenario with multiple interface details
        mock_run.return_value.stdout = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "2: tun0@NONE: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 100"
        )
        mock_run.return_value.returncode = 0
        
        result = PineappleDetector.detect_vpn_connection()
        assert result is not None
        assert result['interface'] == 'tun0@NONE'
        assert result['type'] == 'tun'
        assert result['state'] == 'UP'

    @patch('subprocess.run')
    def test_detect_vpn_connection_without_vpn(self, mock_run):
        # Mock scenario without VPN interfaces
        mock_run.return_value.stdout = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000"
        )
        mock_run.return_value.returncode = 0
        
        result = PineappleDetector.detect_vpn_connection()
        assert result is None

    def test_validate_vpn_security_with_connection(self):
        # Enhanced test for VPN security validation
        connection_info = {
            'interface': 'tun0', 
            'type': 'wireguard', 
            'state': 'UP'
        }
        recommendations = PineappleDetector.validate_vpn_security(connection_info)
        
        assert len(recommendations) > 0
        assert "Recommended VPN type: wireguard" in recommendations
        assert "Use strong encryption protocols (AES-256, ChaCha20)" in recommendations

    def test_validate_vpn_security_without_connection(self):
        recommendations = PineappleDetector.validate_vpn_security(None)
        
        assert recommendations == ["No VPN connection detected"]

    @patch('subprocess.run')
    def test_get_vpn_ip_success(self, mock_run):
        # Simulate successful IP retrieval with fallback services
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "8.8.8.8\n"
        
        ip = PineappleDetector.get_vpn_ip()
        assert ip == "8.8.8.8"

    @patch('subprocess.run')
    def test_get_vpn_ip_failure(self, mock_run):
        # Test multiple service failure scenarios
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, 'curl'),
            subprocess.CalledProcessError(1, 'curl'),
            subprocess.CalledProcessError(1, 'curl')
        ]
        
        ip = PineappleDetector.get_vpn_ip()
        assert ip is None