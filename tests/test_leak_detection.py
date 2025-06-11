import pytest
from unittest.mock import patch
from src.vpn_security.leak_detection import VPNLeakDetector

class TestVPNLeakDetector:
    def test_get_public_ip_success(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = '8.8.8.8\n'
            
            ip = VPNLeakDetector.get_public_ip()
            assert ip == '8.8.8.8'

    def test_get_dns_servers_success(self):
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.readlines.return_value = [
                'nameserver 8.8.8.8\n',
                'nameserver 1.1.1.1\n'
            ]
            
            servers = VPNLeakDetector.get_dns_servers()
            assert len(servers) == 2
            assert '8.8.8.8' in servers
            assert '1.1.1.1' in servers

    def test_get_public_ip_failure(self):
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception('Network error')
            
            ip = VPNLeakDetector.get_public_ip()
            assert ip is None

    def test_detect_leaks(self):
        detector = VPNLeakDetector()
        
        with patch.object(detector, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(detector, 'get_dns_servers', return_value=['8.8.8.8']):
            
            results = detector.detect_leaks()
            assert 'public_ip' in results
            assert 'dns_servers' in results
            assert 'leak_detected' in results