import pytest
import logging
from unittest.mock import patch, MagicMock
from src.vpn_security.leak_detection import VPNLeakDetector

class TestVPNLeakDetector:
    def setup_method(self):
        # Create a mock logger to prevent actual logging during tests
        self.mock_logger = MagicMock(spec=logging.Logger)
        self.detector = VPNLeakDetector(logger=self.mock_logger)

    def test_get_public_ip_success(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = '8.8.8.8\n'
            
            ip = VPNLeakDetector.get_public_ip()
            assert ip == '8.8.8.8'

    def test_get_public_ip_failure(self):
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception('Network error')
            
            ip = VPNLeakDetector.get_public_ip()
            assert ip is None

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

    def test_detect_leaks_full_scenario(self):
        # Create a detector with mocked methods
        detector = VPNLeakDetector()
        
        with patch.object(detector, 'get_public_ip', return_value='1.2.3.4'), \
             patch.object(detector, 'get_dns_servers', return_value=['8.8.8.8', '1.1.1.1']):
            
            results = detector.detect_leaks()
            
            assert results['public_ip'] == '1.2.3.4'
            assert len(results['dns_servers']) == 2
            assert 'Using public DNS servers that might log queries' in results['leaks']
            
            # IMPORTANT: Update this assertion to match the implementation
            # The test should verify the vpn_secure state based on the implementation logic
            assert results['vpn_secure'] is False

    def test_detect_leaks_ip_detection_failure(self):
        # Simulate a scenario where IP detection fails
        detector = VPNLeakDetector()
        
        with patch.object(detector, 'get_public_ip', return_value=None), \
             patch.object(detector, 'get_dns_servers', return_value=[]):
            
            results = detector.detect_leaks()
            
            assert results['public_ip'] is None
            assert results['dns_servers'] == []
            assert 'Unable to detect public IP' in results['leaks']
            assert results['vpn_secure'] is False