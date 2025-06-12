import subprocess
import pytest
from unittest.mock import patch
from src.vpn_security.network_config import VPNConfigDetector

class TestVPNConfigDetector:
    def test_get_network_interfaces(self):
        # Mock subprocess to return predefined output
        mock_output = """
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
        inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic eth0
           valid_lft 86313sec preferred_lft 86313sec
    3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
        link/none 
        inet 10.8.0.1/24 brd 10.8.0.255 scope global tun0
           valid_lft forever preferred_lft forever
    """
    
        with patch('subprocess.run') as mock_run:
            # Create a MagicMock object with a stdout attribute
            mock_run.return_value.stdout = mock_output
            mock_run.return_value.check = True
    
            interfaces = VPNConfigDetector.get_network_interfaces()
    
            # Look for 'tun0' interface case-insensitively
            tun_interface = [iface for iface in interfaces.keys() if iface.lower() == 'tun0']
            assert len(tun_interface) > 0, f"No tun0 interface found in {interfaces}"
            assert interfaces[tun_interface[0]] == '10.8.0.1'
    
    def test_get_routing_table(self):
        # Mock routing table output
        mock_output = """
default via 192.168.1.1 dev eth0 proto dhcp metric 100 
10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.1 
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100 
"""
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = mock_output
            mock_run.return_value.check = True
            
            routes = VPNConfigDetector.get_routing_table()
            
            assert any('tun0' in str(route) for route in routes)
    
    def test_detect_vpn_connection(self):
        # Scenario with VPN connection
        with patch.object(VPNConfigDetector, 'get_network_interfaces', 
                          return_value={'tun0': '10.8.0.1'}):
            with patch.object(VPNConfigDetector, 'get_routing_table', 
                              return_value=[{'dev': 'tun0'}]):
                
                vpn_connection = VPNConfigDetector.detect_vpn_connection()
                
                assert vpn_connection is not None
                assert vpn_connection['interface'] == 'tun0'
                assert vpn_connection['ip_address'] == '10.8.0.1'
    
    def test_no_vpn_connection(self):
        # Scenario without VPN connection
        with patch.object(VPNConfigDetector, 'get_network_interfaces', 
                          return_value={'eth0': '192.168.1.100'}):
            with patch.object(VPNConfigDetector, 'get_routing_table', 
                              return_value=[{'dev': 'eth0'}]):
                
                vpn_connection = VPNConfigDetector.detect_vpn_connection()
                
                assert vpn_connection is None
    
    def test_vpn_connection_error_handling(self):
        # Test error handling when subprocess fails
        with patch('subprocess.run', side_effect=subprocess.CalledProcessError(1, 'cmd')):
            interfaces = VPNConfigDetector.get_network_interfaces()
            routes = VPNConfigDetector.get_routing_table()
            
            assert interfaces == {}
            assert routes == []