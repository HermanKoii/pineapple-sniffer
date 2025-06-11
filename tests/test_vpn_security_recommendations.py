import pytest
from src.vpn_security_recommendations import VPNSecurityRecommendationGenerator

def test_generate_recommendations_empty_config():
    """Test recommendation generation with empty configuration."""
    recommendations = VPNSecurityRecommendationGenerator.generate_recommendations({})
    assert isinstance(recommendations, list)
    assert len(recommendations) > 0

def test_weak_encryption_protocol():
    """Test recommendations for weak encryption protocols."""
    vpn_config = {
        'encryption_protocol': 'pptp'
    }
    recommendations = VPNSecurityRecommendationGenerator.generate_recommendations(vpn_config)
    assert any('Upgrade from PPTP' in rec for rec in recommendations)

def test_missing_dns_leak_protection():
    """Test recommendations for missing DNS leak protection."""
    vpn_config = {
        'dns_leak_protection': False
    }
    recommendations = VPNSecurityRecommendationGenerator.generate_recommendations(vpn_config)
    assert any('Enable DNS leak protection' in rec for rec in recommendations)

def test_missing_kill_switch():
    """Test recommendations for missing kill switch."""
    vpn_config = {
        'kill_switch': False
    }
    recommendations = VPNSecurityRecommendationGenerator.generate_recommendations(vpn_config)
    assert any('Enable VPN kill switch' in rec for rec in recommendations)

def test_weak_authentication():
    """Test recommendations for weak authentication methods."""
    vpn_config = {
        'authentication_method': 'psk',
        'two_factor_auth': False
    }
    recommendations = VPNSecurityRecommendationGenerator.generate_recommendations(vpn_config)
    assert any('Use strong, certificate-based authentication' in rec for rec in recommendations)
    assert any('Enable two-factor authentication' in rec for rec in recommendations)

def test_recommendations_with_good_config():
    """Test recommendations with a well-configured VPN."""
    vpn_config = {
        'encryption_protocol': 'wireguard',
        'authentication_method': 'certificate',
        'dns_leak_protection': True,
        'kill_switch': True,
        'two_factor_auth': True
    }
    recommendations = VPNSecurityRecommendationGenerator.generate_recommendations(vpn_config)
    assert len(recommendations) == 0  # No recommendations for a good config