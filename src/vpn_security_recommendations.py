from typing import Dict, List, Optional, Any
import logging

class VPNSecurityRecommendationGenerator:
    """
    A class to generate actionable security recommendations for VPN configurations.
    
    This class analyzes VPN configuration parameters and provides 
    tailored security recommendations based on detected settings.
    """
    
    @staticmethod
    def generate_recommendations(vpn_config: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on VPN configuration.
        
        Args:
            vpn_config (Dict[str, Any]): A dictionary containing VPN configuration details.
        
        Returns:
            List[str]: A list of security recommendations.
        """
        # Validate input and provide default recommendations for empty config
        if not vpn_config or not isinstance(vpn_config, dict):
            logging.warning("Generating default recommendations for minimal VPN configuration")
            return [
                "Use strong, modern VPN protocols like OpenVPN, WireGuard, or IKEv2",
                "Enable certificate-based authentication",
                "Implement two-factor authentication",
                "Enable DNS leak protection",
                "Set up a VPN kill switch"
            ]
        
        recommendations = []
        
        # Check encryption protocol
        recommendations.extend(
            VPNSecurityRecommendationGenerator._check_encryption_protocol(vpn_config)
        )
        
        # Check authentication method
        recommendations.extend(
            VPNSecurityRecommendationGenerator._check_authentication(vpn_config)
        )
        
        # Check DNS leak protection
        recommendations.extend(
            VPNSecurityRecommendationGenerator._check_dns_leak_protection(vpn_config)
        )
        
        # Check kill switch
        recommendations.extend(
            VPNSecurityRecommendationGenerator._check_kill_switch(vpn_config)
        )
        
        return recommendations
    
    @staticmethod
    def _check_encryption_protocol(vpn_config: Dict[str, Any]) -> List[str]:
        """
        Check and recommend improvements for encryption protocols.
        
        Args:
            vpn_config (Dict[str, Any]): VPN configuration details.
        
        Returns:
            List[str]: Encryption-related recommendations.
        """
        recommendations = []
        encryption_protocol = vpn_config.get('encryption_protocol', '').lower()
        
        # Weak encryption protocols
        weak_protocols = ['pptp', 'l2tp']
        if encryption_protocol in weak_protocols:
            recommendations.append(
                f"Upgrade from {encryption_protocol.upper()} to a more secure protocol like OpenVPN or WireGuard"
            )
        
        # Recommended minimum encryption strength
        if encryption_protocol not in ['openvpn', 'wireguard', 'ikev2']:
            recommendations.append(
                "Consider using strong, modern VPN protocols like OpenVPN, WireGuard, or IKEv2"
            )
        
        return recommendations
    
    @staticmethod
    def _check_authentication(vpn_config: Dict[str, Any]) -> List[str]:
        """
        Check and recommend improvements for authentication methods.
        
        Args:
            vpn_config (Dict[str, Any]): VPN configuration details.
        
        Returns:
            List[str]: Authentication-related recommendations.
        """
        recommendations = []
        auth_method = vpn_config.get('authentication_method', '').lower()
        
        # Weak authentication methods
        if auth_method in ['none', 'psk', 'weak']:
            recommendations.append(
                "Use strong, certificate-based authentication instead of pre-shared keys or weak methods"
            )
        
        # Two-factor authentication
        if not vpn_config.get('two_factor_auth', False):
            recommendations.append(
                "Enable two-factor authentication for enhanced account security"
            )
        
        return recommendations
    
    @staticmethod
    def _check_dns_leak_protection(vpn_config: Dict[str, Any]) -> List[str]:
        """
        Check DNS leak protection configuration.
        
        Args:
            vpn_config (Dict[str, Any]): VPN configuration details.
        
        Returns:
            List[str]: DNS leak protection recommendations.
        """
        recommendations = []
        
        # Check if DNS leak protection is enabled
        if not vpn_config.get('dns_leak_protection', False):
            recommendations.append(
                "Enable DNS leak protection to prevent DNS requests from bypassing the VPN tunnel"
            )
        
        return recommendations
    
    @staticmethod
    def _check_kill_switch(vpn_config: Dict[str, Any]) -> List[str]:
        """
        Check VPN kill switch configuration.
        
        Args:
            vpn_config (Dict[str, Any]): VPN configuration details.
        
        Returns:
            List[str]: Kill switch recommendations.
        """
        recommendations = []
        
        # Check if kill switch is enabled
        if not vpn_config.get('kill_switch', False):
            recommendations.append(
                "Enable VPN kill switch to prevent network traffic when VPN connection drops"
            )
        
        return recommendations