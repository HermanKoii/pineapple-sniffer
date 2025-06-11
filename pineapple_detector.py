#!/usr/bin/env python3
"""
WiFi Pineapple & Network Security Detector
==========================================

A comprehensive security test for detecting WiFi Pineapple attacks, 
man-in-the-middle attacks, and system vulnerabilities.

Usage: python3 pineapple_detector.py [--quick] [--verbose] [--check-vpn] [--vpn-type TYPE]

Extended with VPN configuration checks to detect potential security risks.
"""

# (Existing imports remain the same)
import re

class PineappleDetector:
    # (Existing methods remain the same)

    def test_vpn_configuration(self, vpn_type=None) -> bool:
        """
        Perform VPN configuration security checks.
        
        Args:
            vpn_type (str, optional): Specific VPN type to check. 
                                      Supports 'openvpn', 'wireguard', 'ipsec'.
        
        Returns:
            bool: True if VPN configuration appears secure, False otherwise.
        """
        self.log("Checking VPN configuration security...")
        
        # Detect active VPN interfaces
        interfaces_cmd = ['ifconfig']
        interfaces_result = self.run_command(interfaces_cmd)
        
        vpn_interfaces = []
        if interfaces_result.get('success', False):
            # Look for common VPN interface patterns
            vpn_patterns = ['tun', 'tap', 'ppp', 'utun', 'ipsec']
            for pattern in vpn_patterns:
                found_interfaces = [
                    line.split(':')[0] 
                    for line in interfaces_result.get('stdout', '').split('\n') 
                    if pattern in line.lower()
                ]
                vpn_interfaces.extend(found_interfaces)
        
        if not vpn_interfaces:
            self.log("No VPN interfaces detected", "WARN")
            return True  # Not a failure, just no VPN detected
        
        self.log(f"Detected VPN interfaces: {vpn_interfaces}")
        
        # Perform type-specific checks if vpn_type is specified
        if vpn_type:
            config_check_method = getattr(self, f'_check_{vpn_type}_vpn', None)
            if config_check_method:
                return config_check_method()
        
        return True
    
    def _check_openvpn_vpn(self) -> bool:
        """Check OpenVPN specific configuration."""
        # Look for potential OpenVPN configuration weaknesses
        config_cmd = ['find', '/etc/openvpn', '-type', 'f', '-name', '*.conf']
        config_result = self.run_command(config_cmd)
        
        if config_result.get('success', False):
            configs = config_result.get('stdout', '').split('\n')
            weak_configs = []
            
            for config in configs:
                with open(config, 'r') as f:
                    content = f.read()
                    # Check for weak encryption or vulnerable settings
                    if 'cipher DES' in content or 'auth-nocipher' in content:
                        weak_configs.append(config)
                        self.log(f"Weak OpenVPN configuration detected: {config}", "FAIL")
            
            if weak_configs:
                return False
        
        self.log("OpenVPN configuration appears secure", "PASS")
        return True
    
    def _check_wireguard_vpn(self) -> bool:
        """Check WireGuard specific configuration."""
        # Check WireGuard interface and configuration
        wg_cmd = ['wg', 'show']
        wg_result = self.run_command(wg_cmd)
        
        if wg_result.get('success', False):
            # Basic checks for WireGuard configuration
            allowed_ips_match = re.search(r'allowed ips:\s*([^\n]+)', wg_result.get('stdout', ''), re.IGNORECASE)
            if allowed_ips_match:
                allowed_ips = allowed_ips_match.group(1)
                if '0.0.0.0/0' in allowed_ips:
                    self.log("Potential DNS leak risk in WireGuard configuration", "WARN")
        
        return True
    
    def _check_ipsec_vpn(self) -> bool:
        """Check IPSec specific configuration."""
        # Look for StrongSwan or other IPSec configurations
        ipsec_cmd = ['ipsec', 'statusall']
        ipsec_result = self.run_command(ipsec_cmd)
        
        if ipsec_result.get('success', False):
            # Check for weak configurations or established connections
            if 'no connections loaded' in ipsec_result.get('stdout', '').lower():
                self.log("No active IPSec connections", "INFO")
                return True
        
        return True

def main():
    parser = argparse.ArgumentParser(description='WiFi Pineapple & Network Security Detector')
    parser.add_argument('--quick', action='store_true', help='Run quick test (essential checks only)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', help='Save results to JSON file')
    
    # NEW VPN-SPECIFIC ARGUMENTS
    parser.add_argument('--check-vpn', action='store_true', help='Perform specific VPN configuration checks')
    parser.add_argument('--vpn-type', choices=['openvpn', 'wireguard', 'ipsec'], help='Specify VPN type for targeted checks')
    
    args = parser.parse_args()
    
    detector = PineappleDetector(verbose=args.verbose)
    
    try:
        if args.quick:
            results = detector.run_quick_test()
        else:
            results = detector.run_comprehensive_test()
        
        # Perform VPN checks if requested
        if args.check_vpn:
            vpn_result = detector.test_vpn_configuration(vpn_type=args.vpn_type)
            results['vpn_check_passed'] = vpn_result
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\nResults saved to: {args.output}")
        
        # Exit with error code if threats detected
        sys.exit(0 if results['overall_status'] == 'SECURE' else 1)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()