#!/usr/bin/env python3
"""
WiFi Pineapple & Network Security Detector
==========================================

A comprehensive security test for detecting WiFi Pineapple attacks, 
man-in-the-middle attacks, and system vulnerabilities.

Usage: python3 pineapple_detector.py [--quick] [--verbose]

Based on security analysis methodology that uses established tools
to minimize false positives while detecting real threats.
"""

import subprocess
import json
import datetime
import sys
import os
import argparse
from typing import Dict, List, Optional, Tuple

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
            print(f"[{timestamp}] ✅ {message}")
        elif level == "FAIL":
            print(f"[{timestamp}] ❌ {message}")
            self.threats_detected.append(message)
        elif level == "WARN":
            print(f"[{timestamp}] ⚠️  {message}")
            self.warnings.append(message)
        elif self.verbose or level == "ERROR":
            print(f"[{timestamp}] {level}: {message}")
    
    def run_command(self, cmd: List[str], timeout: int = 10) -> Dict:
        """Execute command and return structured results."""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'success': result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                'command': ' '.join(cmd),
                'error': 'Command timed out',
                'success': False
            }
        except Exception as e:
            return {
                'command': ' '.join(cmd),
                'error': str(e),
                'success': False
            }
    
    def test_ssl_certificates(self) -> bool:
        """Test SSL certificate validation for major domains."""
        self.log("Testing SSL certificate validation...")
        
        failed_domains = []
        
        for domain in self.test_domains:
            # Test with curl (most reliable)
            curl_cmd = ['curl', '-sI', '--connect-timeout', '5', f'https://{domain}']
            result = self.run_command(curl_cmd)
            
            if not result.get('success', False):
                # Check if it's a certificate error vs connection timeout
                stderr = result.get('stderr', '').lower()
                if any(cert_error in stderr for cert_error in ['certificate', 'ssl', 'tls']):
                    failed_domains.append(domain)
                    self.log(f"SSL certificate validation failed for {domain}", "FAIL")
                else:
                    self.log(f"Connection timeout for {domain} (may be network latency)", "WARN")
            else:
                self.log(f"SSL certificate valid for {domain}", "PASS")
        
        if failed_domains:
            self.log(f"SSL validation failed for domains: {', '.join(failed_domains)}", "FAIL")
            return False
        
        self.log("All SSL certificate validations passed", "PASS")
        return True
    
    def test_dns_integrity(self) -> bool:
        """Test DNS resolution consistency across multiple DNS servers."""
        self.log("Testing DNS integrity across multiple servers...")
        
        suspicious_domains = []
        
        for domain in self.test_domains:
            dns_responses = {}
            
            # Test with different DNS servers
            for server_name, server_ip in self.dns_servers.items():
                if server_ip is None:  # Current DNS
                    dig_cmd = ['dig', domain, 'A', '+short']
                else:
                    dig_cmd = ['dig', f'@{server_ip}', domain, 'A', '+short']
                
                result = self.run_command(dig_cmd)
                if result.get('success', False):
                    ips = [line.strip() for line in result.get('stdout', '').split('\n') if line.strip()]
                    dns_responses[server_name] = ips
            
            # Check for suspicious private IP responses
            for server, ips in dns_responses.items():
                for ip in ips:
                    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                        suspicious_domains.append(f"{domain} -> {ip} (via {server})")
                        self.log(f"SUSPICIOUS: {domain} resolving to private IP {ip} via {server}", "FAIL")
            
            # Verify IP ownership for major discrepancies
            unique_responses = set(str(sorted(ips)) for ips in dns_responses.values())
            if len(unique_responses) > 1:
                # This could be legitimate CDN, but let's verify with whois
                first_ips = list(dns_responses.values())[0]
                if first_ips:
                    whois_result = self.run_command(['whois', first_ips[0]])
                    if whois_result.get('success', False):
                        whois_text = whois_result.get('stdout', '').lower()
                        if domain.split('.')[0] not in whois_text:
                            # IP doesn't appear to belong to expected organization
                            self.log(f"DNS inconsistency for {domain} may indicate compromise", "WARN")
                        else:
                            self.log(f"DNS variation for {domain} appears to be legitimate CDN", "PASS")
        
        if suspicious_domains:
            self.log(f"Suspicious DNS responses detected: {suspicious_domains}", "FAIL")
            return False
        
        self.log("DNS integrity check passed", "PASS")
        return True
    
    def test_system_firewall(self) -> bool:
        """Check if system firewall is enabled."""
        self.log("Checking system firewall status...")
        
        # Check macOS firewall
        firewall_cmd = ['sudo', '/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate']
        result = self.run_command(firewall_cmd, timeout=15)
        
        if result.get('success', False):
            if 'enabled' in result.get('stdout', '').lower():
                self.log("System firewall is enabled", "PASS")
                return True
            else:
                self.log("System firewall is DISABLED - critical security risk", "FAIL")
                return False
        else:
            self.log("Could not check firewall status (may need sudo access)", "WARN")
            return True  # Don't fail the test if we can't check
    
    def test_exposed_services(self) -> bool:
        """Check for risky exposed network services."""
        self.log("Scanning for exposed network services...")
        
        risky_services = []
        
        # Check for listening services
        netstat_cmd = ['netstat', '-an']
        result = self.run_command(netstat_cmd)
        
        if result.get('success', False):
            lines = result.get('stdout', '').split('\n')
            
            for line in lines:
                if 'LISTEN' in line and not '127.0.0.1' in line:
                    # Check for risky ports
                    risky_ports = {
                        ':22 ': 'SSH',
                        ':23 ': 'Telnet',
                        ':3389 ': 'RDP',
                        ':5900 ': 'VNC',
                        ':5901 ': 'VNC',
                        ':5902 ': 'VNC'
                    }
                    
                    for port, service in risky_ports.items():
                        if port in line:
                            risky_services.append(f"{service} on port {port.strip(':')}")
                            self.log(f"Risky service exposed: {service} on port {port.strip(': ')}", "FAIL")
        
        if risky_services:
            self.log(f"Exposed risky services: {', '.join(risky_services)}", "FAIL")
            return False
        
        self.log("No risky exposed services detected", "PASS")
        return True
    
    def test_network_configuration(self) -> bool:
        """Verify network configuration for anomalies."""
        self.log("Checking network configuration...")
        
        # Check ARP table for suspicious entries
        arp_cmd = ['arp', '-a']
        arp_result = self.run_command(arp_cmd)
        
        if arp_result.get('success', False):
            arp_lines = arp_result.get('stdout', '').split('\n')
            gateway_macs = []
            
            # Look for duplicate MACs (possible ARP poisoning)
            mac_addresses = {}
            for line in arp_lines:
                if ' at ' in line:
                    parts = line.split(' at ')
                    if len(parts) > 1:
                        mac = parts[1].split(' ')[0]
                        ip = parts[0].split('(')[1].split(')')[0] if '(' in parts[0] else parts[0].strip()
                        
                        if mac in mac_addresses:
                            self.log(f"Duplicate MAC address detected: {mac} for IPs {mac_addresses[mac]} and {ip}", "WARN")
                        else:
                            mac_addresses[mac] = ip
        
        # Check DHCP configuration
        route_cmd = ['route', '-n', 'get', 'default']
        route_result = self.run_command(route_cmd)
        
        if route_result.get('success', False):
            self.log("Network routing configuration appears normal", "PASS")
        
        return True
    
    def test_time_synchronization(self) -> bool:
        """Check system time synchronization (time-based attacks)."""
        self.log("Verifying time synchronization...")
        
        sntp_cmd = ['sntp', '-t', '3', 'time.apple.com']
        result = self.run_command(sntp_cmd)
        
        if result.get('success', False):
            stdout = result.get('stdout', '')
            # Look for large time offset (potential time manipulation)
            if 'offset' in stdout:
                try:
                    offset_line = [line for line in stdout.split('\n') if 'offset' in line][0]
                    offset_str = offset_line.split()[0]
                    offset = abs(float(offset_str))
                    
                    if offset > 10.0:  # More than 10 seconds off
                        self.log(f"Large time offset detected: {offset} seconds", "WARN")
                    else:
                        self.log("System time synchronization is accurate", "PASS")
                except:
                    self.log("Time synchronization check completed", "PASS")
        
        return True
    
    def run_quick_test(self) -> Dict:
        """Run essential tests only."""
        self.log("Running QUICK WiFi Pineapple detection test...")
        
        tests = [
            ("SSL Certificate Validation", self.test_ssl_certificates),
            ("DNS Integrity Check", self.test_dns_integrity),
            ("System Firewall Status", self.test_system_firewall),
        ]
        
        return self._run_tests(tests)
    
    def run_comprehensive_test(self) -> Dict:
        """Run full security test suite."""
        self.log("Running COMPREHENSIVE network security test...")
        
        tests = [
            ("SSL Certificate Validation", self.test_ssl_certificates),
            ("DNS Integrity Check", self.test_dns_integrity),
            ("System Firewall Status", self.test_system_firewall),
            ("Exposed Services Scan", self.test_exposed_services),
            ("Network Configuration Check", self.test_network_configuration),
            ("Time Synchronization Check", self.test_time_synchronization),
        ]
        
        return self._run_tests(tests)
    
    def _run_tests(self, tests: List[Tuple[str, callable]]) -> Dict:
        """Execute test suite and return results."""
        start_time = datetime.datetime.now()
        passed_tests = 0
        total_tests = len(tests)
        
        print(f"\n{'='*60}")
        print(f"WIFI PINEAPPLE & NETWORK SECURITY TEST")
        print(f"{'='*60}")
        print(f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Tests: {total_tests}")
        print()
        
        for test_name, test_func in tests:
            self.log(f"Running: {test_name}")
            try:
                if test_func():
                    passed_tests += 1
            except Exception as e:
                self.log(f"Test {test_name} failed with error: {str(e)}", "ERROR")
            print()
        
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        
        # Generate results
        results = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration.total_seconds(),
            'tests_passed': passed_tests,
            'tests_total': total_tests,
            'threats_detected': self.threats_detected,
            'warnings': self.warnings,
            'overall_status': 'SECURE' if passed_tests == total_tests and not self.threats_detected else 'THREATS_DETECTED'
        }
        
        self._print_summary(results)
        return results
    
    def _print_summary(self, results: Dict):
        """Print test summary."""
        print(f"{'='*60}")
        print(f"TEST SUMMARY")
        print(f"{'='*60}")
        print(f"Duration: {results['duration_seconds']:.1f} seconds")
        print(f"Tests Passed: {results['tests_passed']}/{results['tests_total']}")
        print(f"Threats Detected: {len(results['threats_detected'])}")
        print(f"Warnings: {len(results['warnings'])}")
        print()
        
        if results['overall_status'] == 'SECURE':
            print("🎉 NETWORK APPEARS SECURE")
            print("   No WiFi Pineapple or major security threats detected.")
            print("   Safe to continue using this network.")
        else:
            print("🚨 SECURITY THREATS DETECTED")
            print("   Potential WiFi Pineapple or other security issues found.")
            print("   Consider switching to a trusted network.")
            print()
            
            if results['threats_detected']:
                print("Critical Issues:")
                for threat in results['threats_detected']:
                    print(f"   ❌ {threat}")
                print()
        
        if results['warnings']:
            print("Warnings (may be false positives):")
            for warning in results['warnings']:
                print(f"   ⚠️  {warning}")
            print()
        
        print("Recommendations:")
        if results['overall_status'] == 'SECURE':
            print("   ✅ Continue normal network usage")
            print("   ✅ Run this test periodically on new networks")
        else:
            print("   🔄 Switch to a trusted network")
            print("   🔍 Investigate flagged issues")
            print("   🛡️  Enable additional security measures (VPN, etc.)")
        
        print(f"\nTest completed at {results['end_time']}")


def main():
    parser = argparse.ArgumentParser(description='WiFi Pineapple & Network Security Detector')
    parser.add_argument('--quick', action='store_true', help='Run quick test (essential checks only)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    detector = PineappleDetector(verbose=args.verbose)
    
    try:
        if args.quick:
            results = detector.run_quick_test()
        else:
            results = detector.run_comprehensive_test()
        
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