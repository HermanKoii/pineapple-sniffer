#!/usr/bin/env python3
"""
Network Security Analyzer using Established Security Tools
Orchestrates proven security tools to minimize false positives.
"""

import subprocess
import json
import datetime
import sys
import os
import re
from typing import Dict, List, Optional, Tuple

class SecurityAnalyzer:
    def __init__(self):
        self.test_domains = [
            'google.com',
            'github.com', 
            'apple.com',
            'microsoft.com',
            'cloudflare.com'
        ]
        self.dns_servers = {
            'google': '8.8.8.8',
            'cloudflare': '1.1.1.1',
            'current': None  # Will be detected
        }
        self.results = {}
        
    def log_command(self, command: str, result: dict) -> None:
        """Log command execution for the report."""
        timestamp = datetime.datetime.now().isoformat()
        if 'command_log' not in self.results:
            self.results['command_log'] = []
        
        self.results['command_log'].append({
            'timestamp': timestamp,
            'command': command,
            'result': result
        })
    
    def run_command(self, cmd: List[str], timeout: int = 30) -> Dict:
        """Execute a command and return structured results."""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            output = {
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'success': result.returncode == 0,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            self.log_command(' '.join(cmd), output)
            return output
            
        except subprocess.TimeoutExpired:
            output = {
                'command': ' '.join(cmd),
                'error': 'Command timed out',
                'success': False,
                'timestamp': datetime.datetime.now().isoformat()
            }
            self.log_command(' '.join(cmd), output)
            return output
            
        except Exception as e:
            output = {
                'command': ' '.join(cmd),
                'error': str(e),
                'success': False,
                'timestamp': datetime.datetime.now().isoformat()
            }
            self.log_command(' '.join(cmd), output)
            return output
    
    def check_tool_availability(self) -> Dict:
        """Verify that required security tools are available."""
        print("Checking security tool availability...")
        
        tools = {
            'openssl': ['openssl', 'version'],
            'curl': ['curl', '--version'],
            'dig': ['dig', '-v'],
            'nslookup': ['nslookup', '-version'],
            'netstat': ['netstat', '--version'],
            'lsof': ['lsof', '-v'],
            'security': ['security', '-h'],  # macOS keychain tool
            'scutil': ['scutil', '--help']    # macOS network utility
        }
        
        availability = {}
        for tool_name, cmd in tools.items():
            result = self.run_command(cmd)
            availability[tool_name] = {
                'available': result['success'] or 'usage' in result['stderr'].lower(),
                'version_info': result['stdout'] or result['stderr'],
                'command_result': result
            }
            
            status = "✅" if availability[tool_name]['available'] else "❌"
            print(f"  {status} {tool_name}")
        
        return availability
    
    def analyze_certificates(self, domain: str) -> Dict:
        """Analyze SSL certificates using OpenSSL and curl."""
        print(f"Analyzing certificates for {domain}...")
        
        analysis = {}
        
        # OpenSSL s_client analysis
        openssl_cmd = [
            'openssl', 's_client', '-connect', f'{domain}:443',
            '-servername', domain, '-verify_return_error'
        ]
        openssl_result = self.run_command(openssl_cmd)
        analysis['openssl_verification'] = openssl_result
        
        # Extract certificate with OpenSSL
        cert_cmd = [
            'openssl', 's_client', '-connect', f'{domain}:443',
            '-servername', domain, '-showcerts'
        ]
        cert_result = self.run_command(cert_cmd)
        analysis['certificate_details'] = cert_result
        
        # Curl SSL verification
        curl_cmd = ['curl', '-vvI', f'https://{domain}', '--connect-timeout', '10']
        curl_result = self.run_command(curl_cmd)
        analysis['curl_verification'] = curl_result
        
        # Check for suspicious indicators
        suspicious_indicators = []
        
        if not openssl_result.get('success', False):
            if 'verify error' in openssl_result.get('stderr', ''):
                suspicious_indicators.append("OpenSSL certificate verification failed")
        
        if not curl_result.get('success', False):
            if 'SSL' in curl_result.get('stderr', '') or 'certificate' in curl_result.get('stderr', ''):
                suspicious_indicators.append("Curl SSL verification failed")
        
        # Check for self-signed certificates
        if 'self signed' in openssl_result.get('stderr', '').lower():
            suspicious_indicators.append("Self-signed certificate detected")
            
        # Check for weak protocols
        if 'TLSv1 ' in openssl_result.get('stdout', '') or 'SSLv' in openssl_result.get('stdout', ''):
            suspicious_indicators.append("Weak SSL/TLS protocol detected")
        
        analysis['suspicious_indicators'] = suspicious_indicators
        analysis['risk_level'] = 'HIGH' if suspicious_indicators else 'LOW'
        
        return analysis
    
    def analyze_dns(self, domain: str) -> Dict:
        """Analyze DNS resolution using multiple DNS servers."""
        print(f"Analyzing DNS for {domain}...")
        
        analysis = {}
        
        # Get current DNS configuration
        dns_config_cmd = ['scutil', '--dns']
        dns_config = self.run_command(dns_config_cmd)
        analysis['dns_configuration'] = dns_config
        
        # Test with different DNS servers
        dns_results = {}
        
        for server_name, server_ip in self.dns_servers.items():
            if server_ip is None:  # Current DNS
                dig_cmd = ['dig', domain, 'A', '+short']
            else:
                dig_cmd = ['dig', f'@{server_ip}', domain, 'A', '+short']
            
            result = self.run_command(dig_cmd)
            dns_results[server_name] = result
        
        analysis['dns_resolution_comparison'] = dns_results
        
        # Check for DNS inconsistencies
        ip_addresses = {}
        for server, result in dns_results.items():
            if result.get('success', False):
                ips = [line.strip() for line in result.get('stdout', '').split('\n') if line.strip()]
                ip_addresses[server] = ips
        
        # Compare results
        suspicious_indicators = []
        if len(set(str(sorted(ips)) for ips in ip_addresses.values())) > 1:
            suspicious_indicators.append("DNS resolution inconsistency detected")
        
        # Check for private IP addresses in public DNS (potential DNS hijacking)
        for server, ips in ip_addresses.items():
            for ip in ips:
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                    suspicious_indicators.append(f"Private IP address returned by {server} DNS")
        
        analysis['suspicious_indicators'] = suspicious_indicators
        analysis['risk_level'] = 'HIGH' if suspicious_indicators else 'LOW'
        
        return analysis
    
    def analyze_network_connections(self) -> Dict:
        """Analyze current network connections and listening ports."""
        print("Analyzing network connections...")
        
        analysis = {}
        
        # Get established connections
        netstat_cmd = ['netstat', '-an']
        netstat_result = self.run_command(netstat_cmd)
        analysis['all_connections'] = netstat_result
        
        # Get listening ports
        lsof_cmd = ['lsof', '-i', '-P']
        lsof_result = self.run_command(lsof_cmd)
        analysis['listening_ports'] = lsof_result
        
        # Parse for suspicious indicators
        suspicious_indicators = []
        
        if netstat_result.get('success', False):
            # Check for connections to unusual ports
            lines = netstat_result.get('stdout', '').split('\n')
            for line in lines:
                if 'ESTABLISHED' in line:
                    # Look for connections to suspicious ports
                    if ':22 ' in line or ':23 ' in line or ':3389 ' in line:
                        suspicious_indicators.append(f"Connection to administrative port: {line.strip()}")
        
        if lsof_result.get('success', False):
            # Check for suspicious listening services
            lines = lsof_result.get('stdout', '').split('\n')
            for line in lines:
                if 'LISTEN' in line:
                    # Look for unusual listening ports
                    if any(port in line for port in [':22 ', ':23 ', ':3389 ', ':1337 ', ':31337 ']):
                        suspicious_indicators.append(f"Suspicious listening port: {line.strip()}")
        
        analysis['suspicious_indicators'] = suspicious_indicators
        analysis['risk_level'] = 'MEDIUM' if suspicious_indicators else 'LOW'
        
        return analysis
    
    def analyze_system_certificates(self) -> Dict:
        """Analyze system certificate store for unauthorized additions."""
        print("Analyzing system certificate store...")
        
        analysis = {}
        
        # Get system root certificates (macOS)
        root_certs_cmd = [
            'security', 'find-certificate', '-a', '-p',
            '/System/Library/Keychains/SystemRootCertificates.keychain'
        ]
        root_certs = self.run_command(root_certs_cmd)
        analysis['system_root_certificates'] = root_certs
        
        # Get user certificates 
        user_certs_cmd = ['security', 'find-certificate', '-a', '-p']
        user_certs = self.run_command(user_certs_cmd)
        analysis['user_certificates'] = user_certs
        
        # Look for suspicious certificate authorities
        suspicious_indicators = []
        suspicious_ca_patterns = [
            'DO_NOT_TRUST',
            'UNTRUSTED', 
            'TEST',
            'DEMO',
            'localhost',
            'PROXY',
            'MITM'
        ]
        
        for cert_result in [root_certs, user_certs]:
            if cert_result.get('success', False):
                cert_text = cert_result.get('stdout', '').lower()
                for pattern in suspicious_ca_patterns:
                    if pattern.lower() in cert_text:
                        suspicious_indicators.append(f"Suspicious certificate authority pattern found: {pattern}")
        
        analysis['suspicious_indicators'] = suspicious_indicators
        analysis['risk_level'] = 'HIGH' if suspicious_indicators else 'LOW'
        
        return analysis
    
    def run_comprehensive_analysis(self) -> Dict:
        """Run the complete security analysis."""
        print("="*60)
        print("NETWORK SECURITY ANALYSIS")
        print("="*60)
        print(f"Started at: {datetime.datetime.now()}")
        print()
        
        results = {
            'analysis_start': datetime.datetime.now().isoformat(),
            'tool_availability': self.check_tool_availability(),
            'certificate_analysis': {},
            'dns_analysis': {},
            'network_analysis': self.analyze_network_connections(),
            'system_certificates': self.analyze_system_certificates()
        }
        
        # Analyze certificates for each test domain
        for domain in self.test_domains:
            results['certificate_analysis'][domain] = self.analyze_certificates(domain)
        
        # Analyze DNS for each test domain  
        for domain in self.test_domains:
            results['dns_analysis'][domain] = self.analyze_dns(domain)
        
        results['analysis_end'] = datetime.datetime.now().isoformat()
        
        return results
    
    def generate_report(self, results: Dict) -> str:
        """Generate a comprehensive security report."""
        report = []
        report.append("="*60)
        report.append("NETWORK SECURITY ANALYSIS REPORT")
        report.append("="*60)
        report.append(f"Analysis Period: {results['analysis_start']} to {results['analysis_end']}")
        report.append("")
        
        # Tool availability summary
        tools = results['tool_availability']
        available_tools = sum(1 for tool in tools.values() if tool['available'])
        total_tools = len(tools)
        
        report.append(f"TOOL AVAILABILITY: {available_tools}/{total_tools} tools available")
        for tool_name, tool_info in tools.items():
            status = "✅" if tool_info['available'] else "❌"
            report.append(f"  {status} {tool_name}")
        report.append("")
        
        # Security findings summary
        high_risk_findings = []
        medium_risk_findings = []
        
        # Check certificate analysis
        for domain, analysis in results['certificate_analysis'].items():
            if analysis.get('risk_level') == 'HIGH':
                high_risk_findings.extend([f"Certificate issue for {domain}: {ind}" for ind in analysis.get('suspicious_indicators', [])])
        
        # Check DNS analysis
        for domain, analysis in results['dns_analysis'].items():
            if analysis.get('risk_level') == 'HIGH':
                high_risk_findings.extend([f"DNS issue for {domain}: {ind}" for ind in analysis.get('suspicious_indicators', [])])
        
        # Check network analysis
        if results['network_analysis'].get('risk_level') == 'MEDIUM':
            medium_risk_findings.extend([f"Network: {ind}" for ind in results['network_analysis'].get('suspicious_indicators', [])])
        
        # Check system certificates
        if results['system_certificates'].get('risk_level') == 'HIGH':
            high_risk_findings.extend([f"System certificates: {ind}" for ind in results['system_certificates'].get('suspicious_indicators', [])])
        
        # Report findings
        if high_risk_findings:
            report.append("🚨 HIGH RISK FINDINGS:")
            for finding in high_risk_findings:
                report.append(f"  - {finding}")
            report.append("")
        
        if medium_risk_findings:
            report.append("⚠️  MEDIUM RISK FINDINGS:")
            for finding in medium_risk_findings:
                report.append(f"  - {finding}")
            report.append("")
        
        if not high_risk_findings and not medium_risk_findings:
            report.append("✅ NO SIGNIFICANT SECURITY ISSUES DETECTED")
            report.append("")
        
        report.append("RECOMMENDATIONS:")
        if high_risk_findings or medium_risk_findings:
            report.append("  - Review and investigate flagged items above")
            report.append("  - Consider switching to a trusted network")
            report.append("  - Verify system has not been compromised")
        else:
            report.append("  - Network appears secure for current use")
            report.append("  - Continue periodic security monitoring")
        
        return "\n".join(report)

def main():
    """Main execution function."""
    analyzer = SecurityAnalyzer()
    
    # Run comprehensive analysis
    results = analyzer.run_comprehensive_analysis()
    
    # Generate report
    report = analyzer.generate_report(results)
    
    # Save results
    with open('security_analysis_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    with open('security_analysis_report.txt', 'w') as f:
        f.write(report)
    
    print(report)
    print(f"\nDetailed results saved to: security_analysis_results.json")
    print(f"Report saved to: security_analysis_report.txt")
    
    return results

if __name__ == "__main__":
    main() 