# WiFi Pineapple Detection & Network Security Test

## Quick Start

```bash
# Quick test (2-3 minutes)
python3 pineapple_detector.py --quick

# Full comprehensive test (5-10 minutes)
python3 pineapple_detector.py

# Save results to file
python3 pineapple_detector.py --output results.json

# Verbose output for debugging
python3 pineapple_detector.py --verbose
```

## What This Tool Detects

### Primary Threats
- **WiFi Pineapple attacks** - Rogue access points performing man-in-the-middle attacks
- **DNS hijacking/poisoning** - Malicious DNS responses redirecting traffic
- **SSL/TLS certificate manipulation** - Invalid or compromised certificates
- **ARP poisoning** - Network traffic redirection attacks
- **Exposed system services** - Vulnerable services accessible from network

### System Vulnerabilities
- **Disabled firewall** - Critical system exposure
- **Risky exposed services** - VNC, SSH, Telnet accessible from network
- **Time manipulation attacks** - Clock skewing for authentication bypass

## Test Results Interpretation

### ✅ SECURE Status
- All tests passed
- No threats detected
- Safe to continue using network
- Run periodically on new networks

### 🚨 THREATS_DETECTED Status
- Critical security issues found
- Potential WiFi Pineapple or compromise
- **STOP using network immediately**
- Switch to trusted network
- Investigate flagged issues

### ⚠️ Warnings (May be False Positives)
- Minor inconsistencies detected
- Often legitimate (CDN load balancing)
- Monitor but continue usage
- Consider additional verification

## Test Breakdown

### SSL Certificate Validation
**What it checks:** Validates SSL certificates for major websites
**Detects:** Man-in-the-middle attacks, certificate manipulation
**Red flags:** Certificate errors, self-signed certificates, invalid chains

### DNS Integrity Check  
**What it checks:** Compares DNS responses across multiple servers
**Detects:** DNS hijacking, poisoning, redirection attacks
**Red flags:** Private IP responses, unverified IP ownership

### System Firewall Status
**What it checks:** Verifies firewall is enabled and protecting system
**Detects:** System exposure vulnerabilities
**Red flags:** Disabled firewall, system accessible from network

### Exposed Services Scan
**What it checks:** Scans for risky network services
**Detects:** Vulnerable services accessible from network
**Red flags:** VNC, SSH, Telnet, RDP exposed publicly

### Network Configuration Check
**What it checks:** Analyzes ARP table and routing for anomalies
**Detects:** ARP poisoning, routing manipulation
**Red flags:** Duplicate MAC addresses, suspicious routing

### Time Synchronization Check
**What it checks:** Verifies system time accuracy
**Detects:** Time manipulation attacks
**Red flags:** Large time offsets (>10 seconds)

## Quick Reference Checklist

### Before Connecting to New WiFi
- [ ] Run quick test: `python3 pineapple_detector.py --quick`
- [ ] Verify network name matches expected
- [ ] Check for duplicate network names (evil twins)

### When Results Show THREATS_DETECTED
- [ ] **Disconnect from WiFi immediately**
- [ ] Switch to cellular/trusted network
- [ ] Run test again on trusted network to verify tool
- [ ] Report to network administrator if corporate network
- [ ] Consider using VPN on suspicious networks

### When Results Show SECURE
- [ ] Safe to continue using network
- [ ] Run full test occasionally: `python3 pineapple_detector.py`
- [ ] Keep tool updated for new threat detection

## Advanced Usage

### Regular Monitoring
```bash
# Daily quick check (add to cron)
python3 pineapple_detector.py --quick --output daily_check.json

# Weekly comprehensive test
python3 pineapple_detector.py --output weekly_audit.json
```

### Network Comparison
```bash
# Test on trusted network first (baseline)
python3 pineapple_detector.py --output trusted_baseline.json

# Test on suspicious network
python3 pineapple_detector.py --output suspicious_network.json

# Compare results
```

### Corporate/Enterprise Use
```bash
# Run on all company WiFi networks
python3 pineapple_detector.py --verbose --output company_audit.json

# Schedule regular automated checks
# Monitor for threats across organization
```

## False Positive Management

### Common False Positives
1. **DNS variations** - Legitimate CDN load balancing (Google, Cloudflare)
2. **Connection timeouts** - Network latency, not security issues
3. **Development services** - Legitimate local development servers

### Verification Steps
1. **DNS issues**: Check whois ownership of reported IPs
2. **Certificate issues**: Test from different networks
3. **Service exposure**: Verify if services are intentionally public

## Emergency Response

### If Pineapple Attack Detected
1. **Immediate**: Disconnect from WiFi
2. **Secure**: Switch to cellular/trusted network  
3. **Verify**: Run test on known good network
4. **Investigate**: Check what data may have been exposed
5. **Report**: Notify security team/network administrator

### If System Vulnerabilities Found
1. **Critical**: Enable firewall immediately
2. **High**: Secure/disable exposed services
3. **Medium**: Review and audit service configurations
4. **Monitor**: Set up regular security checks

## Tool Maintenance

### Keep Updated
```bash
# Update the tool regularly for new threat signatures
# Check for new test domains and DNS servers
# Update threat detection patterns
```

### System Requirements
- Python 3.6+
- macOS (Linux support can be added)
- Network access for testing
- sudo access for firewall checks

### Dependencies
- curl (SSL testing)
- dig (DNS testing)  
- netstat (service scanning)
- arp (network analysis)
- sntp (time checking)

## Troubleshooting

### Permission Issues
```bash
# If firewall check fails
sudo python3 pineapple_detector.py

# Or run other tests without sudo
python3 pineapple_detector.py --quick
```

### Network Connectivity Issues
- Ensure internet access available
- Try from different network if all tests fail
- Check if corporate firewall blocks testing domains

### Tool Not Working
- Verify all dependencies installed
- Check Python version (3.6+ required)
- Run with --verbose for detailed output

## Security Best Practices

### When to Run This Tool
- **Always**: Before connecting to new WiFi networks
- **Suspicious networks**: Free WiFi, public hotspots, untrusted locations
- **Regular audit**: Weekly/monthly on trusted networks
- **After incidents**: If you suspect compromise

### Additional Security Measures
- Use VPN on untrusted networks
- Enable firewall always
- Keep system updated
- Monitor network activity
- Use HTTPS-only browsing

### What This Tool Cannot Detect
- Physical network taps
- Sophisticated state-level attacks
- Application-level vulnerabilities
- Social engineering attacks
- Malware already on system

---

**Remember: This tool is one layer of security. Use in combination with other security measures for comprehensive protection.** 