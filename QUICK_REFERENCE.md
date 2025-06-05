# 🍍 WiFi Pineapple Quick Reference Card

## ⚡ IMMEDIATE ASSESSMENT (30 seconds)

```bash
python3 pineapple_detector.py --quick
```

## 🚨 THREAT RESPONSE

### ✅ If "NETWORK APPEARS SECURE"
- ✅ Safe to use network
- ✅ Continue normal activities
- ✅ Run full test when convenient

### ❌ If "SECURITY THREATS DETECTED"
- 🔴 **DISCONNECT IMMEDIATELY**
- 📱 Switch to cellular/trusted network
- 🔍 Investigate before reconnecting
- 📞 Report to network admin

## 🎯 COMMON ATTACK INDICATORS

| Sign | Threat | Action |
|------|--------|--------|
| DNS pointing to private IPs | Pineapple/MITM | DISCONNECT |
| SSL certificate errors | Certificate manipulation | DISCONNECT |
| Firewall disabled | System exposure | ENABLE FIREWALL |
| VNC/SSH exposed | Remote access risk | SECURE SERVICES |

## ⚡ EMERGENCY COMMANDS

```bash
# Enable firewall immediately
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Quick network check
ping -c 2 8.8.8.8

# Check current WiFi
networksetup -getairportnetwork en0
```

## 📋 FIELD CHECKLIST

### Before Connecting
- [ ] Network name matches expected?
- [ ] Any duplicate network names?
- [ ] Run quick test first

### After Test Results
- [ ] All tests passed?
- [ ] Any threats detected?
- [ ] Firewall enabled?
- [ ] System secure?

## 🔧 COMMON FIXES

```bash
# Enable firewall + stealth mode
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

# Flush DNS cache
dscacheutil -flushcache

# Check exposed services
netstat -an | grep LISTEN
```

## 📞 ESCALATION

### If Pineapple Detected
1. Disconnect WiFi
2. Document findings
3. Notify security team
4. Switch to VPN/cellular

### If System Compromised
1. Enable firewall
2. Secure exposed services
3. Full security audit
4. Monitor for intrusion

---
**📱 Keep this handy when using untrusted WiFi!** 