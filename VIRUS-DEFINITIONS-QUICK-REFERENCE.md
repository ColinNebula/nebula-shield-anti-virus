# 🛡️ Virus Definitions Quick Reference

**Version**: 2025.11.03 | **Signatures**: 275 | **Last Updated**: Nov 3, 2025

---

## 📊 At a Glance

| Category | Count | Top Threats |
|----------|-------|-------------|
| 🔐 **Ransomware** | 20 | LockBit 3.0, BlackCat, Play, Akira |
| 🎭 **Trojans** | 45 | Emotet, TrickBot, Pikabot, DarkGate |
| 🕵️ **Infostealers** | 28 | Lumma, Stealc, RisePro, Rhadamanthys |
| 👑 **APT Groups** | 10 | Lazarus, Sandworm, APT29, Volt Typhoon |
| 🆕 **Zero-Days** | 15 | Windows Kernel, Chrome V8, MOVEit |
| 👻 **Fileless** | 10 | PowerShell Empire, WMI, Process Hollowing |
| 📦 **Supply Chain** | 10 | NPM, PyPI, Docker, GitHub Actions |
| 🤖 **AI/ML Threats** | 10 | ChatGPT Worm, Deepfake, Prompt Injection |
| 🔓 **Rootkits** | 8 | UEFI Bootkit, Hypervisor, SMM |
| 📱 **Mobile** | 8 | Pegasus, Flubot, XLoader |

---

## 🚨 Critical Threats (Severity 1.0)

### Ransomware
- LockBit 3.0 (2024) - Triple extortion
- BlackCat/ALPHV (Rust-based)
- Play Ransomware (Enterprise targeting)
- Akira (Rust variant)
- Royal (Infrastructure focus)

### Zero-Day Exploits
- Windows Kernel ZeroDay
- Chrome V8 Engine
- MOVEit Transfer SQL Injection
- Citrix Bleed
- Fortinet SSL-VPN RCE

### APTs
- Lazarus Group (NK cryptocurrency)
- Sandworm Team (RU infrastructure)
- Volt Typhoon (CN critical infra)
- APT29/Cozy Bear (RU cloud)

### AI/ML
- ChatGPT Worm (Polymorphic)
- LLM Prompt Injection
- Neural Trojan Backdoor

---

## 🎯 Quick Detection Guide

### Ransomware Indicators
```
✓ Rapid file encryption
✓ Mass .encrypted extension changes
✓ High entropy file writes
✓ Ransom note creation
✓ Shadow copy deletion
```

### Fileless Attack Indicators
```
✓ PowerShell obfuscation
✓ WMI event subscriptions
✓ Memory-only execution
✓ AMSI/ETW bypass
✓ No disk artifacts
```

### Supply Chain Indicators
```
✓ Suspicious package installs
✓ Postinstall scripts
✓ Typosquatting names
✓ Unsigned code execution
✓ Unusual dependencies
```

### APT Indicators
```
✓ Living-off-the-land tools
✓ Credential harvesting
✓ Lateral movement
✓ Long-term persistence
✓ Data exfiltration
```

---

## 🔧 Quick Commands

### Update Signatures
```bash
cd backend
node scripts/load-signatures.js
```

### Check Status
```bash
node scripts/check-signatures.js
```

### View by Category
```bash
# Check ransomware count
sqlite3 data/nebula_shield.db "SELECT COUNT(*) FROM signatures WHERE type='ransomware';"
```

---

## 📈 Coverage by Year

| Year | Signatures | Notable Threats |
|------|------------|-----------------|
| **2025** | 25 | AI worms, BCI hacks, Quantum threats |
| **2024** | 150 | LockBit 3.0, Lumma, Pikabot, Zero-days |
| **2023** | 50 | WannaCry, Emotet, Zeus (legacy) |
| **Behavioral** | 8 | Process chains, C2, Persistence |
| **ML Models** | 4 | Anomaly detection, Zero-day prediction |

---

## 🛡️ Protection Layers

```
1️⃣ Signature Matching (275 patterns)
2️⃣ Behavioral Analysis (8 signatures)
3️⃣ Machine Learning (4 models)
4️⃣ Cloud Intelligence (VirusTotal)
```

---

## ⚡ Emergency Response

### If Ransomware Detected
1. **IMMEDIATELY** disconnect from network
2. Power off the system
3. Do NOT pay ransom
4. Contact security team
5. Restore from backup

### If APT Activity Detected
1. Isolate affected systems
2. Preserve evidence
3. Analyze lateral movement
4. Check for persistence mechanisms
5. Conduct full incident response

### If Zero-Day Exploit
1. Apply patches immediately
2. Enable enhanced monitoring
3. Review security logs
4. Implement compensating controls
5. Report to authorities

---

## 📱 Contact

- **Support**: support@nebula3ddev.com
- **Website**: https://nebula3ddev.com
- **Emergency**: See `INCIDENT-RESPONSE.md`

---

**Created by Colin Nebula** | **Nebula3ddev.com**
