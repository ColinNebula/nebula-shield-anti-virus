# 🏥 System Healing & Recovery - Complete Guide

## Overview

The **System Healer** is a comprehensive repair module designed to fix critical system issues caused by malware infections, system corruption, or configuration problems. It can restore a compromised computer to a healthy state.

---

## 🎯 Key Capabilities

### ✅ **What the System Healer Can Fix**

| Category | Features | Impact |
|----------|----------|--------|
| **Processes** | Kill malicious processes, Stop crypto miners, Terminate ransomware | 🔴 Critical |
| **System Files** | Run SFC & DISM, Repair boot configuration, Fix corrupted files | 🔴 Critical |
| **Registry** | Remove autorun malware, Fix browser hijacks, Clean startup entries | 🟠 High |
| **Network** | Reset DNS, Clean hosts file, Remove proxy hijacks, Reset adapters | 🟠 High |
| **Browsers** | Reset homepage, Remove extensions, Fix search engines | 🟡 Medium |
| **Services** | Restore critical services, Fix Windows Update, Repair Firewall | 🔴 Critical |
| **Tasks** | Remove malicious scheduled tasks, Clean fake updates | 🟠 High |
| **Updates** | Repair Windows Update, Clear update cache, Reset components | 🟠 High |
| **Backup** | Create system restore points, Enable rollback | 🔴 Critical |

---

## 🚀 Quick Start

### Run Full System Heal

```bash
POST /api/system/heal
```

**Request body (all optional):**
```json
{
  "processes": true,      // Kill malicious processes
  "system": true,         // Repair system files
  "registry": true,       // Clean registry
  "network": true,        // Reset network
  "browsers": true,       // Clean browsers
  "services": true,       // Repair services
  "tasks": true,          // Clean scheduled tasks
  "updates": true,        // Repair Windows Update
  "restorePoint": true    // Create restore point
}
```

**Response:**
```json
{
  "timestamp": "2026-02-17T10:00:00.000Z",
  "success": true,
  "repairs": {
    "processes": {
      "success": true,
      "suspicious": 3,
      "terminated": 2,
      "processes": ["cryptominer.exe", "ransomware.exe"]
    },
    "systemFiles": {
      "success": true,
      "sfc": { "status": "completed", "repaired": true },
      "dism": { "status": "completed", "repaired": true },
      "boot": { "status": "checked", "valid": true }
    },
    "registry": {
      "success": true,
      "autorun": ["malware_startup"],
      "hijack": ["HKCU\\SOFTWARE\\..."],
      "services": []
    },
    "network": {
      "success": true,
      "dns": { "success": true },
      "winsock": { "success": true },
      "tcpip": { "success": true },
      "hosts": { "success": true, "removed": 5 },
      "proxy": { "success": true, "removed": true }
    },
    "browsers": {
      "success": true,
      "chrome": ["homepage_reset", "search_engine_reset"],
      "firefox": [],
      "edge": []
    },
    "services": {
      "success": true,
      "repaired": 3,
      "failed": 0
    },
    "tasks": {
      "success": true,
      "removed": 2,
      "tasks": ["FakeUpdate", "TempTask123"]
    },
    "updates": {
      "success": true,
      "softwareDistribution": { "renamed": true },
      "services": { "restarted": true }
    },
    "restorePoint": {
      "success": true,
      "description": "Nebula Shield System Heal - 2026-02-17",
      "timestamp": "2026-02-17T10:00:00.000Z"
    }
  }
}
```

---

## 🔧 Individual Healing Modules

### 1. Process Healing

**Kill malicious processes running on the system**

```bash
POST /api/system/heal/processes
```

**What it does:**
- Scans for suspicious process names
- Terminates crypto miners, ransomware, keyloggers
- Identifies fake system processes

**Patterns detected:**
- `ransomware|crypto|locker|encryptor`
- `keylogger|logger|keylog`
- `miner|mining|cryptominer`
- `trojan|malware|backdoor`
- Fake `svchost.exe`, `csrss.exe`, `winlogon.exe`

**Example response:**
```json
{
  "success": true,
  "suspicious": 3,
  "terminated": 2,
  "processes": ["cryptominer.exe", "keylogger.exe"]
}
```

---

### 2. System File Repair

**Repair corrupted Windows system files**

```bash
POST /api/system/heal/systemfiles
```

**What it does:**
- Runs **SFC (System File Checker)** - Repairs corrupted system files
- Runs **DISM** - Repairs Windows image
- Checks **boot configuration** (BCD)

**Time required:** 10-20 minutes

**Example response:**
```json
{
  "success": true,
  "sfc": {
    "status": "completed",
    "corrupted": false,
    "repaired": true
  },
  "dism": {
    "status": "completed",
    "repaired": true
  },
  "boot": {
    "status": "checked",
    "valid": true
  }
}
```

---

### 3. Registry Repair

**Clean malware from Windows Registry**

```bash
POST /api/system/heal/registry
```

**What it does:**
- Removes malicious **autorun entries** (startup malware)
- Fixes **browser hijacks** (homepage changes)
- Cleans **suspicious registry keys**

**Keys cleaned:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Internet Explorer\Main`

**Patterns detected:**
- Entries in `temp` or `tmp` folders
- Downloads from HTTP URLs
- Suspicious executables

**Example response:**
```json
{
  "success": true,
  "autorun": ["malware_startup", "cryptominer"],
  "hijack": ["HKCU\\...\\Internet Explorer\\Main"],
  "services": []
}
```

---

### 4. Network Healing

**Reset network configuration**

```bash
POST /api/system/heal/network
```

**What it does:**
- Flushes **DNS cache** (`ipconfig /flushdns`)
- Resets **Winsock** (`netsh winsock reset`)
- Resets **TCP/IP stack** (`netsh int ip reset`)
- Cleans **hosts file** (removes hijacks)
- Removes **proxy hijacks**

**Example response:**
```json
{
  "success": true,
  "dns": { "success": true },
  "winsock": { "success": true },
  "tcpip": { "success": true },
  "hosts": {
    "success": true,
    "removed": 5
  },
  "proxy": {
    "success": true,
    "removed": true
  }
}
```

---

### 5. Browser Cleanup

**Remove browser hijacks and malicious extensions**

```bash
POST /api/system/heal/browsers
```

**What it does:**
- Resets Chrome homepage & search engine
- Removes suspicious preferences
- Cleans startup URLs

**Example response:**
```json
{
  "success": true,
  "chrome": ["homepage_reset", "search_engine_reset"],
  "firefox": [],
  "edge": []
}
```

---

### 6. Service Repair

**Restore critical Windows services**

```bash
POST /api/system/heal/services
```

**Critical services repaired:**
- `wuauserv` - Windows Update
- `wscsvc` - Security Center
- `WinDefend` - Windows Defender
- `mpssvc` - Windows Firewall
- `BITS` - Background Intelligent Transfer
- `Dhcp` - DHCP Client
- `Dnscache` - DNS Client
- `EventLog` - Event Log
- `Themes` - Themes Service

**Example response:**
```json
{
  "success": true,
  "repaired": 3,
  "failed": 0
}
```

---

### 7. Scheduled Task Cleanup

**Remove malicious scheduled tasks**

```bash
POST /api/system/heal/tasks
```

**What it does:**
- Scans all scheduled tasks
- Removes tasks with suspicious patterns:
  - Tasks in `temp` folders
  - Fake update tasks with timestamps
  - Tasks executing from `AppData\Local\Temp`

**Example response:**
```json
{
  "success": true,
  "removed": 2,
  "tasks": ["FakeUpdate12345", "TempTask"]
}
```

---

### 8. Windows Update Repair

**Fix broken Windows Update**

```bash
POST /api/system/heal/updates
```

**What it does:**
1. Stops Windows Update services
2. Renames `SoftwareDistribution` folder (clears cache)
3. Restarts services

**Example response:**
```json
{
  "success": true,
  "softwareDistribution": { "renamed": true },
  "services": { "restarted": true }
}
```

---

### 9. System Restore Point

**Create a restore point before/after repairs**

```bash
POST /api/system/heal/restorepoint
```

**What it does:**
- Creates a Windows System Restore point
- Allows rollback if repairs cause issues

**Example response:**
```json
{
  "success": true,
  "description": "Nebula Shield System Heal - 2026-02-17T10:00:00",
  "timestamp": "2026-02-17T10:00:00.000Z"
}
```

---

### 10. Get Healing Log

**View all healing operations performed**

```bash
GET /api/system/heal/log
```

**Example response:**
```json
{
  "success": true,
  "log": [
    {
      "timestamp": "2026-02-17T10:00:00.000Z",
      "level": "INFO",
      "message": "Terminated suspicious process: cryptominer.exe (PID: 1234)"
    },
    {
      "timestamp": "2026-02-17T10:00:05.000Z",
      "level": "INFO",
      "message": "Removed autorun entry: malware_startup"
    }
  ]
}
```

---

## 📋 Usage Scenarios

### Scenario 1: Ransomware Infection

**Problem:** Computer infected with ransomware, files encrypted

**Solution:**
1. Run `POST /api/system/heal/processes` - Kill ransomware process
2. Run `POST /api/system/heal/registry` - Remove persistence
3. Run `POST /api/system/heal/network` - Reset connections
4. Restore files from backup (separate module)

---

### Scenario 2: Browser Hijacked

**Problem:** Homepage changed, searches redirect to malicious sites

**Solution:**
1. Run `POST /api/system/heal/browsers` - Reset browser settings
2. Run `POST /api/system/heal/registry` - Remove hijack keys
3. Run `POST /api/system/heal/network` - Clean hosts file & proxy

---

### Scenario 3: System Won't Boot

**Problem:** Windows fails to start, boot errors

**Solution:**
1. Boot from recovery media
2. Run `POST /api/system/heal/systemfiles` - Repair boot configuration
3. Run system file checker (SFC & DISM)
4. Restart computer

---

### Scenario 4: Windows Update Broken

**Problem:** Updates fail to install, error codes

**Solution:**
1. Run `POST /api/system/heal/updates` - Reset Windows Update
2. Run `POST /api/system/heal/services` - Restart update services
3. Try updates again

---

### Scenario 5: Crypto Miner Infection

**Problem:** High CPU usage, unknown processes running

**Solution:**
1. Run `POST /api/system/heal/processes` - Kill miner
2. Run `POST /api/system/heal/registry` - Remove startup entry
3. Run `POST /api/system/heal/tasks` - Remove scheduled tasks
4. Run full antivirus scan

---

## ⚠️ Important Notes

### Requires Administrator Rights

All healing operations require **Administrator privileges** to:
- Terminate processes
- Modify registry
- Repair system files
- Restart services

### May Require Restart

Some repairs need a **system restart** to take effect:
- Network reset (Winsock, TCP/IP)
- System file repair (SFC, DISM)
- Service repairs
- Registry changes

### Creates Restore Point

Always create a **restore point** before healing:
```bash
POST /api/system/heal/restorepoint
```

This allows you to rollback if anything goes wrong.

### Time Requirements

| Operation | Time |
|-----------|------|
| Kill Processes | < 1 minute |
| Registry Repair | 1-2 minutes |
| Network Reset | 1-2 minutes |
| Browser Cleanup | < 1 minute |
| Service Repair | 1-2 minutes |
| Task Cleanup | < 1 minute |
| Update Repair | 2-3 minutes |
| System File Repair (SFC) | 10-15 minutes |
| System File Repair (DISM) | 15-30 minutes |

**Full System Heal:** 30-45 minutes

---

## 🛡️ Safety Features

### 1. **Backup Before Action**
- Creates restore points
- Preserves original files

### 2. **Detailed Logging**
- Every action logged
- View with `GET /api/system/heal/log`

### 3. **Rollback Capability**
- System restore points
- Registry backups
- Service state preserved

### 4. **Selective Healing**
- Run only specific repairs
- Skip unnecessary operations
- Minimize disruption

---

## 🔬 Technical Details

### Process Detection Patterns

```javascript
const suspiciousPatterns = [
  /svchost\.exe.*-k netsvcs -p -s/i, // Fake svchost
  /csrss\.exe/i,                      // Fake csrss
  /winlogon\.exe/i,                   // Fake winlogon
  /ransomware|crypto|locker|encryptor/i,
  /keylogger|logger|keylog/i,
  /miner|mining|cryptominer/i,
  /trojan|malware|backdoor/i
];
```

### Registry Autorun Keys Cleaned

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

### Hosts File Location

```
C:\Windows\System32\drivers\etc\hosts
```

### Critical Services Repaired

```
wuauserv, wscsvc, WinDefend, mpssvc, BITS, Dhcp, 
Dnscache, EventLog, Themes
```

---

## 📚 Related Documentation

- [Quarantine System](./REAL_QUARANTINE_GUIDE.md) - File quarantine & restoration
- [File Cleaning](./FILE_CLEANING_GUIDE.md) - Malware removal from files
- [Disk Cleanup](./DISK_CLEANUP_GUIDE.md) - Disk space optimization
- [Threat Detection](./THREAT-HANDLING-GUIDE.md) - Malware scanning

---

## 🆘 Troubleshooting

### "Access Denied" Errors

**Solution:** Run application as Administrator
```powershell
Right-click → Run as Administrator
```

### "Service Already Running" Errors

**Solution:** Stop service first before repairing
```bash
sc stop <service_name>
sc start <service_name>
```

### SFC/DISM Takes Too Long

**Explanation:** These tools scan ALL system files (can take 30+ minutes)
- SFC: 10-15 minutes
- DISM: 15-30 minutes
- Be patient, don't cancel

### Network Reset Causes Connection Loss

**Explanation:** Normal - restart required
```powershell
# After network reset
Restart-Computer
```

---

## 💡 Best Practices

### 1. **Before Healing**
- ✅ Create system restore point
- ✅ Backup important data
- ✅ Close all applications
- ✅ Disable antivirus temporarily (if healing that)

### 2. **During Healing**
- ✅ Don't interrupt operations
- ✅ Monitor logs for errors
- ✅ Be patient with long operations

### 3. **After Healing**
- ✅ Restart computer
- ✅ Run full antivirus scan
- ✅ Verify system works correctly
- ✅ Re-enable all protections

---

## 🎯 Success Metrics

After successful system healing:

- ✅ No malicious processes running
- ✅ Browser works normally
- ✅ Windows Update functions
- ✅ Network connectivity restored
- ✅ No suspicious autorun entries
- ✅ Critical services running
- ✅ System boots normally
- ✅ No error messages

---

## 🚨 When to Use System Healer

### ✅ **USE when:**
- Computer infected with malware
- Browser hijacked
- Windows Update broken
- System running slow (suspicious processes)
- Network connectivity issues
- Boot problems
- Services disabled by malware

### ❌ **DON'T USE when:**
- Hardware failure (disk, RAM, CPU)
- Driver issues (use Driver Manager instead)
- User errors (wrong password, etc.)
- Software bugs (not malware-related)
- Normal Windows updates
- Clean system with no issues

---

## 📞 Support

If system healing fails or causes issues:

1. **Restore from restore point:**
   ```powershell
   rstrui.exe  # Opens System Restore
   ```

2. **Check healing log:**
   ```bash
   GET /api/system/heal/log
   ```

3. **Try individual repairs** instead of full heal

4. **Contact support** with log file

---

**System Healer - Making your computer healthy again! 🏥**
