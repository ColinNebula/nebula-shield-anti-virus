# 📈 Advanced Monitoring Features Guide

## Overview

Nebula Shield's Advanced Monitoring provides deep system-level threat detection capabilities including registry monitoring, certificate validation, memory scanning, rootkit detection, and cryptocurrency miner detection.

---

## 🔍 Features

### 1. Registry Monitor (Windows)
Real-time monitoring of critical Windows registry keys for unauthorized modifications.

**Monitored Keys:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKLM\SYSTEM\CurrentControlSet\Services`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

**Detects:**
- Startup program additions
- Service modifications
- Persistence mechanisms
- Encoded PowerShell commands
- Suspicious script executions

### 2. Certificate Validation
Verify digital signatures on executable files to ensure authenticity and trustworthiness.

**Validates:**
- Authenticode signatures
- Certificate chains
- Certificate revocation status
- Timestamp validity
- Publisher information

### 3. Memory Scanner
Scan running processes for malicious behavior, hidden threats, and memory-resident malware.

**Detects:**
- High CPU usage processes
- Processes without executable paths (rootkits)
- Known malware process names
- Processes running from suspicious locations
- Injected code in memory

### 4. Rootkit Detection
Deep system-level scanning to detect hidden processes, files, and kernel-level threats.

**Scans For:**
- Hidden processes (comparison method)
- Suspicious kernel drivers
- Hidden files in system directories
- API hooks
- File system anomalies

### 5. Cryptocurrency Miner Detection
Identify and block unauthorized cryptocurrency mining activity.

**Indicators:**
- Known miner process names (XMRig, Ethminer, CGMiner, etc.)
- High sustained CPU usage (>80%)
- Network connections to mining pools
- Stratum protocol usage
- Mining-related keywords in process paths

---

## 🚀 API Reference

### Registry Monitoring

#### Start Registry Monitoring
```http
POST /api/monitoring/registry/start
```

**Response:**
```json
{
  "success": true,
  "message": "Registry monitoring started",
  "monitoredKeys": 7
}
```

#### Stop Registry Monitoring
```http
POST /api/monitoring/registry/stop
```

**Response:**
```json
{
  "success": true,
  "message": "Registry monitoring stopped",
  "changesDetected": 5
}
```

#### Get Registry Changes
```http
GET /api/monitoring/registry/changes?limit=100
```

**Response:**
```json
{
  "success": true,
  "changes": [
    {
      "id": "a1b2c3d4e5f6g7h8",
      "timestamp": 1698765432000,
      "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "action": "added",
      "entry": {
        "name": "MyApp",
        "type": "REG_SZ",
        "value": "C:\\Program Files\\MyApp\\app.exe"
      },
      "severity": "high",
      "suspicious": false
    }
  ],
  "total": 25,
  "suspicious": 3
}
```

### Certificate Validation

#### Validate File Certificate
```http
POST /api/monitoring/certificate/validate
Content-Type: application/json

{
  "filePath": "C:\\Program Files\\MyApp\\app.exe"
}
```

**Response:**
```json
{
  "success": true,
  "filePath": "C:\\Program Files\\MyApp\\app.exe",
  "signed": true,
  "status": "Valid",
  "signer": {
    "subject": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
    "issuer": "CN=Microsoft Code Signing PCA 2011",
    "thumbprint": "3B7E0328F7BB73ED...",
    "notBefore": "2023-01-15T00:00:00Z",
    "notAfter": "2025-01-15T00:00:00Z"
  },
  "trust": "trusted",
  "validatedAt": 1698765432000
}
```

### Memory Scanning

#### Start Memory Scanning
```http
POST /api/monitoring/memory/start
```

**Response:**
```json
{
  "success": true,
  "message": "Memory scanning started",
  "interval": "30 seconds"
}
```

#### Stop Memory Scanning
```http
POST /api/monitoring/memory/stop
```

**Response:**
```json
{
  "success": true,
  "message": "Memory scanning stopped",
  "threatsDetected": 2
}
```

#### Perform Memory Scan (Manual)
```http
GET /api/monitoring/memory/scan
```

**Response:**
```json
{
  "success": true,
  "scanned": 342,
  "suspicious": 2,
  "threats": [
    {
      "name": "suspicious.exe",
      "pid": 1234,
      "cpu": 95.5,
      "path": "C:\\Temp\\suspicious.exe",
      "reason": "High CPU usage",
      "threat": "Potential cryptocurrency miner",
      "severity": "high"
    }
  ]
}
```

### Rootkit Detection

#### Scan for Rootkits
```http
POST /api/monitoring/rootkit/scan
```

**Response:**
```json
{
  "success": true,
  "hiddenProcesses": [
    {
      "name": "hidden.exe",
      "pid": 5678,
      "reason": "Process hidden from standard enumeration",
      "severity": "high"
    }
  ],
  "hiddenFiles": [],
  "hookedAPIs": [],
  "suspiciousDrivers": [
    {
      "name": "rootkit.sys",
      "reason": "Suspicious driver name",
      "severity": "high"
    }
  ],
  "threatLevel": "high",
  "rootkitDetected": true,
  "timestamp": 1698765432000
}
```

### Cryptocurrency Miner Detection

#### Scan for Crypto Miners
```http
POST /api/monitoring/cryptominer/scan
```

**Response:**
```json
{
  "success": true,
  "suspiciousProcesses": [
    {
      "name": "xmrig.exe",
      "pid": 9876,
      "cpu": 85.2,
      "path": "C:\\Users\\Public\\xmrig.exe",
      "reason": "Known miner process name",
      "confidence": "high"
    }
  ],
  "networkConnections": [
    {
      "protocol": "TCP",
      "local": "192.168.1.100:52341",
      "remote": "pool.supportxmr.com:3333",
      "state": "ESTABLISHED",
      "pid": 9876,
      "reason": "Connection to known mining pool",
      "confidence": "high"
    }
  ],
  "highCpuProcesses": [],
  "minerDetected": true,
  "confidence": "high",
  "timestamp": 1698765432000
}
```

### Statistics & Monitoring

#### Get Monitoring Statistics
```http
GET /api/monitoring/statistics
```

**Response:**
```json
{
  "success": true,
  "statistics": {
    "registryMonitoring": {
      "active": true,
      "changesDetected": 25,
      "suspiciousChanges": 3,
      "monitoredKeys": 7
    },
    "memoryScanning": {
      "active": true,
      "suspiciousProcesses": 5,
      "criticalThreats": 2
    },
    "threatDetection": {
      "totalThreats": 10,
      "byType": {
        "registry": 3,
        "memory": 5,
        "rootkit": 1,
        "cryptominer": 1
      }
    },
    "platform": "win32"
  }
}
```

#### Get Detected Threats
```http
GET /api/monitoring/threats?limit=50
```

**Response:**
```json
{
  "success": true,
  "threats": [
    {
      "type": "cryptominer",
      "name": "xmrig.exe",
      "pid": 9876,
      "severity": "critical",
      "detectedAt": 1698765432000,
      "reason": "Known cryptocurrency miner"
    }
  ],
  "total": 10,
  "critical": 2,
  "high": 5
}
```

#### Clear Threat History
```http
DELETE /api/monitoring/threats
```

**Response:**
```json
{
  "success": true,
  "cleared": 10
}
```

---

## 💡 Usage Examples

### PowerShell: Start Comprehensive Monitoring

```powershell
# Start registry monitoring
$reg = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/registry/start" -Method Post
Write-Host "Registry monitoring: $($reg.message)"

# Start memory scanning
$mem = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/memory/start" -Method Post
Write-Host "Memory scanning: $($mem.message)"

# Get initial statistics
$stats = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/statistics"
Write-Host "Monitoring active: Registry=$($stats.statistics.registryMonitoring.active), Memory=$($stats.statistics.memoryScanning.active)"
```

### PowerShell: Scan for Threats

```powershell
# Scan for rootkits
$rootkit = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/rootkit/scan" -Method Post
if ($rootkit.rootkitDetected) {
    Write-Host "⚠️ Rootkit detected! Threat level: $($rootkit.threatLevel)" -ForegroundColor Red
    Write-Host "Hidden processes: $($rootkit.hiddenProcesses.Count)"
    Write-Host "Suspicious drivers: $($rootkit.suspiciousDrivers.Count)"
} else {
    Write-Host "✅ No rootkits detected" -ForegroundColor Green
}

# Scan for crypto miners
$miner = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/cryptominer/scan" -Method Post
if ($miner.minerDetected) {
    Write-Host "⚠️ Cryptocurrency miner detected! Confidence: $($miner.confidence)" -ForegroundColor Red
    $miner.suspiciousProcesses | Format-Table -Property name, pid, cpu, reason
} else {
    Write-Host "✅ No crypto miners detected" -ForegroundColor Green
}
```

### PowerShell: Validate Certificate

```powershell
$certCheck = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/certificate/validate" `
    -Method Post `
    -Body '{"filePath":"C:\\Windows\\System32\\notepad.exe"}' `
    -ContentType "application/json"

if ($certCheck.signed) {
    Write-Host "✅ File is digitally signed" -ForegroundColor Green
    Write-Host "Publisher: $($certCheck.signer.subject)"
    Write-Host "Trust: $($certCheck.trust)"
} else {
    Write-Host "⚠️ File is not signed or signature is invalid" -ForegroundColor Yellow
}
```

### PowerShell: Monitor Registry Changes

```powershell
# Start monitoring
Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/registry/start" -Method Post

# Wait for some time
Start-Sleep -Seconds 60

# Get changes
$changes = Invoke-RestMethod -Uri "http://localhost:8080/api/monitoring/registry/changes?limit=50"
Write-Host "Total changes: $($changes.total)"
Write-Host "Suspicious changes: $($changes.suspicious)"

$changes.changes | Where-Object { $_.suspicious } | Format-Table -Property timestamp, key, action, severity
```

---

## 🔒 Security Considerations

### Registry Monitoring
- Requires administrator privileges on Windows
- Monitors only critical keys (can be extended)
- Detects most common persistence mechanisms
- May generate false positives for legitimate software installations

### Certificate Validation
- Windows only (uses PowerShell Get-AuthenticodeSignature)
- Validates against Windows Certificate Store
- Checks certificate chain and revocation status
- Unsigned files are not necessarily malicious

### Memory Scanner
- Monitors CPU usage for miner detection
- Compares process enumeration methods
- May impact system performance during scans
- 30-second scan interval by default

### Rootkit Detection
- Uses multiple detection methods for accuracy
- Compares different process enumeration techniques
- Checks for driver anomalies
- Deep system scans may take several minutes

### Crypto Miner Detection
- Identifies known miner signatures
- Monitors network connections to mining pools
- Tracks sustained high CPU usage
- Can detect both known and unknown miners

---

## ⚙️ Configuration

### Scan Intervals

**Registry Monitoring:** 10 seconds (configurable)
**Memory Scanning:** 30 seconds (configurable)

### CPU Threshold for Miner Detection
Default: 80% sustained CPU usage

### Known Miner Process Names
The system recognizes these common miners:
- XMRig, Ethminer, CGMiner, BFGMiner, CCMiner
- PhoenixMiner, Claymore, Nanominer, LolMiner
- NBMiner, GMiner, T-Rex, TeamRedMiner, SRBMiner, WildRig

---

## 🛡️ Best Practices

1. **Start Monitoring on System Boot**
   - Enable registry and memory monitoring automatically
   - Run initial rootkit and miner scans after startup

2. **Review Alerts Regularly**
   - Check suspicious registry changes daily
   - Investigate high CPU processes
   - Validate unsigned executables

3. **Whitelist Legitimate Software**
   - Add known-good processes to exclusions
   - Document legitimate high-CPU applications
   - Maintain certificate whitelist for trusted publishers

4. **Scheduled Deep Scans**
   - Run rootkit scans weekly
   - Perform crypto miner scans daily
   - Validate certificates on new installations

5. **Monitor Threat Statistics**
   - Track detection trends over time
   - Identify repeat offenders
   - Adjust sensitivity based on environment

---

## 📊 Performance Impact

| Feature | CPU Usage | Memory Usage | Disk I/O |
|---------|-----------|--------------|----------|
| Registry Monitoring | <1% | ~10MB | Low |
| Certificate Validation | <2% | ~5MB | Low |
| Memory Scanner | 2-5% | ~20MB | None |
| Rootkit Detection | 5-10% | ~30MB | Medium |
| Crypto Miner Detection | 1-3% | ~15MB | Low |

---

## 🐛 Troubleshooting

### Registry Monitoring Not Starting
- **Cause:** Not running as administrator
- **Solution:** Run backend with elevated privileges

### Certificate Validation Fails
- **Cause:** PowerShell execution policy
- **Solution:** `Set-ExecutionPolicy RemoteSigned`

### High Memory Scanner False Positives
- **Cause:** Legitimate high-CPU applications
- **Solution:** Adjust CPU threshold or add to whitelist

### Rootkit Scan Taking Too Long
- **Cause:** Large number of processes/files
- **Solution:** Normal for deep scans, wait for completion

### Crypto Miner Detection Missing Known Miners
- **Cause:** New or obfuscated miner names
- **Solution:** Update miner signature database

---

## 🔄 Event Notifications

The Advanced Monitoring system emits real-time events:

```javascript
// Registry monitoring events
advancedMonitoring.on('registryMonitoringStarted', () => {});
advancedMonitoring.on('registryMonitoringStopped', () => {});
advancedMonitoring.on('registryChangesDetected', (changes) => {});
advancedMonitoring.on('suspiciousRegistryChange', (change) => {});

// Memory scanning events
advancedMonitoring.on('memoryScanningStarted', () => {});
advancedMonitoring.on('memoryScanningStopped', () => {});
advancedMonitoring.on('suspiciousProcessesDetected', (processes) => {});

// Threat detection events
advancedMonitoring.on('rootkitDetected', (detection) => {});
advancedMonitoring.on('cryptoMinerDetected', (detection) => {});
```

---

## 📞 Support

For advanced monitoring issues:
- Review event logs in the backend console
- Check permissions (administrator required)
- Verify platform compatibility (Windows for registry/certificates)
- Consult threat detection statistics

---

**Advanced Protection - Deep System Monitoring! 🔍**
