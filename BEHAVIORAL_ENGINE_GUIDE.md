# 🔍 Behavioral Engine - Process Monitoring

## Overview

The **Behavioral Analysis Engine** is an advanced real-time process monitoring system that detects suspicious and malicious activity by analyzing running processes and their behaviors. Unlike signature-based detection, behavioral analysis identifies threats based on what they do rather than what they are.

## 🎯 Key Features

### Real-Time Monitoring
- Continuous process scanning every 5 seconds
- Instant threat detection and alerting
- Live statistics dashboard
- Process tree visualization
- Parent-child relationship analysis

### Behavioral Detection
- **Code Injection**: Remote thread creation, memory writes, DLL injection
- **Privilege Escalation**: Token manipulation, UAC bypass, debug privileges
- **Persistence Mechanisms**: Registry modifications, scheduled tasks, service creation
- **Network Anomalies**: C2 communication, DNS tunneling, reverse shells
- **File Manipulation**: Mass encryption (ransomware), shadow copy deletion
- **Process Behavior**: Process hollowing, parent spoofing, suspicious command lines
- **Anti-Analysis**: VM detection, debugger checks, sandbox evasion

### Heuristic Scoring System
Each process receives a **suspicion score** (0-100) based on:
- Process name and path analysis
- Parent-child relationships
- Resource usage patterns
- Command line arguments
- Known malicious behaviors

**Score Thresholds:**
- **0-69**: Clean (normal behavior)
- **70-79**: Medium risk (suspicious)
- **80-89**: High risk (very suspicious)
- **90-100**: Critical (likely malicious - auto-blocked)

## 📊 How It Works

### Detection Flow

```
┌─────────────────────┐
│  Start Monitoring   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Get Process List   │◄─── Every 5 seconds
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Analyze Process    │
│  ─────────────────  │
│  • Name/Path        │
│  • Parent Process   │
│  • Resource Usage   │
│  • Command Line     │
│  • Known Patterns   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Calculate Suspicion │
│      Score          │
└──────────┬──────────┘
           │
           ▼
     ┌────┴────┐
     │ Score?  │
     └────┬────┘
          │
    ┌─────┼─────┐
    │           │
  < 70        ≥ 70
    │           │
    ▼           ▼
 Clean    ┌──────────┐
          │  Alert   │
          │  User    │
          └─────┬────┘
                │
              ≥ 90?
                │
                ▼
          ┌──────────┐
          │Auto-Block│
          └──────────┘
```

### Behavioral Patterns

#### 1. Code Injection Detection
```javascript
// Detects:
- CreateRemoteThread (weight: 30)
- WriteProcessMemory (weight: 25)
- VirtualAllocEx (weight: 25)
- SetWindowsHookEx (weight: 20)
- QueueUserAPC (weight: 20)
```

**Example:** Malware injecting code into legitimate processes to evade detection.

#### 2. Privilege Escalation
```javascript
// Detects:
- SeDebugPrivilege (weight: 35)
- TakeOwnershipPrivilege (weight: 30)
- ImpersonatePrivilege (weight: 30)
- UAC_Bypass (weight: 40)
- TokenManipulation (weight: 35)
```

**Example:** Trojan attempting to gain SYSTEM-level privileges.

#### 3. Persistence Mechanisms
```javascript
// Detects:
- Registry Run keys (weight: 25)
- Startup folder modifications (weight: 20)
- Scheduled task creation (weight: 25)
- Windows service creation (weight: 30)
- WMI event subscriptions (weight: 35)
```

**Example:** Ransomware ensuring it runs after system reboot.

#### 4. Network Anomalies
```javascript
// Detects:
- Unusual port connections (weight: 20)
- High connection rate (weight: 25)
- C2 server communication (weight: 40)
- DNS tunneling (weight: 35)
- Reverse shell connections (weight: 45)
```

**Example:** Backdoor communicating with command & control server.

#### 5. File System Manipulation
```javascript
// Detects:
- Mass file encryption (weight: 50) ← RANSOMWARE
- System file modification (weight: 40)
- Shadow copy deletion (weight: 45)
- Mass file deletion (weight: 35)
- File name obfuscation (weight: 25)
```

**Example:** Ransomware encrypting user files.

#### 6. Anti-Analysis Techniques
```javascript
// Detects:
- VM detection (weight: 15)
- Debugger checks (weight: 20)
- Sandbox evasion (weight: 25)
- Time-based evasion (weight: 20)
- AV process detection (weight: 15)
```

**Example:** Sophisticated malware checking if it's in a security researcher's VM.

## 🚀 Usage

### Starting the Monitor

```javascript
import behavioralEngine from './services/behavioralEngine';

// Start monitoring
await behavioralEngine.startMonitoring();

// Listen for events
behavioralEngine.on('suspiciousProcess', (alert) => {
  console.log('Suspicious process detected:', alert);
});

behavioralEngine.on('processBlocked', (data) => {
  console.log('Process blocked:', data);
});
```

### Configuration

```javascript
behavioralEngine.configure({
  enabled: true,
  scanInterval: 5000,              // Scan every 5 seconds
  suspicionThreshold: 70,           // Alert when score ≥ 70
  maxProcessHistory: 1000,          // Keep 1000 historical records
  enableProcessTree: true,          // Analyze parent-child relationships
  enableNetworkMonitoring: true,    // Monitor network activity
  enableFileMonitoring: true,       // Monitor file operations
  enableRegistryMonitoring: true,   // Monitor registry changes
  enableMemoryMonitoring: true,     // Monitor memory operations
  whitelistedProcesses: [           // Trusted processes
    'system',
    'csrss.exe',
    'services.exe',
    'explorer.exe'
  ]
});
```

### Getting Process Information

```javascript
// Get status
const status = behavioralEngine.getStatus();
console.log('Monitoring:', status.state.isMonitoring);
console.log('Processes:', status.state.processCount);
console.log('Suspicious:', status.state.suspiciousCount);

// Get specific process info
const processInfo = behavioralEngine.getProcessInfo(1234);
console.log('Score:', processInfo.suspicionScore);
console.log('Flags:', processInfo.flags);

// Get suspicious processes
const suspicious = behavioralEngine.getSuspiciousProcesses();

// Get process tree
const tree = behavioralEngine.getProcessTree(1234);

// Get statistics
const stats = behavioralEngine.getStats();
console.log('Total scanned:', stats.totalProcessesScanned);
console.log('Threats blocked:', stats.threatsBlocked);
```

### Manual Actions

```javascript
// Block a process manually
await behavioralEngine.blockProcess({
  pid: 1234,
  name: 'malware.exe',
  suspicionScore: 95
});

// Clear alerts
const alerts = behavioralEngine.getAlerts();
behavioralEngine.clearAlert(alerts[0].id);

// Export data for analysis
const data = behavioralEngine.exportData();
// Save to file or send to SIEM
```

## 🎨 UI Component

The `ProcessMonitor` component provides a rich dashboard:

### Features
- **Real-time process list** with sortable columns
- **Statistics dashboard** showing key metrics
- **Alert panel** for immediate threat visibility
- **Process details panel** with full analysis
- **Process tree visualization** showing parent-child relationships
- **Filtering and sorting** options
- **One-click blocking** for suspicious processes
- **Data export** for forensic analysis

### Integration

```javascript
import ProcessMonitor from './components/ProcessMonitor';

function App() {
  return (
    <div>
      <ProcessMonitor />
    </div>
  );
}
```

## 📈 Statistics Tracked

| Metric | Description |
|--------|-------------|
| **Processes Monitored** | Total number of active processes |
| **Suspicious Detected** | Processes with score ≥ 70 |
| **Threats Blocked** | Auto-blocked critical threats |
| **Active Alerts** | Unresolved security alerts |
| **Total Scanned** | Cumulative processes analyzed |
| **Uptime** | Time since monitoring started |
| **Average Suspicion** | Mean score of all processes |
| **Last Scan** | Timestamp of most recent scan |

## 🛡️ Detection Examples

### Example 1: Suspicious PowerShell
```
Process: powershell.exe
PID: 3456
Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent: explorer.exe (unusual)
CommandLine: powershell.exe -enc JABzAD