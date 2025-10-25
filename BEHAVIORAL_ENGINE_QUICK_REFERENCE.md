# 🔍 Behavioral Engine - Quick Reference

## Installation & Setup

### 1. Import the Service
```javascript
import behavioralEngine from './services/behavioralEngine';
```

### 2. Start Monitoring
```javascript
await behavioralEngine.startMonitoring();
```

### 3. Add UI Component (Optional)
```javascript
import ProcessMonitor from './components/ProcessMonitor';

// In your router or app:
<Route path="/process-monitor">
  <ProcessMonitor />
</Route>
```

## API Reference

### Core Methods

#### `startMonitoring()`
Start real-time process monitoring.
```javascript
await behavioralEngine.startMonitoring();
```

#### `stopMonitoring()`
Stop process monitoring.
```javascript
behavioralEngine.stopMonitoring();
```

#### `scanProcesses()`
Manually trigger a process scan.
```javascript
await behavioralEngine.scanProcesses();
```

#### `getProcessInfo(pid)`
Get detailed information about a specific process.
```javascript
const info = behavioralEngine.getProcessInfo(1234);
// Returns: { pid, name, path, suspicionScore, flags, behaviors, ... }
```

#### `getSuspiciousProcesses()`
Get all processes with suspicion score ≥ 70.
```javascript
const suspicious = behavioralEngine.getSuspiciousProcesses();
```

#### `getAlerts()`
Get all security alerts.
```javascript
const alerts = behavioralEngine.getAlerts();
```

#### `clearAlert(alertId)`
Mark an alert as resolved.
```javascript
behavioralEngine.clearAlert(alertId);
```

#### `blockProcess(analysis)`
Block a malicious process.
```javascript
await behavioralEngine.blockProcess({
  pid: 1234,
  name: 'malware.exe',
  suspicionScore: 95
});
```

#### `getProcessTree(pid)`
Get parent-child process hierarchy.
```javascript
const tree = behavioralEngine.getProcessTree(1234);
```

#### `getStatus()`
Get current monitoring status.
```javascript
const status = behavioralEngine.getStatus();
// Returns: { config, state, stats }
```

#### `getStats()`
Get monitoring statistics.
```javascript
const stats = behavioralEngine.getStats();
```

#### `configure(config)`
Update configuration.
```javascript
behavioralEngine.configure({
  scanInterval: 10000,
  suspicionThreshold: 80
});
```

#### `exportData()`
Export all data for analysis.
```javascript
const data = behavioralEngine.exportData();
// Save to file or send to SIEM
```

#### `clearData()`
Clear all cached data.
```javascript
behavioralEngine.clearData();
```

## Events

### `monitoringStarted`
Emitted when monitoring starts.
```javascript
behavioralEngine.on('monitoringStarted', () => {
  console.log('Monitoring started');
});
```

### `monitoringStopped`
Emitted when monitoring stops.
```javascript
behavioralEngine.on('monitoringStopped', () => {
  console.log('Monitoring stopped');
});
```

### `scanComplete`
Emitted after each process scan.
```javascript
behavioralEngine.on('scanComplete', (data) => {
  console.log('Scanned:', data.processCount);
  console.log('Suspicious:', data.suspicious);
});
```

### `suspiciousProcess`
Emitted when suspicious process detected (score ≥ 70).
```javascript
behavioralEngine.on('suspiciousProcess', (alert) => {
  console.log('Suspicious:', alert.process.name);
  console.log('Score:', alert.process.suspicionScore);
  console.log('Flags:', alert.process.flags);
});
```

### `processBlocked`
Emitted when process is blocked.
```javascript
behavioralEngine.on('processBlocked', (data) => {
  console.log('Blocked:', data.name);
  console.log('PID:', data.pid);
});
```

### `scanError`
Emitted when scan fails.
```javascript
behavioralEngine.on('scanError', (error) => {
  console.error('Scan error:', error);
});
```

## Configuration Options

```javascript
{
  enabled: true,                    // Enable/disable engine
  scanInterval: 5000,               // Scan interval in ms (default: 5s)
  suspicionThreshold: 70,           // Alert threshold (0-100)
  maxProcessHistory: 1000,          // Max historical records
  enableProcessTree: true,          // Analyze parent-child relationships
  enableNetworkMonitoring: true,    // Monitor network activity
  enableFileMonitoring: true,       // Monitor file operations
  enableRegistryMonitoring: true,   // Monitor registry changes
  enableMemoryMonitoring: true,     // Monitor memory operations
  whitelistedProcesses: [           // Trusted processes (no alerts)
    'system',
    'csrss.exe',
    'smss.exe',
    'services.exe',
    'svchost.exe',
    'lsass.exe',
    'winlogon.exe',
    'explorer.exe'
  ]
}
```

## Suspicion Score Levels

| Score | Severity | Color | Action |
|-------|----------|-------|--------|
| 0-69 | Low/Clean | Green | None |
| 70-79 | Medium | Orange | Alert user |
| 80-89 | High | Red | Alert + recommend block |
| 90-100 | Critical | Dark Red | Auto-block |

## Common Patterns

### Auto-Start Monitoring
```javascript
// In App.js or main component
useEffect(() => {
  behavioralEngine.startMonitoring();
  
  return () => {
    behavioralEngine.stopMonitoring();
  };
}, []);
```

### Handle Alerts in Real-Time
```javascript
useEffect(() => {
  const handleAlert = (alert) => {
    // Show notification
    showNotification({
      title: 'Suspicious Process',
      message: `${alert.process.name} detected`,
      severity: alert.severity
    });
    
    // Log to server
    logToServer(alert);
  };
  
  behavioralEngine.on('suspiciousProcess', handleAlert);
  
  return () => {
    behavioralEngine.removeListener('suspiciousProcess', handleAlert);
  };
}, []);
```

### Custom Whitelist
```javascript
// Add company-specific processes
behavioralEngine.configure({
  whitelistedProcesses: [
    ...behavioralEngine.config.whitelistedProcesses,
    'company-app.exe',
    'internal-tool.exe'
  ]
});
```

### Export for Forensics
```javascript
const exportForensicData = () => {
  const data = behavioralEngine.exportData();
  
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json'
  });
  
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensics-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
};
```

### Integration with Scanner
```javascript
import behavioralEngine from './services/behavioralEngine';
import enhancedScanner from './services/enhancedScanner';

// When behavioral engine detects threat
behavioralEngine.on('suspiciousProcess', async (alert) => {
  if (alert.process.path) {
    // Scan the executable
    const scanResult = await enhancedScanner.scanFile(alert.process.path);
    
    if (scanResult.infected) {
      // Block immediately
      await behavioralEngine.blockProcess(alert.process);
    }
  }
});
```

## Behavioral Patterns Detected

### Code Injection (Total Weight: 120)
- CreateRemoteThread: 30
- WriteProcessMemory: 25
- VirtualAllocEx: 25
- SetWindowsHookEx: 20
- QueueUserAPC: 20

### Privilege Escalation (Total Weight: 170)
- SeDebugPrivilege: 35
- TakeOwnershipPrivilege: 30
- ImpersonatePrivilege: 30
- UAC_Bypass: 40
- TokenManipulation: 35

### Persistence (Total Weight: 135)
- RunKey: 25
- StartupFolder: 20
- ScheduledTask: 25
- ServiceCreation: 30
- WMIPersistence: 35

### Network Anomalies (Total Weight: 165)
- UnusualPort: 20
- HighConnectionRate: 25
- C2Communication: 40
- DNSTunneling: 35
- ReverseShell: 45

### File Manipulation (Total Weight: 195)
- MassFileEncryption: 50 ⚠️ RANSOMWARE
- SystemFileModification: 40
- ShadowCopyDeletion: 45
- MassFileDeletion: 35
- FileObfuscation: 25

### Process Behavior (Total Weight: 160)
- HollowProcess: 40
- ParentSpoofing: 35
- UnusualParent: 30
- RapidProcessSpawn: 25
- SuspiciousCommandLine: 30

### Anti-Analysis (Total Weight: 95)
- VMDetection: 15
- DebuggerCheck: 20
- SandboxEvasion: 25
- TimeDelayEvasion: 20
- AVProcessCheck: 15

## Status Object Structure

```javascript
{
  config: {
    enabled: true,
    scanInterval: 5000,
    suspicionThreshold: 70,
    // ... other config
  },
  state: {
    isMonitoring: true,
    processCount: 45,
    suspiciousCount: 2,
    blockedCount: 1,
    alertCount: 2,
    lastScanTime: Date
  },
  stats: {
    totalProcessesScanned: 1250,
    suspiciousDetected: 15,
    threatsBlocked: 5,
    falsePositives: 2,
    averageSuspicionScore: 12.5,
    uptime: 3600000,  // ms
    currentProcesses: 45,
    lastScan: Date
  }
}
```

## Process Analysis Structure

```javascript
{
  pid: 1234,
  name: 'suspicious.exe',
  path: 'C:\\Users\\User\\AppData\\Local\\Temp\\suspicious.exe',
  parent: 1000,
  user: 'DESKTOP\\User',
  suspicionScore: 85,
  flags: [
    'Running from Temp