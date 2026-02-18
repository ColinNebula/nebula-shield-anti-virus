# Enhanced Real-Time Protection - Quick Reference

## Quick Start

```javascript
import realtimeMonitor from './services/realtimeMonitor';

// Start all protection
realtimeMonitor.start();

// Subscribe to events
realtimeMonitor.subscribe((event, data) => {
  console.log(event, data);
});
```

## Modules Overview

| Module | Purpose | CPU | Memory | Detection Speed |
|--------|---------|-----|--------|-----------------|
| Ransomware Detector | Mass encryption detection | <1% | 5MB | <100ms |
| File Monitor Bridge | C++ backend integration | <1% | 500KB | <10ms |
| Memory Scanner | Code injection detection | 5-10% | 10MB | 30s interval |
| Process Tree Monitor | Privilege escalation | <2% | 3MB | <50ms |
| Registry Monitor | Persistence detection | <1% | 2MB | 5s interval |

## Key Events

```javascript
// Ransomware detected
'ransomware_detected' → { threat, severity: 'critical' }

// Memory threat
'memory_threat_detected' → { detection, severity: 'high' }

// Process threat
'process_threat_detected' → { process, threats }

// Registry threat
'registry_threat_detected' → { path, change, threat }

// File event
'file_monitor_event' → { file_path, event_type }
```

## Common Tasks

### Get Statistics
```javascript
const status = realtimeMonitor.getStatus();
const enhanced = status.enhancedProtection;

console.log('Ransomware threats:', enhanced.ransomware.threatsDetected);
console.log('Memory threats:', enhanced.memoryScanner.threatsDetected);
console.log('Process threats:', enhanced.processTree.suspiciousSpawns);
console.log('Registry changes:', enhanced.registry.changesDetected);
```

### Configure Modules
```javascript
import ransomwareDetector from './services/ransomwareDetector';
import memoryScanner from './services/memoryScanner';
import registryMonitor from './services/registryMonitor';

// Adjust ransomware sensitivity
ransomwareDetector.updateConfig({
  massEncryptionThreshold: 30  // Increase threshold
});

// Change memory scan interval
memoryScanner.updateConfig({
  scanInterval: 60000  // 60 seconds
});

// Adjust registry check frequency
registryMonitor.updateConfig({
  checkInterval: 10000  // 10 seconds
});
```

### Handle Threats
```javascript
window.addEventListener('ransomware_detected', (event) => {
  const { threat, operation } = event.detail;
  
  // Alert user
  alert(`RANSOMWARE DETECTED: ${threat.type}`);
  
  // Block process
  if (operation.processId) {
    // Kill process via API
  }
  
  // Quarantine affected files
  threat.affectedFiles?.forEach(file => {
    // Quarantine file
  });
});
```

### File Monitor Integration
```javascript
import fileMonitorBridge from './services/fileMonitorBridge';

// Connect to C++ backend
fileMonitorBridge.connect(8081);

// Listen for file events
fileMonitorBridge.on('file_event', (event) => {
  console.log(`File ${event.event_type}: ${event.file_path}`);
});

// Control monitoring
fileMonitorBridge.startMonitoring(['C:\\Users']);
fileMonitorBridge.addWatchDirectory('C:\\Program Files');
fileMonitorBridge.stopMonitoring();
```

## Threat Severity Levels

| Level | Score | Description | Action |
|-------|-------|-------------|--------|
| Critical | ≥0.9 | Confirmed malware | Block & quarantine |
| High | 0.7-0.89 | Likely threat | Alert & analyze |
| Medium | 0.5-0.69 | Suspicious | Log & monitor |
| Low | <0.5 | Benign | Log only |

## Detection Patterns

### Ransomware
- ✓ Mass file encryption (20+ files in 30s)
- ✓ Suspicious extensions (.encrypted, .locked)
- ✓ Ransom note creation
- ✓ Rapid directory spread (3+ dirs)

### Memory Threats
- ✓ DLL injection (VirtualAllocEx + WriteProcessMemory)
- ✓ Process hollowing (NtUnmapViewOfSection)
- ✓ Shellcode (NOP sleds, JMP/CALL patterns)
- ✓ RWX memory pages
- ✓ API hooking

### Process Threats
- ✓ Suspicious spawns (PowerShell from Word)
- ✓ Privilege escalation
- ✓ Rapid spawning (5+ in 5s)
- ✓ Suspicious chains (3+ levels)

### Registry Threats
- ✓ Autorun persistence
- ✓ Service creation
- ✓ Policy modifications
- ✓ Security setting changes
- ✓ Debugger hijacking (IFEO)
- ✓ DLL injection (AppInit_DLLs)

## Performance Tuning

### Low-Resource Mode
```javascript
// Disable memory scanner (most CPU intensive)
memoryScanner.stop();

// Reduce registry check frequency
registryMonitor.updateConfig({ checkInterval: 30000 });

// Increase ransomware thresholds
ransomwareDetector.updateConfig({
  massEncryptionThreshold: 50
});
```

### High-Security Mode
```javascript
// Enable all features
memoryScanner.updateConfig({
  scanInterval: 15000,  // Scan every 15s
  enableHeuristics: true,
  deepScanExecutable: true
});

// Reduce thresholds
ransomwareDetector.updateConfig({
  massEncryptionThreshold: 10,
  rapidModificationThreshold: 5
});

// Increase registry monitoring
registryMonitor.updateConfig({
  checkInterval: 2000  // Check every 2s
});
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| High CPU | Reduce memory scan frequency |
| Many false positives | Increase detection thresholds |
| Missing events | Check event listeners registered |
| File monitor disconnected | Verify C++ backend running |
| No registry events | Run with admin privileges |

## API Reference

### realtimeMonitor
```javascript
start()                          // Start all monitoring
stop()                           // Stop all monitoring
subscribe(callback)              // Subscribe to events
getStatus()                      // Get status & stats
refresh()                        // Manual refresh
registerProcess(processInfo)     // Register process
getProcessTree(pid)             // Get process tree
```

### ransomwareDetector
```javascript
start()                          // Start detection
stop()                           // Stop detection
analyzeFileEvent(event)         // Analyze file event
getStatistics()                  // Get stats
getRecentThreats(limit)         // Get recent threats
markFalsePositive(threatId)     // Mark false positive
updateConfig(config)            // Update config
```

### fileMonitorBridge
```javascript
connect(port)                    // Connect to backend
disconnect()                     // Disconnect
on(event, callback)             // Subscribe to event
startMonitoring(directories)    // Start monitoring
stopMonitoring()                // Stop monitoring
addWatchDirectory(dir)          // Add directory
requestStatistics()             // Request stats
```

### memoryScanner
```javascript
start()                          // Start scanning
stop()                           // Stop scanning
getStatistics()                  // Get stats
getRecentThreats(limit)         // Get recent threats
updateConfig(config)            // Update config
clearCache()                    // Clear cache
```

### processTreeMonitor
```javascript
start()                          // Start monitoring
stop()                           // Stop monitoring
registerProcess(info)           // Register process
getProcessTree(pid)             // Get process tree
getStatistics()                  // Get stats
getSuspiciousPatterns(limit)    // Get patterns
getPrivilegeEscalations(limit)  // Get escalations
```

### registryMonitor
```javascript
start()                          // Start monitoring
stop()                           // Stop monitoring
addMonitoredPath(path, category)// Add custom path
getStatistics()                  // Get stats
getRecentChanges(limit)         // Get changes
getPersistenceAttempts(limit)   // Get persistence
resetBaseline()                 // Reset baseline
```

## Example: Complete Integration

```javascript
import realtimeMonitor from './services/realtimeMonitor';

class ThreatMonitor extends React.Component {
  componentDidMount() {
    // Start monitoring
    realtimeMonitor.start();
    
    // Subscribe to events
    this.unsubscribe = realtimeMonitor.subscribe((event, data) => {
      this.handleEvent(event, data);
    });
  }
  
  componentWillUnmount() {
    // Cleanup
    this.unsubscribe();
    realtimeMonitor.stop();
  }
  
  handleEvent(event, data) {
    switch(event) {
      case 'ransomware_detected':
        this.showCriticalAlert('Ransomware', data);
        break;
      case 'memory_threat_detected':
        this.showAlert('Memory Threat', data);
        break;
      case 'process_threat_detected':
        this.showAlert('Process Threat', data);
        break;
      case 'registry_threat_detected':
        this.showAlert('Registry Threat', data);
        break;
    }
  }
  
  render() {
    const status = realtimeMonitor.getStatus();
    const enhanced = status.enhancedProtection;
    
    return (
      <div>
        <h2>Real-Time Protection</h2>
        <div>Ransomware: {enhanced.ransomware.threatsDetected}</div>
        <div>Memory: {enhanced.memoryScanner.threatsDetected}</div>
        <div>Process: {enhanced.processTree.suspiciousSpawns}</div>
        <div>Registry: {enhanced.registry.changesDetected}</div>
      </div>
    );
  }
}
```

---

**Nebula Shield Enhanced Protection** | Created by Colin Nebula
