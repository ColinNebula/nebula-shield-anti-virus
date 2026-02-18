# 🛡️ Mobile Protection Features - Quick Reference Card

## 📞 Service Import Statements

```typescript
import { MalwareScannerService } from '../services/MalwareScannerService';
import { AntiTheftService } from '../services/AntiTheftService';
import { SMSCallProtectionService } from '../services/SMSCallProtectionService';
```

---

## 🦠 Malware Scanner - Common Tasks

### Quick Scan
```typescript
const result = await MalwareScannerService.quickScan(
  (progress, message) => console.log(`${progress}%: ${message}`)
);
```

### Check App Security
```typescript
const report = await MalwareScannerService.getAppSecurityReport('com.example.app');
console.log(`Security Score: ${report.securityScore}/100`);
```

### Quarantine Threat
```typescript
await MalwareScannerService.quarantineThreat(threatId);
```

### Get Scan History
```typescript
const history = await MalwareScannerService.getScanHistory(10);
```

---

## 📍 Anti-Theft - Common Tasks

### Get Location
```typescript
const location = await AntiTheftService.getCurrentLocation();
console.log(`Lat: ${location.latitude}, Lng: ${location.longitude}`);
```

### Remote Lock
```typescript
await AntiTheftService.remoteLock('Device is locked for security');
```

### Sound Alarm
```typescript
await AntiTheftService.soundAlarm();
```

### Check SIM Change
```typescript
const changed = await AntiTheftService.checkSIMChange();
if (changed) console.log('SIM card changed - possible theft!');
```

### Add Trusted Contact
```typescript
await AntiTheftService.addTrustedContact({
  name: 'John Doe',
  phone: '+1-555-1234',
  email: 'john@example.com',
  relationship: 'Family'
});
```

---

## 📱 SMS/Call Protection - Common Tasks

### Check if Number is Spam
```typescript
const check = await SMSCallProtectionService.isSpamNumber('+1-800-555-1234');
if (check.isSpam) {
  console.log(`Spam! Risk: ${check.riskScore}/100`);
}
```

### Check SMS for Phishing
```typescript
const sms = await SMSCallProtectionService.checkSMS(
  '+1-555-0000',
  'URGENT: Verify your account now!'
);
if (sms.isPhishing) {
  console.log(`Phishing detected! Threat: ${sms.threatType}`);
}
```

### Block Number
```typescript
await SMSCallProtectionService.blockNumber('+1-555-SPAM', 'spam', 'Telemarketer');
```

### Get Protection Stats
```typescript
const stats = await SMSCallProtectionService.getProtectionStats();
console.log(`Blocked today: ${stats.todayBlocked}`);
```

### Report Spam
```typescript
await SMSCallProtectionService.reportSpam(
  '+1-555-SPAM',
  'sms',
  'phishing',
  'Fake bank message'
);
```

---

## 🎯 One-Liner Checks

```typescript
// Is device being scanned?
const isScanning = MalwareScannerService.isScanInProgress();

// Get malware database version
const dbInfo = await MalwareScannerService.getDatabaseInfo();
console.log(`DB Version: ${dbInfo.version}, ${dbInfo.signatures} signatures`);

// Get device status
const status = await AntiTheftService.getDeviceStatus();
console.log(`Battery: ${status.batteryLevel}%, Last seen: ${status.lastSeen}`);

// Format phone number
const formatted = SMSCallProtectionService.formatPhoneNumber('5551234567');
// Output: (555) 123-4567
```

---

## 🔧 Settings Management

### Malware Scanner Settings
```typescript
const settings = await MalwareScannerService.getRealtimeSettings();
settings.enabled = true;
settings.scanNewApps = true;
await MalwareScannerService.updateRealtimeSettings(settings);
```

### Anti-Theft Settings
```typescript
const settings = await AntiTheftService.getSettings();
settings.lockOnTheft = true;
settings.trackLocation = true;
settings.maxFailedAttempts = 10;
await AntiTheftService.updateSettings(settings);
```

### SMS/Call Protection Settings
```typescript
const settings = await SMSCallProtectionService.getSettings();
settings.blockSpamCalls = true;
settings.detectPhishing = true;
await SMSCallProtectionService.updateSettings(settings);
```

---

## 📊 Statistics & History

```typescript
// Scan history
const scans = await MalwareScannerService.getScanHistory(10);

// Quarantine items
const quarantine = await MalwareScannerService.getQuarantineItems();

// Location history
const locations = await AntiTheftService.getLocationHistory(50);

// Theft alerts
const alerts = await AntiTheftService.getTheftAlerts(20);

// Blocked numbers
const blocked = await SMSCallProtectionService.getBlockedNumbers();

// Blocked messages
const messages = await SMSCallProtectionService.getBlockedMessages();
```

---

## 🎨 UI Helper Functions

```typescript
// Get threat color
const color = MalwareScannerService.getThreatColor('critical'); // '#d32f2f'

// Get threat icon
const icon = MalwareScannerService.getThreatIcon('malware'); // 'virus'

// Get risk color (SMS)
const color = SMSCallProtectionService.getRiskColor(85); // '#f44336'

// Format duration
const duration = '3m 45s'; // Custom formatting needed
```

---

## ⚡ Real-time Monitoring

```typescript
// Start network monitoring (from existing service)
NetworkTrafficService.startMonitoring((data) => {
  console.log(`Connections: ${data.connections.length}`);
});

// Stop monitoring
NetworkTrafficService.stopMonitoring();

// Check if threat database is up to date
const dbInfo = await MalwareScannerService.getDatabaseInfo();
if (!dbInfo.isUpToDate) {
  await MalwareScannerService.updateDatabase((progress) => {
    console.log(`Updating: ${progress}%`);
  });
}
```

---

## 🚨 Error Handling

```typescript
try {
  const result = await MalwareScannerService.quickScan();
} catch (error) {
  if (error.message.includes('already in progress')) {
    console.log('Scan already running');
  } else {
    console.error('Scan failed:', error);
  }
}

try {
  const location = await AntiTheftService.getCurrentLocation();
} catch (error) {
  if (error.message.includes('permission')) {
    console.log('Location permission denied');
  }
}
```

---

## 📝 Type Definitions

```typescript
// Scan result
interface ScanResult {
  scanId: string;
  threatsFound: number;
  filesScanned: number;
  appsScanned: number;
  threats: ThreatDetection[];
  scanType: 'quick' | 'full' | 'custom';
  status: 'completed' | 'in_progress' | 'failed' | 'cancelled';
}

// Threat detection
interface ThreatDetection {
  id: string;
  type: 'malware' | 'spyware' | 'adware' | 'trojan' | 'ransomware';
  severity: 'critical' | 'high' | 'medium' | 'low';
  name: string;
  confidence: number; // 0-100
  actions: ThreatAction[];
}

// Device location
interface DeviceLocation {
  latitude: number;
  longitude: number;
  accuracy: number;
  address?: string;
  timestamp: string;
}

// SMS message check
interface SMSMessage {
  from: string;
  body: string;
  isSpam: boolean;
  isPhishing: boolean;
  riskScore: number; // 0-100
  threatType?: 'phishing' | 'smishing' | 'spam' | 'scam';
}
```

---

## 🔗 Related Services (Existing)

```typescript
// WiFi Security
import { WiFiSecurityService } from '../services/WiFiSecurityService';
await WiFiSecurityService.scanWiFiNetworks();

// Web Protection
import { WebProtectionService } from '../services/WebProtectionService';
await WebProtectionService.checkURL(url);

// Privacy Audit
import { PrivacyAuditService } from '../services/PrivacyAuditService';
await PrivacyAuditService.getPrivacyScore();

// Network Traffic
import { NetworkTrafficService } from '../services/NetworkTrafficService';
await NetworkTrafficService.getActiveConnections();
```

---

## 📚 Documentation Files

- **`REAL_MOBILE_PROTECTION_FEATURES.md`** - Complete guide (500+ lines)
- **`TESTING_MOBILE_PROTECTION.md`** - Testing guide (400+ lines)
- **`IMPLEMENTATION_SUMMARY.md`** - Overview
- **`MOBILE_PROTECTION_QUICK_REFERENCE.md`** - This file!

---

## 🎯 Common Use Cases

### Daily Security Check
```typescript
const scan = await MalwareScannerService.quickScan();
const location = await AntiTheftService.getCurrentLocation();
const stats = await SMSCallProtectionService.getProtectionStats();
```

### Handle Lost Device
```typescript
await AntiTheftService.remoteLock('Lost device - call 555-1234');
await AntiTheftService.soundAlarm();
const location = await AntiTheftService.getCurrentLocation();
```

### Check Suspicious Message
```typescript
const sms = await SMSCallProtectionService.checkSMS(from, body);
if (sms.isPhishing) {
  await SMSCallProtectionService.reportSpam(from, 'sms', 'phishing');
}
```

---

## ⚙️ Initialization

```typescript
// In App.tsx or main component
useEffect(() => {
  // Initialize anti-theft
  AntiTheftService.initialize();
  
  // Update malware database
  MalwareScannerService.updateDatabase();
  
  // Update spam database
  SMSCallProtectionService.updateDatabase();
}, []);
```

---

## 🎉 Quick Win Examples

### Show Security Score
```typescript
const scan = await MalwareScannerService.quickScan();
const score = 100 - (scan.threatsFound * 10);
Alert.alert('Security Score', `${score}/100`);
```

### Track Device Movement
```typescript
const location = await AntiTheftService.getCurrentLocation();
const history = await AntiTheftService.getLocationHistory(2);
if (history.length >= 2) {
  const distance = calculateDistance(history[0].location, history[1].location);
  console.log(`Moved ${distance}m`);
}
```

### Block All Spam Today
```typescript
const messages = await SMSCallProtectionService.getBlockedMessages();
const today = messages.filter(m => 
  new Date(m.timestamp).toDateString() === new Date().toDateString()
);
console.log(`Blocked ${today.length} spam messages today!`);
```

---

**Keep this card handy for quick reference! 🚀**
