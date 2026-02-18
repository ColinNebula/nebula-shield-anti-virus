# 🌐 Nebula Shield Multi-Platform Features Guide

## Overview

Nebula Shield extends protection beyond your desktop with comprehensive multi-platform support including mobile apps, browser extensions, cross-platform compatibility, and cloud synchronization.

---

## 📱 Mobile Companion App

### Features

The React Native mobile app provides remote monitoring and control of your Nebula Shield protection:

- **Real-time Device Monitoring** - View protection status across all devices
- **Remote Scan Control** - Start, stop, and monitor scans from your phone
- **Threat Alerts** - Receive push notifications for detected threats
- **Quarantine Management** - Review and manage quarantined files remotely
- **Protection Statistics** - Track scans, threats, and protection metrics
- **Multi-device Support** - Manage multiple protected devices from one app

### Installation

#### iOS
```bash
cd mobile-app
npm install
npx pod-install
npm run ios
```

#### Android
```bash
cd mobile-app
npm install
npm run android
```

### Pairing Your Device

1. Open Nebula Shield on your computer
2. Go to Settings → Mobile App → Generate Pairing Code
3. Open the mobile app and tap "Add Device"
4. Enter the 6-digit pairing code
5. Device will appear in your mobile app dashboard

### API Integration

The mobile app communicates with the backend via REST APIs:

#### Get All Devices
```javascript
GET /api/mobile/devices

Response:
{
  "success": true,
  "devices": [
    {
      "id": "device-abc123",
      "name": "My MacBook Pro",
      "platform": "darwin",
      "status": "protected",
      "lastSeen": 1698765432000,
      "filesScanned": 125000,
      "threatsBlocked": 43
    }
  ]
}
```

#### Start Remote Scan
```javascript
POST /api/mobile/devices/:id/scan
Body: { "scanType": "quick" | "full" }

Response:
{
  "success": true,
  "scanId": "scan-1698765432000",
  "scanType": "quick",
  "startedAt": "2025-10-31T12:00:00Z"
}
```

#### Get Scan Status
```javascript
GET /api/mobile/devices/:id/scan/status

Response:
{
  "success": true,
  "scanning": true,
  "scanProgress": {
    "filesScanned": 1250,
    "totalFiles": 5000,
    "progress": 25,
    "currentFile": "/Users/example/Documents/file.pdf"
  }
}
```

### Push Notifications

Configure push notifications in the app settings:

```javascript
// notifications.js in mobile app
import PushNotification from 'react-native-push-notification';

PushNotification.configure({
  onNotification: function (notification) {
    console.log('NOTIFICATION:', notification);
  },
  permissions: {
    alert: true,
    badge: true,
    sound: true,
  },
  requestPermissions: true,
});
```

---

## 🌐 Browser Extension

### Features

Real-time web protection for Chrome and Firefox:

- **Phishing Detection** - AI-powered phishing site identification
- **Malware Blocking** - Block access to known malware distribution sites
- **URL Scanning** - Real-time URL reputation checking
- **Safe Browsing** - Warn before visiting dangerous sites
- **Form Protection** - Prevent credential theft on malicious sites
- **Community Reports** - Report phishing and false positives

### Installation

#### Chrome
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `browser-extension` folder
5. Extension icon appears in toolbar

#### Firefox
1. Open Firefox and go to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Navigate to `browser-extension` folder
4. Select `manifest.json`

### Usage

The extension runs automatically in the background. Click the shield icon to:

- View protection statistics
- Scan current page manually
- Enable/disable protection features
- Report false positives
- Access settings

### Configuration

```javascript
// Extension settings (stored in chrome.storage.sync)
{
  "enabled": true,
  "blockPhishing": true,
  "blockMalware": true,
  "showWarnings": true
}
```

### API Endpoints

#### Check URL Safety
```javascript
POST /api/browser-extension/check-url
Body: { "url": "https://example.com" }

Response:
{
  "success": true,
  "malicious": false,
  "type": "safe",
  "score": 0.02,
  "sources": ["Google Safe Browsing", "URLhaus"]
}
```

#### Report Phishing
```javascript
POST /api/browser-extension/report-phishing
Body: { 
  "url": "https://suspicious-site.com",
  "details": {
    "findings": ["Suspicious keywords", "Urgent language"],
    "score": 8.5,
    "riskLevel": "high"
  }
}

Response:
{
  "success": true,
  "message": "Thank you for reporting this phishing attempt"
}
```

### Content Analysis

The extension analyzes page content for phishing indicators:

```javascript
// Analyzed patterns:
- Suspicious keywords (verify account, confirm identity, etc.)
- Urgent language (act now, limited time, etc.)
- Financial keywords (credit card, social security, etc.)
- Excessive form inputs
- Obfuscated links
```

**Risk Scoring:**
- **Low** (0-3): Minimal indicators
- **Medium** (4-6): Some suspicious patterns
- **High** (7+): Multiple red flags, likely phishing

---

## 💻 Cross-Platform Support

### Supported Platforms

Nebula Shield runs natively on:
- **Windows** 10/11
- **macOS** 10.15+
- **Linux** (Ubuntu, Debian, Fedora, Arch)

### Platform Adapter

The platform adapter provides unified APIs across operating systems:

```javascript
const platformAdapter = require('./platform-adapter');

// Get platform information
const info = platformAdapter.getSystemInfo();
// Returns: platform, architecture, hostname, CPUs, memory, etc.

// Get platform-specific paths
const paths = platformAdapter.getPaths();
// Returns: appData, quarantine, logs, database paths
```

### Platform-Specific Features

#### Windows
- Windows Defender integration
- PowerShell command execution
- Registry monitoring
- Windows Firewall status
- Event log integration

#### macOS
- XProtect integration
- Application Firewall status
- Gatekeeper checks
- LaunchDaemons monitoring
- Keychain access

#### Linux
- ClamAV integration
- UFW/iptables firewall
- systemd service management
- Package manager integration
- SELinux/AppArmor support

### API Endpoints

#### Get Platform Info
```javascript
GET /api/platform/info

Response:
{
  "success": true,
  "platform": {
    "platform": "darwin",
    "architecture": "arm64",
    "hostname": "MacBook-Pro",
    "cpus": 10,
    "totalMemory": 34359738368,
    "osType": "Darwin",
    "osRelease": "23.0.0"
  },
  "paths": {
    "quarantine": "/Users/username/Library/Application Support/NebulaShield/Quarantine",
    "logs": "/Users/username/Library/Logs/NebulaShield",
    "database": "/Users/username/Library/Application Support/NebulaShield/Data"
  }
}
```

#### Get Running Processes
```javascript
GET /api/platform/processes

Response:
{
  "success": true,
  "processes": [
    {
      "pid": 1234,
      "name": "chrome",
      "path": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    }
  ],
  "total": 342
}
```

#### Get Firewall Status
```javascript
GET /api/platform/firewall

Response:
{
  "success": true,
  "firewall": {
    "enabled": true,
    "platform": "macOS Application Firewall"
  }
}
```

#### Get Disk Usage
```javascript
GET /api/platform/disk

Response:
{
  "success": true,
  "disks": [
    {
      "device": "/dev/disk1s1",
      "total": 500107862016,
      "used": 245678123456,
      "free": 254429738560,
      "usagePercent": "49.13%",
      "mountPoint": "/"
    }
  ]
}
```

---

## ☁️ Cloud Sync

### Features

Seamlessly synchronize data across all your devices:

- **Settings Sync** - Keep preferences consistent across devices
- **Quarantine Sync** - Access quarantined files from any device
- **Reports Sync** - View scan history across all devices
- **Automatic Sync** - Background synchronization every 5 minutes
- **Conflict Resolution** - Smart merging of conflicting changes
- **Multi-device Coordination** - Manage protection across your ecosystem

### Device Registration

Register each device with the cloud sync service:

```javascript
POST /api/sync/register
Body: {
  "name": "My MacBook Pro",
  "platform": "darwin",
  "version": "1.0.0",
  "hostname": "MacBook-Pro.local",
  "macAddress": "00:11:22:33:44:55"
}

Response:
{
  "success": true,
  "device": {
    "id": "a1b2c3d4e5f6g7h8",
    "name": "My MacBook Pro",
    "platform": "darwin",
    "lastSeen": 1698765432000
  }
}
```

### Sync Settings

```javascript
POST /api/sync/settings
Body: {
  "deviceId": "a1b2c3d4e5f6g7h8",
  "settings": {
    "realTimeProtection": true,
    "autoQuarantine": true,
    "scanDepth": "deep",
    "updateFrequency": "daily"
  }
}

Response:
{
  "success": true,
  "settings": { /* merged settings */ },
  "timestamp": 1698765432000
}
```

### Sync Quarantine

```javascript
POST /api/sync/quarantine
Body: {
  "deviceId": "a1b2c3d4e5f6g7h8",
  "quarantineData": [
    {
      "id": "q-123",
      "fileName": "malware.exe",
      "originalPath": "/Downloads/malware.exe",
      "threatType": "trojan",
      "quarantinedAt": "2025-10-31T12:00:00Z"
    }
  ]
}

Response:
{
  "success": true,
  "count": 1,
  "timestamp": 1698765432000
}
```

### Get Sync Status

```javascript
GET /api/sync/status?deviceId=a1b2c3d4e5f6g7h8

Response:
{
  "success": true,
  "status": {
    "deviceId": "a1b2c3d4e5f6g7h8",
    "lastSync": 1698765432000,
    "lastSeen": 1698765500000,
    "syncEnabled": true,
    "pendingTasks": 0
  }
}
```

### Conflict Resolution

When conflicts occur (e.g., settings changed on multiple devices):

```javascript
POST /api/sync/resolve-conflict
Body: {
  "deviceId": "a1b2c3d4e5f6g7h8",
  "type": "settings",
  "resolution": "latest" | "server" | "client"
}

Response:
{
  "success": true,
  "resolution": "latest",
  "deviceId": "a1b2c3d4e5f6g7h8",
  "type": "settings"
}
```

**Resolution Strategies:**
- **latest**: Use most recent changes (default)
- **server**: Keep server version
- **client**: Prefer client version

### Get Sync Statistics

```javascript
GET /api/sync/statistics

Response:
{
  "success": true,
  "statistics": {
    "totalDevices": 3,
    "activeDevices": 2,
    "syncEnabled": true,
    "lastSync": {
      "settings": 1698765432000,
      "quarantine": 1698765400000,
      "reports": 1698765450000
    },
    "pendingTasks": 0,
    "totalChanges": {
      "settings": 5,
      "quarantine": 2,
      "reports": 8
    },
    "platforms": {
      "darwin": 1,
      "win32": 1,
      "linux": 1
    }
  }
}
```

### Export/Import Sync Data

Export all sync data for backup:

```javascript
GET /api/sync/export

Response:
{
  "success": true,
  "data": {
    "devices": [ /* all devices */ ],
    "lastSync": { /* sync timestamps */ },
    "changes": { /* all changes */ },
    "statistics": { /* current stats */ },
    "exportedAt": 1698765432000
  }
}
```

Import sync data:

```javascript
POST /api/sync/import
Body: { /* exported data */ }

Response:
{
  "success": true,
  "devicesImported": 3,
  "changesImported": 15
}
```

---

## 🔧 Configuration

### Mobile App Configuration

Edit `mobile-app/App.js`:

```javascript
const API_BASE_URL = __DEV__ 
  ? 'http://localhost:8080/api'  // Development
  : 'https://api.nebulashield.com/api';  // Production
```

### Browser Extension Configuration

Edit `browser-extension/background.js`:

```javascript
const API_BASE_URL = 'http://localhost:8080/api';
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
```

### Cloud Sync Configuration

Edit `backend/cloud-sync-service.js`:

```javascript
this.syncInterval = 5 * 60 * 1000; // 5 minutes
this.conflictResolution = 'latest'; // 'latest', 'server', 'client'
```

---

## 🚀 Quick Start Examples

### Mobile App Integration

```javascript
import { NebulaShieldAPI } from './api-service';

const api = new NebulaShieldAPI();

// Pair a device
const result = await api.pairDevice('123456');

// Start a scan
await api.startScan(deviceId, 'quick');

// Get device status
const status = await api.getDeviceStatus(deviceId);
```

### Browser Extension Integration

```javascript
// Check if URL is safe
chrome.runtime.sendMessage({
  action: 'checkUrl',
  url: 'https://example.com'
}, (result) => {
  if (result.malicious) {
    alert('⚠️ This site is dangerous!');
  }
});

// Report phishing
chrome.runtime.sendMessage({
  action: 'reportPhishing',
  url: currentUrl,
  details: analysis
});
```

### Cross-Platform File Scanning

```javascript
const platformAdapter = require('./platform-adapter');

// Scan a file
const result = await platformAdapter.scanFile('/path/to/file.exe');

console.log('Suspicious patterns:', result.suspicious);
console.log('File size:', result.fileSize);
console.log('Is executable:', result.isExecutable);
```

### Cloud Sync Integration

```javascript
const cloudSync = require('./cloud-sync-service');

// Register device
const device = await cloudSync.registerDevice({
  name: 'My Laptop',
  platform: process.platform,
  hostname: require('os').hostname()
});

// Sync settings
await cloudSync.syncSettings(device.id, settings);

// Get sync status
const status = cloudSync.getSyncStatus(device.id);
```

---

## 📊 Monitoring & Statistics

### Mobile App Dashboard

View comprehensive statistics:
- Total devices protected
- Scans performed across all devices
- Threats blocked globally
- Recent activity timeline
- Device health status

### Browser Extension Stats

Track web protection metrics:
- URLs scanned
- Phishing sites blocked
- Malware sites blocked
- Community reports submitted

### Cloud Sync Metrics

Monitor synchronization:
- Active devices
- Sync operations per hour
- Data synchronized (MB)
- Conflict resolutions
- Platform distribution

---

## 🔒 Security & Privacy

### Data Encryption

All synced data is encrypted:
- Settings: AES-256 encryption
- Quarantine metadata: Encrypted at rest
- API communication: HTTPS/TLS 1.3

### Privacy Features

- **Local Processing**: Threat analysis happens locally
- **Anonymous Reporting**: Phishing reports don't include personal info
- **No Data Sharing**: Your data stays within your devices
- **Opt-out Options**: Disable sync anytime

### Authentication

Mobile app uses secure pairing:
1. Time-limited pairing codes (5 minutes)
2. Device fingerprinting
3. Token-based authentication
4. Automatic session expiry

---

## 🛠️ Troubleshooting

### Mobile App Issues

**Can't pair device:**
- Ensure backend is running on port 8080
- Check network connectivity
- Verify pairing code hasn't expired
- Try regenerating pairing code

**Push notifications not working:**
- Grant notification permissions
- Check notification settings in app
- Verify device is registered
- Restart the app

### Browser Extension Issues

**Extension not blocking threats:**
- Check if extension is enabled
- Update threat database
- Clear extension cache
- Reinstall extension

**False positives:**
- Report via extension popup
- Add site to whitelist
- Adjust sensitivity in settings

### Cross-Platform Issues

**Platform adapter errors:**
- Ensure required permissions (sudo on Linux/macOS)
- Check platform-specific dependencies
- Verify paths are accessible
- Review error logs

### Cloud Sync Issues

**Sync not working:**
- Check internet connection
- Verify device is registered
- Check sync status endpoint
- Clear pending changes
- Re-register device if needed

**Conflicts occurring:**
- Choose resolution strategy
- Export data for backup
- Manually resolve conflicts
- Reset sync state if needed

---

## 📚 API Reference

Complete API documentation available at:
- Mobile App: See API Integration section above
- Browser Extension: See API Endpoints section above
- Cross-Platform: See Platform-Specific Features
- Cloud Sync: See Cloud Sync Features

---

## 🎯 Best Practices

1. **Keep Mobile App Updated** - Update regularly for latest features
2. **Enable Auto-Sync** - Keep devices synchronized automatically
3. **Review Blocked Sites** - Verify browser extension blocking accuracy
4. **Monitor All Devices** - Use mobile app to track protection status
5. **Export Sync Data** - Regular backups of sync configuration
6. **Report Issues** - Help improve protection with community reports

---

## 🌟 Advanced Features

### Custom Sync Intervals

```javascript
cloudSync.syncInterval = 10 * 60 * 1000; // 10 minutes
cloudSync.startSyncTimer();
```

### Manual Sync Trigger

```javascript
const result = await cloudSync.performSync();
console.log('Sync completed:', result);
```

### Platform-Specific Customization

```javascript
if (platformAdapter.isWindows) {
  // Windows-specific code
} else if (platformAdapter.isMacOS) {
  // macOS-specific code
} else if (platformAdapter.isLinux) {
  // Linux-specific code
}
```

### Browser Extension Custom Rules

```javascript
// Add custom phishing patterns
const customPatterns = [
  { pattern: /custom-keyword/i, description: 'Custom indicator' }
];
```

---

## 📞 Support

For multi-platform support:
- **Mobile App**: Check mobile-app/README.md
- **Browser Extension**: Check browser-extension/README.md
- **Cross-Platform**: Review platform-adapter.js documentation
- **Cloud Sync**: See cloud-sync-service.js comments

---

**Multi-Platform Protection - Anywhere, Anytime! 🛡️**
