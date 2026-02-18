# 🚀 Multi-Platform Quick Start Guide

## Overview

Get started with Nebula Shield's multi-platform features in minutes!

---

## 📱 Mobile App - Quick Setup

### 1. Install Dependencies
```bash
cd mobile-app
npm install
```

### 2. iOS Setup
```bash
npx pod-install
npm run ios
```

### 3. Android Setup
```bash
npm run android
```

### 4. Pair Your Device

1. **On Desktop**: Go to Settings → Mobile App → Generate Pairing Code
2. **On Mobile**: Open app → Tap "Add Device" → Enter code
3. **Done!** Your device appears in the mobile dashboard

### 5. Start Monitoring

- View real-time protection status
- Start/stop scans remotely
- Receive threat alerts
- Manage quarantine

---

## 🌐 Browser Extension - 2 Minute Install

### Chrome

1. Open `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select `nebula-shield-anti-virus/browser-extension` folder
5. ✅ Extension ready!

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Navigate to `browser-extension` folder
4. Select `manifest.json`
5. ✅ Extension ready!

### Verify Installation

- Click the shield icon in your toolbar
- You should see: "You're Protected" ✅
- URLs Scanned and Threats Blocked counters

---

## 💻 Cross-Platform - Automatic Detection

No setup needed! Nebula Shield automatically detects your platform:

- ✅ **Windows** - Uses Windows Defender, PowerShell commands
- ✅ **macOS** - Uses XProtect, Application Firewall
- ✅ **Linux** - Uses ClamAV, UFW/iptables

### Test Platform Detection

```bash
# Start backend
node backend/mock-backend.js

# Test platform info
curl http://localhost:8080/api/platform/info
```

You'll see your platform, architecture, and system paths!

---

## ☁️ Cloud Sync - Enable in 3 Steps

### 1. Register Your First Device

```bash
curl -X POST http://localhost:8080/api/sync/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Main Computer",
    "platform": "win32",
    "hostname": "DESKTOP-PC"
  }'
```

### 2. Sync Your Settings

```bash
curl -X POST http://localhost:8080/api/sync/settings \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "YOUR_DEVICE_ID",
    "settings": {
      "realTimeProtection": true,
      "autoQuarantine": true
    }
  }'
```

### 3. Check Sync Status

```bash
curl http://localhost:8080/api/sync/status
```

---

## 🎯 Common Tasks

### Mobile: Start Remote Scan

```javascript
// In mobile app
api.startScan(deviceId, 'quick');
```

### Browser: Check Current Page

1. Click extension icon
2. Click "Scan Current Page"
3. See results instantly!

### Platform: Get System Info

```bash
curl http://localhost:8080/api/platform/info
```

### Sync: Add New Device

```bash
curl -X POST http://localhost:8080/api/sync/register \
  -H "Content-Type: application/json" \
  -d '{"name": "My Laptop", "platform": "darwin"}'
```

---

## ✅ Verification Checklist

After setup, verify everything works:

- [ ] Mobile app shows your devices
- [ ] Browser extension icon shows in toolbar
- [ ] Platform API returns correct system info
- [ ] Cloud sync shows registered devices
- [ ] Mobile app can start scans
- [ ] Browser extension blocks test phishing sites
- [ ] Settings sync across devices

---

## 🔧 Quick Troubleshooting

### Mobile App Won't Connect

```bash
# Check backend is running
curl http://localhost:8080/api/status

# Should return: {"status":"running"}
```

### Browser Extension Not Working

1. Check if enabled in extensions page
2. Click extension icon → verify "Protection Enabled"
3. Try disabling and re-enabling

### Sync Not Working

```bash
# Check sync status
curl http://localhost:8080/api/sync/status

# Re-register device if needed
curl -X POST http://localhost:8080/api/sync/register -d '...'
```

---

## 📚 Next Steps

1. **Mobile App**: Explore threat management and statistics
2. **Browser Extension**: Customize protection settings
3. **Cross-Platform**: Test platform-specific features
4. **Cloud Sync**: Add more devices

---

## 🎓 Learning Resources

- **Full Guide**: [MULTI_PLATFORM_GUIDE.md](MULTI_PLATFORM_GUIDE.md)
- **Mobile App**: See `mobile-app/App.js`
- **Browser Extension**: See `browser-extension/background.js`
- **Platform Adapter**: See `backend/platform-adapter.js`
- **Cloud Sync**: See `backend/cloud-sync-service.js`

---

**You're all set! 🎉 Multi-platform protection activated!**
