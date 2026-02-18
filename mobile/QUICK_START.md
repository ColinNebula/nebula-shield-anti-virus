# 🚀 Mobile App Quick Start

## Setup in 5 Minutes

### 1. Install Dependencies
```bash
cd mobile
npm install
```

### 2. Configure Backend URLs
Find your computer's IP address:
```bash
# Windows
ipconfig
# Look for "IPv4 Address" (e.g., 192.168.1.100)

# Mac/Linux
ifconfig
# Look for "inet" under your network interface
```

Update these files with your IP:

**mobile/src/services/AuthService.ts:**
```typescript
const API_URL = 'http://192.168.1.100:8082/api';  // Replace with your IP
```

**mobile/src/services/SocketService.ts:**
```typescript
const SOCKET_URL = 'http://192.168.1.100:3001';  // Replace with your IP
```

### 3. Start Backend Servers

**Terminal 1 - Auth Server:**
```bash
cd backend
node auth-server.js
```
Should show: `📡 Listening on port 8082`

**Terminal 2 - Mobile API Server:**
```bash
cd backend
node mobile-api-server.js
```
Should show: `📡 Listening on port 3001`

Or use the batch file:
```bash
START-MOBILE-API.bat
```

### 4. Start Mobile App
```bash
cd mobile
npm start
```

Press:
- **`i`** for iOS Simulator
- **`a`** for Android Emulator
- **Scan QR** with Expo Go app on physical device

## First Run

### Step 1: Login/Register
- Email: any valid email format
- Password: at least 6 characters
- Full Name: your name (for registration)

### Step 2: Pair Device
Choose one method:

**Method A - QR Code:**
1. Tap "Generate QR Code"
2. On desktop app, scan the QR code
3. Auto-paired!

**Method B - Manual Code:**
1. Get code from desktop app
2. Enter code in mobile app
3. Tap "Pair Device"

### Step 3: Enjoy!
Navigate through tabs:
- **Dashboard** - System metrics
- **Threats** - Security alerts
- **Scans** - Start/view scans
- **Devices** - Manage connections
- **Settings** - App preferences

## Common Issues

### "Cannot connect to server"
✅ Check backend servers are running  
✅ Verify IP address in service files  
✅ Ensure phone and computer on same WiFi  
✅ Check firewall allows ports 3001 and 8082  

### "Metro bundler error"
```bash
npx expo start -c  # Clear cache
```

### "Module not found"
```bash
rm -rf node_modules package-lock.json
npm install
```

## File Overview

```
📱 Mobile App
├── 🖼️ Screens
│   ├── LoginScreen       → Email/password auth
│   ├── PairingScreen     → Connect to desktop
│   ├── DashboardScreen   → Main metrics view
│   ├── ThreatsScreen     → Security alerts
│   ├── ScansScreen       → Scan controls
│   ├── DevicesScreen     → Device list
│   └── SettingsScreen    → App settings
│
├── 🧭 Navigation
│   └── RootNavigator     → Tab navigation
│
├── 🔧 Services
│   ├── AuthService       → Login/register/token
│   └── SocketService     → Real-time connection
│
└── 📱 App.tsx            → Entry point

🖥️ Backend
└── mobile-api-server.js  → Socket.IO + REST API
```

## Development Tips

### Hot Reload
- **Shake device** or press **`Cmd+D`** (iOS) / **`Cmd+M`** (Android)
- Select "Reload" or "Enable Hot Reloading"

### Debug Mode
- Open Developer Menu
- Enable "Debug Remote JS"
- Chrome DevTools will open

### View Logs
All console.log statements appear in the terminal running `npm start`

## Testing Flow

1. ✅ Start both backend servers
2. ✅ Start mobile app
3. ✅ Register new account
4. ✅ Generate pairing code on mobile
5. ✅ Navigate to Dashboard
6. ✅ Tap "Start Scan" button
7. ✅ View real-time scan progress
8. ✅ Check Threats tab for alerts
9. ✅ View scan history in Scans tab

## Socket Events Reference

### Mobile → Server
```javascript
socket.emit('authenticate', {token, deviceId, deviceType});
socket.emit('pairing:request', {code});
socket.emit('command:execute', {targetDeviceId, command, params});
socket.emit('request:metrics', {});
socket.emit('request:scan-history', {});
```

### Server → Mobile
```javascript
socket.on('authenticated', callback);
socket.on('pairing:success', callback);
socket.on('metrics:data', callback);
socket.on('scan:update', callback);
socket.on('threat:alert', callback);
```

## Quick Commands

```bash
# Start app
npm start

# Start on specific platform
npm run ios
npm run android

# Clear cache
npx expo start -c

# Install new package
npm install package-name

# Update all packages
npm update

# Check for issues
npx expo-doctor
```

## Need Help?

1. Check `MOBILE_APP_GUIDE.md` for detailed documentation
2. Review `MOBILE_IMPLEMENTATION_COMPLETE.md` for technical details
3. Check backend logs for API errors
4. Check mobile terminal for React Native errors

## Production Build

```bash
# Install EAS CLI
npm install -g eas-cli

# Login to Expo
eas login

# Build for Android
eas build --platform android

# Build for iOS
eas build --platform ios
```

---

**Ready to go!** 🎉

Your mobile app is fully set up and ready for development. Happy coding!
