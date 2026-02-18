# Nebula Shield Mobile App Setup & Usage

## Overview
The Nebula Shield Mobile Companion app allows you to remotely monitor and control your desktop antivirus protection from your mobile device.

## Features
✅ **Real-time Monitoring** - View CPU, memory, and disk usage  
✅ **Threat Alerts** - Instant notifications for detected threats  
✅ **Remote Scanning** - Trigger scans from your phone  
✅ **Scan History** - View past scan results and statistics  
✅ **Device Management** - Monitor multiple paired devices  
✅ **Secure Pairing** - QR code or manual pairing code  

## Prerequisites
- Node.js 18 or higher
- Expo CLI (installed globally)
- iOS Simulator (Mac) or Android Emulator
- Physical device with Expo Go app (optional)

## Installation

### 1. Install Dependencies
```bash
cd mobile
npm install
```

### 2. Install Additional Required Packages
```bash
npm install react-native-gesture-handler react-native-qrcode-svg
```

### 3. Configure Backend URL
Edit `src/services/AuthService.ts` and `src/services/SocketService.ts` to set your backend URL:
```typescript
const API_URL = 'http://YOUR_IP_ADDRESS:8082/api';
const SOCKET_URL = 'http://YOUR_IP_ADDRESS:3001';
```

**Important:** Replace `YOUR_IP_ADDRESS` with your computer's local IP address (not localhost) when testing on a physical device.

## Running the App

### Option 1: Development with Expo
```bash
cd mobile
npm start
```

Then:
- Press `i` for iOS Simulator
- Press `a` for Android Emulator
- Scan QR code with Expo Go app on your physical device

### Option 2: Using Provided Scripts
```bash
# Windows
START-EXPO.bat

# PowerShell
.\start-expo.ps1
```

### Option 3: LAN Mode (for physical devices)
```bash
npm start -- --lan
```

## Backend Setup

### 1. Start the Mobile API Server
```bash
# From project root
START-MOBILE-API.bat
```

Or manually:
```bash
cd backend
node mobile-api-server.js
```

The Mobile API server runs on port **3001** by default.

### 2. Start the Authentication Server
```bash
# From backend directory
START-BACKEND.bat
```

The Auth server runs on port **8082** by default.

## Pairing Your Device

### Method 1: QR Code (Recommended)
1. Open the mobile app and login/register
2. On the pairing screen, tap "Generate QR Code"
3. On your desktop Nebula Shield app, go to Settings → Mobile Pairing
4. Scan the QR code displayed on your mobile device
5. Devices will pair automatically

### Method 2: Pairing Code
1. On your desktop Nebula Shield app, go to Settings → Mobile Pairing
2. Generate a pairing code (e.g., ABCD1234)
3. Open the mobile app and enter the code
4. Tap "Pair Device"

## App Structure

```
mobile/
├── src/
│   ├── screens/
│   │   ├── DashboardScreen.tsx    # Main dashboard with metrics
│   │   ├── ThreatsScreen.tsx      # Threat alerts and history
│   │   ├── ScansScreen.tsx        # Scan controls and history
│   │   ├── DevicesScreen.tsx      # Paired devices list
│   │   ├── SettingsScreen.tsx     # App settings
│   │   ├── LoginScreen.tsx        # Authentication
│   │   └── PairingScreen.tsx      # Device pairing
│   ├── navigation/
│   │   └── RootNavigator.tsx      # Navigation setup
│   └── services/
│       ├── AuthService.ts         # Authentication logic
│       └── SocketService.ts       # Real-time communication
├── App.tsx                         # App entry point
└── package.json
```

## Available Screens

### Dashboard
- Real-time system metrics (CPU, memory, disk)
- Quick action buttons (Start Scan, Update, Refresh)
- Active scan progress
- CPU usage chart
- Last scan information

### Threats
- Real-time threat alerts
- Threat severity indicators (Low, Medium, High, Critical)
- Action status (Quarantined, Deleted, Blocked)
- Threat details and removal options

### Scans
- Start new scans (Quick, Full, Custom)
- View scan history
- Scan statistics (files scanned, threats found, duration)
- Active scan progress with real-time updates

### Devices
- List of paired devices
- Device status (Connected/Disconnected)
- Connection management

### Settings
- Notification preferences
- Security options (Biometric login)
- Account management
- App version information

## Real-time Events

The mobile app listens for these Socket.IO events:

### From Desktop → Mobile
- `metrics:data` - System metrics updates
- `scan:update` - Scan progress updates
- `scan:complete` - Scan completion notification
- `threat:alert` - New threat detected
- `scan:history` - Historical scan data
- `devices:list` - Connected devices list

### From Mobile → Desktop
- `command:execute` - Execute command on desktop
- `request:metrics` - Request latest metrics
- `request:scan-history` - Request scan history
- `request:devices` - Request device list

## Troubleshooting

### Cannot Connect to Backend
1. Ensure backend servers are running (Mobile API on port 3001, Auth on port 8082)
2. Check firewall settings - allow incoming connections on ports 3001 and 8082
3. Verify IP address in service files matches your computer's local IP
4. On physical devices, ensure phone and computer are on the same network

### QR Code Not Working
1. Ensure camera permissions are granted
2. Try manual pairing code instead
3. Check that both devices have internet connectivity

### Metro Bundler Issues
```bash
# Clear cache and restart
npx expo start -c
```

### Dependencies Issues
```bash
# Clean install
rm -rf node_modules package-lock.json
npm install
```

## Environment Variables

Create a `.env` file in the mobile directory:
```env
API_URL=http://YOUR_IP:8082/api
SOCKET_URL=http://YOUR_IP:3001
```

## Production Build

### Android
```bash
eas build --platform android
```

### iOS
```bash
eas build --platform ios
```

## Security Considerations

- Always use HTTPS in production
- Implement certificate pinning for API calls
- Enable biometric authentication
- Store sensitive data in secure storage
- Validate all server responses
- Implement rate limiting on authentication endpoints

## Future Enhancements

- [ ] Push notifications for threat alerts
- [ ] Biometric authentication
- [ ] Offline mode with local caching
- [ ] Multiple device support
- [ ] Advanced threat analytics
- [ ] Custom scan schedules
- [ ] Export scan reports
- [ ] Dark mode theme

## Support

For issues or questions:
- Check the main project documentation
- Review backend API documentation
- Check mobile app logs in console
- Verify all services are running

## License

Part of the Nebula Shield Anti-Virus project.
