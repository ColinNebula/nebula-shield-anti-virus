# 📱 Nebula Shield Mobile Companion App

React Native mobile application for remote monitoring and control of Nebula Shield antivirus protection.

## Features

- 🛡️ **Real-time Protection Monitoring** - View status across all devices
- 🔍 **Remote Scan Control** - Start/stop scans from your phone
- 🚨 **Push Notifications** - Instant threat alerts
- 📊 **Statistics Dashboard** - Track scans, threats, and protection metrics
- 🔒 **Quarantine Management** - Review and manage threats remotely
- 📱 **Multi-device Support** - Monitor multiple computers from one app

## Screenshots

[Dashboard] [Device Details] [Threats] [Settings]

## Installation

### Prerequisites
- Node.js 18+
- React Native CLI
- iOS: Xcode 14+, CocoaPods
- Android: Android Studio, JDK 11+

### Setup

```bash
# Install dependencies
npm install

# iOS setup
npx pod-install
npm run ios

# Android setup
npm run android
```

## Quick Start

### 1. Start Backend
Ensure Nebula Shield backend is running:
```bash
cd ../backend
node mock-backend.js
```

### 2. Configure API URL

Development (default):
```javascript
const API_BASE_URL = 'http://localhost:8080/api';
```

Production:
```javascript
const API_BASE_URL = 'https://api.nebulashield.com/api';
```

### 3. Pair Your Device

1. Open Nebula Shield on your computer
2. Go to Settings → Mobile App → Generate Pairing Code
3. Open mobile app
4. Tap "Add Device"
5. Enter 6-digit code
6. ✅ Device paired!

## App Structure

```
App.js                 # Main app with navigation
├── DashboardScreen    # Device list and overview
├── DeviceDetailsScreen # Device status and controls
├── ThreatsScreen      # Threat management
└── SettingsScreen     # App settings
```

## API Service

```javascript
import { NebulaShieldAPI } from './api-service';

const api = new NebulaShieldAPI();

// Get devices
const devices = await api.getDevices();

// Start scan
await api.startScan(deviceId, 'quick');

// Get device status
const status = await api.getDeviceStatus(deviceId);
```

## Navigation

Bottom tab navigation with 3 screens:
- **Dashboard** - Device list and status
- **Threats** - Detected threats
- **Settings** - App configuration

## Push Notifications

Configured automatically using `react-native-push-notification`:

```javascript
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

## Available Scripts

```bash
npm run start       # Start Metro bundler
npm run ios         # Run on iOS simulator
npm run android     # Run on Android emulator
npm run test        # Run tests
npm run lint        # Lint code
```

## Dependencies

```json
{
  "react": "18.2.0",
  "react-native": "0.73.0",
  "@react-navigation/native": "^6.1.9",
  "@react-navigation/bottom-tabs": "^6.5.11",
  "@react-native-async-storage/async-storage": "^1.19.5",
  "react-native-push-notification": "^8.1.1",
  "react-native-vector-icons": "^10.0.3"
}
```

## API Endpoints Used

- `GET /api/mobile/devices` - List paired devices
- `POST /api/mobile/devices/pair` - Pair new device
- `GET /api/mobile/devices/:id/status` - Get device status
- `POST /api/mobile/devices/:id/scan` - Start remote scan
- `GET /api/mobile/devices/:id/scan/status` - Get scan progress
- `DELETE /api/mobile/devices/:id/scan` - Stop scan
- `GET /api/mobile/devices/:id/threats` - Get threats
- `POST /api/mobile/devices/:id/threats/:tid/quarantine` - Quarantine threat
- `GET /api/mobile/devices/:id/settings` - Get settings
- `PUT /api/mobile/devices/:id/settings` - Update settings

## Screens Overview

### Dashboard Screen
- List of all paired devices
- Protection status indicators
- Quick stats (files scanned, threats blocked)
- Pull-to-refresh
- Add device button

### Device Details Screen
- Protection status
- Quick/Full scan buttons
- Scan progress (when scanning)
- Statistics cards
- Auto-refresh every 5 seconds

### Threats Screen
- List of detected threats
- Threat severity indicators
- Quarantine actions
- Filter by device

### Settings Screen
- Real-time protection toggle
- Cloud sync toggle
- Notifications toggle
- Auto-update toggle
- About information

## Styling

Material Design-inspired with custom styling:
- Primary color: `#2196F3` (Blue)
- Success color: `#4CAF50` (Green)
- Warning color: `#FFC107` (Amber)
- Danger color: `#F44336` (Red)

## Troubleshooting

### Can't connect to backend
```bash
# Check backend is running
curl http://localhost:8080/api/status

# iOS: Use your computer's IP instead of localhost
const API_BASE_URL = 'http://192.168.1.100:8080/api';
```

### Push notifications not working
- Check notification permissions in device settings
- Verify PushNotification configuration
- Test with local notifications first

### Device pairing fails
- Ensure pairing code is valid (5 minute expiry)
- Check network connectivity
- Verify backend is accessible
- Try regenerating pairing code

### App crashes on startup
```bash
# Clear Metro cache
npm start -- --reset-cache

# Clean iOS build
cd ios && pod install && cd ..

# Clean Android build
cd android && ./gradlew clean && cd ..
```

## Development

### Enable Debug Mode

```javascript
// In App.js
const __DEV__ = true;
const API_BASE_URL = 'http://localhost:8080/api';
```

### View Logs

```bash
# iOS
npx react-native log-ios

# Android
npx react-native log-android
```

### Hot Reload

Press `R` in terminal or shake device for dev menu.

## Production Build

### iOS
```bash
# Archive for App Store
npm run ios --configuration Release
```

### Android
```bash
# Build APK
cd android
./gradlew assembleRelease

# Build AAB (for Play Store)
./gradlew bundleRelease
```

## Security

- ✅ HTTPS/TLS for API communication
- ✅ Token-based authentication
- ✅ Secure storage with AsyncStorage
- ✅ No sensitive data in logs
- ✅ Certificate pinning (production)

## Performance

- App size: ~50MB
- Memory usage: ~40-60MB
- Network: Minimal (polling every 5s when viewing device)
- Battery: Optimized background tasks

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test on iOS and Android
5. Submit pull request

## License

Part of Nebula Shield Anti-Virus Suite

## Support

For issues or questions:
- Check [MULTI_PLATFORM_GUIDE.md](../MULTI_PLATFORM_GUIDE.md)
- Review API documentation
- Check backend logs
- Enable debug mode

---

**Stay Protected, Anywhere! 🛡️📱**
