# Nebula Shield Mobile Companion App

React Native mobile app for monitoring and controlling Nebula Shield antivirus on desktop devices.

## 📱 Features

- ✅ **Real-Time Dashboard** - Monitor system health (CPU, Memory, Disk)
- ✅ **Remote Control** - Start scans, update signatures from your phone
- ✅ **Threat Alerts** - Instant push notifications when threats detected
- ✅ **Multi-Device Management** - Control multiple desktop devices
- ✅ **Live Charts** - CPU usage history and performance metrics
- ✅ **Quarantine Management** - View and restore quarantined files
- ✅ **WebSocket Integration** - Real-time bidirectional communication

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- React Native CLI
- Android Studio (for Android) or Xcode (for iOS)
- Cloud backend running on http://localhost:3001

### Installation

```bash
cd mobile
npm install
```

### Running on Android

```bash
npm run android
```

### Running on iOS

```bash
cd ios
pod install
cd ..
npm run ios
```

## 🏗️ Project Structure

```
mobile/
├── src/
│   ├── screens/
│   │   ├── DashboardScreen.tsx      # Main monitoring dashboard
│   │   ├── DevicesScreen.tsx        # Device management
│   │   ├── ThreatsScreen.tsx        # Threat history
│   │   └── SettingsScreen.tsx       # App settings
│   ├── services/
│   │   ├── AuthService.ts           # Authentication logic
│   │   └── SocketService.ts         # WebSocket communication
│   └── App.tsx                      # Main app component
├── android/                         # Android native code
├── ios/                             # iOS native code
├── package.json
└── README.md
```

## 🔌 WebSocket Events

### Receiving from Desktop

- `metrics:data` - System health metrics (CPU, memory, disk)
- `scan:update` - Scan progress updates
- `threat:alert` - Threat detection alerts
- `quarantine:updated` - Quarantine changes
- `device:connected` - Device came online
- `device:disconnected` - Device went offline

### Sending to Desktop

- `command:execute` - Execute remote commands (start-scan, update, etc.)
- `request:metrics` - Request latest system metrics

## 📸 Screenshots

### Dashboard
- Real-time system health monitoring
- CPU usage chart (last 5 minutes)
- Quick action buttons
- Threat counter

### Devices
- List of all registered devices
- Online/offline status
- Last seen timestamp
- Remote control buttons

### Threats
- Real-time threat feed
- Severity indicators (low, medium, high, critical)
- Action taken (quarantined, deleted, blocked)
- Detailed threat information

### Settings
- Push notification preferences
- Biometric authentication
- Account management

## 🔐 Authentication

The app uses JWT tokens for authentication:

```typescript
import {AuthService} from './services/AuthService';

// Login
const result = await AuthService.login('admin@test.com', 'admin');
if (result.success) {
  // Token saved automatically
  console.log('Logged in!');
}

// Get current token
const token = await AuthService.getToken();
```

## 🌐 WebSocket Connection

```typescript
import {SocketService} from './services/SocketService';

// Connect
SocketService.connect(token);

// Listen for events
SocketService.on('threat:alert', (data) => {
  console.log('Threat detected:', data.threatName);
});

// Send commands
SocketService.emit('command:execute', {
  targetDeviceId: 'desktop-001',
  command: 'start-scan',
  params: {type: 'quick'}
});
```

## 📦 Dependencies

### Core
- `react-native` - Mobile framework
- `@react-navigation/native` - Navigation
- `@react-navigation/bottom-tabs` - Tab navigation
- `react-native-paper` - Material Design components

### Communication
- `socket.io-client` - WebSocket client
- `axios` - HTTP client

### UI & Charts
- `react-native-chart-kit` - Charts
- `react-native-svg` - SVG support
- `react-native-vector-icons` - Icons

### Storage
- `@react-native-async-storage/async-storage` - Local storage

## 🔧 Configuration

Update API and Socket URLs in:

- `src/services/AuthService.ts` - `API_URL`
- `src/services/SocketService.ts` - `SOCKET_URL`

For production, use environment variables or a config file.

## 🚢 Building for Production

### Android

```bash
cd android
./gradlew assembleRelease
```

APK location: `android/app/build/outputs/apk/release/app-release.apk`

### iOS

```bash
cd ios
xcodebuild -workspace NebulaShield.xcworkspace -scheme NebulaShield -configuration Release
```

## 📱 Push Notifications

To enable push notifications:

1. Set up Firebase Cloud Messaging (FCM)
2. Add google-services.json (Android) and GoogleService-Info.plist (iOS)
3. Install `@react-native-firebase/messaging`
4. Register FCM token with backend

## 🧪 Testing

```bash
npm test
```

## 📝 TODO

- [ ] Implement login/registration screens
- [ ] Add biometric authentication
- [ ] Integrate push notifications
- [ ] Add offline mode support
- [ ] Implement quarantine file restore
- [ ] Add scan history view
- [ ] Create settings persistence
- [ ] Add dark mode theme toggle
- [ ] Implement pull-to-refresh everywhere
- [ ] Add error handling and retry logic

## 📄 License

MIT

---

**Next Steps:**
1. Start cloud backend: `cd cloud-backend && npm install && npm run dev`
2. Install mobile dependencies: `cd mobile && npm install`
3. Run on device: `npm run android` or `npm run ios`
