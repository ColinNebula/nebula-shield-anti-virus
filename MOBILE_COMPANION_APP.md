# Nebula Shield Mobile Companion App

## Overview

The Nebula Shield Mobile Companion provides remote monitoring and control of your desktop antivirus protection from iOS and Android devices.

## Features

### 📱 Real-Time Monitoring
- **Live Protection Status** - View real-time protection state
- **Threat Alerts** - Instant push notifications for detected threats
- **Scan Progress** - Monitor active scans remotely
- **System Health** - CPU, memory, and protection status

### 🛡️ Remote Control
- **Start/Stop Protection** - Enable/disable protection modules
- **Trigger Scans** - Initiate quick, full, or custom scans
- **Quarantine Management** - View and restore quarantined files
- **Whitelist/Blacklist** - Manage trusted and blocked items

### 📊 Statistics & Reports
- **Threat Dashboard** - Visual threat statistics
- **Scan History** - Complete scan logs
- **Protection Timeline** - 24-hour activity overview
- **Detailed Reports** - Export and share reports

### 🔔 Smart Notifications
- **Critical Threats** - Immediate alerts for ransomware, malware
- **Scan Complete** - Notifications when scans finish
- **Update Alerts** - Database and app update notifications
- **Weekly Summary** - Protection statistics digest

### 🔐 Security Features
- **Secure Connection** - End-to-end encrypted communication
- **Biometric Auth** - Face ID / Touch ID / Fingerprint
- **PIN Protection** - Secondary PIN code
- **Remote Lock** - Lock desktop app remotely

## Technology Stack

### Frontend
- **React Native** - Cross-platform mobile framework
- **Expo** - Development toolchain
- **React Navigation** - Navigation system
- **Redux Toolkit** - State management
- **React Native Paper** - Material Design UI

### Backend Integration
- **WebSocket** - Real-time communication
- **REST API** - HTTP endpoints for commands
- **Push Notifications** - Firebase Cloud Messaging
- **OAuth 2.0** - Secure authentication

### Security
- **TLS/SSL** - Encrypted connections
- **JWT Tokens** - Stateless authentication
- **AES-256** - Data encryption
- **Certificate Pinning** - Prevent MITM attacks

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Mobile App (React Native)             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │Dashboard │  │ Threats  │  │ Settings │      │
│  └──────────┘  └──────────┘  └──────────┘      │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │    WebSocket + REST API    │
        │  (Secure Communication)    │
        └────────────┬───────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│         Desktop App (Nebula Shield)             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │Real-Time │  │  Scans   │  │Protection│      │
│  │Monitor   │  │          │  │ Modules  │      │
│  └──────────┘  └──────────┘  └──────────┘      │
└─────────────────────────────────────────────────┘
```

## Project Structure

```
nebula-shield-mobile/
├── src/
│   ├── components/
│   │   ├── Dashboard/
│   │   │   ├── StatusCard.js
│   │   │   ├── QuickActions.js
│   │   │   └── ThreatSummary.js
│   │   ├── Threats/
│   │   │   ├── ThreatList.js
│   │   │   ├── ThreatDetails.js
│   │   │   └── QuarantineView.js
│   │   ├── Scans/
│   │   │   ├── ScanControl.js
│   │   │   ├── ScanHistory.js
│   │   │   └── ScanProgress.js
│   │   └── Common/
│   │       ├── Header.js
│   │       ├── LoadingSpinner.js
│   │       └── EmptyState.js
│   ├── screens/
│   │   ├── DashboardScreen.js
│   │   ├── ThreatsScreen.js
│   │   ├── ScansScreen.js
│   │   ├── SettingsScreen.js
│   │   ├── LoginScreen.js
│   │   └── PairingScreen.js
│   ├── services/
│   │   ├── api.js
│   │   ├── websocket.js
│   │   ├── notifications.js
│   │   ├── auth.js
│   │   └── storage.js
│   ├── store/
│   │   ├── store.js
│   │   ├── slices/
│   │   │   ├── authSlice.js
│   │   │   ├── dashboardSlice.js
│   │   │   ├── threatsSlice.js
│   │   │   └── scansSlice.js
│   │   └── middleware/
│   │       └── websocketMiddleware.js
│   ├── navigation/
│   │   ├── AppNavigator.js
│   │   ├── AuthNavigator.js
│   │   └── MainTabNavigator.js
│   ├── utils/
│   │   ├── constants.js
│   │   ├── helpers.js
│   │   └── validators.js
│   └── theme/
│       ├── colors.js
│       ├── typography.js
│       └── spacing.js
├── assets/
│   ├── icons/
│   ├── images/
│   └── fonts/
├── app.json
├── package.json
└── README.md
```

## Setup Instructions

### Prerequisites
- Node.js 16+
- Expo CLI
- iOS Simulator / Android Emulator
- Desktop Nebula Shield running

### Installation

```bash
# Create React Native project
npx create-expo-app nebula-shield-mobile
cd nebula-shield-mobile

# Install dependencies
npm install @react-navigation/native @react-navigation/bottom-tabs
npm install @react-navigation/native-stack
npm install @reduxjs/toolkit react-redux
npm install react-native-paper react-native-vector-icons
npm install axios socket.io-client
npm install expo-notifications expo-device
npm install expo-secure-store @react-native-async-storage/async-storage
npm install react-native-chart-kit
npm install expo-local-authentication

# Start development server
npx expo start
```

### Pairing with Desktop App

1. **Generate Pairing Code** - Desktop app generates 6-digit code
2. **Enter Code in Mobile** - Enter code in mobile app
3. **Authenticate** - Biometric or PIN authentication
4. **Establish Connection** - Secure WebSocket connection
5. **Sync Data** - Initial data synchronization

## API Endpoints

### Authentication
```
POST /api/mobile/pair
POST /api/mobile/auth/login
POST /api/mobile/auth/refresh
POST /api/mobile/auth/logout
```

### Dashboard
```
GET  /api/mobile/status
GET  /api/mobile/statistics
GET  /api/mobile/recent-threats
```

### Scans
```
POST /api/mobile/scans/start
GET  /api/mobile/scans/status
GET  /api/mobile/scans/history
POST /api/mobile/scans/cancel
```

### Threats
```
GET  /api/mobile/threats
GET  /api/mobile/threats/:id
POST /api/mobile/threats/:id/quarantine
POST /api/mobile/threats/:id/restore
DELETE /api/mobile/threats/:id
```

### Protection
```
POST /api/mobile/protection/enable
POST /api/mobile/protection/disable
GET  /api/mobile/protection/modules
PUT  /api/mobile/protection/modules/:module
```

## WebSocket Events

### Client → Server
```javascript
{
  type: 'subscribe',
  channels: ['threats', 'scans', 'status']
}

{
  type: 'scan_start',
  scanType: 'quick'
}

{
  type: 'protection_toggle',
  module: 'realtime',
  enabled: true
}
```

### Server → Client
```javascript
{
  type: 'threat_detected',
  data: {
    id: '...',
    severity: 'critical',
    name: 'Ransomware.Generic',
    path: 'C:\\...',
    timestamp: '...'
  }
}

{
  type: 'scan_progress',
  data: {
    progress: 45,
    filesScanned: 1234,
    threatsFound: 2
  }
}

{
  type: 'status_update',
  data: {
    protection: 'active',
    lastScan: '...',
    threats: 0
  }
}
```

## Push Notifications

### Notification Types

**Critical Threats**
```
Title: "🚨 Critical Threat Detected"
Body: "Ransomware blocked on Desktop"
Action: Open Threat Details
```

**Scan Complete**
```
Title: "✅ Scan Complete"
Body: "No threats found (1,234 files scanned)"
Action: View Results
```

**Update Available**
```
Title: "🔄 Update Available"
Body: "New virus definitions available"
Action: Update Now
```

### Implementation

```javascript
// Register for push notifications
import * as Notifications from 'expo-notifications';

async function registerForPushNotifications() {
  const { status } = await Notifications.requestPermissionsAsync();
  if (status !== 'granted') {
    return;
  }
  
  const token = await Notifications.getExpoPushTokenAsync();
  // Send token to backend
}

// Handle notification
Notifications.addNotificationReceivedListener(notification => {
  console.log('Notification:', notification);
});

Notifications.addNotificationResponseReceivedListener(response => {
  // Handle user interaction
  const { screen, threatId } = response.notification.request.content.data;
  navigation.navigate(screen, { id: threatId });
});
```

## Security Implementation

### Secure Storage
```javascript
import * as SecureStore from 'expo-secure-store';

// Store auth token securely
await SecureStore.setItemAsync('auth_token', token);

// Retrieve token
const token = await SecureStore.getItemAsync('auth_token');
```

### Biometric Authentication
```javascript
import * as LocalAuthentication from 'expo-local-authentication';

async function authenticateUser() {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const isEnrolled = await LocalAuthentication.isEnrolledAsync();
  
  if (hasHardware && isEnrolled) {
    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: 'Authenticate to access Nebula Shield',
      fallbackLabel: 'Use PIN'
    });
    
    return result.success;
  }
  
  return false;
}
```

### Encrypted Communication
```javascript
import io from 'socket.io-client';

const socket = io('wss://localhost:8080', {
  secure: true,
  rejectUnauthorized: true,
  extraHeaders: {
    'Authorization': `Bearer ${token}`
  },
  transports: ['websocket']
});
```

## UI Components

### Dashboard Screen
```javascript
import React from 'react';
import { View, ScrollView, RefreshControl } from 'react-native';
import { Card, Title, Paragraph, Button } from 'react-native-paper';

const DashboardScreen = () => {
  return (
    <ScrollView>
      <Card style={styles.statusCard}>
        <Card.Content>
          <Title>Protection Status</Title>
          <Paragraph>All systems protected</Paragraph>
        </Card.Content>
      </Card>
      
      <Card style={styles.statsCard}>
        <Card.Content>
          <Title>Recent Activity</Title>
          <Paragraph>0 threats detected today</Paragraph>
        </Card.Content>
      </Card>
    </ScrollView>
  );
};
```

### Threat List
```javascript
import React from 'react';
import { FlatList } from 'react-native';
import { List, Avatar, Badge } from 'react-native-paper';

const ThreatList = ({ threats }) => {
  return (
    <FlatList
      data={threats}
      keyExtractor={item => item.id}
      renderItem={({ item }) => (
        <List.Item
          title={item.name}
          description={item.path}
          left={props => (
            <Avatar.Icon 
              {...props} 
              icon="shield-alert" 
              style={{ backgroundColor: getSeverityColor(item.severity) }}
            />
          )}
          right={props => (
            <Badge>{item.severity}</Badge>
          )}
        />
      )}
    />
  );
};
```

## Desktop Backend Integration

Add mobile API endpoints to your Express backend:

```javascript
// backend/routes/mobile.js
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// Generate pairing code
router.post('/pair', async (req, res) => {
  const pairingCode = generatePairingCode();
  await storePairingCode(pairingCode);
  res.json({ code: pairingCode, expiresIn: 300 });
});

// Authenticate mobile app
router.post('/auth/login', async (req, res) => {
  const { pairingCode, deviceId } = req.body;
  
  if (await validatePairingCode(pairingCode)) {
    const token = jwt.sign({ deviceId }, SECRET_KEY, { expiresIn: '30d' });
    res.json({ token, expiresIn: 2592000 });
  } else {
    res.status(401).json({ error: 'Invalid pairing code' });
  }
});

// Get status
router.get('/status', authenticateMobile, async (req, res) => {
  const status = await getSystemStatus();
  res.json(status);
});

// Start scan
router.post('/scans/start', authenticateMobile, async (req, res) => {
  const { scanType } = req.body;
  const scanId = await startScan(scanType);
  res.json({ scanId, status: 'started' });
});

module.exports = router;
```

## Performance Optimization

### Data Caching
```javascript
import AsyncStorage from '@react-native-async-storage/async-storage';

const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

async function getCachedData(key) {
  const cached = await AsyncStorage.getItem(key);
  if (cached) {
    const { data, timestamp } = JSON.parse(cached);
    if (Date.now() - timestamp < CACHE_DURATION) {
      return data;
    }
  }
  return null;
}

async function setCachedData(key, data) {
  await AsyncStorage.setItem(key, JSON.stringify({
    data,
    timestamp: Date.now()
  }));
}
```

### Image Optimization
```javascript
import { Image } from 'expo-image';

<Image
  source={{ uri: threatIcon }}
  contentFit="cover"
  transition={200}
  cachePolicy="memory-disk"
/>
```

## Testing

### Unit Tests
```bash
npm install --save-dev jest @testing-library/react-native
```

```javascript
import { render, fireEvent } from '@testing-library/react-native';
import DashboardScreen from '../screens/DashboardScreen';

test('renders dashboard correctly', () => {
  const { getByText } = render(<DashboardScreen />);
  expect(getByText('Protection Status')).toBeTruthy();
});
```

### E2E Tests
```bash
npm install --save-dev detox
```

## Distribution

### iOS
1. Create app in App Store Connect
2. Configure provisioning profiles
3. Build with `eas build --platform ios`
4. Submit to App Store

### Android
1. Create app in Google Play Console
2. Configure signing keys
3. Build with `eas build --platform android`
4. Submit to Play Store

## Pricing Model

### Free Tier
- Basic monitoring
- Manual scans
- 5 devices max

### Premium ($4.99/month)
- Real-time alerts
- Unlimited devices
- Advanced statistics
- Priority support

## Future Enhancements

- [ ] Apple Watch / Wear OS companion
- [ ] Siri / Google Assistant shortcuts
- [ ] Dark mode
- [ ] Multiple language support
- [ ] Tablet optimization
- [ ] Widget support
- [ ] Offline mode
- [ ] Export reports as PDF
- [ ] Family sharing
- [ ] Remote desktop control

---

**Ready to build?** Run the setup script and start development!

```bash
./scripts/setup-mobile-app.sh
```
