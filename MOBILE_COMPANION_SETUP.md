# Nebula Shield - Complete Mobile Companion Setup Guide

## 🎯 Overview

The Nebula Shield ecosystem now includes:

1. **Desktop App** (Electron + React) - Main antivirus application
2. **Cloud Backend** (Node.js + Socket.io) - Real-time communication hub
3. **Mobile App** (React Native) - Remote monitoring and control

## 📁 Project Structure

```
nebula-shield-anti-virus/
├── cloud-backend/          # WebSocket server & API
│   ├── routes/            # REST API endpoints
│   ├── socket/            # WebSocket handlers
│   └── server.js          # Main server file
│
├── mobile/                # React Native mobile app
│   └── src/
│       ├── screens/       # Dashboard, Devices, Threats, Settings
│       ├── services/      # Auth & Socket services
│       └── App.tsx        # Main app component
│
├── backend/               # Existing desktop backend
├── src/                   # Existing desktop frontend
└── public/                # Desktop assets
```

## 🚀 Setup Instructions

### Step 1: Install Cloud Backend

```powershell
cd cloud-backend
npm install
```

### Step 2: Configure Cloud Backend

```powershell
# Copy environment template
cp .env.example .env

# Edit .env with your settings
notepad .env
```

Update these values:
```env
PORT=3001
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
```

### Step 3: Start Cloud Backend

```powershell
# Development mode (with auto-reload)
npm run dev

# Or production mode
npm start
```

You should see:
```
╔════════════════════════════════════════════╗
║   🛡️  Nebula Shield Cloud Backend         ║
╚════════════════════════════════════════════╝

✅ Server running on port 3001
✅ Environment: development
✅ WebSocket server ready

🌐 Health check: http://localhost:3001/health
🔌 WebSocket: ws://localhost:3001
```

### Step 4: Install Mobile App Dependencies

```powershell
cd ..\mobile
npm install
```

### Step 5: Run Mobile App

#### For Android:
```powershell
# Make sure Android emulator is running or device is connected
npm run android
```

#### For iOS (Mac only):
```powershell
cd ios
pod install
cd ..
npm run ios
```

## 🔌 How It Works

### Architecture Flow

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Desktop App    │         │   Cloud Backend  │         │   Mobile App    │
│  (Port 3000)    │         │   (Port 3001)    │         │  (iOS/Android)  │
└────────┬────────┘         └────────┬─────────┘         └────────┬────────┘
         │                           │                            │
         │  1. WebSocket Connect     │                            │
         │─────────────────────────►│                            │
         │                           │                            │
         │                           │  2. WebSocket Connect      │
         │                           │◄───────────────────────────│
         │                           │                            │
         │  3. Threat Detected       │                            │
         │─────────────────────────►│                            │
         │                           │  4. Push to Mobile         │
         │                           │───────────────────────────►│
         │                           │                            │
         │                           │  5. Remote Command         │
         │  6. Execute Scan          │◄───────────────────────────│
         │◄─────────────────────────│                            │
         │                           │                            │
         │  7. Scan Progress         │                            │
         │─────────────────────────►│                            │
         │                           │  8. Update Mobile          │
         │                           │───────────────────────────►│
         │                           │                            │
```

### Communication Events

**Desktop → Cloud → Mobile:**
- `threat:detected` - Malware found
- `scan:status` - Scan progress
- `metrics:update` - CPU/Memory/Disk stats
- `quarantine:action` - File quarantined/restored

**Mobile → Cloud → Desktop:**
- `command:execute` - Start scan, update, etc.
- `request:metrics` - Get latest stats

## 📱 Mobile App Features

### 1. Dashboard Screen
- **Real-time metrics**: CPU, Memory, Disk usage
- **CPU history chart**: Last 5 minutes
- **Quick actions**: Start Scan, Update, Refresh
- **Scan progress**: Live progress bar
- **Threat counter**: Total threats blocked

### 2. Devices Screen
- **Device list**: All registered devices
- **Online status**: Green badge for online devices
- **Last seen**: Timestamp of last connection
- **Remote control**: Scan and Update buttons

### 3. Threats Screen
- **Threat feed**: Real-time threat alerts
- **Severity levels**: Low, Medium, High, Critical
- **Action taken**: Quarantined, Deleted, Blocked
- **Timestamp**: When threat was detected

### 4. Settings Screen
- **Notifications**: Toggle threat alerts
- **Biometric auth**: Face ID/Fingerprint
- **Account management**: Logout, Privacy Policy

## 🔐 Security Features

### JWT Authentication
```typescript
// Login from mobile app
const result = await AuthService.login('admin@test.com', 'admin');

// Token automatically stored in AsyncStorage
// WebSocket connection authenticated with token
```

### Secure WebSocket
All WebSocket connections require JWT authentication:
```typescript
socket.emit('authenticate', {
  token: 'your-jwt-token',
  deviceId: 'mobile-001',
  deviceType: 'mobile'
});
```

### Rate Limiting
- 100 requests per 15 minutes per IP
- Protects against brute force attacks

## 🧪 Testing the Integration

### 1. Start All Services

**Terminal 1 - Desktop Backend:**
```powershell
npm run backend
```

**Terminal 2 - Cloud Backend:**
```powershell
cd cloud-backend
npm run dev
```

**Terminal 3 - Desktop Frontend:**
```powershell
npm start
```

**Terminal 4 - Mobile App:**
```powershell
cd mobile
npm run android
```

### 2. Test WebSocket Connection

Open browser console on desktop app and run:
```javascript
// Desktop connects to cloud
const socket = io('http://localhost:3001');
socket.emit('authenticate', {
  token: localStorage.getItem('token'),
  deviceId: 'desktop-001',
  deviceType: 'desktop'
});

// Simulate threat detection
socket.emit('threat:detected', {
  threatName: 'Test.Virus',
  filePath: 'C:\\test.exe',
  severity: 'high',
  action: 'quarantined'
});
```

Mobile app should receive the threat alert instantly!

### 3. Test Remote Commands

From mobile app, tap "Start Scan" button:
```typescript
// This emits:
SocketService.emit('command:execute', {
  targetDeviceId: 'desktop-001',
  command: 'start-scan',
  params: {type: 'quick'}
});
```

Desktop should receive and execute the scan command.

## 📊 Monitoring

### Cloud Backend Health
```
GET http://localhost:3001/health

Response:
{
  "status": "healthy",
  "timestamp": "2025-10-24T...",
  "uptime": 3600,
  "connections": 2
}
```

### Active Connections
Check server console for:
```
🔌 New connection: socket-id-123
✅ Authenticated: User 1, Device desktop-001 (desktop)
🚨 Threat detected for user 1: Trojan.Win32.Agent
📱 Command from mobile: start-scan for device desktop-001
```

## 🚢 Deployment

### Cloud Backend (Production)

**Option 1: Heroku**
```powershell
heroku create nebula-shield-cloud
git subtree push --prefix cloud-backend heroku main
```

**Option 2: AWS EC2**
1. Launch EC2 instance (t2.micro)
2. Install Node.js 18+
3. Clone repository
4. Install PM2: `npm install -g pm2`
5. Start: `pm2 start server.js --name nebula-cloud`

**Option 3: Docker**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY cloud-backend/package*.json ./
RUN npm ci --only=production
COPY cloud-backend/ ./
EXPOSE 3001
CMD ["node", "server.js"]
```

### Mobile App (Production)

**Android:**
```powershell
cd mobile/android
./gradlew assembleRelease
```

**iOS (Mac):**
```powershell
cd mobile/ios
xcodebuild -workspace NebulaShield.xcworkspace -scheme NebulaShield archive
```

Submit to Google Play Store and Apple App Store.

## 🔧 Configuration

### Update API URLs for Production

**mobile/src/services/AuthService.ts:**
```typescript
const API_URL = process.env.NODE_ENV === 'production'
  ? 'https://api.nebulashield.com/api'
  : 'http://localhost:3001/api';
```

**mobile/src/services/SocketService.ts:**
```typescript
const SOCKET_URL = process.env.NODE_ENV === 'production'
  ? 'https://api.nebulashield.com'
  : 'http://localhost:3001';
```

## 📱 Push Notifications (Optional)

### Firebase Cloud Messaging Setup

1. Create Firebase project at https://console.firebase.google.com
2. Add Android/iOS apps
3. Download config files:
   - `google-services.json` (Android) → `mobile/android/app/`
   - `GoogleService-Info.plist` (iOS) → `mobile/ios/`

4. Install dependencies:
```powershell
npm install @react-native-firebase/app @react-native-firebase/messaging
```

5. Register FCM token:
```typescript
import messaging from '@react-native-firebase/messaging';

const token = await messaging().getToken();
// Send token to backend
```

## 🐛 Troubleshooting

### Cloud Backend Won't Start
- Check if port 3001 is already in use: `netstat -ano | findstr :3001`
- Kill process: `taskkill /PID <pid> /F`

### Mobile App Can't Connect
- Make sure cloud backend is running
- Check firewall allows port 3001
- For Android emulator, use `http://10.0.2.2:3001` instead of `localhost`

### WebSocket Not Authenticating
- Verify JWT token is valid
- Check token is being sent in `authenticate` event
- Look for authentication errors in cloud backend logs

## 📈 Performance Tips

1. **Enable compression** on cloud backend (gzip)
2. **Use Redis** for session storage instead of in-memory
3. **Implement reconnection logic** in mobile app
4. **Add offline mode** with local cache
5. **Optimize chart rendering** (use fewer data points)

## 🎉 Success!

You now have a complete cross-platform antivirus ecosystem:

✅ Desktop app with full scanning engine
✅ Cloud backend for real-time communication
✅ Mobile app for remote monitoring
✅ WebSocket integration
✅ JWT authentication
✅ Real-time threat alerts
✅ Remote control capabilities

---

**Need help?** Check the README files in each directory:
- `cloud-backend/README.md` - Cloud backend documentation
- `mobile/README.md` - Mobile app documentation
- Main README - Desktop app documentation
