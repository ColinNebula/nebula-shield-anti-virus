# Mobile Backend Connection Guide

## Issue: Network Error when connecting mobile app to backend

### Root Cause
The mobile API server was only listening on `localhost`, preventing network connections from mobile devices.

### Solution Applied

1. **Updated server configuration** in `backend/mobile-api-server.js`:
   - Changed `server.listen(PORT)` to `server.listen(PORT, '0.0.0.0')`
   - Server now listens on all network interfaces

2. **Created `.env` file** in `mobile/` directory with correct IP:
   ```
   API_URL=http://10.0.0.72:3001/api
   WS_URL=ws://10.0.0.72:3001
   ```

3. **Fixed expo-barcode-scanner** native module by adding it to `app.json` plugins

### How to Start the Backend Server

**Option 1: Using Batch File (Recommended)**
```bash
START-MOBILE-BACKEND.bat
```

**Option 2: Manual Command**
```bash
cd Z:\Directory\projects\nebula-shield-anti-virus
node backend\mobile-api-server.js
```

### Windows Firewall Configuration

If you still get network errors, you may need to allow Node.js through Windows Firewall:

**Method 1: PowerShell (Run as Administrator)**
```powershell
New-NetFirewallRule -DisplayName "Nebula Shield Mobile API" -Direction Inbound -Protocol TCP -LocalPort 3001 -Action Allow
```

**Method 2: GUI**
1. Open Windows Defender Firewall
2. Click "Advanced settings"
3. Click "Inbound Rules" → "New Rule"
4. Select "Port" → Next
5. Select "TCP" and enter port "3001" → Next
6. Select "Allow the connection" → Next
7. Check all profiles (Domain, Private, Public) → Next
8. Name: "Nebula Shield Mobile API" → Finish

### Verify Backend is Running

Test the health endpoint:
```powershell
Invoke-WebRequest -Uri "http://10.0.0.72:3001/api/health"
```

You should see:
```json
{
  "status": "healthy",
  "service": "Nebula Shield Mobile API",
  "connectedDevices": 0,
  "activePairs": 0,
  "timestamp": "..."
}
```

### Mobile App Configuration

The mobile app is configured to connect to:
- **API URL**: `http://10.0.0.72:3001/api`
- **WebSocket**: `ws://10.0.0.72:3001`

Make sure:
1. Your PC and mobile device are on the same Wi-Fi network
2. Your PC's IP address is `10.0.0.72` (check with `ipconfig`)
3. If your IP changes, update `mobile/src/services/ApiService.ts` and `mobile/src/services/AuthService.ts`

### Testing the Connection

1. Start the backend server: `START-MOBILE-BACKEND.bat`
2. Start the Expo dev server: `cd mobile; npm start`
3. Scan the QR code with Expo Go app
4. The mobile app should now connect successfully

### Common Issues

**Issue**: "Network Error" or timeout
- **Solution**: Check firewall settings, ensure backend is running, verify IP address

**Issue**: "Cannot find native module 'ExpoBarCodeScanner'"
- **Solution**: Run `npx expo prebuild --clean` in the mobile directory

**Issue**: Backend server closes immediately
- **Solution**: Check if another process is using port 3001, or check for errors in the console

### Server Endpoints

- Health check: `GET /api/health`
- System status: `GET /api/system/status`
- Generate pairing code: `POST /api/pairing/generate-code`
- Pair device: `POST /api/pairing/pair`
- And more... (see backend/mobile-api-server.js for full API)
