# Mobile Protection - Data Source Explanation

## Why Mobile Protection Shows Simulated Data

The Mobile Protection screen displays **simulated/mock data** by design when running in **Expo Go** or development mode. This is EXPECTED BEHAVIOR and not a bug.

### Why Simulated Data is Used

#### 1. **Expo Go Limitations**
- Expo Go cannot access native device APIs required for real WiFi scanning
- Real device information requires native modules not available in Expo Go
- Actual WiFi network scanning needs platform-specific permissions and APIs

#### 2. **Development/Demo Mode**
The app is designed to demonstrate features even without:
- Native device permissions
- Actual WiFi scanning capabilities
- Real hardware access
- Production build environment

#### 3. **Cross-Platform Compatibility**
Simulated data ensures the app works consistently across:
- iOS devices
- Android devices
- Expo Go environment
- Development mode
- Testing environments

## Data Source Indicator

The app displays a badge showing the current data source:

- **"Real Device Data"** ✓ (Green) - Using actual device APIs and sensors
- **"Simulated Data"** ℹ️ (Orange) - Using mock data for demonstration

This indicator appears in the header of the Mobile Protection screen.

## What Shows Simulated Data

When using Expo Go or development builds without native modules:

### 1. Device Health
```typescript
dataSource: 'mock'
```
- Battery level
- Storage information
- Memory usage
- Device model/brand
- Security status (jailbreak/root detection)

### 2. WiFi Security Scan
- Network list (generated mock networks)
- Security ratings
- Threat detection
- Channel analysis
- Evil twin detection

### 3. Privacy Audit
- Permission usage tracking
- App privacy scores
- Tracker detection
- Data access logs

### 4. Network Traffic
- Active connections
- Traffic statistics
- Suspicious activities
- Blocked domains

## How to Get REAL Data

To display real device data instead of simulated data:

### Option 1: Build Standalone App (Recommended)
```bash
cd mobile
npx eas build --platform android
# or
npx eas build --platform ios
```

This creates a production build with all native modules properly installed.

### Option 2: Development Build with Native Modules
```bash
cd mobile
npx expo install react-native-device-info expo-network
npx expo prebuild
npx expo run:android
# or
npx expo run:ios
```

### Option 3: Add Required Permissions

For Android (`mobile/app.json`):
```json
{
  "expo": {
    "android": {
      "permissions": [
        "ACCESS_WIFI_STATE",
        "ACCESS_NETWORK_STATE",
        "ACCESS_FINE_LOCATION",
        "READ_PHONE_STATE"
      ]
    }
  }
}
```

For iOS (`mobile/app.json`):
```json
{
  "expo": {
    "ios": {
      "infoPlist": {
        "NSLocationWhenInUseUsageDescription": "Required for WiFi scanning",
        "NSLocationAlwaysUsageDescription": "Required for WiFi scanning"
      }
    }
  }
}
```

## Backend API Behavior

The backend `/api/wifi/scan` endpoint also returns simulated data because:

1. **The backend server cannot access your phone's WiFi networks**
2. Backend runs on your PC, not on the mobile device
3. WiFi scanning must happen on the device itself

The backend is designed to:
- Store and sync scan results
- Provide threat intelligence
- Manage security policies
- NOT perform actual device WiFi scanning

## Current Implementation Status

### ✅ Working with Simulated Data
- Complete UI/UX demonstration
- All features visible and testable
- No crashes or errors
- Proper error handling
- Fallback mechanisms

### 🔨 Requires Native Build for Real Data
- Actual WiFi network scanning
- Real device health metrics
- True permission monitoring
- Live network traffic analysis

## Testing the App

### In Expo Go (Current)
```bash
cd mobile
npx expo start --go
```
- Shows simulated data
- Perfect for UI/UX testing
- No permissions required
- Instant updates

### Production Build
```bash
npx eas build --platform android --profile production
```
- Shows real device data
- Requires permissions
- Full native capabilities
- App store ready

## Summary

**The mobile protection features are working correctly.** The simulated data you're seeing is:

1. ✅ Expected behavior in Expo Go
2. ✅ Intentional design for development
3. ✅ Clearly indicated with badges
4. ✅ Demonstrates all features properly

To get real data, build a standalone app with native modules. The simulated data mode allows you to develop, test, and demonstrate the app without requiring a production build.

---

**Last Updated:** November 7, 2025
**Status:** Working as Designed
**Data Source:** Simulated (Expo Go) / Real (Standalone Build)
