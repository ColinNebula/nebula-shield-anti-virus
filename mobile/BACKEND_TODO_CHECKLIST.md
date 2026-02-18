# Backend Integration TODO Checklist

## 🎯 Quick Reference for Backend Integration

This file lists all locations where backend integration is needed. Search for these patterns in the codebase:

```
// TODO: Uncomment when backend endpoint is ready
```

---

## 📋 Files Requiring Backend Integration

### 1. ApiService.ts
**File**: `mobile/src/services/ApiService.ts`

**Status**: ⚠️ Needs backend URL configuration

**Tasks**:
- [ ] Update `baseURL` with production backend URL
- [ ] Implement token storage and retrieval
- [ ] Add refresh token logic
- [ ] Implement request retry mechanism
- [ ] Add offline queue for failed requests

**Lines**: Throughout file

---

### 2. NetworkTrafficService.ts
**File**: `mobile/src/services/NetworkTrafficService.ts`

**Status**: ⚠️ 10 endpoints to integrate

**Endpoints to Uncomment**:
- [ ] Line ~150: `getActiveConnections()` - GET /api/network/connections
- [ ] Line ~170: `getTrafficStats()` - GET /api/network/stats
- [ ] Line ~185: `getAppTrafficData()` - GET /api/network/apps
- [ ] Line ~271: `getFirewallRules()` - GET /api/network/firewall/rules
- [ ] Line ~278: `addFirewallRule()` - POST /api/network/firewall/rules
- [ ] Line ~288: `removeFirewallRule()` - DELETE /api/network/firewall/rules/{id}
- [ ] Line ~295: `getBlockedTrackers()` - GET /api/network/trackers/blocked
- [ ] Line ~320: `getSuspiciousActivities()` - GET /api/network/threats/activities
- [ ] Line ~340: `getSuspiciousServers()` - GET /api/network/threats/servers
- [ ] Line ~360: `blockServer()` - POST /api/network/threats/block

**Mock Data to Remove**:
- [ ] `generateMockConnections()`
- [ ] `generateMockStats()`
- [ ] `generateMockAppTraffic()`
- [ ] `generateMockFirewallRules()`
- [ ] `generateMockTrackers()`
- [ ] `generateMockSuspiciousActivities()`
- [ ] `generateMockSuspiciousServers()`

---

### 3. WiFiSecurityService.ts
**File**: `mobile/src/services/WiFiSecurityService.ts`

**Status**: ⚠️ 3 endpoints to integrate

**Endpoints to Uncomment**:
- [ ] Line ~50: `scanWiFiNetworks()` - GET /api/wifi/scan
- [ ] Line ~80: `analyzeChannelInterference()` - GET /api/wifi/channel-analysis
- [ ] Line ~100: `detectEvilTwins()` - GET /api/wifi/evil-twins

**Mock Data to Remove**:
- [ ] Mock network generation (6 sample networks)
- [ ] Router vendor detection (move to backend)
- [ ] Evil twin detection algorithm (move to backend)

---

### 4. PrivacyAuditService.ts
**File**: `mobile/src/services/PrivacyAuditService.ts`

**Status**: ⚠️ 5 endpoints to integrate

**Endpoints to Uncomment**:
- [ ] Line ~60: `getAppPermissions()` - GET /api/privacy/permissions
- [ ] Line ~80: `getPermissionTimeline()` - GET /api/privacy/permissions/timeline
- [ ] Line ~100: `checkDataBreaches()` - GET /api/privacy/breaches
- [ ] Line ~120: `getPermissionRecommendations()` - GET /api/privacy/recommendations
- [ ] Line ~140: `getPermissionAnalytics()` - GET /api/privacy/analytics

**Mock Data to Remove**:
- [ ] `generateMockPermissions()`
- [ ] `generateMockTimeline()`
- [ ] `generateMockBreaches()`
- [ ] `generateMockRecommendations()`
- [ ] `generateMockAnalytics()`

---

### 5. SecureBrowserService.ts
**File**: `mobile/src/services/SecureBrowserService.ts`

**Status**: ⚠️ 15+ endpoints to integrate

**Endpoints to Uncomment**:
- [ ] Line ~170: `getDNSSettings()` - GET /api/browser/dns/settings
- [ ] Line ~180: `updateDNSSettings()` - PUT /api/browser/dns/settings
- [ ] Line ~200: `getFingerprintProtection()` - GET /api/browser/fingerprint/settings
- [ ] Line ~210: `updateFingerprintProtection()` - PUT /api/browser/fingerprint/settings
- [ ] Line ~240: `getDownloads()` - GET /api/browser/downloads
- [ ] Line ~300: `getBookmarks()` - GET /api/browser/bookmarks
- [ ] Line ~320: `addBookmark()` - POST /api/browser/bookmarks
- [ ] Line ~330: `deleteBookmark()` - DELETE /api/browser/bookmarks/{id}
- [ ] Line ~360: `getScriptBlocking()` - GET /api/browser/scripts/settings
- [ ] Line ~370: `updateScriptBlocking()` - PUT /api/browser/scripts/settings
- [ ] Line ~400: `getPrivacyMetrics()` - GET /api/browser/privacy/metrics
- [ ] Line ~430: `checkPhishing()` - POST /api/browser/phishing/check
- [ ] Line ~480: `getWebsitePrivacyScore()` - POST /api/browser/privacy-score
- [ ] Line ~550: `getCookies()` - GET /api/browser/cookies
- [ ] Line ~570: `deleteCookies()` - DELETE /api/browser/cookies
- [ ] Line ~580: `getBrowsingHistory()` - GET /api/browser/history
- [ ] Line ~600: `clearHistory()` - DELETE /api/browser/history

**Mock Data to Remove**:
- [ ] All mock cookie generation
- [ ] Mock history generation
- [ ] Mock download items
- [ ] Mock bookmarks
- [ ] Privacy score calculation (move to backend)

---

### 6. DeviceHealthService.ts
**File**: `mobile/src/services/DeviceHealthService.ts`

**Status**: ⚠️ 1 endpoint to integrate

**Endpoints to Uncomment**:
- [ ] Line ~40: `getSystemHealth()` - GET /api/device/health

**Mock Data to Remove**:
- [ ] Mock health score calculation
- [ ] Mock component scores

---

## 🔍 Search Patterns

Use these commands to find all TODO comments:

### PowerShell
```powershell
# Find all TODO comments
Get-ChildItem -Path "mobile\src\services" -Filter "*.ts" -Recurse | Select-String "TODO:" | Select-Object Path, LineNumber, Line

# Count TODO comments
(Get-ChildItem -Path "mobile\src\services" -Filter "*.ts" -Recurse | Select-String "TODO:").Count
```

### VS Code Search
```
Search: TODO: Uncomment when backend
Include: mobile/src/services/**/*.ts
```

---

## ✅ Integration Progress Tracker

### Phase 1: Core Authentication (Priority: Critical)
- [ ] Setup backend URL in ApiService
- [ ] Test login endpoint
- [ ] Test register endpoint
- [ ] Test 2FA flow
- [ ] Implement token storage
- [ ] Implement token refresh

**Estimated Time**: 2-4 hours

---

### Phase 2: Network Traffic (Priority: High)
- [ ] Integrate active connections endpoint
- [ ] Integrate traffic stats endpoint
- [ ] Integrate app traffic data endpoint
- [ ] Test firewall rule CRUD operations
- [ ] Integrate tracker blocking
- [ ] Integrate threat detection

**Estimated Time**: 4-6 hours

---

### Phase 3: WiFi Security (Priority: Medium)
- [ ] Integrate WiFi scanning
- [ ] Integrate channel analysis
- [ ] Integrate evil twin detection
- [ ] Test security threat detection

**Estimated Time**: 2-3 hours

---

### Phase 4: Privacy Audit (Priority: High)
- [ ] Integrate permission monitoring
- [ ] Integrate timeline tracking
- [ ] Integrate data breach checking
- [ ] Integrate recommendations engine
- [ ] Integrate analytics dashboard

**Estimated Time**: 3-4 hours

---

### Phase 5: Secure Browser (Priority: Medium)
- [ ] Integrate phishing detection
- [ ] Integrate privacy scoring
- [ ] Integrate cookie management
- [ ] Integrate history management
- [ ] Integrate download manager
- [ ] Integrate bookmark system
- [ ] Integrate DNS settings
- [ ] Integrate fingerprint protection
- [ ] Integrate privacy metrics

**Estimated Time**: 6-8 hours

---

### Phase 6: Device Health (Priority: Low)
- [ ] Integrate system health monitoring
- [ ] Test health score calculations

**Estimated Time**: 1-2 hours

---

## 📊 Statistics

**Total Services**: 6
**Total Endpoints**: 40+
**Total TODO Comments**: ~50
**Mock Data Generators**: ~15

**Estimated Total Integration Time**: 18-27 hours

---

## 🚀 Quick Start Guide

### Step 1: Configure Backend URL
```typescript
// mobile/src/services/ApiService.ts
private baseURL = 'https://your-backend-url.com/api';
```

### Step 2: Test Authentication First
```typescript
// Start with login endpoint
const response = await ApiService.login(email, password);
console.log('Login response:', response);
```

### Step 3: Uncomment One Service at a Time
1. Start with NetworkTrafficService
2. Test each endpoint individually
3. Verify data structure matches mock data
4. Remove mock data fallback when confirmed working

### Step 4: Update Error Handling
```typescript
try {
  const result = await ApiService.someEndpoint();
  if (result.success) {
    return result.data;
  }
} catch (error) {
  console.error('API Error:', error);
  // Show user-friendly error message
  Alert.alert('Error', 'Failed to fetch data. Please try again.');
  // Optionally: Return cached data or empty array
}
```

---

## 🔒 Security Checklist

- [ ] Use HTTPS in production
- [ ] Implement certificate pinning
- [ ] Store tokens securely (AsyncStorage with encryption)
- [ ] Implement token expiration handling
- [ ] Add request signing for sensitive operations
- [ ] Sanitize all user inputs
- [ ] Validate all API responses
- [ ] Implement rate limiting on client side
- [ ] Add request timeout handling
- [ ] Implement proper error logging (without exposing sensitive data)

---

## 📝 Notes

- All mock data is designed to match expected backend response format
- Each TODO comment includes the expected endpoint and response structure
- Services are designed to gracefully fallback to mock data during development
- Remove mock data generators only after confirming backend endpoints work
- Keep mock data generation for testing purposes

---

## 📞 Quick Help

**Finding TODOs**: 
```
Ctrl+Shift+F in VS Code → Search "TODO: Uncomment"
```

**Testing API Calls**:
```typescript
// Enable API logging
console.log('API Request:', endpoint, options);
console.log('API Response:', response);
```

**Common Issues**:
1. **CORS Error**: Configure backend CORS headers
2. **401 Unauthorized**: Check token is being sent correctly
3. **Network Error**: Verify backend URL and network connectivity
4. **Data Mismatch**: Compare mock data structure with actual API response

---

Last Updated: November 6, 2025
