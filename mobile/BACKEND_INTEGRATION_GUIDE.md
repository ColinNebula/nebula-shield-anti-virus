# Backend Integration Guide

## 📋 Overview

This guide provides all required backend endpoints for the Nebula Shield mobile app. All services currently use mock data with TODO comments marking integration points.

---

## 🔐 Authentication Endpoints

### Base URL
```
http://your-backend-url/api/auth
```

### Endpoints

#### 1. Login
```http
POST /login
Content-Type: application/json

Request:
{
  "email": "string",
  "password": "string"
}

Response:
{
  "success": true,
  "token": "string",
  "user": {
    "id": "string",
    "email": "string",
    "name": "string",
    "twoFactorEnabled": boolean
  }
}
```

#### 2. Register
```http
POST /register
Content-Type: application/json

Request:
{
  "email": "string",
  "password": "string",
  "name": "string"
}

Response:
{
  "success": true,
  "message": "Registration successful"
}
```

#### 3. Forgot Password
```http
POST /forgot-password
Content-Type: application/json

Request:
{
  "email": "string"
}

Response:
{
  "success": true,
  "message": "Password reset email sent"
}
```

#### 4. Enable 2FA
```http
POST /2fa/enable
Content-Type: application/json
Authorization: Bearer {token}

Response:
{
  "success": true,
  "qrCode": "string (base64 image)",
  "secret": "string"
}
```

#### 5. Verify 2FA
```http
POST /2fa/verify
Content-Type: application/json
Authorization: Bearer {token}

Request:
{
  "code": "string"
}

Response:
{
  "success": true,
  "message": "2FA verified successfully"
}
```

---

## 📡 Network Traffic Endpoints

### Base URL
```
http://your-backend-url/api/network
```

### Endpoints

#### 1. Get Active Connections
```http
GET /connections
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "packageName": "string",
      "destination": "string",
      "ip": "string",
      "port": number,
      "protocol": "TCP" | "UDP" | "HTTP" | "HTTPS",
      "bytesSent": number,
      "bytesReceived": number,
      "status": "active" | "established" | "closed",
      "threat": "none" | "low" | "medium" | "high",
      "timestamp": "ISO8601 string"
    }
  ]
}
```

#### 2. Get Traffic Stats
```http
GET /stats
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "totalConnections": number,
    "activeConnections": number,
    "bytesReceived": number,
    "bytesSent": number,
    "blockedConnections": number,
    "averageSpeed": number,
    "peakSpeed": number
  }
}
```

#### 3. Get App Traffic Data
```http
GET /apps
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "packageName": "string",
      "icon": "string (base64 or URL)",
      "dataUsed": number,
      "dataReceived": number,
      "dataSent": number,
      "connections": number,
      "blocked": number,
      "threat": "low" | "medium" | "high",
      "lastActive": "ISO8601 string"
    }
  ]
}
```

#### 4. Get Firewall Rules
```http
GET /firewall/rules
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "packageName": "string",
      "type": "block_all" | "wifi_only" | "cellular_only" | "allow_all",
      "enabled": boolean,
      "created": "ISO8601 string"
    }
  ]
}
```

#### 5. Add Firewall Rule
```http
POST /firewall/rules
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "app": "string",
  "packageName": "string",
  "type": "block_all" | "wifi_only" | "cellular_only" | "allow_all"
}

Response:
{
  "success": true,
  "message": "Firewall rule added successfully"
}
```

#### 6. Delete Firewall Rule
```http
DELETE /firewall/rules/{ruleId}
Authorization: Bearer {token}

Response:
{
  "success": true,
  "message": "Firewall rule deleted"
}
```

#### 7. Get Blocked Trackers
```http
GET /trackers/blocked
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "domain": "string",
      "tracker": "string",
      "category": "analytics" | "advertising" | "social" | "fingerprinting",
      "app": "string",
      "count": number,
      "lastBlocked": "ISO8601 string"
    }
  ]
}
```

#### 8. Get Suspicious Activities
```http
GET /threats/activities
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "type": "data_exfiltration" | "suspicious_connection" | "malware_communication" | "port_scan",
      "severity": "low" | "medium" | "high" | "critical",
      "description": "string",
      "timestamp": "ISO8601 string",
      "blocked": boolean
    }
  ]
}
```

#### 9. Get Suspicious Servers
```http
GET /threats/servers
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "domain": "string",
      "ip": "string",
      "country": "string",
      "threatType": "malware" | "phishing" | "c2" | "botnet",
      "severity": "medium" | "high" | "critical",
      "connections": number,
      "lastSeen": "ISO8601 string",
      "blocked": boolean
    }
  ]
}
```

#### 10. Block Server
```http
POST /threats/block
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "ip": "string"
}

Response:
{
  "success": true,
  "message": "Server blocked successfully"
}
```

---

## 📶 WiFi Security Endpoints

### Base URL
```
http://your-backend-url/api/wifi
```

### Endpoints

#### 1. Scan WiFi Networks
```http
GET /scan
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "ssid": "string",
      "bssid": "string",
      "security": "WPA3" | "WPA2" | "WPA" | "WEP" | "Open",
      "signalStrength": number,
      "frequency": number,
      "channel": number,
      "isSecure": boolean,
      "isConnected": boolean,
      "threats": ["string"],
      "routerVendor": "string",
      "estimatedSpeed": number,
      "channelWidth": number,
      "interferenceLevel": "low" | "medium" | "high",
      "congestionScore": number,
      "uptime": number,
      "connectedDevices": number
    }
  ]
}
```

#### 2. Get Channel Analysis
```http
GET /channel-analysis
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "channel": number,
    "frequency": number,
    "congestion": number,
    "interference": number,
    "recommendedChannel": number,
    "nearbyNetworks": number
  }
}
```

#### 3. Detect Evil Twins
```http
GET /evil-twins
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "ssid": "string",
      "networks": [
        {
          "bssid": "string",
          "signalStrength": number,
          "vendor": "string"
        }
      ],
      "suspicionLevel": "low" | "medium" | "high"
    }
  ]
}
```

---

## 🔒 Privacy Audit Endpoints

### Base URL
```
http://your-backend-url/api/privacy
```

### Endpoints

#### 1. Get App Permissions
```http
GET /permissions
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "packageName": "string",
      "icon": "string",
      "permissions": {
        "camera": boolean,
        "microphone": boolean,
        "location": boolean,
        "contacts": boolean,
        "storage": boolean
      },
      "lastAccessed": "ISO8601 string",
      "frequency": "never" | "rarely" | "sometimes" | "often",
      "riskLevel": "low" | "medium" | "high"
    }
  ]
}
```

#### 2. Get Permission Timeline
```http
GET /permissions/timeline?days=30
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "permission": "camera" | "microphone" | "location" | "contacts" | "storage",
      "action": "granted" | "denied" | "accessed",
      "timestamp": "ISO8601 string"
    }
  ]
}
```

#### 3. Check Data Breaches
```http
GET /breaches
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "service": "string",
      "date": "ISO8601 string",
      "description": "string",
      "affectedAccounts": number,
      "dataTypes": ["string"],
      "severity": "low" | "medium" | "high" | "critical",
      "status": "unresolved" | "acknowledged" | "resolved"
    }
  ]
}
```

#### 4. Get Permission Recommendations
```http
GET /recommendations
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "app": "string",
      "packageName": "string",
      "permission": "string",
      "reason": "string",
      "action": "revoke" | "review" | "restrict",
      "priority": "low" | "medium" | "high",
      "impact": "string"
    }
  ]
}
```

#### 5. Get Permission Analytics
```http
GET /analytics
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "totalApps": number,
    "totalPermissions": number,
    "highRiskApps": number,
    "unusedPermissions": number,
    "byPermissionType": {
      "camera": number,
      "microphone": number,
      "location": number,
      "contacts": number,
      "storage": number
    },
    "trend": "increasing" | "stable" | "decreasing",
    "last30Days": {
      "granted": number,
      "revoked": number,
      "accessed": number
    }
  }
}
```

---

## 🌐 Secure Browser Endpoints

### Base URL
```
http://your-backend-url/api/browser
```

### Endpoints

#### 1. Check Phishing
```http
POST /phishing/check
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "url": "string"
}

Response:
{
  "success": true,
  "data": {
    "url": "string",
    "isPhishing": boolean,
    "isSafe": boolean,
    "threatLevel": "safe" | "low" | "medium" | "high" | "critical",
    "threatType": "phishing" | "malware" | "social_engineering" | "fake_site" | "data_theft",
    "description": "string",
    "indicators": ["string"],
    "recommendation": "string"
  }
}
```

#### 2. Get Website Privacy Score
```http
POST /privacy-score
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "url": "string"
}

Response:
{
  "success": true,
  "data": {
    "url": "string",
    "domain": "string",
    "overall": number,
    "rating": "excellent" | "good" | "fair" | "poor" | "critical",
    "breakdown": {
      "https": number,
      "cookies": number,
      "trackers": number,
      "ads": number,
      "security": number
    },
    "risks": [
      {
        "id": "string",
        "type": "privacy" | "security" | "tracking" | "data_collection",
        "severity": "low" | "medium" | "high" | "critical",
        "title": "string",
        "description": "string",
        "detected": "ISO8601 string"
      }
    ],
    "recommendations": ["string"],
    "certificate": {
      "issuer": "string",
      "validFrom": "ISO8601 string",
      "validTo": "ISO8601 string",
      "isValid": boolean,
      "algorithm": "string",
      "keySize": number
    }
  }
}
```

#### 3. Get Cookies
```http
GET /cookies?domain={domain}
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "name": "string",
      "domain": "string",
      "value": "string",
      "path": "string",
      "expires": "ISO8601 string",
      "secure": boolean,
      "httpOnly": boolean,
      "sameSite": "strict" | "lax" | "none",
      "size": number,
      "category": "necessary" | "functional" | "analytics" | "advertising",
      "blocked": boolean
    }
  ]
}
```

#### 4. Delete Cookies
```http
DELETE /cookies
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "domain": "string (optional)",
  "category": "string (optional)"
}

Response:
{
  "success": true,
  "message": "Cookies deleted successfully"
}
```

#### 5. Get Browsing History
```http
GET /history?days=7
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "url": "string",
      "title": "string",
      "domain": "string",
      "timestamp": "ISO8601 string",
      "privacyScore": number,
      "blocked": {
        "ads": number,
        "trackers": number
      }
    }
  ]
}
```

#### 6. Get Blocking Stats
```http
GET /stats
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "totalBlocked": number,
    "ads": number,
    "trackers": number,
    "malicious": number,
    "cookies": number,
    "bandwidthSaved": number,
    "timeSaved": number
  }
}
```

#### 7. Get Downloads
```http
GET /downloads
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "url": "string",
      "filename": "string",
      "mimeType": "string",
      "size": number,
      "downloaded": number,
      "status": "pending" | "downloading" | "completed" | "failed" | "paused",
      "threat": "safe" | "suspicious" | "malicious",
      "timestamp": "ISO8601 string",
      "path": "string",
      "error": "string"
    }
  ]
}
```

#### 8. Get Bookmarks
```http
GET /bookmarks?folder={folder}
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": [
    {
      "id": "string",
      "url": "string",
      "title": "string",
      "favicon": "string",
      "folder": "string",
      "tags": ["string"],
      "created": "ISO8601 string",
      "accessed": "ISO8601 string",
      "visitCount": number
    }
  ]
}
```

#### 9. Add Bookmark
```http
POST /bookmarks
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "url": "string",
  "title": "string",
  "folder": "string",
  "tags": ["string"]
}

Response:
{
  "success": true,
  "data": {
    "id": "string",
    "url": "string",
    "title": "string",
    "folder": "string",
    "tags": ["string"],
    "created": "ISO8601 string"
  }
}
```

#### 10. Delete Bookmark
```http
DELETE /bookmarks/{bookmarkId}
Authorization: Bearer {token}

Response:
{
  "success": true,
  "message": "Bookmark deleted"
}
```

#### 11. Get DNS Settings
```http
GET /dns/settings
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "provider": "cloudflare" | "google" | "quad9" | "custom",
    "dnsOverHttps": boolean,
    "dnsOverTls": boolean,
    "customServers": ["string"],
    "blockMalware": boolean,
    "blockTrackers": boolean,
    "blockAdult": boolean
  }
}
```

#### 12. Update DNS Settings
```http
PUT /dns/settings
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "provider": "cloudflare" | "google" | "quad9" | "custom",
  "dnsOverHttps": boolean,
  "dnsOverTls": boolean,
  "customServers": ["string"],
  "blockMalware": boolean,
  "blockTrackers": boolean,
  "blockAdult": boolean
}

Response:
{
  "success": true,
  "message": "DNS settings updated"
}
```

#### 13. Get Fingerprint Protection
```http
GET /fingerprint/settings
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "enabled": boolean,
    "blockCanvas": boolean,
    "blockWebGL": boolean,
    "blockWebRTC": boolean,
    "blockAudioContext": boolean,
    "spoofUserAgent": boolean,
    "spoofTimezone": boolean,
    "spoofLanguage": boolean,
    "protectionLevel": "low" | "medium" | "high" | "maximum"
  }
}
```

#### 14. Update Fingerprint Protection
```http
PUT /fingerprint/settings
Authorization: Bearer {token}
Content-Type: application/json

Request:
{
  "enabled": boolean,
  "blockCanvas": boolean,
  "blockWebGL": boolean,
  "blockWebRTC": boolean,
  "blockAudioContext": boolean,
  "spoofUserAgent": boolean,
  "spoofTimezone": boolean,
  "spoofLanguage": boolean,
  "protectionLevel": "low" | "medium" | "high" | "maximum"
}

Response:
{
  "success": true,
  "message": "Fingerprint protection updated"
}
```

#### 15. Get Privacy Metrics
```http
GET /privacy/metrics
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "sessionStart": "ISO8601 string",
    "totalRequests": number,
    "blockedRequests": number,
    "httpsUpgrades": number,
    "cookiesBlocked": number,
    "trackersBlocked": number,
    "adsBlocked": number,
    "fingerprintingAttempts": number,
    "maliciousBlocked": number,
    "bandwidthSaved": number,
    "privacyScore": number
  }
}
```

---

## 📱 Device Health Endpoints

### Base URL
```
http://your-backend-url/api/device
```

### Endpoints

#### 1. Get System Health
```http
GET /health
Authorization: Bearer {token}

Response:
{
  "success": true,
  "data": {
    "overall": number,
    "status": "excellent" | "good" | "fair" | "poor",
    "components": {
      "battery": number,
      "storage": number,
      "memory": number,
      "security": number,
      "performance": number
    },
    "issues": ["string"],
    "recommendations": ["string"]
  }
}
```

---

## 🔧 Integration Steps

### 1. Update ApiService
Edit `mobile/src/services/ApiService.ts`:

```typescript
class ApiService {
  private baseURL = 'YOUR_BACKEND_URL'; // Update this
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }

  private getHeaders() {
    return {
      'Content-Type': 'application/json',
      ...(this.token ? { 'Authorization': `Bearer ${this.token}` } : {})
    };
  }

  async request(endpoint: string, options: RequestInit = {}) {
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      headers: {
        ...this.getHeaders(),
        ...options.headers
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }
}
```

### 2. Uncomment Backend Calls
Search for `// TODO: Uncomment when backend endpoint is ready` in all service files and uncomment the API calls.

### 3. Remove Mock Data Fallbacks
Once backend is working, remove the mock data generators and fallback logic.

### 4. Update Error Handling
Add proper error handling and user-friendly error messages.

### 5. Test Integration
Test each endpoint with real backend before removing mock data.

---

## 📍 Files to Update

1. **Authentication**
   - `mobile/src/services/ApiService.ts` - Add authentication methods
   - `mobile/src/screens/LoginScreen.tsx` - Uncomment API calls

2. **Network Traffic**
   - `mobile/src/services/NetworkTrafficService.ts` - Uncomment all endpoint calls
   - Remove mock data generators

3. **WiFi Security**
   - `mobile/src/services/WiFiSecurityService.ts` - Uncomment scan and analysis calls

4. **Privacy Audit**
   - `mobile/src/services/PrivacyAuditService.ts` - Uncomment permissions and breach checks

5. **Secure Browser**
   - `mobile/src/services/SecureBrowserService.ts` - Uncomment all browser-related calls

6. **Device Health**
   - `mobile/src/services/DeviceHealthService.ts` - Uncomment health monitoring calls

---

## ⚠️ Important Notes

1. **Authentication**: All endpoints (except login/register) require Bearer token
2. **Error Handling**: Implement proper error handling for network failures
3. **Rate Limiting**: Consider implementing rate limiting on backend
4. **Data Validation**: Validate all responses on client side
5. **Security**: Use HTTPS in production
6. **CORS**: Configure CORS on backend to allow mobile app origin

---

## 🧪 Testing Checklist

- [ ] Authentication flow (login, register, 2FA)
- [ ] Network traffic monitoring
- [ ] Firewall rule creation and deletion
- [ ] WiFi scanning and analysis
- [ ] Privacy audit and breach checking
- [ ] Browser security features
- [ ] Bookmark and download management
- [ ] Settings persistence
- [ ] Error handling for offline mode
- [ ] Token refresh mechanism

---

## 📞 Support

For backend integration assistance, refer to individual service files where each TODO comment indicates the exact endpoint and expected response format.
