# Authentication Hardening Guide 🔐

## Overview
Advanced authentication security with device fingerprinting, behavioral biometrics, anomalous login detection, and session hijacking prevention.

## Features

### 1. Device Fingerprinting
Creates unique device identifiers based on:
- **Hardware**: CPU, memory, MAC addresses, platform, architecture
- **Software**: OS version, timezone, language, screen resolution
- **Browser**: Canvas fingerprint, WebGL, installed fonts, plugins
- **Network**: IP address, VPN/Tor/proxy detection

### 2. Behavioral Biometrics
Analyzes user behavior patterns:
- **Typing Patterns**: Keystroke dynamics and rhythm
- **Mouse Movement**: Speed, acceleration, patterns
- **Navigation Patterns**: Common page sequences and paths
- **Time Patterns**: Active hours and session durations
- **Interaction Patterns**: Click frequency, scroll behavior

### 3. Anomalous Login Detection
Detects suspicious login attempts:
- **Impossible Travel**: Geographically impossible location changes
- **New Country/Region**: First-time access from new locations
- **VPN/Tor Detection**: Anonymization tool usage
- **Suspicious Regions**: High-risk geographical areas
- **Time Anomalies**: Unusual access times

### 4. Session Hijacking Prevention
Protects active sessions:
- **Session Binding**: Bind to IP, user agent, device fingerprint
- **Activity Monitoring**: Track session activity patterns
- **Location Tracking**: Detect location jumps
- **Timeout Management**: Automatic session expiration
- **Anomaly Detection**: Identify suspicious session behavior

## API Reference

### AuthenticationHardeningService

#### Generate Device Fingerprint
```javascript
const fingerprint = await AuthService.generateDeviceFingerprint({
  userAgent: 'Mozilla/5.0...',
  language: 'en-US',
  screenResolution: '1920x1080',
  ipAddress: '192.168.1.100',
  canvasFingerprint: 'abc123...',
  webglFingerprint: 'def456...',
  installedFonts: ['Arial', 'Helvetica', 'Times New Roman'],
  plugins: ['Chrome PDF Plugin', 'Native Client'],
  cookiesEnabled: true,
  doNotTrack: false,
  vpnDetected: false,
  torDetected: false
});

console.log('Device fingerprint hash:', fingerprint.hash);
```

#### Verify Device Fingerprint
```javascript
const verification = AuthService.verifyDeviceFingerprint(
  fingerprintHash,
  currentContext
);

if (verification.verified) {
  console.log('Device verified!');
} else {
  console.log('Device mismatch:', verification.reason);
  console.log('Changes detected:', verification.changes);
}
```

#### Analyze Behavioral Biometrics
```javascript
const analysis = await AuthService.analyzeBehavioralBiometrics(userId, {
  typing: {
    avgSpeed: 250, // ms per keystroke
    rhythm: [200, 240, 260, 230]
  },
  mouse: {
    avgSpeed: 150, // pixels per second
    patterns: [[100, 200], [150, 250], [200, 300]]
  },
  navigation: {
    path: '/dashboard -> /settings -> /profile',
    sequence: ['dashboard', 'settings', 'profile']
  },
  timestamp: new Date().toISOString(),
  sessionStart: Date.now() - 3600000 // 1 hour ago
});

console.log('Overall score:', analysis.overallScore);
console.log('Trust level:', analysis.trustLevel);
console.log('Anomalies:', analysis.anomalies);
```

#### Detect Anomalous Location
```javascript
const locationCheck = await AuthService.detectAnomalousLocation(userId, {
  coordinates: { lat: 40.7128, lon: -74.0060 },
  country: 'US',
  city: 'New York',
  region: 'NY',
  timestamp: new Date().toISOString(),
  vpnDetected: false,
  torDetected: false
});

if (locationCheck.anomalous) {
  console.log('Anomalous login!');
  console.log('Reason:', locationCheck.reason);
  console.log('Risk score:', locationCheck.riskScore);
  console.log('Details:', locationCheck.details);
}
```

#### Create Authenticated Session
```javascript
const session = await AuthService.createSession(userId, {
  ipAddress: '192.168.1.100',
  userAgent: 'Mozilla/5.0...',
  location: {
    coordinates: { lat: 40.7128, lon: -74.0060 },
    country: 'US',
    city: 'New York',
    vpnDetected: false,
    torDetected: false
  }
});

if (session.success) {
  console.log('Session created:', session.sessionId);
  
  if (session.requireMFA) {
    console.log('MFA required due to risk score:', session.riskScore);
  }
} else {
  console.log('Login failed:', session.reason);
}
```

#### Prevent Session Hijacking
```javascript
const hijackCheck = await AuthService.preventSessionHijacking(sessionId, {
  ipAddress: '192.168.1.100',
  userAgent: 'Mozilla/5.0...',
  fingerprint: fingerprintHash,
  location: {
    coordinates: { lat: 40.7128, lon: -74.0060 }
  }
});

if (hijackCheck.hijacked) {
  console.log('Session hijacking detected!');
  console.log('Probability:', hijackCheck.probability);
  console.log('Checks failed:', hijackCheck.checks);
  // Session automatically terminated
} else {
  console.log('Session valid');
}
```

#### Terminate Session
```javascript
const terminated = AuthService.terminateSession(sessionId, 'USER_LOGOUT');
console.log('Session terminated:', terminated);
```

#### Record Failed Login
```javascript
AuthService.recordFailedLogin(userId, {
  ipAddress: '192.168.1.100',
  userAgent: 'Mozilla/5.0...',
  reason: 'INVALID_PASSWORD'
});
```

## Event Emissions

```javascript
// Service initialized
AuthService.on('service-initialized', () => {
  console.log('Authentication hardening active');
});

// Fingerprint generated
AuthService.on('fingerprint-generated', (fingerprint) => {
  console.log('New device fingerprint:', fingerprint.hash);
});

// Behavior analyzed
AuthService.on('behavior-analyzed', (analysis) => {
  console.log(`User ${analysis.userId} trust level: ${analysis.trustLevel}`);
});

// Location analyzed
AuthService.on('location-analyzed', ({ userId, analysis }) => {
  if (analysis.anomalous) {
    console.log(`Anomalous login for ${userId}: ${analysis.reason}`);
  }
});

// Session created
AuthService.on('session-created', (session) => {
  console.log(`Session ${session.id} created for user ${session.userId}`);
});

// Session terminated
AuthService.on('session-terminated', ({ sessionId, reason }) => {
  console.log(`Session ${sessionId} terminated: ${reason}`);
});

// Session hijacking detected
AuthService.on('session-hijack-detected', ({ sessionId, context }) => {
  console.log(`ALERT: Session hijacking detected for ${sessionId}`);
  // Trigger security incident response
});

// Account locked
AuthService.on('account-locked', ({ userId, attempts }) => {
  console.log(`Account ${userId} locked after ${attempts} failed attempts`);
});
```

## Configuration

### Customizable Settings
```javascript
// In AuthenticationHardeningService constructor or config:
{
  maxLoginAttempts: 5,           // Failed attempts before lockout
  lockoutDuration: 900000,       // 15 minutes in ms
  sessionTimeout: 1800000,       // 30 minutes in ms
  behavioralThreshold: 0.7,      // 70% similarity threshold
  mfaRiskThreshold: 0.3,         // Trigger MFA above 30% risk
  fingerprintSimilarity: 0.85    // 85% match required
}
```

## Security Workflow

### Login Flow
```
1. User submits credentials
   ↓
2. Generate device fingerprint
   ↓
3. Check against known devices
   ↓
4. Analyze login location
   ↓
5. Calculate risk score
   ↓
6. If risk > threshold → Require MFA
   ↓
7. Create session with monitoring
   ↓
8. Continuous behavioral analysis
```

### Session Protection Flow
```
Every Request:
1. Extract session ID
   ↓
2. Verify session exists
   ↓
3. Check session timeout
   ↓
4. Compare current context:
   - IP address
   - User agent
   - Device fingerprint
   - Location
   ↓
5. Calculate hijacking probability
   ↓
6. If hijacked → Terminate session
   ↓
7. Update session activity
```

## Behavioral Learning

The system learns user behavior over time:

### Initial Login (Cold Start)
- **Trust Level**: HIGH (benefit of doubt)
- **Confidence**: LOW (no baseline)
- **Action**: Collect behavioral data

### After 10+ Sessions
- **Trust Level**: Based on score
- **Confidence**: MEDIUM
- **Action**: Compare against baseline

### After 20+ Sessions
- **Trust Level**: Highly accurate
- **Confidence**: HIGH
- **Action**: Strict anomaly detection

## Risk Scoring

### Location Risk Factors
- **Impossible Travel**: +0.4 (40%)
- **New Country**: +0.3 (30%)
- **VPN/Tor**: +0.2 (20%)
- **Suspicious Region**: +0.1 (10%)

### Session Risk Factors
- **IP Mismatch**: +0.25 (25%)
- **User Agent Change**: +0.20 (20%)
- **Fingerprint Mismatch**: +0.30 (30%)
- **Location Jump**: +0.25 (25%)

### MFA Triggers
- Risk score > 0.3 (30%)
- New device
- New country
- VPN/Tor detected
- Behavioral anomalies detected

## Device Fingerprint Components

### Hardware Fingerprint
```json
{
  "cpu": {
    "model": "Intel(R) Core(TM) i7-9700K",
    "cores": 8,
    "speed": 3600
  },
  "memory": 17179869184,
  "platform": "win32",
  "arch": "x64",
  "hostname": "DESKTOP-ABC123",
  "macAddresses": ["00:11:22:33:44:55"]
}
```

### Browser Fingerprint
```json
{
  "canvas": "hash_of_canvas_rendering",
  "webgl": "hash_of_webgl_rendering",
  "fonts": ["Arial", "Calibri", "Times New Roman"],
  "plugins": ["Chrome PDF Plugin", "Native Client"],
  "cookiesEnabled": true,
  "doNotTrack": false
}
```

## Integration Example

```javascript
import AuthService from './services/AuthenticationHardeningService';
import ForensicsService from './services/ForensicsService';

// User login handler
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // Verify credentials (your existing logic)
  const user = await verifyCredentials(username, password);

  if (!user) {
    // Record failed attempt
    AuthService.recordFailedLogin(username, {
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
      reason: 'INVALID_CREDENTIALS'
    });

    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create session with security checks
  const session = await AuthService.createSession(user.id, {
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    location: await getGeoLocation(req.ip),
    // Pass browser fingerprint from client
    ...req.body.fingerprint
  });

  if (!session.success) {
    return res.status(403).json({ 
      error: session.reason,
      lockoutEnd: session.lockoutEnd
    });
  }

  // Log security event
  ForensicsService.logIncident({
    type: 'USER_LOGIN',
    severity: session.riskScore > 0.5 ? 'high' : 'low',
    source: { ip: req.ip },
    action: 'LOGGED_IN',
    metadata: {
      userId: user.id,
      riskScore: session.riskScore,
      mfaRequired: session.requireMFA
    }
  });

  if (session.requireMFA) {
    return res.json({
      requireMFA: true,
      sessionId: session.sessionId
    });
  }

  res.json({
    sessionId: session.sessionId,
    user: user
  });
});

// Middleware for session validation
app.use(async (req, res, next) => {
  const sessionId = req.headers['x-session-id'];

  if (!sessionId) {
    return res.status(401).json({ error: 'No session' });
  }

  // Check for session hijacking
  const hijackCheck = await AuthService.preventSessionHijacking(sessionId, {
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    fingerprint: req.headers['x-device-fingerprint'],
    location: await getGeoLocation(req.ip)
  });

  if (hijackCheck.hijacked) {
    // Log security incident
    ForensicsService.logIncident({
      type: 'SESSION_HIJACK_ATTEMPT',
      severity: 'critical',
      source: { ip: req.ip },
      action: 'BLOCKED',
      metadata: {
        sessionId,
        probability: hijackCheck.probability,
        checks: hijackCheck.checks
      }
    });

    return res.status(401).json({ error: 'Session invalid' });
  }

  next();
});
```

## Client-Side Fingerprinting

```javascript
// Client-side script to generate fingerprint data
async function generateBrowserFingerprint() {
  // Canvas fingerprint
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillText('Nebula Shield', 2, 2);
  const canvasFingerprint = canvas.toDataURL();

  // WebGL fingerprint
  const gl = canvas.getContext('webgl');
  const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
  const webglFingerprint = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);

  // Installed fonts
  const fonts = ['Arial', 'Calibri', 'Comic Sans MS', 'Courier New', 
                 'Georgia', 'Helvetica', 'Times New Roman', 'Verdana'];
  const installedFonts = fonts.filter(font => isFontAvailable(font));

  // Plugins
  const plugins = Array.from(navigator.plugins).map(p => p.name);

  return {
    userAgent: navigator.userAgent,
    language: navigator.language,
    screenResolution: `${screen.width}x${screen.height}`,
    canvasFingerprint: hashString(canvasFingerprint),
    webglFingerprint,
    installedFonts,
    plugins,
    cookiesEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack === '1'
  };
}

// Send to server during login
const fingerprint = await generateBrowserFingerprint();
fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({
    username,
    password,
    fingerprint
  })
});
```

## Statistics

```javascript
const stats = AuthService.getStatistics();
console.log('Active sessions:', stats.activeSessions);
console.log('Device fingerprints:', stats.deviceFingerprints);
console.log('Behavior profiles:', stats.behaviorProfiles);
console.log('Locked accounts:', stats.lockedAccounts);
```

## Best Practices

1. **Multi-Factor Authentication**: Always enable MFA for high-risk logins
2. **Regular Fingerprint Updates**: Re-fingerprint devices periodically
3. **Behavioral Training**: Allow time for system to learn user patterns
4. **Location Whitelisting**: Let users mark trusted locations
5. **Session Rotation**: Rotate session IDs periodically
6. **Incident Response**: Automatically trigger investigation for hijack attempts
7. **User Notification**: Alert users of suspicious login attempts
8. **Grace Period**: Allow brief IP changes for mobile users

## Troubleshooting

### False Positives
- Adjust `behavioralThreshold` (lower = more lenient)
- Increase `fingerprintSimilarity` tolerance for mobile devices
- Whitelist corporate VPNs

### False Negatives
- Lower `mfaRiskThreshold` to trigger MFA more often
- Decrease `behavioralThreshold` for stricter matching
- Add custom risk factors for your environment

### Session Issues
- Check `sessionTimeout` configuration
- Verify session storage persistence
- Review session cleanup intervals

## Security Considerations

⚠️ **Privacy**: Device fingerprinting may raise privacy concerns
⚠️ **GDPR Compliance**: Ensure proper user consent and data handling
⚠️ **False Positives**: Balance security with user experience
⚠️ **Performance**: Behavioral analysis adds computational overhead
⚠️ **Mobile Users**: Expect more fingerprint changes on mobile devices

## Support

For authentication hardening support:
- Review behavior profiles for accuracy
- Monitor anomalous login alerts
- Tune thresholds based on your user base
- Integrate with your identity provider (IdP)
