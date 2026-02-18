# Advanced Security Features - Quick Reference Card

## 🔐 Authentication Hardening

### Generate Device Fingerprint
```javascript
const fingerprint = await AuthService.generateDeviceFingerprint({
  userAgent: navigator.userAgent,
  language: navigator.language,
  screenResolution: `${screen.width}x${screen.height}`,
  ipAddress: clientIP,
  canvasFingerprint: canvasHash,
  webglFingerprint: webglHash
});
```

### Verify Device
```javascript
const verification = AuthService.verifyDeviceFingerprint(
  fingerprintHash,
  currentContext
);
// Returns: { verified, confidence, reason, changes }
```

### Analyze Behavior
```javascript
const analysis = await AuthService.analyzeBehavioralBiometrics(userId, {
  typing: { avgSpeed: 250, rhythm: [...] },
  mouse: { avgSpeed: 150, patterns: [...] },
  navigation: { path: '/dashboard -> /settings' },
  timestamp: new Date().toISOString()
});
// Returns: { overallScore, trustLevel, anomalies }
```

### Detect Anomalous Location
```javascript
const locationCheck = await AuthService.detectAnomalousLocation(userId, {
  coordinates: { lat: 40.7128, lon: -74.0060 },
  country: 'US',
  city: 'New York',
  vpnDetected: false,
  torDetected: false
});
// Returns: { anomalous, reason, riskScore, details }
```

### Create Secure Session
```javascript
const session = await AuthService.createSession(userId, {
  ipAddress: '192.168.1.100',
  userAgent: 'Mozilla/5.0...',
  location: {...}
});
// Returns: { success, sessionId, requireMFA, riskScore }
```

### Prevent Session Hijacking
```javascript
const hijackCheck = await AuthService.preventSessionHijacking(
  sessionId,
  currentContext
);
// Returns: { hijacked, probability, reason, checks }
```

### Configuration
```javascript
maxLoginAttempts: 5        // Failed attempts before lockout
lockoutDuration: 900000    // 15 minutes
sessionTimeout: 1800000    // 30 minutes
behavioralThreshold: 0.7   // 70% similarity
mfaRiskThreshold: 0.3      // Trigger MFA > 30% risk
```

---

## 📝 Forensics & Reporting

### Log Security Incident
```javascript
const incident = ForensicsService.logIncident({
  type: 'SQL_INJECTION',
  severity: 'high',
  source: { ip: '192.168.1.100', port: 54321 },
  destination: { ip: '10.0.0.50', port: 80 },
  protocol: 'HTTP',
  action: 'BLOCKED'
});
```

### Start PCAP Capture
```javascript
const capture = await ForensicsService.startPCAPCapture({
  interface: 'all',
  filter: 'tcp port 80',
  maxSize: 100 * 1024 * 1024,  // 100MB
  maxDuration: 3600000          // 1 hour
});
```

### Stop PCAP Capture
```javascript
const session = ForensicsService.stopPCAPCapture();
// Returns: { id, startTime, endTime, duration, packetCount }
```

### Analyze PCAP
```javascript
const analysis = await ForensicsService.analyzePCAP('/path/to/file.pcap');
// Returns: { threats, statistics, timeline }
```

### Replay Attack
```javascript
const replay = await ForensicsService.replayAttack('INC-1234567890-ABCD');
// Returns: { sequence, analysis, recommendations }
```

### Generate Compliance Report
```javascript
const report = await ForensicsService.generateComplianceReport('PCI-DSS', {
  startDate: '2025-01-01',
  endDate: '2025-01-31'
});
// Returns: { summary, controls, findings, recommendations }
```

### Export to SIEM
```javascript
const result = await ForensicsService.exportToSIEM('CEF');
// Returns: { file, count }
```

### Generate Attack Report
```javascript
const report = await ForensicsService.generateAttackReport('INC-1234567890-ABCD');
// Returns: { executive_summary, technical_details, impact_assessment, recommendations }
```

### Compliance Standards
- **SOC 2**: Trust Services Criteria
- **PCI-DSS**: Payment Card Industry
- **HIPAA**: Healthcare data protection
- **GDPR**: EU data privacy
- **ISO 27001**: Information security

### SIEM Formats
- **CEF**: Common Event Format (ArcSight, Splunk)
- **LEEF**: Log Event Extended Format (QRadar)
- **JSON**: Custom SIEM solutions
- **Syslog**: Traditional logging
- **Splunk**: Splunk HEC
- **QRadar**: IBM Security

---

## 🎯 Event Listeners

### Authentication Events
```javascript
AuthService.on('fingerprint-generated', (fingerprint) => {});
AuthService.on('behavior-analyzed', (analysis) => {});
AuthService.on('location-analyzed', ({ userId, analysis }) => {});
AuthService.on('session-created', (session) => {});
AuthService.on('session-terminated', ({ sessionId, reason }) => {});
AuthService.on('session-hijack-detected', ({ sessionId, context }) => {});
AuthService.on('account-locked', ({ userId, attempts }) => {});
```

### Forensics Events
```javascript
ForensicsService.on('incident-logged', (incident) => {});
ForensicsService.on('pcap-started', (session) => {});
ForensicsService.on('pcap-stopped', (session) => {});
ForensicsService.on('pcap-analyzed', (analysis) => {});
ForensicsService.on('attack-replayed', (replay) => {});
ForensicsService.on('compliance-report-generated', ({ standard, file }) => {});
ForensicsService.on('siem-export-completed', ({ format, file, count }) => {});
```

---

## 🌐 API Endpoints

### Authentication
```
POST   /api/auth/fingerprint              - Generate fingerprint
POST   /api/auth/fingerprint/verify       - Verify fingerprint
POST   /api/auth/behavior/analyze         - Analyze behavior
POST   /api/auth/location/analyze         - Detect anomaly
POST   /api/auth/session                  - Create session
POST   /api/auth/session/validate         - Validate session
DELETE /api/auth/session/:id              - Terminate session
POST   /api/auth/unlock/:userId           - Unlock account
```

### Forensics
```
GET    /api/forensics/stats                - Get statistics
POST   /api/forensics/pcap/start           - Start capture
POST   /api/forensics/pcap/stop            - Stop capture
POST   /api/forensics/pcap/analyze         - Analyze PCAP
POST   /api/forensics/replay/:id           - Replay attack
POST   /api/forensics/compliance           - Generate report
POST   /api/forensics/siem/export          - Export to SIEM
POST   /api/forensics/incident             - Log incident
```

---

## 🛡️ Security Features

### Device Fingerprinting Components
- Hardware: CPU, memory, MAC addresses, platform
- Software: OS, timezone, language, screen resolution
- Browser: Canvas, WebGL, fonts, plugins
- Network: IP address, VPN/Tor detection

### Behavioral Biometrics
- Typing speed and rhythm
- Mouse movement patterns
- Navigation sequences
- Active time patterns
- Session duration patterns

### Risk Factors
- Impossible travel: +0.4
- New country: +0.3
- VPN/Tor: +0.2
- Suspicious region: +0.1
- IP mismatch: +0.25
- User agent change: +0.20
- Fingerprint mismatch: +0.30

### MFA Triggers
- Risk score > 0.3 (30%)
- New device detected
- New country login
- VPN/Tor detected
- Behavioral anomalies

---

## 📊 Statistics

### Authentication Stats
```javascript
const stats = AuthService.getStatistics();
// Returns: { activeSessions, deviceFingerprints, behaviorProfiles, lockedAccounts }
```

### Forensics Stats
```javascript
const stats = ForensicsService.getStatistics();
// Returns: { totalIncidents, byType, bySeverity, pcapCaptures, reportsGenerated }
```

---

## 💡 Quick Tips

### Authentication
✅ Always enable MFA for high-risk logins  
✅ Re-fingerprint devices periodically  
✅ Allow time for behavioral learning  
✅ Whitelist corporate VPNs  
✅ Rotate session IDs periodically  

### Forensics
✅ Enable automatic PCAP for critical incidents  
✅ Generate monthly compliance reports  
✅ Configure real-time SIEM export  
✅ Maintain chain of custody  
✅ Use attack replay for training  

---

## 🔧 Troubleshooting

### High False Positives (Auth)
- Lower `behavioralThreshold` (0.6 instead of 0.7)
- Increase `fingerprintSimilarity` tolerance
- Whitelist known VPNs

### High False Negatives (Auth)
- Raise `mfaRiskThreshold` (0.2 instead of 0.3)
- Decrease `behavioralThreshold`
- Add custom risk factors

### PCAP Issues
- Ensure admin/root privileges
- Install WinPcap (Windows) or libpcap (Linux/Mac)
- Check network interface permissions

### SIEM Export Issues
- Verify SIEM endpoint connectivity
- Check format compatibility
- Ensure proper authentication

---

## 📁 File Locations

### Forensics Data
```
%APPDATA%/NebulaShield/forensics/
├── incidents/     - Individual incident files
├── pcap/          - Network captures
├── reports/       - Compliance reports
└── siem_export_*  - SIEM export files
```

### Configuration
- Services: `src/services/`
- Routes: `src/routes/`
- Components: `src/components/`
- Documentation: Root directory

---

## 🚀 Quick Start

### 1. Import Services
```javascript
import ForensicsService from './services/ForensicsService';
import AuthService from './services/AuthenticationHardeningService';
```

### 2. Register Routes
```javascript
import forensicsRoutes from './routes/forensics';
import authRoutes from './routes/authentication';

app.use('/api/forensics', forensicsRoutes);
app.use('/api/auth', authRoutes);
```

### 3. Add UI Components
```javascript
import ForensicsReporting from './components/ForensicsReporting';
import AuthenticationHardening from './components/AuthenticationHardening';
```

### 4. Start Using
```javascript
// Log incidents
ForensicsService.logIncident({...});

// Secure login
const session = await AuthService.createSession(userId, context);
```

---

**For detailed documentation, see:**
- `FORENSICS_REPORTING_GUIDE.md`
- `AUTHENTICATION_HARDENING_GUIDE.md`
- `ADVANCED_SECURITY_IMPLEMENTATION.md`
