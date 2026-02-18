# Testing Mobile Protection Features

This guide helps you test all the new real mobile protection features in Nebula Shield Mobile.

## 🧪 Quick Test Guide

### Setup
```bash
cd mobile
npm install expo-location
npx expo start
```

---

## 1. Malware Scanner Testing

### Test Quick Scan
```typescript
// In any screen or component
import { MalwareScannerService } from '../services/MalwareScannerService';

// Test quick scan
const testQuickScan = async () => {
  const result = await MalwareScannerService.quickScan(
    (progress, message) => {
      console.log(`${progress}%: ${message}`);
    }
  );
  
  console.log('=== SCAN RESULTS ===');
  console.log(`Scan ID: ${result.scanId}`);
  console.log(`Duration: ${result.duration}ms`);
  console.log(`Apps Scanned: ${result.appsScanned}`);
  console.log(`Files Scanned: ${result.filesScanned}`);
  console.log(`Threats Found: ${result.threatsFound}`);
  
  result.threats.forEach((threat, index) => {
    console.log(`\nThreat ${index + 1}:`);
    console.log(`  Type: ${threat.type}`);
    console.log(`  Severity: ${threat.severity}`);
    console.log(`  Name: ${threat.name}`);
    console.log(`  Confidence: ${threat.confidence}%`);
  });
};

// Run test
testQuickScan();
```

**Expected Output:**
- Progress updates from 0% to 100%
- Detection of mock malicious apps (FakeBanking, SpyTracker)
- Possible suspicious permission warnings
- ~5 second scan duration (simulated)

### Test App Security Report
```typescript
const testAppReport = async () => {
  const report = await MalwareScannerService.getAppSecurityReport('com.example.app');
  
  console.log('=== APP SECURITY REPORT ===');
  console.log(`App: ${report.appName}`);
  console.log(`Security Score: ${report.securityScore}/100`);
  console.log(`Risk Level: ${report.riskLevel}`);
  console.log(`Permissions: ${report.permissions.length}`);
  console.log(`Network Connections: ${report.networkConnections}`);
  
  report.permissions.forEach(perm => {
    console.log(`\n  ${perm.displayName}:`);
    console.log(`    Risk: ${perm.riskLevel}`);
    console.log(`    Necessary: ${perm.isNecessary}`);
  });
};

testAppReport();
```

---

## 2. Anti-Theft Testing

### Test Location Tracking
```typescript
import { AntiTheftService } from '../services/AntiTheftService';

const testLocationTracking = async () => {
  // Initialize
  const initialized = await AntiTheftService.initialize();
  console.log(`Anti-theft initialized: ${initialized}`);
  
  // Get current location
  const location = await AntiTheftService.getCurrentLocation();
  
  if (location) {
    console.log('=== LOCATION ===');
    console.log(`Latitude: ${location.latitude}`);
    console.log(`Longitude: ${location.longitude}`);
    console.log(`Accuracy: ${location.accuracy}m`);
    console.log(`Address: ${location.address}`);
    console.log(`Timestamp: ${location.timestamp}`);
    
    // Open in maps
    const mapsUrl = `https://www.google.com/maps?q=${location.latitude},${location.longitude}`;
    console.log(`View on map: ${mapsUrl}`);
  } else {
    console.log('Location permission denied or unavailable');
  }
};

testLocationTracking();
```

**Expected Behavior:**
- Request location permission
- Return current GPS coordinates
- Geocode address
- Save to location history

### Test Remote Commands
```typescript
const testRemoteCommands = async () => {
  // Test remote lock
  console.log('Testing remote lock...');
  await AntiTheftService.remoteLock('Test lock message');
  
  // Test alarm
  console.log('Testing alarm...');
  await AntiTheftService.soundAlarm();
  
  // Test message
  console.log('Testing message...');
  await AntiTheftService.sendMessage('This is a test message from anti-theft');
  
  // Check command history
  const history = await AntiTheftService.getCommandHistory(5);
  console.log(`\nCommand History (${history.length} commands):`);
  history.forEach(cmd => {
    console.log(`  ${cmd.type}: ${cmd.status} (${cmd.sentAt})`);
  });
};

testRemoteCommands();
```

### Test Failed Login Detection
```typescript
const testFailedLogins = async () => {
  console.log('Simulating failed login attempts...');
  
  // Simulate 3 failed attempts
  for (let i = 1; i <= 3; i++) {
    await AntiTheftService.recordFailedAttempt();
    console.log(`Failed attempt ${i} recorded`);
  }
  
  // Check alerts
  const alerts = await AntiTheftService.getTheftAlerts(10);
  console.log(`\nTheft Alerts (${alerts.length}):`);
  alerts.forEach(alert => {
    console.log(`  ${alert.type}: ${alert.details}`);
    console.log(`    Severity: ${alert.severity}`);
    console.log(`    Time: ${alert.timestamp}`);
  });
  
  // Reset counter
  AntiTheftService.resetFailedAttempts();
  console.log('Failed attempts counter reset');
};

testFailedLogins();
```

---

## 3. SMS/Call Protection Testing

### Test Spam Number Detection
```typescript
import { SMSCallProtectionService } from '../services/SMSCallProtectionService';

const testSpamDetection = async () => {
  const testNumbers = [
    '+18005551234',  // 800 number (likely spam)
    '+19005554321',  // 900 number (premium rate)
    '+15551234567',  // Normal number
    '12345',         // Short code
  ];
  
  console.log('=== SPAM NUMBER TESTING ===\n');
  
  for (const number of testNumbers) {
    const check = await SMSCallProtectionService.isSpamNumber(number);
    
    console.log(`Number: ${number}`);
    console.log(`  Is Spam: ${check.isSpam}`);
    console.log(`  Risk Score: ${check.riskScore}/100`);
    console.log(`  Reasons: ${check.reasons.join(', ')}`);
    console.log(`  Color: ${SMSCallProtectionService.getRiskColor(check.riskScore)}\n`);
  }
};

testSpamDetection();
```

### Test SMS Phishing Detection
```typescript
const testPhishingDetection = async () => {
  const testMessages = [
    {
      from: '+15551234567',
      body: 'Your Amazon account has been suspended. Click here to verify immediately: http://amaz0n-verify.com'
    },
    {
      from: '+18885559999',
      body: 'URGENT: IRS tax refund pending. Verify your SSN to claim $2,450.'
    },
    {
      from: '+15559876543',
      body: 'Hi, meeting at 3pm today. See you there!'
    },
    {
      from: '+19005551111',
      body: 'Congratulations! You won a $500 gift card. Click to claim your prize now!'
    }
  ];
  
  console.log('=== PHISHING DETECTION TESTING ===\n');
  
  for (const msg of testMessages) {
    const analysis = await SMSCallProtectionService.checkSMS(msg.from, msg.body);
    
    console.log(`From: ${msg.from}`);
    console.log(`Message: "${msg.body.substring(0, 50)}..."`);
    console.log(`  Is Spam: ${analysis.isSpam}`);
    console.log(`  Is Phishing: ${analysis.isPhishing}`);
    console.log(`  Risk Score: ${analysis.riskScore}/100`);
    console.log(`  Threat Type: ${analysis.threatType || 'none'}`);
    console.log(`  Reasons: ${analysis.blockedReasons.join(', ')}`);
    console.log('');
  }
};

testPhishingDetection();
```

**Expected Results:**
```
Message 1: High risk (phishing)
  - Pattern: urgent + verify + click link
  - URL detected
  - Risk: 85/100

Message 2: Critical risk (phishing)
  - Government impersonation (IRS, SSN)
  - Urgency tactics
  - Money mention
  - Risk: 95/100

Message 3: Safe
  - Normal conversation
  - Risk: 5/100

Message 4: High risk (scam)
  - Prize/lottery pattern
  - Urgency + click
  - Gift card mention
  - Risk: 75/100
```

### Test Block/Report Functions
```typescript
const testBlockingFunctions = async () => {
  // Block a number
  await SMSCallProtectionService.blockNumber('+18005551234', 'spam', 'Telemarketer');
  console.log('Number blocked');
  
  // Report spam
  await SMSCallProtectionService.reportSpam(
    '+18885559999',
    'sms',
    'phishing',
    'IRS scam message'
  );
  console.log('Spam reported');
  
  // Get blocked numbers
  const blocked = await SMSCallProtectionService.getBlockedNumbers();
  console.log(`\nBlocked Numbers (${blocked.length}):`);
  blocked.forEach(b => {
    console.log(`  ${b.number} (${b.type})`);
    console.log(`    Blocked: ${b.blockedAt}`);
    console.log(`    Block count: ${b.blockCount}`);
  });
  
  // Get stats
  const stats = await SMSCallProtectionService.getProtectionStats();
  console.log('\n=== PROTECTION STATS ===');
  console.log(`Total Blocked: ${stats.totalBlocked}`);
  console.log(`Spam Calls: ${stats.spamCallsBlocked}`);
  console.log(`Spam SMS: ${stats.spamSMSBlocked}`);
  console.log(`Phishing: ${stats.phishingAttempts}`);
  console.log(`Today: ${stats.todayBlocked}`);
};

testBlockingFunctions();
```

---

## 4. Integration Testing

### Test All Services Together
```typescript
const testAllServices = async () => {
  console.log('=== COMPREHENSIVE SECURITY TEST ===\n');
  
  // 1. Malware Scan
  console.log('1. Running malware scan...');
  const scanResult = await MalwareScannerService.quickScan();
  console.log(`✓ Scan complete: ${scanResult.threatsFound} threats\n`);
  
  // 2. Check Device Location
  console.log('2. Checking device location...');
  const location = await AntiTheftService.getCurrentLocation();
  console.log(`✓ Location: ${location?.latitude}, ${location?.longitude}\n`);
  
  // 3. Test SMS Protection
  console.log('3. Testing SMS protection...');
  const smsCheck = await SMSCallProtectionService.checkSMS(
    '+15551234567',
    'Verify your account immediately'
  );
  console.log(`✓ SMS Risk: ${smsCheck.riskScore}/100\n`);
  
  // 4. Get Protection Stats
  console.log('4. Getting protection statistics...');
  const stats = await SMSCallProtectionService.getProtectionStats();
  console.log(`✓ Total Protected: ${stats.totalBlocked}\n`);
  
  console.log('=== ALL TESTS COMPLETE ===');
};

testAllServices();
```

---

## 5. UI Component Testing

### Test in Mobile Protection Screen
1. Open app
2. Navigate to "Mobile Protection" screen
3. Test each tab:
   - **Overview**: Check device health, security score
   - **WiFi**: Scan WiFi networks
   - **Privacy**: View permission usage
   - **Traffic**: Monitor network connections

### Test in Scans Screen
1. Navigate to "Scans" screen
2. Tap FAB (+) button
3. Select "Quick Scan"
4. Monitor progress bar
5. View scan results
6. Check threat details

---

## 6. Performance Testing

### Measure Scan Performance
```typescript
const measureScanPerformance = async () => {
  const iterations = 5;
  const durations: number[] = [];
  
  console.log(`Running ${iterations} quick scans...`);
  
  for (let i = 1; i <= iterations; i++) {
    const start = Date.now();
    await MalwareScannerService.quickScan();
    const duration = Date.now() - start;
    durations.push(duration);
    
    console.log(`Scan ${i}: ${duration}ms`);
  }
  
  const average = durations.reduce((a, b) => a + b, 0) / iterations;
  console.log(`\nAverage scan time: ${average}ms`);
};

measureScanPerformance();
```

---

## 7. Error Handling Testing

### Test Error Scenarios
```typescript
const testErrorHandling = async () => {
  // Test without location permission
  try {
    const location = await AntiTheftService.getCurrentLocation();
    console.log('Location:', location);
  } catch (error) {
    console.log('✓ Location error handled:', error.message);
  }
  
  // Test concurrent scans
  try {
    const scan1 = MalwareScannerService.quickScan();
    const scan2 = MalwareScannerService.quickScan();
    await Promise.all([scan1, scan2]);
  } catch (error) {
    console.log('✓ Concurrent scan error handled:', error.message);
  }
  
  // Test invalid number format
  try {
    const check = await SMSCallProtectionService.isSpamNumber('invalid');
    console.log('Check result:', check);
  } catch (error) {
    console.log('✓ Invalid number error handled:', error.message);
  }
};

testErrorHandling();
```

---

## 8. Manual Testing Checklist

### Malware Scanner
- [ ] Quick scan completes successfully
- [ ] Full scan completes successfully
- [ ] Threats are detected
- [ ] Threats can be quarantined
- [ ] Scan history is saved
- [ ] Progress updates work
- [ ] Can cancel mid-scan

### Anti-Theft
- [ ] Location permission requested
- [ ] Current location retrieved
- [ ] Location history saved
- [ ] Remote lock displays message
- [ ] Alarm can be triggered
- [ ] Failed attempts recorded
- [ ] Trusted contacts can be added
- [ ] SIM change detected

### SMS/Call Protection
- [ ] Spam numbers detected
- [ ] Phishing patterns recognized
- [ ] Numbers can be blocked
- [ ] Blocked list viewable
- [ ] Stats calculated correctly
- [ ] Reports can be submitted
- [ ] Protection settings saved

---

## 9. Automated Test Suite

Create `__tests__/MobileProtection.test.ts`:

```typescript
import { MalwareScannerService } from '../services/MalwareScannerService';
import { SMSCallProtectionService } from '../services/SMSCallProtectionService';
import { AntiTheftService } from '../services/AntiTheftService';

describe('Mobile Protection Services', () => {
  describe('MalwareScannerService', () => {
    it('should perform quick scan', async () => {
      const result = await MalwareScannerService.quickScan();
      expect(result.status).toBe('completed');
      expect(result.scanType).toBe('quick');
    });
    
    it('should detect threats', async () => {
      const result = await MalwareScannerService.quickScan();
      expect(result.threats).toBeDefined();
      expect(Array.isArray(result.threats)).toBe(true);
    });
  });
  
  describe('SMSCallProtectionService', () => {
    it('should detect spam numbers', async () => {
      const check = await SMSCallProtectionService.isSpamNumber('+18005551234');
      expect(check.isSpam).toBeDefined();
      expect(check.riskScore).toBeGreaterThanOrEqual(0);
      expect(check.riskScore).toBeLessThanOrEqual(100);
    });
    
    it('should detect phishing SMS', async () => {
      const sms = await SMSCallProtectionService.checkSMS(
        '+15551234567',
        'URGENT: Verify your account now!'
      );
      expect(sms.isPhishing).toBe(true);
      expect(sms.riskScore).toBeGreaterThan(50);
    });
  });
  
  describe('AntiTheftService', () => {
    it('should initialize successfully', async () => {
      const result = await AntiTheftService.initialize();
      expect(typeof result).toBe('boolean');
    });
  });
});
```

Run tests:
```bash
npm test
```

---

## 🐛 Common Issues & Solutions

### Issue 1: "Location permission denied"
**Solution**: Go to device Settings > Apps > Nebula Shield > Permissions > Location > Allow

### Issue 2: "Scan takes too long"
**Solution**: This is expected for full scans. Quick scans should complete in ~5 seconds (simulated).

### Issue 3: "No threats detected"
**Solution**: The service uses mock data. Real threats would be detected in production with actual app scanning.

### Issue 4: "SMS detection not working"
**Solution**: iOS has limitations on SMS access. Use manual check feature or test on Android.

---

## 📝 Test Results Template

```
=== MOBILE PROTECTION TEST RESULTS ===
Date: [DATE]
Device: [MODEL]
OS: [iOS/Android VERSION]

MALWARE SCANNER
✓/✗ Quick scan completed
✓/✗ Full scan completed
✓/✗ Threats detected
✓/✗ Quarantine working
Notes: 

ANTI-THEFT
✓/✗ Location tracking
✓/✗ Remote lock
✓/✗ Alarm function
✓/✗ Failed attempt tracking
Notes:

SMS/CALL PROTECTION
✓/✗ Spam detection
✓/✗ Phishing detection
✓/✗ Blocking functions
✓/✗ Statistics accurate
Notes:

OVERALL STATUS: PASS/FAIL
```

---

## 🎯 Next Steps

After testing:
1. Report any bugs on GitHub
2. Suggest improvements
3. Contribute to threat databases
4. Share testing results
5. Write additional tests

---

**Happy Testing! 🛡️**
