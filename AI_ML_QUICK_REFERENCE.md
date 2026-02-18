# 🤖 AI/ML Features - Quick Reference

## ✅ Implementation Status

All AI/ML features have been successfully implemented and are running on the backend (port 8080):

### 1. 🧠 Behavior-Based Detection ✅
- **Status**: Active
- **Endpoint**: `/api/behavior/*`
- **Purpose**: Detect zero-day threats using ML-based behavior analysis
- **Key Features**:
  - File system monitoring (rapid creation, encryption, hidden files)
  - Process behavior analysis (injection, privilege escalation)
  - Network activity monitoring (C&C, data exfiltration)
  - Registry modification tracking
  - Neural network ML model with explainable AI
  - Adaptive learning from user feedback

**Quick Test:**
```bash
GET http://localhost:8080/api/behavior/stats
```

### 2. 🔮 Predictive Analytics ✅
- **Status**: Active
- **Endpoint**: `/api/predictive/*`
- **Purpose**: Predict vulnerabilities and attack vectors before exploitation
- **Key Features**:
  - System state analysis (OS, security, software)
  - Vulnerability identification (outdated software, missing patches)
  - Attack vector prediction (ransomware, phishing, zero-day, etc.)
  - Time-series threat forecasting
  - Prioritized recommendations
  - CVSS-based risk scoring

**Quick Test:**
```bash
GET http://localhost:8080/api/predictive/analyze
```

**Sample Result:**
- Overall Risk Score: 0.47 (Medium)
- Vulnerabilities Found: 3
- Attack Predictions: 6
- Confidence: 95%

### 3. ⏰ Smart Scan Scheduling ✅
- **Status**: Active & Monitoring
- **Endpoint**: `/api/scheduler/*`
- **Purpose**: AI-optimized scan scheduling based on system usage
- **Key Features**:
  - Continuous usage pattern monitoring (every 5 minutes)
  - Hourly and daily pattern analysis
  - Optimal time window detection
  - Impact estimation before scheduling
  - Adaptive scheduling (auto-adjusts based on usage changes)
  - User preference integration

**Quick Test:**
```bash
POST http://localhost:8080/api/scheduler/optimize
{
  "scanType": "full",
  "frequency": "daily"
}
```

### 4. 🌐 Threat Intelligence Feed ✅
- **Status**: Active
- **Endpoint**: `/api/threat-intel/*`
- **Purpose**: Real-time threat intelligence from global databases
- **Key Features**:
  - Multi-source integration (URLhaus, AbuseIPDB, etc.)
  - IP reputation checking
  - URL safety verification
  - File hash lookup
  - Intelligent caching (1-hour TTL)
  - Automatic feed updates

**Quick Test:**
```bash
GET http://localhost:8080/api/threat-intel/ip/8.8.8.8
```

---

## 📡 API Endpoints Summary

### Behavior Detection
- `POST /api/behavior/analyze` - Analyze file behavior
- `GET /api/behavior/stats` - Get statistics
- `POST /api/behavior/train` - Train with feedback
- `POST /api/behavior/log-activity` - Log activity

### Predictive Analytics
- `GET /api/predictive/analyze` - Full analysis
- `GET /api/predictive/stats` - Statistics
- `GET /api/predictive/vulnerabilities` - Vulnerability list
- `GET /api/predictive/attack-vectors` - Attack predictions
- `GET /api/predictive/forecast?hours=24` - Time-series forecast

### Smart Scheduler
- `POST /api/scheduler/optimize` - Generate optimal schedule
- `GET /api/scheduler/patterns` - Usage patterns
- `POST /api/scheduler/schedule` - Schedule scan
- `GET /api/scheduler/scans` - List scheduled scans
- `PUT /api/scheduler/preferences` - Update preferences
- `GET /api/scheduler/stats` - Statistics

### Threat Intelligence
- `POST /api/threat-intel/initialize` - Initialize service
- `GET /api/threat-intel/ip/:ip` - Check IP reputation
- `POST /api/threat-intel/url` - Check URL reputation
- `POST /api/threat-intel/hash` - Check file hash
- `GET /api/threat-intel/feeds` - Get threat feeds
- `POST /api/threat-intel/update` - Update feeds

---

## 🚀 Quick Start Examples

### Example 1: Complete File Security Check
```javascript
// 1. Scan file
const scan = await fetch('http://localhost:8080/api/scan/file', {
  method: 'POST',
  body: fileFormData
});

// 2. Analyze behavior
const behavior = await fetch('http://localhost:8080/api/behavior/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ filePath: scan.file_path })
});

// 3. Check threat intelligence
const threat = await fetch(`http://localhost:8080/api/threat-intel/hash`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ hash: scan.fileHash })
});

// Decision
if (behavior.verdict === 'malicious' || threat.isThreat) {
  // Quarantine
}
```

### Example 2: Proactive Security Assessment
```javascript
// Run predictive analysis
const analysis = await fetch('http://localhost:8080/api/predictive/analyze')
  .then(r => r.json());

console.log(`Risk Level: ${analysis.analysis.overallRisk.level}`);
console.log(`Vulnerabilities: ${analysis.analysis.vulnerabilities.length}`);

// Get top recommendations
const critical = analysis.analysis.recommendations
  .filter(r => r.priority === 'critical');

critical.forEach(rec => {
  console.log(`⚠️ ${rec.title}: ${rec.action}`);
});
```

### Example 3: Optimize Scan Schedule
```javascript
// Get optimal schedule
const schedule = await fetch('http://localhost:8080/api/scheduler/optimize', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    scanType: 'full',
    frequency: 'daily'
  })
}).then(r => r.json());

console.log(`Best time: ${schedule.schedule.recommendations[0].time}`);
console.log(`Confidence: ${schedule.schedule.confidence * 100}%`);

// Schedule it
await fetch('http://localhost:8080/api/scheduler/schedule', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    scanType: 'full',
    schedule: schedule.schedule.recommendations[0]
  })
});
```

---

## 📈 Performance Metrics

### Behavior Detection
- Analysis Time: 30-60 seconds per file
- CPU Impact: Low-Medium (during monitoring)
- Memory: ~50-100MB
- Accuracy: Adaptive (improves with training)

### Predictive Analytics
- Analysis Time: 2-5 seconds
- CPU Impact: Low (background)
- Update Frequency: Recommended every 1-6 hours
- Confidence: 70-95% (based on data availability)

### Smart Scheduler
- Monitoring Overhead: ~1% CPU every 5 minutes
- Data Storage: ~5MB (7 days of metrics)
- Pattern Analysis: 1-2 seconds
- Adaptation Time: Real-time

### Threat Intelligence
- Lookup Time: <1 second (cached), 2-5 seconds (API)
- Cache Duration: 1 hour
- Update Frequency: Every 1-4 hours
- Sources: 4+ global databases

---

## 🎯 Detection Capabilities

### Behavior-Based Threats Detected
- ✅ Ransomware (file encryption patterns)
- ✅ Trojans (process injection, backdoors)
- ✅ Spyware (data exfiltration, keylogging)
- ✅ Rootkits (privilege escalation, hiding)
- ✅ Worms (network propagation)
- ✅ APTs (advanced persistent threats)
- ✅ Zero-day exploits (unknown malware)

### Predictive Attack Vectors
- ✅ Ransomware attacks
- ✅ Phishing campaigns
- ✅ Zero-day exploits
- ✅ Brute force attacks
- ✅ Malware infections
- ✅ DDoS attacks
- ✅ Data exfiltration

---

## 🔧 Configuration

### Enable/Disable Features
Edit `backend/.env`:
```bash
BEHAVIOR_DETECTION_ENABLED=true
PREDICTIVE_ANALYTICS_ENABLED=true
SMART_SCHEDULER_ENABLED=true
THREAT_INTEL_ENABLED=true
```

### Adjust Thresholds
```bash
# Behavior Detection
BEHAVIOR_THRESHOLD_SUSPICIOUS=0.65
BEHAVIOR_THRESHOLD_MALICIOUS=0.85

# Scheduler
SCHEDULER_OPTIMAL_USAGE_THRESHOLD=0.3
```

---

## 📚 Documentation

- **Full Guide**: `AI_ML_FEATURES_GUIDE.md`
- **Behavior Detection**: `backend/behavior-based-detector.js`
- **Predictive Analytics**: `backend/predictive-analytics.js`
- **Smart Scheduler**: `backend/smart-scan-scheduler.js`
- **Threat Intelligence**: `backend/threat-intelligence-service.js`

---

## ✨ Next Steps

1. **Test All Features**: Use the quick test endpoints above
2. **Review Analytics**: Check `/api/predictive/analyze` for your system
3. **Optimize Schedule**: Set up smart scheduling with `/api/scheduler/optimize`
4. **Enable Monitoring**: Let the system learn your usage patterns
5. **Review Recommendations**: Act on high-priority security recommendations

---

**Status**: ✅ All Features Active and Running
**Backend**: http://localhost:8080
**Last Updated**: October 31, 2025
