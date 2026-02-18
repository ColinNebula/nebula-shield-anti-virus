# 🤖 AI/ML Features - Practical Examples

## Complete Implementation Examples

### Example 1: Multi-Layer File Security Analysis

This example demonstrates how to use all AI/ML features together for comprehensive file analysis.

```javascript
async function analyzeFileSecurity(filePath) {
  const results = {
    signature: null,
    behavior: null,
    intelligence: null,
    recommendation: 'unknown'
  };

  // Step 1: Traditional signature-based scan
  const formData = new FormData();
  formData.append('file', fs.createReadStream(filePath));
  
  const scanResponse = await fetch('http://localhost:8080/api/scan/file', {
    method: 'POST',
    body: formData
  });
  results.signature = await scanResponse.json();

  // Step 2: Behavior-based analysis (ML)
  const behaviorResponse = await fetch('http://localhost:8080/api/behavior/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      filePath: filePath,
      deep: true,
      monitorDuration: 30000
    })
  });
  results.behavior = await behaviorResponse.json();

  // Step 3: Threat intelligence lookup
  if (results.signature.fileHash) {
    const intelResponse = await fetch('http://localhost:8080/api/threat-intel/hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        hash: results.signature.fileHash
      })
    });
    results.intelligence = await intelResponse.json();
  }

  // Step 4: Make informed decision
  const threatScore = calculateThreatScore(results);
  
  if (threatScore >= 0.85 || 
      results.behavior.analysis.verdict === 'critical' ||
      results.intelligence?.reputation.isThreat) {
    results.recommendation = 'quarantine_immediate';
  } else if (threatScore >= 0.65 || 
             results.behavior.analysis.verdict === 'malicious') {
    results.recommendation = 'quarantine';
  } else if (threatScore >= 0.40 || 
             results.behavior.analysis.verdict === 'suspicious') {
    results.recommendation = 'monitor';
  } else {
    results.recommendation = 'allow';
  }

  return results;
}

function calculateThreatScore(results) {
  let score = 0;
  let weights = { signature: 0.3, behavior: 0.4, intelligence: 0.3 };

  // Signature scan weight
  if (results.signature.threat_type !== 'CLEAN') {
    score += results.signature.confidence * weights.signature;
  }

  // Behavior analysis weight
  score += results.behavior.analysis.score * weights.behavior;

  // Threat intelligence weight
  if (results.intelligence?.reputation.isThreat) {
    score += (results.intelligence.reputation.confidence / 100) * weights.intelligence;
  }

  return Math.min(score, 1.0);
}

// Usage
const analysis = await analyzeFileSecurity('C:\\Downloads\\suspicious.exe');
console.log('Threat Score:', analysis.threatScore);
console.log('Recommendation:', analysis.recommendation);
```

---

### Example 2: Automated Security Posture Assessment

Automatically assess and improve your security posture using predictive analytics.

```javascript
async function assessSecurityPosture() {
  // Run comprehensive predictive analysis
  const response = await fetch('http://localhost:8080/api/predictive/analyze');
  const data = await response.json();
  const analysis = data.analysis;

  console.log('╔══════════════════════════════════════════════╗');
  console.log('║    Security Posture Assessment Report       ║');
  console.log('╚══════════════════════════════════════════════╝\n');

  // Overall risk
  console.log('📊 Overall Risk Assessment:');
  console.log(`   Risk Level: ${analysis.overallRisk.level.toUpperCase()}`);
  console.log(`   Risk Score: ${(analysis.overallRisk.score * 100).toFixed(1)}%`);
  console.log(`   Confidence: ${(analysis.confidence * 100).toFixed(0)}%\n`);

  // Vulnerabilities
  console.log('🔍 Vulnerabilities Detected:');
  analysis.vulnerabilities.forEach((vuln, index) => {
    console.log(`   ${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.description}`);
    console.log(`      → ${vuln.recommendation}`);
  });

  // Attack predictions
  console.log('\n⚠️  Predicted Attack Vectors:');
  analysis.predictions
    .filter(p => p.likelihood > 0.5)
    .forEach((pred, index) => {
      console.log(`   ${index + 1}. ${pred.attackVector} (${(pred.likelihood * 100).toFixed(0)}% likelihood)`);
      console.log(`      Impact: ${pred.impact}`);
      console.log(`      Time to Exploit: ${pred.timeToExploit.value} ${pred.timeToExploit.unit}`);
      console.log(`      Mitigations:`);
      pred.mitigations.slice(0, 3).forEach(m => {
        console.log(`        - ${m}`);
      });
  });

  // Recommendations
  console.log('\n✅ Recommended Actions (Priority Order):');
  analysis.recommendations.slice(0, 5).forEach((rec, index) => {
    const emoji = rec.priority === 'critical' ? '🔴' : 
                  rec.priority === 'high' ? '🟡' : '🟢';
    console.log(`   ${index + 1}. ${emoji} [${rec.priority.toUpperCase()}] ${rec.title}`);
    console.log(`      Action: ${rec.action}`);
    if (rec.automated) {
      console.log(`      ✨ Can be automated`);
    }
  });

  // Apply automated fixes
  const automatedFixes = analysis.recommendations.filter(r => r.automated);
  console.log(`\n🤖 Found ${automatedFixes.length} automated fixes`);

  for (const fix of automatedFixes) {
    console.log(`   Applying: ${fix.title}...`);
    // await applyFix(fix);
  }

  // Schedule preventive scan
  const scheduleResponse = await fetch('http://localhost:8080/api/scheduler/optimize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scanType: 'deep',
      frequency: 'weekly'
    })
  });
  const schedule = await scheduleResponse.json();

  console.log('\n⏰ Scheduled Preventive Scan:');
  console.log(`   Time: ${schedule.schedule.recommendations[0].time}`);
  console.log(`   Day: ${schedule.schedule.recommendations[0].dayOfWeek}`);
  console.log(`   Confidence: ${(schedule.schedule.confidence * 100).toFixed(0)}%`);

  return analysis;
}

// Run assessment
assessSecurityPosture();
```

---

### Example 3: Smart Scheduled Scanning System

Set up an intelligent scanning system that adapts to your usage patterns.

```javascript
class SmartScanningSystem {
  constructor() {
    this.baseUrl = 'http://localhost:8080';
    this.preferences = {
      preferredTimeRanges: [
        { start: '22:00', end: '06:00' } // Night time
      ],
      avoidTimeRanges: [
        { start: '09:00', end: '17:00' } // Work hours
      ],
      scanPriority: 'balanced',
      maxCpuUsage: 50,
      maxMemoryUsage: 70
    };
  }

  async initialize() {
    // Update scheduler preferences
    await fetch(`${this.baseUrl}/api/scheduler/preferences`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(this.preferences)
    });

    console.log('✅ Scheduler preferences updated');
  }

  async getUsagePatterns() {
    const response = await fetch(`${this.baseUrl}/api/scheduler/patterns`);
    const data = await response.json();
    return data.patterns;
  }

  async scheduleOptimalScans() {
    // Quick daily scan
    const quickSchedule = await this.optimizeSchedule('quick', 'daily');
    await this.scheduleScan('quick', quickSchedule.recommendations[0]);

    // Full weekly scan
    const fullSchedule = await this.optimizeSchedule('full', 'weekly');
    await this.scheduleScan('full', fullSchedule.recommendations[0]);

    // Deep monthly scan
    const deepSchedule = await this.optimizeSchedule('deep', 'weekly');
    await this.scheduleScan('deep', deepSchedule.recommendations[0]);

    console.log('✅ All scans scheduled optimally');
  }

  async optimizeSchedule(scanType, frequency) {
    const response = await fetch(`${this.baseUrl}/api/scheduler/optimize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanType, frequency })
    });
    const data = await response.json();
    return data.schedule;
  }

  async scheduleScan(scanType, schedule) {
    const response = await fetch(`${this.baseUrl}/api/scheduler/schedule`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scanType,
        schedule,
        options: {
          autoQuarantine: true,
          deepScan: scanType === 'deep'
        }
      })
    });
    const data = await response.json();
    
    console.log(`📅 Scheduled ${scanType} scan:`);
    console.log(`   Time: ${schedule.time}`);
    console.log(`   Day: ${schedule.dayOfWeek}`);
    console.log(`   System Impact: ${schedule.systemImpact?.level || 'low'}`);
    
    return data.scan;
  }

  async getScheduledScans() {
    const response = await fetch(`${this.baseUrl}/api/scheduler/scans`);
    const data = await response.json();
    return data.scans;
  }

  async displaySchedule() {
    const scans = await this.getScheduledScans();
    
    console.log('\n📋 Scheduled Scans:');
    scans.forEach((scan, index) => {
      console.log(`\n${index + 1}. ${scan.scanType.toUpperCase()} Scan`);
      console.log(`   Next Run: ${new Date(scan.nextRun).toLocaleString()}`);
      console.log(`   Enabled: ${scan.enabled ? '✅' : '❌'}`);
      console.log(`   Adaptive: ${scan.adaptive ? '✅' : '❌'}`);
    });
  }
}

// Usage
const scanner = new SmartScanningSystem();
await scanner.initialize();
await scanner.scheduleOptimalScans();
await scanner.displaySchedule();
```

---

### Example 4: Real-Time Threat Monitoring Dashboard

Create a real-time monitoring dashboard using AI/ML features.

```javascript
class ThreatMonitoringDashboard {
  constructor() {
    this.baseUrl = 'http://localhost:8080';
    this.updateInterval = 60000; // 1 minute
  }

  async start() {
    console.log('🚀 Starting Threat Monitoring Dashboard...\n');
    
    // Initial load
    await this.updateDashboard();
    
    // Periodic updates
    setInterval(() => this.updateDashboard(), this.updateInterval);
  }

  async updateDashboard() {
    console.clear();
    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║       Nebula Shield - AI/ML Threat Dashboard          ║');
    console.log('╚════════════════════════════════════════════════════════╝\n');
    console.log(`Last Update: ${new Date().toLocaleString()}\n`);

    // 1. System Status
    await this.displaySystemStatus();

    // 2. Behavior Detection Stats
    await this.displayBehaviorStats();

    // 3. Current Risk Assessment
    await this.displayRiskAssessment();

    // 4. Threat Intelligence
    await this.displayThreatIntelligence();

    // 5. Scheduler Status
    await this.displaySchedulerStatus();
  }

  async displaySystemStatus() {
    const response = await fetch(`${this.baseUrl}/api/status`);
    const status = await response.json();

    console.log('🖥️  System Status:');
    console.log(`   Status: ${status.status === 'running' ? '✅ Running' : '❌ Error'}`);
    console.log(`   Uptime: ${Math.floor(status.uptime / 60)} minutes`);
    console.log(`   Real-time Protection: ${status.real_time_protection ? '✅ Enabled' : '❌ Disabled'}`);
    console.log(`   Total Scans: ${status.stats.totalScans}`);
    console.log(`   Threats Detected: ${status.stats.threatsDetected}\n`);
  }

  async displayBehaviorStats() {
    const response = await fetch(`${this.baseUrl}/api/behavior/stats`);
    const data = await response.json();
    const stats = data.stats;

    console.log('🧠 Behavior Detection:');
    console.log(`   Monitored Files: ${stats.behaviorProfiles}`);
    console.log(`   File Activities: ${stats.fileActivityLogs}`);
    console.log(`   Network Activities: ${stats.networkActivityLogs}`);
    console.log(`   Registry Activities: ${stats.registryActivityLogs}\n`);
  }

  async displayRiskAssessment() {
    const response = await fetch(`${this.baseUrl}/api/predictive/analyze`);
    const data = await response.json();
    const analysis = data.analysis;

    const riskColor = analysis.overallRisk.level === 'critical' ? '🔴' :
                     analysis.overallRisk.level === 'high' ? '🟡' :
                     analysis.overallRisk.level === 'medium' ? '🟠' : '🟢';

    console.log('🔮 Risk Assessment:');
    console.log(`   ${riskColor} Risk Level: ${analysis.overallRisk.level.toUpperCase()}`);
    console.log(`   Risk Score: ${(analysis.overallRisk.score * 100).toFixed(1)}%`);
    console.log(`   Vulnerabilities: ${analysis.vulnerabilities.length}`);
    console.log(`   Attack Predictions: ${analysis.predictions.length}`);
    
    // Show top threat
    if (analysis.predictions.length > 0) {
      const topThreat = analysis.predictions[0];
      console.log(`   Top Threat: ${topThreat.attackVector} (${(topThreat.likelihood * 100).toFixed(0)}%)\n`);
    } else {
      console.log('   No active threat predictions\n');
    }
  }

  async displayThreatIntelligence() {
    const response = await fetch(`${this.baseUrl}/api/threat-intel/feeds`);
    const data = await response.json();

    console.log('🌐 Threat Intelligence:');
    console.log(`   Feeds Active: ✅`);
    console.log(`   Last Update: ${new Date(data.lastUpdate).toLocaleString()}`);
    console.log(`   Cache Entries: Active\n`);
  }

  async displaySchedulerStatus() {
    const statsResponse = await fetch(`${this.baseUrl}/api/scheduler/stats`);
    const statsData = await statsResponse.json();
    const stats = statsData.stats;

    const scansResponse = await fetch(`${this.baseUrl}/api/scheduler/scans`);
    const scansData = await scansResponse.json();

    console.log('⏰ Smart Scheduler:');
    console.log(`   Scheduled Scans: ${stats.scheduledScans}`);
    console.log(`   Data Points: ${stats.dataPoints}`);
    console.log(`   Optimal Windows: ${stats.optimalWindows}`);
    
    if (scansData.scans.length > 0) {
      const nextScan = scansData.scans[0];
      console.log(`   Next Scan: ${nextScan.scanType} at ${new Date(nextScan.nextRun).toLocaleString()}\n`);
    }
  }
}

// Start dashboard
const dashboard = new ThreatMonitoringDashboard();
dashboard.start();
```

---

### Example 5: Network Traffic Analysis with AI

Monitor and analyze network traffic using AI threat detection and threat intelligence.

```javascript
async function analyzeNetworkConnection(connection) {
  const {
    sourceIP,
    destIP,
    sourcePort,
    destPort,
    protocol,
    bytes
  } = connection;

  console.log(`🔍 Analyzing connection: ${sourceIP}:${sourcePort} → ${destIP}:${destPort}`);

  // Step 1: Check destination IP reputation
  const ipResponse = await fetch(`http://localhost:8080/api/threat-intel/ip/${destIP}`);
  const ipData = await ipResponse.json();
  const ipReputation = ipData.reputation;

  if (ipReputation.isThreat) {
    console.log(`⚠️  THREAT: Destination IP is malicious!`);
    console.log(`   Threat Level: ${ipReputation.threatLevel}`);
    console.log(`   Tags: ${ipReputation.tags.join(', ')}`);
    console.log(`   Sources: ${ipReputation.sources.join(', ')}`);
    
    // Block IP
    await fetch('http://localhost:8080/api/firewall/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip: destIP,
        reason: `Malicious IP: ${ipReputation.tags.join(', ')}`,
        permanent: true
      })
    });
    
    return { action: 'blocked', reason: 'malicious_ip' };
  }

  // Step 2: Analyze with AI threat detector
  const aiResponse = await fetch('http://localhost:8080/api/ai/analyze-connection', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(connection)
  });
  const aiAnalysis = await aiResponse.json();

  if (aiAnalysis.isThreat) {
    console.log(`⚠️  AI DETECTED: ${aiAnalysis.threatType}`);
    console.log(`   Confidence: ${(aiAnalysis.confidence * 100).toFixed(0)}%`);
    console.log(`   Indicators: ${aiAnalysis.indicators.join(', ')}`);
    
    // Log for behavior analysis
    await fetch('http://localhost:8080/api/behavior/log-activity', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'network',
        activity: {
          ...connection,
          threatType: aiAnalysis.threatType,
          timestamp: Date.now()
        }
      })
    });
    
    return { action: 'monitored', reason: aiAnalysis.threatType };
  }

  console.log('✅ Connection appears safe');
  return { action: 'allowed', reason: 'clean' };
}

// Monitor connections
const connections = [
  { sourceIP: '192.168.1.100', destIP: '8.8.8.8', sourcePort: 54321, destPort: 53, protocol: 'udp', bytes: 512 },
  { sourceIP: '192.168.1.100', destIP: '203.0.113.1', sourcePort: 54322, destPort: 443, protocol: 'tcp', bytes: 10240 }
];

for (const conn of connections) {
  const result = await analyzeNetworkConnection(conn);
  console.log(`Action taken: ${result.action}\n`);
}
```

---

## Testing All Features Together

```javascript
async function comprehensiveTest() {
  console.log('🧪 Running Comprehensive AI/ML Feature Test\n');

  // 1. Behavior Detection
  console.log('1️⃣ Testing Behavior-Based Detection...');
  const behaviorStats = await fetch('http://localhost:8080/api/behavior/stats')
    .then(r => r.json());
  console.log(`   ✅ Behavior profiles: ${behaviorStats.stats.behaviorProfiles}\n`);

  // 2. Predictive Analytics
  console.log('2️⃣ Testing Predictive Analytics...');
  const prediction = await fetch('http://localhost:8080/api/predictive/analyze')
    .then(r => r.json());
  console.log(`   ✅ Risk level: ${prediction.analysis.overallRisk.level}\n`);

  // 3. Smart Scheduler
  console.log('3️⃣ Testing Smart Scheduler...');
  const schedule = await fetch('http://localhost:8080/api/scheduler/optimize', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanType: 'quick', frequency: 'daily' })
  }).then(r => r.json());
  console.log(`   ✅ Optimal time: ${schedule.schedule.recommendations[0].time}\n`);

  // 4. Threat Intelligence
  console.log('4️⃣ Testing Threat Intelligence...');
  const intel = await fetch('http://localhost:8080/api/threat-intel/ip/8.8.8.8')
    .then(r => r.json());
  console.log(`   ✅ IP reputation: ${intel.reputation.isThreat ? 'Threat' : 'Clean'}\n`);

  console.log('✨ All AI/ML features tested successfully!');
}

comprehensiveTest();
```

---

## Performance Optimization Tips

1. **Batch Operations**: Process multiple files/connections together
2. **Caching**: Leverage threat intelligence caching
3. **Async Processing**: Use Promise.all for parallel operations
4. **Throttling**: Rate-limit API calls for large datasets
5. **Background Monitoring**: Run pattern analysis during low activity

---

**For complete documentation, see `AI_ML_FEATURES_GUIDE.md`**
