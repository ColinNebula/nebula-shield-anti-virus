# Forensics & Reporting System 📝

## Overview
Advanced forensics and reporting system providing detailed attack analysis, PCAP capture, compliance reporting, and SIEM integration.

## Features

### 1. Incident Logging & Forensics
- **Comprehensive Incident Tracking**: Every security event is logged with full context
- **Chain of Custody**: Maintains evidence integrity for legal proceedings
- **Evidence Collection**: Automatic capture of network traffic, process info, file hashes
- **Metadata Enrichment**: User agent, geolocation, threat intelligence integration

### 2. PCAP Capture & Analysis
- **Real-time Packet Capture**: Record network traffic during security events
- **Attack Pattern Detection**: Automatic analysis of captured traffic
- **Protocol Analysis**: Deep inspection of network protocols
- **Threat Extraction**: Identify malicious payloads and signatures

### 3. Attack Replay Functionality
- **Timeline Reconstruction**: Replay attacks step-by-step
- **Attack Vector Analysis**: Understand how the attack occurred
- **Vulnerability Assessment**: Identify exploited weaknesses
- **Impact Analysis**: Determine scope and severity

### 4. Compliance Reporting
Generates reports for multiple compliance standards:
- **SOC 2**: Trust Services Criteria compliance
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act
- **GDPR**: General Data Protection Regulation
- **ISO 27001**: Information Security Management

### 5. SIEM Integration
Export security events to popular SIEM platforms:
- **CEF (Common Event Format)**: ArcSight, Splunk
- **LEEF (Log Event Extended Format)**: QRadar
- **JSON**: Custom SIEM solutions
- **Syslog**: Traditional logging systems
- **Splunk HEC**: HTTP Event Collector
- **QRadar**: IBM Security

## API Reference

### ForensicsService

#### Log Security Incident
```javascript
const incident = ForensicsService.logIncident({
  type: 'SQL_INJECTION',
  severity: 'high',
  source: { ip: '192.168.1.100', port: 54321 },
  destination: { ip: '10.0.0.50', port: 80 },
  protocol: 'HTTP',
  payload: 'malicious SQL query',
  action: 'BLOCKED',
  userAgent: 'Mozilla/5.0...',
  geolocation: { country: 'US', city: 'New York' }
});
```

#### Start PCAP Capture
```javascript
const capture = await ForensicsService.startPCAPCapture({
  interface: 'eth0',
  filter: 'tcp port 80',
  maxSize: 100 * 1024 * 1024, // 100MB
  maxDuration: 3600000 // 1 hour
});
```

#### Stop PCAP Capture
```javascript
const session = ForensicsService.stopPCAPCapture();
console.log(`Captured ${session.packetCount} packets`);
```

#### Analyze PCAP
```javascript
const analysis = await ForensicsService.analyzePCAP('/path/to/capture.pcap');
console.log('Threats found:', analysis.threats);
console.log('Suspicious patterns:', analysis.statistics.suspiciousPatterns);
```

#### Replay Attack
```javascript
const replay = await ForensicsService.replayAttack('INC-1234567890-ABCD');
console.log('Attack vector:', replay.analysis.attackVector);
console.log('Recommendations:', replay.analysis.recommendations);
```

#### Generate Compliance Report
```javascript
const report = await ForensicsService.generateComplianceReport('PCI-DSS', {
  startDate: '2025-01-01',
  endDate: '2025-01-31'
});
console.log('Controls assessed:', report.controls.length);
console.log('Findings:', report.findings.length);
```

#### Export to SIEM
```javascript
const result = await ForensicsService.exportToSIEM('CEF', {
  incidents: recentIncidents
});
console.log(`Exported ${result.count} events to ${result.file}`);
```

#### Generate Attack Report
```javascript
const report = await ForensicsService.generateAttackReport('INC-1234567890-ABCD');
console.log('Executive summary:', report.executive_summary);
console.log('Technical details:', report.technical_details);
console.log('IoCs:', report.technical_details.indicators_of_compromise);
```

## Event Emissions

The ForensicsService emits the following events:

```javascript
// Incident logged
ForensicsService.on('incident-logged', (incident) => {
  console.log(`New incident: ${incident.id}`);
});

// PCAP capture started
ForensicsService.on('pcap-started', (session) => {
  console.log(`Capture started: ${session.id}`);
});

// PCAP capture stopped
ForensicsService.on('pcap-stopped', (session) => {
  console.log(`Capture stopped. Duration: ${session.duration}ms`);
});

// PCAP analyzed
ForensicsService.on('pcap-analyzed', (analysis) => {
  console.log(`Found ${analysis.threats.length} threats`);
});

// Attack replayed
ForensicsService.on('attack-replayed', (replay) => {
  console.log(`Replayed attack: ${replay.incidentId}`);
});

// Compliance report generated
ForensicsService.on('compliance-report-generated', ({ standard, file }) => {
  console.log(`${standard} report: ${file}`);
});

// SIEM export completed
ForensicsService.on('siem-export-completed', ({ format, file, count }) => {
  console.log(`Exported ${count} events in ${format} format`);
});
```

## Storage Structure

```
%APPDATA%/NebulaShield/forensics/
├── incidents/
│   ├── INC-1234567890-ABCD.json
│   ├── INC-1234567891-EFGH.json
│   └── ...
├── pcap/
│   ├── capture_1234567890_a1b2c3d4.pcap
│   ├── capture_1234567891_e5f6g7h8.pcap
│   └── ...
├── reports/
│   ├── SOC2_1234567890.json
│   ├── PCI-DSS_1234567891.json
│   ├── attack_report_INC-1234567890-ABCD_1234567892.json
│   └── ...
└── siem_export_CEF_1234567893.log
```

## Incident Structure

```json
{
  "id": "INC-1234567890-ABCD",
  "timestamp": "2025-10-25T12:00:00.000Z",
  "type": "SQL_INJECTION",
  "severity": "high",
  "source": {
    "ip": "192.168.1.100",
    "port": 54321
  },
  "destination": {
    "ip": "10.0.0.50",
    "port": 80
  },
  "protocol": "HTTP",
  "payload": "...",
  "action": "BLOCKED",
  "metadata": {
    "userAgent": "Mozilla/5.0...",
    "geolocation": {
      "country": "US",
      "city": "New York"
    },
    "threatIntel": { ... },
    "signatures": [ ... ]
  },
  "evidence": {
    "networkCapture": "/path/to/capture.pcap",
    "processInfo": { ... },
    "fileHashes": [ ... ],
    "registryChanges": [ ... ]
  },
  "chainOfCustody": [
    {
      "timestamp": "2025-10-25T12:00:00.000Z",
      "action": "INCIDENT_LOGGED",
      "user": "SYSTEM"
    }
  ]
}
```

## SIEM Format Examples

### CEF (Common Event Format)
```
CEF:0|NebulaShield|AntiVirus|1.0|SQL_INJECTION|SQL_INJECTION|8|src=192.168.1.100 dst=10.0.0.50 proto=HTTP act=BLOCKED cs1=INC-1234567890-ABCD cs1Label=IncidentID
```

### LEEF (Log Event Extended Format)
```
LEEF:2.0|NebulaShield|AntiVirus|1.0|SQL_INJECTION|devTime=2025-10-25T12:00:00.000Z  src=192.168.1.100  dst=10.0.0.50  proto=HTTP  sev=high  identSrc=INC-1234567890-ABCD
```

### Splunk JSON
```json
{
  "time": 1729857600,
  "event": "SQL_INJECTION",
  "severity": "high",
  "source": { "ip": "192.168.1.100", "port": 54321 },
  "destination": { "ip": "10.0.0.50", "port": 80 },
  "action": "BLOCKED",
  "metadata": { ... }
}
```

## Compliance Reports

### SOC 2 Controls
- **CC6.1**: Logical and Physical Access Controls
- **CC7.2**: Detection of Security Events and Incidents
- **CC7.3**: Security Incident Response and Mitigation
- **CC7.4**: Identification of Incidents and Abnormal Events

### PCI-DSS Requirements
- **10.1**: Implement audit trails
- **10.2**: Implement automated audit trails
- **10.3**: Record audit trail entries
- **11.4**: Use intrusion-detection/prevention techniques

## Best Practices

1. **Regular PCAP Captures**: Enable automatic capture for critical incidents
2. **Compliance Reporting**: Generate monthly compliance reports
3. **SIEM Integration**: Configure real-time export to your SIEM
4. **Evidence Retention**: Maintain forensic data according to compliance requirements
5. **Attack Replay**: Use for security training and incident response drills
6. **Chain of Custody**: Ensure evidence integrity for legal purposes

## Statistics

```javascript
const stats = ForensicsService.getStatistics();
console.log('Total incidents:', stats.totalIncidents);
console.log('By type:', stats.byType);
console.log('By severity:', stats.bySeverity);
console.log('PCAP captures:', stats.pcapCaptures);
console.log('Reports generated:', stats.reportsGenerated);
```

## Integration Example

```javascript
import ForensicsService from './services/ForensicsService';
import FirewallService from './services/FirewallService';

// Integrate with firewall
FirewallService.on('packet-blocked', async (packet) => {
  // Log incident
  const incident = ForensicsService.logIncident({
    type: 'FIREWALL_BLOCK',
    severity: 'medium',
    source: packet.source,
    destination: packet.destination,
    protocol: packet.protocol,
    action: 'BLOCKED'
  });

  // Start PCAP capture for critical incidents
  if (packet.severity === 'critical') {
    await ForensicsService.startPCAPCapture({
      filter: `host ${packet.source.ip}`,
      maxDuration: 300000 // 5 minutes
    });
  }

  // Export to SIEM
  await ForensicsService.exportToSIEM('CEF', {
    incidents: [incident]
  });
});
```

## Troubleshooting

### PCAP Capture Issues
- Ensure administrator/root privileges for packet capture
- Install WinPcap (Windows) or libpcap (Linux/Mac)
- Check network interface permissions

### SIEM Export Issues
- Verify SIEM endpoint connectivity
- Check format compatibility with target SIEM
- Ensure proper authentication credentials

### Report Generation Issues
- Verify sufficient disk space
- Check directory permissions
- Ensure all required data is available

## Support

For forensics and reporting support:
- Check incident logs in `%APPDATA%/NebulaShield/forensics/incidents/`
- Review PCAP captures in `forensics/pcap/`
- Consult generated reports in `forensics/reports/`
