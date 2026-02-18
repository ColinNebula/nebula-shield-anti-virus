/**
 * Network Traffic Analysis Service
 * Deep packet inspection and threat detection for network traffic
 * Real-time monitoring with advanced threat intelligence
 */

import notificationService from './notificationService';

class NetworkTrafficAnalysis {
  constructor() {
    this.monitoring = false;
    this.connections = new Map();
    this.packetLog = [];
    this.alerts = [];
    this.statistics = {
      packetsAnalyzed: 0,
      threatsBlocked: 0,
      suspiciousActivity: 0,
      bandwidthUsed: { sent: 0, received: 0 },
      lastAnalysis: null
    };
    this.listeners = new Set();
    this.threatSignatures = this.loadThreatSignatures();
    this.behavioralPatterns = new Map();
    this.whitelistedDomains = new Set(['google.com', 'microsoft.com', 'github.com']);
    this.blacklistedIPs = new Set();
    this.loadSettings();
  }

  // ==================== THREAT SIGNATURES ====================
  
  loadThreatSignatures() {
    return {
      // Malware communication patterns
      malware: {
        beaconing: {
          name: 'Command & Control Beaconing',
          pattern: /regular intervals/,
          minOccurrences: 5,
          timeWindow: 60000, // 1 minute
          severity: 'critical'
        },
        dataExfiltration: {
          name: 'Data Exfiltration',
          uploadThreshold: 10485760, // 10 MB
          timeWindow: 60000,
          severity: 'critical'
        },
        dnsQuery: {
          name: 'DNS Tunneling',
          pattern: /([a-f0-9]{32,}|[A-Z0-9]{20,})\./i,
          severity: 'high'
        }
      },

      // SQL Injection patterns
      sqlInjection: [
        { pattern: /(\bunion\b.*?\bselect\b|\bselect\b.*?\bfrom\b.*?\bwhere\b)/i, name: 'SQL Union/Select', severity: 'critical' },
        { pattern: /'.*?(?:or|and).*?'.*?=.*?'/i, name: 'SQL Boolean Injection', severity: 'critical' },
        { pattern: /;\s*drop\s+table/i, name: 'SQL Drop Table', severity: 'critical' },
        { pattern: /\bexec\s*\(/i, name: 'SQL Exec Statement', severity: 'high' }
      ],

      // XSS patterns
      xss: [
        { pattern: /<script[^>]*>.*?<\/script>/is, name: 'Script Tag Injection', severity: 'high' },
        { pattern: /javascript:/i, name: 'JavaScript Protocol', severity: 'medium' },
        { pattern: /on(?:load|error|click|mouseover)\s*=/i, name: 'Event Handler Injection', severity: 'high' },
        { pattern: /eval\s*\(/i, name: 'Eval Function', severity: 'high' }
      ],

      // Command injection
      commandInjection: [
        { pattern: /[;&|]\s*(?:cat|ls|pwd|whoami|id|uname|rm|wget|curl)/i, name: 'Shell Command Injection', severity: 'critical' },
        { pattern: /\$\(.*?\)|`.*?`/i, name: 'Command Substitution', severity: 'critical' },
        { pattern: /\|\s*(?:nc|netcat|bash|sh)/i, name: 'Reverse Shell Attempt', severity: 'critical' }
      ],

      // Crypto mining signatures
      cryptoMining: [
        { pattern: /coinhive|cryptonight|monero|xmrig/i, name: 'Crypto Mining Script', severity: 'high' },
        { pattern: /stratum\+tcp/i, name: 'Mining Pool Connection', severity: 'high' },
        { pattern: /minerd|cpuminer/i, name: 'Mining Software', severity: 'high' }
      ],

      // Obfuscation patterns
      obfuscation: [
        { pattern: /eval\(atob\(/i, name: 'Base64 Eval Obfuscation', severity: 'high' },
        { pattern: /unescape\(.*?%/i, name: 'URL Encoding Obfuscation', severity: 'medium' },
        { pattern: /String\.fromCharCode/i, name: 'Character Code Obfuscation', severity: 'medium' }
      ],

      // Path traversal
      pathTraversal: [
        { pattern: /\.\.\/|\.\.\\|%2e%2e/i, name: 'Directory Traversal', severity: 'high' },
        { pattern: /\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32/i, name: 'System File Access', severity: 'critical' }
      ],

      // Ransomware indicators
      ransomware: [
        { pattern: /\.encrypt|\.locked|\.crypto|\.zzzzz/i, name: 'Ransomware File Extension', severity: 'critical' },
        { pattern: /YOUR FILES ARE ENCRYPTED|PAY.*BITCOIN|DECRYPT.*KEY/i, name: 'Ransomware Message', severity: 'critical' }
      ],

      // Phishing patterns
      phishing: [
        { pattern: /verify.*account|suspended.*account|unusual.*activity/i, name: 'Phishing Keywords', severity: 'medium' },
        { pattern: /urgently|immediate action|click here now/i, name: 'Urgency Tactics', severity: 'medium' }
      ]
    };
  }

  // ==================== DEEP PACKET INSPECTION ====================
  
  async inspectPacket(packet) {
    const inspection = {
      packetId: packet.id || `pkt-${Date.now()}`,
      timestamp: new Date().toISOString(),
      source: packet.source,
      destination: packet.destination,
      protocol: packet.protocol,
      size: packet.payload?.length || 0,
      findings: [],
      threatLevel: 'clean',
      riskScore: 0,
      action: 'allow'
    };

    // Skip if whitelisted
    if (this.isWhitelisted(packet.destination)) {
      inspection.action = 'allow';
      inspection.whitelisted = true;
      return inspection;
    }

    // Check if blacklisted
    if (this.isBlacklisted(packet.source) || this.isBlacklisted(packet.destination)) {
      inspection.threatLevel = 'critical';
      inspection.riskScore = 100;
      inspection.action = 'block';
      inspection.findings.push({
        category: 'blacklist',
        name: 'Blacklisted IP/Domain',
        severity: 'critical',
        matched: packet.destination
      });
      return inspection;
    }

    const payload = packet.payload || '';

    // Run signature matching
    await this.matchSignatures(payload, inspection);

    // Behavioral analysis
    await this.analyzeBehavior(packet, inspection);

    // Protocol-specific analysis
    await this.analyzeProtocol(packet, inspection);

    // Calculate final risk score and determine action
    this.calculateRiskScore(inspection);

    // Update statistics
    this.statistics.packetsAnalyzed++;
    if (inspection.action === 'block') {
      this.statistics.threatsBlocked++;
    }
    if (inspection.threatLevel !== 'clean') {
      this.statistics.suspiciousActivity++;
    }

    // Log packet
    this.logPacket(inspection);

    // Generate alerts for threats
    if (inspection.threatLevel === 'critical' || inspection.threatLevel === 'high') {
      this.generateAlert(inspection);
    }

    return inspection;
  }

  async matchSignatures(payload, inspection) {
    const signatures = this.threatSignatures;

    // Check SQL Injection
    for (const sig of signatures.sqlInjection) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'sql_injection',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check XSS
    for (const sig of signatures.xss) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'xss',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check Command Injection
    for (const sig of signatures.commandInjection) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'command_injection',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check Crypto Mining
    for (const sig of signatures.cryptoMining) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'crypto_mining',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check Obfuscation
    for (const sig of signatures.obfuscation) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'obfuscation',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check Path Traversal
    for (const sig of signatures.pathTraversal) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'path_traversal',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check Ransomware
    for (const sig of signatures.ransomware) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'ransomware',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }

    // Check Phishing
    for (const sig of signatures.phishing) {
      if (sig.pattern.test(payload)) {
        inspection.findings.push({
          category: 'phishing',
          name: sig.name,
          severity: sig.severity,
          matched: payload.match(sig.pattern)?.[0] || ''
        });
        inspection.riskScore += this.getSeverityScore(sig.severity);
      }
    }
  }

  async analyzeBehavior(packet, inspection) {
    const key = `${packet.source}-${packet.destination}`;
    
    if (!this.behavioralPatterns.has(key)) {
      this.behavioralPatterns.set(key, {
        firstSeen: Date.now(),
        packetCount: 0,
        bytesSent: 0,
        intervals: [],
        lastPacketTime: Date.now()
      });
    }

    const pattern = this.behavioralPatterns.get(key);
    const now = Date.now();
    const interval = now - pattern.lastPacketTime;

    pattern.packetCount++;
    pattern.bytesSent += packet.payload?.length || 0;
    pattern.intervals.push(interval);
    pattern.lastPacketTime = now;

    // Check for beaconing (regular intervals)
    if (pattern.intervals.length >= 5) {
      const recentIntervals = pattern.intervals.slice(-5);
      const avgInterval = recentIntervals.reduce((a, b) => a + b, 0) / recentIntervals.length;
      const variance = recentIntervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / recentIntervals.length;
      const stdDev = Math.sqrt(variance);

      // Low variance indicates regular beaconing
      if (stdDev < avgInterval * 0.2 && avgInterval > 1000) {
        inspection.findings.push({
          category: 'behavioral',
          name: 'C&C Beaconing Detected',
          severity: 'critical',
          matched: `Regular intervals: ~${Math.round(avgInterval / 1000)}s`
        });
        inspection.riskScore += 50;
      }
    }

    // Check for data exfiltration (large upload)
    const timeSinceFirst = now - pattern.firstSeen;
    if (timeSinceFirst < 60000 && pattern.bytesSent > 10485760) { // 10MB in 1 minute
      inspection.findings.push({
        category: 'behavioral',
        name: 'Possible Data Exfiltration',
        severity: 'critical',
        matched: `${Math.round(pattern.bytesSent / 1048576)}MB uploaded in ${Math.round(timeSinceFirst / 1000)}s`
      });
      inspection.riskScore += 60;
    }

    // Check for port scanning (many connections to different ports)
    const destinationPorts = new Set();
    for (const [k, v] of this.behavioralPatterns.entries()) {
      if (k.startsWith(packet.source)) {
        destinationPorts.add(k.split('-')[1].split(':')[1]);
      }
    }
    if (destinationPorts.size > 10) {
      inspection.findings.push({
        category: 'behavioral',
        name: 'Port Scanning Detected',
        severity: 'high',
        matched: `${destinationPorts.size} different ports accessed`
      });
      inspection.riskScore += 40;
    }

    // Clean up old patterns (older than 5 minutes)
    if (timeSinceFirst > 300000) {
      this.behavioralPatterns.delete(key);
    }
  }

  async analyzeProtocol(packet, inspection) {
    const protocol = packet.protocol?.toUpperCase();

    switch (protocol) {
      case 'DNS':
        this.analyzeDNS(packet, inspection);
        break;
      case 'HTTP':
      case 'HTTPS':
        this.analyzeHTTP(packet, inspection);
        break;
      case 'FTP':
        this.analyzeFTP(packet, inspection);
        break;
      case 'SMTP':
        this.analyzeSMTP(packet, inspection);
        break;
      case 'SMB':
        this.analyzeSMB(packet, inspection);
        break;
    }
  }

  analyzeDNS(packet, inspection) {
    const payload = packet.payload || '';
    
    // Check for DNS tunneling
    if (this.threatSignatures.malware.dnsQuery.pattern.test(payload)) {
      inspection.findings.push({
        category: 'dns',
        name: 'Possible DNS Tunneling',
        severity: 'high',
        matched: 'Suspicious DNS query pattern'
      });
      inspection.riskScore += 40;
    }

    // Check for DGA (Domain Generation Algorithm)
    const domain = packet.destination;
    if (domain && this.isDGADomain(domain)) {
      inspection.findings.push({
        category: 'dns',
        name: 'DGA Domain Detected',
        severity: 'high',
        matched: domain
      });
      inspection.riskScore += 45;
    }
  }

  analyzeHTTP(packet, inspection) {
    const payload = packet.payload || '';

    // Check for suspicious user agents
    const userAgentMatch = payload.match(/User-Agent:\s*([^\r\n]+)/i);
    if (userAgentMatch) {
      const userAgent = userAgentMatch[1];
      if (this.isSuspiciousUserAgent(userAgent)) {
        inspection.findings.push({
          category: 'http',
          name: 'Suspicious User Agent',
          severity: 'medium',
          matched: userAgent
        });
        inspection.riskScore += 20;
      }
    }

    // Check for unencrypted credentials
    if (payload.match(/password=|pwd=|pass=/i) && packet.protocol === 'HTTP') {
      inspection.findings.push({
        category: 'http',
        name: 'Unencrypted Credentials',
        severity: 'high',
        matched: 'Credentials sent over HTTP'
      });
      inspection.riskScore += 30;
    }
  }

  analyzeFTP(packet, inspection) {
    const payload = packet.payload || '';

    // Check for FTP credentials
    if (payload.match(/USER |PASS /i)) {
      inspection.findings.push({
        category: 'ftp',
        name: 'FTP Credentials in Clear Text',
        severity: 'medium',
        matched: 'FTP authentication detected'
      });
      inspection.riskScore += 15;
    }
  }

  analyzeSMTP(packet, inspection) {
    const payload = packet.payload || '';

    // Check for email with suspicious content
    if (payload.match(/verify.*account|suspended.*account|click.*link/i)) {
      inspection.findings.push({
        category: 'smtp',
        name: 'Potential Phishing Email',
        severity: 'medium',
        matched: 'Phishing keywords detected'
      });
      inspection.riskScore += 25;
    }
  }

  analyzeSMB(packet, inspection) {
    // SMB is often used in ransomware lateral movement
    inspection.findings.push({
      category: 'smb',
      name: 'SMB Traffic Detected',
      severity: 'low',
      matched: 'Monitor for ransomware activity'
    });
    inspection.riskScore += 10;
  }

  // ==================== HELPER FUNCTIONS ====================
  
  isDGADomain(domain) {
    // Simple DGA detection based on entropy and randomness
    if (!domain || domain.length < 10) return false;

    const parts = domain.split('.');
    const subdomain = parts[0];

    // Check entropy (randomness)
    const entropy = this.calculateEntropy(subdomain);
    if (entropy > 3.5) return true;

    // Check for consonant clusters
    const consonantClusters = subdomain.match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi);
    if (consonantClusters && consonantClusters.length > 0) return true;

    // Check for numeric sequences
    const numericRatio = (subdomain.match(/\d/g) || []).length / subdomain.length;
    if (numericRatio > 0.3) return true;

    return false;
  }

  calculateEntropy(str) {
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  isSuspiciousUserAgent(userAgent) {
    const suspicious = [
      /python|curl|wget|scanner|bot|crawler/i,
      /^[a-z]{1,3}$/i, // Too short
      /\d{10,}/i // Long numeric sequences
    ];

    return suspicious.some(pattern => pattern.test(userAgent));
  }

  getSeverityScore(severity) {
    const scores = {
      critical: 50,
      high: 35,
      medium: 20,
      low: 10
    };
    return scores[severity] || 0;
  }

  calculateRiskScore(inspection) {
    // Cap risk score at 100
    inspection.riskScore = Math.min(inspection.riskScore, 100);

    // Determine threat level
    if (inspection.riskScore >= 70) {
      inspection.threatLevel = 'critical';
      inspection.action = 'block';
    } else if (inspection.riskScore >= 50) {
      inspection.threatLevel = 'high';
      inspection.action = 'warn';
    } else if (inspection.riskScore >= 30) {
      inspection.threatLevel = 'medium';
      inspection.action = 'warn';
    } else if (inspection.riskScore >= 15) {
      inspection.threatLevel = 'low';
      inspection.action = 'allow';
    } else {
      inspection.threatLevel = 'clean';
      inspection.action = 'allow';
    }
  }

  // ==================== WHITELIST/BLACKLIST ====================
  
  isWhitelisted(target) {
    if (!target) return false;
    return Array.from(this.whitelistedDomains).some(domain => 
      target.includes(domain)
    );
  }

  isBlacklisted(target) {
    if (!target) return false;
    return this.blacklistedIPs.has(target);
  }

  addToWhitelist(domain) {
    this.whitelistedDomains.add(domain);
    this.saveSettings();
  }

  removeFromWhitelist(domain) {
    this.whitelistedDomains.delete(domain);
    this.saveSettings();
  }

  addToBlacklist(ip) {
    this.blacklistedIPs.add(ip);
    this.saveSettings();
  }

  removeFromBlacklist(ip) {
    this.blacklistedIPs.delete(ip);
    this.saveSettings();
  }

  // ==================== LOGGING & ALERTS ====================
  
  logPacket(inspection) {
    this.packetLog.unshift(inspection);
    
    // Keep only last 1000 packets
    if (this.packetLog.length > 1000) {
      this.packetLog = this.packetLog.slice(0, 1000);
    }

    this.notifyListeners('packet-inspected', inspection);
  }

  generateAlert(inspection) {
    const alert = {
      id: `alert-${Date.now()}`,
      timestamp: new Date().toISOString(),
      threatLevel: inspection.threatLevel,
      source: inspection.source,
      destination: inspection.destination,
      protocol: inspection.protocol,
      findings: inspection.findings,
      riskScore: inspection.riskScore,
      action: inspection.action
    };

    this.alerts.unshift(alert);

    // Keep only last 100 alerts
    if (this.alerts.length > 100) {
      this.alerts = this.alerts.slice(0, 100);
    }

    this.notifyListeners('alert-generated', alert);

    // Show notification
    const severity = inspection.threatLevel;
    const type = severity === 'critical' ? 'error' : 'warning';
    
    notificationService.show({
      type,
      title: `🚨 ${severity.toUpperCase()} Network Threat Detected`,
      message: `${inspection.findings[0]?.name || 'Unknown threat'} - ${inspection.action}ed`,
      duration: severity === 'critical' ? 0 : 10000,
      actions: severity === 'critical' ? [
        {
          label: 'View Details',
          onClick: () => this.notifyListeners('show-alert-details', alert)
        },
        {
          label: 'Block Permanently',
          onClick: () => this.addToBlacklist(inspection.source)
        }
      ] : []
    });
  }

  // ==================== MONITORING ====================
  
  startMonitoring() {
    if (this.monitoring) return;

    this.monitoring = true;
    this.statistics.lastAnalysis = new Date().toISOString();
    this.notifyListeners('monitoring-started', {});

    notificationService.show({
      type: 'info',
      title: 'Network Traffic Analysis Active',
      message: 'Deep packet inspection is now monitoring network traffic',
      duration: 5000
    });

    // Simulate packet capture (in production, this would use native packet capture)
    this.monitoringInterval = setInterval(() => {
      this.capturePackets();
    }, 1000);
  }

  stopMonitoring() {
    if (!this.monitoring) return;

    this.monitoring = false;
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    this.notifyListeners('monitoring-stopped', {});

    notificationService.show({
      type: 'info',
      title: 'Network Traffic Analysis Stopped',
      message: 'Network monitoring has been disabled',
      duration: 5000
    });
  }

  async capturePackets() {
    // Simulate packet capture (demo purposes)
    // In production, this would interface with native packet capture library
    
    const packets = this.simulatePackets();
    
    for (const packet of packets) {
      await this.inspectPacket(packet);
    }
  }

  simulatePackets() {
    // Generate realistic network packets for demo
    const packets = [];
    const packetCount = Math.floor(Math.random() * 5) + 1;

    for (let i = 0; i < packetCount; i++) {
      const type = Math.random();
      
      if (type < 0.7) {
        // Normal traffic
        packets.push({
          id: `pkt-${Date.now()}-${i}`,
          source: '192.168.1.100',
          destination: 'google.com',
          protocol: 'HTTPS',
          payload: 'GET / HTTP/1.1\r\nHost: google.com\r\nUser-Agent: Mozilla/5.0'
        });
      } else if (type < 0.85) {
        // Suspicious traffic
        packets.push({
          id: `pkt-${Date.now()}-${i}`,
          source: '192.168.1.100',
          destination: 'unknown-domain.com',
          protocol: 'HTTP',
          payload: 'GET /admin.php?id=1\' OR \'1\'=\'1 HTTP/1.1'
        });
      } else {
        // Malicious traffic
        packets.push({
          id: `pkt-${Date.now()}-${i}`,
          source: '192.168.1.100',
          destination: '185.220.101.1',
          protocol: 'TCP',
          payload: 'eval(atob("bWFsaWNpb3VzX2NvZGU="))'
        });
      }
    }

    return packets;
  }

  // ==================== DATA MANAGEMENT ====================
  
  getPacketLog() {
    return this.packetLog;
  }

  getAlerts() {
    return this.alerts;
  }

  getStatistics() {
    return { ...this.statistics };
  }

  clearLogs() {
    this.packetLog = [];
    this.notifyListeners('logs-cleared', {});
  }

  clearAlerts() {
    this.alerts = [];
    this.notifyListeners('alerts-cleared', {});
  }

  resetStatistics() {
    this.statistics = {
      packetsAnalyzed: 0,
      threatsBlocked: 0,
      suspiciousActivity: 0,
      bandwidthUsed: { sent: 0, received: 0 },
      lastAnalysis: null
    };
    this.saveSettings();
  }

  // ==================== SETTINGS ====================
  
  loadSettings() {
    try {
      const stored = localStorage.getItem('network-traffic-analysis-settings');
      if (stored) {
        const settings = JSON.parse(stored);
        this.whitelistedDomains = new Set(settings.whitelistedDomains || []);
        this.blacklistedIPs = new Set(settings.blacklistedIPs || []);
        this.statistics = settings.statistics || this.statistics;
      }
    } catch (error) {
      console.warn('Failed to load network traffic analysis settings:', error);
    }
  }

  saveSettings() {
    try {
      const settings = {
        whitelistedDomains: Array.from(this.whitelistedDomains),
        blacklistedIPs: Array.from(this.blacklistedIPs),
        statistics: this.statistics
      };
      localStorage.setItem('network-traffic-analysis-settings', JSON.stringify(settings));
    } catch (error) {
      console.warn('Failed to save network traffic analysis settings:', error);
    }
  }

  // ==================== EVENT LISTENERS ====================
  
  addListener(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  removeListener(callback) {
    this.listeners.delete(callback);
  }

  notifyListeners(event, data) {
    this.listeners.forEach(callback => {
      try {
        callback(event, data);
      } catch (error) {
        console.error('Listener error:', error);
      }
    });
  }

  // ==================== CLEANUP ====================
  
  destroy() {
    this.stopMonitoring();
    this.listeners.clear();
    this.behavioralPatterns.clear();
  }
}

// Export singleton instance
const networkTrafficAnalysis = new NetworkTrafficAnalysis();
export default networkTrafficAnalysis;
