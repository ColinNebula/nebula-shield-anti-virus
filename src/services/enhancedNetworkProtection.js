/**
 * Enhanced Network Protection Service
 * Advanced intrusion detection, DDoS protection, and packet analysis
 */

// ==================== THREAT INTELLIGENCE DATABASE ====================

const THREAT_DATABASE = {
  // Known malicious IPs with severity and type
  maliciousIPs: [
    { ip: '185.220.101.1', type: 'Tor Exit Node', severity: 'high', country: 'Unknown', asn: 'AS00000' },
    { ip: '45.142.122.3', type: 'C2 Server', severity: 'critical', country: 'Russia', asn: 'AS12345' },
    { ip: '198.98.57.207', type: 'Botnet', severity: 'critical', country: 'China', asn: 'AS54321' },
    { ip: '91.219.236.197', type: 'Scanning Host', severity: 'high', country: 'Russia', asn: 'AS67890' },
    { ip: '23.129.64.216', type: 'Malware Distribution', severity: 'critical', country: 'USA', asn: 'AS99999' },
    { ip: '185.220.100.240', type: 'Tor Exit Node', severity: 'high', country: 'Unknown', asn: 'AS00000' },
    { ip: '103.253.145.12', type: 'DDoS Source', severity: 'critical', country: 'Singapore', asn: 'AS11111' }
  ],

  // Attack signatures for pattern matching
  attackSignatures: [
    {
      id: 'sig_001',
      name: 'Port Scan Detection',
      pattern: 'multiple_syn_packets',
      threshold: 10,
      timeWindow: 5, // seconds
      severity: 'medium',
      description: 'Detects rapid connection attempts to multiple ports'
    },
    {
      id: 'sig_002',
      name: 'SYN Flood Attack',
      pattern: 'syn_flood',
      threshold: 100,
      timeWindow: 1,
      severity: 'critical',
      description: 'Detects DDoS SYN flood attacks'
    },
    {
      id: 'sig_003',
      name: 'Brute Force SSH',
      pattern: 'ssh_auth_failure',
      threshold: 5,
      timeWindow: 60,
      severity: 'high',
      description: 'Detects SSH brute force attempts'
    },
    {
      id: 'sig_004',
      name: 'Brute Force RDP',
      pattern: 'rdp_auth_failure',
      threshold: 5,
      timeWindow: 60,
      severity: 'high',
      description: 'Detects RDP brute force attempts'
    },
    {
      id: 'sig_005',
      name: 'SQL Injection',
      pattern: 'sql_keywords',
      threshold: 1,
      timeWindow: 1,
      severity: 'critical',
      description: 'Detects SQL injection attempts in traffic'
    },
    {
      id: 'sig_006',
      name: 'DNS Tunneling',
      pattern: 'dns_subdomain_length',
      threshold: 50,
      timeWindow: 1,
      severity: 'high',
      description: 'Detects DNS tunneling for data exfiltration'
    }
  ],

  // Known exploit patterns
  exploitPatterns: [
    { pattern: 'EternalBlue', ports: [445], protocol: 'TCP', cve: 'CVE-2017-0144' },
    { pattern: 'BlueKeep', ports: [3389], protocol: 'TCP', cve: 'CVE-2019-0708' },
    { pattern: 'Log4Shell', ports: [80, 443, 8080], protocol: 'TCP', cve: 'CVE-2021-44228' },
    { pattern: 'ProxyLogon', ports: [443], protocol: 'TCP', cve: 'CVE-2021-26855' }
  ]
};

// ==================== GEO-IP DATABASE (ENHANCED) ====================

const GEO_DATABASE = {
  // Major services
  '8.8.8.8': { country: 'United States', city: 'Mountain View', org: 'Google DNS', flag: '🇺🇸', risk: 'low' },
  '1.1.1.1': { country: 'United States', city: 'San Francisco', org: 'Cloudflare DNS', flag: '🇺🇸', risk: 'low' },
  '142.250.': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸', risk: 'low' },
  '172.217.': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸', risk: 'low' },
  '151.101.': { country: 'United States', city: 'San Francisco', org: 'Fastly CDN', flag: '🇺🇸', risk: 'low' },
  '104.244.': { country: 'United States', city: 'San Francisco', org: 'Twitter', flag: '🇺🇸', risk: 'low' },
  '13.107.': { country: 'United States', city: 'Redmond', org: 'Microsoft', flag: '🇺🇸', risk: 'low' },
  '20.190.': { country: 'United States', city: 'Redmond', org: 'Microsoft Azure', flag: '🇺🇸', risk: 'low' },
  '52.': { country: 'United States', city: 'Various', org: 'Amazon AWS', flag: '🇺🇸', risk: 'low' },
  
  // High-risk regions
  '185.220.': { country: 'Unknown', city: 'Unknown', org: 'Tor Exit Node', flag: '⚠️', risk: 'high' },
  '91.219.': { country: 'Russia', city: 'Moscow', org: 'Unknown ISP', flag: '🇷🇺', risk: 'high' },
  '45.142.': { country: 'Russia', city: 'St. Petersburg', org: 'Datacenter', flag: '🇷🇺', risk: 'high' },
  '103.253.': { country: 'Singapore', city: 'Singapore', org: 'Unknown Hosting', flag: '🇸🇬', risk: 'medium' }
};

// ==================== INTRUSION DETECTION ENGINE ====================

class IntrusionDetectionSystem {
  constructor() {
    this.eventLog = [];
    this.blockedIPs = new Set();
    this.suspiciousActivity = [];
    this.packetStats = {
      total: 0,
      analyzed: 0,
      blocked: 0,
      suspicious: 0
    };
  }

  /**
   * Analyze packet for threats
   */
  analyzePacket(packet) {
    this.packetStats.total++;
    this.packetStats.analyzed++;

    const threats = [];

    // Check against malicious IP database
    const maliciousIP = THREAT_DATABASE.maliciousIPs.find(
      entry => entry.ip === packet.sourceIP || entry.ip === packet.destIP
    );
    
    if (maliciousIP) {
      threats.push({
        type: 'Malicious IP',
        severity: maliciousIP.severity,
        description: `Connection to known ${maliciousIP.type}`,
        ip: maliciousIP.ip,
        details: maliciousIP
      });
    }

    // Check for port scanning
    if (this.detectPortScan(packet)) {
      threats.push({
        type: 'Port Scan',
        severity: 'medium',
        description: 'Multiple connection attempts detected',
        ip: packet.sourceIP
      });
    }

    // Check for exploit patterns
    const exploit = this.detectExploit(packet);
    if (exploit) {
      threats.push({
        type: 'Exploit Attempt',
        severity: 'critical',
        description: `${exploit.pattern} exploit detected (${exploit.cve})`,
        ip: packet.sourceIP,
        cve: exploit.cve
      });
    }

    // Check for anomalous traffic
    if (this.detectAnomaly(packet)) {
      threats.push({
        type: 'Anomalous Traffic',
        severity: 'low',
        description: 'Unusual traffic pattern detected',
        ip: packet.sourceIP
      });
    }

    if (threats.length > 0) {
      this.packetStats.suspicious++;
      this.logThreat(packet, threats);
      return { blocked: true, threats };
    }

    return { blocked: false, threats: [] };
  }

  detectPortScan(packet) {
    // Simplified port scan detection
    const recentConnections = this.eventLog.filter(
      e => e.sourceIP === packet.sourceIP && 
      Date.now() - e.timestamp < 5000
    );
    
    const uniquePorts = new Set(recentConnections.map(e => e.destPort));
    return uniquePorts.size > 10;
  }

  detectExploit(packet) {
    return THREAT_DATABASE.exploitPatterns.find(
      exploit => exploit.ports.includes(packet.destPort) && 
      exploit.protocol === packet.protocol
    );
  }

  detectAnomaly(packet) {
    // Detect unusually large packets or high frequency
    return packet.size > 65000 || packet.frequency > 1000;
  }

  logThreat(packet, threats) {
    this.suspiciousActivity.push({
      timestamp: Date.now(),
      packet,
      threats,
      action: 'logged'
    });

    // Keep only last 1000 events
    if (this.suspiciousActivity.length > 1000) {
      this.suspiciousActivity.shift();
    }
  }

  getRecentThreats(limit = 50) {
    return this.suspiciousActivity
      .slice(-limit)
      .reverse()
      .map(activity => ({
        ...activity,
        timestamp: new Date(activity.timestamp).toISOString()
      }));
  }

  getStats() {
    return {
      ...this.packetStats,
      blockedIPsCount: this.blockedIPs.size,
      recentThreats: this.suspiciousActivity.length
    };
  }
}

// ==================== DDOS PROTECTION ENGINE ====================

class DDoSProtectionEngine {
  constructor() {
    this.connectionTracker = new Map();
    this.rateLimit = {
      maxConnectionsPerIP: 100,
      maxPacketsPerSecond: 1000,
      timeWindow: 1000 // 1 second
    };
    this.protectionLevel = 'medium';
    this.mitigationActions = [];
    
    // Layer 7 (Application Layer) DDoS Protection
    this.layer7Protection = {
      httpFloodDetection: true,
      slowlorisDetection: true,
      requestRateLimit: 50, // requests per minute per IP
      incompleteRequestTimeout: 30000, // 30 seconds
      connectionLifetime: 300000 // 5 minutes max
    };
    
    // Connection fingerprinting for bot detection
    this.connectionFingerprints = new Map();
    
    // CAPTCHA challenge tracking
    this.captchaChallenges = new Map();
    
    // Slowloris attack tracking
    this.slowConnections = new Map();
  }

  /**
   * Check if traffic is a DDoS attack
   */
  checkDDoS(sourceIP, connections, packet = {}) {
    const now = Date.now();
    
    if (!this.connectionTracker.has(sourceIP)) {
      this.connectionTracker.set(sourceIP, {
        connections: [],
        packets: 0,
        firstSeen: now,
        httpRequests: [],
        incompleteRequests: 0
      });
    }

    const tracker = this.connectionTracker.get(sourceIP);
    tracker.connections.push({ timestamp: now });
    tracker.packets++;

    // Clean old entries
    tracker.connections = tracker.connections.filter(
      conn => now - conn.timestamp < this.rateLimit.timeWindow
    );

    // Check for DDoS patterns
    const connectionCount = tracker.connections.length;
    const duration = now - tracker.firstSeen;

    // SYN flood detection
    if (connectionCount > this.rateLimit.maxConnectionsPerIP) {
      this.logMitigation(sourceIP, 'SYN Flood', 'critical', connectionCount);
      return {
        isDDoS: true,
        type: 'SYN Flood',
        severity: 'critical',
        connectionCount,
        action: 'block'
      };
    }

    // High packet rate detection
    if (tracker.packets > this.rateLimit.maxPacketsPerSecond && duration < 1000) {
      this.logMitigation(sourceIP, 'High Packet Rate', 'high', tracker.packets);
      return {
        isDDoS: true,
        type: 'Packet Flood',
        severity: 'high',
        packetRate: tracker.packets,
        action: 'rate_limit'
      };
    }
    
    // Layer 7 (Application Layer) DDoS Detection
    const layer7Result = this.detectLayer7DDoS(sourceIP, packet);
    if (layer7Result.isDDoS) {
      return layer7Result;
    }
    
    // Slowloris/Slow HTTP Attack Detection
    const slowAttackResult = this.detectSlowAttack(sourceIP, packet);
    if (slowAttackResult.isDDoS) {
      return slowAttackResult;
    }

    return { isDDoS: false };
  }
  
  /**
   * Detect Layer 7 (Application Layer) DDoS attacks
   */
  detectLayer7DDoS(sourceIP, packet) {
    if (!this.layer7Protection.httpFloodDetection) {
      return { isDDoS: false };
    }
    
    const now = Date.now();
    const tracker = this.connectionTracker.get(sourceIP);
    
    // Track HTTP requests
    if (packet.protocol === 'HTTP' || packet.protocol === 'HTTPS' || packet.destPort === 80 || packet.destPort === 443) {
      tracker.httpRequests.push(now);
      
      // Clean old requests (older than 1 minute)
      tracker.httpRequests = tracker.httpRequests.filter(t => now - t < 60000);
      
      // HTTP Flood Detection
      const requestsPerMinute = tracker.httpRequests.length;
      if (requestsPerMinute > this.layer7Protection.requestRateLimit) {
        this.logMitigation(sourceIP, 'HTTP Flood', 'high', requestsPerMinute);
        
        // Issue CAPTCHA challenge instead of immediate block
        this.issueCaptchaChallenge(sourceIP);
        
        return {
          isDDoS: true,
          type: 'HTTP Flood (Layer 7)',
          severity: 'high',
          requestsPerMinute,
          action: 'captcha_challenge',
          description: `Detected ${requestsPerMinute} HTTP requests in 1 minute`
        };
      }
      
      // Connection fingerprinting for bot detection
      const fingerprintResult = this.checkConnectionFingerprint(sourceIP, packet);
      if (fingerprintResult.isBot) {
        this.logMitigation(sourceIP, 'Bot Detection', 'medium', fingerprintResult.score);
        return {
          isDDoS: true,
          type: 'Bot Traffic Detected',
          severity: 'medium',
          botScore: fingerprintResult.score,
          action: 'captcha_challenge',
          description: fingerprintResult.reason
        };
      }
    }
    
    return { isDDoS: false };
  }
  
  /**
   * Detect Slowloris and Slow HTTP attacks
   */
  detectSlowAttack(sourceIP, packet) {
    if (!this.layer7Protection.slowlorisDetection) {
      return { isDDoS: false };
    }
    
    const now = Date.now();
    
    if (!this.slowConnections.has(sourceIP)) {
      this.slowConnections.set(sourceIP, {
        connections: [],
        incompleteRequests: 0
      });
    }
    
    const slowTracker = this.slowConnections.get(sourceIP);
    
    // Track connection establishment time
    if (packet.flags && packet.flags.includes('SYN')) {
      slowTracker.connections.push({
        startTime: now,
        completed: false,
        bytesSent: 0
      });
    }
    
    // Check for incomplete requests that remain open too long
    slowTracker.connections = slowTracker.connections.filter(conn => {
      const age = now - conn.startTime;
      
      // Connection older than timeout and incomplete
      if (!conn.completed && age > this.layer7Protection.incompleteRequestTimeout) {
        slowTracker.incompleteRequests++;
        return false;
      }
      
      // Remove very old connections
      return age < this.layer7Protection.connectionLifetime;
    });
    
    // Slowloris Detection: Many incomplete requests from same IP
    if (slowTracker.incompleteRequests > 10) {
      this.logMitigation(sourceIP, 'Slowloris Attack', 'critical', slowTracker.incompleteRequests);
      return {
        isDDoS: true,
        type: 'Slowloris Attack',
        severity: 'critical',
        incompleteRequests: slowTracker.incompleteRequests,
        action: 'block',
        description: `Detected ${slowTracker.incompleteRequests} slow/incomplete HTTP requests`
      };
    }
    
    // Slow POST Attack Detection
    const activeSlowConnections = slowTracker.connections.filter(c => !c.completed).length;
    if (activeSlowConnections > 20) {
      this.logMitigation(sourceIP, 'Slow HTTP POST', 'high', activeSlowConnections);
      return {
        isDDoS: true,
        type: 'Slow HTTP POST Attack',
        severity: 'high',
        activeConnections: activeSlowConnections,
        action: 'rate_limit',
        description: `Detected ${activeSlowConnections} slow HTTP connections`
      };
    }
    
    return { isDDoS: false };
  }
  
  /**
   * Connection fingerprinting for bot detection
   */
  checkConnectionFingerprint(sourceIP, packet) {
    if (!this.connectionFingerprints.has(sourceIP)) {
      this.connectionFingerprints.set(sourceIP, {
        userAgents: new Set(),
        tcpOptions: [],
        requestPatterns: [],
        behaviorScore: 0
      });
    }
    
    const fingerprint = this.connectionFingerprints.get(sourceIP);
    let botScore = 0;
    let reasons = [];
    
    // Check User-Agent consistency
    if (packet.headers && packet.headers['user-agent']) {
      fingerprint.userAgents.add(packet.headers['user-agent']);
      
      // Bots often rotate user agents frequently
      if (fingerprint.userAgents.size > 5) {
        botScore += 30;
        reasons.push('Rotating user agents');
      }
      
      // Check for common bot user agent patterns
      const ua = packet.headers['user-agent'].toLowerCase();
      if (ua.includes('bot') || ua.includes('crawler') || ua.includes('spider') || 
          ua.includes('curl') || ua.includes('wget') || ua.includes('python')) {
        botScore += 40;
        reasons.push('Bot user agent detected');
      }
    }
    
    // Check request pattern regularity (bots often make perfectly timed requests)
    if (packet.timestamp) {
      fingerprint.requestPatterns.push(packet.timestamp);
      
      if (fingerprint.requestPatterns.length >= 10) {
        const intervals = [];
        for (let i = 1; i < fingerprint.requestPatterns.length; i++) {
          intervals.push(fingerprint.requestPatterns[i] - fingerprint.requestPatterns[i-1]);
        }
        
        // Calculate variance in intervals
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;
        
        // Very low variance = robotic behavior
        if (variance < 100 && avgInterval < 5000) {
          botScore += 25;
          reasons.push('Robotic request timing');
        }
        
        // Keep only recent patterns
        fingerprint.requestPatterns = fingerprint.requestPatterns.slice(-20);
      }
    }
    
    // Check for missing browser headers
    if (packet.headers) {
      const hasAccept = packet.headers['accept'];
      const hasAcceptLanguage = packet.headers['accept-language'];
      const hasAcceptEncoding = packet.headers['accept-encoding'];
      
      if (!hasAccept || !hasAcceptLanguage || !hasAcceptEncoding) {
        botScore += 15;
        reasons.push('Missing browser headers');
      }
    }
    
    return {
      isBot: botScore >= 50,
      score: botScore,
      reason: reasons.join(', '),
      fingerprint
    };
  }
  
  /**
   * Issue CAPTCHA challenge to suspicious traffic
   */
  issueCaptchaChallenge(sourceIP) {
    const challengeId = Math.random().toString(36).substring(7);
    const expiresAt = Date.now() + 300000; // 5 minutes
    
    this.captchaChallenges.set(sourceIP, {
      id: challengeId,
      issuedAt: Date.now(),
      expiresAt,
      attempts: 0,
      solved: false
    });
    
    // Emit event for frontend to display CAPTCHA
    return {
      requiresCaptcha: true,
      challengeId,
      message: 'Please complete CAPTCHA to continue'
    };
  }
  
  /**
   * Verify CAPTCHA response
   */
  verifyCaptcha(sourceIP, challengeId, response) {
    const challenge = this.captchaChallenges.get(sourceIP);
    
    if (!challenge || challenge.id !== challengeId) {
      return { valid: false, reason: 'Invalid challenge ID' };
    }
    
    if (Date.now() > challenge.expiresAt) {
      this.captchaChallenges.delete(sourceIP);
      return { valid: false, reason: 'Challenge expired' };
    }
    
    challenge.attempts++;
    
    // Simulate CAPTCHA verification (in production, use real CAPTCHA service)
    const isValid = response && response.length > 0;
    
    if (isValid) {
      challenge.solved = true;
      return { valid: true, message: 'CAPTCHA solved successfully' };
    } else {
      if (challenge.attempts >= 3) {
        this.captchaChallenges.delete(sourceIP);
        return { valid: false, reason: 'Too many failed attempts' };
      }
      return { valid: false, reason: 'Incorrect CAPTCHA response' };
    }
  }

  logMitigation(ip, attackType, severity, metric) {
    this.mitigationActions.push({
      timestamp: new Date().toISOString(),
      ip,
      attackType,
      severity,
      metric,
      action: 'blocked'
    });

    // Keep only last 100 mitigations
    if (this.mitigationActions.length > 100) {
      this.mitigationActions.shift();
    }
  }

  setProtectionLevel(level) {
    this.protectionLevel = level;
    
    switch (level) {
      case 'low':
        this.rateLimit.maxConnectionsPerIP = 200;
        this.rateLimit.maxPacketsPerSecond = 2000;
        break;
      case 'medium':
        this.rateLimit.maxConnectionsPerIP = 100;
        this.rateLimit.maxPacketsPerSecond = 1000;
        break;
      case 'high':
        this.rateLimit.maxConnectionsPerIP = 50;
        this.rateLimit.maxPacketsPerSecond = 500;
        break;
      case 'maximum':
        this.rateLimit.maxConnectionsPerIP = 20;
        this.rateLimit.maxPacketsPerSecond = 200;
        break;
    }
  }

  getMitigationHistory() {
    return this.mitigationActions.slice(-50).reverse();
  }

  getStats() {
    return {
      protectionLevel: this.protectionLevel,
      rateLimit: this.rateLimit,
      totalMitigations: this.mitigationActions.length,
      activeIPTracking: this.connectionTracker.size
    };
  }
}

// ==================== TRAFFIC ANALYZER ====================

class TrafficAnalyzer {
  constructor() {
    this.trafficHistory = [];
    this.protocolStats = {
      TCP: { packets: 0, bytes: 0 },
      UDP: { packets: 0, bytes: 0 },
      ICMP: { packets: 0, bytes: 0 },
      HTTP: { packets: 0, bytes: 0 },
      HTTPS: { packets: 0, bytes: 0 },
      DNS: { packets: 0, bytes: 0 }
    };
    this.portStats = {};
    this.geoStats = {};
  }

  analyzeTraffic(packet) {
    // Update protocol stats
    if (this.protocolStats[packet.protocol]) {
      this.protocolStats[packet.protocol].packets++;
      this.protocolStats[packet.protocol].bytes += packet.size || 0;
    }

    // Update port stats
    const port = packet.destPort;
    if (!this.portStats[port]) {
      this.portStats[port] = { packets: 0, bytes: 0 };
    }
    this.portStats[port].packets++;
    this.portStats[port].bytes += packet.size || 0;

    // Update geo stats
    const geo = packet.geo || { country: 'Unknown' };
    if (!this.geoStats[geo.country]) {
      this.geoStats[geo.country] = { packets: 0, bytes: 0, flag: geo.flag };
    }
    this.geoStats[geo.country].packets++;
    this.geoStats[geo.country].bytes += packet.size || 0;

    // Add to history
    this.trafficHistory.push({
      timestamp: Date.now(),
      protocol: packet.protocol,
      bytes: packet.size || 0
    });

    // Keep only last 1000 packets
    if (this.trafficHistory.length > 1000) {
      this.trafficHistory.shift();
    }
  }

  getTopPorts(limit = 10) {
    return Object.entries(this.portStats)
      .sort(([, a], [, b]) => b.packets - a.packets)
      .slice(0, limit)
      .map(([port, stats]) => ({
        port: parseInt(port),
        ...stats,
        service: this.getServiceName(parseInt(port))
      }));
  }

  getTopCountries(limit = 10) {
    return Object.entries(this.geoStats)
      .sort(([, a], [, b]) => b.packets - a.packets)
      .slice(0, limit)
      .map(([country, stats]) => ({
        country,
        ...stats
      }));
  }

  getServiceName(port) {
    const services = {
      80: 'HTTP',
      443: 'HTTPS',
      53: 'DNS',
      22: 'SSH',
      21: 'FTP',
      25: 'SMTP',
      110: 'POP3',
      143: 'IMAP',
      3389: 'RDP',
      3306: 'MySQL',
      5432: 'PostgreSQL',
      27017: 'MongoDB'
    };
    return services[port] || 'Unknown';
  }

  getProtocolDistribution() {
    return this.protocolStats;
  }

  getBandwidthTrend() {
    // Calculate bandwidth over last minute
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    const recentTraffic = this.trafficHistory.filter(
      t => t.timestamp > oneMinuteAgo
    );

    const totalBytes = recentTraffic.reduce((sum, t) => sum + t.bytes, 0);
    const avgBytesPerSecond = totalBytes / 60;
    const mbps = (avgBytesPerSecond * 8) / 1000000; // Convert to Mbps

    return {
      current: mbps,
      totalBytes,
      packetCount: recentTraffic.length
    };
  }
}

// ==================== AUTOMATED RESPONSE SYSTEM ====================

class AutomatedResponseSystem {
  constructor() {
    // IP Reputation Database
    this.ipReputations = new Map();
    
    // Whitelist auto-learning
    this.autoWhitelist = new Map();
    this.whitelistThreshold = {
      requestCount: 1000,    // 1000+ successful requests
      timeSpan: 86400000,    // Over 24 hours
      errorRate: 0.05,       // < 5% error rate
      consistencyScore: 0.8  // High behavior consistency
    };
    
    // Firewall rules auto-generated
    this.autoFirewallRules = [];
    
    // Progressive penalty system
    this.penaltyLevels = {
      0: { name: 'clean', action: 'allow', duration: 0 },
      1: { name: 'warning', action: 'monitor', duration: 300000 }, // 5 min
      2: { name: 'caution', action: 'throttle_light', duration: 900000 }, // 15 min
      3: { name: 'suspicious', action: 'throttle_heavy', duration: 1800000 }, // 30 min
      4: { name: 'hostile', action: 'block_temporary', duration: 3600000 }, // 1 hour
      5: { name: 'malicious', action: 'block_permanent', duration: Infinity }
    };
    
    // Response history
    this.responseHistory = [];
  }
  
  /**
   * Calculate dynamic IP reputation score (0-100)
   */
  calculateIPReputation(ip, activityHistory) {
    if (!this.ipReputations.has(ip)) {
      this.ipReputations.set(ip, {
        score: 50, // Neutral starting score
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        requestCount: 0,
        successfulRequests: 0,
        failedRequests: 0,
        blockedRequests: 0,
        captchaSolved: 0,
        captchaFailed: 0,
        violationHistory: [],
        penaltyLevel: 0
      });
    }
    
    const reputation = this.ipReputations.get(ip);
    let score = reputation.score;
    
    // Positive indicators (increase score)
    if (activityHistory.successful) {
      reputation.successfulRequests++;
      score += 0.5;
    }
    
    if (activityHistory.captchaSolved) {
      reputation.captchaSolved++;
      score += 2;
    }
    
    // Negative indicators (decrease score)
    if (activityHistory.failed) {
      reputation.failedRequests++;
      score -= 1;
    }
    
    if (activityHistory.blocked) {
      reputation.blockedRequests++;
      score -= 5;
    }
    
    if (activityHistory.captchaFailed) {
      reputation.captchaFailed++;
      score -= 3;
    }
    
    if (activityHistory.ddosDetected) {
      reputation.violationHistory.push({ type: 'ddos', timestamp: Date.now() });
      score -= 15;
    }
    
    if (activityHistory.exploitDetected) {
      reputation.violationHistory.push({ type: 'exploit', timestamp: Date.now() });
      score -= 20;
    }
    
    // Time-based score recovery (good behavior over time)
    const daysSinceFirstSeen = (Date.now() - reputation.firstSeen) / 86400000;
    if (daysSinceFirstSeen > 7 && reputation.violationHistory.length === 0) {
      score += daysSinceFirstSeen * 0.1; // Slow recovery
    }
    
    // Clamp score between 0-100
    score = Math.max(0, Math.min(100, score));
    reputation.score = score;
    reputation.lastSeen = Date.now();
    reputation.requestCount++;
    
    return {
      score,
      category: this.getReputationCategory(score),
      trustLevel: this.getTrustLevel(score),
      reputation
    };
  }
  
  /**
   * Get reputation category
   */
  getReputationCategory(score) {
    if (score >= 90) return 'excellent';
    if (score >= 75) return 'good';
    if (score >= 50) return 'neutral';
    if (score >= 25) return 'suspicious';
    if (score >= 10) return 'bad';
    return 'malicious';
  }
  
  /**
   * Get trust level
   */
  getTrustLevel(score) {
    if (score >= 80) return 'trusted';
    if (score >= 60) return 'moderate';
    if (score >= 40) return 'low';
    return 'untrusted';
  }
  
  /**
   * Apply progressive penalty system
   */
  applyProgressivePenalty(ip, violation) {
    const reputation = this.ipReputations.get(ip);
    if (!reputation) return null;
    
    // Calculate violation severity
    const severityScore = this.calculateViolationSeverity(violation);
    
    // Determine new penalty level
    let newPenaltyLevel = reputation.penaltyLevel;
    
    if (severityScore >= 80) {
      newPenaltyLevel = 5; // Immediate permanent block
    } else if (severityScore >= 60) {
      newPenaltyLevel = Math.min(5, reputation.penaltyLevel + 2);
    } else if (severityScore >= 40) {
      newPenaltyLevel = Math.min(5, reputation.penaltyLevel + 1);
    } else if (severityScore >= 20) {
      // Stay at current level or increase by 1
      if (reputation.violationHistory.length > 3) {
        newPenaltyLevel = Math.min(5, reputation.penaltyLevel + 1);
      }
    }
    
    reputation.penaltyLevel = newPenaltyLevel;
    const penalty = this.penaltyLevels[newPenaltyLevel];
    
    // Log penalty application
    const penaltyRecord = {
      timestamp: Date.now(),
      ip,
      violation: violation.type,
      previousLevel: reputation.penaltyLevel - (newPenaltyLevel - reputation.penaltyLevel),
      newLevel: newPenaltyLevel,
      action: penalty.action,
      duration: penalty.duration,
      expiresAt: penalty.duration === Infinity ? null : Date.now() + penalty.duration
    };
    
    this.responseHistory.push(penaltyRecord);
    
    // Generate firewall rule if blocking
    if (penalty.action.includes('block')) {
      this.generateFirewallRule(ip, penalty, violation);
    }
    
    return penaltyRecord;
  }
  
  /**
   * Calculate violation severity score
   */
  calculateViolationSeverity(violation) {
    const severityMap = {
      'ddos_critical': 90,
      'ddos_high': 70,
      'ddos_medium': 50,
      'exploit_critical': 95,
      'exploit_high': 75,
      'exploit_medium': 55,
      'slowloris': 80,
      'bot_traffic': 40,
      'brute_force': 60,
      'sql_injection': 85,
      'xss_attack': 70,
      'suspicious_pattern': 35
    };
    
    const key = `${violation.type}_${violation.severity}`.toLowerCase();
    return severityMap[key] || 30;
  }
  
  /**
   * Auto-generate firewall rule
   */
  generateFirewallRule(ip, penalty, violation) {
    const rule = {
      id: `auto_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: 'auto-generated',
      createdAt: Date.now(),
      expiresAt: penalty.duration === Infinity ? null : Date.now() + penalty.duration,
      sourceIP: ip,
      action: penalty.action.includes('permanent') ? 'drop' : 'reject',
      protocol: 'any',
      direction: 'inbound',
      enabled: true,
      priority: 'high',
      reason: `Auto-generated: ${violation.type} (${violation.severity})`,
      penaltyLevel: penalty.name,
      metadata: {
        violationType: violation.type,
        severity: violation.severity,
        autoGenerated: true,
        canExpire: penalty.duration !== Infinity
      }
    };
    
    this.autoFirewallRules.push(rule);
    
    // Emit event for firewall to apply rule
    this.emitFirewallRuleEvent(rule);
    
    return rule;
  }
  
  /**
   * Whitelist auto-learning system
   */
  evaluateForWhitelisting(ip) {
    const reputation = this.ipReputations.get(ip);
    if (!reputation) return { shouldWhitelist: false };
    
    // Check if already in auto-whitelist
    if (this.autoWhitelist.has(ip)) {
      return { shouldWhitelist: true, reason: 'Already whitelisted' };
    }
    
    // Calculate metrics
    const totalRequests = reputation.requestCount;
    const errorRate = reputation.failedRequests / totalRequests;
    const ageInDays = (Date.now() - reputation.firstSeen) / 86400000;
    const consistencyScore = this.calculateConsistencyScore(reputation);
    
    // Evaluation criteria
    const criteria = {
      sufficientRequests: totalRequests >= this.whitelistThreshold.requestCount,
      sufficientAge: ageInDays >= 1, // At least 1 day of history
      lowErrorRate: errorRate < this.whitelistThreshold.errorRate,
      highConsistency: consistencyScore >= this.whitelistThreshold.consistencyScore,
      noViolations: reputation.violationHistory.length === 0,
      highReputation: reputation.score >= 75
    };
    
    // Check if all criteria met
    const allCriteriaMet = Object.values(criteria).every(c => c === true);
    
    if (allCriteriaMet) {
      this.addToAutoWhitelist(ip, reputation);
      return {
        shouldWhitelist: true,
        reason: 'Automatically learned as legitimate user',
        criteria
      };
    }
    
    return {
      shouldWhitelist: false,
      reason: 'Criteria not met',
      criteria,
      missingCriteria: Object.entries(criteria)
        .filter(([k, v]) => !v)
        .map(([k]) => k)
    };
  }
  
  /**
   * Calculate consistency score for IP behavior
   */
  calculateConsistencyScore(reputation) {
    let score = 0;
    
    // Check user agent consistency (if tracking)
    // Check request timing consistency
    // Check endpoint access patterns
    
    // Simplified: base on success rate and violation absence
    const successRate = reputation.successfulRequests / reputation.requestCount;
    const violationPenalty = reputation.violationHistory.length * 0.1;
    
    score = successRate - violationPenalty;
    
    return Math.max(0, Math.min(1, score));
  }
  
  /**
   * Add IP to auto-whitelist
   */
  addToAutoWhitelist(ip, reputation) {
    this.autoWhitelist.set(ip, {
      addedAt: Date.now(),
      reason: 'auto-learned',
      reputation: reputation.score,
      requestCount: reputation.requestCount,
      successRate: reputation.successfulRequests / reputation.requestCount
    });
    
    // Remove any existing auto-generated firewall rules for this IP
    this.removeAutoFirewallRules(ip);
  }
  
  /**
   * Remove auto-generated firewall rules for IP
   */
  removeAutoFirewallRules(ip) {
    this.autoFirewallRules = this.autoFirewallRules.filter(rule => {
      if (rule.sourceIP === ip && rule.metadata.autoGenerated) {
        this.emitFirewallRuleRemovalEvent(rule);
        return false;
      }
      return true;
    });
  }
  
  /**
   * Clean up expired firewall rules
   */
  cleanupExpiredRules() {
    const now = Date.now();
    const expiredRules = [];
    
    this.autoFirewallRules = this.autoFirewallRules.filter(rule => {
      if (rule.expiresAt && rule.expiresAt < now) {
        expiredRules.push(rule);
        this.emitFirewallRuleRemovalEvent(rule);
        return false;
      }
      return true;
    });
    
    return expiredRules;
  }
  
  /**
   * Emit firewall rule event (stub for integration)
   */
  emitFirewallRuleEvent(rule) {
    // This would integrate with actual firewall system
    console.log('[AUTO-FIREWALL] Rule created:', rule);
  }
  
  /**
   * Emit firewall rule removal event
   */
  emitFirewallRuleRemovalEvent(rule) {
    console.log('[AUTO-FIREWALL] Rule removed:', rule.id);
  }
  
  /**
   * Get statistics
   */
  getStats() {
    return {
      totalIPs: this.ipReputations.size,
      whitelistedIPs: this.autoWhitelist.size,
      activeFirewallRules: this.autoFirewallRules.length,
      penaltyDistribution: this.getPenaltyDistribution(),
      reputationDistribution: this.getReputationDistribution()
    };
  }
  
  /**
   * Get penalty distribution
   */
  getPenaltyDistribution() {
    const distribution = {};
    for (let i = 0; i <= 5; i++) {
      distribution[this.penaltyLevels[i].name] = 0;
    }
    
    for (const [ip, rep] of this.ipReputations) {
      const penaltyName = this.penaltyLevels[rep.penaltyLevel].name;
      distribution[penaltyName]++;
    }
    
    return distribution;
  }
  
  /**
   * Get reputation distribution
   */
  getReputationDistribution() {
    const distribution = {
      excellent: 0,
      good: 0,
      neutral: 0,
      suspicious: 0,
      bad: 0,
      malicious: 0
    };
    
    for (const [ip, rep] of this.ipReputations) {
      const category = this.getReputationCategory(rep.score);
      distribution[category]++;
    }
    
    return distribution;
  }
}

// ==================== GLOBAL INSTANCES ====================

const ids = new IntrusionDetectionSystem();
const ddosProtection = new DDoSProtectionEngine();
const trafficAnalyzer = new TrafficAnalyzer();
const automatedResponse = new AutomatedResponseSystem();

// ==================== NETWORK MONITORING ====================

/**
 * Generate simulated network traffic
 */
const generateNetworkTraffic = () => {
  const connections = [
    // Normal web browsing
    {
      id: 'conn_001', protocol: 'TCP', localAddress: '192.168.1.100', localPort: 54321,
      remoteAddress: '142.250.185.46', remotePort: 443, state: 'ESTABLISHED',
      process: 'chrome.exe', pid: 8432, direction: 'outbound',
      bandwidth: { sent: 12400, received: 45600 }, duration: 127, threat: null,
      packets: { sent: 234, received: 456 }, latency: 12
    },
    {
      id: 'conn_002', protocol: 'TCP', localAddress: '192.168.1.100', localPort: 54322,
      remoteAddress: '151.101.1.140', remotePort: 443, state: 'ESTABLISHED',
      process: 'chrome.exe', pid: 8432, direction: 'outbound',
      bandwidth: { sent: 8900, received: 34200 }, duration: 89, threat: null,
      packets: { sent: 178, received: 342 }, latency: 18
    },
    // Microsoft services
    {
      id: 'conn_003', protocol: 'TCP', localAddress: '192.168.1.100', localPort: 54323,
      remoteAddress: '13.107.42.16', remotePort: 443, state: 'ESTABLISHED',
      process: 'MicrosoftEdge.exe', pid: 12456, direction: 'outbound',
      bandwidth: { sent: 5600, received: 18900 }, duration: 234, threat: null,
      packets: { sent: 112, received: 189 }, latency: 15
    },
    // DNS queries
    {
      id: 'conn_004', protocol: 'UDP', localAddress: '192.168.1.100', localPort: 52147,
      remoteAddress: '8.8.8.8', remotePort: 53, state: 'ACTIVE',
      process: 'svchost.exe', pid: 1234, direction: 'outbound',
      bandwidth: { sent: 120, received: 240 }, duration: 2, threat: null,
      packets: { sent: 5, received: 5 }, latency: 8
    },
    // Suspicious Tor connection
    {
      id: 'conn_005', protocol: 'TCP', localAddress: '192.168.1.100', localPort: 54325,
      remoteAddress: '185.220.101.1', remotePort: 9001, state: 'ESTABLISHED',
      process: 'unknown.exe', pid: 9999, direction: 'outbound',
      bandwidth: { sent: 45000, received: 23000 }, duration: 678, 
      packets: { sent: 450, received: 230 }, latency: 234,
      threat: {
        level: 'high', type: 'Tor Exit Node',
        description: 'Connection to known Tor exit node - possible anonymization attempt'
      }
    },
    // Critical: Inbound RDP brute force
    {
      id: 'conn_006', protocol: 'TCP', localAddress: '192.168.1.100', localPort: 3389,
      remoteAddress: '91.219.236.197', remotePort: 54891, state: 'SYN_RECEIVED',
      process: 'svchost.exe', pid: 4, direction: 'inbound',
      bandwidth: { sent: 0, received: 120 }, duration: 1,
      packets: { sent: 0, received: 45 }, latency: 456,
      threat: {
        level: 'critical', type: 'Brute Force Attack',
        description: 'RDP brute force attempt detected from suspicious IP'
      }
    },
    // Critical: DDoS source
    {
      id: 'conn_007', protocol: 'UDP', localAddress: '192.168.1.100', localPort: 80,
      remoteAddress: '103.253.145.12', remotePort: 12345, state: 'SYN_FLOOD',
      process: 'httpd.exe', pid: 5555, direction: 'inbound',
      bandwidth: { sent: 0, received: 567000 }, duration: 5,
      packets: { sent: 0, received: 8900 }, latency: 234,
      threat: {
        level: 'critical', type: 'DDoS Attack',
        description: 'SYN flood attack detected - 8900 packets in 5 seconds'
      }
    },
    // Development servers
    {
      id: 'conn_008', protocol: 'TCP', localAddress: '0.0.0.0', localPort: 3002,
      remoteAddress: '*', remotePort: 0, state: 'LISTENING',
      process: 'node.exe', pid: 15234, direction: 'inbound',
      bandwidth: { sent: 0, received: 0 }, duration: 1234, threat: null,
      packets: { sent: 0, received: 0 }, latency: 0
    },
    {
      id: 'conn_009', protocol: 'TCP', localAddress: '0.0.0.0', localPort: 8082,
      remoteAddress: '*', remotePort: 0, state: 'LISTENING',
      process: 'node.exe', pid: 13824, direction: 'inbound',
      bandwidth: { sent: 0, received: 0 }, duration: 567, threat: null,
      packets: { sent: 0, received: 0 }, latency: 0
    }
  ];

  return connections;
};

/**
 * Get enriched geo location data
 */
const getGeoLocation = (ip) => {
  // Exact match
  if (GEO_DATABASE[ip]) {
    return GEO_DATABASE[ip];
  }

  // Prefix match
  for (const prefix in GEO_DATABASE) {
    if (ip.startsWith(prefix)) {
      return GEO_DATABASE[prefix];
    }
  }

  // Private networks
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.') || ip === '*') {
    return { country: 'Local Network', city: 'LAN', org: 'Private Network', flag: '🏠', risk: 'low' };
  }

  return { country: 'Unknown', city: 'Unknown', org: 'Unknown', flag: '🌍', risk: 'unknown' };
};

// ==================== PUBLIC API ====================

/**
 * Get enhanced active connections with IDS analysis
 */
export const getEnhancedConnections = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const connections = generateNetworkTraffic();
      
      // Enrich with geo data and IDS analysis
      const enriched = connections.map(conn => {
        const geo = getGeoLocation(conn.remoteAddress);
        
        // Analyze packet for threats
        const packet = {
          sourceIP: conn.direction === 'inbound' ? conn.remoteAddress : conn.localAddress,
          destIP: conn.direction === 'inbound' ? conn.localAddress : conn.remoteAddress,
          sourcePort: conn.direction === 'inbound' ? conn.remotePort : conn.localPort,
          destPort: conn.direction === 'inbound' ? conn.localPort : conn.remotePort,
          protocol: conn.protocol,
          size: conn.bandwidth.sent + conn.bandwidth.received,
          frequency: conn.packets ? conn.packets.sent + conn.packets.received : 0
        };

        const idsAnalysis = ids.analyzePacket(packet);
        trafficAnalyzer.analyzeTraffic({ ...packet, geo });

        // Check for DDoS
        const ddosCheck = ddosProtection.checkDDoS(conn.remoteAddress, [conn]);

        let threat = conn.threat;
        if (idsAnalysis.threats.length > 0 && !threat) {
          threat = idsAnalysis.threats[0];
        } else if (ddosCheck.isDDoS && !threat) {
          threat = {
            level: ddosCheck.severity,
            type: ddosCheck.type,
            description: `DDoS attack detected: ${ddosCheck.connectionCount || ddosCheck.packetRate} events`
          };
        }

        return {
          ...conn,
          geo,
          threat,
          idsAnalysis: idsAnalysis.threats,
          ddosCheck
        };
      });

      const summary = {
        total: enriched.length,
        established: enriched.filter(c => c.state === 'ESTABLISHED').length,
        listening: enriched.filter(c => c.state === 'LISTENING').length,
        threats: enriched.filter(c => c.threat).length,
        critical: enriched.filter(c => c.threat?.level === 'critical').length,
        high: enriched.filter(c => c.threat?.level === 'high').length,
        medium: enriched.filter(c => c.threat?.level === 'medium').length,
        inbound: enriched.filter(c => c.direction === 'inbound').length,
        outbound: enriched.filter(c => c.direction === 'outbound').length
      };

      resolve({
        success: true,
        connections: enriched,
        summary,
        timestamp: new Date().toISOString()
      });
    }, 1000);
  });
};

/**
 * Get IDS statistics and recent threats
 */
export const getIDSStats = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        stats: ids.getStats(),
        recentThreats: ids.getRecentThreats(20),
        signatures: THREAT_DATABASE.attackSignatures,
        timestamp: new Date().toISOString()
      });
    }, 300);
  });
};

/**
 * Get DDoS protection status
 */
export const getDDoSStatus = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        stats: ddosProtection.getStats(),
        mitigationHistory: ddosProtection.getMitigationHistory(),
        timestamp: new Date().toISOString()
      });
    }, 300);
  });
};

/**
 * Set DDoS protection level
 */
export const setDDoSProtection = async (level) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      ddosProtection.setProtectionLevel(level);
      resolve({
        success: true,
        level,
        rateLimit: ddosProtection.rateLimit,
        message: `DDoS protection set to ${level}`
      });
    }, 300);
  });
};

/**
 * Get traffic analysis
 */
export const getTrafficAnalysis = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        protocolDistribution: trafficAnalyzer.getProtocolDistribution(),
        topPorts: trafficAnalyzer.getTopPorts(10),
        topCountries: trafficAnalyzer.getTopCountries(10),
        bandwidthTrend: trafficAnalyzer.getBandwidthTrend(),
        timestamp: new Date().toISOString()
      });
    }, 300);
  });
};

/**
 * Get network statistics (enhanced)
 */
export const getEnhancedNetworkStats = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const idsStats = ids.getStats();
      const ddosStats = ddosProtection.getStats();
      const bandwidth = trafficAnalyzer.getBandwidthTrend();

      resolve({
        success: true,
        stats: {
          packetsAnalyzed: idsStats.analyzed,
          packetsBlocked: idsStats.blocked,
          suspiciousPackets: idsStats.suspicious,
          threatsDetected: idsStats.recentThreats,
          ddosMitigations: ddosStats.totalMitigations,
          protectionLevel: ddosStats.protectionLevel,
          bandwidth: {
            current: bandwidth.current,
            peak: 45.6,
            average: 12.3
          },
          totalTraffic: {
            sent: 1250000000, // 1.25 GB
            received: 3450000000, // 3.45 GB
            total: 4700000000 // 4.7 GB
          }
        },
        timestamp: new Date().toISOString()
      });
    }, 500);
  });
};

// Re-export original functions
export {
  scanOpenPorts,
  getFirewallRules,
  addFirewallRule,
  updateFirewallRule,
  deleteFirewallRule,
  applySecurityProfile,
  blockIP
} from './networkProtection';

export default {
  getEnhancedConnections,
  getIDSStats,
  getDDoSStatus,
  setDDoSProtection,
  getTrafficAnalysis,
  getEnhancedNetworkStats
};
