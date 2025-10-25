/**
 * Network Protection Service
 * Real-time network monitoring, firewall management, and intrusion detection
 */

// Known malicious IPs (sample database)
const MALICIOUS_IPS = [
  '185.220.101.1',
  '45.142.122.3',
  '198.98.57.207',
  '91.219.236.197',
  '23.129.64.216',
  '185.220.100.240'
];

// Known command & control servers
const C2_SERVERS = [
  '192.0.2.1',
  '198.51.100.1',
  '203.0.113.1'
];

// Suspicious ports
const SUSPICIOUS_PORTS = {
  outbound: [4444, 5555, 6666, 31337, 12345, 1337, 6667], // Common backdoor/trojan ports
  inbound: [23, 135, 139, 445, 3389, 5900] // Telnet, RPC, SMB, RDP, VNC
};

// GeoIP database (simplified)
const GEO_DATABASE = {
  '8.8.8.8': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸' },
  '1.1.1.1': { country: 'United States', city: 'San Francisco', org: 'Cloudflare', flag: '🇺🇸' },
  '142.250.': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸' },
  '172.217.': { country: 'United States', city: 'Mountain View', org: 'Google LLC', flag: '🇺🇸' },
  '151.101.': { country: 'United States', city: 'San Francisco', org: 'Fastly', flag: '🇺🇸' },
  '104.244.': { country: 'United States', city: 'San Francisco', org: 'Twitter', flag: '🇺🇸' },
  '13.107.': { country: 'United States', city: 'Redmond', org: 'Microsoft', flag: '🇺🇸' },
  '20.190.': { country: 'United States', city: 'Redmond', org: 'Microsoft Azure', flag: '🇺🇸' },
  '185.220.': { country: 'Unknown', city: 'Unknown', org: 'Tor Exit Node', flag: '⚠️' },
  '91.219.': { country: 'Russia', city: 'Moscow', org: 'Unknown ISP', flag: '🇷🇺' }
};

/**
 * Simulate active network connections
 */
const generateActiveConnections = () => {
  const connections = [
    // Browser connections
    {
      id: 'conn_001',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54321,
      remoteAddress: '142.250.185.46',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'chrome.exe',
      pid: 8432,
      direction: 'outbound',
      bandwidth: { sent: 12400, received: 45600 },
      duration: 127,
      threat: null
    },
    {
      id: 'conn_002',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54322,
      remoteAddress: '151.101.1.140',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'chrome.exe',
      pid: 8432,
      direction: 'outbound',
      bandwidth: { sent: 8900, received: 34200 },
      duration: 89,
      threat: null
    },
    // Microsoft services
    {
      id: 'conn_003',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54323,
      remoteAddress: '13.107.42.16',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'MicrosoftEdge.exe',
      pid: 12456,
      direction: 'outbound',
      bandwidth: { sent: 5600, received: 18900 },
      duration: 234,
      threat: null
    },
    // DNS queries
    {
      id: 'conn_004',
      protocol: 'UDP',
      localAddress: '192.168.1.100',
      localPort: 52147,
      remoteAddress: '8.8.8.8',
      remotePort: 53,
      state: 'ACTIVE',
      process: 'svchost.exe',
      pid: 1234,
      direction: 'outbound',
      bandwidth: { sent: 120, received: 240 },
      duration: 2,
      threat: null
    },
    // System updates
    {
      id: 'conn_005',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54324,
      remoteAddress: '20.190.151.9',
      remotePort: 443,
      state: 'ESTABLISHED',
      process: 'WindowsUpdate.exe',
      pid: 5678,
      direction: 'outbound',
      bandwidth: { sent: 3400, received: 156000 },
      duration: 456,
      threat: null
    },
    // Suspicious Tor connection
    {
      id: 'conn_006',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 54325,
      remoteAddress: '185.220.101.1',
      remotePort: 9001,
      state: 'ESTABLISHED',
      process: 'unknown.exe',
      pid: 9999,
      direction: 'outbound',
      bandwidth: { sent: 45000, received: 23000 },
      duration: 678,
      threat: {
        level: 'high',
        type: 'Tor Exit Node',
        description: 'Connection to known Tor exit node - possible anonymization attempt'
      }
    },
    // Suspicious inbound RDP
    {
      id: 'conn_007',
      protocol: 'TCP',
      localAddress: '192.168.1.100',
      localPort: 3389,
      remoteAddress: '91.219.236.197',
      remotePort: 54891,
      state: 'SYN_RECEIVED',
      process: 'svchost.exe',
      pid: 4,
      direction: 'inbound',
      bandwidth: { sent: 0, received: 120 },
      duration: 1,
      threat: {
        level: 'critical',
        type: 'Suspicious Inbound Connection',
        description: 'Unsolicited RDP connection attempt from suspicious IP'
      }
    },
    // Node.js development server
    {
      id: 'conn_008',
      protocol: 'TCP',
      localAddress: '0.0.0.0',
      localPort: 3000,
      remoteAddress: '*',
      remotePort: 0,
      state: 'LISTENING',
      process: 'node.exe',
      pid: 15234,
      direction: 'inbound',
      bandwidth: { sent: 0, received: 0 },
      duration: 1234,
      threat: null
    },
    // Auth server
    {
      id: 'conn_009',
      protocol: 'TCP',
      localAddress: '0.0.0.0',
      localPort: 8082,
      remoteAddress: '*',
      remotePort: 0,
      state: 'LISTENING',
      process: 'node.exe',
      pid: 13824,
      direction: 'inbound',
      bandwidth: { sent: 0, received: 0 },
      duration: 567,
      threat: null
    }
  ];

  return connections;
};

/**
 * Get geolocation for IP address
 */
const getGeoLocation = (ip) => {
  // Check for exact match
  if (GEO_DATABASE[ip]) {
    return GEO_DATABASE[ip];
  }

  // Check for prefix match
  for (const prefix in GEO_DATABASE) {
    if (ip.startsWith(prefix)) {
      return GEO_DATABASE[prefix];
    }
  }

  // Default for private IPs
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return { country: 'Local Network', city: 'LAN', org: 'Private Network', flag: '🏠' };
  }

  return { country: 'Unknown', city: 'Unknown', org: 'Unknown', flag: '🌍' };
};

/**
 * Check if IP is malicious
 */
const checkMaliciousIP = (ip) => {
  if (MALICIOUS_IPS.includes(ip)) {
    return { malicious: true, reason: 'Known malicious IP' };
  }
  if (C2_SERVERS.includes(ip)) {
    return { malicious: true, reason: 'Command & Control server' };
  }
  return { malicious: false };
};

/**
 * Check if port is suspicious
 */
const checkSuspiciousPort = (port, direction) => {
  if (direction === 'outbound' && SUSPICIOUS_PORTS.outbound.includes(port)) {
    return { suspicious: true, reason: 'Common backdoor/trojan port' };
  }
  if (direction === 'inbound' && SUSPICIOUS_PORTS.inbound.includes(port)) {
    return { suspicious: true, reason: 'Commonly exploited service port' };
  }
  return { suspicious: false };
};

/**
 * Scan for open ports on local machine
 */
export const scanOpenPorts = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const openPorts = [
        {
          port: 80,
          protocol: 'TCP',
          service: 'HTTP',
          state: 'LISTENING',
          process: 'httpd.exe',
          pid: 1234,
          risk: 'low',
          recommendation: 'Web server - ensure it\'s intentional'
        },
        {
          port: 443,
          protocol: 'TCP',
          service: 'HTTPS',
          state: 'LISTENING',
          process: 'httpd.exe',
          pid: 1234,
          risk: 'low',
          recommendation: 'Secure web server - normal'
        },
        {
          port: 3000,
          protocol: 'TCP',
          service: 'Node.js Dev Server',
          state: 'LISTENING',
          process: 'node.exe',
          pid: 5678,
          risk: 'low',
          recommendation: 'Development server - close when not in use'
        },
        {
          port: 8082,
          protocol: 'TCP',
          service: 'Auth Server',
          state: 'LISTENING',
          process: 'node.exe',
          pid: 5680,
          risk: 'low',
          recommendation: 'Backend service - normal'
        },
        {
          port: 135,
          protocol: 'TCP',
          service: 'RPC',
          state: 'LISTENING',
          process: 'svchost.exe',
          pid: 892,
          risk: 'medium',
          recommendation: 'Windows RPC - can be exploited, consider disabling if not needed'
        },
        {
          port: 445,
          protocol: 'TCP',
          service: 'SMB',
          state: 'LISTENING',
          process: 'System',
          pid: 4,
          risk: 'high',
          recommendation: 'File sharing - disable if not needed, frequently targeted by ransomware'
        },
        {
          port: 3389,
          protocol: 'TCP',
          service: 'RDP',
          state: 'LISTENING',
          process: 'svchost.exe',
          pid: 1024,
          risk: 'high',
          recommendation: 'Remote Desktop - use VPN or disable if not needed'
        },
        {
          port: 5900,
          protocol: 'TCP',
          service: 'VNC',
          state: 'LISTENING',
          process: 'vnc.exe',
          pid: 3456,
          risk: 'medium',
          recommendation: 'Remote access - ensure strong authentication'
        }
      ];

      resolve({
        success: true,
        ports: openPorts,
        summary: {
          total: openPorts.length,
          low: openPorts.filter(p => p.risk === 'low').length,
          medium: openPorts.filter(p => p.risk === 'medium').length,
          high: openPorts.filter(p => p.risk === 'high').length
        },
        scannedAt: new Date().toISOString()
      });
    }, 2000);
  });
};

/**
 * Get active network connections
 */
export const getActiveConnections = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const connections = generateActiveConnections();
      
      // Enrich with geo data and threat analysis
      const enriched = connections.map(conn => {
        const geo = getGeoLocation(conn.remoteAddress);
        const malicious = checkMaliciousIP(conn.remoteAddress);
        const portCheck = checkSuspiciousPort(
          conn.direction === 'outbound' ? conn.remotePort : conn.localPort,
          conn.direction
        );

        let threat = conn.threat;
        if (malicious.malicious && !threat) {
          threat = {
            level: 'critical',
            type: 'Malicious IP',
            description: malicious.reason
          };
        } else if (portCheck.suspicious && !threat) {
          threat = {
            level: 'medium',
            type: 'Suspicious Port',
            description: portCheck.reason
          };
        }

        return {
          ...conn,
          geo,
          threat
        };
      });

      const summary = {
        total: enriched.length,
        established: enriched.filter(c => c.state === 'ESTABLISHED').length,
        listening: enriched.filter(c => c.state === 'LISTENING').length,
        threats: enriched.filter(c => c.threat).length,
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

// ==================== ADVANCED FIREWALL ENHANCEMENTS ====================

/**
 * Firewall Zone Management
 */
const FIREWALL_ZONES = {
  trusted: {
    name: 'Trusted Zone',
    networks: ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12'],
    defaultAction: 'allow',
    level: 'low',
    description: 'Private networks with minimal restrictions'
  },
  public: {
    name: 'Public Zone',
    networks: ['0.0.0.0/0'],
    defaultAction: 'block',
    level: 'high',
    description: 'Internet with strict filtering'
  },
  dmz: {
    name: 'DMZ Zone',
    networks: ['192.168.100.0/24'],
    defaultAction: 'restrict',
    level: 'medium',
    description: 'Demilitarized zone for public-facing services'
  },
  guest: {
    name: 'Guest Zone',
    networks: ['192.168.200.0/24'],
    defaultAction: 'restrict',
    level: 'medium',
    description: 'Guest network with limited access'
  }
};

/**
 * Threat Intelligence Feed
 */
class ThreatIntelligenceFeed {
  constructor() {
    this.maliciousIPs = new Set(MALICIOUS_IPS);
    this.maliciousDomains = new Set([
      'malware-example.com',
      'phishing-test.net',
      'c2-server.evil',
      'ransomware-distributor.org'
    ]);
    this.compromisedIPs = new Map();
    this.reputationCache = new Map();
    this.lastUpdate = new Date();
  }

  async checkIPReputation(ip) {
    if (this.reputationCache.has(ip)) {
      return this.reputationCache.get(ip);
    }

    let reputation = {
      ip,
      score: 100, // 0-100, higher is better
      status: 'clean',
      threats: [],
      firstSeen: null,
      lastSeen: null,
      categories: []
    };

    // Check against known malicious IPs
    if (this.maliciousIPs.has(ip)) {
      reputation.score = 0;
      reputation.status = 'malicious';
      reputation.threats.push('Known malicious IP');
      reputation.categories.push('malware', 'c2');
    }

    // Check for recent compromise
    if (this.compromisedIPs.has(ip)) {
      const compromiseData = this.compromisedIPs.get(ip);
      reputation.score = Math.max(0, reputation.score - 50);
      reputation.status = 'suspicious';
      reputation.threats.push(`Compromised: ${compromiseData.reason}`);
    }

    // Check Tor exit nodes
    if (ip.startsWith('185.220.')) {
      reputation.score = Math.max(0, reputation.score - 30);
      reputation.status = 'suspicious';
      reputation.categories.push('tor', 'anonymizer');
    }

    // Cache for 1 hour
    this.reputationCache.set(ip, reputation);
    setTimeout(() => this.reputationCache.delete(ip), 3600000);

    return reputation;
  }

  reportCompromisedIP(ip, reason) {
    this.compromisedIPs.set(ip, {
      timestamp: new Date(),
      reason,
      reportedBy: 'firewall'
    });
  }

  addMaliciousIP(ip) {
    this.maliciousIPs.add(ip);
  }

  removeMaliciousIP(ip) {
    this.maliciousIPs.delete(ip);
  }

  getStatistics() {
    return {
      maliciousIPs: this.maliciousIPs.size,
      maliciousDomains: this.maliciousDomains.size,
      compromisedIPs: this.compromisedIPs.size,
      cachedReputations: this.reputationCache.size,
      lastUpdate: this.lastUpdate
    };
  }
}

/**
 * Rate Limiting & DDoS Protection
 */
class RateLimiter {
  constructor() {
    this.connectionCounts = new Map();
    this.blockedIPs = new Map();
    this.config = {
      maxConnectionsPerIP: 100,
      maxConnectionsPerMinute: 50,
      blockDuration: 300000, // 5 minutes
      ddosThreshold: 1000 // connections per second
    };
  }

  checkRateLimit(ip) {
    const now = Date.now();
    
    // Check if IP is blocked
    if (this.blockedIPs.has(ip)) {
      const blockInfo = this.blockedIPs.get(ip);
      if (now - blockInfo.timestamp < this.config.blockDuration) {
        return {
          allowed: false,
          reason: 'rate_limit_exceeded',
          blockedUntil: new Date(blockInfo.timestamp + this.config.blockDuration),
          blockReason: blockInfo.reason
        };
      } else {
        // Unblock after duration
        this.blockedIPs.delete(ip);
      }
    }

    // Get or create connection counter
    if (!this.connectionCounts.has(ip)) {
      this.connectionCounts.set(ip, {
        total: 0,
        recent: [],
        firstSeen: now
      });
    }

    const counter = this.connectionCounts.get(ip);
    counter.total++;
    counter.recent.push(now);

    // Clean old entries (keep last minute)
    counter.recent = counter.recent.filter(t => now - t < 60000);

    // Check rate limits
    if (counter.recent.length > this.config.maxConnectionsPerMinute) {
      this.blockIP(ip, 'Too many connections per minute', now);
      return {
        allowed: false,
        reason: 'rate_limit_exceeded',
        connections: counter.recent.length,
        limit: this.config.maxConnectionsPerMinute
      };
    }

    if (counter.total > this.config.maxConnectionsPerIP) {
      this.blockIP(ip, 'Total connection limit exceeded', now);
      return {
        allowed: false,
        reason: 'connection_limit_exceeded',
        total: counter.total,
        limit: this.config.maxConnectionsPerIP
      };
    }

    // DDoS detection (connections per second)
    const lastSecond = counter.recent.filter(t => now - t < 1000);
    if (lastSecond.length > this.config.ddosThreshold) {
      this.blockIP(ip, 'Possible DDoS attack detected', now);
      return {
        allowed: false,
        reason: 'ddos_detected',
        connectionsPerSecond: lastSecond.length
      };
    }

    return {
      allowed: true,
      connections: counter.recent.length,
      total: counter.total
    };
  }

  blockIP(ip, reason, timestamp) {
    this.blockedIPs.set(ip, { reason, timestamp });
  }

  unblockIP(ip) {
    this.blockedIPs.delete(ip);
  }

  getBlockedIPs() {
    const now = Date.now();
    const blocked = [];
    
    for (const [ip, info] of this.blockedIPs.entries()) {
      if (now - info.timestamp < this.config.blockDuration) {
        blocked.push({
          ip,
          reason: info.reason,
          blockedAt: new Date(info.timestamp),
          unblocksAt: new Date(info.timestamp + this.config.blockDuration)
        });
      }
    }
    
    return blocked;
  }

  getStatistics() {
    return {
      totalIPs: this.connectionCounts.size,
      blockedIPs: this.blockedIPs.size,
      activeConnections: Array.from(this.connectionCounts.values())
        .reduce((sum, c) => sum + c.recent.length, 0)
    };
  }
}

/**
 * Geographic IP Blocking (Geo-Fencing)
 */
class GeoIPFilter {
  constructor() {
    this.blockedCountries = new Set(['KP', 'IR', 'SY']); // North Korea, Iran, Syria
    this.allowedCountries = new Set(); // Empty = allow all except blocked
    this.mode = 'blocklist'; // 'blocklist' or 'allowlist'
  }

  checkCountry(ip) {
    // Simple geo-lookup (in production, use MaxMind GeoIP2 or similar)
    const geo = this.lookupGeo(ip);
    
    if (this.mode === 'blocklist') {
      if (this.blockedCountries.has(geo.countryCode)) {
        return {
          allowed: false,
          reason: 'geo_blocked',
          country: geo.country,
          countryCode: geo.countryCode
        };
      }
    } else if (this.mode === 'allowlist') {
      if (!this.allowedCountries.has(geo.countryCode)) {
        return {
          allowed: false,
          reason: 'geo_not_allowed',
          country: geo.country,
          countryCode: geo.countryCode
        };
      }
    }

    return { allowed: true, geo };
  }

  lookupGeo(ip) {
    // Simplified geo lookup
    for (const [prefix, info] of Object.entries(GEO_DATABASE)) {
      if (ip.startsWith(prefix)) {
        return { ...info, countryCode: 'US' }; // Default to US for demo
      }
    }
    return { country: 'Unknown', countryCode: 'XX', city: 'Unknown', org: 'Unknown' };
  }

  blockCountry(countryCode) {
    this.blockedCountries.add(countryCode);
  }

  unblockCountry(countryCode) {
    this.blockedCountries.delete(countryCode);
  }

  allowCountry(countryCode) {
    this.allowedCountries.add(countryCode);
  }

  setMode(mode) {
    this.mode = mode;
  }
}

/**
 * Deep Packet Inspection (DPI)
 */
class DeepPacketInspector {
  constructor() {
    this.signatures = this.loadSignatures();
  }

  loadSignatures() {
    return {
      malware: [
        { pattern: /eval\(atob\(/i, name: 'Obfuscated JavaScript', severity: 'high' },
        { pattern: /<script[^>]*>.*?(document\.write|eval|unescape)/is, name: 'XSS Attempt', severity: 'high' },
        { pattern: /\bwget\b.*?\bhttp/i, name: 'Wget Download', severity: 'medium' },
        { pattern: /\bcurl\b.*?-o/i, name: 'Curl Download', severity: 'medium' },
        { pattern: /powershell.*?-enc/i, name: 'Encoded PowerShell', severity: 'critical' }
      ],
      sql_injection: [
        { pattern: /(\bunion\b.*?\bselect\b|\bselect\b.*?\bfrom\b.*?\bwhere\b)/i, name: 'SQL Injection', severity: 'critical' },
        { pattern: /'.*?(?:or|and).*?'.*?=.*?'/i, name: 'SQL Boolean Injection', severity: 'critical' },
        { pattern: /;\s*drop\s+table/i, name: 'SQL Drop Table', severity: 'critical' }
      ],
      command_injection: [
        { pattern: /[;&|]\s*(?:cat|ls|pwd|whoami|id|uname)/i, name: 'Command Injection', severity: 'critical' },
        { pattern: /\$\(.*?\)|`.*?`/i, name: 'Command Substitution', severity: 'high' }
      ],
      path_traversal: [
        { pattern: /\.\.\/|\.\.\\|%2e%2e/i, name: 'Path Traversal', severity: 'high' },
        { pattern: /\/etc\/passwd|\/etc\/shadow/i, name: 'Passwd File Access', severity: 'critical' }
      ],
      crypto_mining: [
        { pattern: /coinhive|cryptonight|monero/i, name: 'Crypto Mining Script', severity: 'medium' },
        { pattern: /stratum\+tcp/i, name: 'Mining Pool Connection', severity: 'high' }
      ]
    };
  }

  inspectPayload(payload) {
    const findings = [];

    for (const [category, signatures] of Object.entries(this.signatures)) {
      for (const sig of signatures) {
        if (sig.pattern.test(payload)) {
          findings.push({
            category,
            name: sig.name,
            severity: sig.severity,
            matched: payload.match(sig.pattern)?.[0] || '',
            timestamp: new Date()
          });
        }
      }
    }

    return {
      inspected: true,
      payloadSize: payload.length,
      findings,
      threat: findings.length > 0,
      riskScore: this.calculateRiskScore(findings)
    };
  }

  calculateRiskScore(findings) {
    const severityScores = { critical: 100, high: 70, medium: 40, low: 20 };
    return findings.reduce((score, f) => score + severityScores[f.severity], 0);
  }
}

/**
 * Application Layer Firewall (Layer 7)
 */
class ApplicationFirewall {
  constructor() {
    this.appRules = new Map();
    this.processWhitelist = new Set(['chrome.exe', 'firefox.exe', 'msedge.exe', 'vscode.exe']);
    this.processBlacklist = new Set(['suspicious.exe', 'malware.exe']);
  }

  checkApplication(process, destination) {
    // Check blacklist first
    if (this.processBlacklist.has(process)) {
      return {
        allowed: false,
        reason: 'application_blacklisted',
        process
      };
    }

    // Check application-specific rules
    if (this.appRules.has(process)) {
      const rule = this.appRules.get(process);
      
      // Check if destination is allowed
      if (rule.allowedDestinations && !rule.allowedDestinations.includes('*')) {
        const allowed = rule.allowedDestinations.some(dest => destination.includes(dest));
        if (!allowed) {
          return {
            allowed: false,
            reason: 'destination_not_allowed',
            process,
            destination
          };
        }
      }

      // Check ports
      if (rule.allowedPorts && !rule.allowedPorts.includes('*')) {
        const port = parseInt(destination.split(':')[1]);
        if (!rule.allowedPorts.includes(port)) {
          return {
            allowed: false,
            reason: 'port_not_allowed',
            process,
            port
          };
        }
      }
    }

    return { allowed: true, process };
  }

  addAppRule(process, rule) {
    this.appRules.set(process, rule);
  }

  whitelistProcess(process) {
    this.processWhitelist.add(process);
    this.processBlacklist.delete(process);
  }

  blacklistProcess(process) {
    this.processBlacklist.add(process);
    this.processWhitelist.delete(process);
  }
}

/**
 * Intrusion Prevention System (IPS)
 */
class IntrusionPreventionSystem {
  constructor() {
    this.detectionRules = this.loadIPSRules();
    this.activeThreats = new Map();
    this.autoBlock = true;
  }

  loadIPSRules() {
    return {
      port_scan: {
        name: 'Port Scan Detection',
        threshold: 10, // ports per minute
        action: 'block',
        severity: 'high'
      },
      brute_force: {
        name: 'Brute Force Attack',
        threshold: 5, // failed attempts
        action: 'block',
        severity: 'critical'
      },
      syn_flood: {
        name: 'SYN Flood Attack',
        threshold: 100, // SYN packets per second
        action: 'block',
        severity: 'critical'
      },
      data_exfiltration: {
        name: 'Data Exfiltration',
        threshold: 10485760, // 10 MB in 1 minute
        action: 'alert',
        severity: 'critical'
      }
    };
  }

  detectThreat(connection) {
    const threats = [];

    // Port scan detection
    // (In real implementation, track sequential port connections)
    
    // Brute force detection
    // (Track failed authentication attempts)
    
    // SYN flood detection
    if (connection.state === 'SYN_RECV') {
      // Track SYN packets
    }

    return threats;
  }

  shouldBlock(threatType) {
    const rule = this.detectionRules[threatType];
    return this.autoBlock && rule && rule.action === 'block';
  }
}

// Initialize advanced firewall components
const threatIntelligence = new ThreatIntelligenceFeed();
const rateLimiter = new RateLimiter();
const geoIPFilter = new GeoIPFilter();
const packetInspector = new DeepPacketInspector();
const appFirewall = new ApplicationFirewall();
const ipsSystem = new IntrusionPreventionSystem();

/**
 * Firewall rules database (Enhanced)
 */
let firewallRules = [
  {
    id: 'rule_001',
    name: 'Block Tor Network',
    direction: 'outbound',
    action: 'block',
    protocol: 'TCP',
    ports: [9001, 9030, 9050, 9051],
    ips: MALICIOUS_IPS,
    enabled: true,
    priority: 1,
    description: 'Blocks connections to known Tor exit nodes',
    zone: 'public',
    logging: true,
    rateLimit: null
  },
  {
    id: 'rule_002',
    name: 'Block Inbound RDP',
    direction: 'inbound',
    action: 'block',
    protocol: 'TCP',
    ports: [3389],
    ips: ['*'],
    enabled: false,
    priority: 2,
    description: 'Blocks all inbound Remote Desktop connections',
    zone: 'public',
    logging: true,
    rateLimit: null
  },
  {
    id: 'rule_003',
    name: 'Allow Web Browsing',
    direction: 'outbound',
    action: 'allow',
    protocol: 'TCP',
    ports: [80, 443],
    ips: ['*'],
    enabled: true,
    priority: 10,
    description: 'Allows HTTP and HTTPS traffic',
    zone: 'trusted',
    logging: false,
    rateLimit: { maxPerMinute: 1000 }
  },
  {
    id: 'rule_004',
    name: 'Block SMB',
    direction: 'inbound',
    action: 'block',
    protocol: 'TCP',
    ports: [445, 139],
    ips: ['*'],
    enabled: true,
    priority: 1,
    description: 'Blocks inbound SMB to prevent ransomware spread',
    zone: 'public',
    logging: true,
    rateLimit: null
  },
  {
    id: 'rule_005',
    name: 'Block Malicious IPs (Threat Intel)',
    direction: 'both',
    action: 'block',
    protocol: '*',
    ports: ['*'],
    ips: Array.from(threatIntelligence.maliciousIPs),
    enabled: true,
    priority: 1,
    description: 'Blocks IPs from threat intelligence feed',
    zone: 'public',
    logging: true,
    rateLimit: null
  },
  {
    id: 'rule_006',
    name: 'Rate Limit SSH',
    direction: 'inbound',
    action: 'allow',
    protocol: 'TCP',
    ports: [22],
    ips: ['*'],
    enabled: true,
    priority: 5,
    description: 'Allow SSH with rate limiting',
    zone: 'trusted',
    logging: true,
    rateLimit: { maxPerMinute: 10 }
  },
  {
    id: 'rule_007',
    name: 'DPI - Block Malware Signatures',
    direction: 'both',
    action: 'block',
    protocol: '*',
    ports: ['*'],
    ips: ['*'],
    enabled: true,
    priority: 1,
    description: 'Deep packet inspection for malware signatures',
    zone: 'public',
    logging: true,
    dpi: true
  }
];

/**
 * Get firewall rules
 */
export const getFirewallRules = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        rules: firewallRules,
        summary: {
          total: firewallRules.length,
          enabled: firewallRules.filter(r => r.enabled).length,
          disabled: firewallRules.filter(r => !r.enabled).length,
          block: firewallRules.filter(r => r.action === 'block').length,
          allow: firewallRules.filter(r => r.action === 'allow').length
        }
      });
    }, 500);
  });
};

/**
 * Add firewall rule
 */
export const addFirewallRule = async (rule) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const newRule = {
        ...rule,
        id: `rule_${String(firewallRules.length + 1).padStart(3, '0')}`,
        enabled: true
      };
      firewallRules.push(newRule);
      
      resolve({
        success: true,
        rule: newRule,
        message: 'Firewall rule added successfully'
      });
    }, 300);
  });
};

/**
 * Update firewall rule
 */
export const updateFirewallRule = async (id, updates) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const index = firewallRules.findIndex(r => r.id === id);
      if (index !== -1) {
        firewallRules[index] = { ...firewallRules[index], ...updates };
        resolve({
          success: true,
          rule: firewallRules[index],
          message: 'Firewall rule updated successfully'
        });
      } else {
        resolve({
          success: false,
          message: 'Rule not found'
        });
      }
    }, 300);
  });
};

/**
 * Delete firewall rule
 */
export const deleteFirewallRule = async (id) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const index = firewallRules.findIndex(r => r.id === id);
      if (index !== -1) {
        firewallRules.splice(index, 1);
        resolve({
          success: true,
          message: 'Firewall rule deleted successfully'
        });
      } else {
        resolve({
          success: false,
          message: 'Rule not found'
        });
      }
    }, 300);
  });
};

/**
 * Security profiles
 */
export const applySecurityProfile = async (profileName) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      let newRules = [];
      
      switch (profileName) {
        case 'maximum':
          newRules = [
            { name: 'Block All Inbound', direction: 'inbound', action: 'block', protocol: 'TCP', ports: ['*'], ips: ['*'], priority: 1, description: 'Blocks all inbound connections' },
            { name: 'Allow Web', direction: 'outbound', action: 'allow', protocol: 'TCP', ports: [80, 443], ips: ['*'], priority: 10, description: 'Allows web browsing only' }
          ];
          break;
        case 'balanced':
          newRules = [
            { name: 'Block Suspicious Ports', direction: 'inbound', action: 'block', protocol: 'TCP', ports: [135, 139, 445, 3389], ips: ['*'], priority: 1, description: 'Blocks commonly exploited ports' },
            { name: 'Allow Standard Services', direction: 'outbound', action: 'allow', protocol: 'TCP', ports: [80, 443, 21, 22], ips: ['*'], priority: 10, description: 'Allows standard internet services' }
          ];
          break;
        case 'gaming':
          newRules = [
            { name: 'Allow Gaming Ports', direction: 'inbound', action: 'allow', protocol: 'UDP', ports: [3074, 3075, 27015, 27036], ips: ['*'], priority: 5, description: 'Allows common gaming ports' },
            { name: 'Allow All Outbound', direction: 'outbound', action: 'allow', protocol: 'TCP', ports: ['*'], ips: ['*'], priority: 10, description: 'Allows all outbound traffic' }
          ];
          break;
        default:
          newRules = firewallRules;
      }

      // Generate IDs
      firewallRules = newRules.map((rule, idx) => ({
        ...rule,
        id: `rule_${String(idx + 1).padStart(3, '0')}`,
        enabled: true
      }));

      resolve({
        success: true,
        profile: profileName,
        rules: firewallRules,
        message: `${profileName} security profile applied`
      });
    }, 500);
  });
};

/**
 * Block specific IP
 */
export const blockIP = async (ip, reason) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const newRule = {
        id: `rule_${String(firewallRules.length + 1).padStart(3, '0')}`,
        name: `Block ${ip}`,
        direction: 'both',
        action: 'block',
        protocol: 'TCP',
        ports: ['*'],
        ips: [ip],
        enabled: true,
        priority: 1,
        description: reason || 'Manually blocked IP'
      };
      
      firewallRules.unshift(newRule);
      
      resolve({
        success: true,
        rule: newRule,
        message: `IP ${ip} has been blocked`
      });
    }, 300);
  });
};

/**
 * Get network statistics
 */
export const getNetworkStats = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        stats: {
          totalTraffic: {
            sent: 1250000000, // 1.25 GB
            received: 3450000000, // 3.45 GB
            total: 4700000000 // 4.7 GB
          },
          packetsBlocked: 1247,
          threatsBlocked: 23,
          connectionsActive: 47,
          bandwidthUsage: {
            current: 2.4, // Mbps
            peak: 45.6,
            average: 12.3
          },
          topProcesses: [
            { name: 'chrome.exe', bandwidth: 1200000, percentage: 45 },
            { name: 'node.exe', bandwidth: 800000, percentage: 30 },
            { name: 'svchost.exe', bandwidth: 400000, percentage: 15 },
            { name: 'system', bandwidth: 267000, percentage: 10 }
          ]
        },
        timestamp: new Date().toISOString()
      });
    }, 500);
  });
};

// ==================== ENHANCED FIREWALL FUNCTIONS ====================

/**
 * Check IP reputation using threat intelligence
 */
export const checkIPReputation = async (ip) => {
  return new Promise((resolve) => {
    setTimeout(async () => {
      const reputation = await threatIntelligence.checkIPReputation(ip);
      resolve({
        success: true,
        reputation
      });
    }, 100);
  });
};

/**
 * Check rate limit for IP
 */
export const checkRateLimit = async (ip) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const result = rateLimiter.checkRateLimit(ip);
      resolve({
        success: true,
        result
      });
    }, 50);
  });
};

/**
 * Get blocked IPs from rate limiter
 */
export const getBlockedIPs = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const blocked = rateLimiter.getBlockedIPs();
      resolve({
        success: true,
        blockedIPs: blocked,
        count: blocked.length
      });
    }, 100);
  });
};

/**
 * Unblock IP from rate limiter
 */
export const unblockIP = async (ip) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      rateLimiter.unblockIP(ip);
      resolve({
        success: true,
        message: `IP ${ip} has been unblocked`
      });
    }, 100);
  });
};

/**
 * Inspect packet payload using DPI
 */
export const inspectPacket = async (payload) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const result = packetInspector.inspectPayload(payload);
      resolve({
        success: true,
        inspection: result
      });
    }, 150);
  });
};

/**
 * Check application firewall rules
 */
export const checkApplicationAccess = async (process, destination) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const result = appFirewall.checkApplication(process, destination);
      resolve({
        success: true,
        result
      });
    }, 100);
  });
};

/**
 * Add application to whitelist
 */
export const whitelistApplication = async (process) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      appFirewall.whitelistProcess(process);
      resolve({
        success: true,
        message: `${process} added to whitelist`
      });
    }, 100);
  });
};

/**
 * Add application to blacklist
 */
export const blacklistApplication = async (process) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      appFirewall.blacklistProcess(process);
      resolve({
        success: true,
        message: `${process} added to blacklist`
      });
    }, 100);
  });
};

/**
 * Check geographic location and filtering
 */
export const checkGeoLocation = async (ip) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const result = geoIPFilter.checkCountry(ip);
      resolve({
        success: true,
        result
      });
    }, 100);
  });
};

/**
 * Block traffic from specific country
 */
export const blockCountry = async (countryCode) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      geoIPFilter.blockCountry(countryCode);
      resolve({
        success: true,
        message: `Country ${countryCode} has been blocked`
      });
    }, 100);
  });
};

/**
 * Unblock traffic from specific country
 */
export const unblockCountry = async (countryCode) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      geoIPFilter.unblockCountry(countryCode);
      resolve({
        success: true,
        message: `Country ${countryCode} has been unblocked`
      });
    }, 100);
  });
};

/**
 * Get firewall zones configuration
 */
export const getFirewallZones = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        zones: FIREWALL_ZONES
      });
    }, 100);
  });
};

/**
 * Get comprehensive firewall statistics
 */
export const getFirewallStatistics = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        statistics: {
          threatIntelligence: threatIntelligence.getStatistics(),
          rateLimiter: rateLimiter.getStatistics(),
          rules: {
            total: firewallRules.length,
            enabled: firewallRules.filter(r => r.enabled).length,
            disabled: firewallRules.filter(r => !r.enabled).length,
            blockRules: firewallRules.filter(r => r.action === 'block').length,
            allowRules: firewallRules.filter(r => r.action === 'allow').length,
            dpiEnabled: firewallRules.filter(r => r.dpi).length,
            rateLimited: firewallRules.filter(r => r.rateLimit).length
          },
          zones: Object.keys(FIREWALL_ZONES).length,
          geoFiltering: {
            mode: geoIPFilter.mode,
            blockedCountries: geoIPFilter.blockedCountries.size,
            allowedCountries: geoIPFilter.allowedCountries.size
          }
        },
        timestamp: new Date().toISOString()
      });
    }, 200);
  });
};

/**
 * Perform comprehensive connection analysis
 */
export const analyzeConnection = async (connection) => {
  return new Promise((resolve) => {
    setTimeout(async () => {
      const analysis = {
        connectionId: connection.id,
        timestamp: new Date().toISOString(),
        
        // IP Reputation
        sourceReputation: await threatIntelligence.checkIPReputation(connection.remoteAddress),
        
        // Rate limiting
        rateLimit: rateLimiter.checkRateLimit(connection.remoteAddress),
        
        // Geo-location
        geoCheck: geoIPFilter.checkCountry(connection.remoteAddress),
        
        // Application check
        appCheck: appFirewall.checkApplication(connection.process, connection.remoteAddress),
        
        // IPS detection
        ipsThreats: ipsSystem.detectThreat(connection),
        
        // Risk scoring
        riskScore: 0,
        recommendation: 'allow',
        reasons: []
      };

      // Calculate risk score
      if (analysis.sourceReputation.status === 'malicious') {
        analysis.riskScore += 100;
        analysis.recommendation = 'block';
        analysis.reasons.push('Malicious IP detected');
      } else if (analysis.sourceReputation.status === 'suspicious') {
        analysis.riskScore += 50;
        analysis.reasons.push('Suspicious IP');
      }

      if (!analysis.rateLimit.allowed) {
        analysis.riskScore += 30;
        analysis.recommendation = 'block';
        analysis.reasons.push(`Rate limit: ${analysis.rateLimit.reason}`);
      }

      if (!analysis.geoCheck.allowed) {
        analysis.riskScore += 40;
        analysis.recommendation = 'block';
        analysis.reasons.push(`Geo-blocked: ${analysis.geoCheck.reason}`);
      }

      if (!analysis.appCheck.allowed) {
        analysis.riskScore += 60;
        analysis.recommendation = 'block';
        analysis.reasons.push(`App policy: ${analysis.appCheck.reason}`);
      }

      if (analysis.riskScore === 0) {
        analysis.reasons.push('No threats detected');
      }

      resolve({
        success: true,
        analysis
      });
    }, 300);
  });
};

/**
 * Add malicious IP to threat intelligence
 */
export const reportMaliciousIP = async (ip, reason) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      threatIntelligence.addMaliciousIP(ip);
      threatIntelligence.reportCompromisedIP(ip, reason);
      
      resolve({
        success: true,
        message: `IP ${ip} added to threat intelligence database`,
        reason
      });
    }, 100);
  });
};

/**
 * Remove IP from malicious list
 */
export const removeMaliciousIP = async (ip) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      threatIntelligence.removeMaliciousIP(ip);
      
      resolve({
        success: true,
        message: `IP ${ip} removed from threat intelligence database`
      });
    }, 100);
  });
};

/**
 * Get IPS (Intrusion Prevention System) status
 */
export const getIPSStatus = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        success: true,
        ips: {
          enabled: ipsSystem.autoBlock,
          rules: Object.keys(ipsSystem.detectionRules).length,
          activeThreats: ipsSystem.activeThreats.size,
          detectionRules: ipsSystem.detectionRules
        }
      });
    }, 100);
  });
};

/**
 * Enable/Disable IPS auto-blocking
 */
export const setIPSAutoBlock = async (enabled) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      ipsSystem.autoBlock = enabled;
      
      resolve({
        success: true,
        message: `IPS auto-blocking ${enabled ? 'enabled' : 'disabled'}`,
        autoBlock: ipsSystem.autoBlock
      });
    }, 100);
  });
};

/**
 * Test firewall rule against connection
 */
export const testFirewallRule = async (rule, connection) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const matches = [];
      const blocks = [];

      // Check direction
      if (rule.direction !== 'both' && rule.direction !== connection.direction) {
        return resolve({
          success: true,
          matches: false,
          reason: 'Direction mismatch'
        });
      }

      // Check protocol
      if (rule.protocol !== '*' && rule.protocol !== connection.protocol) {
        return resolve({
          success: true,
          matches: false,
          reason: 'Protocol mismatch'
        });
      }

      // Check port
      if (!rule.ports.includes('*') && !rule.ports.includes(connection.remotePort)) {
        return resolve({
          success: true,
          matches: false,
          reason: 'Port mismatch'
        });
      }

      // Check IP
      if (!rule.ips.includes('*') && !rule.ips.includes(connection.remoteAddress)) {
        return resolve({
          success: true,
          matches: false,
          reason: 'IP mismatch'
        });
      }

      resolve({
        success: true,
        matches: true,
        action: rule.action,
        rule: rule.name,
        reason: `Rule matches - Action: ${rule.action}`
      });
    }, 100);
  });
};

/**
 * Get advanced firewall recommendations
 */
export const getFirewallRecommendations = async () => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const recommendations = [];

      // Check for duplicate rules
      const ruleSignatures = new Map();
      firewallRules.forEach(rule => {
        const sig = `${rule.direction}-${rule.action}-${rule.protocol}-${rule.ports.join(',')}`; 
        if (ruleSignatures.has(sig)) {
          recommendations.push({
            type: 'duplicate_rule',
            severity: 'low',
            title: 'Duplicate Rule Detected',
            description: `Rule "${rule.name}" is similar to "${ruleSignatures.get(sig)}"`,
            suggestion: 'Consider consolidating duplicate rules'
          });
        }
        ruleSignatures.set(sig, rule.name);
      });

      // Check for conflicting rules
      const blockRules = firewallRules.filter(r => r.action === 'block' && r.enabled);
      const allowRules = firewallRules.filter(r => r.action === 'allow' && r.enabled);
      
      // Check if any allow rules conflict with block rules
      allowRules.forEach(allow => {
        blockRules.forEach(block => {
          if (allow.protocol === block.protocol || block.protocol === '*') {
            const portOverlap = allow.ports.some(p => block.ports.includes(p) || block.ports.includes('*'));
            if (portOverlap) {
              recommendations.push({
                type: 'rule_conflict',
                severity: 'medium',
                title: 'Conflicting Rules',
                description: `Allow rule "${allow.name}" may conflict with block rule "${block.name}"`,
                suggestion: 'Review rule priorities to ensure correct behavior'
              });
            }
          }
        });
      });

      // Check for missing essential rules
      const hasInboundSMBBlock = firewallRules.some(r => 
        r.enabled && r.action === 'block' && r.direction === 'inbound' && 
        (r.ports.includes(445) || r.ports.includes(139))
      );
      if (!hasInboundSMBBlock) {
        recommendations.push({
          type: 'security_gap',
          severity: 'high',
          title: 'Missing SMB Protection',
          description: 'No firewall rule blocking inbound SMB connections',
          suggestion: 'Add rule to block ports 445 and 139 to prevent ransomware spread'
        });
      }

      // Check for open RDP
      const hasRDPBlock = firewallRules.some(r =>
        r.enabled && r.action === 'block' && r.direction === 'inbound' && r.ports.includes(3389)
      );
      if (!hasRDPBlock) {
        recommendations.push({
          type: 'security_gap',
          severity: 'critical',
          title: 'RDP Port Exposed',
          description: 'Remote Desktop (port 3389) is not blocked',
          suggestion: 'Block inbound RDP or restrict to specific IPs only'
        });
      }

      // Check rate limiting
      const criticalPortsWithoutRateLimit = firewallRules.filter(r =>
        r.enabled && r.action === 'allow' && !r.rateLimit &&
        (r.ports.includes(22) || r.ports.includes(21) || r.ports.includes(3389))
      );
      if (criticalPortsWithoutRateLimit.length > 0) {
        recommendations.push({
          type: 'performance_risk',
          severity: 'medium',
          title: 'Missing Rate Limiting',
          description: `${criticalPortsWithoutRateLimit.length} allow rules on critical ports lack rate limiting`,
          suggestion: 'Add rate limits to prevent brute force attacks'
        });
      }

      // Check DPI coverage
      const dpiRules = firewallRules.filter(r => r.dpi && r.enabled);
      if (dpiRules.length === 0) {
        recommendations.push({
          type: 'security_gap',
          severity: 'high',
          title: 'No Deep Packet Inspection',
          description: 'DPI is not enabled on any firewall rules',
          suggestion: 'Enable DPI for enhanced malware detection'
        });
      }

      resolve({
        success: true,
        recommendations,
        summary: {
          total: recommendations.length,
          critical: recommendations.filter(r => r.severity === 'critical').length,
          high: recommendations.filter(r => r.severity === 'high').length,
          medium: recommendations.filter(r => r.severity === 'medium').length,
          low: recommendations.filter(r => r.severity === 'low').length
        }
      });
    }, 500);
  });
};

export default {
  scanOpenPorts,
  getActiveConnections,
  getFirewallRules,
  addFirewallRule,
  updateFirewallRule,
  deleteFirewallRule,
  applySecurityProfile,
  blockIP,
  getNetworkStats,
  
  // Enhanced firewall functions
  checkIPReputation,
  checkRateLimit,
  getBlockedIPs,
  unblockIP,
  inspectPacket,
  checkApplicationAccess,
  whitelistApplication,
  blacklistApplication,
  checkGeoLocation,
  blockCountry,
  unblockCountry,
  getFirewallZones,
  getFirewallStatistics,
  analyzeConnection,
  reportMaliciousIP,
  removeMaliciousIP,
  getIPSStatus,
  setIPSAutoBlock,
  testFirewallRule,
  getFirewallRecommendations
};
