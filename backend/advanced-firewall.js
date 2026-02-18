/**
 * Nebula Shield - Advanced Firewall System
 * Enterprise-grade network security with DPI, IDS/IPS, Application Control, and Geo-Blocking
 */

const EventEmitter = require('events');
const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const execAsync = promisify(exec);

class AdvancedFirewall extends EventEmitter {
  constructor() {
    super();
    
    // Core Components
    this.dpiEngine = null;              // Deep Packet Inspection
    this.idsEngine = null;              // Intrusion Detection System
    this.ipsEngine = null;              // Intrusion Prevention System
    this.appFilter = null;              // Application-Level Filter
    this.geoBlocker = null;             // Geo-Blocking Engine
    this.trafficAnalyzer = null;        // Traffic Analysis
    this.bandwidthManager = null;       // Bandwidth Management
    
    // Rule Storage
    this.rules = new Map();
    this.blockedIPs = new Set();
    this.allowedIPs = new Set();
    this.blockedDomains = new Set();
    this.allowedDomains = new Set();
    this.blockedApplications = new Set();
    this.blockedCountries = new Set();
    
    // Connection Tracking
    this.activeConnections = new Map();
    this.connectionHistory = [];
    this.suspiciousConnections = new Map();
    
    // Threat Intelligence
    this.threatSignatures = new Map();
    this.knownMalwareIPs = new Set();
    this.knownC2Servers = new Set();
    this.knownPhishingDomains = new Set();
    this.torExitNodes = new Set();
    
    // DPI Patterns
    this.dpiPatterns = {
      malware: [
        { pattern: /(\x4d\x5a\x90\x00)/i, name: 'PE Header Detection', severity: 'high' },
        { pattern: /eval\s*\(|exec\s*\(/i, name: 'Code Injection', severity: 'critical' },
        { pattern: /base64_decode|gzinflate/i, name: 'Obfuscation Detected', severity: 'high' }
      ],
      exploits: [
        { pattern: /\.\.\//g, name: 'Path Traversal', severity: 'high' },
        { pattern: /<script[\s\S]*?>/i, name: 'XSS Attempt', severity: 'medium' },
        { pattern: /union\s+select|or\s+1\s*=\s*1/i, name: 'SQL Injection', severity: 'critical' }
      ],
      ddos: [
        { pattern: /LOIC|HOIC/i, name: 'DDoS Tool', severity: 'critical' },
        { pattern: /slowloris|hulk/i, name: 'DDoS Pattern', severity: 'high' }
      ],
      cryptominers: [
        { pattern: /stratum\+tcp|stratum\+ssl/i, name: 'Mining Pool Protocol', severity: 'high' },
        { pattern: /coinhive|cryptonight/i, name: 'Browser Miner', severity: 'high' },
        { pattern: /xmrig|ethminer|ccminer/i, name: 'Mining Software', severity: 'critical' }
      ],
      c2_communication: [
        { pattern: /cmd\.exe|powershell\.exe/i, name: 'Remote Command Execution', severity: 'critical' },
        { pattern: /\/beacon|\/check-in|\/heartbeat/i, name: 'C2 Beacon', severity: 'critical' }
      ]
    };
    
    // IDS/IPS Signatures
    this.idsSignatures = new Map([
      ['port_scan', { threshold: 10, timeWindow: 60000, action: 'block', severity: 'high' }],
      ['brute_force_ssh', { threshold: 5, timeWindow: 300000, action: 'block', severity: 'critical' }],
      ['brute_force_rdp', { threshold: 3, timeWindow: 600000, action: 'block', severity: 'critical' }],
      ['brute_force_ftp', { threshold: 5, timeWindow: 300000, action: 'block', severity: 'high' }],
      ['syn_flood', { threshold: 100, timeWindow: 10000, action: 'block', severity: 'critical' }],
      ['udp_flood', { threshold: 200, timeWindow: 10000, action: 'block', severity: 'critical' }],
      ['icmp_flood', { threshold: 50, timeWindow: 10000, action: 'block', severity: 'high' }],
      ['dns_amplification', { threshold: 20, timeWindow: 30000, action: 'block', severity: 'critical' }],
      ['http_flood', { threshold: 100, timeWindow: 60000, action: 'rate_limit', severity: 'high' }]
    ]);
    
    // Application Signatures
    this.applicationSignatures = new Map([
      ['torrent', { patterns: [/BitTorrent|uTorrent|Transmission/i], ports: [6881, 6882, 6883, 6889], risk: 'medium' }],
      ['p2p', { patterns: [/eMule|KaZaA|Limewire/i], ports: [4662, 4672], risk: 'medium' }],
      ['remote_desktop', { patterns: [/mstsc|RDP/i], ports: [3389], risk: 'low' }],
      ['ssh', { patterns: [/OpenSSH|PuTTY/i], ports: [22], risk: 'low' }],
      ['vpn', { patterns: [/OpenVPN|IPSec/i], ports: [1194, 500, 4500], risk: 'low' }],
      ['gaming', { patterns: [/Steam|Origin|Battle\.net/i], ports: [27015, 27016], risk: 'low' }]
    ]);
    
    // Geo-IP Database (simplified)
    this.geoDatabase = new Map([
      ['192.0.2.0/24', 'US'],      // Example
      ['198.51.100.0/24', 'CN'],   // Example
      ['203.0.113.0/24', 'RU']     // Example
    ]);
    
    // Statistics
    this.statistics = {
      packetsInspected: 0,
      threatsBlocked: 0,
      allowedConnections: 0,
      droppedPackets: 0,
      dpiDetections: 0,
      idsAlerts: 0,
      ipsBlocks: 0,
      appBlocks: 0,
      geoBlocks: 0,
      bandwidth: {
        inbound: 0,
        outbound: 0,
        total: 0
      },
      topBlockedIPs: new Map(),
      topBlockedPorts: new Map(),
      topThreats: new Map(),
      ruleHits: new Map()
    };
    
    // Monitoring
    this.isMonitoring = false;
    this.monitoringInterval = null;
    this.dpiInterval = null;
    this.idsInterval = null;
    
    // Platform
    this.platform = os.platform();
    
    this.initialize();
  }

  /**
   * Initialize Advanced Firewall
   */
  async initialize() {
    console.log('🛡️  Initializing Advanced Firewall System...');
    
    // Load default rules
    this.loadDefaultRules();
    
    // Load threat intelligence
    this.loadThreatIntelligence();
    
    // Initialize DPI Engine
    this.initializeDPI();
    
    // Initialize IDS/IPS
    this.initializeIDS();
    
    // Initialize Application Filter
    this.initializeAppFilter();
    
    // Initialize Geo-Blocker
    this.initializeGeoBlocker();
    
    // Initialize Traffic Analyzer
    this.initializeTrafficAnalyzer();
    
    console.log('✅ Advanced Firewall System initialized');
    console.log(`   Platform: ${this.platform}`);
    console.log(`   Rules loaded: ${this.rules.size}`);
    console.log(`   Threat signatures: ${this.threatSignatures.size}`);
    console.log(`   IDS signatures: ${this.idsSignatures.size}`);
    console.log(`   Application signatures: ${this.applicationSignatures.size}`);
  }

  /**
   * Load default firewall rules
   */
  loadDefaultRules() {
    const defaultRules = [
      {
        id: 'fw_001',
        name: 'Block Malware C2 Communication',
        type: 'ip_list',
        action: 'block',
        direction: 'both',
        protocol: 'any',
        target: 'c2_servers',
        enabled: true,
        priority: 1,
        description: 'Block all command & control server communications'
      },
      {
        id: 'fw_002',
        name: 'Block Tor Exit Nodes',
        type: 'ip_list',
        action: 'block',
        direction: 'both',
        protocol: 'any',
        target: 'tor_nodes',
        enabled: true,
        priority: 1,
        description: 'Block connections from/to Tor exit nodes'
      },
      {
        id: 'fw_003',
        name: 'Block Cryptocurrency Mining',
        type: 'dpi',
        action: 'block',
        direction: 'outbound',
        protocol: 'tcp',
        pattern: 'cryptominers',
        enabled: true,
        priority: 2,
        description: 'Deep packet inspection to block cryptocurrency mining'
      },
      {
        id: 'fw_004',
        name: 'Prevent Port Scanning',
        type: 'ids',
        action: 'block',
        direction: 'inbound',
        protocol: 'any',
        signature: 'port_scan',
        enabled: true,
        priority: 2,
        description: 'Detect and block port scanning attempts'
      },
      {
        id: 'fw_005',
        name: 'Prevent SSH Brute Force',
        type: 'ids',
        action: 'block',
        direction: 'inbound',
        protocol: 'tcp',
        ports: [22],
        signature: 'brute_force_ssh',
        enabled: true,
        priority: 1,
        description: 'Prevent SSH brute force attacks'
      },
      {
        id: 'fw_006',
        name: 'Prevent RDP Brute Force',
        type: 'ids',
        action: 'block',
        direction: 'inbound',
        protocol: 'tcp',
        ports: [3389],
        signature: 'brute_force_rdp',
        enabled: true,
        priority: 1,
        description: 'Prevent Remote Desktop brute force attacks'
      },
      {
        id: 'fw_007',
        name: 'Block DDoS Attacks',
        type: 'ids',
        action: 'block',
        direction: 'inbound',
        protocol: 'any',
        signature: 'syn_flood',
        enabled: true,
        priority: 1,
        description: 'Detect and block DDoS attacks'
      },
      {
        id: 'fw_008',
        name: 'Application Control - Torrent',
        type: 'application',
        action: 'block',
        direction: 'both',
        protocol: 'tcp',
        application: 'torrent',
        enabled: false,
        priority: 3,
        description: 'Block BitTorrent and P2P file sharing'
      },
      {
        id: 'fw_009',
        name: 'Geo-Block High-Risk Countries',
        type: 'geo',
        action: 'block',
        direction: 'inbound',
        protocol: 'any',
        countries: ['KP', 'IR', 'SY'],
        enabled: false,
        priority: 2,
        description: 'Block connections from high-risk countries'
      },
      {
        id: 'fw_010',
        name: 'Allow Standard Web Traffic',
        type: 'port',
        action: 'allow',
        direction: 'outbound',
        protocol: 'tcp',
        ports: [80, 443, 8080, 8443],
        enabled: true,
        priority: 5,
        description: 'Allow HTTP/HTTPS traffic'
      },
      {
        id: 'fw_011',
        name: 'Allow DNS',
        type: 'port',
        action: 'allow',
        direction: 'outbound',
        protocol: 'udp',
        ports: [53],
        enabled: true,
        priority: 5,
        description: 'Allow DNS queries'
      },
      {
        id: 'fw_012',
        name: 'Block NetBIOS/SMB',
        type: 'port',
        action: 'block',
        direction: 'inbound',
        protocol: 'tcp',
        ports: [137, 138, 139, 445],
        enabled: true,
        priority: 2,
        description: 'Block NetBIOS and SMB (prevents ransomware spread)'
      }
    ];

    defaultRules.forEach(rule => {
      this.rules.set(rule.id, rule);
    });
  }

  /**
   * Load threat intelligence data
   */
  loadThreatIntelligence() {
    // Known malware IPs (examples)
    const malwareIPs = [
      '198.51.100.1', '198.51.100.2', '198.51.100.3',
      '203.0.113.1', '203.0.113.2'
    ];
    malwareIPs.forEach(ip => this.knownMalwareIPs.add(ip));

    // Known C2 servers (examples)
    const c2Servers = [
      '192.0.2.100', '192.0.2.101', '192.0.2.102'
    ];
    c2Servers.forEach(ip => this.knownC2Servers.add(ip));

    // Known phishing domains (examples)
    const phishingDomains = [
      'malicious-site.ru', 'phishing-bank.com', 'fake-login.net'
    ];
    phishingDomains.forEach(domain => this.knownPhishingDomains.add(domain));

    // Tor exit nodes (examples)
    const torNodes = [
      '185.220.101.1', '185.220.101.2', '185.220.101.3'
    ];
    torNodes.forEach(ip => this.torExitNodes.add(ip));

    // Create threat signatures
    this.threatSignatures.set('malware_download', {
      pattern: /\.exe|\.dll|\.scr|\.bat|\.vbs/i,
      severity: 'high',
      action: 'block'
    });

    this.threatSignatures.set('phishing_attempt', {
      pattern: /verify.*account|confirm.*identity|urgent.*action/i,
      severity: 'medium',
      action: 'warn'
    });

    this.threatSignatures.set('data_exfiltration', {
      pattern: /password|credential|ssn|credit.*card/i,
      severity: 'critical',
      action: 'block'
    });
  }

  /**
   * Initialize Deep Packet Inspection
   */
  initializeDPI() {
    this.dpiEngine = {
      enabled: true,
      scanDepth: 'full', // 'headers', 'partial', 'full'
      patterns: this.dpiPatterns,
      detections: []
    };
    
    console.log('   DPI Engine initialized');
  }

  /**
   * Initialize Intrusion Detection/Prevention System
   */
  initializeIDS() {
    this.idsEngine = {
      enabled: true,
      mode: 'prevention', // 'detection' or 'prevention'
      signatures: this.idsSignatures,
      alerts: [],
      blocks: []
    };

    this.ipsEngine = {
      enabled: true,
      autoBlock: true,
      blockDuration: 3600000, // 1 hour
      whitelist: new Set()
    };

    console.log('   IDS/IPS Engine initialized');
  }

  /**
   * Initialize Application Filter
   */
  initializeAppFilter() {
    this.appFilter = {
      enabled: true,
      mode: 'blacklist', // 'whitelist' or 'blacklist'
      signatures: this.applicationSignatures,
      blockedApps: [],
      allowedApps: []
    };

    console.log('   Application Filter initialized');
  }

  /**
   * Initialize Geo-Blocker
   */
  initializeGeoBlocker() {
    this.geoBlocker = {
      enabled: false,
      mode: 'blacklist', // 'whitelist' or 'blacklist'
      blockedCountries: this.blockedCountries,
      allowedCountries: new Set(),
      database: this.geoDatabase
    };

    console.log('   Geo-Blocker initialized');
  }

  /**
   * Initialize Traffic Analyzer
   */
  initializeTrafficAnalyzer() {
    this.trafficAnalyzer = {
      enabled: true,
      captureWindow: 300000, // 5 minutes
      protocols: new Map(),
      applications: new Map(),
      topTalkers: new Map(),
      anomalies: []
    };

    this.bandwidthManager = {
      enabled: false,
      limits: {
        global: { upload: 0, download: 0 },
        perConnection: { upload: 0, download: 0 }
      },
      quotas: new Map()
    };

    console.log('   Traffic Analyzer initialized');
  }

  /**
   * Deep Packet Inspection
   */
  performDPI(packet) {
    if (!this.dpiEngine.enabled) return { clean: true };

    this.statistics.packetsInspected++;

    const { payload, protocol, sourceIP, destIP, destPort } = packet;
    
    if (!payload) return { clean: true };

    const detections = [];

    // Scan against all pattern categories
    for (const [category, patterns] of Object.entries(this.dpiEngine.patterns)) {
      for (const { pattern, name, severity } of patterns) {
        if (pattern.test(payload)) {
          const detection = {
            category,
            name,
            severity,
            sourceIP,
            destIP,
            destPort,
            protocol,
            timestamp: new Date().toISOString()
          };

          detections.push(detection);
          this.statistics.dpiDetections++;

          // Track top threats
          const threatCount = this.statistics.topThreats.get(name) || 0;
          this.statistics.topThreats.set(name, threatCount + 1);

          // Log to DPI engine
          this.dpiEngine.detections.unshift(detection);
          if (this.dpiEngine.detections.length > 1000) {
            this.dpiEngine.detections = this.dpiEngine.detections.slice(0, 1000);
          }

          // Emit event
          this.emit('dpi:detection', detection);
        }
      }
    }

    if (detections.length > 0) {
      return {
        clean: false,
        detections,
        action: 'block',
        reason: `DPI detected ${detections.length} threat(s)`
      };
    }

    return { clean: true };
  }

  /**
   * Intrusion Detection System
   */
  performIDS(packet) {
    if (!this.idsEngine.enabled) return { normal: true };

    const { sourceIP, destIP, destPort, protocol, timestamp } = packet;
    const now = Date.now();

    // Check for known attack patterns
    for (const [signatureName, config] of this.idsSignatures) {
      const key = `${sourceIP}:${signatureName}`;
      const events = this.suspiciousConnections.get(key) || [];
      
      // Clean old events
      const recentEvents = events.filter(
        time => now - time < config.timeWindow
      );

      // Add current event
      recentEvents.push(now);
      this.suspiciousConnections.set(key, recentEvents);

      // Check threshold
      if (recentEvents.length >= config.threshold) {
        const alert = {
          type: signatureName,
          severity: config.severity,
          sourceIP,
          destIP,
          destPort,
          protocol,
          count: recentEvents.length,
          action: config.action,
          timestamp: new Date().toISOString()
        };

        this.statistics.idsAlerts++;
        this.idsEngine.alerts.unshift(alert);
        
        if (this.idsEngine.alerts.length > 1000) {
          this.idsEngine.alerts = this.idsEngine.alerts.slice(0, 1000);
        }

        // Emit event
        this.emit('ids:alert', alert);

        // IPS: Auto-block if enabled
        if (this.ipsEngine.enabled && config.action === 'block') {
          this.autoBlockIP(sourceIP, signatureName, config.severity);
          this.statistics.ipsBlocks++;

          return {
            normal: false,
            alert,
            action: 'block',
            reason: `IDS detected ${signatureName}`
          };
        }

        return {
          normal: false,
          alert,
          action: config.action,
          reason: `IDS detected ${signatureName}`
        };
      }
    }

    return { normal: true };
  }

  /**
   * Application-Level Filtering
   */
  performAppFilter(packet) {
    if (!this.appFilter.enabled) return { allowed: true };

    const { payload, destPort, protocol } = packet;

    // Check against application signatures
    for (const [appName, signature] of this.applicationSignatures) {
      // Check if application is blocked
      if (this.blockedApplications.has(appName)) {
        // Check port match
        if (signature.ports && signature.ports.includes(destPort)) {
          this.statistics.appBlocks++;
          
          this.emit('app:blocked', {
            application: appName,
            port: destPort,
            risk: signature.risk,
            timestamp: new Date().toISOString()
          });

          return {
            allowed: false,
            application: appName,
            action: 'block',
            reason: `Application ${appName} is blocked`
          };
        }

        // Check pattern match
        if (payload && signature.patterns) {
          for (const pattern of signature.patterns) {
            if (pattern.test(payload)) {
              this.statistics.appBlocks++;
              
              this.emit('app:blocked', {
                application: appName,
                port: destPort,
                risk: signature.risk,
                timestamp: new Date().toISOString()
              });

              return {
                allowed: false,
                application: appName,
                action: 'block',
                reason: `Application ${appName} is blocked`
              };
            }
          }
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Geo-IP Blocking
   */
  performGeoBlocking(packet) {
    if (!this.geoBlocker.enabled) return { allowed: true };

    const { sourceIP, destIP } = packet;
    
    // Get country for source IP
    const sourceCountry = this.getCountryByIP(sourceIP);
    const destCountry = this.getCountryByIP(destIP);

    // Check blocklist mode
    if (this.geoBlocker.mode === 'blacklist') {
      if (this.blockedCountries.has(sourceCountry) || this.blockedCountries.has(destCountry)) {
        this.statistics.geoBlocks++;
        
        this.emit('geo:blocked', {
          sourceIP,
          sourceCountry,
          destIP,
          destCountry,
          timestamp: new Date().toISOString()
        });

        return {
          allowed: false,
          country: sourceCountry || destCountry,
          action: 'block',
          reason: `Geo-blocked country: ${sourceCountry || destCountry}`
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Get country by IP (simplified)
   */
  getCountryByIP(ip) {
    // Simplified lookup - in production would use MaxMind or similar
    for (const [range, country] of this.geoDatabase) {
      if (this.ipInRange(ip, range)) {
        return country;
      }
    }
    return 'UNKNOWN';
  }

  /**
   * Check if IP is in range (simplified)
   */
  ipInRange(ip, range) {
    // Simplified - production would use proper CIDR matching
    return range.includes(ip.split('.')[0]);
  }

  /**
   * Analyze Traffic
   */
  analyzeTraffic(packet) {
    if (!this.trafficAnalyzer.enabled) return;

    const { protocol, sourceIP, destIP, size = 0 } = packet;

    // Track protocol usage
    const protoCount = this.trafficAnalyzer.protocols.get(protocol) || 0;
    this.trafficAnalyzer.protocols.set(protocol, protoCount + 1);

    // Track top talkers
    const talkerKey = `${sourceIP}->${destIP}`;
    const talkerCount = this.trafficAnalyzer.topTalkers.get(talkerKey) || 0;
    this.trafficAnalyzer.topTalkers.set(talkerKey, talkerCount + size);

    // Update bandwidth statistics
    this.statistics.bandwidth.total += size;
    this.statistics.bandwidth.outbound += size;

    // Detect anomalies (simplified)
    if (size > 10000000) { // 10MB packet
      this.trafficAnalyzer.anomalies.push({
        type: 'large_packet',
        size,
        sourceIP,
        destIP,
        protocol,
        timestamp: new Date().toISOString()
      });

      this.emit('traffic:anomaly', {
        type: 'large_packet',
        size,
        sourceIP,
        destIP
      });
    }
  }

  /**
   * Comprehensive Packet Inspection
   */
  inspectPacket(packet) {
    const {
      sourceIP,
      destIP,
      sourcePort,
      destPort,
      protocol,
      payload,
      direction,
      size = 0,
      timestamp = Date.now()
    } = packet;

    this.statistics.packetsInspected++;

    // Update bandwidth
    if (direction === 'inbound') {
      this.statistics.bandwidth.inbound += size;
    } else {
      this.statistics.bandwidth.outbound += size;
    }
    this.statistics.bandwidth.total += size;

    // Track blocked IPs
    const ipCount = this.statistics.topBlockedIPs.get(sourceIP) || 0;
    this.statistics.topBlockedIPs.set(sourceIP, ipCount);

    // Check IP blocklist/allowlist
    if (this.blockedIPs.has(sourceIP) || this.blockedIPs.has(destIP)) {
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      return {
        action: 'block',
        reason: 'IP in blocklist',
        rule: 'ip_blocklist'
      };
    }

    if (this.allowedIPs.has(sourceIP) || this.allowedIPs.has(destIP)) {
      this.statistics.allowedConnections++;
      return {
        action: 'allow',
        reason: 'IP in allowlist',
        rule: 'ip_allowlist'
      };
    }

    // Check against threat intelligence
    if (this.knownMalwareIPs.has(sourceIP) || this.knownMalwareIPs.has(destIP)) {
      this.statistics.threatsBlocked++;
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      
      this.emit('threat:blocked', {
        type: 'malware_ip',
        sourceIP,
        destIP,
        timestamp: new Date().toISOString()
      });

      return {
        action: 'block',
        reason: 'Known malware IP',
        rule: 'threat_intelligence'
      };
    }

    if (this.knownC2Servers.has(sourceIP) || this.knownC2Servers.has(destIP)) {
      this.statistics.threatsBlocked++;
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      
      this.emit('threat:blocked', {
        type: 'c2_server',
        sourceIP,
        destIP,
        timestamp: new Date().toISOString()
      });

      return {
        action: 'block',
        reason: 'C2 server communication',
        rule: 'threat_intelligence'
      };
    }

    // Deep Packet Inspection
    const dpiResult = this.performDPI(packet);
    if (!dpiResult.clean) {
      this.statistics.threatsBlocked++;
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      return dpiResult;
    }

    // Intrusion Detection/Prevention
    const idsResult = this.performIDS(packet);
    if (!idsResult.normal && idsResult.action === 'block') {
      this.statistics.threatsBlocked++;
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      return idsResult;
    }

    // Application Filtering
    const appResult = this.performAppFilter(packet);
    if (!appResult.allowed) {
      this.statistics.droppedPackets++;
      return appResult;
    }

    // Geo-Blocking
    const geoResult = this.performGeoBlocking(packet);
    if (!geoResult.allowed) {
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      return geoResult;
    }

    // Traffic Analysis
    this.analyzeTraffic(packet);

    // Apply firewall rules
    const ruleResult = this.applyRules(packet);
    if (ruleResult.action === 'block') {
      this.statistics.threatsBlocked++;
      this.statistics.droppedPackets++;
      this.trackBlockedIP(sourceIP);
      return ruleResult;
    }

    // Default allow
    this.statistics.allowedConnections++;
    return {
      action: 'allow',
      reason: 'Passed all inspections',
      rule: 'default_allow'
    };
  }

  /**
   * Apply firewall rules
   */
  applyRules(packet) {
    const sortedRules = Array.from(this.rules.values())
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      if (this.matchesRule(rule, packet)) {
        // Increment rule hit counter
        const hits = this.statistics.ruleHits.get(rule.id) || 0;
        this.statistics.ruleHits.set(rule.id, hits + 1);

        return {
          action: rule.action,
          reason: rule.description,
          rule: rule.name,
          ruleId: rule.id
        };
      }
    }

    return { action: 'allow', reason: 'No matching rules', rule: 'default' };
  }

  /**
   * Check if packet matches rule
   */
  matchesRule(rule, packet) {
    const { sourceIP, destIP, destPort, protocol, direction, payload } = packet;

    // Direction check
    if (rule.direction !== 'both' && rule.direction !== direction) {
      return false;
    }

    // Protocol check
    if (rule.protocol !== 'any' && rule.protocol !== protocol) {
      return false;
    }

    // Type-specific matching
    switch (rule.type) {
      case 'port':
        return rule.ports && rule.ports.includes(destPort);
      
      case 'ip_list':
        if (rule.target === 'c2_servers') {
          return this.knownC2Servers.has(sourceIP) || this.knownC2Servers.has(destIP);
        }
        if (rule.target === 'tor_nodes') {
          return this.torExitNodes.has(sourceIP) || this.torExitNodes.has(destIP);
        }
        return false;
      
      case 'dpi':
        const dpiResult = this.performDPI(packet);
        return !dpiResult.clean;
      
      case 'ids':
        const idsResult = this.performIDS(packet);
        return !idsResult.normal;
      
      case 'application':
        const appResult = this.performAppFilter(packet);
        return !appResult.allowed;
      
      case 'geo':
        const geoResult = this.performGeoBlocking(packet);
        return !geoResult.allowed;
      
      default:
        return false;
    }
  }

  /**
   * Auto-block IP address
   */
  autoBlockIP(ip, reason, severity) {
    this.blockedIPs.add(ip);
    
    const blockEntry = {
      ip,
      reason,
      severity,
      timestamp: new Date().toISOString(),
      expiresAt: new Date(Date.now() + this.ipsEngine.blockDuration).toISOString()
    };

    this.ipsEngine.blocks.push(blockEntry);

    // Schedule unblock
    setTimeout(() => {
      this.unblockIP(ip);
    }, this.ipsEngine.blockDuration);

    this.emit('ips:block', blockEntry);

    return blockEntry;
  }

  /**
   * Track blocked IP
   */
  trackBlockedIP(ip) {
    const count = this.statistics.topBlockedIPs.get(ip) || 0;
    this.statistics.topBlockedIPs.set(ip, count + 1);
  }

  /**
   * Block IP address
   */
  blockIP(ip, reason = 'Manual block') {
    this.blockedIPs.add(ip);
    this.emit('ip:blocked', { ip, reason, timestamp: new Date().toISOString() });
    return { success: true, ip, blocked: true };
  }

  /**
   * Unblock IP address
   */
  unblockIP(ip) {
    this.blockedIPs.delete(ip);
    this.emit('ip:unblocked', { ip, timestamp: new Date().toISOString() });
    return { success: true, ip, unblocked: true };
  }

  /**
   * Block domain
   */
  blockDomain(domain, reason = 'Manual block') {
    this.blockedDomains.add(domain);
    this.emit('domain:blocked', { domain, reason, timestamp: new Date().toISOString() });
    return { success: true, domain, blocked: true };
  }

  /**
   * Block application
   */
  blockApplication(appName) {
    if (this.applicationSignatures.has(appName)) {
      this.blockedApplications.add(appName);
      this.emit('app:blocked', { application: appName, timestamp: new Date().toISOString() });
      return { success: true, application: appName, blocked: true };
    }
    return { success: false, error: 'Application not recognized' };
  }

  /**
   * Block country
   */
  blockCountry(countryCode) {
    this.blockedCountries.add(countryCode);
    this.emit('country:blocked', { country: countryCode, timestamp: new Date().toISOString() });
    return { success: true, country: countryCode, blocked: true };
  }

  /**
   * Add rule
   */
  addRule(rule) {
    const ruleId = rule.id || `fw_${Date.now()}`;
    const fullRule = {
      ...rule,
      id: ruleId,
      createdAt: new Date().toISOString(),
      enabled: rule.enabled !== false
    };
    this.rules.set(ruleId, fullRule);
    this.emit('rule:added', fullRule);
    return { success: true, rule: fullRule };
  }

  /**
   * Update rule
   */
  updateRule(ruleId, updates) {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      return { success: false, error: 'Rule not found' };
    }
    const updatedRule = {
      ...rule,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    this.rules.set(ruleId, updatedRule);
    this.emit('rule:updated', updatedRule);
    return { success: true, rule: updatedRule };
  }

  /**
   * Delete rule
   */
  deleteRule(ruleId) {
    const rule = this.rules.get(ruleId);
    if (!rule) {
      return { success: false, error: 'Rule not found' };
    }
    this.rules.delete(ruleId);
    this.emit('rule:deleted', { ruleId });
    return { success: true, deleted: true };
  }

  /**
   * Get all rules
   */
  getRules() {
    return Array.from(this.rules.values());
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.statistics,
      ruleHits: Object.fromEntries(this.statistics.ruleHits),
      topBlockedIPs: Object.fromEntries(
        Array.from(this.statistics.topBlockedIPs.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
      ),
      topThreats: Object.fromEntries(
        Array.from(this.statistics.topThreats.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
      ),
      blockedIPsCount: this.blockedIPs.size,
      blockedDomainsCount: this.blockedDomains.size,
      blockedApplicationsCount: this.blockedApplications.size,
      blockedCountriesCount: this.blockedCountries.size,
      rulesCount: this.rules.size,
      activeRulesCount: Array.from(this.rules.values()).filter(r => r.enabled).length,
      dpiEnabled: this.dpiEngine.enabled,
      idsEnabled: this.idsEngine.enabled,
      ipsEnabled: this.ipsEngine.enabled,
      appFilterEnabled: this.appFilter.enabled,
      geoBlockerEnabled: this.geoBlocker.enabled
    };
  }

  /**
   * Get DPI detections
   */
  getDPIDetections(limit = 50) {
    return this.dpiEngine.detections.slice(0, limit);
  }

  /**
   * Get IDS alerts
   */
  getIDSAlerts(limit = 50) {
    return this.idsEngine.alerts.slice(0, limit);
  }

  /**
   * Get IPS blocks
   */
  getIPSBlocks(limit = 50) {
    return this.ipsEngine.blocks.slice(0, limit);
  }

  /**
   * Get traffic analysis
   */
  getTrafficAnalysis() {
    return {
      protocols: Object.fromEntries(this.trafficAnalyzer.protocols),
      topTalkers: Object.fromEntries(
        Array.from(this.trafficAnalyzer.topTalkers.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
      ),
      anomalies: this.trafficAnalyzer.anomalies.slice(0, 20),
      bandwidth: this.statistics.bandwidth
    };
  }

  /**
   * Get blocked lists
   */
  getBlockedLists() {
    return {
      ips: Array.from(this.blockedIPs),
      domains: Array.from(this.blockedDomains),
      applications: Array.from(this.blockedApplications),
      countries: Array.from(this.blockedCountries)
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.statistics = {
      packetsInspected: 0,
      threatsBlocked: 0,
      allowedConnections: 0,
      droppedPackets: 0,
      dpiDetections: 0,
      idsAlerts: 0,
      ipsBlocks: 0,
      appBlocks: 0,
      geoBlocks: 0,
      bandwidth: {
        inbound: 0,
        outbound: 0,
        total: 0
      },
      topBlockedIPs: new Map(),
      topBlockedPorts: new Map(),
      topThreats: new Map(),
      ruleHits: new Map()
    };
    return { success: true, message: 'Statistics reset' };
  }

  /**
   * Start monitoring
   */
  startMonitoring() {
    if (this.isMonitoring) return { success: false, message: 'Already monitoring' };

    this.isMonitoring = true;
    
    // Simulate packet inspection
    this.monitoringInterval = setInterval(() => {
      if (Math.random() < 0.4) {
        const packet = this.generateRandomPacket();
        this.inspectPacket(packet);
      }
    }, 1000);

    this.emit('monitoring:started');
    return { success: true, message: 'Monitoring started' };
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    if (!this.isMonitoring) return { success: false, message: 'Not monitoring' };

    this.isMonitoring = false;
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    this.emit('monitoring:stopped');
    return { success: true, message: 'Monitoring stopped' };
  }

  /**
   * Generate random packet for simulation
   */
  generateRandomPacket() {
    const protocols = ['tcp', 'udp', 'icmp'];
    const directions = ['inbound', 'outbound'];
    const ports = [22, 80, 443, 3389, 8080, 3306, 5432, 6379];
    
    return {
      sourceIP: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      destIP: `192.168.1.${Math.floor(Math.random() * 255)}`,
      sourcePort: Math.floor(Math.random() * 65535),
      destPort: ports[Math.floor(Math.random() * ports.length)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      direction: directions[Math.floor(Math.random() * directions.length)],
      payload: Math.random() < 0.1 ? 'GET / HTTP/1.1\r\nHost: example.com' : null,
      size: Math.floor(Math.random() * 65536),
      timestamp: Date.now()
    };
  }
}

module.exports = AdvancedFirewall;
