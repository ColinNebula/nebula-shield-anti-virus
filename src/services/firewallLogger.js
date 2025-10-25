/**
 * Advanced Firewall Logging System
 * Persistent storage, forensic analysis, export capabilities
 */

import mlAnomalyDetector from './mlAnomalyDetection';

// ==================== CONFIGURATION ====================

const LOGGING_CONFIG = {
  maxLogEntries: 10000,              // Maximum logs in IndexedDB
  maxMemoryEntries: 1000,            // Maximum logs in memory
  retentionDays: 90,                 // Auto-delete logs older than 90 days
  autoExport: true,                  // Auto-export to file when limit reached
  compressionEnabled: true,          // Compress old logs
  indexingEnabled: true,             // Enable fast search indexing
  realTimeAnalysis: true,            // Enable real-time threat analysis
  forensicMode: true,                // Detailed forensic logging
  
  // Storage keys
  storageKeys: {
    logs: 'firewall_threat_logs',
    stats: 'firewall_statistics',
    alerts: 'firewall_critical_alerts',
    sessions: 'firewall_sessions',
    forensics: 'firewall_forensics'
  }
};

// ==================== LOG ENTRY STRUCTURE ====================

class LogEntry {
  constructor(data) {
    this.id = this.generateId();
    this.timestamp = new Date().toISOString();
    this.threatType = data.threatType || 'unknown';
    this.severity = data.severity || 'medium';
    this.action = data.action || 'blocked';
    this.sourceIP = data.sourceIP || 'unknown';
    this.destinationIP = data.destinationIP || 'unknown';
    this.port = data.port || null;
    this.protocol = data.protocol || 'unknown';
    this.signatureName = data.signatureName || 'Generic';
    this.payload = data.payload || '';
    this.blocked = data.blocked !== false;
    this.confidence = data.confidence || 0.8;
    
    // Forensic details
    this.forensics = {
      userAgent: data.userAgent || null,
      headers: data.headers || {},
      requestMethod: data.requestMethod || null,
      url: data.url || null,
      processName: data.processName || null,
      packetSize: data.packetSize || 0,
      connectionDuration: data.connectionDuration || 0,
      geolocation: data.geolocation || null,
      asn: data.asn || null
    };
    
    // Attack chain tracking
    this.attackChain = {
      isPartOfChain: false,
      chainId: null,
      sequence: 0,
      relatedEvents: []
    };
    
    // ML Anomaly Detection
    this.mlAnalysis = {
      anomalyScore: 0,
      zeroDayPotential: false,
      ensembleConfidence: 0,
      anomalousFeatures: [],
      recommendation: null
    };
    
    // Response details
    this.response = {
      blocked: this.blocked,
      quarantined: data.quarantined || false,
      alertSent: data.alertSent || false,
      autoRemediationApplied: data.autoRemediationApplied || false,
      remediationActions: data.remediationActions || []
    };
  }
  
  generateId() {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  toJSON() {
    return {
      id: this.id,
      timestamp: this.timestamp,
      threatType: this.threatType,
      severity: this.severity,
      action: this.action,
      sourceIP: this.sourceIP,
      destinationIP: this.destinationIP,
      port: this.port,
      protocol: this.protocol,
      signatureName: this.signatureName,
      payload: this.payload,
      blocked: this.blocked,
      confidence: this.confidence,
      forensics: this.forensics,
      attackChain: this.attackChain,
      mlAnalysis: this.mlAnalysis,
      response: this.response
    };
  }
}

// ==================== INDEXEDDB MANAGER ====================

class IndexedDBManager {
  constructor() {
    this.dbName = 'NebulaShieldFirewallLogs';
    this.version = 2;
    this.db = null;
  }
  
  async initialize() {
    return new Promise((resolve, reject) => {
      try {
        const request = indexedDB.open(this.dbName, this.version);
        
        request.onerror = () => {
          console.error('IndexedDB error:', request.error);
          reject(new Error(`Failed to open database: ${request.error?.message || 'Unknown error'}`));
        };
        
        request.onsuccess = () => {
          this.db = request.result;
          console.log('✅ IndexedDB opened successfully');
          resolve(this.db);
        };
        
        request.onupgradeneeded = (event) => {
          try {
            const db = event.target.result;
            
            // Logs store
            if (!db.objectStoreNames.contains('logs')) {
              const logsStore = db.createObjectStore('logs', { keyPath: 'id' });
              logsStore.createIndex('timestamp', 'timestamp', { unique: false });
              logsStore.createIndex('severity', 'severity', { unique: false });
              logsStore.createIndex('threatType', 'threatType', { unique: false });
              logsStore.createIndex('sourceIP', 'sourceIP', { unique: false });
              logsStore.createIndex('blocked', 'blocked', { unique: false });
            }
            
            // Statistics store
            if (!db.objectStoreNames.contains('statistics')) {
              db.createObjectStore('statistics', { keyPath: 'date' });
            }
            
            // Critical alerts store
            if (!db.objectStoreNames.contains('alerts')) {
              const alertsStore = db.createObjectStore('alerts', { keyPath: 'id' });
              alertsStore.createIndex('timestamp', 'timestamp', { unique: false });
              alertsStore.createIndex('resolved', 'resolved', { unique: false });
            }
            
            // Sessions store (for attack chain tracking)
            if (!db.objectStoreNames.contains('sessions')) {
              const sessionsStore = db.createObjectStore('sessions', { keyPath: 'sessionId' });
              sessionsStore.createIndex('startTime', 'startTime', { unique: false });
            }
            
            // Forensics store (detailed packet captures)
            if (!db.objectStoreNames.contains('forensics')) {
              const forensicsStore = db.createObjectStore('forensics', { keyPath: 'id' });
              forensicsStore.createIndex('logId', 'logId', { unique: false });
              forensicsStore.createIndex('timestamp', 'timestamp', { unique: false });
            }
            
            console.log('✅ IndexedDB schema upgraded');
          } catch (upgradeError) {
            console.error('Schema upgrade error:', upgradeError);
            reject(new Error(`Schema upgrade failed: ${upgradeError.message}`));
          }
        };
      } catch (error) {
        console.error('IndexedDB initialization error:', error);
        reject(new Error(`Database initialization failed: ${error.message}`));
      }
    });
  }
  
  async addLog(log) {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['logs'], 'readwrite');
      const store = transaction.objectStore('logs');
      const request = store.add(log.toJSON());
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  
  async getLogs(filters = {}) {
    if (!this.db) await this.initialize();
    
    // Default limit to prevent loading too many logs
    const limit = filters.limit || 100;
    const offset = filters.offset || 0;
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['logs'], 'readonly');
      const store = transaction.objectStore('logs');
      const index = store.index('timestamp');
      
      // Use cursor for efficient pagination
      const logs = [];
      let skipped = 0;
      let collected = 0;
      
      // Open cursor in reverse order (newest first)
      const request = index.openCursor(null, 'prev');
      
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        
        if (cursor && collected < limit) {
          const log = cursor.value;
          
          // Apply filters
          let passesFilter = true;
          
          if (filters.severity && log.severity !== filters.severity) {
            passesFilter = false;
          }
          if (filters.threatType && log.threatType !== filters.threatType) {
            passesFilter = false;
          }
          if (filters.sourceIP && log.sourceIP !== filters.sourceIP) {
            passesFilter = false;
          }
          if (filters.startDate && new Date(log.timestamp) < new Date(filters.startDate)) {
            passesFilter = false;
          }
          if (filters.endDate && new Date(log.timestamp) > new Date(filters.endDate)) {
            passesFilter = false;
          }
          if (filters.blocked !== undefined && log.blocked !== filters.blocked) {
            passesFilter = false;
          }
          
          if (passesFilter) {
            if (skipped < offset) {
              skipped++;
            } else {
              logs.push(log);
              collected++;
            }
          }
          
          cursor.continue();
        } else {
          resolve(logs);
        }
      };
      
      request.onerror = () => reject(request.error);
    });
  }
  
  async searchLogs(query, limit = 50) {
    if (!this.db) await this.initialize();
    
    const queryLower = query.toLowerCase();
    const results = [];
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['logs'], 'readonly');
      const store = transaction.objectStore('logs');
      const index = store.index('timestamp');
      
      // Use cursor for efficient search (stop after finding enough results)
      const request = index.openCursor(null, 'prev');
      
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        
        if (cursor && results.length < limit) {
          const log = cursor.value;
          
          // Check if log matches search query
          if (
            log.threatType?.toLowerCase().includes(queryLower) ||
            log.sourceIP?.toLowerCase().includes(queryLower) ||
            log.destinationIP?.toLowerCase().includes(queryLower) ||
            log.signatureName?.toLowerCase().includes(queryLower) ||
            log.payload?.toLowerCase().includes(queryLower) ||
            log.forensics?.url?.toLowerCase().includes(queryLower)
          ) {
            results.push(log);
          }
          
          cursor.continue();
        } else {
          resolve(results);
        }
      };
      
      request.onerror = () => reject(request.error);
    });
  }
  
  async getLogCount(filters = {}) {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['logs'], 'readonly');
      const store = transaction.objectStore('logs');
      const request = store.count();
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  
  async getLogById(id) {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['logs'], 'readonly');
      const store = transaction.objectStore('logs');
      const request = store.get(id);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  
  async deleteLogs(ids) {
    if (!this.db) await this.initialize();
    
    const transaction = this.db.transaction(['logs'], 'readwrite');
    const store = transaction.objectStore('logs');
    
    const promises = ids.map(id => {
      return new Promise((resolve, reject) => {
        const request = store.delete(id);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    });
    
    return Promise.all(promises);
  }
  
  async clearAllLogs() {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['logs'], 'readwrite');
      const store = transaction.objectStore('logs');
      const request = store.clear();
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }
  
  async addAlert(alert) {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['alerts'], 'readwrite');
      const store = transaction.objectStore('alerts');
      const request = store.add(alert);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  
  async getAlerts(filters = {}) {
    if (!this.db) await this.initialize();
    
    const limit = filters.limit || 100;
    const offset = filters.offset || 0;
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['alerts'], 'readonly');
      const store = transaction.objectStore('alerts');
      const index = store.index('timestamp');
      
      const alerts = [];
      let skipped = 0;
      let collected = 0;
      
      // Open cursor in reverse order (newest first)
      const request = index.openCursor(null, 'prev');
      
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        
        if (cursor && collected < limit) {
          const alert = cursor.value;
          
          // Apply filters inline
          let passesFilter = true;
          if (filters.resolved !== undefined && alert.resolved !== filters.resolved) {
            passesFilter = false;
          }
          if (filters.severity && alert.severity !== filters.severity) {
            passesFilter = false;
          }
          
          if (passesFilter) {
            if (skipped < offset) {
              skipped++;
            } else {
              alerts.push(alert);
              collected++;
            }
          }
          
          cursor.continue();
        } else {
          resolve(alerts);
        }
      };
      
      request.onerror = () => reject(request.error);
    });
  }
  
  async updateStatistics(stats) {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['statistics'], 'readwrite');
      const store = transaction.objectStore('statistics');
      const request = store.put(stats);
      
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  
  async getStatistics(date = new Date().toISOString().split('T')[0]) {
    if (!this.db) await this.initialize();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction(['statistics'], 'readonly');
      const store = transaction.objectStore('statistics');
      const request = store.get(date);
      
      request.onsuccess = () => resolve(request.result || this.createEmptyStats(date));
      request.onerror = () => reject(request.error);
    });
  }
  
  createEmptyStats(date) {
    return {
      date,
      totalThreats: 0,
      threatsBlocked: 0,
      criticalThreats: 0,
      highThreats: 0,
      mediumThreats: 0,
      lowThreats: 0,
      topThreatTypes: {},
      topSourceIPs: {},
      topTargetPorts: {}
    };
  }
}

// ==================== FORENSIC ANALYZER ====================

class ForensicAnalyzer {
  constructor() {
    this.analysisCache = new Map();
  }
  
  /**
   * Perform deep forensic analysis on a log entry
   */
  async analyze(log) {
    const analysis = {
      logId: log.id,
      timestamp: new Date().toISOString(),
      riskScore: this.calculateRiskScore(log),
      attackVector: this.identifyAttackVector(log),
      iocExtraction: this.extractIOCs(log),
      behavioralAnalysis: this.analyzeBehavior(log),
      networkAnalysis: this.analyzeNetwork(log),
      payloadAnalysis: this.analyzePayload(log),
      mitreMapping: this.mapToMitre(log),
      recommendations: this.generateRecommendations(log),
      relatedThreats: await this.findRelatedThreats(log),
      threatIntelligence: this.enrichWithThreatIntel(log)
    };
    
    return analysis;
  }
  
  calculateRiskScore(log) {
    let score = 0;
    
    // Base severity score
    const severityScores = { critical: 90, high: 70, medium: 40, low: 20 };
    score += severityScores[log.severity] || 40;
    
    // Confidence multiplier
    score *= log.confidence;
    
    // Attack chain bonus
    if (log.attackChain.isPartOfChain) {
      score += 20;
    }
    
    // Failed block penalty
    if (!log.blocked) {
      score += 30;
    }
    
    // Multiple forensic indicators
    const forensicFlags = Object.values(log.forensics).filter(v => v !== null).length;
    score += forensicFlags * 2;
    
    return Math.min(Math.round(score), 100);
  }
  
  identifyAttackVector(log) {
    const vectors = [];
    
    if (log.forensics.url) vectors.push('Web Application');
    if (log.forensics.userAgent) vectors.push('HTTP Client');
    if (log.port && [22, 23, 3389].includes(log.port)) vectors.push('Remote Access');
    if (log.port && [445, 139].includes(log.port)) vectors.push('SMB/File Sharing');
    if (log.port === 53) vectors.push('DNS');
    if (log.threatType.includes('phishing')) vectors.push('Social Engineering');
    if (log.threatType.includes('ransomware')) vectors.push('Malware');
    if (log.threatType.includes('botnet')) vectors.push('Command & Control');
    
    return vectors.length > 0 ? vectors : ['Unknown'];
  }
  
  extractIOCs(log) {
    const iocs = {
      ips: [],
      domains: [],
      urls: [],
      fileHashes: [],
      emails: [],
      bitcoinWallets: []
    };
    
    // Extract IPs
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const ips = log.payload.match(ipRegex) || [];
    iocs.ips = [...new Set([...ips, log.sourceIP].filter(ip => ip !== 'unknown'))];
    
    // Extract domains
    const domainRegex = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/gi;
    const domains = log.payload.match(domainRegex) || [];
    iocs.domains = [...new Set(domains)];
    
    // Extract URLs
    const urlRegex = /(https?:\/\/[^\s]+)/gi;
    const urls = log.payload.match(urlRegex) || [];
    iocs.urls = [...new Set([...urls, log.forensics.url].filter(u => u !== null))];
    
    // Extract emails
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = log.payload.match(emailRegex) || [];
    iocs.emails = [...new Set(emails)];
    
    // Extract Bitcoin wallets
    const btcRegex = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g;
    const wallets = log.payload.match(btcRegex) || [];
    iocs.bitcoinWallets = [...new Set(wallets)];
    
    return iocs;
  }
  
  analyzeBehavior(log) {
    const behaviors = [];
    
    // Rapid requests
    if (log.forensics.connectionDuration < 100) {
      behaviors.push({ type: 'rapid_requests', severity: 'medium', description: 'Unusually fast connection attempts' });
    }
    
    // Large payload
    if (log.forensics.packetSize > 10000) {
      behaviors.push({ type: 'large_payload', severity: 'medium', description: 'Abnormally large packet size' });
    }
    
    // Suspicious user agent
    if (log.forensics.userAgent && /bot|crawler|scanner|curl|wget/i.test(log.forensics.userAgent)) {
      behaviors.push({ type: 'automated_tool', severity: 'high', description: 'Automated tool detected' });
    }
    
    // Port scanning
    if (log.threatType.includes('scan')) {
      behaviors.push({ type: 'reconnaissance', severity: 'high', description: 'Port scanning activity' });
    }
    
    // Data exfiltration
    if (log.threatType.includes('exfiltration')) {
      behaviors.push({ type: 'data_theft', severity: 'critical', description: 'Potential data exfiltration' });
    }
    
    return behaviors;
  }
  
  analyzeNetwork(log) {
    return {
      sourceInfo: {
        ip: log.sourceIP,
        geolocation: log.forensics.geolocation,
        asn: log.forensics.asn,
        reputation: this.checkIPReputation(log.sourceIP)
      },
      destinationInfo: {
        ip: log.destinationIP,
        port: log.port,
        protocol: log.protocol
      },
      connectionMetrics: {
        duration: log.forensics.connectionDuration,
        packetSize: log.forensics.packetSize,
        connectionType: this.classifyConnection(log)
      }
    };
  }
  
  checkIPReputation(ip) {
    // Mock reputation check - in production, integrate with threat intel feeds
    const knownBadIPs = ['192.168.100.100', '10.0.0.50'];
    return knownBadIPs.includes(ip) ? 'malicious' : 'unknown';
  }
  
  classifyConnection(log) {
    if (log.port && log.port < 1024) return 'privileged';
    if (log.port && log.port > 49152) return 'ephemeral';
    return 'registered';
  }
  
  analyzePayload(log) {
    const payload = log.payload || '';
    
    return {
      length: payload.length,
      encoding: this.detectEncoding(payload),
      entropy: this.calculateEntropy(payload),
      suspiciousPatterns: this.findSuspiciousPatterns(payload),
      containsBase64: /[A-Za-z0-9+/=]{40,}/.test(payload),
      containsHex: /[0-9a-fA-F]{32,}/.test(payload),
      containsSQLKeywords: /(select|insert|update|delete|drop|union)/i.test(payload),
      containsScriptTags: /<script|javascript:/i.test(payload)
    };
  }
  
  detectEncoding(payload) {
    if (/^[A-Za-z0-9+/=]+$/.test(payload)) return 'base64';
    if (/^[0-9a-fA-F]+$/.test(payload)) return 'hex';
    if (/[\x00-\x1F\x7F-\xFF]/.test(payload)) return 'binary';
    return 'plaintext';
  }
  
  calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const frequencies = {};
    
    for (let char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (let freq of Object.values(frequencies)) {
      const p = freq / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy.toFixed(2);
  }
  
  findSuspiciousPatterns(payload) {
    const patterns = [];
    
    if (/(\.\.|%2e%2e|%252e)/i.test(payload)) {
      patterns.push('path_traversal');
    }
    if (/(union|select|insert|update|delete).*?(from|into)/i.test(payload)) {
      patterns.push('sql_injection');
    }
    if (/<script|javascript:|onerror|onload/i.test(payload)) {
      patterns.push('xss');
    }
    if (/(\||;|&&|`|\$\()/i.test(payload)) {
      patterns.push('command_injection');
    }
    if (/eval\(|exec\(|system\(/i.test(payload)) {
      patterns.push('code_execution');
    }
    
    return patterns;
  }
  
  mapToMitre(log) {
    const techniques = [];
    
    // Initial Access
    if (log.threatType.includes('phishing')) {
      techniques.push({ id: 'T1566', name: 'Phishing', tactic: 'Initial Access' });
    }
    if (log.threatType.includes('exploit')) {
      techniques.push({ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' });
    }
    
    // Execution
    if (log.threatType.includes('command_injection') || log.threatType.includes('code_injection')) {
      techniques.push({ id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' });
    }
    
    // Persistence
    if (log.threatType.includes('web_shell') || log.threatType.includes('backdoor')) {
      techniques.push({ id: 'T1505', name: 'Server Software Component', tactic: 'Persistence' });
    }
    
    // Defense Evasion
    if (log.forensics.encoding !== 'plaintext') {
      techniques.push({ id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' });
    }
    
    // Credential Access
    if (log.threatType.includes('brute_force') || log.threatType.includes('credential')) {
      techniques.push({ id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' });
    }
    
    // Discovery
    if (log.threatType.includes('scan') || log.threatType.includes('reconnaissance')) {
      techniques.push({ id: 'T1046', name: 'Network Service Scanning', tactic: 'Discovery' });
    }
    
    // Command and Control
    if (log.threatType.includes('c2') || log.threatType.includes('botnet')) {
      techniques.push({ id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' });
    }
    
    // Exfiltration
    if (log.threatType.includes('exfiltration')) {
      techniques.push({ id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' });
    }
    
    // Impact
    if (log.threatType.includes('ransomware')) {
      techniques.push({ id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' });
    }
    if (log.threatType.includes('cryptomining')) {
      techniques.push({ id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' });
    }
    
    return techniques;
  }
  
  generateRecommendations(log) {
    const recommendations = [];
    
    if (log.severity === 'critical') {
      recommendations.push({
        priority: 'immediate',
        action: 'Block source IP permanently',
        reason: 'Critical threat detected'
      });
      recommendations.push({
        priority: 'immediate',
        action: 'Scan all systems for compromise',
        reason: 'Potential breach attempt'
      });
    }
    
    if (log.threatType.includes('ransomware')) {
      recommendations.push({
        priority: 'immediate',
        action: 'Isolate affected systems',
        reason: 'Ransomware detected'
      });
      recommendations.push({
        priority: 'high',
        action: 'Restore from backup',
        reason: 'Data encryption risk'
      });
    }
    
    if (log.threatType.includes('scan') || log.threatType.includes('reconnaissance')) {
      recommendations.push({
        priority: 'high',
        action: 'Enable rate limiting on firewall',
        reason: 'Port scanning detected'
      });
      recommendations.push({
        priority: 'medium',
        action: 'Review exposed services',
        reason: 'Minimize attack surface'
      });
    }
    
    if (!log.blocked) {
      recommendations.push({
        priority: 'immediate',
        action: 'Update firewall signatures',
        reason: 'Threat was not blocked'
      });
      recommendations.push({
        priority: 'high',
        action: 'Review firewall rules',
        reason: 'Detection gap identified'
      });
    }
    
    if (log.attackChain.isPartOfChain) {
      recommendations.push({
        priority: 'high',
        action: 'Investigate entire attack chain',
        reason: 'Part of coordinated attack'
      });
    }
    
    return recommendations;
  }
  
  async findRelatedThreats(log) {
    // This would query the database for related threats
    // For now, return empty array - will be populated when integrated with DB
    return [];
  }
  
  enrichWithThreatIntel(log) {
    // Mock threat intelligence enrichment
    // In production, integrate with MISP, AlienVault OTX, VirusTotal, etc.
    return {
      knownThreat: false,
      threatFamily: null,
      firstSeen: null,
      lastSeen: null,
      prevalence: 'unknown',
      associatedActors: [],
      associatedCampaigns: []
    };
  }
}

// ==================== EXPORT MANAGER ====================

class ExportManager {
  /**
   * Export logs to JSON format
   */
  exportToJSON(logs, statistics = null, filters = {}) {
    const data = {
      metadata: {
        exportDate: new Date().toISOString(),
        version: '2.0',
        application: 'Nebula Shield Advanced Firewall',
        totalLogs: logs.length,
        filters: filters
      },
      statistics: statistics || this.calculateStatistics(logs),
      logs: logs.map(log => ({
        ...log,
        timestamp: new Date(log.timestamp).toISOString(),
        confidencePercent: (log.confidence * 100).toFixed(2) + '%'
      }))
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const filename = `nebula-shield-logs-${this.formatDate()}.json`;
    this.downloadBlob(blob, filename);
  }
  
  /**
   * Export logs to CSV format
   */
  exportToCSV(logs, includeForensics = false) {
    if (logs.length === 0) {
      throw new Error('No logs to export');
    }
    
    // CSV headers
    const headers = [
      'Timestamp', 'Date', 'Time', 'Threat Type', 'Severity', 'Action', 
      'Source IP', 'Destination IP', 'Port', 'Protocol', 'Signature Name', 
      'Blocked', 'Confidence %', 'Risk Score', 'Description'
    ];
    
    if (includeForensics) {
      headers.push('Geolocation', 'User Agent', 'URL', 'Packet Size', 'TTL');
    }
    
    // CSV rows
    const rows = logs.map(log => {
      const date = new Date(log.timestamp);
      const row = [
        log.timestamp,
        date.toLocaleDateString(),
        date.toLocaleTimeString(),
        log.threatType,
        log.severity,
        log.action,
        log.sourceIP,
        log.destinationIP,
        log.port || 'N/A',
        log.protocol,
        log.signatureName || 'Unknown',
        log.blocked ? 'Yes' : 'No',
        (log.confidence * 100).toFixed(1),
        log.riskScore || 'N/A',
        (log.description || log.message || '').replace(/"/g, '""')
      ];
      
      if (includeForensics && log.forensics) {
        row.push(
          log.forensics.geolocation?.country || 'Unknown',
          log.forensics.userAgent || 'N/A',
          log.forensics.url || 'N/A',
          log.forensics.packetSize || 'N/A',
          log.forensics.ttl || 'N/A'
        );
      } else if (includeForensics) {
        row.push('N/A', 'N/A', 'N/A', 'N/A', 'N/A');
      }
      
      return row;
    });
    
    // Combine headers and rows
    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const filename = `nebula-shield-logs-${this.formatDate()}.csv`;
    this.downloadBlob(blob, filename);
  }
  
  /**
   * Export logs to PDF format using jsPDF
   */
  async exportToPDF(logs, statistics = null, options = {}) {
    // Dynamically import jsPDF
    const { default: jsPDF } = await import('jspdf');
    await import('jspdf-autotable');
    
    const stats = statistics || this.calculateStatistics(logs);
    const doc = new jsPDF('p', 'mm', 'a4');
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    let yPosition = 20;
    
    // Title
    doc.setFontSize(22);
    doc.setTextColor(124, 58, 237); // Purple
    doc.text('🛡️ Nebula Shield', pageWidth / 2, yPosition, { align: 'center' });
    
    yPosition += 8;
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('Firewall Security Report', pageWidth / 2, yPosition, { align: 'center' });
    
    yPosition += 10;
    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100);
    doc.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, yPosition, { align: 'center' });
    
    yPosition += 3;
    doc.text(`Report Period: ${options.dateRange || 'All Time'}`, pageWidth / 2, yPosition, { align: 'center' });
    
    // Summary Statistics Box
    yPosition += 10;
    doc.setFillColor(243, 244, 246);
    doc.rect(15, yPosition, pageWidth - 30, 45, 'F');
    
    yPosition += 8;
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Executive Summary', 20, yPosition);
    
    yPosition += 8;
    doc.setFontSize(10);
    
    const summaryData = [
      ['Total Threats Detected', stats.totalThreats.toLocaleString()],
      ['Threats Blocked', `${stats.threatsBlocked.toLocaleString()} (${((stats.threatsBlocked / stats.totalThreats) * 100 || 0).toFixed(1)}%)`],
      ['Critical Severity', stats.criticalThreats.toLocaleString()],
      ['High Severity', stats.highThreats.toLocaleString()],
      ['Medium Severity', stats.mediumThreats.toLocaleString()],
      ['Low Severity', stats.lowThreats.toLocaleString()]
    ];
    
    summaryData.forEach(([label, value], index) => {
      const col1X = 20;
      const col2X = pageWidth / 2 + 10;
      const row = Math.floor(index / 2);
      const col = index % 2;
      const x = col === 0 ? col1X : col2X;
      const y = yPosition + (row * 6);
      
      doc.setTextColor(100, 100, 100);
      doc.text(label + ':', x, y);
      doc.setTextColor(0, 0, 0);
      doc.setFont(undefined, 'bold');
      doc.text(value, x + 50, y);
      doc.setFont(undefined, 'normal');
    });
  
    
    // Threat Type Breakdown Table
    yPosition += 25;
    doc.setFontSize(12);
    doc.setTextColor(0, 0, 0);
    doc.text('Threat Type Breakdown', 15, yPosition);
    
    yPosition += 5;
    const threatTypes = this.getThreatTypeBreakdown(logs);
    const threatTableData = Object.entries(threatTypes)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([type, count]) => [
        type,
        count.toLocaleString(),
        ((count / logs.length) * 100).toFixed(1) + '%'
      ]);
    
    doc.autoTable({
      startY: yPosition,
      head: [['Threat Type', 'Count', 'Percentage']],
      body: threatTableData,
      theme: 'striped',
      headStyles: { fillColor: [124, 58, 237] },
      margin: { left: 15, right: 15 },
      styles: { fontSize: 9 }
    });
    
    // Detailed Logs Table
    yPosition = doc.lastAutoTable.finalY + 15;
    if (yPosition > pageHeight - 50) {
      doc.addPage();
      yPosition = 20;
    }
    
    doc.setFontSize(12);
    doc.text('Detailed Threat Log', 15, yPosition);
    
    yPosition += 5;
    const maxLogs = options.maxLogs || 50;
    const logsTableData = logs.slice(0, maxLogs).map(log => [
      new Date(log.timestamp).toLocaleString(),
      log.threatType,
      log.severity.toUpperCase(),
      log.sourceIP,
      log.destinationIP || 'N/A',
      log.blocked ? '✓ Blocked' : '✗ Allowed'
    ]);
    
    doc.autoTable({
      startY: yPosition,
      head: [['Timestamp', 'Threat Type', 'Severity', 'Source IP', 'Dest IP', 'Status']],
      body: logsTableData,
      theme: 'striped',
      headStyles: { fillColor: [124, 58, 237] },
      margin: { left: 15, right: 15 },
      styles: { fontSize: 8, cellPadding: 2 },
      columnStyles: {
        0: { cellWidth: 35 },
        1: { cellWidth: 30 },
        2: { cellWidth: 20 },
        3: { cellWidth: 30 },
        4: { cellWidth: 30 },
        5: { cellWidth: 25 }
      },
      didParseCell: function(data) {
        if (data.section === 'body' && data.column.index === 2) {
          const severity = data.cell.raw.toLowerCase();
          if (severity.includes('critical')) data.cell.styles.textColor = [220, 38, 38];
          else if (severity.includes('high')) data.cell.styles.textColor = [245, 158, 11];
          else if (severity.includes('medium')) data.cell.styles.textColor = [59, 130, 246];
          else if (severity.includes('low')) data.cell.styles.textColor = [16, 185, 129];
        }
      }
    });
    
    // Footer on each page
    const totalPages = doc.internal.pages.length - 1;
    for (let i = 1; i <= totalPages; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150, 150, 150);
      doc.text(
        `Nebula Shield v2.0 | Page ${i} of ${totalPages}`,
        pageWidth / 2,
        pageHeight - 10,
        { align: 'center' }
      );
    }
    
    // Save PDF
    const filename = `nebula-shield-report-${this.formatDate()}.pdf`;
    doc.save(filename);
  }
  
  /**
   * Calculate statistics from logs
   */
  calculateStatistics(logs) {
    const stats = {
      totalThreats: logs.length,
      threatsBlocked: logs.filter(l => l.blocked).length,
      criticalThreats: logs.filter(l => l.severity === 'critical').length,
      highThreats: logs.filter(l => l.severity === 'high').length,
      mediumThreats: logs.filter(l => l.severity === 'medium').length,
      lowThreats: logs.filter(l => l.severity === 'low').length
    };
    return stats;
  }
  
  /**
   * Get threat type breakdown
   */
  getThreatTypeBreakdown(logs) {
    const breakdown = {};
    logs.forEach(log => {
      const type = log.threatType || 'Unknown';
      breakdown[type] = (breakdown[type] || 0) + 1;
    });
    return breakdown;
  }
  
  /**
   * Format date for filenames
   */
  formatDate() {
    const now = new Date();
    return now.toISOString().split('T')[0] + '-' + 
           now.toTimeString().split(' ')[0].replace(/:/g, '');
  }
  
  downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
}

// ==================== MAIN LOGGER CLASS ====================

export class FirewallLogger {
  constructor() {
    this.db = new IndexedDBManager();
    this.forensicAnalyzer = new ForensicAnalyzer();
    this.exportManager = new ExportManager();
    this.memoryLogs = [];
    this.listeners = [];
    this.initialized = false;
  }
  
  async initialize() {
    if (this.initialized) return;
    
    try {
      await this.db.initialize();
      await this.cleanupOldLogs();
      this.initialized = true;
      console.log('✅ Firewall Logger initialized');
    } catch (error) {
      console.error('❌ Failed to initialize Firewall Logger:', error);
      // Mark as initialized anyway to prevent infinite retry loops
      this.initialized = true;
      throw error;
    }
  }
  
  /**
   * Log a new threat event
   */
  async logThreat(data) {
    if (!this.initialized) await this.initialize();
    
    const log = new LogEntry(data);
    
    // Add to memory cache
    this.memoryLogs.unshift(log);
    if (this.memoryLogs.length > LOGGING_CONFIG.maxMemoryEntries) {
      this.memoryLogs.pop();
    }
    
    // Store in IndexedDB
    try {
      await this.db.addLog(log);
      await this.updateDailyStatistics(log);
      
      // Create critical alert if needed
      if (log.severity === 'critical') {
        await this.createCriticalAlert(log);
      }
      
      // Perform forensic analysis if enabled
      if (LOGGING_CONFIG.forensicMode) {
        const forensics = await this.forensicAnalyzer.analyze(log);
        // Store forensics separately for detailed analysis
      }
      
      // Notify listeners
      this.notifyListeners('new_log', log);
      
      return log;
    } catch (error) {
      console.error('Failed to log threat:', error);
      return log; // Still return log even if storage fails
    }
  }
  
  /**
   * Get logs with filters
   */
  async getLogs(filters = {}) {
    if (!this.initialized) {
      try {
        await this.initialize();
      } catch (error) {
        console.error('Failed to initialize logger:', error);
        return [];
      }
    }
    
    try {
      return await this.db.getLogs(filters);
    } catch (error) {
      console.error('Failed to get logs:', error);
      return [];
    }
  }
  
  /**
   * Search logs
   */
  async searchLogs(query) {
    if (!this.initialized) await this.initialize();
    return await this.db.searchLogs(query);
  }
  
  /**
   * Get forensic analysis for a specific log
   */
  async getForensicAnalysis(logId) {
    if (!this.initialized) await this.initialize();
    
    const log = await this.db.getLogById(logId);
    if (!log) return null;
    
    return await this.forensicAnalyzer.analyze(log);
  }
  
  /**
   * Get statistics
   */
  async getStatistics(filters = {}) {
    if (!this.initialized) {
      try {
        await this.initialize();
      } catch (error) {
        console.error('Failed to initialize logger:', error);
        // Return empty statistics if initialization fails
        return this.getEmptyStatistics();
      }
    }
    
    try {
      const logs = await this.db.getLogs(filters);
      
      const stats = {
        totalThreats: logs.length,
        threatsBlocked: logs.filter(l => l.blocked).length,
        criticalThreats: logs.filter(l => l.severity === 'critical').length,
        highThreats: logs.filter(l => l.severity === 'high').length,
        mediumThreats: logs.filter(l => l.severity === 'medium').length,
        lowThreats: logs.filter(l => l.severity === 'low').length,
        blockRate: logs.length > 0 ? Math.round((logs.filter(l => l.blocked).length / logs.length) * 100) : 0,
        
        topThreatTypes: this.getTopN(logs, 'threatType', 5),
        topSourceIPs: this.getTopN(logs, 'sourceIP', 10),
        topTargetPorts: this.getTopN(logs, 'port', 5),
        
        timeline: this.generateTimeline(logs),
        severityDistribution: this.getSeverityDistribution(logs)
      };
      
      return stats;
    } catch (error) {
      console.error('Failed to calculate statistics:', error);
      return this.getEmptyStatistics();
    }
  }
  
  /**
   * Return empty statistics object
   */
  getEmptyStatistics() {
    return {
      totalThreats: 0,
      threatsBlocked: 0,
      criticalThreats: 0,
      highThreats: 0,
      mediumThreats: 0,
      lowThreats: 0,
      blockRate: 0,
      topThreatTypes: [],
      topSourceIPs: [],
      topTargetPorts: [],
      timeline: [],
      severityDistribution: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      }
    };
  }
  
  getTopN(logs, field, n) {
    const counts = {};
    logs.forEach(log => {
      const value = log[field];
      if (value) {
        counts[value] = (counts[value] || 0) + 1;
      }
    });
    
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([name, count]) => ({ name, count }));
  }
  
  generateTimeline(logs) {
    const timeline = {};
    logs.forEach(log => {
      const date = new Date(log.timestamp).toISOString().split('T')[0];
      timeline[date] = (timeline[date] || 0) + 1;
    });
    
    return Object.entries(timeline)
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, count]) => ({ date, count }));
  }
  
  getSeverityDistribution(logs) {
    return {
      critical: logs.filter(l => l.severity === 'critical').length,
      high: logs.filter(l => l.severity === 'high').length,
      medium: logs.filter(l => l.severity === 'medium').length,
      low: logs.filter(l => l.severity === 'low').length
    };
  }
  
  /**
   * Export logs
   */
  async exportLogs(format = 'json', filters = {}, options = {}) {
    if (!this.initialized) await this.initialize();
    
    const logs = await this.db.getLogs(filters);
    
    if (logs.length === 0) {
      throw new Error('No logs available to export');
    }
    
    const stats = options.includeStats !== false ? await this.getStatisticsFast(7) : null;
    
    switch (format.toLowerCase()) {
      case 'json':
        this.exportManager.exportToJSON(logs, stats, filters);
        break;
      case 'csv':
        this.exportManager.exportToCSV(logs, options.includeForensics || false);
        break;
      case 'pdf':
        await this.exportManager.exportToPDF(logs, stats, {
          dateRange: options.dateRange || 'All Time',
          maxLogs: options.maxLogs || 50
        });
        break;
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
    
    return { success: true, count: logs.length, format };
  }
  
  /**
   * Clear all logs
   */
  async clearLogs() {
    if (!this.initialized) await this.initialize();
    
    await this.db.clearAllLogs();
    this.memoryLogs = [];
    this.notifyListeners('logs_cleared');
  }
  
  /**
   * Cleanup old logs based on retention policy
   */
  async cleanupOldLogs() {
    if (!this.db || !this.db.db) {
      console.warn('Database not initialized, skipping cleanup');
      return 0;
    }
    
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - LOGGING_CONFIG.retentionDays);
      
      // Use cursor to efficiently find and delete old logs without loading all
      return new Promise((resolve, reject) => {
        try {
          const transaction = this.db.db.transaction(['logs'], 'readwrite');
          const store = transaction.objectStore('logs');
          const index = store.index('timestamp');
          
          let deletedCount = 0;
          const range = IDBKeyRange.upperBound(cutoffDate.toISOString());
          const request = index.openCursor(range);
          
          request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
              cursor.delete();
              deletedCount++;
              cursor.continue();
            } else {
              if (deletedCount > 0) {
                console.log(`🗑️ Cleaned up ${deletedCount} old logs`);
              }
              resolve(deletedCount);
            }
          };
          
          request.onerror = () => {
            console.error('Cleanup cursor error:', request.error);
            resolve(0); // Don't fail initialization on cleanup error
          };
          
          transaction.onerror = () => {
            console.error('Cleanup transaction error:', transaction.error);
            resolve(0);
          };
        } catch (error) {
          console.error('Cleanup error:', error);
          resolve(0);
        }
      });
    } catch (error) {
      console.error('Failed to cleanup old logs:', error);
      return 0;
    }
  }
  
  /**
   * Get statistics efficiently without loading all logs
   */
  async getStatisticsFast(days = 7) {
    if (!this.initialized) await this.initialize();
    
    const stats = {
      totalLogs: 0,
      criticalThreats: 0,
      highThreats: 0,
      mediumThreats: 0,
      lowThreats: 0,
      blockedCount: 0,
      allowedCount: 0,
      topThreatTypes: {},
      topSourceIPs: {},
      topTargetPorts: {},
      recentLogs: []
    };
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.db.transaction(['logs'], 'readonly');
      const store = transaction.objectStore('logs');
      const index = store.index('timestamp');
      const range = IDBKeyRange.lowerBound(cutoffDate.getTime());
      
      const request = index.openCursor(range, 'prev');
      
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        
        if (cursor) {
          const log = cursor.value;
          stats.totalLogs++;
          
          // Count by severity
          if (log.severity === 'critical') stats.criticalThreats++;
          else if (log.severity === 'high') stats.highThreats++;
          else if (log.severity === 'medium') stats.mediumThreats++;
          else if (log.severity === 'low') stats.lowThreats++;
          
          // Count blocked/allowed
          if (log.blocked) stats.blockedCount++;
          else stats.allowedCount++;
          
          // Track top threat types
          stats.topThreatTypes[log.threatType] = (stats.topThreatTypes[log.threatType] || 0) + 1;
          
          // Track top source IPs
          if (log.sourceIP && log.sourceIP !== 'unknown') {
            stats.topSourceIPs[log.sourceIP] = (stats.topSourceIPs[log.sourceIP] || 0) + 1;
          }
          
          // Track top ports
          if (log.port) {
            stats.topTargetPorts[log.port] = (stats.topTargetPorts[log.port] || 0) + 1;
          }
          
          // Keep last 10 for recent logs
          if (stats.recentLogs.length < 10) {
            stats.recentLogs.push(log);
          }
          
          cursor.continue();
        } else {
          resolve(stats);
        }
      };
      
      request.onerror = () => reject(request.error);
    });
  }
  
  /**
   * Update daily statistics
   */
  async updateDailyStatistics(log) {
    const today = new Date().toISOString().split('T')[0];
    const stats = await this.db.getStatistics(today);
    
    stats.totalThreats++;
    if (log.blocked) stats.threatsBlocked++;
    
    // Update severity counts
    stats[`${log.severity}Threats`]++;
    
    // Update top threat types
    stats.topThreatTypes[log.threatType] = (stats.topThreatTypes[log.threatType] || 0) + 1;
    
    // Update top source IPs
    if (log.sourceIP !== 'unknown') {
      stats.topSourceIPs[log.sourceIP] = (stats.topSourceIPs[log.sourceIP] || 0) + 1;
    }
    
    // Update top target ports
    if (log.port) {
      stats.topTargetPorts[log.port] = (stats.topTargetPorts[log.port] || 0) + 1;
    }
    
    await this.db.updateStatistics(stats);
  }
  
  /**
   * Create critical alert
   */
  async createCriticalAlert(log) {
    const alert = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      severity: 'critical',
      logId: log.id,
      title: `Critical Threat: ${log.signatureName}`,
      description: `${log.threatType} detected from ${log.sourceIP}`,
      resolved: false,
      acknowledgedBy: null,
      acknowledgedAt: null
    };
    
    await this.db.addAlert(alert);
    this.notifyListeners('critical_alert', alert);
  }
  
  /**
   * Subscribe to events
   */
  subscribe(callback) {
    this.listeners.push(callback);
    return () => {
      this.listeners = this.listeners.filter(cb => cb !== callback);
    };
  }
  
  /**
   * Notify all listeners
   */
  notifyListeners(event, data) {
    this.listeners.forEach(callback => {
      try {
        callback(event, data);
      } catch (error) {
        console.error('Listener error:', error);
      }
    });
  }
}

// Create singleton instance
const firewallLogger = new FirewallLogger();

export default firewallLogger;
