/**
 * Threat Intelligence Service
 * Real-time threat feeds, IP reputation, IoC detection, and MITRE ATT&CK mapping
 */

import notificationService from './notificationService';

// Threat Intelligence Feeds
const THREAT_FEEDS = {
  malwareIPs: 'https://feeds.nebula-shield.com/malware-ips',
  phishingDomains: 'https://feeds.nebula-shield.com/phishing-domains',
  ransomwareHashes: 'https://feeds.nebula-shield.com/ransomware-hashes',
  botnetC2: 'https://feeds.nebula-shield.com/botnet-c2',
  exploitKits: 'https://feeds.nebula-shield.com/exploit-kits'
};

// MITRE ATT&CK Framework Tactics
const MITRE_TACTICS = {
  TA0001: { name: 'Initial Access', techniques: 11 },
  TA0002: { name: 'Execution', techniques: 13 },
  TA0003: { name: 'Persistence', techniques: 19 },
  TA0004: { name: 'Privilege Escalation', techniques: 13 },
  TA0005: { name: 'Defense Evasion', techniques: 42 },
  TA0006: { name: 'Credential Access', techniques: 17 },
  TA0007: { name: 'Discovery', techniques: 30 },
  TA0008: { name: 'Lateral Movement', techniques: 9 },
  TA0009: { name: 'Collection', techniques: 17 },
  TA0010: { name: 'Exfiltration', techniques: 9 },
  TA0011: { name: 'Command and Control', techniques: 16 },
  TA0040: { name: 'Impact', techniques: 13 }
};

class ThreatIntelligenceService {
  constructor() {
    this.threatFeeds = new Map();
    this.ipReputation = new Map();
    this.domainReputation = new Map();
    this.fileHashDatabase = new Map();
    this.indicators = new Set();
    this.detectedThreats = [];
    this.mitreDetections = [];
    this.feedUpdateInterval = null;
    this.updateFrequency = 60 * 60 * 1000; // 1 hour
    this.listeners = new Set();
    this.stats = {
      totalThreats: 0,
      blockedIPs: 0,
      blockedDomains: 0,
      maliciousFiles: 0,
      lastUpdate: null,
      feedStatus: 'disconnected'
    };
    
    this.initialize();
  }

  // ==================== INITIALIZATION ====================

  async initialize() {
    console.log('[Threat Intel] Initializing threat intelligence service...');
    
    // Load cached threat data
    this.loadCache();
    
    // Update threat feeds
    await this.updateThreatFeeds();
    
    // Start auto-update
    this.startAutoUpdate();
    
    // Load sample threat data
    this.loadSampleThreats();
    
    console.log('[Threat Intel] Initialization complete');
  }

  loadSampleThreats() {
    // Sample malicious IPs
    const maliciousIPs = [
      { ip: '192.0.2.1', reputation: 'malicious', category: 'botnet', confidence: 95 },
      { ip: '198.51.100.50', reputation: 'malicious', category: 'phishing', confidence: 88 },
      { ip: '203.0.113.100', reputation: 'suspicious', category: 'scanning', confidence: 72 },
      { ip: '185.220.101.1', reputation: 'malicious', category: 'tor-exit', confidence: 65 },
      { ip: '45.142.212.61', reputation: 'malicious', category: 'ransomware-c2', confidence: 98 }
    ];

    maliciousIPs.forEach(({ ip, reputation, category, confidence }) => {
      this.ipReputation.set(ip, { reputation, category, confidence, lastSeen: new Date().toISOString() });
    });

    // Sample malicious domains
    const maliciousDomains = [
      { domain: 'evil-phishing-site.com', reputation: 'malicious', category: 'phishing', confidence: 92 },
      { domain: 'malware-download.net', reputation: 'malicious', category: 'malware-distribution', confidence: 96 },
      { domain: 'suspicious-login.org', reputation: 'suspicious', category: 'credential-theft', confidence: 78 },
      { domain: 'fake-bank-login.com', reputation: 'malicious', category: 'phishing', confidence: 99 }
    ];

    maliciousDomains.forEach(({ domain, reputation, category, confidence }) => {
      this.domainReputation.set(domain, { reputation, category, confidence, lastSeen: new Date().toISOString() });
    });

    // Sample malicious file hashes
    const maliciousHashes = [
      { hash: '44d88612fea8a8f36de82e1278abb02f', type: 'md5', threat: 'Trojan.Generic', confidence: 90 },
      { hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', type: 'sha256', threat: 'Ransomware.WannaCry', confidence: 100 },
      { hash: 'b3215c06647bc550406a9c8ccc378756', type: 'md5', threat: 'Backdoor.Cobalt', confidence: 85 }
    ];

    maliciousHashes.forEach(({ hash, type, threat, confidence }) => {
      this.fileHashDatabase.set(hash, { type, threat, confidence, firstSeen: new Date().toISOString() });
    });
  }

  // ==================== THREAT FEED MANAGEMENT ====================

  async updateThreatFeeds() {
    console.log('[Threat Intel] Updating threat feeds...');
    this.stats.feedStatus = 'updating';
    this.notifyListeners({ type: 'feed_update_started' });

    try {
      // Simulate fetching from multiple threat feeds
      await this.fetchFeed('malwareIPs', THREAT_FEEDS.malwareIPs);
      await this.fetchFeed('phishingDomains', THREAT_FEEDS.phishingDomains);
      await this.fetchFeed('ransomwareHashes', THREAT_FEEDS.ransomwareHashes);
      await this.fetchFeed('botnetC2', THREAT_FEEDS.botnetC2);
      await this.fetchFeed('exploitKits', THREAT_FEEDS.exploitKits);

      this.stats.lastUpdate = new Date().toISOString();
      this.stats.feedStatus = 'connected';
      this.saveCache();

      this.notifyListeners({ type: 'feed_update_completed', timestamp: this.stats.lastUpdate });

      notificationService.show({
        type: 'success',
        title: 'Threat Feeds Updated',
        message: 'Latest threat intelligence downloaded',
        duration: 3000
      });

    } catch (error) {
      console.error('[Threat Intel] Feed update failed:', error);
      this.stats.feedStatus = 'error';
      this.notifyListeners({ type: 'feed_update_failed', error: error.message });
      throw error;
    }
  }

  async fetchFeed(feedName, feedUrl) {
    // Simulate API call to threat feed
    return new Promise((resolve) => {
      setTimeout(() => {
        const feedData = {
          name: feedName,
          url: feedUrl,
          lastUpdate: new Date().toISOString(),
          entries: Math.floor(Math.random() * 1000) + 500
        };
        
        this.threatFeeds.set(feedName, feedData);
        resolve(feedData);
      }, 500);
    });
  }

  startAutoUpdate() {
    if (this.feedUpdateInterval) {
      clearInterval(this.feedUpdateInterval);
    }

    this.feedUpdateInterval = setInterval(() => {
      this.updateThreatFeeds().catch(error => {
        console.error('[Threat Intel] Auto-update failed:', error);
      });
    }, this.updateFrequency);
  }

  stopAutoUpdate() {
    if (this.feedUpdateInterval) {
      clearInterval(this.feedUpdateInterval);
      this.feedUpdateInterval = null;
    }
  }

  // ==================== IP REPUTATION ====================

  checkIPReputation(ip) {
    const reputation = this.ipReputation.get(ip);
    
    if (reputation) {
      const threat = {
        type: 'malicious_ip',
        ip,
        ...reputation,
        timestamp: new Date().toISOString()
      };

      if (reputation.reputation === 'malicious') {
        this.stats.blockedIPs++;
        this.detectedThreats.push(threat);
        this.saveCache();

        notificationService.show({
          type: 'error',
          title: 'Malicious IP Blocked',
          message: `Blocked connection to ${ip} (${reputation.category})`,
          duration: 5000
        });
      }

      return threat;
    }

    return {
      type: 'ip_check',
      ip,
      reputation: 'clean',
      confidence: 100,
      timestamp: new Date().toISOString()
    };
  }

  addIPThreat(ip, category, confidence = 90) {
    this.ipReputation.set(ip, {
      reputation: 'malicious',
      category,
      confidence,
      lastSeen: new Date().toISOString()
    });
    this.saveCache();
  }

  // ==================== DOMAIN REPUTATION ====================

  checkDomainReputation(domain) {
    const reputation = this.domainReputation.get(domain);
    
    if (reputation) {
      const threat = {
        type: 'malicious_domain',
        domain,
        ...reputation,
        timestamp: new Date().toISOString()
      };

      if (reputation.reputation === 'malicious') {
        this.stats.blockedDomains++;
        this.detectedThreats.push(threat);
        this.saveCache();

        notificationService.show({
          type: 'error',
          title: 'Malicious Domain Blocked',
          message: `Blocked access to ${domain} (${reputation.category})`,
          duration: 5000
        });
      }

      return threat;
    }

    return {
      type: 'domain_check',
      domain,
      reputation: 'clean',
      confidence: 100,
      timestamp: new Date().toISOString()
    };
  }

  addDomainThreat(domain, category, confidence = 90) {
    this.domainReputation.set(domain, {
      reputation: 'malicious',
      category,
      confidence,
      lastSeen: new Date().toISOString()
    });
    this.saveCache();
  }

  // ==================== FILE HASH CHECKING ====================

  checkFileHash(hash) {
    const threat = this.fileHashDatabase.get(hash.toLowerCase());
    
    if (threat) {
      const detection = {
        type: 'malicious_file',
        hash,
        ...threat,
        timestamp: new Date().toISOString()
      };

      this.stats.maliciousFiles++;
      this.detectedThreats.push(detection);
      this.saveCache();

      notificationService.show({
        type: 'error',
        title: 'Malicious File Detected',
        message: `File matches known threat: ${threat.threat}`,
        duration: 5000
      });

      return detection;
    }

    return {
      type: 'hash_check',
      hash,
      status: 'clean',
      confidence: 100,
      timestamp: new Date().toISOString()
    };
  }

  addFileHashThreat(hash, threat, hashType = 'md5', confidence = 95) {
    this.fileHashDatabase.set(hash.toLowerCase(), {
      type: hashType,
      threat,
      confidence,
      firstSeen: new Date().toISOString()
    });
    this.saveCache();
  }

  // ==================== INDICATORS OF COMPROMISE (IOC) ====================

  addIndicator(ioc) {
    const indicator = {
      ...ioc,
      id: `ioc-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      addedAt: new Date().toISOString()
    };

    this.indicators.add(JSON.stringify(indicator));
    this.saveCache();

    return indicator;
  }

  checkIndicators(data) {
    const matches = [];
    
    for (const iocStr of this.indicators) {
      const ioc = JSON.parse(iocStr);
      
      if (this.matchesIndicator(data, ioc)) {
        matches.push(ioc);
      }
    }

    if (matches.length > 0) {
      notificationService.show({
        type: 'warning',
        title: 'IoC Detected',
        message: `${matches.length} indicator(s) of compromise found`,
        duration: 5000
      });
    }

    return matches;
  }

  matchesIndicator(data, ioc) {
    switch (ioc.type) {
      case 'ip':
        return data.ip === ioc.value;
      case 'domain':
        return data.domain === ioc.value || data.url?.includes(ioc.value);
      case 'hash':
        return data.hash === ioc.value;
      case 'url':
        return data.url === ioc.value;
      case 'email':
        return data.email === ioc.value;
      default:
        return false;
    }
  }

  getIndicators() {
    return Array.from(this.indicators).map(ioc => JSON.parse(ioc));
  }

  // ==================== MITRE ATT&CK MAPPING ====================

  detectMITRETechnique(behaviorData) {
    const detections = [];

    // Analyze behavior and map to MITRE techniques
    if (behaviorData.type === 'process_creation') {
      detections.push(this.createMITREDetection('T1059', 'Command and Scripting Interpreter', 'TA0002'));
    }

    if (behaviorData.type === 'registry_modification') {
      detections.push(this.createMITREDetection('T1547', 'Boot or Logon Autostart Execution', 'TA0003'));
    }

    if (behaviorData.type === 'network_connection' && behaviorData.port === 445) {
      detections.push(this.createMITREDetection('T1021', 'Remote Services', 'TA0008'));
    }

    if (behaviorData.type === 'credential_access') {
      detections.push(this.createMITREDetection('T1003', 'OS Credential Dumping', 'TA0006'));
    }

    if (behaviorData.type === 'data_exfiltration') {
      detections.push(this.createMITREDetection('T1048', 'Exfiltration Over Alternative Protocol', 'TA0010'));
    }

    detections.forEach(detection => {
      this.mitreDetections.push(detection);
      this.stats.totalThreats++;
    });

    if (detections.length > 0) {
      this.saveCache();
      
      notificationService.show({
        type: 'error',
        title: 'MITRE ATT&CK Detection',
        message: `Detected: ${detections[0].technique}`,
        duration: 5000
      });
    }

    return detections;
  }

  createMITREDetection(techniqueId, techniqueName, tacticId) {
    return {
      id: `mitre-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      techniqueId,
      technique: techniqueName,
      tacticId,
      tactic: MITRE_TACTICS[tacticId]?.name || 'Unknown',
      timestamp: new Date().toISOString(),
      severity: 'high'
    };
  }

  getMITREDetections(limit = 100) {
    return this.mitreDetections.slice(-limit).reverse();
  }

  getMITRETactics() {
    return Object.entries(MITRE_TACTICS).map(([id, data]) => ({
      id,
      ...data,
      detections: this.mitreDetections.filter(d => d.tacticId === id).length
    }));
  }

  // ==================== THREAT CORRELATION ====================

  correlateThreats(timeWindow = 300000) { // 5 minutes
    const recentThreats = this.detectedThreats.filter(threat => 
      Date.now() - new Date(threat.timestamp).getTime() < timeWindow
    );

    const correlations = [];
    const threatsBySource = new Map();

    // Group threats by source (IP, domain, hash)
    recentThreats.forEach(threat => {
      const source = threat.ip || threat.domain || threat.hash;
      if (!threatsBySource.has(source)) {
        threatsBySource.set(source, []);
      }
      threatsBySource.get(source).push(threat);
    });

    // Find correlations
    threatsBySource.forEach((threats, source) => {
      if (threats.length >= 2) {
        correlations.push({
          source,
          threatCount: threats.length,
          threats,
          severity: this.calculateCorrelationSeverity(threats),
          timestamp: new Date().toISOString()
        });
      }
    });

    return correlations;
  }

  calculateCorrelationSeverity(threats) {
    const avgConfidence = threats.reduce((sum, t) => sum + (t.confidence || 0), 0) / threats.length;
    
    if (avgConfidence >= 90 && threats.length >= 3) return 'critical';
    if (avgConfidence >= 75 && threats.length >= 2) return 'high';
    if (avgConfidence >= 60) return 'medium';
    return 'low';
  }

  // ==================== STATISTICS & REPORTING ====================

  getStatistics() {
    return {
      ...this.stats,
      totalDetections: this.detectedThreats.length,
      mitreDetections: this.mitreDetections.length,
      indicators: this.indicators.size,
      ipThreats: this.ipReputation.size,
      domainThreats: this.domainReputation.size,
      fileThreats: this.fileHashDatabase.size,
      feeds: this.threatFeeds.size
    };
  }

  getRecentThreats(limit = 50) {
    return this.detectedThreats.slice(-limit).reverse();
  }

  getThreatsByType() {
    const byType = new Map();
    
    this.detectedThreats.forEach(threat => {
      const count = byType.get(threat.type) || 0;
      byType.set(threat.type, count + 1);
    });

    return Object.fromEntries(byType);
  }

  getThreatTimeline(hours = 24) {
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    return this.detectedThreats.filter(threat => 
      new Date(threat.timestamp).getTime() >= cutoff
    );
  }

  // ==================== CACHE MANAGEMENT ====================

  loadCache() {
    try {
      const cachedStats = localStorage.getItem('threat_intel_stats');
      if (cachedStats) {
        this.stats = { ...this.stats, ...JSON.parse(cachedStats) };
      }

      const cachedThreats = localStorage.getItem('threat_intel_threats');
      if (cachedThreats) {
        this.detectedThreats = JSON.parse(cachedThreats);
      }

      const cachedMitre = localStorage.getItem('threat_intel_mitre');
      if (cachedMitre) {
        this.mitreDetections = JSON.parse(cachedMitre);
      }
    } catch (error) {
      console.error('[Threat Intel] Failed to load cache:', error);
    }
  }

  saveCache() {
    try {
      localStorage.setItem('threat_intel_stats', JSON.stringify(this.stats));
      localStorage.setItem('threat_intel_threats', JSON.stringify(this.detectedThreats.slice(-1000))); // Keep last 1000
      localStorage.setItem('threat_intel_mitre', JSON.stringify(this.mitreDetections.slice(-500))); // Keep last 500
    } catch (error) {
      console.error('[Threat Intel] Failed to save cache:', error);
    }
  }

  // ==================== EVENT LISTENERS ====================

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notifyListeners(event) {
    this.listeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error('[Threat Intel] Listener error:', error);
      }
    });
  }

  // ==================== CLEANUP ====================

  destroy() {
    this.stopAutoUpdate();
    this.saveCache();
    this.listeners.clear();
  }
}

// Export singleton instance
const threatIntelligenceService = new ThreatIntelligenceService();
export default threatIntelligenceService;
