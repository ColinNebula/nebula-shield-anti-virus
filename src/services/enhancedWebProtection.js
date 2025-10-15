// ==================== ENHANCED WEB PROTECTION SERVICE ====================
// Advanced real-time threat detection, phishing protection, DNS filtering,
// SSL/TLS validation, content analysis, and comprehensive security monitoring

// ==================== THREAT DATABASES ====================

// Known malicious domains (expanded database)
const MALICIOUS_DOMAINS = new Set([
  'malware-site.com',
  'phishing-bank.com',
  'fake-paypal.com',
  'virus-download.com',
  'scam-lottery.com',
  'fake-antivirus.com',
  'trojan-host.com',
  'malicious-ad.net',
  'ransomware-host.com',
  'cryptominer-pool.com',
  'spyware-download.org',
  'fake-microsoft-support.com',
  'credential-stealer.net',
  'malvertising-network.com',
  'drive-by-download.org'
]);

// Dangerous file extensions for downloads
const DANGEROUS_FILE_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
  '.jar', '.msi', '.apk', '.app', '.deb', '.dmg', '.pkg',
  '.ps1', '.hta', '.lnk', '.reg', '.dll', '.sys', '.drv',
  '.scpt', '.action', '.workflow', '.bin', '.gadget'
]);

// Web attack patterns (XSS, SQL injection, etc.)
const WEB_ATTACK_PATTERNS = [
  {
    id: 'xss_attack',
    type: 'web_attack',
    severity: 'critical',
    pattern: /<script[^>]*>.*?<\/script>|javascript:|onerror=|onclick=/i,
    description: 'Cross-Site Scripting (XSS) attack detected'
  },
  {
    id: 'sql_injection',
    type: 'web_attack',
    severity: 'critical',
    pattern: /('|(--)|;|union.*select|insert.*into|delete.*from|drop.*table)/i,
    description: 'SQL Injection attempt detected'
  },
  {
    id: 'command_injection',
    type: 'web_attack',
    severity: 'critical',
    pattern: /(\||;|`|\$\(|\$\{|&&|\|\|).*?(cat|ls|rm|wget|curl|bash|sh|cmd)/i,
    description: 'Command Injection attempt detected'
  },
  {
    id: 'path_traversal',
    type: 'web_attack',
    severity: 'high',
    pattern: /\.\.[\/\\]|\.\.%2[fF]|%2e%2e[\/\\]/,
    description: 'Path Traversal attack detected'
  },
  {
    id: 'xxe_attack',
    type: 'web_attack',
    severity: 'high',
    pattern: /<!ENTITY.*SYSTEM|<!DOCTYPE.*\[/i,
    description: 'XML External Entity (XXE) attack detected'
  },
  {
    id: 'ldap_injection',
    type: 'web_attack',
    severity: 'high',
    pattern: /[\(\)\*\|&=!]/,
    description: 'LDAP Injection attempt detected'
  }
];

// URL threat patterns
const THREAT_PATTERNS = [
  {
    id: 'phishing_banking',
    type: 'phishing',
    severity: 'critical',
    pattern: /(?:verify|update|confirm|secure).*(?:bank|account|paypal|payment)/i,
    description: 'Banking phishing pattern detected'
  },
  {
    id: 'phishing_credentials',
    type: 'phishing',
    severity: 'high',
    pattern: /(?:login|signin|account).*(?:suspended|locked|verify|confirm)/i,
    description: 'Credential phishing pattern detected'
  },
  {
    id: 'phishing_urgency',
    type: 'phishing',
    severity: 'high',
    pattern: /(?:urgent|immediate|action.*required|expires.*today)/i,
    description: 'Urgency-based phishing tactic detected'
  },
  {
    id: 'phishing_prize',
    type: 'phishing',
    severity: 'medium',
    pattern: /(?:won|winner|prize|reward|congratulations|claim.*now)/i,
    description: 'Prize scam pattern detected'
  },
  {
    id: 'malware_download',
    type: 'malware',
    severity: 'critical',
    pattern: /(?:download|install|update).*(?:codec|player|flash|java|update)/i,
    description: 'Malicious download pattern detected'
  },
  {
    id: 'suspicious_script',
    type: 'suspicious',
    severity: 'medium',
    pattern: /(?:javascript|script|eval|document\.write)/i,
    description: 'Suspicious script injection detected'
  },
  {
    id: 'typosquatting',
    type: 'phishing',
    severity: 'high',
    pattern: /(?:g00gle|micr0soft|amaz0n|faceb00k|paypa1|app1e)/i,
    description: 'Typosquatting attempt detected'
  },
  {
    id: 'crypto_mining',
    type: 'malware',
    severity: 'high',
    pattern: /(?:coinhive|crypto-loot|deepminer|mining.*pool)/i,
    description: 'Cryptocurrency mining detected'
  }
];

// Suspicious URL indicators
const SUSPICIOUS_INDICATORS = [
  {
    id: 'ip_address',
    check: (url) => /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname),
    score: 20,
    description: 'Uses IP address instead of domain name'
  },
  {
    id: 'excessive_subdomains',
    check: (url) => url.hostname.split('.').length > 4,
    score: 15,
    description: 'Excessive number of subdomains'
  },
  {
    id: 'non_standard_port',
    check: (url) => url.port && !['80', '443', '8080', ''].includes(url.port),
    score: 10,
    description: 'Non-standard port number'
  },
  {
    id: 'url_shortener',
    check: (url) => {
      const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
      return shorteners.some(s => url.hostname.includes(s));
    },
    score: 15,
    description: 'URL shortener (may hide destination)'
  },
  {
    id: 'long_url',
    check: (url) => url.href.length > 200,
    score: 10,
    description: 'Unusually long URL (possible obfuscation)'
  },
  {
    id: 'credential_symbol',
    check: (url) => url.href.includes('@'),
    score: 25,
    description: '@ symbol in URL (credential phishing)'
  },
  {
    id: 'http_only',
    check: (url) => url.protocol === 'http:',
    score: 5,
    description: 'No SSL/TLS encryption (HTTP only)'
  },
  {
    id: 'suspicious_tld',
    check: (url) => {
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work'];
      return suspiciousTLDs.some(tld => url.hostname.endsWith(tld));
    },
    score: 15,
    description: 'Suspicious top-level domain'
  },
  {
    id: 'excessive_hyphens',
    check: (url) => (url.hostname.match(/-/g) || []).length > 2,
    score: 10,
    description: 'Excessive hyphens in domain'
  },
  {
    id: 'numeric_domain',
    check: (url) => /\d{4,}/.test(url.hostname),
    score: 10,
    description: 'Domain contains long numeric sequences'
  }
];

// Safe domain whitelist
const SAFE_DOMAINS = new Set([
  'google.com',
  'youtube.com',
  'facebook.com',
  'amazon.com',
  'wikipedia.org',
  'twitter.com',
  'linkedin.com',
  'microsoft.com',
  'apple.com',
  'github.com',
  'stackoverflow.com',
  'reddit.com',
  'netflix.com',
  'instagram.com',
  'paypal.com'
]);

// Content threat patterns
const CONTENT_PATTERNS = [
  {
    id: 'malicious_keywords',
    keywords: ['malware', 'trojan', 'ransomware', 'keylogger', 'backdoor', 'exploit'],
    weight: 15
  },
  {
    id: 'scam_keywords',
    keywords: ['free money', 'get rich', 'work from home', 'guaranteed income', 'easy money'],
    weight: 10
  },
  {
    id: 'phishing_keywords',
    keywords: ['verify account', 'suspended account', 'urgent action', 'click here now', 'limited time'],
    weight: 15
  }
];

// ==================== THREAT INTELLIGENCE CLASS ====================

class ThreatIntelligence {
  constructor() {
    this.threatDatabase = new Map();
    this.reputationCache = new Map();
    this.updateInterval = 3600000; // 1 hour
    this.initializeThreatDatabase();
  }

  initializeThreatDatabase() {
    // Initialize with known threats
    MALICIOUS_DOMAINS.forEach(domain => {
      this.threatDatabase.set(domain, {
        type: 'malware',
        severity: 'critical',
        source: 'Internal Database',
        added: Date.now()
      });
    });
  }

  async checkReputation(url) {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    // Check cache first
    if (this.reputationCache.has(domain)) {
      const cached = this.reputationCache.get(domain);
      if (Date.now() - cached.timestamp < this.updateInterval) {
        return cached.data;
      }
    }

    // Check if domain is in threat database
    if (this.threatDatabase.has(domain)) {
      const threat = this.threatDatabase.get(domain);
      return {
        safe: false,
        threat: threat,
        source: 'Threat Database'
      };
    }

    // Check if domain is whitelisted
    const baseDomain = this.extractBaseDomain(domain);
    if (SAFE_DOMAINS.has(baseDomain)) {
      return {
        safe: true,
        whitelisted: true,
        source: 'Whitelist'
      };
    }

    // Simulate API check (in production, call real APIs)
    const apiResult = await this.simulateAPICheck(domain);
    
    // Cache result
    this.reputationCache.set(domain, {
      data: apiResult,
      timestamp: Date.now()
    });

    return apiResult;
  }

  extractBaseDomain(domain) {
    const parts = domain.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return domain;
  }

  async simulateAPICheck(domain) {
    // Simulate checking against external threat intelligence APIs:
    // - Google Safe Browsing
    // - VirusTotal
    // - PhishTank
    // - URLhaus
    // - OpenPhish

    return new Promise((resolve) => {
      setTimeout(() => {
        const isThreat = Math.random() < 0.08; // 8% threat rate for demo
        
        if (isThreat) {
          const types = ['malware', 'phishing', 'suspicious'];
          const severities = ['critical', 'high', 'medium'];
          resolve({
            safe: false,
            threat: {
              type: types[Math.floor(Math.random() * types.length)],
              severity: severities[Math.floor(Math.random() * severities.length)],
              source: 'Threat Intelligence API'
            }
          });
        } else {
          resolve({
            safe: true,
            source: 'Threat Intelligence API'
          });
        }
      }, 150);
    });
  }

  addToThreatDatabase(domain, threatInfo) {
    this.threatDatabase.set(domain.toLowerCase(), {
      ...threatInfo,
      added: Date.now()
    });
    this.reputationCache.delete(domain.toLowerCase());
  }

  removeFromThreatDatabase(domain) {
    this.threatDatabase.delete(domain.toLowerCase());
    this.reputationCache.delete(domain.toLowerCase());
  }

  getThreatDatabaseSize() {
    return this.threatDatabase.size;
  }

  clearCache() {
    this.reputationCache.clear();
  }
}

// ==================== DNS FILTER CLASS ====================

class DNSFilter {
  constructor() {
    this.blockedDomains = new Set(MALICIOUS_DOMAINS);
    this.allowedDomains = new Set(SAFE_DOMAINS);
    this.dnsCache = new Map();
    this.blockingEnabled = true;
  }

  isDomainBlocked(domain) {
    const lowerDomain = domain.toLowerCase();
    
    // Check direct match
    if (this.blockedDomains.has(lowerDomain)) {
      return {
        blocked: true,
        reason: 'Domain in blocklist'
      };
    }

    // Check if it's a subdomain of blocked domain
    for (const blocked of this.blockedDomains) {
      if (lowerDomain.endsWith(`.${blocked}`)) {
        return {
          blocked: true,
          reason: `Subdomain of blocked domain: ${blocked}`
        };
      }
    }

    // Check if it's in allowed list
    const baseDomain = this.extractBaseDomain(lowerDomain);
    if (this.allowedDomains.has(baseDomain)) {
      return {
        blocked: false,
        reason: 'Domain in allowlist'
      };
    }

    return { blocked: false };
  }

  extractBaseDomain(domain) {
    const parts = domain.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return domain;
  }

  blockDomain(domain, reason = 'User blocked') {
    this.blockedDomains.add(domain.toLowerCase());
    this.dnsCache.delete(domain.toLowerCase());
  }

  unblockDomain(domain) {
    this.blockedDomains.delete(domain.toLowerCase());
    this.dnsCache.delete(domain.toLowerCase());
  }

  addToAllowlist(domain) {
    this.allowedDomains.add(domain.toLowerCase());
    this.blockedDomains.delete(domain.toLowerCase());
  }

  removeFromAllowlist(domain) {
    this.allowedDomains.delete(domain.toLowerCase());
  }

  getBlockedDomains() {
    return Array.from(this.blockedDomains);
  }

  getAllowedDomains() {
    return Array.from(this.allowedDomains);
  }

  setBlockingEnabled(enabled) {
    this.blockingEnabled = enabled;
  }
}

// ==================== CONTENT ANALYZER CLASS ====================

class ContentAnalyzer {
  constructor() {
    this.analysisCache = new Map();
  }

  async analyzeContent(url, content = null) {
    // In production, fetch and analyze actual page content
    // For now, analyze URL and simulate content analysis
    
    const urlObj = new URL(url);
    const analysis = {
      suspiciousContent: [],
      contentRisk: 0,
      scannedAt: Date.now()
    };

    // Analyze URL for content patterns
    CONTENT_PATTERNS.forEach(pattern => {
      const urlLower = url.toLowerCase();
      const matchCount = pattern.keywords.filter(kw => urlLower.includes(kw)).length;
      
      if (matchCount > 0) {
        analysis.suspiciousContent.push({
          type: pattern.id,
          matches: matchCount,
          weight: pattern.weight
        });
        analysis.contentRisk += pattern.weight * matchCount;
      }
    });

    return analysis;
  }

  clearCache() {
    this.analysisCache.clear();
  }
}

// ==================== SSL/TLS VALIDATOR CLASS ====================

class SSLValidator {
  constructor() {
    this.validationCache = new Map();
  }

  async validateSSL(url) {
    const urlObj = new URL(url);
    
    // Check if HTTPS
    if (urlObj.protocol !== 'https:') {
      return {
        valid: false,
        issues: ['No SSL/TLS encryption (HTTP only)'],
        severity: 'medium'
      };
    }

    // In production, check:
    // - Certificate validity
    // - Certificate chain
    // - Revocation status
    // - Certificate transparency logs
    // - Cipher strength

    // Simulate SSL validation
    return this.simulateSSLCheck(url);
  }

  async simulateSSLCheck(url) {
    return new Promise((resolve) => {
      setTimeout(() => {
        const hasIssue = Math.random() < 0.05; // 5% have SSL issues
        
        if (hasIssue) {
          const issues = [
            ['Self-signed certificate', 'high'],
            ['Expired certificate', 'critical'],
            ['Invalid certificate chain', 'high'],
            ['Weak cipher suite', 'medium'],
            ['Certificate mismatch', 'critical']
          ];
          
          const [issue, severity] = issues[Math.floor(Math.random() * issues.length)];
          
          resolve({
            valid: false,
            issues: [issue],
            severity: severity
          });
        } else {
          resolve({
            valid: true,
            issues: [],
            severity: 'none'
          });
        }
      }, 100);
    });
  }

  clearCache() {
    this.validationCache.clear();
  }
}

// ==================== ENHANCED WEB PROTECTION SERVICE ====================

class EnhancedWebProtectionService {
  constructor() {
    this.threatIntelligence = new ThreatIntelligence();
    this.dnsFilter = new DNSFilter();
    this.contentAnalyzer = new ContentAnalyzer();
    this.sslValidator = new SSLValidator();
    
    this.enabled = true;
    this.realTimeProtection = true;
    this.blockPhishing = true;
    this.blockMalware = true;
    this.requireHTTPS = false;
    
    this.scanHistory = [];
    this.maxHistorySize = 100;
    
    this.statistics = {
      totalScans: 0,
      threatsBlocked: 0,
      phishingBlocked: 0,
      malwareBlocked: 0,
      suspiciousBlocked: 0,
      sslIssuesDetected: 0,
      urlsAllowed: 0,
      downloadsBlocked: 0,
      attacksBlocked: 0,
      lastScan: null
    };

    this.initializeFromStorage();
  }

  initializeFromStorage() {
    try {
      const saved = localStorage.getItem('enhancedWebProtection_settings');
      if (saved) {
        const settings = JSON.parse(saved);
        this.enabled = settings.enabled ?? true;
        this.realTimeProtection = settings.realTimeProtection ?? true;
        this.blockPhishing = settings.blockPhishing ?? true;
        this.blockMalware = settings.blockMalware ?? true;
        this.requireHTTPS = settings.requireHTTPS ?? false;
      }

      const savedStats = localStorage.getItem('enhancedWebProtection_statistics');
      if (savedStats) {
        this.statistics = { ...this.statistics, ...JSON.parse(savedStats) };
      }

      const savedHistory = localStorage.getItem('enhancedWebProtection_history');
      if (savedHistory) {
        this.scanHistory = JSON.parse(savedHistory);
      }
    } catch (error) {
      console.error('Failed to load web protection settings:', error);
    }
  }

  saveToStorage() {
    try {
      const settings = {
        enabled: this.enabled,
        realTimeProtection: this.realTimeProtection,
        blockPhishing: this.blockPhishing,
        blockMalware: this.blockMalware,
        requireHTTPS: this.requireHTTPS
      };
      localStorage.setItem('enhancedWebProtection_settings', JSON.stringify(settings));
      localStorage.setItem('enhancedWebProtection_statistics', JSON.stringify(this.statistics));
      localStorage.setItem('enhancedWebProtection_history', JSON.stringify(this.scanHistory.slice(0, this.maxHistorySize)));
    } catch (error) {
      console.error('Failed to save web protection settings:', error);
    }
  }

  async scanURL(url) {
    if (!this.enabled) {
      return {
        url: url,
        safe: true,
        bypassed: true,
        message: 'Web protection is disabled'
      };
    }

    this.statistics.totalScans++;
    this.statistics.lastScan = Date.now();

    const scanResult = {
      url: url,
      scannedAt: Date.now(),
      threats: [],
      warnings: [],
      info: [],
      riskScore: 0,
      safe: true
    };

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      // 1. DNS Filter Check
      const dnsCheck = this.dnsFilter.isDomainBlocked(domain);
      if (dnsCheck.blocked) {
        scanResult.threats.push({
          type: 'blocked_domain',
          severity: 'critical',
          description: `Domain blocked: ${dnsCheck.reason}`,
          category: 'malware'
        });
        scanResult.riskScore += 100;
      }

      // 2. Threat Intelligence Check
      const reputationCheck = await this.threatIntelligence.checkReputation(url);
      if (!reputationCheck.safe && reputationCheck.threat) {
        scanResult.threats.push({
          type: reputationCheck.threat.type,
          severity: reputationCheck.threat.severity,
          description: `Threat detected by ${reputationCheck.source}`,
          category: reputationCheck.threat.type
        });
        scanResult.riskScore += this.getSeverityScore(reputationCheck.threat.severity);
      }

      // 3. Pattern Matching
      THREAT_PATTERNS.forEach(pattern => {
        if (pattern.pattern.test(url)) {
          scanResult.threats.push({
            type: pattern.type,
            severity: pattern.severity,
            description: pattern.description,
            category: pattern.type,
            patternId: pattern.id
          });
          scanResult.riskScore += this.getSeverityScore(pattern.severity);
        }
      });

      // 4. Suspicious Indicators
      const suspicionScore = this.checkSuspiciousIndicators(urlObj);
      scanResult.riskScore += suspicionScore.totalScore;
      suspicionScore.indicators.forEach(indicator => {
        scanResult.warnings.push({
          type: 'suspicious',
          severity: 'medium',
          description: indicator.description,
          score: indicator.score
        });
      });

      // 5. SSL/TLS Validation
      const sslCheck = await this.sslValidator.validateSSL(url);
      if (!sslCheck.valid) {
        sslCheck.issues.forEach(issue => {
          scanResult.warnings.push({
            type: 'ssl_issue',
            severity: sslCheck.severity,
            description: issue,
            category: 'ssl'
          });
          scanResult.riskScore += this.getSeverityScore(sslCheck.severity);
        });
        this.statistics.sslIssuesDetected++;
      }

      // 6. Content Analysis
      const contentAnalysis = await this.contentAnalyzer.analyzeContent(url);
      if (contentAnalysis.contentRisk > 0) {
        scanResult.warnings.push({
          type: 'suspicious_content',
          severity: 'medium',
          description: `Suspicious content patterns detected (risk: ${contentAnalysis.contentRisk})`,
          details: contentAnalysis.suspiciousContent
        });
        scanResult.riskScore += contentAnalysis.contentRisk;
      }

      // 7. HTTPS Requirement Check
      if (this.requireHTTPS && urlObj.protocol !== 'https:') {
        scanResult.warnings.push({
          type: 'no_https',
          severity: 'medium',
          description: 'HTTPS required but URL uses HTTP',
          category: 'ssl'
        });
        scanResult.riskScore += 15;
      }

      // Normalize risk score (0-100)
      scanResult.riskScore = Math.min(scanResult.riskScore, 100);

      // Determine if safe based on settings
      scanResult.safe = this.determineSafety(scanResult);

      // Update statistics
      if (!scanResult.safe) {
        this.statistics.threatsBlocked++;
        
        scanResult.threats.forEach(threat => {
          if (threat.category === 'phishing') {
            this.statistics.phishingBlocked++;
          } else if (threat.category === 'malware') {
            this.statistics.malwareBlocked++;
          } else {
            this.statistics.suspiciousBlocked++;
          }
        });
      } else {
        this.statistics.urlsAllowed++;
      }

      // Add to history
      this.addToHistory(scanResult);

      // Save to storage
      this.saveToStorage();

      return scanResult;

    } catch (error) {
      console.error('URL scan error:', error);
      return {
        url: url,
        safe: false,
        threats: [{
          type: 'error',
          severity: 'low',
          description: 'Invalid URL or scan error: ' + error.message
        }],
        scannedAt: Date.now(),
        riskScore: 30
      };
    }
  }

  checkSuspiciousIndicators(urlObj) {
    const indicators = [];
    let totalScore = 0;

    SUSPICIOUS_INDICATORS.forEach(indicator => {
      if (indicator.check(urlObj)) {
        indicators.push({
          id: indicator.id,
          description: indicator.description,
          score: indicator.score
        });
        totalScore += indicator.score;
      }
    });

    return { indicators, totalScore };
  }

  getSeverityScore(severity) {
    const scores = {
      critical: 100,
      high: 75,
      medium: 50,
      low: 25,
      none: 0
    };
    return scores[severity] || 25;
  }

  determineSafety(scanResult) {
    // Check critical threats
    const hasCriticalThreat = scanResult.threats.some(t => t.severity === 'critical');
    if (hasCriticalThreat) return false;

    // Check if phishing and phishing blocking enabled
    const hasPhishing = scanResult.threats.some(t => t.category === 'phishing');
    if (hasPhishing && this.blockPhishing) return false;

    // Check if malware and malware blocking enabled
    const hasMalware = scanResult.threats.some(t => t.category === 'malware');
    if (hasMalware && this.blockMalware) return false;

    // Check high risk score
    if (scanResult.riskScore >= 75) return false;

    return scanResult.threats.length === 0;
  }

  addToHistory(scanResult) {
    this.scanHistory.unshift({
      url: scanResult.url,
      scannedAt: scanResult.scannedAt,
      safe: scanResult.safe,
      riskScore: scanResult.riskScore,
      threatsCount: scanResult.threats.length,
      warningsCount: scanResult.warnings.length
    });

    // Keep only last 100 scans
    if (this.scanHistory.length > this.maxHistorySize) {
      this.scanHistory = this.scanHistory.slice(0, this.maxHistorySize);
    }
  }

  // ==================== DOMAIN MANAGEMENT ====================

  blockDomain(domain, reason = 'User blocked') {
    this.dnsFilter.blockDomain(domain, reason);
    this.threatIntelligence.addToThreatDatabase(domain, {
      type: 'blocked',
      severity: 'high',
      source: 'User',
      reason: reason
    });
    this.saveToStorage();
  }

  unblockDomain(domain) {
    this.dnsFilter.unblockDomain(domain);
    this.threatIntelligence.removeFromThreatDatabase(domain);
    this.saveToStorage();
  }

  addToAllowlist(domain) {
    this.dnsFilter.addToAllowlist(domain);
    this.saveToStorage();
  }

  removeFromAllowlist(domain) {
    this.dnsFilter.removeFromAllowlist(domain);
    this.saveToStorage();
  }

  getBlockedDomains() {
    return this.dnsFilter.getBlockedDomains();
  }

  getAllowedDomains() {
    return this.dnsFilter.getAllowedDomains();
  }

  // ==================== SETTINGS ====================

  setEnabled(enabled) {
    this.enabled = enabled;
    this.saveToStorage();
  }

  setRealTimeProtection(enabled) {
    this.realTimeProtection = enabled;
    this.saveToStorage();
  }

  setBlockPhishing(enabled) {
    this.blockPhishing = enabled;
    this.saveToStorage();
  }

  setBlockMalware(enabled) {
    this.blockMalware = enabled;
    this.saveToStorage();
  }

  setRequireHTTPS(enabled) {
    this.requireHTTPS = enabled;
    this.saveToStorage();
  }

  getSettings() {
    return {
      enabled: this.enabled,
      realTimeProtection: this.realTimeProtection,
      blockPhishing: this.blockPhishing,
      blockMalware: this.blockMalware,
      requireHTTPS: this.requireHTTPS
    };
  }

  // ==================== DOWNLOAD PROTECTION ====================

  /**
   * Scan download URL before downloading
   * @param {string} downloadUrl - URL of the file to download
   * @param {string} filename - Name of the file being downloaded
   * @returns {Object} Download scan result with safety assessment
   */
  async scanDownload(downloadUrl, filename = '') {
    if (!this.enabled) {
      return {
        safe: true,
        bypassed: true,
        message: 'Download protection is disabled'
      };
    }

    const result = {
      url: downloadUrl,
      filename: filename || this.extractFilenameFromUrl(downloadUrl),
      safe: true,
      threats: [],
      warnings: [],
      scannedAt: Date.now()
    };

    try {
      const urlObj = new URL(downloadUrl);
      const fileExtension = result.filename.toLowerCase().match(/\.[^.]+$/)?.[0] || '';

      // Check 1: Dangerous file extension
      if (DANGEROUS_FILE_EXTENSIONS.has(fileExtension)) {
        result.warnings.push({
          type: 'dangerous_extension',
          severity: 'high',
          description: `Potentially dangerous file type: ${fileExtension}`,
          recommendation: 'Scan file after download before executing'
        });
      }

      // Check 2: Domain reputation
      const domainCheck = this.dnsFilter.isDomainBlocked(urlObj.hostname);
      if (domainCheck.blocked) {
        result.safe = false;
        result.threats.push({
          type: 'blocked_domain',
          severity: 'critical',
          description: `Download from blocked domain: ${domainCheck.reason}`,
          recommendation: 'DO NOT DOWNLOAD - Known malicious source'
        });
        this.statistics.downloadsBlocked++;
      }

      // Check 3: Direct IP download (suspicious)
      if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
        result.warnings.push({
          type: 'ip_download',
          severity: 'medium',
          description: 'Download from IP address instead of domain',
          recommendation: 'Verify source before downloading'
        });
      }

      // Check 4: Non-HTTPS download
      if (urlObj.protocol === 'http:' && this.requireHTTPS) {
        result.warnings.push({
          type: 'insecure_download',
          severity: 'medium',
          description: 'Download over insecure HTTP connection',
          recommendation: 'File could be intercepted or modified'
        });
      }

      // Check 5: Suspicious filename patterns
      const suspiciousPatterns = [
        /crack|keygen|patch|activator/i,
        /setup.*exe.*\d{3,}/i,
        /invoice.*pdf.*\.exe/i,
        /document.*\.(scr|exe|bat)/i
      ];

      for (const pattern of suspiciousPatterns) {
        if (pattern.test(result.filename)) {
          result.warnings.push({
            type: 'suspicious_filename',
            severity: 'high',
            description: 'Filename matches malware distribution pattern',
            recommendation: 'Likely malware - avoid downloading'
          });
          break;
        }
      }

      // Update statistics
      this.statistics.totalScans++;
      if (!result.safe) {
        this.statistics.threatsBlocked++;
      }

      this.saveToStorage();

    } catch (error) {
      result.safe = false;
      result.threats.push({
        type: 'invalid_url',
        severity: 'high',
        description: 'Invalid download URL',
        recommendation: 'Cannot verify safety'
      });
    }

    return result;
  }

  /**
   * Extract filename from URL
   */
  extractFilenameFromUrl(url) {
    try {
      const urlObj = new URL(url);
      const pathname = urlObj.pathname;
      const filename = pathname.split('/').pop();
      return filename || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Check if file extension is dangerous
   */
  isDangerousFileType(filename) {
    const extension = filename.toLowerCase().match(/\.[^.]+$/)?.[0] || '';
    return DANGEROUS_FILE_EXTENSIONS.has(extension);
  }

  // ==================== WEB ATTACK DETECTION ====================

  /**
   * Detect web attacks in URL parameters
   * @param {string} url - URL to analyze for attack patterns
   * @returns {Object} Attack detection result
   */
  detectWebAttacks(url) {
    const result = {
      hasAttack: false,
      attacks: [],
      scannedAt: Date.now()
    };

    try {
      const urlObj = new URL(url);
      const fullUrl = urlObj.href;
      const params = urlObj.searchParams;

      // Check URL and parameters against attack patterns
      for (const pattern of WEB_ATTACK_PATTERNS) {
        // Check full URL
        if (pattern.pattern.test(fullUrl)) {
          result.hasAttack = true;
          result.attacks.push({
            type: pattern.type,
            id: pattern.id,
            severity: pattern.severity,
            description: pattern.description,
            location: 'url',
            recommendation: 'Block access - active attack detected'
          });
        }

        // Check each parameter
        for (const [key, value] of params) {
          if (pattern.pattern.test(value)) {
            result.hasAttack = true;
            result.attacks.push({
              type: pattern.type,
              id: pattern.id,
              severity: pattern.severity,
              description: pattern.description,
              location: `parameter: ${key}`,
              recommendation: 'Block access - active attack detected'
            });
          }
        }
      }

      if (result.hasAttack) {
        this.statistics.threatsBlocked++;
        this.statistics.totalScans++;
        this.saveToStorage();
      }

    } catch (error) {
      console.error('Web attack detection error:', error);
    }

    return result;
  }

  // ==================== STATISTICS ====================

  getStatistics() {
    return {
      ...this.statistics,
      blockedDomainsCount: this.dnsFilter.blockedDomains.size,
      allowedDomainsCount: this.dnsFilter.allowedDomains.size,
      threatDatabaseSize: this.threatIntelligence.getThreatDatabaseSize(),
      historySize: this.scanHistory.length
    };
  }

  getScanHistory() {
    return this.scanHistory;
  }

  clearScanHistory() {
    this.scanHistory = [];
    this.saveToStorage();
  }

  resetStatistics() {
    this.statistics = {
      totalScans: 0,
      threatsBlocked: 0,
      phishingBlocked: 0,
      malwareBlocked: 0,
      suspiciousBlocked: 0,
      sslIssuesDetected: 0,
      urlsAllowed: 0,
      lastScan: null
    };
    this.saveToStorage();
  }

  // ==================== CACHE MANAGEMENT ====================

  clearAllCaches() {
    this.threatIntelligence.clearCache();
    this.contentAnalyzer.clearCache();
    this.sslValidator.clearCache();
  }

  // ==================== EXPORT/IMPORT ====================

  exportSettings() {
    return {
      settings: this.getSettings(),
      blockedDomains: this.getBlockedDomains(),
      allowedDomains: this.getAllowedDomains(),
      statistics: this.statistics,
      exportedAt: Date.now()
    };
  }

  importSettings(data) {
    try {
      if (data.settings) {
        this.setEnabled(data.settings.enabled);
        this.setRealTimeProtection(data.settings.realTimeProtection);
        this.setBlockPhishing(data.settings.blockPhishing);
        this.setBlockMalware(data.settings.blockMalware);
        this.setRequireHTTPS(data.settings.requireHTTPS);
      }

      if (data.blockedDomains) {
        data.blockedDomains.forEach(domain => this.blockDomain(domain, 'Imported'));
      }

      if (data.allowedDomains) {
        data.allowedDomains.forEach(domain => this.addToAllowlist(domain));
      }

      this.saveToStorage();
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

// ==================== SINGLETON INSTANCE ====================

const enhancedWebProtection = new EnhancedWebProtectionService();

// ==================== EXPORTS ====================

export default enhancedWebProtection;

export {
  MALICIOUS_DOMAINS,
  THREAT_PATTERNS,
  SUSPICIOUS_INDICATORS,
  SAFE_DOMAINS,
  DANGEROUS_FILE_EXTENSIONS,
  WEB_ATTACK_PATTERNS,
  ThreatIntelligence,
  DNSFilter,
  ContentAnalyzer,
  SSLValidator
};
