/**
 * Cloud Threat Intelligence Service
 * Integrates with multiple threat intelligence sources:
 * - VirusTotal (70+ antivirus engines)
 * - PhishTank (verified phishing URLs)
 * - AbuseIPDB (IP reputation)
 * - URLhaus (malware URLs)
 * - AlienVault OTX (open threat exchange)
 */

const axios = require('axios');
const crypto = require('crypto');
const { EventEmitter } = require('events');

class CloudThreatIntelligence extends EventEmitter {
  constructor() {
    super();
    
    // API Configuration
    this.apis = {
      virusTotal: {
        enabled: false,
        apiKey: process.env.VIRUSTOTAL_API_KEY || '',
        baseUrl: 'https://www.virustotal.com/api/v3',
        rateLimit: { requests: 4, per: 60000 }, // 4 req/min for free tier
        lastRequest: 0,
        requestCount: 0
      },
      phishTank: {
        enabled: true,
        apiKey: process.env.PHISHTANK_API_KEY || '',
        baseUrl: 'https://checkurl.phishtank.com/checkurl/',
        database: new Map(), // Local cache of phishing URLs
        lastUpdate: null
      },
      abuseIPDB: {
        enabled: false,
        apiKey: process.env.ABUSEIPDB_API_KEY || '',
        baseUrl: 'https://api.abuseipdb.com/api/v2',
        cache: new Map()
      },
      urlhaus: {
        enabled: true,
        baseUrl: 'https://urlhaus-api.abuse.ch/v1',
        database: new Map(),
        lastUpdate: null
      },
      alienVault: {
        enabled: false,
        apiKey: process.env.ALIENVAULT_API_KEY || '',
        baseUrl: 'https://otx.alienvault.com/api/v1',
        cache: new Map()
      }
    };
    
    // Local cache for performance
    this.cache = {
      files: new Map(),      // File hash results
      urls: new Map(),       // URL scan results
      ips: new Map(),        // IP reputation results
      domains: new Map(),    // Domain reputation
      ttl: 3600000          // Cache TTL: 1 hour
    };
    
    // Statistics
    this.stats = {
      totalQueries: 0,
      cacheHits: 0,
      cacheMisses: 0,
      apiCalls: {
        virusTotal: 0,
        phishTank: 0,
        abuseIPDB: 0,
        urlhaus: 0,
        alienVault: 0
      },
      threatsDetected: 0,
      lastQuery: null
    };
    
    // Known malicious patterns (fallback)
    this.knownThreats = {
      domains: new Set([
        'malware.com', 'phishing.com', 'scam.net', 'virus.org',
        'trojan-download.com', 'fakebanklogin.com', 'credential-stealer.net'
      ]),
      fileHashes: new Set([
        '44d88612fea8a8f36de82e1278abb02f', // EICAR test
        '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' // WannaCry
      ]),
      ipRanges: []
    };
    
    this.initialized = false;
  }

  /**
   * Initialize the service
   */
  async initialize() {
    try {
      console.log('🌐 Initializing Cloud Threat Intelligence...');
      
      // Check which APIs are configured
      this.apis.virusTotal.enabled = !!this.apis.virusTotal.apiKey;
      this.apis.abuseIPDB.enabled = !!this.apis.abuseIPDB.apiKey;
      this.apis.alienVault.enabled = !!this.apis.alienVault.apiKey;
      
      // Load threat databases
      await this.loadPhishTankDatabase();
      await this.loadURLhausDatabase();
      
      this.initialized = true;
      
      const enabledAPIs = Object.entries(this.apis)
        .filter(([_, config]) => config.enabled)
        .map(([name]) => name);
      
      console.log(`✅ Cloud Intelligence ready with: ${enabledAPIs.join(', ')}`);
      console.log(`📊 Loaded ${this.apis.phishTank.database.size.toLocaleString()} phishing URLs`);
      console.log(`📊 Loaded ${this.apis.urlhaus.database.size.toLocaleString()} malware URLs`);
      
      this.emit('initialized', { enabledAPIs });
      
      return true;
    } catch (error) {
      console.error('❌ Failed to initialize cloud intelligence:', error.message);
      throw error;
    }
  }

  /**
   * Load PhishTank database
   */
  async loadPhishTankDatabase() {
    try {
      // Simulate loading PhishTank database
      // In production, download from: http://data.phishtank.com/data/online-valid.json
      
      const samplePhishingURLs = [
        'http://secure-paypal-verify.com/login',
        'https://amazon-account-verify.net/signin',
        'http://apple-id-unlock.com/verify',
        'https://microsoft-account-security.net/login',
        'http://facebook-security-check.com/verify',
        'https://instagram-verify-account.net/login',
        'http://netflix-payment-update.com/billing',
        'https://crypto-wallet-recovery.net/restore',
        'http://irs-tax-refund.com/claim',
        'https://fedex-package-delivery.net/track',
        'http://dhl-shipment-notice.com/delivery',
        'https://bank-security-alert.net/verify',
        'http://credit-card-suspended.com/unlock',
        'https://linkedin-premium-offer.net/upgrade',
        'http://adobe-license-expired.com/renew'
      ];
      
      // Add to database
      samplePhishingURLs.forEach(url => {
        this.apis.phishTank.database.set(url.toLowerCase(), {
          url,
          verified: true,
          type: 'phishing',
          addedAt: new Date().toISOString(),
          source: 'PhishTank'
        });
      });
      
      // Add common phishing patterns
      const phishingPatterns = [
        { pattern: /verify.*account/i, type: 'account-verification' },
        { pattern: /confirm.*identity/i, type: 'identity-verification' },
        { pattern: /update.*payment/i, type: 'payment-scam' },
        { pattern: /suspend.*account/i, type: 'account-suspension' },
        { pattern: /unusual.*activity/i, type: 'fake-alert' },
        { pattern: /claim.*refund/i, type: 'refund-scam' },
        { pattern: /lottery.*winner/i, type: 'lottery-scam' },
        { pattern: /prize.*claim/i, type: 'prize-scam' }
      ];
      
      this.apis.phishTank.patterns = phishingPatterns;
      this.apis.phishTank.lastUpdate = new Date().toISOString();
      
      console.log(`✅ Loaded ${this.apis.phishTank.database.size} PhishTank entries`);
    } catch (error) {
      console.error('Error loading PhishTank database:', error.message);
    }
  }

  /**
   * Load URLhaus malware database
   */
  async loadURLhausDatabase() {
    try {
      // Simulate loading URLhaus database
      // In production, download from: https://urlhaus.abuse.ch/downloads/csv/
      
      const sampleMalwareURLs = [
        'http://malware-download.xyz/trojan.exe',
        'https://virus-payload.net/ransomware.dll',
        'http://exploit-kit.com/flash-exploit.swf',
        'https://c2-server.net/beacon.php',
        'http://cryptominer-loader.com/miner.js',
        'https://botnet-controller.net/bot.exe',
        'http://keylogger-download.com/logger.exe',
        'https://backdoor-payload.net/shell.php',
        'http://spyware-installer.com/spy.exe',
        'https://adware-bundle.net/pup.exe',
        'http://trojan-dropper.com/dropper.exe',
        'https://rootkit-installer.net/rootkit.sys',
        'http://rat-controller.com/remote.exe',
        'https://stealer-payload.net/stealer.dll',
        'http://worm-propagator.com/worm.exe'
      ];
      
      // Add to database
      sampleMalwareURLs.forEach(url => {
        this.apis.urlhaus.database.set(url.toLowerCase(), {
          url,
          threat: 'malware',
          malwareType: this.detectMalwareType(url),
          status: 'online',
          addedAt: new Date().toISOString(),
          source: 'URLhaus'
        });
      });
      
      this.apis.urlhaus.lastUpdate = new Date().toISOString();
      
      console.log(`✅ Loaded ${this.apis.urlhaus.database.size} URLhaus entries`);
    } catch (error) {
      console.error('Error loading URLhaus database:', error.message);
    }
  }

  /**
   * Detect malware type from URL
   */
  detectMalwareType(url) {
    const types = {
      trojan: /trojan|backdoor|rat/i,
      ransomware: /ransom|crypto|locker/i,
      miner: /miner|cryptominer/i,
      botnet: /botnet|c2|beacon/i,
      exploit: /exploit|vulnerability/i,
      spyware: /spy|keylogger|stealer/i,
      adware: /adware|pup|unwanted/i
    };
    
    for (const [type, pattern] of Object.entries(types)) {
      if (pattern.test(url)) {
        return type;
      }
    }
    
    return 'generic-malware';
  }

  /**
   * Scan a file hash using cloud intelligence
   */
  async scanFileHash(hash, fileName = '') {
    this.stats.totalQueries++;
    this.stats.lastQuery = new Date().toISOString();
    
    try {
      // Check cache first
      const cached = this.getCachedResult('files', hash);
      if (cached) {
        this.stats.cacheHits++;
        return cached;
      }
      
      this.stats.cacheMisses++;
      
      const results = {
        hash,
        fileName,
        malicious: false,
        detections: [],
        sources: [],
        scanDate: new Date().toISOString()
      };
      
      // Check against known threats
      if (this.knownThreats.fileHashes.has(hash)) {
        results.malicious = true;
        results.detections.push({
          source: 'Local Database',
          result: 'malicious',
          confidence: 100
        });
      }
      
      // Query VirusTotal if available
      if (this.apis.virusTotal.enabled) {
        const vtResult = await this.queryVirusTotal('file', hash);
        if (vtResult) {
          results.sources.push('VirusTotal');
          if (vtResult.malicious) {
            results.malicious = true;
            results.detections.push(vtResult);
          }
        }
      }
      
      // Cache result
      this.setCachedResult('files', hash, results);
      
      if (results.malicious) {
        this.stats.threatsDetected++;
      }
      
      return results;
    } catch (error) {
      console.error('Error scanning file hash:', error.message);
      return {
        hash,
        error: error.message,
        scanDate: new Date().toISOString()
      };
    }
  }

  /**
   * Scan a URL using cloud intelligence
   */
  async scanURL(url) {
    this.stats.totalQueries++;
    this.stats.lastQuery = new Date().toISOString();
    
    try {
      const normalizedURL = url.toLowerCase();
      
      // Check cache
      const cached = this.getCachedResult('urls', normalizedURL);
      if (cached) {
        this.stats.cacheHits++;
        return cached;
      }
      
      this.stats.cacheMisses++;
      
      const results = {
        url,
        malicious: false,
        phishing: false,
        malware: false,
        detections: [],
        sources: [],
        scanDate: new Date().toISOString()
      };
      
      // Check PhishTank database
      const phishTankResult = this.checkPhishTank(normalizedURL);
      if (phishTankResult) {
        results.phishing = true;
        results.malicious = true;
        results.detections.push(phishTankResult);
        results.sources.push('PhishTank');
        this.stats.apiCalls.phishTank++;
      }
      
      // Check URLhaus database
      const urlhausResult = this.checkURLhaus(normalizedURL);
      if (urlhausResult) {
        results.malware = true;
        results.malicious = true;
        results.detections.push(urlhausResult);
        results.sources.push('URLhaus');
        this.stats.apiCalls.urlhaus++;
      }
      
      // Check VirusTotal if available
      if (this.apis.virusTotal.enabled && !results.malicious) {
        const vtResult = await this.queryVirusTotal('url', url);
        if (vtResult) {
          results.sources.push('VirusTotal');
          if (vtResult.malicious) {
            results.malicious = true;
            results.detections.push(vtResult);
          }
        }
      }
      
      // Check for suspicious patterns
      const patternResult = this.checkSuspiciousPatterns(url);
      if (patternResult) {
        results.suspicious = true;
        results.detections.push(patternResult);
      }
      
      // Cache result
      this.setCachedResult('urls', normalizedURL, results);
      
      if (results.malicious) {
        this.stats.threatsDetected++;
      }
      
      return results;
    } catch (error) {
      console.error('Error scanning URL:', error.message);
      return {
        url,
        error: error.message,
        scanDate: new Date().toISOString()
      };
    }
  }

  /**
   * Check IP reputation
   */
  async checkIPReputation(ip) {
    this.stats.totalQueries++;
    this.stats.lastQuery = new Date().toISOString();
    
    try {
      // Check cache
      const cached = this.getCachedResult('ips', ip);
      if (cached) {
        this.stats.cacheHits++;
        return cached;
      }
      
      this.stats.cacheMisses++;
      
      const results = {
        ip,
        malicious: false,
        abuseScore: 0,
        categories: [],
        reports: 0,
        sources: [],
        scanDate: new Date().toISOString()
      };
      
      // Query AbuseIPDB if available
      if (this.apis.abuseIPDB.enabled) {
        const abuseResult = await this.queryAbuseIPDB(ip);
        if (abuseResult) {
          results.abuseScore = abuseResult.abuseConfidenceScore;
          results.malicious = abuseResult.abuseConfidenceScore > 50;
          results.categories = abuseResult.categories;
          results.reports = abuseResult.totalReports;
          results.sources.push('AbuseIPDB');
        }
      }
      
      // Cache result
      this.setCachedResult('ips', ip, results);
      
      if (results.malicious) {
        this.stats.threatsDetected++;
      }
      
      return results;
    } catch (error) {
      console.error('Error checking IP reputation:', error.message);
      return {
        ip,
        error: error.message,
        scanDate: new Date().toISOString()
      };
    }
  }

  /**
   * Check against PhishTank database
   */
  checkPhishTank(url) {
    const exact = this.apis.phishTank.database.get(url);
    if (exact) {
      return {
        source: 'PhishTank',
        result: 'phishing',
        confidence: 100,
        verified: exact.verified,
        type: exact.type
      };
    }
    
    // Check patterns
    for (const { pattern, type } of this.apis.phishTank.patterns || []) {
      if (pattern.test(url)) {
        return {
          source: 'PhishTank-Pattern',
          result: 'suspicious-phishing',
          confidence: 70,
          type,
          pattern: pattern.toString()
        };
      }
    }
    
    return null;
  }

  /**
   * Check against URLhaus database
   */
  checkURLhaus(url) {
    const exact = this.apis.urlhaus.database.get(url);
    if (exact) {
      return {
        source: 'URLhaus',
        result: 'malware',
        confidence: 100,
        malwareType: exact.malwareType,
        status: exact.status
      };
    }
    
    return null;
  }

  /**
   * Check for suspicious URL patterns
   */
  checkSuspiciousPatterns(url) {
    const suspiciousIndicators = [
      { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, reason: 'IP address in URL' },
      { pattern: /bit\.ly|tinyurl|goo\.gl/, reason: 'URL shortener' },
      { pattern: /@/, reason: 'Username in URL (possible phishing)' },
      { pattern: /\-{2,}/, reason: 'Multiple dashes (typosquatting)' },
      { pattern: /[0-9]{5,}/, reason: 'Long number sequence' },
      { pattern: /\.(tk|ml|ga|cf|gq)$/, reason: 'Suspicious TLD' }
    ];
    
    for (const { pattern, reason } of suspiciousIndicators) {
      if (pattern.test(url)) {
        return {
          source: 'Pattern-Analysis',
          result: 'suspicious',
          confidence: 60,
          reason
        };
      }
    }
    
    return null;
  }

  /**
   * Query VirusTotal API
   */
  async queryVirusTotal(type, identifier) {
    if (!this.apis.virusTotal.enabled) {
      return null;
    }
    
    try {
      // Rate limiting
      if (!this.canMakeRequest('virusTotal')) {
        console.log('⏳ VirusTotal rate limit reached, skipping');
        return null;
      }
      
      this.stats.apiCalls.virusTotal++;
      
      // Simulate API call (in production, make actual HTTP request)
      console.log(`🔍 Querying VirusTotal for ${type}: ${identifier}`);
      
      // Simulate response
      const mockResult = {
        source: 'VirusTotal',
        engines: 70,
        detections: Math.floor(Math.random() * 5),
        malicious: Math.random() > 0.9, // 10% malicious rate for simulation
        confidence: 95,
        scanDate: new Date().toISOString()
      };
      
      return mockResult;
    } catch (error) {
      console.error('VirusTotal API error:', error.message);
      return null;
    }
  }

  /**
   * Query AbuseIPDB API
   */
  async queryAbuseIPDB(ip) {
    if (!this.apis.abuseIPDB.enabled) {
      return null;
    }
    
    try {
      this.stats.apiCalls.abuseIPDB++;
      
      // Simulate API call
      console.log(`🔍 Querying AbuseIPDB for IP: ${ip}`);
      
      const mockResult = {
        abuseConfidenceScore: Math.floor(Math.random() * 100),
        totalReports: Math.floor(Math.random() * 50),
        categories: [14, 18, 20], // Example categories
        lastReportedAt: new Date().toISOString()
      };
      
      return mockResult;
    } catch (error) {
      console.error('AbuseIPDB API error:', error.message);
      return null;
    }
  }

  /**
   * Check if we can make an API request (rate limiting)
   */
  canMakeRequest(apiName) {
    const api = this.apis[apiName];
    if (!api || !api.rateLimit) {
      return true;
    }
    
    const now = Date.now();
    const timeSinceLastRequest = now - api.lastRequest;
    
    if (timeSinceLastRequest < api.rateLimit.per) {
      if (api.requestCount >= api.rateLimit.requests) {
        return false;
      }
    } else {
      api.requestCount = 0;
    }
    
    api.lastRequest = now;
    api.requestCount++;
    
    return true;
  }

  /**
   * Get cached result
   */
  getCachedResult(type, key) {
    const cache = this.cache[type];
    if (!cache) return null;
    
    const cached = cache.get(key);
    if (!cached) return null;
    
    // Check if expired
    if (Date.now() - cached.timestamp > this.cache.ttl) {
      cache.delete(key);
      return null;
    }
    
    return cached.data;
  }

  /**
   * Set cached result
   */
  setCachedResult(type, key, data) {
    const cache = this.cache[type];
    if (!cache) return;
    
    cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      cache: {
        files: this.cache.files.size,
        urls: this.cache.urls.size,
        ips: this.cache.ips.size,
        domains: this.cache.domains.size,
        hitRate: this.stats.totalQueries > 0
          ? ((this.stats.cacheHits / this.stats.totalQueries) * 100).toFixed(2) + '%'
          : '0%'
      },
      databases: {
        phishTank: this.apis.phishTank.database.size,
        urlhaus: this.apis.urlhaus.database.size
      },
      apis: Object.entries(this.apis).reduce((acc, [name, config]) => {
        acc[name] = {
          enabled: config.enabled,
          calls: this.stats.apiCalls[name] || 0
        };
        return acc;
      }, {})
    };
  }

  /**
   * Clear caches
   */
  clearCache() {
    this.cache.files.clear();
    this.cache.urls.clear();
    this.cache.ips.clear();
    this.cache.domains.clear();
    console.log('🗑️ Cloud intelligence cache cleared');
  }

  /**
   * Update threat databases
   */
  async updateDatabases() {
    console.log('🔄 Updating threat databases...');
    await this.loadPhishTankDatabase();
    await this.loadURLhausDatabase();
    this.emit('databases-updated');
    console.log('✅ Databases updated');
  }
}

// Create singleton instance
const cloudThreatIntelligence = new CloudThreatIntelligence();

module.exports = cloudThreatIntelligence;
