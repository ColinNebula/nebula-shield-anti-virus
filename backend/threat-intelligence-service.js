/**
 * Live Threat Intelligence Feed Service
 * Integrates multiple threat intelligence sources
 */

const https = require('https');
const fs = require('fs').promises;
const path = require('path');

class ThreatIntelligenceService {
  constructor() {
    this.cache = new Map();
    this.cacheExpiry = 3600000; // 1 hour
    this.feedsPath = path.join(__dirname, 'threat-feeds.json');
    this.feeds = null;
    this.lastUpdate = 0;
    this.updateInterval = 3600000; // Update every hour
  }

  /**
   * Initialize threat feeds
   */
  async initialize() {
    try {
      const data = await fs.readFile(this.feedsPath, 'utf8');
      this.feeds = JSON.parse(data);
      this.lastUpdate = Date.now();
      console.log('✅ Threat Intelligence Service initialized');
    } catch (error) {
      console.log('Creating default threat feeds...');
      await this.createDefaultFeeds();
    }
  }

  /**
   * Check if IP is malicious
   */
  async checkIpReputation(ip) {
    await this.ensureInitialized();

    // Check cache first
    const cached = this.getFromCache(`ip:${ip}`);
    if (cached) return cached;

    const result = {
      ip,
      isThreat: false,
      threatLevel: 'clean',
      sources: [],
      tags: [],
      confidence: 0
    };

    // Check against known malicious IPs
    if (this.feeds && this.feeds.maliciousIps) {
      const match = this.feeds.maliciousIps.find(entry => entry.ip === ip);
      if (match) {
        result.isThreat = true;
        result.threatLevel = match.severity || 'high';
        result.sources.push(match.source || 'local-database');
        result.tags.push(...(match.tags || []));
        result.confidence = 90;
      }
    }

    // Check against abuse.ch URLhaus
    try {
      const urlhausResult = await this.checkUrlhaus(ip);
      if (urlhausResult.isThreat) {
        result.isThreat = true;
        result.threatLevel = this.escalateThreatLevel(result.threatLevel, urlhausResult.threatLevel);
        result.sources.push('URLhaus');
        result.tags.push(...urlhausResult.tags);
        result.confidence = Math.max(result.confidence, urlhausResult.confidence);
      }
    } catch (error) {
      console.warn('URLhaus check failed:', error.message);
    }

    // Check against AbuseIPDB (if configured)
    try {
      const abuseIpDbResult = await this.checkAbuseIPDB(ip);
      if (abuseIpDbResult.isThreat) {
        result.isThreat = true;
        result.threatLevel = this.escalateThreatLevel(result.threatLevel, abuseIpDbResult.threatLevel);
        result.sources.push('AbuseIPDB');
        result.confidence = Math.max(result.confidence, abuseIpDbResult.confidence);
      }
    } catch (error) {
      console.warn('AbuseIPDB check failed:', error.message);
    }

    this.saveToCache(`ip:${ip}`, result);
    return result;
  }

  /**
   * Check if URL is malicious
   */
  async checkUrlReputation(url) {
    await this.ensureInitialized();

    // Check cache first
    const cached = this.getFromCache(`url:${url}`);
    if (cached) return cached;

    const result = {
      url,
      isThreat: false,
      threatLevel: 'clean',
      sources: [],
      tags: [],
      confidence: 0
    };

    // Extract domain from URL
    const domain = this.extractDomain(url);

    // Check against known malicious domains
    if (this.feeds && this.feeds.maliciousDomains) {
      const match = this.feeds.maliciousDomains.find(entry => 
        entry.domain === domain || url.includes(entry.domain)
      );
      
      if (match) {
        result.isThreat = true;
        result.threatLevel = match.severity || 'high';
        result.sources.push(match.source || 'local-database');
        result.tags.push(...(match.tags || []));
        result.confidence = 85;
      }
    }

    // Check against phishing patterns
    const phishingCheck = this.checkPhishingPatterns(url);
    if (phishingCheck.suspicious) {
      result.isThreat = true;
      result.threatLevel = 'medium';
      result.sources.push('heuristic-analysis');
      result.tags.push('phishing-indicators');
      result.confidence = Math.max(result.confidence, phishingCheck.confidence);
    }

    this.saveToCache(`url:${url}`, result);
    return result;
  }

  /**
   * Check if domain is malicious
   */
  async checkDomainReputation(domain) {
    await this.ensureInitialized();

    const cached = this.getFromCache(`domain:${domain}`);
    if (cached) return cached;

    const result = {
      domain,
      isThreat: false,
      threatLevel: 'clean',
      sources: [],
      tags: [],
      confidence: 0
    };

    // Check against known malicious domains
    if (this.feeds && this.feeds.maliciousDomains) {
      const match = this.feeds.maliciousDomains.find(entry => 
        entry.domain === domain || entry.domain.endsWith(`.${domain}`)
      );
      
      if (match) {
        result.isThreat = true;
        result.threatLevel = match.severity || 'high';
        result.sources.push(match.source || 'local-database');
        result.tags.push(...(match.tags || []));
        result.confidence = 90;
      }
    }

    // Check domain age and characteristics
    const domainAnalysis = this.analyzeDomain(domain);
    if (domainAnalysis.suspicious) {
      result.isThreat = true;
      result.threatLevel = this.escalateThreatLevel(result.threatLevel, 'low');
      result.sources.push('domain-analysis');
      result.tags.push(...domainAnalysis.indicators);
      result.confidence = Math.max(result.confidence, domainAnalysis.confidence);
    }

    this.saveToCache(`domain:${domain}`, result);
    return result;
  }

  /**
   * Check file hash reputation
   */
  async checkHashReputation(hash) {
    await this.ensureInitialized();

    const cached = this.getFromCache(`hash:${hash}`);
    if (cached) return cached;

    const result = {
      hash,
      isThreat: false,
      threatLevel: 'clean',
      sources: [],
      malwareFamily: null,
      confidence: 0
    };

    // Check against known malware hashes
    if (this.feeds && this.feeds.malwareHashes) {
      const match = this.feeds.malwareHashes.find(entry => 
        entry.md5 === hash || entry.sha256 === hash || entry.sha1 === hash
      );
      
      if (match) {
        result.isThreat = true;
        result.threatLevel = match.severity || 'critical';
        result.sources.push(match.source || 'MalwareBazaar');
        result.malwareFamily = match.family;
        result.confidence = 95;
      }
    }

    // Check MalwareBazaar API
    try {
      const bazaarResult = await this.checkMalwareBazaar(hash);
      if (bazaarResult.isThreat) {
        result.isThreat = true;
        result.threatLevel = bazaarResult.threatLevel;
        result.sources.push('MalwareBazaar-API');
        result.malwareFamily = bazaarResult.family;
        result.confidence = Math.max(result.confidence, bazaarResult.confidence);
      }
    } catch (error) {
      console.warn('MalwareBazaar check failed:', error.message);
    }

    this.saveToCache(`hash:${hash}`, result);
    return result;
  }

  /**
   * Check URLhaus (abuse.ch)
   */
  async checkUrlhaus(ip) {
    return new Promise((resolve, reject) => {
      const postData = JSON.stringify({ host: ip });

      const options = {
        hostname: 'urlhaus-api.abuse.ch',
        path: '/v1/host/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': postData.length
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            
            if (parsed.query_status === 'ok' && parsed.urlhaus_reference) {
              resolve({
                isThreat: true,
                threatLevel: 'high',
                tags: ['malware-distribution', 'urlhaus'],
                confidence: 85
              });
            } else {
              resolve({
                isThreat: false,
                threatLevel: 'clean',
                tags: [],
                confidence: 0
              });
            }
          } catch (error) {
            reject(error);
          }
        });
      });

      req.on('error', reject);
      req.write(postData);
      req.end();

      // Timeout after 5 seconds
      setTimeout(() => {
        req.destroy();
        reject(new Error('URLhaus API timeout'));
      }, 5000);
    });
  }

  /**
   * Check MalwareBazaar (abuse.ch)
   */
  async checkMalwareBazaar(hash) {
    return new Promise((resolve, reject) => {
      const postData = JSON.stringify({ 
        query: 'get_info',
        hash: hash
      });

      const options = {
        hostname: 'mb-api.abuse.ch',
        path: '/api/v1/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': postData.length
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            
            if (parsed.query_status === 'ok' && parsed.data && parsed.data.length > 0) {
              const sample = parsed.data[0];
              resolve({
                isThreat: true,
                threatLevel: 'critical',
                family: sample.signature,
                confidence: 95
              });
            } else {
              resolve({
                isThreat: false,
                threatLevel: 'clean',
                confidence: 0
              });
            }
          } catch (error) {
            reject(error);
          }
        });
      });

      req.on('error', reject);
      req.write(postData);
      req.end();

      // Timeout after 5 seconds
      setTimeout(() => {
        req.destroy();
        reject(new Error('MalwareBazaar API timeout'));
      }, 5000);
    });
  }

  /**
   * Check AbuseIPDB
   */
  async checkAbuseIPDB(ip) {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    
    if (!apiKey) {
      throw new Error('AbuseIPDB API key not configured');
    }

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.abuseipdb.com',
        path: `/api/v2/check?ipAddress=${ip}`,
        method: 'GET',
        headers: {
          'Key': apiKey,
          'Accept': 'application/json'
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            
            if (parsed.data && parsed.data.abuseConfidenceScore > 50) {
              resolve({
                isThreat: true,
                threatLevel: parsed.data.abuseConfidenceScore > 80 ? 'critical' : 'high',
                confidence: parsed.data.abuseConfidenceScore
              });
            } else {
              resolve({
                isThreat: false,
                threatLevel: 'clean',
                confidence: 100 - (parsed.data?.abuseConfidenceScore || 0)
              });
            }
          } catch (error) {
            reject(error);
          }
        });
      });

      req.on('error', reject);
      req.end();

      // Timeout after 5 seconds
      setTimeout(() => {
        req.destroy();
        reject(new Error('AbuseIPDB API timeout'));
      }, 5000);
    });
  }

  /**
   * Check phishing patterns
   */
  checkPhishingPatterns(url) {
    const indicators = [];
    let suspicionScore = 0;

    // Check for IP address in URL
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      indicators.push('IP address in URL');
      suspicionScore += 30;
    }

    // Check for suspicious TLDs
    const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    if (suspiciousTlds.some(tld => url.includes(tld))) {
      indicators.push('Suspicious TLD');
      suspicionScore += 25;
    }

    // Check for homograph attack (lookalike characters)
    if (/[а-яА-Я]/.test(url)) { // Cyrillic characters
      indicators.push('Homograph attack');
      suspicionScore += 40;
    }

    // Check for excessive subdomains
    const subdomains = url.split('//')[1]?.split('/')[0]?.split('.') || [];
    if (subdomains.length > 4) {
      indicators.push('Excessive subdomains');
      suspicionScore += 20;
    }

    // Check for suspicious keywords
    const phishingKeywords = /paypal|verify|account|secure|update|login|signin|banking/i;
    if (phishingKeywords.test(url) && !url.includes('paypal.com')) {
      indicators.push('Phishing keywords');
      suspicionScore += 35;
    }

    // Check for URL shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co'];
    if (shorteners.some(s => url.includes(s))) {
      indicators.push('URL shortener');
      suspicionScore += 15;
    }

    return {
      suspicious: suspicionScore >= 30,
      confidence: Math.min(suspicionScore, 85),
      indicators
    };
  }

  /**
   * Analyze domain characteristics
   */
  analyzeDomain(domain) {
    const indicators = [];
    let suspicionScore = 0;

    // Check domain length
    if (domain.length > 30) {
      indicators.push('Unusually long domain');
      suspicionScore += 15;
    }

    // Check for excessive hyphens
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount > 2) {
      indicators.push('Excessive hyphens');
      suspicionScore += 20;
    }

    // Check for numbers in domain
    if (/\d{3,}/.test(domain)) {
      indicators.push('Multiple numbers in domain');
      suspicionScore += 15;
    }

    // Check for brand impersonation
    const brands = ['microsoft', 'google', 'amazon', 'paypal', 'facebook', 'apple'];
    const domainLower = domain.toLowerCase();
    brands.forEach(brand => {
      if (domainLower.includes(brand) && !domainLower.endsWith(`${brand}.com`)) {
        indicators.push(`Possible ${brand} impersonation`);
        suspicionScore += 40;
      }
    });

    return {
      suspicious: suspicionScore >= 30,
      confidence: Math.min(suspicionScore, 70),
      indicators
    };
  }

  /**
   * Extract domain from URL
   */
  extractDomain(url) {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `http://${url}`);
      return urlObj.hostname;
    } catch (error) {
      return url.split('/')[0].split(':')[0];
    }
  }

  /**
   * Escalate threat level
   */
  escalateThreatLevel(current, newLevel) {
    const levels = ['clean', 'low', 'medium', 'high', 'critical'];
    const currentIndex = levels.indexOf(current);
    const newIndex = levels.indexOf(newLevel);
    return levels[Math.max(currentIndex, newIndex)];
  }

  /**
   * Get from cache
   */
  getFromCache(key) {
    const cached = this.cache.get(key);
    
    if (cached && Date.now() - cached.timestamp < this.cacheExpiry) {
      return cached.data;
    }
    
    this.cache.delete(key);
    return null;
  }

  /**
   * Save to cache
   */
  saveToCache(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
    
    // Limit cache size
    if (this.cache.size > 1000) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  /**
   * Ensure initialized
   */
  async ensureInitialized() {
    if (!this.feeds || Date.now() - this.lastUpdate > this.updateInterval) {
      await this.initialize();
    }
  }

  /**
   * Create default feeds
   */
  async createDefaultFeeds() {
    const defaultFeeds = {
      version: '1.0.0',
      lastUpdated: new Date().toISOString(),
      maliciousIps: [],
      maliciousDomains: [],
      malwareHashes: []
    };

    await fs.writeFile(this.feedsPath, JSON.stringify(defaultFeeds, null, 2));
    this.feeds = defaultFeeds;
  }

  /**
   * Update threat feeds from remote sources
   */
  async updateFeeds() {
    console.log('🔄 Updating threat intelligence feeds...');
    
    try {
      // This would fetch from real threat intelligence sources
      // For now, we'll use the local database
      await this.initialize();
      
      console.log('✅ Threat feeds updated');
      return true;
    } catch (error) {
      console.error('❌ Failed to update threat feeds:', error);
      return false;
    }
  }
}

module.exports = new ThreatIntelligenceService();
