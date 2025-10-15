// Web Protection Service
// Real-time URL scanning and malicious website blocking

class WebProtectionService {
  constructor() {
    this.blockedDomains = new Set();
    this.phishingPatterns = [];
    this.maliciousURLs = new Set();
    this.safeCache = new Map();
    this.isEnabled = true;
    this.stats = {
      blockedAttempts: 0,
      scannedURLs: 0,
      phishingDetected: 0,
      malwareDetected: 0
    };
    
    this.initializeBlacklists();
  }

  // Initialize known malicious patterns and domains
  initializeBlacklists() {
    // Known malicious domains (sample list)
    this.maliciousURLs = new Set([
      'malware-site.com',
      'phishing-bank.com',
      'fake-paypal.com',
      'virus-download.com',
      'scam-lottery.com',
      'fake-antivirus.com',
      'trojan-host.com',
      'malicious-ad.net'
    ]);

    // Phishing patterns
    this.phishingPatterns = [
      /paypal.*verify/i,
      /bank.*account.*suspended/i,
      /urgent.*action.*required/i,
      /confirm.*identity/i,
      /security.*alert/i,
      /prize.*winner/i,
      /claim.*reward/i,
      /update.*payment.*info/i,
      /account.*locked/i,
      /verify.*credentials/i
    ];
  }

  // Scan URL for threats
  async scanURL(url) {
    this.stats.scannedURLs++;

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      
      // Check cache first
      if (this.safeCache.has(url)) {
        const cached = this.safeCache.get(url);
        if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
          return cached.result;
        }
      }

      const threats = [];

      // 1. Check against known malicious domains
      if (this.isMaliciousDomain(domain)) {
        threats.push({
          type: 'malware',
          severity: 'critical',
          description: 'Known malicious domain detected',
          domain: domain
        });
        this.stats.malwareDetected++;
      }

      // 2. Check for phishing patterns
      const phishingCheck = this.checkPhishingPatterns(url);
      if (phishingCheck.isPhishing) {
        threats.push({
          type: 'phishing',
          severity: 'high',
          description: phishingCheck.reason,
          domain: domain
        });
        this.stats.phishingDetected++;
      }

      // 3. Check suspicious patterns
      const suspiciousCheck = this.checkSuspiciousPatterns(urlObj);
      if (suspiciousCheck.isSuspicious) {
        threats.push({
          type: 'suspicious',
          severity: 'medium',
          description: suspiciousCheck.reason,
          domain: domain
        });
      }

      // 4. Check URL reputation (simulated)
      const reputationCheck = await this.checkURLReputation(url);
      if (reputationCheck.isBlacklisted) {
        threats.push({
          type: 'blacklisted',
          severity: 'high',
          description: 'URL found in threat database',
          source: reputationCheck.source
        });
      }

      const result = {
        url: url,
        safe: threats.length === 0,
        threats: threats,
        scannedAt: new Date().toISOString(),
        riskScore: this.calculateRiskScore(threats)
      };

      // Cache result
      this.safeCache.set(url, {
        result: result,
        timestamp: Date.now()
      });

      if (threats.length > 0) {
        this.stats.blockedAttempts++;
      }

      return result;

    } catch (error) {
      console.error('URL scan error:', error);
      return {
        url: url,
        safe: false,
        threats: [{
          type: 'error',
          severity: 'low',
          description: 'Invalid URL or scan error'
        }],
        scannedAt: new Date().toISOString(),
        riskScore: 30
      };
    }
  }

  // Check if domain is known to be malicious
  isMaliciousDomain(domain) {
    // Direct match
    if (this.maliciousURLs.has(domain)) {
      return true;
    }

    // Check subdomains
    for (const malicious of this.maliciousURLs) {
      if (domain.endsWith(`.${malicious}`)) {
        return true;
      }
    }

    return false;
  }

  // Check for phishing patterns
  checkPhishingPatterns(url) {
    for (const pattern of this.phishingPatterns) {
      if (pattern.test(url)) {
        return {
          isPhishing: true,
          reason: `Phishing pattern detected: ${pattern.source}`
        };
      }
    }
    return { isPhishing: false };
  }

  // Check suspicious URL patterns
  checkSuspiciousPatterns(urlObj) {
    const suspicious = [];

    // IP address instead of domain
    if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname)) {
      suspicious.push('Uses IP address instead of domain name');
    }

    // Excessive subdomains
    if (urlObj.hostname.split('.').length > 4) {
      suspicious.push('Excessive number of subdomains');
    }

    // Non-standard port for HTTP/HTTPS
    if (urlObj.port && !['80', '443', ''].includes(urlObj.port)) {
      suspicious.push('Non-standard port number');
    }

    // URL shortener (potential redirect)
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
    if (shorteners.some(s => urlObj.hostname.includes(s))) {
      suspicious.push('URL shortener detected (may hide destination)');
    }

    // Very long URL (obfuscation)
    if (urlObj.href.length > 200) {
      suspicious.push('Unusually long URL (possible obfuscation)');
    }

    // @ symbol in URL (credential stealing)
    if (urlObj.href.includes('@')) {
      suspicious.push('@ symbol in URL (possible credential phishing)');
    }

    if (suspicious.length > 0) {
      return {
        isSuspicious: true,
        reason: suspicious.join(', ')
      };
    }

    return { isSuspicious: false };
  }

  // Simulate checking against threat databases
  async checkURLReputation(url) {
    // In production, this would call APIs like:
    // - Google Safe Browsing API
    // - VirusTotal API
    // - PhishTank API
    // - OpenPhish
    
    return new Promise((resolve) => {
      setTimeout(() => {
        // Simulate threat database check
        const isBlacklisted = Math.random() < 0.05; // 5% chance for demo
        resolve({
          isBlacklisted: isBlacklisted,
          source: isBlacklisted ? 'Threat Intelligence Database' : null
        });
      }, 100);
    });
  }

  // Calculate risk score (0-100)
  calculateRiskScore(threats) {
    if (threats.length === 0) return 0;

    const severityScores = {
      critical: 100,
      high: 75,
      medium: 50,
      low: 25
    };

    const maxScore = Math.max(...threats.map(t => severityScores[t.severity] || 25));
    return maxScore;
  }

  // Block a specific domain
  blockDomain(domain) {
    this.maliciousURLs.add(domain.toLowerCase());
    this.safeCache.clear(); // Clear cache when blocklist changes
  }

  // Unblock a domain
  unblockDomain(domain) {
    this.maliciousURLs.delete(domain.toLowerCase());
    this.safeCache.clear();
  }

  // Get protection stats
  getStats() {
    return {
      ...this.stats,
      blockedDomains: this.maliciousURLs.size,
      cachedResults: this.safeCache.size
    };
  }

  // Enable/disable protection
  setEnabled(enabled) {
    this.isEnabled = enabled;
  }

  // Clear cache
  clearCache() {
    this.safeCache.clear();
  }

  // Reset stats
  resetStats() {
    this.stats = {
      blockedAttempts: 0,
      scannedURLs: 0,
      phishingDetected: 0,
      malwareDetected: 0
    };
  }
}

// Singleton instance
const webProtection = new WebProtectionService();

export default webProtection;
