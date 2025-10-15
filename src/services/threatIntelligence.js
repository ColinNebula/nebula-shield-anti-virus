// Real Threat Intelligence Service
// Integrates with multiple threat intelligence sources for real-time detection

import axios from 'axios';

class ThreatIntelligenceService {
  constructor() {
    // API keys (set in .env file)
    this.virusTotalKey = process.env.REACT_APP_VIRUSTOTAL_API_KEY;
    this.abuseIPDBKey = process.env.REACT_APP_ABUSEIPDB_API_KEY;
    this.urlScanKey = process.env.REACT_APP_URLSCAN_API_KEY;
    
    // Cache for API responses (1 hour TTL)
    this.cache = new Map();
    this.cacheTTL = 3600000; // 1 hour
    
    // Known threat databases (real public lists)
    this.phishingDomains = new Set();
    this.malwareDomains = new Set();
    this.loadPublicThreatLists();
  }

  // Load public threat intelligence feeds
  async loadPublicThreatLists() {
    try {
      // PhishTank public feed (real data)
      const phishTankResponse = await axios.get(
        'https://data.phishtank.com/data/online-valid.json',
        { timeout: 10000 }
      );
      
      if (phishTankResponse.data) {
        phishTankResponse.data.forEach(entry => {
          try {
            const domain = new URL(entry.url).hostname;
            this.phishingDomains.add(domain.toLowerCase());
          } catch (e) {
            // Invalid URL, skip
          }
        });
      }
    } catch (error) {
      console.warn('Could not load PhishTank feed (using fallback)');
      // Use fallback known phishing domains
      this.loadFallbackPhishingDomains();
    }

    try {
      // URLhaus malware URL feed (real data)
      const urlhausResponse = await axios.get(
        'https://urlhaus.abuse.ch/downloads/csv_recent/',
        { timeout: 10000 }
      );
      
      if (urlhausResponse.data) {
        const lines = urlhausResponse.data.split('\n');
        lines.forEach(line => {
          if (line.startsWith('#') || !line.trim()) return;
          
          const parts = line.split(',');
          if (parts.length > 2) {
            try {
              const url = parts[2].replace(/"/g, '');
              const domain = new URL(url).hostname;
              this.malwareDomains.add(domain.toLowerCase());
            } catch (e) {
              // Invalid URL, skip
            }
          }
        });
      }
    } catch (error) {
      console.warn('Could not load URLhaus feed (using fallback)');
      this.loadFallbackMalwareDomains();
    }
  }

  // Fallback phishing domains (known bad actors)
  loadFallbackPhishingDomains() {
    const fallbackDomains = [
      'paypa1.com', 'paypal-verify.com', 'paypal-secure.com',
      'amazon-security.com', 'apple-verify.com', 'microsoft-support.com',
      'google-account.com', 'netflix-billing.com', 'facebook-security.com',
      'instagram-verify.com', 'twitter-security.com', 'linkedin-verify.com'
    ];
    
    fallbackDomains.forEach(domain => this.phishingDomains.add(domain));
  }

  loadFallbackMalwareDomains() {
    const fallbackDomains = [
      'malware-download.com', 'virus-host.net', 'trojan-server.com'
    ];
    
    fallbackDomains.forEach(domain => this.malwareDomains.add(domain));
  }

  // Check URL with VirusTotal (REAL API)
  async checkURLWithVirusTotal(url) {
    if (!this.virusTotalKey || this.virusTotalKey === 'demo-key') {
      return null; // No API key available
    }

    const cacheKey = `vt_url_${url}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      // Encode URL for VirusTotal API
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
      
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/urls/${urlId}`,
        {
          headers: { 'x-apikey': this.virusTotalKey },
          timeout: 10000
        }
      );

      const result = {
        malicious: response.data.data.attributes.last_analysis_stats.malicious || 0,
        suspicious: response.data.data.attributes.last_analysis_stats.suspicious || 0,
        harmless: response.data.data.attributes.last_analysis_stats.harmless || 0,
        undetected: response.data.data.attributes.last_analysis_stats.undetected || 0,
        reputation: response.data.data.attributes.reputation || 0
      };

      this.addToCache(cacheKey, result);
      return result;
    } catch (error) {
      if (error.response?.status === 404) {
        // URL not in VirusTotal database, submit for analysis
        await this.submitURLToVirusTotal(url);
      }
      return null;
    }
  }

  // Submit URL to VirusTotal for analysis
  async submitURLToVirusTotal(url) {
    if (!this.virusTotalKey || this.virusTotalKey === 'demo-key') {
      return;
    }

    try {
      await axios.post(
        'https://www.virustotal.com/api/v3/urls',
        new URLSearchParams({ url }),
        {
          headers: { 
            'x-apikey': this.virusTotalKey,
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );
    } catch (error) {
      // Submission failed, continue without it
    }
  }

  // Check IP address with AbuseIPDB (REAL API)
  async checkIPWithAbuseIPDB(ip) {
    if (!this.abuseIPDBKey) {
      return null;
    }

    const cacheKey = `abuse_ip_${ip}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await axios.get(
        `https://api.abuseipdb.com/api/v2/check`,
        {
          params: { ipAddress: ip, maxAgeInDays: 90 },
          headers: { 
            'Key': this.abuseIPDBKey,
            'Accept': 'application/json'
          },
          timeout: 10000
        }
      );

      const result = {
        abuseConfidenceScore: response.data.data.abuseConfidenceScore,
        totalReports: response.data.data.totalReports,
        isWhitelisted: response.data.data.isWhitelisted
      };

      this.addToCache(cacheKey, result);
      return result;
    } catch (error) {
      return null;
    }
  }

  // Check domain against loaded threat feeds
  checkDomainReputation(domain) {
    if (!domain) return { threat: false };

    const domainLower = domain.toLowerCase();

    // Check against phishing domains
    if (this.phishingDomains.has(domainLower)) {
      return {
        threat: true,
        type: 'phishing',
        source: 'PhishTank Feed',
        confidence: 'high'
      };
    }

    // Check against malware domains
    if (this.malwareDomains.has(domainLower)) {
      return {
        threat: true,
        type: 'malware',
        source: 'URLhaus Feed',
        confidence: 'high'
      };
    }

    // Check for typosquatting of popular domains
    const typosquatResult = this.detectTyposquatting(domainLower);
    if (typosquatResult.isTyrosquat) {
      return {
        threat: true,
        type: 'typosquatting',
        source: 'Pattern Analysis',
        confidence: 'medium',
        targetDomain: typosquatResult.targetDomain
      };
    }

    return { threat: false };
  }

  // Detect typosquatting (real algorithm)
  detectTyposquatting(domain) {
    const popularDomains = [
      'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
      'apple.com', 'paypal.com', 'netflix.com', 'instagram.com',
      'twitter.com', 'linkedin.com', 'ebay.com', 'walmart.com'
    ];

    for (const popular of popularDomains) {
      // Levenshtein distance check
      const distance = this.levenshteinDistance(domain, popular);
      
      if (distance > 0 && distance <= 2) {
        return {
          isTyrosquat: true,
          targetDomain: popular,
          distance: distance
        };
      }

      // Homoglyph detection (visual similarity)
      if (this.hasHomoglyphs(domain, popular)) {
        return {
          isTyrosquat: true,
          targetDomain: popular,
          type: 'homoglyph'
        };
      }

      // Subdomain impersonation (e.g., paypal.com.evil.com)
      if (domain.includes(popular) && domain !== popular) {
        return {
          isTyrosquat: true,
          targetDomain: popular,
          type: 'subdomain'
        };
      }
    }

    return { isTyrosquat: false };
  }

  // Calculate Levenshtein distance (edit distance)
  levenshteinDistance(str1, str2) {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  // Detect homoglyph attacks
  hasHomoglyphs(str1, str2) {
    const homoglyphs = {
      'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å'],
      'e': ['е', 'è', 'é', 'ê', 'ë'],
      'i': ['і', 'ì', 'í', 'î', 'ï'],
      'o': ['о', 'ò', 'ó', 'ô', 'õ', 'ö'],
      'u': ['ù', 'ú', 'û', 'ü'],
      'c': ['с', 'ç'],
      'p': ['р'],
      'x': ['х'],
      'y': ['у', 'ý', 'ÿ']
    };

    // Normalize strings
    let normalized1 = str1.toLowerCase();
    let normalized2 = str2.toLowerCase();

    // Replace homoglyphs with base characters
    for (const [base, glyphs] of Object.entries(homoglyphs)) {
      glyphs.forEach(glyph => {
        normalized1 = normalized1.replace(new RegExp(glyph, 'g'), base);
      });
    }

    return normalized1 === normalized2 && str1 !== str2;
  }

  // Cache management
  getFromCache(key) {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.data;
    }
    this.cache.delete(key);
    return null;
  }

  addToCache(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  clearCache() {
    this.cache.clear();
  }

  // Get statistics
  getStats() {
    return {
      phishingDomains: this.phishingDomains.size,
      malwareDomains: this.malwareDomains.size,
      cachedEntries: this.cache.size,
      hasVirusTotalAPI: !!(this.virusTotalKey && this.virusTotalKey !== 'demo-key'),
      hasAbuseIPDBAPI: !!this.abuseIPDBKey,
      hasURLScanAPI: !!this.urlScanKey
    };
  }
}

// Singleton instance
const threatIntelligence = new ThreatIntelligenceService();

export default threatIntelligence;
