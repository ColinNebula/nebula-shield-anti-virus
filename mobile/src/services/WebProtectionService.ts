/**
 * Web Protection Service
 * Checks URLs against known malicious sites and phishing databases
 * Works on both iOS and Android
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';

export interface URLCheckResult {
  isSafe: boolean;
  threatType?: 'malware' | 'phishing' | 'spam' | 'suspicious';
  threatLevel?: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
  blockedReason?: string;
}

export interface ThreatDatabase {
  malware: string[];
  phishing: string[];
  spam: string[];
  lastUpdated: string;
}

class WebProtectionServiceClass {
  private threatDatabase: ThreatDatabase = {
    malware: [],
    phishing: [],
    spam: [],
    lastUpdated: new Date().toISOString(),
  };

  private dangerousPatterns = [
    /.*\.(exe|scr|bat|cmd|vbs|js)$/i, // Executable extensions
    /.*password.*reset.*/i,
    /.*account.*suspended.*/i,
    /.*verify.*account.*/i,
    /.*urgent.*action.*required.*/i,
    /.*click.*here.*claim.*/i,
    /.*congratulations.*won.*/i,
  ];

  constructor() {
    this.loadThreatDatabase();
    this.initializeBasicThreats();
  }

  /**
   * Initialize with common known threats
   */
  private initializeBasicThreats() {
    // Common malware distribution sites
    this.threatDatabase.malware = [
      'malware-site.com',
      'virus-download.net',
      'fake-download.org',
    ];

    // Common phishing domains
    this.threatDatabase.phishing = [
      'paypal-verify.com',
      'apple-id-verify.com',
      'amazon-account-verify.com',
      'google-account-recovery.com',
      'microsoft-account-help.com',
      'secure-banking-update.com',
    ];

    // Spam/scam sites
    this.threatDatabase.spam = [
      'free-money-now.com',
      'win-iphone-today.com',
      'congratulations-winner.com',
    ];
  }

  /**
   * Load threat database from storage
   */
  private async loadThreatDatabase() {
    try {
      const stored = await AsyncStorage.getItem('threat_database');
      if (stored) {
        this.threatDatabase = JSON.parse(stored);
      }
    } catch (error) {
      console.error('Error loading threat database:', error);
    }
  }

  /**
   * Save threat database to storage
   */
  private async saveThreatDatabase() {
    try {
      await AsyncStorage.setItem('threat_database', JSON.stringify(this.threatDatabase));
    } catch (error) {
      console.error('Error saving threat database:', error);
    }
  }

  /**
   * Check if a URL is safe
   */
  async checkURL(url: string): Promise<URLCheckResult> {
    try {
      const cleanURL = this.normalizeURL(url);
      const domain = this.extractDomain(cleanURL);

      // Check against local threat database
      if (this.threatDatabase.malware.includes(domain)) {
        return {
          isSafe: false,
          threatType: 'malware',
          threatLevel: 'critical',
          description: 'This site is known to distribute malware',
          blockedReason: 'Domain found in malware database',
        };
      }

      if (this.threatDatabase.phishing.includes(domain)) {
        return {
          isSafe: false,
          threatType: 'phishing',
          threatLevel: 'high',
          description: 'This site is a known phishing attempt',
          blockedReason: 'Domain found in phishing database',
        };
      }

      if (this.threatDatabase.spam.includes(domain)) {
        return {
          isSafe: false,
          threatType: 'spam',
          threatLevel: 'medium',
          description: 'This site is known for spam/scams',
          blockedReason: 'Domain found in spam database',
        };
      }

      // Check for suspicious patterns
      const suspiciousPattern = this.checkSuspiciousPatterns(url);
      if (suspiciousPattern) {
        return {
          isSafe: false,
          threatType: 'suspicious',
          threatLevel: 'medium',
          description: suspiciousPattern,
          blockedReason: 'URL matches suspicious pattern',
        };
      }

      // Check for typosquatting of popular domains
      const typosquatting = this.checkTyposquatting(domain);
      if (typosquatting) {
        return {
          isSafe: false,
          threatType: 'phishing',
          threatLevel: 'high',
          description: `This domain looks similar to ${typosquatting} but is not the official site`,
          blockedReason: 'Possible typosquatting detected',
        };
      }

      return {
        isSafe: true,
      };
    } catch (error) {
      console.error('Error checking URL:', error);
      return {
        isSafe: true, // Fail open rather than blocking everything
      };
    }
  }

  /**
   * Normalize URL for comparison
   */
  private normalizeURL(url: string): string {
    try {
      // Add protocol if missing
      if (!url.match(/^https?:\/\//i)) {
        url = 'https://' + url;
      }
      return url.toLowerCase().trim();
    } catch (error) {
      return url.toLowerCase().trim();
    }
  }

  /**
   * Extract domain from URL
   */
  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch (error) {
      // If URL parsing fails, try to extract domain manually
      const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\?]+)/i);
      return match ? match[1] : url;
    }
  }

  /**
   * Check for suspicious URL patterns
   */
  private checkSuspiciousPatterns(url: string): string | null {
    for (const pattern of this.dangerousPatterns) {
      if (pattern.test(url)) {
        return `URL contains suspicious pattern: ${pattern.source}`;
      }
    }

    // Check for unusual character usage
    if (url.includes('@') || url.includes('%40')) {
      return 'URL contains @ symbol, often used in phishing attempts';
    }

    // Check for IP addresses instead of domain names
    if (url.match(/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) {
      return 'URL uses IP address instead of domain name (suspicious)';
    }

    // Check for excessive subdomains
    const domain = this.extractDomain(url);
    const parts = domain.split('.');
    if (parts.length > 4) {
      return 'URL has excessive subdomains (suspicious)';
    }

    return null;
  }

  /**
   * Check for typosquatting of popular domains
   */
  private checkTyposquatting(domain: string): string | null {
    const popularDomains = [
      'paypal.com',
      'apple.com',
      'google.com',
      'microsoft.com',
      'amazon.com',
      'facebook.com',
      'instagram.com',
      'twitter.com',
      'linkedin.com',
      'netflix.com',
      'chase.com',
      'bankofamerica.com',
    ];

    for (const trustedDomain of popularDomains) {
      // Check if domain is similar but not exact match
      if (domain !== trustedDomain) {
        const similarity = this.calculateSimilarity(domain, trustedDomain);
        if (similarity > 0.7) {
          // More than 70% similar
          return trustedDomain;
        }
      }
    }

    return null;
  }

  /**
   * Calculate similarity between two strings (Levenshtein distance)
   */
  private calculateSimilarity(str1: string, str2: string): number {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) {
      return 1.0;
    }
    
    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  /**
   * Calculate Levenshtein distance
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

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
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Add domain to threat database
   */
  async addThreat(domain: string, type: 'malware' | 'phishing' | 'spam') {
    if (!this.threatDatabase[type].includes(domain)) {
      this.threatDatabase[type].push(domain);
      this.threatDatabase.lastUpdated = new Date().toISOString();
      await this.saveThreatDatabase();
    }
  }

  /**
   * Remove domain from threat database
   */
  async removeThreat(domain: string, type: 'malware' | 'phishing' | 'spam') {
    const index = this.threatDatabase[type].indexOf(domain);
    if (index > -1) {
      this.threatDatabase[type].splice(index, 1);
      this.threatDatabase.lastUpdated = new Date().toISOString();
      await this.saveThreatDatabase();
    }
  }

  /**
   * Get threat database statistics
   */
  getStats() {
    return {
      malwareCount: this.threatDatabase.malware.length,
      phishingCount: this.threatDatabase.phishing.length,
      spamCount: this.threatDatabase.spam.length,
      totalThreats:
        this.threatDatabase.malware.length +
        this.threatDatabase.phishing.length +
        this.threatDatabase.spam.length,
      lastUpdated: this.threatDatabase.lastUpdated,
    };
  }

  /**
   * Update threat database from remote server
   */
  async updateThreatDatabase(apiUrl?: string): Promise<boolean> {
    try {
      // In production, fetch from actual threat intelligence API
      // For now, this is a placeholder
      const url = apiUrl || 'https://api.nebulashield.com/threats';
      
      // Uncomment when backend threat API is ready
      // const response = await axios.get(url);
      // if (response.data) {
      //   this.threatDatabase = {
      //     ...response.data,
      //     lastUpdated: new Date().toISOString(),
      //   };
      //   await this.saveThreatDatabase();
      //   return true;
      // }
      
      return false;
    } catch (error) {
      console.error('Error updating threat database:', error);
      return false;
    }
  }
}

export const WebProtectionService = new WebProtectionServiceClass();
