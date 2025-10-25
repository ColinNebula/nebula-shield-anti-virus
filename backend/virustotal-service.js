/**
 * VirusTotal API Integration
 * Real-time threat intelligence using VirusTotal v3 API
 */

const https = require('https');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

class VirusTotalService {
  constructor() {
    // Get API key from environment variable
    this.apiKey = process.env.VIRUSTOTAL_API_KEY || '';
    this.apiUrl = 'https://www.virustotal.com/api/v3';
    this.rateLimitDelay = 15000; // 15 seconds for free tier (4 requests/min)
    this.lastRequestTime = 0;
    this.cache = new Map();
    this.cacheExpiry = 24 * 60 * 60 * 1000; // 24 hours
  }

  /**
   * Check if API key is configured
   */
  isConfigured() {
    return this.apiKey && this.apiKey.length > 0;
  }

  /**
   * Scan file using VirusTotal
   */
  async scanFile(filePath) {
    if (!this.isConfigured()) {
      return {
        success: false,
        error: 'VirusTotal API key not configured',
        demo: true
      };
    }

    try {
      // Calculate file hash first (faster than uploading)
      const hash = await this.calculateFileHash(filePath);
      
      // Check cache
      const cached = this.getFromCache(hash);
      if (cached) {
        return {
          success: true,
          cached: true,
          ...cached
        };
      }

      // Check if file report exists
      const report = await this.getFileReport(hash);
      
      if (report && report.data) {
        const result = this.parseReport(report.data);
        this.saveToCache(hash, result);
        return {
          success: true,
          cached: false,
          ...result
        };
      }

      // File not in VT database, upload it
      const uploadResult = await this.uploadFile(filePath);
      
      if (uploadResult.success) {
        // Wait for analysis (may take time)
        const analysisId = uploadResult.data.id;
        const analysisResult = await this.waitForAnalysis(analysisId);
        
        if (analysisResult) {
          const result = this.parseReport(analysisResult);
          this.saveToCache(hash, result);
          return {
            success: true,
            cached: false,
            ...result
          };
        }
      }

      return {
        success: false,
        error: 'Failed to scan file'
      };

    } catch (error) {
      console.error('VirusTotal scan error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get file report by hash
   */
  async getFileReport(hash) {
    await this.respectRateLimit();

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3/files/${hash}`,
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else if (res.statusCode === 404) {
            resolve(null); // File not in database
          } else {
            reject(new Error(`VirusTotal API error: ${res.statusCode}`));
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Upload file to VirusTotal
   */
  async uploadFile(filePath) {
    await this.respectRateLimit();

    try {
      const stats = await fs.stat(filePath);
      
      // VirusTotal file size limit: 650 MB for premium, 32 MB for free
      if (stats.size > 32 * 1024 * 1024) {
        return {
          success: false,
          error: 'File too large (32MB limit for free tier)'
        };
      }

      const fileContent = await fs.readFile(filePath);
      const fileName = path.basename(filePath);
      
      // Get upload URL
      const uploadUrl = await this.getUploadUrl();
      
      return new Promise((resolve, reject) => {
        const boundary = '----NebulaShieldBoundary' + Date.now();
        const formData = this.buildMultipartForm(boundary, fileName, fileContent);

        const urlObj = new URL(uploadUrl);
        const options = {
          hostname: urlObj.hostname,
          path: urlObj.pathname + urlObj.search,
          method: 'POST',
          headers: {
            'x-apikey': this.apiKey,
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
            'Content-Length': formData.length
          }
        };

        const req = https.request(options, (res) => {
          let data = '';

          res.on('data', (chunk) => {
            data += chunk;
          });

          res.on('end', () => {
            if (res.statusCode === 200) {
              resolve({
                success: true,
                data: JSON.parse(data).data
              });
            } else {
              reject(new Error(`Upload failed: ${res.statusCode}`));
            }
          });
        });

        req.on('error', reject);
        req.write(formData);
        req.end();
      });

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get upload URL
   */
  async getUploadUrl() {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: '/api/v3/files/upload_url',
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode === 200) {
            const parsed = JSON.parse(data);
            resolve(parsed.data);
          } else {
            reject(new Error(`Failed to get upload URL: ${res.statusCode}`));
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Wait for analysis to complete
   */
  async waitForAnalysis(analysisId, maxAttempts = 10) {
    for (let i = 0; i < maxAttempts; i++) {
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
      
      const result = await this.getAnalysisResult(analysisId);
      
      if (result && result.data && result.data.attributes.status === 'completed') {
        return result.data.attributes.results;
      }
    }
    
    return null;
  }

  /**
   * Get analysis result
   */
  async getAnalysisResult(analysisId) {
    await this.respectRateLimit();

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3/analyses/${analysisId}`,
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`Analysis check failed: ${res.statusCode}`));
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Parse VirusTotal report
   */
  parseReport(data) {
    const attrs = data.attributes;
    const stats = attrs.last_analysis_stats || {};
    
    const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    
    const detections = [];
    
    if (attrs.last_analysis_results) {
      Object.entries(attrs.last_analysis_results).forEach(([engine, result]) => {
        if (result.category === 'malicious' || result.category === 'suspicious') {
          detections.push({
            engine,
            category: result.category,
            result: result.result,
            method: result.method
          });
        }
      });
    }

    return {
      hash: data.id,
      sha256: attrs.sha256,
      md5: attrs.md5,
      sha1: attrs.sha1,
      stats: {
        malicious,
        suspicious,
        undetected: stats.undetected || 0,
        harmless: stats.harmless || 0,
        total: totalEngines
      },
      detections,
      reputation: attrs.reputation || 0,
      firstSeen: attrs.first_submission_date,
      lastSeen: attrs.last_analysis_date,
      names: attrs.names || [],
      tags: attrs.tags || [],
      isThreat: malicious > 0 || suspicious > 0,
      threatLevel: this.calculateThreatLevel(malicious, suspicious, totalEngines)
    };
  }

  /**
   * Calculate threat level
   */
  calculateThreatLevel(malicious, suspicious, total) {
    if (total === 0) return 'unknown';
    
    const detectionRate = ((malicious + suspicious) / total) * 100;
    
    if (detectionRate >= 50) return 'critical';
    if (detectionRate >= 25) return 'high';
    if (detectionRate >= 10) return 'medium';
    if (detectionRate > 0) return 'low';
    return 'clean';
  }

  /**
   * Calculate file hash
   */
  async calculateFileHash(filePath) {
    const content = await fs.readFile(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Build multipart form data
   */
  buildMultipartForm(boundary, fileName, fileContent) {
    const parts = [];
    
    parts.push(Buffer.from(`--${boundary}\r\n`));
    parts.push(Buffer.from(`Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n`));
    parts.push(Buffer.from('Content-Type: application/octet-stream\r\n\r\n'));
    parts.push(fileContent);
    parts.push(Buffer.from(`\r\n--${boundary}--\r\n`));
    
    return Buffer.concat(parts);
  }

  /**
   * Respect rate limit
   */
  async respectRateLimit() {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < this.rateLimitDelay) {
      const waitTime = this.rateLimitDelay - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.lastRequestTime = Date.now();
  }

  /**
   * Get from cache
   */
  getFromCache(hash) {
    const cached = this.cache.get(hash);
    
    if (cached && Date.now() - cached.timestamp < this.cacheExpiry) {
      return cached.data;
    }
    
    this.cache.delete(hash);
    return null;
  }

  /**
   * Save to cache
   */
  saveToCache(hash, data) {
    this.cache.set(hash, {
      data,
      timestamp: Date.now()
    });
    
    // Limit cache size
    if (this.cache.size > 500) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
  }

  /**
   * Check URL reputation
   */
  async checkUrl(url) {
    if (!this.isConfigured()) {
      return {
        success: false,
        error: 'VirusTotal API key not configured'
      };
    }

    await this.respectRateLimit();

    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3/urls/${urlId}`,
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode === 200) {
            const parsed = JSON.parse(data);
            resolve({
              success: true,
              ...this.parseReport(parsed.data)
            });
          } else if (res.statusCode === 404) {
            resolve({
              success: true,
              isThreat: false,
              threatLevel: 'unknown',
              message: 'URL not found in database'
            });
          } else {
            reject(new Error(`URL check failed: ${res.statusCode}`));
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Check IP reputation
   */
  async checkIp(ip) {
    if (!this.isConfigured()) {
      return {
        success: false,
        error: 'VirusTotal API key not configured'
      };
    }

    await this.respectRateLimit();

    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'www.virustotal.com',
        path: `/api/v3/ip_addresses/${ip}`,
        method: 'GET',
        headers: {
          'x-apikey': this.apiKey
        }
      };

      const req = https.request(options, (res) => {
        let data = '';

        res.on('data', (chunk) => {
          data += chunk;
        });

        res.on('end', () => {
          if (res.statusCode === 200) {
            const parsed = JSON.parse(data);
            resolve({
              success: true,
              ...this.parseReport(parsed.data)
            });
          } else {
            reject(new Error(`IP check failed: ${res.statusCode}`));
          }
        });
      });

      req.on('error', reject);
      req.end();
    });
  }
}

module.exports = new VirusTotalService();
