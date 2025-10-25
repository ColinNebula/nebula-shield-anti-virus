/**
 * Integrated Scanner Service
 * Combines malware detection, VirusTotal, and threat intelligence
 */

const malwareEngine = require('./malware-detection-engine');
const virusTotalService = require('./virustotal-service');
const threatIntelService = require('./threat-intelligence-service');
const fs = require('fs').promises;
const path = require('path');

class IntegratedScannerService {
  constructor() {
    this.scanHistory = [];
    this.activeScans = new Map();
  }

  /**
   * Perform comprehensive file scan
   */
  async scanFile(filePath, options = {}) {
    const scanId = this.generateScanId();
    const startTime = Date.now();

    const scanResult = {
      scanId,
      filePath,
      fileName: path.basename(filePath),
      startTime,
      endTime: null,
      duration: null,
      status: 'scanning',
      threats: [],
      detectionMethods: [],
      overallThreatLevel: 'clean',
      confidence: 0,
      engines: {
        malwareEngine: null,
        virusTotal: null,
        threatIntelligence: null
      },
      fileInfo: null
    };

    this.activeScans.set(scanId, scanResult);

    try {
      // Get file info
      scanResult.fileInfo = await this.getFileInfo(filePath);

      // 1. Local malware engine (fastest, always runs)
      console.log(`🔍 Scanning ${scanResult.fileName} with malware engine...`);
      scanResult.engines.malwareEngine = await malwareEngine.scanFile(filePath);
      
      if (!scanResult.engines.malwareEngine.isClean) {
        scanResult.threats.push(...scanResult.engines.malwareEngine.threats);
        scanResult.detectionMethods.push(...scanResult.engines.malwareEngine.detectionMethods);
      }

      // 2. Threat intelligence (check hash reputation)
      if (options.useThreatIntel !== false) {
        console.log(`🌐 Checking threat intelligence...`);
        const hashCheck = await threatIntelService.checkHashReputation(
          scanResult.fileInfo.sha256
        );
        
        scanResult.engines.threatIntelligence = hashCheck;
        
        if (hashCheck.isThreat) {
          scanResult.threats.push({
            name: hashCheck.malwareFamily || 'Known malware',
            type: 'MALWARE',
            severity: hashCheck.threatLevel,
            description: `File hash found in threat intelligence databases`,
            sources: hashCheck.sources,
            method: 'Threat Intelligence',
            confidence: hashCheck.confidence
          });
          scanResult.detectionMethods.push('threat-intelligence');
        }
      }

      // 3. VirusTotal (if configured and requested)
      if (options.useVirusTotal !== false && virusTotalService.isConfigured()) {
        console.log(`☁️ Checking VirusTotal...`);
        const vtResult = await virusTotalService.scanFile(filePath);
        
        scanResult.engines.virusTotal = vtResult;
        
        if (vtResult.success && vtResult.isThreat) {
          scanResult.threats.push({
            name: 'Multiple AV detections',
            type: 'MALWARE',
            severity: vtResult.threatLevel,
            description: `Detected by ${vtResult.stats.malicious}/${vtResult.stats.total} engines`,
            detections: vtResult.detections.slice(0, 5), // Top 5 detections
            method: 'VirusTotal',
            confidence: Math.min((vtResult.stats.malicious / vtResult.stats.total) * 100, 100)
          });
          scanResult.detectionMethods.push('virustotal');
        }
      }

      // Calculate overall threat level and confidence
      scanResult.overallThreatLevel = this.calculateOverallThreatLevel(scanResult.threats);
      scanResult.confidence = this.calculateConfidence(scanResult.threats);
      scanResult.status = scanResult.threats.length > 0 ? 'threat-detected' : 'clean';

    } catch (error) {
      console.error('Scan error:', error);
      scanResult.status = 'error';
      scanResult.error = error.message;
    }

    // Finalize scan
    scanResult.endTime = Date.now();
    scanResult.duration = scanResult.endTime - startTime;
    
    this.activeScans.delete(scanId);
    this.scanHistory.unshift(scanResult);
    
    // Limit history to 100 scans
    if (this.scanHistory.length > 100) {
      this.scanHistory = this.scanHistory.slice(0, 100);
    }

    return scanResult;
  }

  /**
   * Scan multiple files
   */
  async scanFiles(filePaths, options = {}) {
    const results = [];
    
    for (const filePath of filePaths) {
      try {
        const result = await this.scanFile(filePath, options);
        results.push(result);
      } catch (error) {
        results.push({
          filePath,
          status: 'error',
          error: error.message
        });
      }
    }

    return {
      totalScanned: results.length,
      threatsFound: results.filter(r => r.status === 'threat-detected').length,
      cleanFiles: results.filter(r => r.status === 'clean').length,
      errors: results.filter(r => r.status === 'error').length,
      results
    };
  }

  /**
   * Scan directory recursively
   */
  async scanDirectory(dirPath, options = {}) {
    const files = await this.getFilesRecursively(dirPath, options.maxDepth || 5);
    return await this.scanFiles(files, options);
  }

  /**
   * Quick scan (uses hash lookup only)
   */
  async quickScan(filePath) {
    const fileInfo = await this.getFileInfo(filePath);
    
    // Check threat intelligence
    const hashCheck = await threatIntelService.checkHashReputation(fileInfo.sha256);
    
    // Check VirusTotal cache (if available)
    let vtCheck = null;
    if (virusTotalService.isConfigured()) {
      vtCheck = await virusTotalService.getFileReport(fileInfo.sha256);
    }

    return {
      filePath,
      fileInfo,
      isThreat: hashCheck.isThreat || (vtCheck?.isThreat || false),
      threatLevel: hashCheck.isThreat ? hashCheck.threatLevel : (vtCheck?.threatLevel || 'clean'),
      sources: hashCheck.sources,
      scanType: 'quick'
    };
  }

  /**
   * Check URL safety
   */
  async checkUrl(url) {
    const results = {
      url,
      isThreat: false,
      threatLevel: 'clean',
      sources: [],
      checks: {}
    };

    // Threat intelligence check
    const tiCheck = await threatIntelService.checkUrlReputation(url);
    results.checks.threatIntelligence = tiCheck;
    
    if (tiCheck.isThreat) {
      results.isThreat = true;
      results.threatLevel = this.escalateThreatLevel(results.threatLevel, tiCheck.threatLevel);
      results.sources.push(...tiCheck.sources);
    }

    // VirusTotal check (if configured)
    if (virusTotalService.isConfigured()) {
      const vtCheck = await virusTotalService.checkUrl(url);
      results.checks.virusTotal = vtCheck;
      
      if (vtCheck.success && vtCheck.isThreat) {
        results.isThreat = true;
        results.threatLevel = this.escalateThreatLevel(results.threatLevel, vtCheck.threatLevel);
        results.sources.push('VirusTotal');
      }
    }

    return results;
  }

  /**
   * Check IP reputation
   */
  async checkIp(ip) {
    const results = {
      ip,
      isThreat: false,
      threatLevel: 'clean',
      sources: [],
      checks: {}
    };

    // Threat intelligence check
    const tiCheck = await threatIntelService.checkIpReputation(ip);
    results.checks.threatIntelligence = tiCheck;
    
    if (tiCheck.isThreat) {
      results.isThreat = true;
      results.threatLevel = this.escalateThreatLevel(results.threatLevel, tiCheck.threatLevel);
      results.sources.push(...tiCheck.sources);
      results.tags = tiCheck.tags;
    }

    // VirusTotal check (if configured)
    if (virusTotalService.isConfigured()) {
      const vtCheck = await virusTotalService.checkIp(ip);
      results.checks.virusTotal = vtCheck;
      
      if (vtCheck.success && vtCheck.isThreat) {
        results.isThreat = true;
        results.threatLevel = this.escalateThreatLevel(results.threatLevel, vtCheck.threatLevel);
        results.sources.push('VirusTotal');
      }
    }

    return results;
  }

  /**
   * Get file information
   */
  async getFileInfo(filePath) {
    const stats = await fs.stat(filePath);
    const content = await fs.readFile(filePath);
    
    const crypto = require('crypto');
    
    return {
      path: filePath,
      name: path.basename(filePath),
      extension: path.extname(filePath),
      size: stats.size,
      created: stats.birthtime,
      modified: stats.mtime,
      md5: crypto.createHash('md5').update(content).digest('hex'),
      sha1: crypto.createHash('sha1').update(content).digest('hex'),
      sha256: crypto.createHash('sha256').update(content).digest('hex')
    };
  }

  /**
   * Get files recursively
   */
  async getFilesRecursively(dirPath, maxDepth = 5, currentDepth = 0) {
    if (currentDepth >= maxDepth) return [];
    
    const files = [];
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory()) {
        const subFiles = await this.getFilesRecursively(fullPath, maxDepth, currentDepth + 1);
        files.push(...subFiles);
      } else {
        files.push(fullPath);
      }
    }
    
    return files;
  }

  /**
   * Calculate overall threat level
   */
  calculateOverallThreatLevel(threats) {
    if (threats.length === 0) return 'clean';
    
    const levels = ['clean', 'low', 'medium', 'high', 'critical'];
    let maxLevel = 0;
    
    for (const threat of threats) {
      const levelIndex = levels.indexOf(threat.severity);
      if (levelIndex > maxLevel) {
        maxLevel = levelIndex;
      }
    }
    
    return levels[maxLevel];
  }

  /**
   * Calculate confidence score
   */
  calculateConfidence(threats) {
    if (threats.length === 0) return 0;
    
    const confidences = threats.map(t => t.confidence || 50);
    return Math.round(confidences.reduce((a, b) => a + b, 0) / confidences.length);
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
   * Generate scan ID
   */
  generateScanId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get scan status
   */
  getScanStatus(scanId) {
    return this.activeScans.get(scanId);
  }

  /**
   * Get scan history
   */
  getScanHistory(limit = 10) {
    return this.scanHistory.slice(0, limit);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    const total = this.scanHistory.length;
    const threats = this.scanHistory.filter(s => s.status === 'threat-detected').length;
    const clean = this.scanHistory.filter(s => s.status === 'clean').length;
    
    return {
      totalScans: total,
      threatsDetected: threats,
      cleanFiles: clean,
      detectionRate: total > 0 ? ((threats / total) * 100).toFixed(2) : 0,
      engines: {
        malwareEngine: malwareEngine.initialized,
        virusTotal: virusTotalService.isConfigured(),
        threatIntelligence: true
      }
    };
  }
}

module.exports = new IntegratedScannerService();
