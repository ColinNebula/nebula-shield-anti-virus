// VirusTotal API Integration Service
import CryptoJS from 'crypto-js';

const VIRUSTOTAL_API_KEY = process.env.REACT_APP_VIRUSTOTAL_API_KEY || 'demo-key';
const VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3';

class VirusTotalService {
  constructor() {
    this.cache = new Map(); // Cache results to avoid rate limits
    this.requestQueue = [];
    this.isProcessing = false;
  }

  // Calculate SHA-256 hash of file content
  calculateFileHash(fileContent) {
    try {
      if (typeof fileContent === 'string') {
        return CryptoJS.SHA256(fileContent).toString();
      } else if (fileContent instanceof ArrayBuffer) {
        const wordArray = CryptoJS.lib.WordArray.create(fileContent);
        return CryptoJS.SHA256(wordArray).toString();
      }
      return null;
    } catch (error) {
      console.error('Error calculating hash:', error);
      return null;
    }
  }

  // Calculate hash from file path (simulated - in real app would read file)
  async calculateHashFromPath(filePath) {
    // For demo purposes, create a deterministic hash from the file path
    return CryptoJS.SHA256(filePath).toString();
  }

  // Get file report from VirusTotal
  async getFileReport(fileHash) {
    // Check cache first
    if (this.cache.has(fileHash)) {
      const cached = this.cache.get(fileHash);
      if (Date.now() - cached.timestamp < 3600000) { // 1 hour cache
        return cached.data;
      }
    }

    // For demo mode without API key
    if (VIRUSTOTAL_API_KEY === 'demo-key') {
      return this.generateMockReport(fileHash);
    }

    try {
      const response = await fetch(`${VIRUSTOTAL_API_URL}/files/${fileHash}`, {
        method: 'GET',
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      });

      if (response.status === 404) {
        return {
          found: false,
          message: 'File not found in VirusTotal database'
        };
      }

      if (!response.ok) {
        throw new Error(`VirusTotal API error: ${response.status}`);
      }

      const data = await response.json();
      const report = this.parseVirusTotalResponse(data);

      // Cache the result
      this.cache.set(fileHash, {
        data: report,
        timestamp: Date.now()
      });

      return report;
    } catch (error) {
      console.error('VirusTotal API error:', error);
      return {
        error: error.message,
        found: false
      };
    }
  }

  // Parse VirusTotal API response
  parseVirusTotalResponse(data) {
    const attributes = data.data?.attributes || {};
    const stats = attributes.last_analysis_stats || {};
    const results = attributes.last_analysis_results || {};

    const totalEngines = Object.keys(results).length;
    const detections = stats.malicious || 0;
    const undetected = stats.undetected || 0;
    const suspicious = stats.suspicious || 0;

    // Get detailed vendor results
    const vendors = Object.entries(results).map(([vendor, result]) => ({
      name: vendor,
      detected: result.category === 'malicious' || result.category === 'suspicious',
      category: result.category,
      result: result.result || 'Clean',
      engine_version: result.engine_version
    }));

    return {
      found: true,
      hash: data.data?.id || '',
      stats: {
        malicious: detections,
        suspicious: suspicious,
        undetected: undetected,
        harmless: stats.harmless || 0,
        total: totalEngines
      },
      detectionRatio: `${detections}/${totalEngines}`,
      detectionRate: totalEngines > 0 ? (detections / totalEngines * 100).toFixed(1) : 0,
      reputation: this.calculateReputation(stats),
      lastAnalysis: attributes.last_analysis_date 
        ? new Date(attributes.last_analysis_date * 1000).toISOString()
        : null,
      vendors: vendors.sort((a, b) => {
        if (a.detected && !b.detected) return -1;
        if (!a.detected && b.detected) return 1;
        return a.name.localeCompare(b.name);
      }),
      fileNames: attributes.names || [],
      fileType: attributes.type_description || 'Unknown',
      fileSize: attributes.size || 0,
      tags: attributes.tags || []
    };
  }

  // Calculate reputation score
  calculateReputation(stats) {
    const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
    if (total === 0) return 'unknown';

    const maliciousRate = (stats.malicious / total) * 100;
    const suspiciousRate = (stats.suspicious / total) * 100;

    if (maliciousRate > 30 || (maliciousRate + suspiciousRate) > 50) {
      return 'malicious';
    } else if (maliciousRate > 10 || suspiciousRate > 20) {
      return 'suspicious';
    } else if (maliciousRate > 0) {
      return 'potentially-unwanted';
    } else {
      return 'clean';
    }
  }

  // Generate mock report for demo mode
  generateMockReport(fileHash) {
    // Deterministic random based on hash
    const hashNum = parseInt(fileHash.substring(0, 8), 16);
    const isMalicious = hashNum % 10 < 2; // 20% chance
    const isSuspicious = hashNum % 10 < 4 && !isMalicious; // 20% more

    const totalEngines = 70;
    let detections = 0;
    let suspicious = 0;

    if (isMalicious) {
      detections = Math.floor(totalEngines * (0.3 + Math.random() * 0.5)); // 30-80%
    } else if (isSuspicious) {
      suspicious = Math.floor(totalEngines * (0.1 + Math.random() * 0.2)); // 10-30%
      detections = Math.floor(totalEngines * (0.05 + Math.random() * 0.1)); // 5-15%
    }

    const vendors = [
      'Microsoft', 'Kaspersky', 'Avast', 'AVG', 'Bitdefender', 'ESET-NOD32', 
      'F-Secure', 'McAfee', 'Symantec', 'TrendMicro', 'Sophos', 'Panda',
      'Avira', 'DrWeb', 'ClamAV', 'Comodo', 'GData', 'Jiangmin', 'K7AntiVirus',
      'K7GW', 'Malwarebytes', 'MaxSecure', 'Rising', 'Yandex', 'ZoneAlarm'
    ];

    const vendorResults = vendors.slice(0, totalEngines).map((vendor, index) => {
      const shouldDetect = index < detections;
      const isSusp = index >= detections && index < detections + suspicious;
      
      return {
        name: vendor,
        detected: shouldDetect || isSusp,
        category: shouldDetect ? 'malicious' : (isSusp ? 'suspicious' : 'undetected'),
        result: shouldDetect ? 'Trojan.Generic.Suspicious' : (isSusp ? 'Potentially Unwanted' : 'Clean'),
        engine_version: `${Math.floor(Math.random() * 5 + 1)}.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 100)}`
      };
    });

    const stats = {
      malicious: detections,
      suspicious: suspicious,
      undetected: totalEngines - detections - suspicious,
      harmless: 0,
      total: totalEngines
    };

    return {
      found: true,
      hash: fileHash,
      stats: stats,
      detectionRatio: `${detections}/${totalEngines}`,
      detectionRate: ((detections / totalEngines) * 100).toFixed(1),
      reputation: this.calculateReputation(stats),
      lastAnalysis: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
      vendors: vendorResults,
      fileNames: ['sample_file.exe'],
      fileType: 'Win32 EXE',
      fileSize: Math.floor(Math.random() * 5000000) + 10000,
      tags: isMalicious ? ['malware', 'trojan', 'suspicious'] : (isSuspicious ? ['potentially-unwanted'] : [])
    };
  }

  // Check file by path
  async checkFile(filePath) {
    const hash = await this.calculateHashFromPath(filePath);
    if (!hash) {
      return { error: 'Failed to calculate file hash' };
    }
    return await this.getFileReport(hash);
  }

  // Get reputation badge info
  getReputationBadge(reputation) {
    const badges = {
      'clean': {
        color: '#10b981',
        icon: '✓',
        text: 'Clean',
        description: 'No threats detected'
      },
      'potentially-unwanted': {
        color: '#f59e0b',
        icon: '⚠',
        text: 'Potentially Unwanted',
        description: 'Some vendors flagged this file'
      },
      'suspicious': {
        color: '#ef4444',
        icon: '!',
        text: 'Suspicious',
        description: 'Multiple vendors detected threats'
      },
      'malicious': {
        color: '#dc2626',
        icon: '✕',
        text: 'Malicious',
        description: 'High threat detection rate'
      },
      'unknown': {
        color: '#6b7280',
        icon: '?',
        text: 'Unknown',
        description: 'File not analyzed yet'
      }
    };

    return badges[reputation] || badges.unknown;
  }

  // Format detection ratio for display
  formatDetectionRatio(ratio) {
    if (!ratio) return 'N/A';
    const [detected, total] = ratio.split('/').map(Number);
    if (total === 0) return 'N/A';
    
    const percentage = ((detected / total) * 100).toFixed(1);
    return {
      ratio: ratio,
      percentage: `${percentage}%`,
      detected: detected,
      total: total
    };
  }
}

// Export singleton instance
const virusTotalService = new VirusTotalService();
export default virusTotalService;
