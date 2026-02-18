/**
 * Browser Extension Protection Service
 * Monitors and analyzes browser extensions for malicious behavior
 * Supports Chrome, Firefox, Edge, and Brave
 */

import notificationService from './notificationService';

class BrowserExtensionProtection {
  constructor() {
    this.monitoringActive = false;
    this.extensions = new Map();
    this.maliciousPatterns = this.loadMaliciousPatterns();
    this.browserProfiles = new Map();
    this.listeners = new Set();
    this.scanHistory = [];
    this.statistics = {
      totalExtensionsScanned: 0,
      maliciousFound: 0,
      suspiciousFound: 0,
      lastScanTime: null
    };
    this.loadStatistics();
  }

  // ==================== MALICIOUS PATTERNS DATABASE ====================
  
  loadMaliciousPatterns() {
    return {
      permissions: {
        // High-risk permissions
        highRisk: [
          'webRequest',
          'webRequestBlocking',
          'debugger',
          'management',
          'proxy',
          'privacy',
          'nativeMessaging'
        ],
        // Medium-risk permissions
        mediumRisk: [
          'cookies',
          'history',
          'tabs',
          'bookmarks',
          'downloads',
          'geolocation',
          'clipboardRead',
          'clipboardWrite'
        ],
        // Suspicious permission combinations
        suspiciousCombinations: [
          ['webRequest', 'cookies', 'tabs'],
          ['cookies', 'history', 'tabs'],
          ['webRequest', 'webRequestBlocking', '<all_urls>']
        ]
      },
      
      // Known malicious extension IDs (example database)
      knownMalicious: new Set([
        'example-malicious-id-1',
        'example-malicious-id-2'
      ]),
      
      // Suspicious name patterns
      suspiciousNames: [
        /free.*vpn/i,
        /ad.*blocker.*plus/i,
        /video.*downloader/i,
        /pdf.*converter/i,
        /weather/i,
        /bitcoin|crypto|wallet/i,
        /security.*scanner/i
      ],
      
      // Suspicious developer patterns
      suspiciousDevelopers: [
        /unknown/i,
        /not.*provided/i,
        /n\/a/i
      ],
      
      // Red flag behaviors
      behaviors: {
        // Extensions with these characteristics are suspicious
        noDescription: true,
        noWebsite: true,
        recentlyInstalled: 7, // days
        lowRating: 3.0,
        fewUsers: 1000,
        frequentUpdates: 5, // updates per week
        obfuscatedCode: true
      }
    };
  }

  // ==================== BROWSER DETECTION ====================
  
  detectInstalledBrowsers() {
    const browsers = [];
    
    // In Electron environment, we can detect browsers
    if (window.electron && window.electron.detectBrowsers) {
      return window.electron.detectBrowsers();
    }
    
    // Fallback detection based on user agent and known paths
    const userAgent = navigator.userAgent.toLowerCase();
    
    if (userAgent.includes('chrome') && !userAgent.includes('edg')) {
      browsers.push({
        name: 'Google Chrome',
        id: 'chrome',
        profilePath: this.getDefaultProfilePath('chrome'),
        icon: '🌐'
      });
    }
    
    if (userAgent.includes('firefox')) {
      browsers.push({
        name: 'Mozilla Firefox',
        id: 'firefox',
        profilePath: this.getDefaultProfilePath('firefox'),
        icon: '🦊'
      });
    }
    
    if (userAgent.includes('edg')) {
      browsers.push({
        name: 'Microsoft Edge',
        id: 'edge',
        profilePath: this.getDefaultProfilePath('edge'),
        icon: '🔷'
      });
    }
    
    return browsers;
  }

  getDefaultProfilePath(browser) {
    // Handle both Electron and browser contexts
    const userProfile = (typeof process !== 'undefined' && process.env) 
      ? (process.env.USERPROFILE || process.env.HOME)
      : (window.electron?.getUserDataPath?.() || '');
    
    const paths = {
      chrome: `${userProfile}\\AppData\\Local\\Google\\Chrome\\User Data\\Default`,
      firefox: `${userProfile}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles`,
      edge: `${userProfile}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default`,
      brave: `${userProfile}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default`
    };
    
    return paths[browser] || null;
  }

  // ==================== EXTENSION SCANNING ====================
  
  async scanAllBrowsers() {
    console.log('🔍 Scanning browser extensions...');
    
    const browsers = this.detectInstalledBrowsers();
    const results = {
      browsersScanned: browsers.length,
      totalExtensions: 0,
      malicious: [],
      suspicious: [],
      clean: [],
      errors: []
    };

    for (const browser of browsers) {
      try {
        const browserResult = await this.scanBrowser(browser);
        results.totalExtensions += browserResult.extensions.length;
        results.malicious.push(...browserResult.malicious);
        results.suspicious.push(...browserResult.suspicious);
        results.clean.push(...browserResult.clean);
      } catch (error) {
        console.error(`Error scanning ${browser.name}:`, error);
        results.errors.push({
          browser: browser.name,
          error: error.message
        });
      }
    }

    // Update statistics
    this.statistics.totalExtensionsScanned += results.totalExtensions;
    this.statistics.maliciousFound += results.malicious.length;
    this.statistics.suspiciousFound += results.suspicious.length;
    this.statistics.lastScanTime = new Date().toISOString();
    this.saveStatistics();

    // Save to history
    this.scanHistory.unshift({
      timestamp: new Date().toISOString(),
      results
    });

    // Notify listeners
    this.notifyListeners('scan-complete', results);

    // Show notifications
    if (results.malicious.length > 0) {
      notificationService.show({
        type: 'error',
        title: '⚠️ Malicious Extensions Found!',
        message: `${results.malicious.length} malicious extension(s) detected`,
        duration: 0,
        actions: [
          {
            label: 'View Details',
            onClick: () => this.notifyListeners('show-details', results)
          },
          {
            label: 'Remove All',
            onClick: () => this.removeExtensions(results.malicious)
          }
        ]
      });
    } else if (results.suspicious.length > 0) {
      notificationService.show({
        type: 'warning',
        title: 'Suspicious Extensions Found',
        message: `${results.suspicious.length} suspicious extension(s) detected`,
        duration: 8000
      });
    } else {
      notificationService.show({
        type: 'success',
        title: 'Browser Extensions Clean',
        message: 'No malicious or suspicious extensions found',
        duration: 5000
      });
    }

    return results;
  }

  async scanBrowser(browser) {
    console.log(`Scanning ${browser.name}...`);
    
    let extensions = [];
    
    // Get extensions based on browser type
    if (window.electron && window.electron.getBrowserExtensions) {
      extensions = await window.electron.getBrowserExtensions(browser.id);
    } else {
      // Fallback: simulate extension detection
      extensions = await this.simulateExtensionDetection(browser);
    }

    const results = {
      browser,
      extensions: [],
      malicious: [],
      suspicious: [],
      clean: []
    };

    // Analyze each extension
    for (const ext of extensions) {
      const analysis = this.analyzeExtension(ext, browser);
      
      const enrichedExt = {
        ...ext,
        browser: browser.name,
        browserId: browser.id,
        analysis
      };

      results.extensions.push(enrichedExt);
      this.extensions.set(ext.id, enrichedExt);

      if (analysis.threatLevel === 'malicious') {
        results.malicious.push(enrichedExt);
      } else if (analysis.threatLevel === 'suspicious') {
        results.suspicious.push(enrichedExt);
      } else {
        results.clean.push(enrichedExt);
      }
    }

    return results;
  }

  // ==================== EXTENSION ANALYSIS ====================
  
  analyzeExtension(extension, browser) {
    const analysis = {
      threatLevel: 'clean',
      riskScore: 0,
      flags: [],
      recommendations: []
    };

    // Check if known malicious
    if (this.maliciousPatterns.knownMalicious.has(extension.id)) {
      analysis.threatLevel = 'malicious';
      analysis.riskScore = 100;
      analysis.flags.push('Known malicious extension ID');
      analysis.recommendations.push('Remove immediately');
      return analysis;
    }

    // Check permissions
    const permissionRisk = this.analyzePermissions(extension.permissions || []);
    analysis.riskScore += permissionRisk.score;
    analysis.flags.push(...permissionRisk.flags);

    // Check name patterns
    for (const pattern of this.maliciousPatterns.suspiciousNames) {
      if (pattern.test(extension.name)) {
        analysis.riskScore += 20;
        analysis.flags.push(`Suspicious name pattern: ${pattern.toString()}`);
      }
    }

    // Check developer
    const developer = extension.author || extension.developer || 'Unknown';
    for (const pattern of this.maliciousPatterns.suspiciousDevelopers) {
      if (pattern.test(developer)) {
        analysis.riskScore += 15;
        analysis.flags.push('Unknown or unverified developer');
      }
    }

    // Check description
    if (!extension.description || extension.description.length < 20) {
      analysis.riskScore += 10;
      analysis.flags.push('No proper description provided');
    }

    // Check website
    if (!extension.homepageUrl && !extension.website) {
      analysis.riskScore += 10;
      analysis.flags.push('No official website');
    }

    // Check installation date
    if (extension.installDate) {
      const daysSinceInstall = (Date.now() - new Date(extension.installDate)) / (1000 * 60 * 60 * 24);
      if (daysSinceInstall < this.maliciousPatterns.behaviors.recentlyInstalled) {
        analysis.riskScore += 5;
        analysis.flags.push(`Recently installed (${Math.floor(daysSinceInstall)} days ago)`);
      }
    }

    // Check update frequency (if available)
    if (extension.updateInfo && extension.updateInfo.frequency === 'high') {
      analysis.riskScore += 10;
      analysis.flags.push('Unusually frequent updates');
    }

    // Determine threat level based on risk score
    if (analysis.riskScore >= 70) {
      analysis.threatLevel = 'malicious';
      analysis.recommendations.push('Remove this extension immediately');
      analysis.recommendations.push('Change passwords for accounts accessed while extension was active');
      analysis.recommendations.push('Run a full system scan');
    } else if (analysis.riskScore >= 40) {
      analysis.threatLevel = 'suspicious';
      analysis.recommendations.push('Review extension permissions carefully');
      analysis.recommendations.push('Consider removing if not essential');
      analysis.recommendations.push('Check developer reputation');
    } else if (analysis.riskScore >= 20) {
      analysis.threatLevel = 'low-risk';
      analysis.recommendations.push('Monitor extension behavior');
      analysis.recommendations.push('Review permissions periodically');
    } else {
      analysis.threatLevel = 'clean';
    }

    return analysis;
  }

  analyzePermissions(permissions) {
    const result = {
      score: 0,
      flags: []
    };

    // Check high-risk permissions
    for (const permission of permissions) {
      if (this.maliciousPatterns.permissions.highRisk.includes(permission)) {
        result.score += 15;
        result.flags.push(`High-risk permission: ${permission}`);
      } else if (this.maliciousPatterns.permissions.mediumRisk.includes(permission)) {
        result.score += 5;
        result.flags.push(`Medium-risk permission: ${permission}`);
      }
    }

    // Check for suspicious permission combinations
    for (const combo of this.maliciousPatterns.permissions.suspiciousCombinations) {
      if (combo.every(perm => permissions.includes(perm))) {
        result.score += 25;
        result.flags.push(`Suspicious permission combination: ${combo.join(', ')}`);
      }
    }

    // Check for <all_urls> permission
    if (permissions.includes('<all_urls>') || permissions.includes('*://*/*')) {
      result.score += 20;
      result.flags.push('Can access all websites');
    }

    return result;
  }

  // ==================== EXTENSION MANAGEMENT ====================
  
  async removeExtension(extensionId, browserId) {
    try {
      if (window.electron && window.electron.removeExtension) {
        const result = await window.electron.removeExtension(browserId, extensionId);
        
        if (result.success) {
          this.extensions.delete(extensionId);
          this.notifyListeners('extension-removed', { extensionId, browserId });
          
          notificationService.show({
            type: 'success',
            title: 'Extension Removed',
            message: 'Malicious extension has been removed successfully',
            duration: 5000
          });
        }
        
        return result;
      } else {
        // Provide manual removal instructions
        const extension = this.extensions.get(extensionId);
        const browser = extension?.browser || 'browser';
        
        notificationService.show({
          type: 'info',
          title: 'Manual Removal Required',
          message: `Please remove the extension manually from ${browser} settings`,
          duration: 10000
        });
        
        return {
          success: false,
          message: 'Manual removal required',
          instructions: this.getRemovalInstructions(browserId)
        };
      }
    } catch (error) {
      console.error('Extension removal error:', error);
      notificationService.show({
        type: 'error',
        title: 'Removal Failed',
        message: `Failed to remove extension: ${error.message}`,
        duration: 8000
      });
      return { success: false, error: error.message };
    }
  }

  async removeExtensions(extensions) {
    const results = {
      removed: [],
      failed: []
    };

    for (const ext of extensions) {
      const result = await this.removeExtension(ext.id, ext.browserId);
      if (result.success) {
        results.removed.push(ext);
      } else {
        results.failed.push({ extension: ext, error: result.error || result.message });
      }
    }

    return results;
  }

  getRemovalInstructions(browserId) {
    const instructions = {
      chrome: [
        '1. Open Chrome and go to chrome://extensions',
        '2. Find the malicious extension',
        '3. Click "Remove"',
        '4. Confirm removal'
      ],
      firefox: [
        '1. Open Firefox and go to about:addons',
        '2. Click on "Extensions" in the sidebar',
        '3. Find the malicious extension',
        '4. Click the three dots menu and select "Remove"'
      ],
      edge: [
        '1. Open Edge and go to edge://extensions',
        '2. Find the malicious extension',
        '3. Click "Remove"',
        '4. Confirm removal'
      ]
    };

    return instructions[browserId] || instructions.chrome;
  }

  // ==================== REAL-TIME MONITORING ====================
  
  startMonitoring() {
    if (this.monitoringActive) return;

    this.monitoringActive = true;
    
    // Scan every hour
    this.monitoringInterval = setInterval(() => {
      this.scanAllBrowsers();
    }, 3600000); // 1 hour

    // Initial scan
    this.scanAllBrowsers();

    this.notifyListeners('monitoring-started', {});
    
    notificationService.show({
      type: 'info',
      title: 'Extension Monitoring Active',
      message: 'Browser extensions are being monitored for threats',
      duration: 5000
    });
  }

  stopMonitoring() {
    if (!this.monitoringActive) return;

    this.monitoringActive = false;
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }

    this.notifyListeners('monitoring-stopped', {});
    
    notificationService.show({
      type: 'info',
      title: 'Extension Monitoring Stopped',
      message: 'Browser extension monitoring has been disabled',
      duration: 5000
    });
  }

  isMonitoring() {
    return this.monitoringActive;
  }

  // ==================== EXTENSION SIMULATION (FOR DEMO) ====================
  
  async simulateExtensionDetection(browser) {
    // Simulate realistic browser extensions for demo
    const extensions = [
      {
        id: 'ext-001',
        name: 'uBlock Origin',
        version: '1.45.2',
        description: 'An efficient wide-spectrum content blocker',
        enabled: true,
        permissions: ['webRequest', 'webRequestBlocking', 'storage', 'tabs', '<all_urls>'],
        author: 'Raymond Hill',
        homepageUrl: 'https://github.com/gorhill/uBlock',
        installDate: new Date('2023-01-15').toISOString(),
        updateInfo: { frequency: 'low' }
      },
      {
        id: 'ext-002',
        name: 'LastPass Password Manager',
        version: '4.98.0',
        description: 'LastPass is a password manager that secures your passwords',
        enabled: true,
        permissions: ['storage', 'tabs', 'webRequest', '<all_urls>', 'cookies'],
        author: 'LastPass',
        homepageUrl: 'https://www.lastpass.com',
        installDate: new Date('2023-03-20').toISOString()
      },
      {
        id: 'ext-003',
        name: 'Free VPN Extension',
        version: '1.0.0',
        description: '',
        enabled: true,
        permissions: ['proxy', 'webRequest', 'webRequestBlocking', '<all_urls>', 'cookies', 'history'],
        author: 'Unknown',
        installDate: new Date().toISOString(),
        updateInfo: { frequency: 'high' }
      },
      {
        id: 'ext-004',
        name: 'Video Downloader Plus',
        version: '2.3.1',
        description: 'Download videos from any website',
        enabled: true,
        permissions: ['tabs', 'downloads', '<all_urls>'],
        installDate: new Date('2024-10-15').toISOString()
      },
      {
        id: 'ext-005',
        name: 'React Developer Tools',
        version: '4.28.0',
        description: 'React debugging tools for Chrome',
        enabled: true,
        permissions: ['storage', 'tabs'],
        author: 'Meta Platforms, Inc.',
        homepageUrl: 'https://react.dev',
        installDate: new Date('2023-06-10').toISOString()
      }
    ];

    return extensions;
  }

  // ==================== DATA MANAGEMENT ====================
  
  getExtensions() {
    return Array.from(this.extensions.values());
  }

  getExtension(extensionId) {
    return this.extensions.get(extensionId);
  }

  getScanHistory() {
    return this.scanHistory;
  }

  getStatistics() {
    return { ...this.statistics };
  }

  loadStatistics() {
    try {
      const stored = localStorage.getItem('browser-extension-stats');
      if (stored) {
        this.statistics = JSON.parse(stored);
      }
    } catch (error) {
      console.warn('Failed to load browser extension statistics:', error);
    }
  }

  saveStatistics() {
    try {
      localStorage.setItem('browser-extension-stats', JSON.stringify(this.statistics));
    } catch (error) {
      console.warn('Failed to save browser extension statistics:', error);
    }
  }

  resetStatistics() {
    this.statistics = {
      totalExtensionsScanned: 0,
      maliciousFound: 0,
      suspiciousFound: 0,
      lastScanTime: null
    };
    this.saveStatistics();
  }

  // ==================== EVENT LISTENERS ====================
  
  addListener(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  removeListener(callback) {
    this.listeners.delete(callback);
  }

  notifyListeners(event, data) {
    this.listeners.forEach(callback => {
      try {
        callback(event, data);
      } catch (error) {
        console.error('Listener error:', error);
      }
    });
  }

  // ==================== CLEANUP ====================
  
  destroy() {
    this.stopMonitoring();
    this.listeners.clear();
    this.extensions.clear();
  }
}

// Export singleton instance
const browserExtensionProtection = new BrowserExtensionProtection();
export default browserExtensionProtection;
