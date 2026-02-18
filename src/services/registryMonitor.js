/**
 * Windows Registry Monitor
 * 
 * Detects persistence mechanisms, policy changes, and security modifications
 * in the Windows Registry
 */

class RegistryMonitor {
  constructor() {
    this.isMonitoring = false;
    this.monitoredKeys = new Map();
    this.detectedChanges = [];
    this.persistenceAttempts = [];
    
    // Critical registry paths to monitor
    this.criticalPaths = {
      // Autorun locations
      autorun: [
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run',
        'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run'
      ],
      
      // Services
      services: [
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services'
      ],
      
      // Policy settings
      policies: [
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
        'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies',
        'HKEY_CURRENT_USER\\SOFTWARE\\Policies'
      ],
      
      // Security settings
      security: [
        'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender'
      ],
      
      // Browser extensions/plugins
      browser: [
        'HKEY_CURRENT_USER\\Software\\Google\\Chrome\\Extensions',
        'HKEY_LOCAL_MACHINE\\Software\\Google\\Chrome\\Extensions',
        'HKEY_CURRENT_USER\\Software\\Mozilla\\Firefox\\Extensions',
        'HKEY_CURRENT_USER\\Software\\Microsoft\\Edge\\Extensions'
      ],
      
      // Image File Execution Options (debugger hijacking)
      ifeo: [
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
      ],
      
      // DLL injection points
      appInit: [
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
        'HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'
      ]
    };
    
    // Suspicious value names
    this.suspiciousValueNames = new Set([
      'debugger',
      'appinit_dlls',
      'loadappinit_dlls',
      'userinitmprlogonscript'
    ]);
    
    // Config
    this.config = {
      monitorAutorun: true,
      monitorServices: true,
      monitorPolicies: true,
      monitorSecurity: true,
      monitorBrowser: true,
      checkInterval: 5000, // Check every 5 seconds
      enableHeuristics: true
    };
    
    // Stats
    this.stats = {
      totalChecks: 0,
      changesDetected: 0,
      persistenceAttempts: 0,
      policyChanges: 0,
      securityModifications: 0,
      lastCheck: null
    };
    
    // Baseline snapshot
    this.baseline = new Map();
  }

  /**
   * Start registry monitoring
   */
  async start() {
    if (this.isMonitoring) return;
    
    this.isMonitoring = true;
    console.log('📋 Registry monitoring started');
    
    // Create baseline snapshot
    await this.createBaseline();
    
    // Start periodic checking
    this.checkInterval = setInterval(() => {
      this.checkForChanges();
    }, this.config.checkInterval);
  }

  /**
   * Stop registry monitoring
   */
  stop() {
    this.isMonitoring = false;
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
    console.log('🛑 Registry monitoring stopped');
  }

  /**
   * Create baseline snapshot of monitored keys
   */
  async createBaseline() {
    console.log('Creating registry baseline...');
    
    for (const [category, paths] of Object.entries(this.criticalPaths)) {
      for (const path of paths) {
        try {
          const values = await this.readRegistryKey(path);
          this.baseline.set(path, values);
          this.monitoredKeys.set(path, {
            category,
            lastCheck: Date.now(),
            changeCount: 0
          });
        } catch (error) {
          // Key may not exist or access denied
          console.debug(`Could not read ${path}:`, error.message);
        }
      }
    }
    
    console.log(`✅ Baseline created: ${this.baseline.size} keys monitored`);
  }

  /**
   * Check for registry changes
   */
  async checkForChanges() {
    if (!this.isMonitoring) return;
    
    this.stats.totalChecks++;
    this.stats.lastCheck = new Date().toISOString();
    
    for (const [path, baselineValues] of this.baseline.entries()) {
      try {
        const currentValues = await this.readRegistryKey(path);
        const changes = this.detectChanges(path, baselineValues, currentValues);
        
        if (changes.length > 0) {
          this.handleRegistryChanges(path, changes);
          
          // Update baseline with current values
          this.baseline.set(path, currentValues);
        }
      } catch (error) {
        console.debug(`Error checking ${path}:`, error.message);
      }
    }
  }

  /**
   * Detect changes between baseline and current values
   */
  detectChanges(path, baseline, current) {
    const changes = [];
    
    // Check for new values
    for (const [name, value] of Object.entries(current)) {
      if (!baseline[name]) {
        changes.push({
          type: 'value_added',
          name,
          value,
          oldValue: null
        });
      } else if (baseline[name] !== value) {
        changes.push({
          type: 'value_modified',
          name,
          value,
          oldValue: baseline[name]
        });
      }
    }
    
    // Check for deleted values
    for (const name of Object.keys(baseline)) {
      if (!current[name]) {
        changes.push({
          type: 'value_deleted',
          name,
          value: null,
          oldValue: baseline[name]
        });
      }
    }
    
    return changes;
  }

  /**
   * Handle detected registry changes
   */
  handleRegistryChanges(path, changes) {
    this.stats.changesDetected++;
    
    const keyInfo = this.monitoredKeys.get(path);
    if (keyInfo) {
      keyInfo.changeCount++;
    }
    
    for (const change of changes) {
      const threat = this.analyzeChange(path, change, keyInfo);
      
      if (threat) {
        this.handleThreat(path, change, threat);
      } else {
        // Log benign change
        this.logChange(path, change);
      }
    }
  }

  /**
   * Analyze registry change for threats
   */
  analyzeChange(path, change, keyInfo) {
    const threats = [];
    
    // 1. Check for autorun persistence
    if (keyInfo.category === 'autorun' && change.type === 'value_added') {
      threats.push({
        type: 'persistence_autorun',
        severity: 0.8,
        description: `New autorun entry: ${change.name}`
      });
      this.stats.persistenceAttempts++;
    }
    
    // 2. Check for service creation
    if (keyInfo.category === 'services' && change.type === 'value_added') {
      threats.push({
        type: 'service_creation',
        severity: 0.7,
        description: `New service created: ${change.name}`
      });
    }
    
    // 3. Check for policy changes
    if (keyInfo.category === 'policies') {
      threats.push({
        type: 'policy_modification',
        severity: 0.75,
        description: `Policy changed: ${change.name}`
      });
      this.stats.policyChanges++;
    }
    
    // 4. Check for security modifications
    if (keyInfo.category === 'security') {
      threats.push({
        type: 'security_modification',
        severity: 0.85,
        description: `Security setting modified: ${change.name}`
      });
      this.stats.securityModifications++;
    }
    
    // 5. Check for debugger hijacking (IFEO)
    if (keyInfo.category === 'ifeo' && change.name.toLowerCase() === 'debugger') {
      threats.push({
        type: 'debugger_hijacking',
        severity: 0.95,
        description: `Debugger hijacking attempt detected`
      });
    }
    
    // 6. Check for AppInit DLL injection
    if (keyInfo.category === 'appInit' && 
        this.suspiciousValueNames.has(change.name.toLowerCase())) {
      threats.push({
        type: 'dll_injection',
        severity: 0.9,
        description: `DLL injection via ${change.name}`
      });
    }
    
    // 7. Check for browser extension modification
    if (keyInfo.category === 'browser' && change.type === 'value_added') {
      threats.push({
        type: 'browser_extension',
        severity: 0.6,
        description: `Browser extension added: ${change.name}`
      });
    }
    
    // 8. Heuristic checks
    if (this.config.enableHeuristics) {
      const heuristic = this.performHeuristicAnalysis(path, change);
      if (heuristic) threats.push(heuristic);
    }
    
    // Return highest severity threat
    return threats.reduce((max, t) => 
      t.severity > (max?.severity || 0) ? t : max, null);
  }

  /**
   * Perform heuristic analysis on registry change
   */
  performHeuristicAnalysis(path, change) {
    // Check for suspicious file paths in values
    if (typeof change.value === 'string') {
      const value = change.value.toLowerCase();
      
      // Check for temp directory executables
      if (value.includes('\\temp\\') && value.includes('.exe')) {
        return {
          type: 'suspicious_path',
          severity: 0.7,
          description: 'Registry value points to temp directory executable'
        };
      }
      
      // Check for obfuscated paths
      if (value.includes('..\\') || value.match(/[^\x20-\x7E]/)) {
        return {
          type: 'obfuscated_path',
          severity: 0.65,
          description: 'Registry value contains obfuscated path'
        };
      }
      
      // Check for PowerShell/script execution
      if (value.includes('powershell') || value.includes('wscript') || 
          value.includes('cscript')) {
        return {
          type: 'script_execution',
          severity: 0.6,
          description: 'Registry value executes script'
        };
      }
    }
    
    return null;
  }

  /**
   * Handle detected threat
   */
  handleThreat(path, change, threat) {
    const detection = {
      id: `registry_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      path,
      change,
      threat,
      timestamp: new Date().toISOString(),
      action: 'logged'
    };
    
    this.detectedChanges.push(detection);
    
    if (threat.type.includes('persistence')) {
      this.persistenceAttempts.push(detection);
    }
    
    console.warn(`🚨 REGISTRY THREAT DETECTED`);
    console.warn(`   Path: ${path}`);
    console.warn(`   Type: ${threat.type}`);
    console.warn(`   Severity: ${(threat.severity * 100).toFixed(0)}%`);
    console.warn(`   Description: ${threat.description}`);
    console.warn(`   Change: ${change.type} - ${change.name}`);
    
    // Emit event
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('registry_threat_detected', {
        detail: detection
      }));
    }
  }

  /**
   * Log benign change
   */
  logChange(path, change) {
    this.detectedChanges.push({
      path,
      change,
      threat: null,
      timestamp: new Date().toISOString()
    });
    
    // Keep only recent changes
    if (this.detectedChanges.length > 1000) {
      this.detectedChanges = this.detectedChanges.slice(-500);
    }
  }

  /**
   * Read registry key values (mock - would use native API)
   */
  async readRegistryKey(path) {
    // This would integrate with Windows Registry API via native module
    // For now, return mock data
    return {};
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      monitoredKeys: this.monitoredKeys.size,
      activePersistence: this.persistenceAttempts.filter(p =>
        Date.now() - new Date(p.timestamp).getTime() < 300000 // 5 minutes
      ).length
    };
  }

  /**
   * Get recent changes
   */
  getRecentChanges(limit = 20) {
    return this.detectedChanges.slice(-limit).reverse();
  }

  /**
   * Get persistence attempts
   */
  getPersistenceAttempts(limit = 10) {
    return this.persistenceAttempts.slice(-limit).reverse();
  }

  /**
   * Get monitored keys info
   */
  getMonitoredKeys() {
    return Array.from(this.monitoredKeys.entries()).map(([path, info]) => ({
      path,
      ...info
    }));
  }

  /**
   * Add custom registry path to monitor
   */
  async addMonitoredPath(path, category = 'custom') {
    try {
      const values = await this.readRegistryKey(path);
      this.baseline.set(path, values);
      this.monitoredKeys.set(path, {
        category,
        lastCheck: Date.now(),
        changeCount: 0
      });
      console.log(`Added monitoring for: ${path}`);
    } catch (error) {
      console.error(`Failed to add monitoring for ${path}:`, error);
    }
  }

  /**
   * Remove monitored path
   */
  removeMonitoredPath(path) {
    this.baseline.delete(path);
    this.monitoredKeys.delete(path);
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Restart if check interval changed
    if (newConfig.checkInterval && this.isMonitoring) {
      this.stop();
      this.start();
    }
  }

  /**
   * Reset baseline
   */
  async resetBaseline() {
    this.baseline.clear();
    await this.createBaseline();
  }
}

// Export singleton
const registryMonitor = new RegistryMonitor();
export default registryMonitor;
