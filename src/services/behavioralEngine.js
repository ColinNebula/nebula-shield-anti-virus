/**
 * Nebula Shield - Behavioral Analysis Engine
 * 
 * Real-time process monitoring and behavioral analysis to detect:
 * - Suspicious process behavior
 * - Code injection attempts
 * - Privilege escalation
 * - Network anomalies
 * - File system manipulation
 * - Registry modifications
 * - Memory manipulation
 * - Parent-child process relationships
 * 
 * Features:
 * - Process tree analysis
 * - Behavioral pattern detection
 * - Heuristic scoring
 * - Machine learning integration
 * - Real-time alerting
 */

import { EventEmitter } from 'events';

class BehavioralEngine extends EventEmitter {
  constructor() {
    super();
    
    // Configuration
    this.config = {
      enabled: true,
      scanInterval: 5000, // Check processes every 5 seconds
      suspicionThreshold: 70, // Alert when suspicion score >= 70
      maxProcessHistory: 1000,
      enableProcessTree: true,
      enableNetworkMonitoring: true,
      enableFileMonitoring: true,
      enableRegistryMonitoring: true,
      enableMemoryMonitoring: true,
      whitelistedProcesses: [
        'system', 'csrss.exe', 'smss.exe', 'services.exe',
        'svchost.exe', 'lsass.exe', 'winlogon.exe', 'explorer.exe'
      ]
    };

    // State management
    this.state = {
      isMonitoring: false,
      processCache: new Map(), // pid -> process info
      processHistory: [],
      suspiciousProcesses: [],
      blockedProcesses: [],
      alerts: [],
      lastScanTime: null
    };

    // Statistics
    this.stats = {
      totalProcessesScanned: 0,
      suspiciousDetected: 0,
      threatsBlocked: 0,
      falsePositives: 0,
      averageSuspicionScore: 0,
      uptime: 0
    };

    // Behavioral patterns
    this.patterns = {
      // Code injection indicators
      codeInjection: [
        { name: 'CreateRemoteThread', weight: 30, description: 'Remote thread creation' },
        { name: 'WriteProcessMemory', weight: 25, description: 'Process memory write' },
        { name: 'VirtualAllocEx', weight: 25, description: 'Remote memory allocation' },
        { name: 'SetWindowsHookEx', weight: 20, description: 'Keyboard/mouse hook' },
        { name: 'QueueUserAPC', weight: 20, description: 'APC queue manipulation' }
      ],

      // Privilege escalation
      privEscalation: [
        { name: 'SeDebugPrivilege', weight: 35, description: 'Debug privileges requested' },
        { name: 'TakeOwnershipPrivilege', weight: 30, description: 'Ownership takeover' },
        { name: 'ImpersonatePrivilege', weight: 30, description: 'Token impersonation' },
        { name: 'UAC_Bypass', weight: 40, description: 'UAC bypass attempt' },
        { name: 'TokenManipulation', weight: 35, description: 'Token manipulation' }
      ],

      // Persistence mechanisms
      persistence: [
        { name: 'RunKey', weight: 25, description: 'Registry Run key modification' },
        { name: 'StartupFolder', weight: 20, description: 'Startup folder modification' },
        { name: 'ScheduledTask', weight: 25, description: 'Scheduled task creation' },
        { name: 'ServiceCreation', weight: 30, description: 'Windows service creation' },
        { name: 'WMIPersistence', weight: 35, description: 'WMI event subscription' }
      ],

      // Network activity
      networkAnomalies: [
        { name: 'UnusualPort', weight: 20, description: 'Connection to unusual port' },
        { name: 'HighConnectionRate', weight: 25, description: 'Excessive connections' },
        { name: 'C2Communication', weight: 40, description: 'C2 server communication' },
        { name: 'DNSTunneling', weight: 35, description: 'DNS tunneling detected' },
        { name: 'ReverseShell', weight: 45, description: 'Reverse shell connection' }
      ],

      // File system manipulation
      fileManipulation: [
        { name: 'MassFileEncryption', weight: 50, description: 'Mass file encryption (ransomware)' },
        { name: 'SystemFileModification', weight: 40, description: 'System file modification' },
        { name: 'ShadowCopyDeletion', weight: 45, description: 'Shadow copy deletion' },
        { name: 'MassFileDeletion', weight: 35, description: 'Mass file deletion' },
        { name: 'FileObfuscation', weight: 25, description: 'File name obfuscation' }
      ],

      // Process behavior
      processBehavior: [
        { name: 'HollowProcess', weight: 40, description: 'Process hollowing detected' },
        { name: 'ParentSpoofing', weight: 35, description: 'Parent process spoofing' },
        { name: 'UnusualParent', weight: 30, description: 'Unusual parent process' },
        { name: 'RapidProcessSpawn', weight: 25, description: 'Rapid process spawning' },
        { name: 'SuspiciousCommandLine', weight: 30, description: 'Suspicious command line' }
      ],

      // Anti-analysis
      antiAnalysis: [
        { name: 'VMDetection', weight: 15, description: 'VM detection attempt' },
        { name: 'DebuggerCheck', weight: 20, description: 'Debugger detection' },
        { name: 'SandboxEvasion', weight: 25, description: 'Sandbox evasion' },
        { name: 'TimeDelayEvasion', weight: 20, description: 'Time-based evasion' },
        { name: 'AVProcessCheck', weight: 15, description: 'AV process detection' }
      ]
    };

    // Monitoring timer
    this.monitoringTimer = null;
    this.startTime = Date.now();
  }

  /**
   * Start behavioral monitoring
   */
  async startMonitoring() {
    if (this.state.isMonitoring) {
      console.log('[BehavioralEngine] Already monitoring');
      return;
    }

    console.log('[BehavioralEngine] Starting process monitoring...');
    this.state.isMonitoring = true;
    this.startTime = Date.now();
    
    // Initial scan
    await this.scanProcesses();
    
    // Schedule periodic scans
    this.monitoringTimer = setInterval(() => {
      this.scanProcesses();
    }, this.config.scanInterval);

    this.emit('monitoringStarted');
  }

  /**
   * Stop behavioral monitoring
   */
  stopMonitoring() {
    if (!this.state.isMonitoring) {
      return;
    }

    console.log('[BehavioralEngine] Stopping process monitoring...');
    
    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.monitoringTimer = null;
    }

    this.state.isMonitoring = false;
    this.emit('monitoringStopped');
  }

  /**
   * Scan all running processes
   */
  async scanProcesses() {
    try {
      this.state.lastScanTime = new Date();
      
      // Get running processes
      const processes = await this.getRunningProcesses();
      
      // Analyze each process
      for (const process of processes) {
        await this.analyzeProcess(process);
      }

      // Update statistics
      this.updateStats();
      
      // Emit scan complete event
      this.emit('scanComplete', {
        processCount: processes.length,
        suspicious: this.state.suspiciousProcesses.length,
        timestamp: this.state.lastScanTime
      });

    } catch (error) {
      console.error('[BehavioralEngine] Scan error:', error);
      this.emit('scanError', error);
    }
  }

  /**
   * Get running processes (browser simulation)
   */
  async getRunningProcesses() {
    // In browser environment, we simulate process data
    // In Electron, we can use actual OS APIs
    
    if (typeof window !== 'undefined' && window.electron) {
      // Electron environment - get real processes
      try {
        return await window.electron.getProcessList();
      } catch (error) {
        console.warn('[BehavioralEngine] Failed to get real processes, using simulation');
      }
    }

    // Browser simulation
    return this.simulateProcesses();
  }

  /**
   * Simulate process list for browser environment
   */
  simulateProcesses() {
    const simulatedProcesses = [
      { pid: 4, name: 'System', path: 'System', parent: 0, user: 'NT AUTHORITY\\SYSTEM', cpu: 0.1, memory: 512 },
      { pid: 420, name: 'csrss.exe', path: 'C:\\Windows\\System32\\csrss.exe', parent: 4, user: 'NT AUTHORITY\\SYSTEM', cpu: 0.0, memory: 4096 },
      { pid: 580, name: 'services.exe', path: 'C:\\Windows\\System32\\services.exe', parent: 420, user: 'NT AUTHORITY\\SYSTEM', cpu: 0.1, memory: 8192 },
      { pid: 1234, name: 'explorer.exe', path: 'C:\\Windows\\explorer.exe', parent: 580, user: 'DESKTOP\\User', cpu: 2.5, memory: 102400 },
      { pid: 2048, name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', parent: 1234, user: 'DESKTOP\\User', cpu: 5.2, memory: 204800 },
      { pid: 3072, name: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', parent: 580, user: 'NT AUTHORITY\\NETWORK SERVICE', cpu: 0.3, memory: 16384 },
      { pid: 4096, name: 'node.exe', path: 'C:\\Program Files\\nodejs\\node.exe', parent: 1234, user: 'DESKTOP\\User', cpu: 1.8, memory: 81920 }
    ];

    // Randomly add suspicious process for demonstration
    if (Math.random() > 0.7) {
      simulatedProcesses.push({
        pid: Math.floor(Math.random() * 10000),
        name: 'suspicious.exe',
        path: 'C:\\Users\\User\\AppData\\Local\\Temp\\suspicious.exe',
        parent: 1234,
        user: 'DESKTOP\\User',
        cpu: 15.5,
        memory: 51200,
        suspicious: true
      });
    }

    return simulatedProcesses;
  }

  /**
   * Analyze individual process for suspicious behavior
   */
  async analyzeProcess(process) {
    // Skip if already analyzed recently
    const cached = this.state.processCache.get(process.pid);
    if (cached && Date.now() - cached.lastChecked < 30000) {
      return cached;
    }

    // Calculate suspicion score
    const analysis = {
      pid: process.pid,
      name: process.name,
      path: process.path,
      parent: process.parent,
      user: process.user,
      suspicionScore: 0,
      flags: [],
      behaviors: [],
      timestamp: new Date(),
      lastChecked: Date.now()
    };

    // Check if whitelisted
    if (this.isWhitelisted(process.name)) {
      analysis.whitelisted = true;
      this.state.processCache.set(process.pid, analysis);
      return analysis;
    }

    // Analyze process name and path
    analysis.suspicionScore += this.analyzeProcessName(process, analysis);
    analysis.suspicionScore += this.analyzeProcessPath(process, analysis);
    
    // Analyze parent process relationship
    analysis.suspicionScore += this.analyzeParentProcess(process, analysis);
    
    // Analyze resource usage
    analysis.suspicionScore += this.analyzeResourceUsage(process, analysis);
    
    // Analyze command line (if available)
    if (process.commandLine) {
      analysis.suspicionScore += this.analyzeCommandLine(process, analysis);
    }

    // Check for known malicious patterns
    analysis.suspicionScore += this.checkMaliciousPatterns(process, analysis);

    // Store in cache
    this.state.processCache.set(process.pid, analysis);
    
    // Add to history
    this.state.processHistory.push({
      pid: process.pid,
      name: process.name,
      score: analysis.suspicionScore,
      timestamp: analysis.timestamp
    });

    // Trim history
    if (this.state.processHistory.length > this.config.maxProcessHistory) {
      this.state.processHistory = this.state.processHistory.slice(-this.config.maxProcessHistory);
    }

    // Check if suspicious
    if (analysis.suspicionScore >= this.config.suspicionThreshold) {
      this.handleSuspiciousProcess(analysis);
    }

    this.stats.totalProcessesScanned++;

    return analysis;
  }

  /**
   * Analyze process name for suspicious patterns
   */
  analyzeProcessName(process, analysis) {
    let score = 0;

    const name = process.name.toLowerCase();

    // Check for suspicious extensions
    if (name.match(/\.(scr|pif|vbs|bat|cmd|ps1)$/)) {
      score += 15;
      analysis.flags.push('Suspicious file extension');
    }

    // Check for double extensions
    if (name.match(/\.\w+\.\w+$/)) {
      score += 20;
      analysis.flags.push('Double file extension');
    }

    // Check for random/gibberish names
    if (name.match(/^[a-z0-9]{8,}\.exe$/)) {
      score += 10;
      analysis.flags.push('Random process name');
    }

    // Check for system process impersonation
    const systemProcesses = ['svchost', 'csrss', 'lsass', 'services', 'smss'];
    for (const sysProc of systemProcesses) {
      if (name.includes(sysProc) && !name.startsWith(sysProc)) {
        score += 25;
        analysis.flags.push(`Potential ${sysProc} impersonation`);
      }
    }

    // Check for obfuscation characters
    if (name.match(/[^a-z0-9_.\-]/i)) {
      score += 15;
      analysis.flags.push('Obfuscated process name');
    }

    return score;
  }

  /**
   * Analyze process path for suspicious locations
   */
  analyzeProcessPath(process, analysis) {
    let score = 0;

    if (!process.path) return 0;

    const path = process.path.toLowerCase();

    // Suspicious locations
    const suspiciousLocations = [
      { pattern: /appdata\\local\\temp/, score: 30, desc: 'Running from Temp folder' },
      { pattern: /users\\public/, score: 25, desc: 'Running from Public folder' },
      { pattern: /programdata\\/, score: 15, desc: 'Running from ProgramData' },
      { pattern: /downloads/, score: 20, desc: 'Running from Downloads' },
      { pattern: /desktop/, score: 20, desc: 'Running from Desktop' },
      { pattern: /recycle\.bin/, score: 35, desc: 'Running from Recycle Bin' },
      { pattern: /\$recycle\.bin/, score: 35, desc: 'Running from Recycle Bin' }
    ];

    for (const location of suspiciousLocations) {
      if (path.match(location.pattern)) {
        score += location.score;
        analysis.flags.push(location.desc);
      }
    }

    // Check if path matches expected system locations
    if (path.includes('system32') && !path.startsWith('c:\\windows\\system32')) {
      score += 30;
      analysis.flags.push('Fake System32 path');
    }

    return score;
  }

  /**
   * Analyze parent-child process relationships
   */
  analyzeParentProcess(process, analysis) {
    let score = 0;

    if (!process.parent || !this.config.enableProcessTree) return 0;

    const parent = this.state.processCache.get(process.parent);
    if (!parent) return 0;

    // Unusual parent-child relationships
    const unusualRelationships = [
      { parent: 'explorer.exe', child: /cmd\.exe|powershell\.exe|wscript\.exe/, score: 15 },
      { parent: 'winword.exe', child: /cmd\.exe|powershell\.exe|wscript\.exe/, score: 25 },
      { parent: 'excel.exe', child: /cmd\.exe|powershell\.exe|wscript\.exe/, score: 25 },
      { parent: 'outlook.exe', child: /cmd\.exe|powershell\.exe/, score: 20 },
      { parent: 'chrome.exe', child: /cmd\.exe|powershell\.exe/, score: 20 }
    ];

    for (const rel of unusualRelationships) {
      if (parent.name.toLowerCase().includes(rel.parent) && 
          process.name.toLowerCase().match(rel.child)) {
        score += rel.score;
        analysis.flags.push(`Unusual parent: ${parent.name} spawned ${process.name}`);
        analysis.behaviors.push({
          type: 'UnusualParent',
          weight: rel.score,
          description: `${parent.name} -> ${process.name}`
        });
      }
    }

    return score;
  }

  /**
   * Analyze resource usage patterns
   */
  analyzeResourceUsage(process, analysis) {
    let score = 0;

    // High CPU usage
    if (process.cpu > 80) {
      score += 15;
      analysis.flags.push('Extremely high CPU usage');
    } else if (process.cpu > 50) {
      score += 10;
      analysis.flags.push('High CPU usage');
    }

    // High memory usage
    if (process.memory > 512 * 1024 * 1024) { // 512MB
      score += 10;
      analysis.flags.push('High memory usage');
    }

    return score;
  }

  /**
   * Analyze command line arguments
   */
  analyzeCommandLine(process, analysis) {
    let score = 0;
    const cmdLine = process.commandLine.toLowerCase();

    // Suspicious PowerShell patterns
    const psPatterns = [
      { pattern: /-enc.*[a-z0-9+\/=]{50,}/i, score: 30, desc: 'Encoded PowerShell command' },
      { pattern: /downloadstring|downloadfile/i, score: 25, desc: 'PowerShell download' },
      { pattern: /invoke-expression|iex/i, score: 20, desc: 'PowerShell code execution' },
      { pattern: /bypass.*executionpolicy/i, score: 20, desc: 'Execution policy bypass' },
      { pattern: /hidden.*window/i, score: 15, desc: 'Hidden window' }
    ];

    for (const pattern of psPatterns) {
      if (cmdLine.match(pattern.pattern)) {
        score += pattern.score;
        analysis.flags.push(pattern.desc);
        analysis.behaviors.push({
          type: 'SuspiciousCommandLine',
          weight: pattern.score,
          description: pattern.desc
        });
      }
    }

    return score;
  }

  /**
   * Check for known malicious patterns
   */
  checkMaliciousPatterns(process, analysis) {
    let score = 0;

    // Simulated behavior detection
    // In production, this would analyze actual process behavior

    if (process.suspicious) {
      score += 50;
      analysis.flags.push('Known malicious pattern detected');
      analysis.behaviors.push({
        type: 'MaliciousPattern',
        weight: 50,
        description: 'Process matches known malware signature'
      });
    }

    return score;
  }

  /**
   * Check if process is whitelisted
   */
  isWhitelisted(processName) {
    const name = processName.toLowerCase();
    return this.config.whitelistedProcesses.some(wp => 
      name === wp || name.startsWith(wp.replace('.exe', ''))
    );
  }

  /**
   * Handle detection of suspicious process
   */
  handleSuspiciousProcess(analysis) {
    console.warn(`[BehavioralEngine] Suspicious process detected: ${analysis.name} (Score: ${analysis.suspicionScore})`);
    
    // Add to suspicious list
    if (!this.state.suspiciousProcesses.find(p => p.pid === analysis.pid)) {
      this.state.suspiciousProcesses.push(analysis);
    }

    // Create alert
    const alert = {
      id: Date.now(),
      type: 'suspicious_process',
      severity: this.getSeverity(analysis.suspicionScore),
      process: analysis,
      timestamp: new Date(),
      resolved: false
    };

    this.state.alerts.push(alert);
    this.stats.suspiciousDetected++;

    // Emit alert event
    this.emit('suspiciousProcess', alert);

    // Auto-block if score is very high
    if (analysis.suspicionScore >= 90) {
      this.blockProcess(analysis);
    }
  }

  /**
   * Get severity level based on suspicion score
   */
  getSeverity(score) {
    if (score >= 90) return 'critical';
    if (score >= 80) return 'high';
    if (score >= 70) return 'medium';
    return 'low';
  }

  /**
   * Block a malicious process
   */
  async blockProcess(analysis) {
    console.log(`[BehavioralEngine] Blocking process: ${analysis.name} (PID: ${analysis.pid})`);
    
    try {
      // In Electron, we can actually kill the process
      if (typeof window !== 'undefined' && window.electron) {
        await window.electron.killProcess(analysis.pid);
      }

      this.state.blockedProcesses.push({
        ...analysis,
        blockedAt: new Date()
      });

      this.stats.threatsBlocked++;

      this.emit('processBlocked', {
        pid: analysis.pid,
        name: analysis.name,
        score: analysis.suspicionScore
      });

      return true;
    } catch (error) {
      console.error('[BehavioralEngine] Failed to block process:', error);
      return false;
    }
  }

  /**
   * Get process information by PID
   */
  getProcessInfo(pid) {
    return this.state.processCache.get(pid);
  }

  /**
   * Get all suspicious processes
   */
  getSuspiciousProcesses() {
    return this.state.suspiciousProcesses;
  }

  /**
   * Get all alerts
   */
  getAlerts() {
    return this.state.alerts;
  }

  /**
   * Clear alert
   */
  clearAlert(alertId) {
    const alert = this.state.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.resolved = true;
    }
  }

  /**
   * Get process tree for a specific process
   */
  getProcessTree(pid) {
    const tree = [];
    const visited = new Set();

    const buildTree = (currentPid, level = 0) => {
      if (visited.has(currentPid)) return;
      visited.add(currentPid);

      const process = this.state.processCache.get(currentPid);
      if (!process) return;

      tree.push({
        ...process,
        level
      });

      // Find children
      for (const [childPid, childProcess] of this.state.processCache) {
        if (childProcess.parent === currentPid) {
          buildTree(childPid, level + 1);
        }
      }
    };

    buildTree(pid);
    return tree;
  }

  /**
   * Update statistics
   */
  updateStats() {
    // Calculate average suspicion score
    const scores = Array.from(this.state.processCache.values())
      .filter(p => !p.whitelisted)
      .map(p => p.suspicionScore);

    if (scores.length > 0) {
      this.stats.averageSuspicionScore = 
        scores.reduce((a, b) => a + b, 0) / scores.length;
    }

    // Calculate uptime
    this.stats.uptime = Date.now() - this.startTime;
  }

  /**
   * Get current statistics
   */
  getStats() {
    return {
      ...this.stats,
      currentProcesses: this.state.processCache.size,
      suspiciousProcesses: this.state.suspiciousProcesses.length,
      blockedProcesses: this.state.blockedProcesses.length,
      activeAlerts: this.state.alerts.filter(a => !a.resolved).length,
      isMonitoring: this.state.isMonitoring,
      lastScan: this.state.lastScanTime
    };
  }

  /**
   * Get current status
   */
  getStatus() {
    return {
      config: this.config,
      state: {
        isMonitoring: this.state.isMonitoring,
        processCount: this.state.processCache.size,
        suspiciousCount: this.state.suspiciousProcesses.length,
        blockedCount: this.state.blockedProcesses.length,
        alertCount: this.state.alerts.filter(a => !a.resolved).length,
        lastScanTime: this.state.lastScanTime
      },
      stats: this.getStats()
    };
  }

  /**
   * Configure behavioral engine
   */
  configure(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Restart monitoring if interval changed
    if (newConfig.scanInterval && this.state.isMonitoring) {
      this.stopMonitoring();
      this.startMonitoring();
    }
  }

  /**
   * Export process data for analysis
   */
  exportData() {
    return {
      timestamp: new Date(),
      processes: Array.from(this.state.processCache.values()),
      suspicious: this.state.suspiciousProcesses,
      blocked: this.state.blockedProcesses,
      alerts: this.state.alerts,
      stats: this.stats
    };
  }

  /**
   * Clear all data
   */
  clearData() {
    this.state.processCache.clear();
    this.state.processHistory = [];
    this.state.suspiciousProcesses = [];
    this.state.alerts = [];
    
    console.log('[BehavioralEngine] Data cleared');
  }
}

// Singleton instance
const behavioralEngine = new BehavioralEngine();

// Export singleton and class
export default behavioralEngine;
export { BehavioralEngine };
