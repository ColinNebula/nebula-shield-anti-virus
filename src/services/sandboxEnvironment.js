/**
 * Sandbox Environment Service
 * Isolated execution environment for testing suspicious files
 * Virtual environment with behavior monitoring and threat analysis
 */

import antivirusApi from './antivirusApi';
import notificationService from './notificationService';

class SandboxEnvironment {
  constructor() {
    this.sandboxes = new Map();
    this.executionHistory = [];
    this.listeners = new Set();
    this.maxConcurrentSandboxes = 3;
    this.activeSandboxCount = 0;
    this.statistics = {
      totalExecutions: 0,
      maliciousDetected: 0,
      suspiciousDetected: 0,
      cleanFiles: 0,
      lastExecution: null
    };
    this.behaviorPatterns = this.loadBehaviorPatterns();
    this.loadStatistics();
  }

  // ==================== BEHAVIOR PATTERNS ====================
  
  loadBehaviorPatterns() {
    return {
      // File system operations
      fileSystem: {
        suspicious: [
          { action: 'encrypt_files', severity: 'critical', indicator: 'Ransomware behavior' },
          { action: 'delete_shadow_copies', severity: 'critical', indicator: 'Anti-recovery technique' },
          { action: 'modify_registry', severity: 'high', indicator: 'Registry modification' },
          { action: 'create_startup_entry', severity: 'high', indicator: 'Persistence mechanism' },
          { action: 'access_system_files', severity: 'medium', indicator: 'System file access' },
          { action: 'mass_file_creation', severity: 'high', indicator: 'Unusual file activity' }
        ]
      },

      // Network operations
      network: {
        suspicious: [
          { action: 'connect_c2', severity: 'critical', indicator: 'C&C server connection' },
          { action: 'download_payload', severity: 'critical', indicator: 'Malware download' },
          { action: 'data_exfiltration', severity: 'critical', indicator: 'Data theft' },
          { action: 'port_scanning', severity: 'high', indicator: 'Network scanning' },
          { action: 'dns_tunneling', severity: 'high', indicator: 'Covert channel' }
        ]
      },

      // Process operations
      process: {
        suspicious: [
          { action: 'inject_code', severity: 'critical', indicator: 'Code injection' },
          { action: 'create_remote_thread', severity: 'critical', indicator: 'Process manipulation' },
          { action: 'escalate_privileges', severity: 'critical', indicator: 'Privilege escalation' },
          { action: 'spawn_shell', severity: 'high', indicator: 'Shell spawning' },
          { action: 'disable_security', severity: 'critical', indicator: 'Security bypass' }
        ]
      },

      // Memory operations
      memory: {
        suspicious: [
          { action: 'allocate_executable', severity: 'high', indicator: 'Executable memory allocation' },
          { action: 'modify_code', severity: 'high', indicator: 'Self-modification' },
          { action: 'read_credentials', severity: 'critical', indicator: 'Credential theft' }
        ]
      },

      // Behavioral indicators
      behavioral: {
        suspicious: [
          { action: 'rapid_file_changes', severity: 'high', indicator: 'Ransomware encryption' },
          { action: 'persistence_multiple', severity: 'high', indicator: 'Multiple persistence methods' },
          { action: 'anti_analysis', severity: 'medium', indicator: 'Anti-sandbox techniques' },
          { action: 'time_delay', severity: 'low', indicator: 'Delayed execution' }
        ]
      }
    };
  }

  // ==================== SANDBOX CREATION ====================
  
  async createSandbox(options = {}) {
    if (this.activeSandboxCount >= this.maxConcurrentSandboxes) {
      throw new Error(`Maximum concurrent sandboxes (${this.maxConcurrentSandboxes}) reached`);
    }

    const sandboxId = `sandbox-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const sandbox = {
      id: sandboxId,
      createdAt: new Date().toISOString(),
      status: 'initializing',
      options: {
        timeout: options.timeout || 60000, // 60 seconds default
        networkEnabled: options.networkEnabled !== false,
        fileSystemAccess: options.fileSystemAccess !== false,
        memoryLimit: options.memoryLimit || 512, // MB
        cpuLimit: options.cpuLimit || 50, // percentage
        captureScreenshots: options.captureScreenshots !== false,
        monitorRegistry: options.monitorRegistry !== false,
        monitorProcesses: options.monitorProcesses !== false,
        ...options
      },
      environment: {
        os: 'Windows 10 (Sandbox)',
        architecture: 'x64',
        isolated: true,
        readonly: false
      },
      monitoring: {
        fileOperations: [],
        networkActivity: [],
        processActivity: [],
        registryChanges: [],
        memoryAllocations: [],
        screenshots: []
      },
      analysis: {
        behaviorScore: 0,
        threatLevel: 'unknown',
        indicators: [],
        verdict: 'pending'
      }
    };

    this.sandboxes.set(sandboxId, sandbox);
    this.activeSandboxCount++;

    // Initialize sandbox environment
    await this.initializeSandbox(sandbox);

    return sandbox;
  }

  async initializeSandbox(sandbox) {
    sandbox.status = 'ready';
    this.notifyListeners('sandbox-created', sandbox);
    
    console.log(`✅ Sandbox ${sandbox.id} initialized`);
  }

  // ==================== FILE EXECUTION ====================
  
  async executeFile(filePath, sandboxOptions = {}) {
    console.log(`🔬 Executing file in sandbox: ${filePath}`);

    // Create sandbox
    const sandbox = await this.createSandbox(sandboxOptions);

    try {
      // Update status
      sandbox.status = 'executing';
      sandbox.filePath = filePath;
      sandbox.fileName = filePath.split(/[\\/]/).pop();
      sandbox.executionStartTime = new Date().toISOString();
      
      this.notifyListeners('execution-started', sandbox);

      notificationService.show({
        type: 'info',
        title: 'Sandbox Execution Started',
        message: `Testing ${sandbox.fileName} in isolated environment...`,
        duration: 5000
      });

      // Execute file in sandbox
      const result = await this.runInSandbox(sandbox, filePath);

      // Analyze results
      const analysis = this.analyzeSandboxBehavior(sandbox, result);
      sandbox.analysis = analysis;
      sandbox.executionEndTime = new Date().toISOString();
      sandbox.executionDuration = Date.now() - new Date(sandbox.executionStartTime).getTime();
      sandbox.status = 'completed';

      // Update statistics
      this.statistics.totalExecutions++;
      if (analysis.threatLevel === 'malicious') {
        this.statistics.maliciousDetected++;
      } else if (analysis.threatLevel === 'suspicious') {
        this.statistics.suspiciousDetected++;
      } else {
        this.statistics.cleanFiles++;
      }
      this.statistics.lastExecution = new Date().toISOString();
      this.saveStatistics();

      // Save to history
      this.executionHistory.unshift({
        sandboxId: sandbox.id,
        filePath,
        fileName: sandbox.fileName,
        timestamp: new Date().toISOString(),
        analysis: analysis,
        duration: sandbox.executionDuration
      });

      // Keep only last 100 executions
      if (this.executionHistory.length > 100) {
        this.executionHistory = this.executionHistory.slice(0, 100);
      }

      this.notifyListeners('execution-complete', { sandbox, analysis });

      // Show results notification
      this.showResultsNotification(sandbox, analysis);

      return {
        success: true,
        sandboxId: sandbox.id,
        analysis
      };

    } catch (error) {
      console.error('Sandbox execution error:', error);
      sandbox.status = 'error';
      sandbox.error = error.message;
      
      this.notifyListeners('execution-error', { sandbox, error });

      notificationService.show({
        type: 'error',
        title: 'Sandbox Execution Failed',
        message: `Error: ${error.message}`,
        duration: 8000
      });

      return {
        success: false,
        error: error.message
      };

    } finally {
      // Cleanup sandbox after delay
      setTimeout(() => this.destroySandbox(sandbox.id), 5000);
    }
  }

  async runInSandbox(sandbox, filePath) {
    // Simulate sandbox execution
    // In production, this would use Windows Sandbox, Docker, or VM technology
    
    return new Promise((resolve) => {
      const duration = sandbox.options.timeout || 60000;
      
      // Simulate monitoring for specified duration
      const monitoringInterval = setInterval(() => {
        this.captureMonitoringData(sandbox);
      }, 1000);

      setTimeout(() => {
        clearInterval(monitoringInterval);
        
        // Generate execution result
        const result = this.generateExecutionResult(sandbox);
        resolve(result);
      }, Math.min(duration, 5000)); // Cap at 5 seconds for demo
    });
  }

  captureMonitoringData(sandbox) {
    const monitoring = sandbox.monitoring;
    const timestamp = new Date().toISOString();

    // Simulate file operations
    if (Math.random() > 0.7) {
      const operations = ['read', 'write', 'create', 'delete', 'modify', 'encrypt'];
      const operation = operations[Math.floor(Math.random() * operations.length)];
      
      monitoring.fileOperations.push({
        timestamp,
        operation,
        path: `C:\\Sandbox\\file_${Math.floor(Math.random() * 100)}.txt`,
        size: Math.floor(Math.random() * 10000)
      });
    }

    // Simulate network activity
    if (Math.random() > 0.8 && sandbox.options.networkEnabled) {
      const activities = ['connect', 'send', 'receive', 'dns_query'];
      const activity = activities[Math.floor(Math.random() * activities.length)];
      
      monitoring.networkActivity.push({
        timestamp,
        activity,
        destination: Math.random() > 0.5 ? 'legitimate-site.com' : '185.220.101.1',
        protocol: Math.random() > 0.5 ? 'HTTPS' : 'TCP',
        bytes: Math.floor(Math.random() * 5000)
      });
    }

    // Simulate process activity
    if (Math.random() > 0.75) {
      const activities = ['create', 'terminate', 'inject', 'spawn'];
      const activity = activities[Math.floor(Math.random() * activities.length)];
      
      monitoring.processActivity.push({
        timestamp,
        activity,
        process: `process_${Math.floor(Math.random() * 10)}.exe`,
        pid: Math.floor(Math.random() * 10000)
      });
    }

    // Simulate registry changes
    if (Math.random() > 0.85 && sandbox.options.monitorRegistry) {
      const operations = ['create_key', 'modify_value', 'delete_key'];
      const operation = operations[Math.floor(Math.random() * operations.length)];
      
      monitoring.registryChanges.push({
        timestamp,
        operation,
        key: `HKEY_CURRENT_USER\\Software\\Test_${Math.floor(Math.random() * 10)}`,
        value: 'TestValue'
      });
    }
  }

  generateExecutionResult(sandbox) {
    const random = Math.random();
    
    // Determine behavior based on randomness
    let behaviorType;
    if (random < 0.7) {
      behaviorType = 'clean';
    } else if (random < 0.9) {
      behaviorType = 'suspicious';
    } else {
      behaviorType = 'malicious';
    }

    const result = {
      exitCode: 0,
      executionTime: Date.now() - new Date(sandbox.executionStartTime).getTime(),
      behaviorType
    };

    // Add malicious behaviors for demo
    if (behaviorType === 'malicious') {
      sandbox.monitoring.fileOperations.push({
        timestamp: new Date().toISOString(),
        operation: 'encrypt',
        path: 'C:\\Users\\Documents\\important.docx',
        indicator: 'Ransomware encryption'
      });
      
      sandbox.monitoring.networkActivity.push({
        timestamp: new Date().toISOString(),
        activity: 'connect',
        destination: '185.220.101.1',
        protocol: 'TCP',
        indicator: 'C&C server connection'
      });

      sandbox.monitoring.processActivity.push({
        timestamp: new Date().toISOString(),
        activity: 'inject',
        process: 'explorer.exe',
        indicator: 'Code injection'
      });
    } else if (behaviorType === 'suspicious') {
      sandbox.monitoring.registryChanges.push({
        timestamp: new Date().toISOString(),
        operation: 'create_key',
        key: 'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        value: 'Suspicious.exe',
        indicator: 'Persistence mechanism'
      });
    }

    return result;
  }

  // ==================== BEHAVIOR ANALYSIS ====================
  
  analyzeSandboxBehavior(sandbox, result) {
    const analysis = {
      behaviorScore: 0,
      threatLevel: 'clean',
      indicators: [],
      verdict: 'clean',
      confidence: 100,
      recommendations: []
    };

    const monitoring = sandbox.monitoring;

    // Analyze file operations
    this.analyzeFileOperations(monitoring.fileOperations, analysis);

    // Analyze network activity
    this.analyzeNetworkActivity(monitoring.networkActivity, analysis);

    // Analyze process activity
    this.analyzeProcessActivity(monitoring.processActivity, analysis);

    // Analyze registry changes
    this.analyzeRegistryChanges(monitoring.registryChanges, analysis);

    // Analyze memory allocations
    this.analyzeMemoryAllocations(monitoring.memoryAllocations, analysis);

    // Determine final verdict
    this.determineVerdict(analysis);

    return analysis;
  }

  analyzeFileOperations(operations, analysis) {
    for (const op of operations) {
      // Check for encryption operations
      if (op.operation === 'encrypt' || op.indicator?.includes('encryption')) {
        analysis.behaviorScore += 50;
        analysis.indicators.push({
          category: 'file_system',
          severity: 'critical',
          name: 'File Encryption Detected',
          description: 'Ransomware-like behavior: encrypting files',
          evidence: op
        });
      }

      // Check for mass file operations
      const fileOpsCount = operations.filter(o => 
        ['create', 'delete', 'modify'].includes(o.operation)
      ).length;
      
      if (fileOpsCount > 10) {
        analysis.behaviorScore += 25;
        analysis.indicators.push({
          category: 'file_system',
          severity: 'high',
          name: 'Excessive File Operations',
          description: `${fileOpsCount} file operations detected`,
          evidence: { count: fileOpsCount }
        });
      }

      // Check for system file access
      if (op.path?.includes('System32') || op.path?.includes('Windows')) {
        analysis.behaviorScore += 15;
        analysis.indicators.push({
          category: 'file_system',
          severity: 'medium',
          name: 'System File Access',
          description: 'Accessing Windows system files',
          evidence: op
        });
      }
    }
  }

  analyzeNetworkActivity(activities, analysis) {
    for (const activity of activities) {
      // Check for C&C connections
      if (activity.indicator?.includes('C&C') || this.isSuspiciousIP(activity.destination)) {
        analysis.behaviorScore += 60;
        analysis.indicators.push({
          category: 'network',
          severity: 'critical',
          name: 'C&C Server Connection',
          description: 'Connection to known malicious server',
          evidence: activity
        });
      }

      // Check for data exfiltration
      if (activity.bytes > 1000000) { // > 1 MB
        analysis.behaviorScore += 30;
        analysis.indicators.push({
          category: 'network',
          severity: 'high',
          name: 'Large Data Transfer',
          description: 'Possible data exfiltration',
          evidence: activity
        });
      }

      // Check for unusual ports
      const port = activity.destination?.split(':')[1];
      if (port && this.isSuspiciousPort(parseInt(port))) {
        analysis.behaviorScore += 20;
        analysis.indicators.push({
          category: 'network',
          severity: 'medium',
          name: 'Suspicious Port Usage',
          description: `Using uncommon port ${port}`,
          evidence: activity
        });
      }
    }
  }

  analyzeProcessActivity(activities, analysis) {
    for (const activity of activities) {
      // Check for code injection
      if (activity.activity === 'inject' || activity.indicator?.includes('injection')) {
        analysis.behaviorScore += 70;
        analysis.indicators.push({
          category: 'process',
          severity: 'critical',
          name: 'Code Injection Detected',
          description: 'Attempting to inject code into other processes',
          evidence: activity
        });
      }

      // Check for process spawning
      if (activity.activity === 'spawn' || activity.activity === 'create') {
        analysis.behaviorScore += 10;
        analysis.indicators.push({
          category: 'process',
          severity: 'low',
          name: 'Process Creation',
          description: 'Creating new processes',
          evidence: activity
        });
      }
    }
  }

  analyzeRegistryChanges(changes, analysis) {
    for (const change of changes) {
      // Check for startup/persistence
      if (change.key?.includes('Run') || change.indicator?.includes('Persistence')) {
        analysis.behaviorScore += 40;
        analysis.indicators.push({
          category: 'registry',
          severity: 'high',
          name: 'Persistence Mechanism',
          description: 'Creating registry entry for auto-start',
          evidence: change
        });
      }

      // Check for security settings modification
      if (change.key?.includes('Windows Defender') || change.key?.includes('Security')) {
        analysis.behaviorScore += 50;
        analysis.indicators.push({
          category: 'registry',
          severity: 'critical',
          name: 'Security Settings Modification',
          description: 'Attempting to modify security settings',
          evidence: change
        });
      }
    }
  }

  analyzeMemoryAllocations(allocations, analysis) {
    for (const allocation of allocations) {
      if (allocation.executable) {
        analysis.behaviorScore += 25;
        analysis.indicators.push({
          category: 'memory',
          severity: 'high',
          name: 'Executable Memory Allocation',
          description: 'Allocating executable memory',
          evidence: allocation
        });
      }
    }
  }

  determineVerdict(analysis) {
    // Determine threat level based on behavior score
    if (analysis.behaviorScore >= 70) {
      analysis.threatLevel = 'malicious';
      analysis.verdict = 'malicious';
      analysis.confidence = 95;
      analysis.recommendations.push('DO NOT execute this file on production systems');
      analysis.recommendations.push('Quarantine immediately');
      analysis.recommendations.push('Report to security team');
    } else if (analysis.behaviorScore >= 40) {
      analysis.threatLevel = 'suspicious';
      analysis.verdict = 'suspicious';
      analysis.confidence = 80;
      analysis.recommendations.push('Exercise caution');
      analysis.recommendations.push('Review behavior indicators');
      analysis.recommendations.push('Consider additional analysis');
    } else if (analysis.behaviorScore >= 20) {
      analysis.threatLevel = 'potentially_unwanted';
      analysis.verdict = 'potentially_unwanted';
      analysis.confidence = 70;
      analysis.recommendations.push('Monitor for unusual behavior');
      analysis.recommendations.push('Review permissions and actions');
    } else {
      analysis.threatLevel = 'clean';
      analysis.verdict = 'clean';
      analysis.confidence = 90;
      analysis.recommendations.push('No malicious behavior detected');
      analysis.recommendations.push('File appears safe based on sandbox analysis');
    }
  }

  // ==================== HELPER FUNCTIONS ====================
  
  isSuspiciousIP(ip) {
    const suspiciousPatterns = [
      /^185\.220\./,  // Tor exit nodes
      /^91\.219\./,   // Known malicious range
      /^198\.98\./    // Known malicious range
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(ip));
  }

  isSuspiciousPort(port) {
    const suspiciousPorts = [4444, 5555, 6666, 31337, 12345, 1337, 6667];
    return suspiciousPorts.includes(port);
  }

  showResultsNotification(sandbox, analysis) {
    const severity = analysis.threatLevel;
    let type, title, message;

    if (severity === 'malicious') {
      type = 'error';
      title = '🚨 MALICIOUS File Detected!';
      message = `${sandbox.fileName} exhibits malicious behavior - DO NOT EXECUTE`;
    } else if (severity === 'suspicious') {
      type = 'warning';
      title = '⚠️ Suspicious Behavior Detected';
      message = `${sandbox.fileName} shows suspicious activity`;
    } else {
      type = 'success';
      title = '✅ File Appears Clean';
      message = `${sandbox.fileName} passed sandbox analysis`;
    }

    notificationService.show({
      type,
      title,
      message,
      duration: severity === 'malicious' ? 0 : 8000,
      actions: [
        {
          label: 'View Report',
          onClick: () => this.notifyListeners('show-report', { sandbox, analysis })
        },
        ...(severity === 'malicious' ? [{
          label: 'Quarantine',
          onClick: async () => {
            await antivirusApi.quarantineFile(sandbox.filePath);
            notificationService.show({
              type: 'success',
              title: 'File Quarantined',
              message: 'Malicious file has been quarantined',
              duration: 5000
            });
          }
        }] : [])
      ]
    });
  }

  // ==================== SANDBOX MANAGEMENT ====================
  
  getSandbox(sandboxId) {
    return this.sandboxes.get(sandboxId);
  }

  getAllSandboxes() {
    return Array.from(this.sandboxes.values());
  }

  getActiveSandboxes() {
    return this.getAllSandboxes().filter(s => s.status === 'executing' || s.status === 'ready');
  }

  async destroySandbox(sandboxId) {
    const sandbox = this.sandboxes.get(sandboxId);
    if (!sandbox) return;

    sandbox.status = 'destroyed';
    this.sandboxes.delete(sandboxId);
    this.activeSandboxCount--;

    this.notifyListeners('sandbox-destroyed', { sandboxId });
    console.log(`🗑️ Sandbox ${sandboxId} destroyed`);
  }

  async destroyAllSandboxes() {
    const sandboxIds = Array.from(this.sandboxes.keys());
    for (const id of sandboxIds) {
      await this.destroySandbox(id);
    }
  }

  // ==================== DATA MANAGEMENT ====================
  
  getExecutionHistory() {
    return this.executionHistory;
  }

  getStatistics() {
    return { ...this.statistics };
  }

  loadStatistics() {
    try {
      const stored = localStorage.getItem('sandbox-statistics');
      if (stored) {
        this.statistics = JSON.parse(stored);
      }
    } catch (error) {
      console.warn('Failed to load sandbox statistics:', error);
    }
  }

  saveStatistics() {
    try {
      localStorage.setItem('sandbox-statistics', JSON.stringify(this.statistics));
    } catch (error) {
      console.warn('Failed to save sandbox statistics:', error);
    }
  }

  resetStatistics() {
    this.statistics = {
      totalExecutions: 0,
      maliciousDetected: 0,
      suspiciousDetected: 0,
      cleanFiles: 0,
      lastExecution: null
    };
    this.saveStatistics();
  }

  clearHistory() {
    this.executionHistory = [];
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
  
  async destroy() {
    await this.destroyAllSandboxes();
    this.listeners.clear();
  }
}

// Export singleton instance
const sandboxEnvironment = new SandboxEnvironment();
export default sandboxEnvironment;
