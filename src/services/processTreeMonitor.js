/**
 * Process Tree Monitoring System
 * 
 * Tracks process parent-child relationships, privilege escalation,
 * and suspicious process spawning patterns
 */

class ProcessTreeMonitor {
  constructor() {
    this.isMonitoring = false;
    this.processTree = new Map(); // pid -> process info
    this.parentChildMap = new Map(); // parentPid -> [childPids]
    this.suspiciousPatterns = [];
    this.privilegeEscalations = [];
    
    // Suspicious patterns
    this.suspiciousSpawns = new Set([
      'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
      'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
      'bitsadmin.exe', 'sc.exe', 'net.exe', 'netsh.exe'
    ]);
    
    this.trustedParents = new Set([
      'explorer.exe', 'services.exe', 'svchost.exe', 'system'
    ]);
    
    // Detection config
    this.config = {
      maxChildProcesses: 10, // Max children per parent
      rapidSpawnThreshold: 5, // Processes spawned rapidly
      rapidSpawnWindow: 5000, // Within 5 seconds
      privilegeEscalationDelay: 2000, // Delay to detect escalation
      suspiciousChainLength: 3 // Suspicious process chain depth
    };
    
    // Stats
    this.stats = {
      totalProcesses: 0,
      suspiciousSpawns: 0,
      privilegeEscalations: 0,
      blockedProcesses: 0,
      processChains: 0
    };
  }

  /**
   * Start process tree monitoring
   */
  start() {
    if (this.isMonitoring) return;
    
    this.isMonitoring = true;
    console.log('🌳 Process tree monitoring started');
    
    // Initialize with current processes
    this.initializeProcessTree();
    
    // Clean up old data periodically
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldProcesses();
    }, 60000);
  }

  /**
   * Stop process tree monitoring
   */
  stop() {
    this.isMonitoring = false;
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    console.log('🛑 Process tree monitoring stopped');
  }

  /**
   * Register a new process
   */
  registerProcess(processInfo) {
    if (!this.isMonitoring) return null;
    
    const {
      pid,
      name,
      parentPid,
      commandLine,
      user,
      isElevated,
      startTime,
      cpuUsage,
      memoryUsage,
      networkConnections
    } = processInfo;
    
    this.stats.totalProcesses++;
    
    const process = {
      pid,
      name: name?.toLowerCase() || 'unknown',
      parentPid: parentPid || 0,
      commandLine: commandLine || '',
      user: user || 'unknown',
      isElevated: isElevated || false,
      startTime: startTime || Date.now(),
      cpuUsage: cpuUsage || 0,
      memoryUsage: memoryUsage || 0,
      networkConnections: networkConnections || [],
      children: [],
      suspicionScore: 0,
      flags: []
    };
    
    // Store in tree
    this.processTree.set(pid, process);
    
    // Update parent-child relationships
    if (parentPid && parentPid !== 0) {
      if (!this.parentChildMap.has(parentPid)) {
        this.parentChildMap.set(parentPid, []);
      }
      this.parentChildMap.get(parentPid).push(pid);
      
      // Update parent's children list
      const parent = this.processTree.get(parentPid);
      if (parent) {
        parent.children.push(pid);
      }
    }
    
    // Analyze for suspicious patterns
    const threats = this.analyzeProcessSpawn(process);
    
    return threats;
  }

  /**
   * Analyze process spawn for suspicious patterns
   */
  analyzeProcessSpawn(process) {
    const threats = [];
    
    // 1. Check for suspicious process name
    if (this.isSuspiciousProcess(process.name)) {
      process.flags.push('suspicious_executable');
      process.suspicionScore += 0.3;
      
      threats.push({
        type: 'suspicious_process',
        severity: 0.6,
        description: `Suspicious process spawned: ${process.name}`,
        process
      });
    }
    
    // 2. Check for unusual parent-child relationship
    const parentCheck = this.checkParentChildRelationship(process);
    if (parentCheck) {
      threats.push(parentCheck);
    }
    
    // 3. Check for rapid process spawning
    const rapidSpawn = this.checkRapidSpawning(process);
    if (rapidSpawn) {
      threats.push(rapidSpawn);
    }
    
    // 4. Check for privilege escalation
    const privEscalation = this.checkPrivilegeEscalation(process);
    if (privEscalation) {
      threats.push(privEscalation);
    }
    
    // 5. Check for suspicious process chains
    const chainCheck = this.checkProcessChain(process);
    if (chainCheck) {
      threats.push(chainCheck);
    }
    
    // 6. Check for unusual network activity
    if (process.networkConnections && process.networkConnections.length > 0) {
      const networkCheck = this.checkNetworkBehavior(process);
      if (networkCheck) {
        threats.push(networkCheck);
      }
    }
    
    // Update suspicious patterns
    if (threats.length > 0) {
      this.suspiciousPatterns.push({
        timestamp: Date.now(),
        process,
        threats
      });
      this.stats.suspiciousSpawns++;
    }
    
    return threats.length > 0 ? threats : null;
  }

  /**
   * Check if process name is suspicious
   */
  isSuspiciousProcess(name) {
    return this.suspiciousSpawns.has(name);
  }

  /**
   * Check parent-child relationship
   */
  checkParentChildRelationship(process) {
    if (!process.parentPid) return null;
    
    const parent = this.processTree.get(process.parentPid);
    if (!parent) return null;
    
    // Check for suspicious parent-child combinations
    const suspiciousCombos = [
      { parent: 'winword.exe', child: 'powershell.exe' },
      { parent: 'excel.exe', child: 'cmd.exe' },
      { parent: 'outlook.exe', child: 'wscript.exe' },
      { parent: 'chrome.exe', child: 'powershell.exe' },
      { parent: 'firefox.exe', child: 'cmd.exe' }
    ];
    
    const isSuspicious = suspiciousCombos.some(combo =>
      parent.name.includes(combo.parent) && process.name.includes(combo.child)
    );
    
    if (isSuspicious) {
      process.flags.push('suspicious_parent_child');
      process.suspicionScore += 0.5;
      
      return {
        type: 'suspicious_parent_child',
        severity: 0.75,
        description: `Suspicious spawn: ${parent.name} -> ${process.name}`,
        process,
        parent
      };
    }
    
    return null;
  }

  /**
   * Check for rapid process spawning
   */
  checkRapidSpawning(process) {
    if (!process.parentPid) return null;
    
    const children = this.parentChildMap.get(process.parentPid) || [];
    const now = Date.now();
    const window = this.config.rapidSpawnWindow;
    
    // Count recent spawns from same parent
    const recentSpawns = children.filter(childPid => {
      const child = this.processTree.get(childPid);
      return child && (now - child.startTime) < window;
    });
    
    if (recentSpawns.length >= this.config.rapidSpawnThreshold) {
      const parent = this.processTree.get(process.parentPid);
      process.flags.push('rapid_spawning');
      process.suspicionScore += 0.4;
      
      return {
        type: 'rapid_spawning',
        severity: 0.7,
        description: `Rapid process spawning: ${recentSpawns.length} processes in ${window}ms`,
        process,
        parent,
        spawnCount: recentSpawns.length
      };
    }
    
    return null;
  }

  /**
   * Check for privilege escalation
   */
  checkPrivilegeEscalation(process) {
    if (!process.parentPid || !process.isElevated) return null;
    
    const parent = this.processTree.get(process.parentPid);
    if (!parent) return null;
    
    // Child has elevated privileges but parent doesn't
    if (process.isElevated && !parent.isElevated) {
      process.flags.push('privilege_escalation');
      process.suspicionScore += 0.6;
      
      this.privilegeEscalations.push({
        timestamp: Date.now(),
        process,
        parent
      });
      this.stats.privilegeEscalations++;
      
      return {
        type: 'privilege_escalation',
        severity: 0.85,
        description: `Privilege escalation detected: ${parent.name} -> ${process.name}`,
        process,
        parent
      };
    }
    
    return null;
  }

  /**
   * Check for suspicious process chains
   */
  checkProcessChain(process) {
    const chain = this.getProcessChain(process.pid);
    
    if (chain.length >= this.config.suspiciousChainLength) {
      // Check if chain contains multiple suspicious processes
      const suspiciousCount = chain.filter(p => 
        this.isSuspiciousProcess(p.name)
      ).length;
      
      if (suspiciousCount >= 2) {
        process.flags.push('suspicious_chain');
        process.suspicionScore += 0.5;
        this.stats.processChains++;
        
        return {
          type: 'suspicious_chain',
          severity: 0.8,
          description: `Suspicious process chain detected: ${chain.map(p => p.name).join(' -> ')}`,
          process,
          chain
        };
      }
    }
    
    return null;
  }

  /**
   * Check network behavior
   */
  checkNetworkBehavior(process) {
    // Check for suspicious processes making network connections
    if (this.isSuspiciousProcess(process.name) && process.networkConnections.length > 0) {
      process.flags.push('suspicious_network');
      process.suspicionScore += 0.4;
      
      return {
        type: 'suspicious_network',
        severity: 0.7,
        description: `Suspicious process with network activity: ${process.name}`,
        process,
        connections: process.networkConnections
      };
    }
    
    return null;
  }

  /**
   * Get full process chain (ancestry)
   */
  getProcessChain(pid) {
    const chain = [];
    let current = this.processTree.get(pid);
    
    while (current && chain.length < 10) { // Max depth 10
      chain.unshift(current);
      if (!current.parentPid || current.parentPid === 0) break;
      current = this.processTree.get(current.parentPid);
    }
    
    return chain;
  }

  /**
   * Get process tree starting from pid
   */
  getProcessTree(pid) {
    const process = this.processTree.get(pid);
    if (!process) return null;
    
    const tree = {
      ...process,
      children: this.getChildren(pid)
    };
    
    return tree;
  }

  /**
   * Get all children recursively
   */
  getChildren(pid) {
    const childPids = this.parentChildMap.get(pid) || [];
    
    return childPids.map(childPid => {
      const child = this.processTree.get(childPid);
      if (!child) return null;
      
      return {
        ...child,
        children: this.getChildren(childPid)
      };
    }).filter(Boolean);
  }

  /**
   * Update process info
   */
  updateProcess(pid, updates) {
    const process = this.processTree.get(pid);
    if (process) {
      Object.assign(process, updates);
    }
  }

  /**
   * Remove process from tree
   */
  removeProcess(pid) {
    const process = this.processTree.get(pid);
    if (!process) return;
    
    // Remove from parent's children
    if (process.parentPid) {
      const siblings = this.parentChildMap.get(process.parentPid) || [];
      const index = siblings.indexOf(pid);
      if (index > -1) {
        siblings.splice(index, 1);
      }
    }
    
    // Remove from tree
    this.processTree.delete(pid);
    this.parentChildMap.delete(pid);
  }

  /**
   * Initialize process tree from current processes
   */
  async initializeProcessTree() {
    // This would integrate with system API to get current processes
    // For now, it's a placeholder
    console.log('Initializing process tree...');
  }

  /**
   * Clean up old/terminated processes
   */
  cleanupOldProcesses() {
    const now = Date.now();
    const maxAge = 10 * 60 * 1000; // 10 minutes
    
    // Remove old processes
    for (const [pid, process] of this.processTree.entries()) {
      if (now - process.startTime > maxAge) {
        this.removeProcess(pid);
      }
    }
    
    // Keep only recent suspicious patterns
    this.suspiciousPatterns = this.suspiciousPatterns.filter(p =>
      now - p.timestamp < maxAge
    );
    
    this.privilegeEscalations = this.privilegeEscalations.filter(e =>
      now - e.timestamp < maxAge
    );
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      activeProcesses: this.processTree.size,
      suspiciousActive: Array.from(this.processTree.values())
        .filter(p => p.suspicionScore > 0.5).length
    };
  }

  /**
   * Get suspicious patterns
   */
  getSuspiciousPatterns(limit = 20) {
    return this.suspiciousPatterns.slice(-limit).reverse();
  }

  /**
   * Get privilege escalations
   */
  getPrivilegeEscalations(limit = 10) {
    return this.privilegeEscalations.slice(-limit).reverse();
  }
}

// Export singleton
const processTreeMonitor = new ProcessTreeMonitor();
export default processTreeMonitor;
