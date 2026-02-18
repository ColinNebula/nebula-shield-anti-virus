/**
 * Memory Scanner for In-Memory Threats
 * 
 * Detects code injection, shellcode, and in-memory malware
 * that may bypass file-based detection
 */

class MemoryScanner {
  constructor() {
    this.isScanning = false;
    this.scanInterval = null;
    this.detectedThreats = [];
    
    // Shellcode signatures (common patterns)
    this.shellcodePatterns = [
      /\x90{10,}/, // NOP sled
      /\xeb\x.{0,10}\x5e/, // JMP/CALL/POP pattern
      /\x31\xc0/, // XOR EAX,EAX
      /\x50\x68/, // PUSH/PUSH pattern
      /\x89\xe5/, // MOV EBP,ESP
    ];
    
    // Suspicious API calls that indicate code injection
    this.suspiciousAPIs = new Set([
      'VirtualAllocEx',
      'WriteProcessMemory',
      'CreateRemoteThread',
      'NtCreateThreadEx',
      'RtlCreateUserThread',
      'SetThreadContext',
      'QueueUserAPC',
      'NtMapViewOfSection',
      'ZwMapViewOfSection'
    ]);
    
    // Process injection techniques
    this.injectionTechniques = new Map([
      ['dll_injection', { severity: 0.8, description: 'DLL Injection detected' }],
      ['process_hollowing', { severity: 0.9, description: 'Process Hollowing detected' }],
      ['apc_injection', { severity: 0.85, description: 'APC Queue Injection detected' }],
      ['thread_hijacking', { severity: 0.85, description: 'Thread Hijacking detected' }],
      ['atom_bombing', { severity: 0.9, description: 'Atom Bombing detected' }],
      ['reflective_dll', { severity: 0.95, description: 'Reflective DLL Loading detected' }]
    ]);
    
    // Config
    this.config = {
      scanInterval: 30000, // Scan every 30 seconds
      maxMemorySize: 100 * 1024 * 1024, // 100MB max scan size
      suspiciousThreshold: 0.7,
      enableHeuristics: true,
      deepScanExecutable: true
    };
    
    // Stats
    this.stats = {
      totalScans: 0,
      processesScanned: 0,
      threatsDetected: 0,
      injectionDetected: 0,
      shellcodeDetected: 0,
      lastScan: null
    };
    
    // Cache for process memory hashes
    this.memoryHashes = new Map();
  }

  /**
   * Start memory scanning
   */
  start() {
    if (this.isScanning) return;
    
    this.isScanning = true;
    console.log('🔬 Memory scanning started');
    
    // Initial scan
    this.performScan();
    
    // Periodic scanning
    this.scanInterval = setInterval(() => {
      this.performScan();
    }, this.config.scanInterval);
  }

  /**
   * Stop memory scanning
   */
  stop() {
    this.isScanning = false;
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
    console.log('🛑 Memory scanning stopped');
  }

  /**
   * Perform memory scan on all processes
   */
  async performScan() {
    if (!this.isScanning) return;
    
    this.stats.totalScans++;
    this.stats.lastScan = new Date().toISOString();
    
    try {
      // Get list of running processes
      const processes = await this.getRunningProcesses();
      
      for (const process of processes) {
        if (!this.isScanning) break;
        
        await this.scanProcess(process);
        this.stats.processesScanned++;
      }
      
      console.log(`✅ Memory scan complete: ${processes.length} processes scanned`);
    } catch (error) {
      console.error('Memory scan error:', error);
    }
  }

  /**
   * Scan individual process memory
   */
  async scanProcess(process) {
    const threats = [];
    
    try {
      // 1. Check for code injection indicators
      const injectionCheck = await this.checkCodeInjection(process);
      if (injectionCheck) threats.push(injectionCheck);
      
      // 2. Check for shellcode patterns
      if (this.config.enableHeuristics) {
        const shellcodeCheck = await this.checkShellcode(process);
        if (shellcodeCheck) threats.push(shellcodeCheck);
      }
      
      // 3. Check for memory anomalies
      const anomalyCheck = await this.checkMemoryAnomalies(process);
      if (anomalyCheck) threats.push(anomalyCheck);
      
      // 4. Check for suspicious memory regions
      const regionCheck = await this.checkSuspiciousRegions(process);
      if (regionCheck) threats.push(regionCheck);
      
      // 5. Check for API hooking
      const hookCheck = await this.checkAPIHooks(process);
      if (hookCheck) threats.push(hookCheck);
      
      // Process detected threats
      if (threats.length > 0) {
        this.handleMemoryThreat(process, threats);
      }
    } catch (error) {
      // Process may have terminated or access denied
      if (error.message !== 'ACCESS_DENIED') {
        console.warn(`Failed to scan process ${process.pid}:`, error.message);
      }
    }
    
    return threats;
  }

  /**
   * Check for code injection indicators
   */
  async checkCodeInjection(process) {
    // Check for suspicious API calls in process
    const apiCalls = await this.getProcessAPICalls(process);
    
    const suspiciousCalls = apiCalls.filter(call =>
      this.suspiciousAPIs.has(call.name)
    );
    
    if (suspiciousCalls.length > 0) {
      // Determine injection technique
      const technique = this.identifyInjectionTechnique(suspiciousCalls);
      
      if (technique) {
        this.stats.injectionDetected++;
        const info = this.injectionTechniques.get(technique);
        
        return {
          type: 'code_injection',
          technique,
          severity: info.severity,
          description: info.description,
          process,
          apiCalls: suspiciousCalls,
          timestamp: Date.now()
        };
      }
    }
    
    return null;
  }

  /**
   * Identify injection technique from API calls
   */
  identifyInjectionTechnique(apiCalls) {
    const callNames = apiCalls.map(c => c.name);
    
    // DLL Injection pattern
    if (callNames.includes('VirtualAllocEx') && 
        callNames.includes('WriteProcessMemory') && 
        callNames.includes('CreateRemoteThread')) {
      return 'dll_injection';
    }
    
    // Process Hollowing pattern
    if (callNames.includes('NtUnmapViewOfSection') || 
        callNames.includes('ZwUnmapViewOfSection')) {
      return 'process_hollowing';
    }
    
    // APC Injection
    if (callNames.includes('QueueUserAPC')) {
      return 'apc_injection';
    }
    
    // Thread Hijacking
    if (callNames.includes('SetThreadContext')) {
      return 'thread_hijacking';
    }
    
    // Atom Bombing
    if (callNames.includes('NtQueueApcThread') || 
        callNames.includes('GlobalGetAtomName')) {
      return 'atom_bombing';
    }
    
    return null;
  }

  /**
   * Check for shellcode patterns in memory
   */
  async checkShellcode(process) {
    const memoryRegions = await this.getExecutableMemoryRegions(process);
    
    for (const region of memoryRegions) {
      // Skip if region is too large
      if (region.size > this.config.maxMemorySize) continue;
      
      const data = await this.readMemoryRegion(process, region);
      
      // Check for shellcode patterns
      for (const pattern of this.shellcodePatterns) {
        if (pattern.test(data)) {
          this.stats.shellcodeDetected++;
          
          return {
            type: 'shellcode_detected',
            severity: 0.9,
            description: 'Shellcode pattern detected in process memory',
            process,
            region,
            pattern: pattern.source,
            timestamp: Date.now()
          };
        }
      }
    }
    
    return null;
  }

  /**
   * Check for memory anomalies
   */
  async checkMemoryAnomalies(process) {
    const memoryInfo = await this.getProcessMemoryInfo(process);
    
    const anomalies = [];
    
    // Check for unusual memory allocations
    if (memoryInfo.executableRegions > 50) {
      anomalies.push('excessive_executable_regions');
    }
    
    // Check for RWX (Read-Write-Execute) pages - highly suspicious
    if (memoryInfo.rwxRegions > 0) {
      anomalies.push('rwx_memory_pages');
    }
    
    // Check for private executable memory (not backed by file)
    if (memoryInfo.privateExecutable > 10 * 1024 * 1024) { // >10MB
      anomalies.push('large_private_executable');
    }
    
    // Check for memory size changes
    const previousHash = this.memoryHashes.get(process.pid);
    const currentHash = this.calculateMemoryHash(memoryInfo);
    
    if (previousHash && previousHash !== currentHash) {
      anomalies.push('memory_modified');
    }
    
    this.memoryHashes.set(process.pid, currentHash);
    
    if (anomalies.length > 0) {
      return {
        type: 'memory_anomaly',
        severity: 0.75,
        description: `Memory anomalies detected: ${anomalies.join(', ')}`,
        process,
        anomalies,
        memoryInfo,
        timestamp: Date.now()
      };
    }
    
    return null;
  }

  /**
   * Check for suspicious memory regions
   */
  async checkSuspiciousRegions(process) {
    const regions = await this.getMemoryRegions(process);
    
    const suspicious = regions.filter(region => {
      // Executable region not backed by file
      if (region.executable && !region.fileBacked) return true;
      
      // RWX permissions
      if (region.read && region.write && region.execute) return true;
      
      // Unusual base address (not aligned)
      if (region.baseAddress % 0x10000 !== 0) return true;
      
      return false;
    });
    
    if (suspicious.length > 0) {
      return {
        type: 'suspicious_memory_region',
        severity: 0.7,
        description: `${suspicious.length} suspicious memory regions detected`,
        process,
        regions: suspicious,
        timestamp: Date.now()
      };
    }
    
    return null;
  }

  /**
   * Check for API hooking
   */
  async checkAPIHooks(process) {
    // Check if critical APIs have been hooked/modified
    const criticalAPIs = [
      'NtCreateFile',
      'NtReadVirtualMemory',
      'NtWriteVirtualMemory',
      'NtProtectVirtualMemory'
    ];
    
    const hooks = await this.detectAPIHooks(process, criticalAPIs);
    
    if (hooks.length > 0) {
      return {
        type: 'api_hooking',
        severity: 0.8,
        description: `API hooking detected: ${hooks.length} APIs modified`,
        process,
        hooks,
        timestamp: Date.now()
      };
    }
    
    return null;
  }

  /**
   * Handle detected memory threat
   */
  handleMemoryThreat(process, threats) {
    this.stats.threatsDetected++;
    
    const detection = {
      id: `memory_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      process,
      threats,
      timestamp: new Date().toISOString(),
      action: 'logged'
    };
    
    this.detectedThreats.push(detection);
    
    // Find highest severity threat
    const highestThreat = threats.reduce((max, t) => 
      t.severity > max.severity ? t : max
    );
    
    console.warn(`🚨 MEMORY THREAT DETECTED in ${process.name} (PID: ${process.pid})`);
    console.warn(`   Type: ${highestThreat.type}`);
    console.warn(`   Severity: ${(highestThreat.severity * 100).toFixed(0)}%`);
    console.warn(`   Description: ${highestThreat.description}`);
    
    // Emit event
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('memory_threat_detected', {
        detail: detection
      }));
    }
  }

  /**
   * Get running processes (mock - would integrate with system API)
   */
  async getRunningProcesses() {
    // This would integrate with native module or API
    // For now, return mock data
    return [];
  }

  /**
   * Get process API calls (mock)
   */
  async getProcessAPICalls(process) {
    // Would integrate with API monitoring/hooking framework
    return [];
  }

  /**
   * Get executable memory regions (mock)
   */
  async getExecutableMemoryRegions(process) {
    // Would use native API to enumerate memory regions
    return [];
  }

  /**
   * Read memory region (mock)
   */
  async readMemoryRegion(process, region) {
    // Would use ReadProcessMemory or similar
    return Buffer.alloc(0);
  }

  /**
   * Get process memory info (mock)
   */
  async getProcessMemoryInfo(process) {
    // Would query process memory statistics
    return {
      executableRegions: 0,
      rwxRegions: 0,
      privateExecutable: 0,
      totalSize: 0
    };
  }

  /**
   * Get memory regions (mock)
   */
  async getMemoryRegions(process) {
    return [];
  }

  /**
   * Detect API hooks (mock)
   */
  async detectAPIHooks(process, apis) {
    return [];
  }

  /**
   * Calculate memory hash for change detection
   */
  calculateMemoryHash(memoryInfo) {
    const str = JSON.stringify(memoryInfo);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      activeThreats: this.detectedThreats.filter(t =>
        Date.now() - new Date(t.timestamp).getTime() < 60000
      ).length,
      cachedHashes: this.memoryHashes.size
    };
  }

  /**
   * Get recent threats
   */
  getRecentThreats(limit = 10) {
    return this.detectedThreats.slice(-limit).reverse();
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Restart if scan interval changed
    if (newConfig.scanInterval && this.isScanning) {
      this.stop();
      this.start();
    }
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.memoryHashes.clear();
  }
}

// Export singleton
const memoryScanner = new MemoryScanner();
export default memoryScanner;
