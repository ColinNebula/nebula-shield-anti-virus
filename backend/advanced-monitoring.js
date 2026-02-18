/**
 * Advanced Monitoring Module
 * - Registry Monitor (Windows)
 * - Certificate Validation
 * - Memory Scanner
 * - Rootkit Detection
 * - Cryptocurrency Miner Detection
 */

const { EventEmitter } = require('events');
const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const execAsync = promisify(exec);

class AdvancedMonitoring extends EventEmitter {
  constructor() {
    super();
    this.platform = os.platform();
    this.registryMonitoringActive = false;
    this.memoryMonitoringActive = false;
    this.registryChanges = [];
    this.suspiciousProcesses = [];
    this.detectedThreats = [];
    
    // Registry keys to monitor (Windows)
    this.criticalRegistryKeys = [
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
      'HKLM\\SYSTEM\\CurrentControlSet\\Services',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'
    ];
    
    // Cryptocurrency miner indicators
    this.minerIndicators = {
      processNames: [
        'xmrig', 'ethminer', 'cgminer', 'bfgminer', 'ccminer',
        'phoenixminer', 'claymore', 'nanominer', 'lolminer', 'nbminer',
        'gminer', 't-rex', 'teamredminer', 'srbminer', 'wildrig'
      ],
      cpuThreshold: 80, // CPU usage %
      networkPatterns: [
        'stratum+tcp', 'stratum+ssl', 'ethash', 'cryptonight',
        'pool.', 'mining.', 'miner.', 'hashrate', 'nicehash'
      ],
      fileHashes: new Set() // Known miner file hashes
    };
    
    // Rootkit detection signatures
    this.rootkitSignatures = {
      hiddenProcesses: [],
      hiddenFiles: [],
      hookedAPIs: [],
      suspiciousDrivers: []
    };
    
    console.log('🔍 Advanced Monitoring initialized');
  }

  /**
   * Start Registry Monitoring (Windows)
   */
  async startRegistryMonitoring() {
    if (this.platform !== 'win32') {
      return { success: false, message: 'Registry monitoring only available on Windows' };
    }

    if (this.registryMonitoringActive) {
      return { success: false, message: 'Registry monitoring already active' };
    }

    this.registryMonitoringActive = true;
    console.log('🔍 Starting registry monitoring...');

    // Take baseline snapshot
    await this.takeRegistrySnapshot();

    // Start monitoring loop
    this.registryMonitorInterval = setInterval(async () => {
      await this.checkRegistryChanges();
    }, 10000); // Check every 10 seconds

    this.emit('registryMonitoringStarted');
    
    return {
      success: true,
      message: 'Registry monitoring started',
      monitoredKeys: this.criticalRegistryKeys.length
    };
  }

  /**
   * Stop Registry Monitoring
   */
  stopRegistryMonitoring() {
    if (!this.registryMonitoringActive) {
      return { success: false, message: 'Registry monitoring not active' };
    }

    clearInterval(this.registryMonitorInterval);
    this.registryMonitoringActive = false;

    this.emit('registryMonitoringStopped');

    return {
      success: true,
      message: 'Registry monitoring stopped',
      changesDetected: this.registryChanges.length
    };
  }

  /**
   * Take Registry Snapshot
   */
  async takeRegistrySnapshot() {
    this.registryBaseline = {};

    for (const key of this.criticalRegistryKeys) {
      try {
        const values = await this.getRegistryValues(key);
        this.registryBaseline[key] = values;
      } catch (error) {
        console.warn(`Failed to snapshot registry key: ${key}`);
      }
    }

    return this.registryBaseline;
  }

  /**
   * Get Registry Values
   */
  async getRegistryValues(keyPath) {
    try {
      const { stdout } = await execAsync(`reg query "${keyPath}" /s`);
      const entries = this.parseRegistryOutput(stdout);
      return entries;
    } catch (error) {
      return [];
    }
  }

  /**
   * Parse Registry Output
   */
  parseRegistryOutput(output) {
    const lines = output.split('\n').filter(line => line.trim());
    const entries = [];

    for (const line of lines) {
      if (line.includes('REG_SZ') || line.includes('REG_DWORD') || line.includes('REG_EXPAND_SZ')) {
        const parts = line.trim().split(/\s{2,}/);
        if (parts.length >= 3) {
          entries.push({
            name: parts[0],
            type: parts[1],
            value: parts.slice(2).join(' ')
          });
        }
      }
    }

    return entries;
  }

  /**
   * Check Registry Changes
   */
  async checkRegistryChanges() {
    const changes = [];

    for (const key of this.criticalRegistryKeys) {
      try {
        const currentValues = await this.getRegistryValues(key);
        const baselineValues = this.registryBaseline[key] || [];

        // Check for new entries
        for (const current of currentValues) {
          const existsInBaseline = baselineValues.some(
            baseline => baseline.name === current.name && baseline.value === current.value
          );

          if (!existsInBaseline) {
            const change = {
              id: crypto.randomBytes(8).toString('hex'),
              timestamp: Date.now(),
              key: key,
              action: 'added',
              entry: current,
              severity: this.assessRegistryChangeSeverity(key, current),
              suspicious: this.isSuspiciousRegistryEntry(current)
            };

            changes.push(change);
            this.registryChanges.push(change);

            if (change.suspicious) {
              this.emit('suspiciousRegistryChange', change);
              this.detectedThreats.push({
                type: 'registry',
                ...change
              });
            }
          }
        }

        // Check for removed entries
        for (const baseline of baselineValues) {
          const existsInCurrent = currentValues.some(
            current => current.name === baseline.name
          );

          if (!existsInCurrent) {
            const change = {
              id: crypto.randomBytes(8).toString('hex'),
              timestamp: Date.now(),
              key: key,
              action: 'removed',
              entry: baseline,
              severity: 'medium',
              suspicious: false
            };

            changes.push(change);
            this.registryChanges.push(change);
          }
        }
      } catch (error) {
        console.warn(`Failed to check registry key: ${key}`);
      }
    }

    if (changes.length > 0) {
      this.emit('registryChangesDetected', changes);
    }

    return changes;
  }

  /**
   * Assess Registry Change Severity
   */
  assessRegistryChangeSeverity(key, entry) {
    // High severity for startup locations
    if (key.includes('Run') || key.includes('Winlogon')) {
      return 'high';
    }

    // Medium severity for services
    if (key.includes('Services')) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Check if Registry Entry is Suspicious
   */
  isSuspiciousRegistryEntry(entry) {
    const suspiciousIndicators = [
      /powershell.*-enc/i, // Encoded PowerShell
      /cmd\.exe.*\/c/i, // Command execution
      /wscript|cscript/i, // Script execution
      /regsvr32/i, // DLL registration
      /rundll32/i, // DLL execution
      /mshta/i, // HTML Application
      /\\temp\\/i, // Temp directory
      /\\appdata\\local\\temp/i,
      /\.bat|\.vbs|\.js|\.ps1/i, // Script files
      /http:|https:/i // Network URLs
    ];

    const value = entry.value?.toLowerCase() || '';

    return suspiciousIndicators.some(pattern => pattern.test(value));
  }

  /**
   * Validate Certificate on Executable
   */
  async validateCertificate(filePath) {
    if (this.platform !== 'win32') {
      return {
        success: false,
        message: 'Certificate validation only available on Windows',
        filePath
      };
    }

    try {
      // Use PowerShell to get authenticode signature
      const psCommand = `Get-AuthenticodeSignature -FilePath "${filePath}" | Select-Object Status, SignerCertificate, TimeStamperCertificate | ConvertTo-Json`;
      const { stdout } = await execAsync(`powershell -Command "${psCommand}"`);
      
      const result = JSON.parse(stdout);
      
      const validation = {
        success: true,
        filePath,
        signed: result.Status === 0 || result.Status === 'Valid',
        status: this.getSignatureStatus(result.Status),
        signer: result.SignerCertificate ? {
          subject: result.SignerCertificate.Subject,
          issuer: result.SignerCertificate.Issuer,
          thumbprint: result.SignerCertificate.Thumbprint,
          notBefore: result.SignerCertificate.NotBefore,
          notAfter: result.SignerCertificate.NotAfter
        } : null,
        timestamp: result.TimeStamperCertificate ? {
          subject: result.TimeStamperCertificate.Subject,
          issuer: result.TimeStamperCertificate.Issuer
        } : null,
        trust: this.assessCertificateTrust(result),
        validatedAt: Date.now()
      };

      return validation;
    } catch (error) {
      // Fallback: Check if file is signed using simpler method
      try {
        const { stdout } = await execAsync(`powershell -Command "(Get-AuthenticodeSignature '${filePath}').Status"`);
        const status = stdout.trim();
        
        return {
          success: true,
          filePath,
          signed: status === 'Valid',
          status: this.getSignatureStatus(status),
          trust: status === 'Valid' ? 'trusted' : 'untrusted',
          validatedAt: Date.now(),
          error: 'Limited certificate information available'
        };
      } catch (fallbackError) {
        return {
          success: false,
          filePath,
          signed: false,
          status: 'unsigned',
          trust: 'untrusted',
          error: error.message,
          validatedAt: Date.now()
        };
      }
    }
  }

  /**
   * Get Signature Status
   */
  getSignatureStatus(status) {
    const statusMap = {
      0: 'Valid',
      'Valid': 'Valid',
      'NotSigned': 'Unsigned',
      'HashMismatch': 'Modified',
      'NotTrusted': 'Untrusted',
      'UnknownError': 'Unknown'
    };

    return statusMap[status] || status;
  }

  /**
   * Assess Certificate Trust
   */
  assessCertificateTrust(certInfo) {
    if (!certInfo.SignerCertificate) return 'untrusted';
    
    if (certInfo.Status === 0 || certInfo.Status === 'Valid') {
      return 'trusted';
    }

    if (certInfo.Status === 'NotTrusted') {
      return 'untrusted';
    }

    return 'unknown';
  }

  /**
   * Start Memory Scanning
   */
  async startMemoryScanning() {
    if (this.memoryMonitoringActive) {
      return { success: false, message: 'Memory scanning already active' };
    }

    this.memoryMonitoringActive = true;
    console.log('🧠 Starting memory scanning...');

    // Start memory monitoring loop
    this.memoryMonitorInterval = setInterval(async () => {
      await this.scanMemory();
    }, 30000); // Scan every 30 seconds

    this.emit('memoryScanningStarted');

    return {
      success: true,
      message: 'Memory scanning started',
      interval: '30 seconds'
    };
  }

  /**
   * Stop Memory Scanning
   */
  stopMemoryScanning() {
    if (!this.memoryMonitoringActive) {
      return { success: false, message: 'Memory scanning not active' };
    }

    clearInterval(this.memoryMonitorInterval);
    this.memoryMonitoringActive = false;

    this.emit('memoryScanningStopped');

    return {
      success: true,
      message: 'Memory scanning stopped',
      threatsDetected: this.suspiciousProcesses.length
    };
  }

  /**
   * Scan Memory for Threats
   */
  async scanMemory() {
    const processes = await this.getProcessList();
    const suspicious = [];

    for (const process of processes) {
      // Check for high CPU usage (potential miner)
      if (process.cpu > this.minerIndicators.cpuThreshold) {
        suspicious.push({
          ...process,
          reason: 'High CPU usage',
          threat: 'Potential cryptocurrency miner',
          severity: 'high'
        });
      }

      // Check for known miner process names
      const isMiner = this.minerIndicators.processNames.some(
        miner => process.name.toLowerCase().includes(miner.toLowerCase())
      );

      if (isMiner) {
        suspicious.push({
          ...process,
          reason: 'Known miner process name',
          threat: 'Cryptocurrency miner detected',
          severity: 'critical'
        });
      }

      // Check for processes without executable path (potential rootkit)
      if (!process.path || process.path === 'unknown') {
        suspicious.push({
          ...process,
          reason: 'No executable path',
          threat: 'Potential rootkit or hidden process',
          severity: 'high'
        });
      }

      // Check for processes running from suspicious locations
      if (process.path) {
        const suspiciousLocations = [
          /\\temp\\/i,
          /\\appdata\\local\\temp/i,
          /\\windows\\temp/i,
          /recycle\.bin/i
        ];

        if (suspiciousLocations.some(pattern => pattern.test(process.path))) {
          suspicious.push({
            ...process,
            reason: 'Running from suspicious location',
            threat: 'Potentially malicious process',
            severity: 'medium'
          });
        }
      }
    }

    if (suspicious.length > 0) {
      this.suspiciousProcesses.push(...suspicious);
      this.emit('suspiciousProcessesDetected', suspicious);

      for (const proc of suspicious) {
        if (proc.severity === 'critical' || proc.severity === 'high') {
          this.detectedThreats.push({
            type: 'memory',
            ...proc,
            detectedAt: Date.now()
          });
        }
      }
    }

    return {
      scanned: processes.length,
      suspicious: suspicious.length,
      threats: suspicious
    };
  }

  /**
   * Get Process List
   */
  async getProcessList() {
    const processes = [];

    try {
      if (this.platform === 'win32') {
        const { stdout } = await execAsync('powershell -Command "Get-Process | Select-Object Name, Id, CPU, Path | ConvertTo-Json"');
        const procList = JSON.parse(stdout);
        
        for (const proc of (Array.isArray(procList) ? procList : [procList])) {
          processes.push({
            name: proc.Name,
            pid: proc.Id,
            cpu: proc.CPU || 0,
            path: proc.Path || 'unknown'
          });
        }
      } else if (this.platform === 'darwin') {
        const { stdout } = await execAsync('ps aux');
        const lines = stdout.split('\n').slice(1);
        
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 11) {
            processes.push({
              name: parts[10],
              pid: parseInt(parts[1]),
              cpu: parseFloat(parts[2]),
              path: parts[10]
            });
          }
        }
      } else {
        // Linux
        const { stdout } = await execAsync('ps aux');
        const lines = stdout.split('\n').slice(1);
        
        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 11) {
            processes.push({
              name: parts[10],
              pid: parseInt(parts[1]),
              cpu: parseFloat(parts[2]),
              path: parts[10]
            });
          }
        }
      }
    } catch (error) {
      console.error('Failed to get process list:', error.message);
    }

    return processes;
  }

  /**
   * Detect Rootkits
   */
  async detectRootkits() {
    console.log('🔎 Scanning for rootkits...');
    
    const detections = {
      hiddenProcesses: [],
      hiddenFiles: [],
      hookedAPIs: [],
      suspiciousDrivers: [],
      timestamp: Date.now()
    };

    // 1. Check for hidden processes (discrepancy between process lists)
    const hiddenProcs = await this.checkHiddenProcesses();
    detections.hiddenProcesses = hiddenProcs;

    // 2. Check for suspicious kernel drivers (Windows)
    if (this.platform === 'win32') {
      const drivers = await this.checkSuspiciousDrivers();
      detections.suspiciousDrivers = drivers;
    }

    // 3. Check for file system anomalies
    const hiddenFiles = await this.checkHiddenFiles();
    detections.hiddenFiles = hiddenFiles;

    // 4. Calculate threat level
    const totalDetections = 
      detections.hiddenProcesses.length +
      detections.hiddenFiles.length +
      detections.suspiciousDrivers.length;

    detections.threatLevel = totalDetections === 0 ? 'none' :
                            totalDetections < 3 ? 'low' :
                            totalDetections < 7 ? 'medium' : 'high';

    detections.rootkitDetected = totalDetections > 0;

    if (detections.rootkitDetected) {
      this.emit('rootkitDetected', detections);
      this.detectedThreats.push({
        type: 'rootkit',
        ...detections
      });
    }

    return detections;
  }

  /**
   * Check for Hidden Processes
   */
  async checkHiddenProcesses() {
    const hidden = [];

    try {
      // Compare different methods of listing processes
      const method1 = await this.getProcessList();
      
      // Alternative method
      let method2 = [];
      if (this.platform === 'win32') {
        const { stdout } = await execAsync('tasklist /FO CSV /NH');
        const lines = stdout.split('\n').filter(l => l.trim());
        
        for (const line of lines) {
          const parts = line.split(',').map(p => p.replace(/"/g, ''));
          if (parts.length >= 2) {
            method2.push({
              name: parts[0],
              pid: parseInt(parts[1])
            });
          }
        }
      }

      // Find discrepancies
      for (const proc of method2) {
        const existsInMethod1 = method1.some(p => p.pid === proc.pid);
        if (!existsInMethod1) {
          hidden.push({
            name: proc.name,
            pid: proc.pid,
            reason: 'Process hidden from standard enumeration',
            severity: 'high'
          });
        }
      }
    } catch (error) {
      console.warn('Failed to check for hidden processes:', error.message);
    }

    return hidden;
  }

  /**
   * Check for Suspicious Drivers (Windows)
   */
  async checkSuspiciousDrivers() {
    const suspicious = [];

    try {
      const { stdout } = await execAsync('driverquery /FO CSV /NH');
      const lines = stdout.split('\n').filter(l => l.trim());

      for (const line of lines) {
        const parts = line.split(',').map(p => p.replace(/"/g, ''));
        if (parts.length >= 1) {
          const driverName = parts[0].toLowerCase();

          // Check for suspicious driver names
          const suspiciousPatterns = [
            /rootkit/i,
            /hidden/i,
            /stealth/i,
            /hook/i,
            /injec/i
          ];

          if (suspiciousPatterns.some(pattern => pattern.test(driverName))) {
            suspicious.push({
              name: parts[0],
              reason: 'Suspicious driver name',
              severity: 'high'
            });
          }
        }
      }
    } catch (error) {
      console.warn('Failed to check drivers:', error.message);
    }

    return suspicious;
  }

  /**
   * Check for Hidden Files
   */
  async checkHiddenFiles() {
    const hidden = [];
    const suspiciousLocations = [
      'C:\\Windows\\System32',
      'C:\\Windows\\Temp',
      'C:\\ProgramData'
    ];

    try {
      for (const location of suspiciousLocations) {
        try {
          const files = await fs.readdir(location);
          
          for (const file of files) {
            // Check for files with suspicious characteristics
            if (file.startsWith('.') || file.includes('$')) {
              const filePath = path.join(location, file);
              
              try {
                const stats = await fs.stat(filePath);
                
                if (stats.size === 0 || stats.size > 100 * 1024 * 1024) {
                  hidden.push({
                    path: filePath,
                    size: stats.size,
                    reason: stats.size === 0 ? 'Zero-byte file' : 'Unusually large file',
                    severity: 'medium'
                  });
                }
              } catch (err) {
                // File access denied - could be hidden
                hidden.push({
                  path: filePath,
                  reason: 'Access denied',
                  severity: 'low'
                });
              }
            }
          }
        } catch (err) {
          // Location access denied
        }
      }
    } catch (error) {
      console.warn('Failed to check for hidden files:', error.message);
    }

    return hidden.slice(0, 10); // Limit to 10 results
  }

  /**
   * Detect Cryptocurrency Miners
   */
  async detectCryptoMiners() {
    console.log('💰 Scanning for cryptocurrency miners...');

    const detections = {
      suspiciousProcesses: [],
      networkConnections: [],
      highCpuProcesses: [],
      timestamp: Date.now()
    };

    // 1. Check running processes
    const processes = await this.getProcessList();
    
    for (const proc of processes) {
      // Check process name
      const isMinerName = this.minerIndicators.processNames.some(
        miner => proc.name.toLowerCase().includes(miner.toLowerCase())
      );

      if (isMinerName) {
        detections.suspiciousProcesses.push({
          ...proc,
          reason: 'Known miner process name',
          confidence: 'high'
        });
      }

      // Check CPU usage
      if (proc.cpu > this.minerIndicators.cpuThreshold) {
        detections.highCpuProcesses.push({
          ...proc,
          reason: `High CPU usage (${proc.cpu.toFixed(1)}%)`,
          confidence: 'medium'
        });
      }
    }

    // 2. Check network connections for mining pools
    const networkConnections = await this.checkNetworkConnections();
    
    for (const conn of networkConnections) {
      const isMiningPool = this.minerIndicators.networkPatterns.some(
        pattern => conn.remote.toLowerCase().includes(pattern.toLowerCase())
      );

      if (isMiningPool) {
        detections.networkConnections.push({
          ...conn,
          reason: 'Connection to known mining pool',
          confidence: 'high'
        });
      }
    }

    // Calculate overall detection
    detections.minerDetected = 
      detections.suspiciousProcesses.length > 0 ||
      detections.networkConnections.length > 0 ||
      detections.highCpuProcesses.length >= 3;

    detections.confidence = this.calculateMinerConfidence(detections);

    if (detections.minerDetected) {
      this.emit('cryptoMinerDetected', detections);
      this.detectedThreats.push({
        type: 'cryptominer',
        ...detections
      });
    }

    return detections;
  }

  /**
   * Check Network Connections
   */
  async checkNetworkConnections() {
    const connections = [];

    try {
      if (this.platform === 'win32') {
        const { stdout } = await execAsync('netstat -ano');
        const lines = stdout.split('\n').slice(4);

        for (const line of lines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 5) {
            const remote = parts[2];
            if (remote && !remote.startsWith('127.0.0.1') && !remote.startsWith('[::1]')) {
              connections.push({
                protocol: parts[0],
                local: parts[1],
                remote: remote,
                state: parts[3],
                pid: parseInt(parts[4]) || 0
              });
            }
          }
        }
      }
    } catch (error) {
      console.warn('Failed to check network connections:', error.message);
    }

    return connections;
  }

  /**
   * Calculate Miner Detection Confidence
   */
  calculateMinerConfidence(detections) {
    let score = 0;

    score += detections.suspiciousProcesses.length * 40;
    score += detections.networkConnections.length * 30;
    score += Math.min(detections.highCpuProcesses.length, 3) * 10;

    if (score >= 80) return 'high';
    if (score >= 50) return 'medium';
    if (score >= 20) return 'low';
    return 'none';
  }

  /**
   * Get Monitoring Statistics
   */
  getStatistics() {
    return {
      registryMonitoring: {
        active: this.registryMonitoringActive,
        changesDetected: this.registryChanges.length,
        suspiciousChanges: this.registryChanges.filter(c => c.suspicious).length,
        monitoredKeys: this.criticalRegistryKeys.length
      },
      memoryScanning: {
        active: this.memoryMonitoringActive,
        suspiciousProcesses: this.suspiciousProcesses.length,
        criticalThreats: this.suspiciousProcesses.filter(p => p.severity === 'critical').length
      },
      threatDetection: {
        totalThreats: this.detectedThreats.length,
        byType: {
          registry: this.detectedThreats.filter(t => t.type === 'registry').length,
          memory: this.detectedThreats.filter(t => t.type === 'memory').length,
          rootkit: this.detectedThreats.filter(t => t.type === 'rootkit').length,
          cryptominer: this.detectedThreats.filter(t => t.type === 'cryptominer').length
        }
      },
      platform: this.platform
    };
  }

  /**
   * Get Registry Changes
   */
  getRegistryChanges(limit = 100) {
    return {
      changes: this.registryChanges.slice(-limit).reverse(),
      total: this.registryChanges.length,
      suspicious: this.registryChanges.filter(c => c.suspicious).length
    };
  }

  /**
   * Get Detected Threats
   */
  getDetectedThreats(limit = 50) {
    return {
      threats: this.detectedThreats.slice(-limit).reverse(),
      total: this.detectedThreats.length,
      critical: this.detectedThreats.filter(t => t.severity === 'critical').length,
      high: this.detectedThreats.filter(t => t.severity === 'high').length
    };
  }

  /**
   * Clear Threat History
   */
  clearThreatHistory() {
    const count = this.detectedThreats.length;
    this.detectedThreats = [];
    this.suspiciousProcesses = [];
    this.registryChanges = [];

    return {
      success: true,
      cleared: count
    };
  }
}

module.exports = AdvancedMonitoring;
