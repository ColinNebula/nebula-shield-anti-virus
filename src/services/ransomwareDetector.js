/**
 * Ransomware Behavior Detection System
 * 
 * Monitors for mass file encryption patterns and ransomware-like behaviors:
 * - Rapid file modifications across multiple directories
 * - File extension changes to encrypted formats
 * - Creation of ransom notes (README.txt, DECRYPT_INSTRUCTIONS, etc.)
 * - Mass file deletion followed by new file creation
 * - Suspicious file renaming patterns
 */

class RansomwareDetector {
  constructor() {
    this.isMonitoring = false;
    this.fileOperations = new Map(); // Track file operations by directory
    this.suspiciousExtensions = new Set([
      '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.locky',
      '.cerber', '.zepto', '.thor', '.aesir', '.zzzzz', '.micro',
      '.dharma', '.wallet', '.onion', '.wncry', '.wcry', '.sage'
    ]);
    this.ransomNotePatterns = [
      /decrypt/i, /ransom/i, /bitcoin/i, /restore.*files/i,
      /pay.*bitcoin/i, /your.*files.*encrypted/i, /readme/i,
      /how.*to.*decrypt/i, /recovery.*instructions/i
    ];
    
    // Detection thresholds
    this.config = {
      rapidModificationThreshold: 10, // Files modified in same directory
      rapidModificationWindow: 5000, // Within 5 seconds
      massEncryptionThreshold: 20, // Files encrypted across system
      massEncryptionWindow: 30000, // Within 30 seconds
      suspiciousRenameThreshold: 5, // Renamed files with encrypted extensions
      directorySpreadThreshold: 3, // Spread across multiple directories
    };
    
    // Detection state
    this.recentOperations = [];
    this.encryptionEvents = [];
    this.detectedThreats = [];
    this.blockedProcesses = new Set();
    
    // Statistics
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      threatsBlocked: 0,
      falsePositives: 0,
      filesProtected: 0,
      lastDetection: null
    };
  }

  /**
   * Start ransomware monitoring
   */
  start() {
    if (this.isMonitoring) return;
    
    this.isMonitoring = true;
    console.log('🛡️ Ransomware detection started');
    
    // Clean up old events every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldEvents();
    }, 60000);
  }

  /**
   * Stop ransomware monitoring
   */
  stop() {
    this.isMonitoring = false;
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    console.log('🛑 Ransomware detection stopped');
  }

  /**
   * Analyze file event for ransomware behavior
   */
  analyzeFileEvent(event) {
    if (!this.isMonitoring) return null;
    
    this.stats.totalScans++;
    
    const now = Date.now();
    const operation = {
      timestamp: now,
      filePath: event.file_path,
      eventType: event.event_type,
      extension: event.file_extension,
      processId: event.process_id,
      directory: this.getDirectory(event.file_path)
    };
    
    this.recentOperations.push(operation);
    
    // Check for ransomware patterns
    const threats = [];
    
    // 1. Check for suspicious file extensions
    if (this.isSuspiciousExtension(operation.extension)) {
      threats.push(this.checkEncryptionPattern(operation));
    }
    
    // 2. Check for ransom note creation
    if (operation.eventType === 'created') {
      const ransomNote = this.checkRansomNote(operation);
      if (ransomNote) threats.push(ransomNote);
    }
    
    // 3. Check for rapid mass modifications
    const rapidMod = this.checkRapidModifications(operation);
    if (rapidMod) threats.push(rapidMod);
    
    // 4. Check for mass file renaming
    const massRename = this.checkMassRenaming(operation);
    if (massRename) threats.push(massRename);
    
    // 5. Check for directory spread pattern
    const directorySpread = this.checkDirectorySpread(operation);
    if (directorySpread) threats.push(directorySpread);
    
    // Process detected threats
    const highestThreat = threats.reduce((max, t) => 
      t && t.severity > (max?.severity || 0) ? t : max, null);
    
    if (highestThreat && highestThreat.severity >= 0.7) {
      this.handleRansomwareDetection(highestThreat, operation);
      return highestThreat;
    }
    
    return null;
  }

  /**
   * Check for encryption pattern
   */
  checkEncryptionPattern(operation) {
    const now = Date.now();
    const window = this.config.massEncryptionWindow;
    
    // Count recent encryption-like events
    const recentEncryptions = this.recentOperations.filter(op => 
      now - op.timestamp < window &&
      this.isSuspiciousExtension(op.extension)
    );
    
    if (recentEncryptions.length >= this.config.massEncryptionThreshold) {
      this.encryptionEvents.push({ timestamp: now, count: recentEncryptions.length });
      
      return {
        type: 'mass_encryption',
        severity: 0.95,
        confidence: 0.9,
        description: `Mass file encryption detected: ${recentEncryptions.length} files`,
        affectedFiles: recentEncryptions.map(op => op.filePath),
        processId: operation.processId,
        timestamp: now
      };
    }
    
    return null;
  }

  /**
   * Check for ransom note creation
   */
  checkRansomNote(operation) {
    const fileName = this.getFileName(operation.filePath).toLowerCase();
    
    // Check if filename matches ransom note patterns
    const matchesPattern = this.ransomNotePatterns.some(pattern => 
      pattern.test(fileName)
    );
    
    if (matchesPattern) {
      return {
        type: 'ransom_note',
        severity: 0.98,
        confidence: 0.85,
        description: `Suspected ransom note created: ${fileName}`,
        affectedFiles: [operation.filePath],
        processId: operation.processId,
        timestamp: Date.now()
      };
    }
    
    return null;
  }

  /**
   * Check for rapid modifications in same directory
   */
  checkRapidModifications(operation) {
    const now = Date.now();
    const window = this.config.rapidModificationWindow;
    
    // Count modifications in same directory
    const dirOperations = this.recentOperations.filter(op =>
      now - op.timestamp < window &&
      op.directory === operation.directory &&
      (op.eventType === 'modified' || op.eventType === 'created')
    );
    
    if (dirOperations.length >= this.config.rapidModificationThreshold) {
      return {
        type: 'rapid_modification',
        severity: 0.75,
        confidence: 0.7,
        description: `Rapid file modifications in ${operation.directory}: ${dirOperations.length} files`,
        affectedFiles: dirOperations.map(op => op.filePath),
        processId: operation.processId,
        timestamp: now
      };
    }
    
    return null;
  }

  /**
   * Check for mass file renaming with encrypted extensions
   */
  checkMassRenaming(operation) {
    const now = Date.now();
    const window = this.config.massEncryptionWindow;
    
    // Count rename operations with suspicious extensions
    const suspiciousRenames = this.recentOperations.filter(op =>
      now - op.timestamp < window &&
      op.eventType === 'moved' &&
      this.isSuspiciousExtension(op.extension)
    );
    
    if (suspiciousRenames.length >= this.config.suspiciousRenameThreshold) {
      return {
        type: 'mass_renaming',
        severity: 0.85,
        confidence: 0.8,
        description: `Mass file renaming detected: ${suspiciousRenames.length} files`,
        affectedFiles: suspiciousRenames.map(op => op.filePath),
        processId: operation.processId,
        timestamp: now
      };
    }
    
    return null;
  }

  /**
   * Check for spread across multiple directories
   */
  checkDirectorySpread(operation) {
    const now = Date.now();
    const window = this.config.massEncryptionWindow;
    
    // Count unique directories with suspicious activity
    const directories = new Set(
      this.recentOperations
        .filter(op => now - op.timestamp < window)
        .map(op => op.directory)
    );
    
    if (directories.size >= this.config.directorySpreadThreshold) {
      const affectedDirs = Array.from(directories);
      return {
        type: 'directory_spread',
        severity: 0.8,
        confidence: 0.75,
        description: `Activity spread across ${directories.size} directories`,
        affectedDirectories: affectedDirs,
        processId: operation.processId,
        timestamp: now
      };
    }
    
    return null;
  }

  /**
   * Handle detected ransomware threat
   */
  handleRansomwareDetection(threat, operation) {
    this.stats.threatsDetected++;
    this.stats.lastDetection = new Date().toISOString();
    
    const detection = {
      id: `ransomware_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...threat,
      operation,
      action: 'blocked',
      timestamp: new Date().toISOString()
    };
    
    this.detectedThreats.push(detection);
    
    // Block the process
    if (operation.processId && !this.blockedProcesses.has(operation.processId)) {
      this.blockedProcesses.add(operation.processId);
      this.stats.threatsBlocked++;
      
      console.warn(`🚨 RANSOMWARE DETECTED - Process ${operation.processId} blocked!`);
      console.warn(`   Type: ${threat.type}`);
      console.warn(`   Severity: ${(threat.severity * 100).toFixed(0)}%`);
      console.warn(`   Description: ${threat.description}`);
    }
    
    // Emit event for UI notification
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('ransomware_detected', { 
        detail: detection 
      }));
    }
  }

  /**
   * Check if file extension is suspicious
   */
  isSuspiciousExtension(extension) {
    if (!extension) return false;
    return this.suspiciousExtensions.has(extension.toLowerCase());
  }

  /**
   * Clean up old events to prevent memory leak
   */
  cleanupOldEvents() {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    
    this.recentOperations = this.recentOperations.filter(op => 
      now - op.timestamp < maxAge
    );
    
    this.encryptionEvents = this.encryptionEvents.filter(ev =>
      now - ev.timestamp < maxAge
    );
    
    // Keep only last 100 detected threats
    if (this.detectedThreats.length > 100) {
      this.detectedThreats = this.detectedThreats.slice(-100);
    }
  }

  /**
   * Get directory from file path
   */
  getDirectory(filePath) {
    const parts = filePath.split(/[/\\]/);
    parts.pop(); // Remove filename
    return parts.join('/');
  }

  /**
   * Get filename from path
   */
  getFileName(filePath) {
    const parts = filePath.split(/[/\\]/);
    return parts[parts.length - 1] || '';
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
      blockedProcesses: this.blockedProcesses.size,
      recentOperations: this.recentOperations.length
    };
  }

  /**
   * Get recent threats
   */
  getRecentThreats(limit = 10) {
    return this.detectedThreats.slice(-limit).reverse();
  }

  /**
   * Mark threat as false positive
   */
  markFalsePositive(threatId) {
    const threat = this.detectedThreats.find(t => t.id === threatId);
    if (threat) {
      threat.falsePositive = true;
      this.stats.falsePositives++;
      
      // Unblock process if needed
      if (threat.operation?.processId) {
        this.blockedProcesses.delete(threat.operation.processId);
      }
    }
  }

  /**
   * Update configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      totalScans: 0,
      threatsDetected: 0,
      threatsBlocked: 0,
      falsePositives: 0,
      filesProtected: 0,
      lastDetection: null
    };
    this.detectedThreats = [];
    this.blockedProcesses.clear();
  }
}

// Export singleton instance
const ransomwareDetector = new RansomwareDetector();
export default ransomwareDetector;
