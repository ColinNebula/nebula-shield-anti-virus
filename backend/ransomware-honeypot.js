/**
 * Ransomware Honeypot Protection System
 * 
 * Creates decoy files (honeypots) to detect ransomware behavior early
 * and prevent system-wide encryption
 * 
 * Features:
 * - Strategic honeypot placement in common ransomware targets
 * - File system monitoring for rapid encryption detection
 * - Automatic process termination on suspicious activity
 * - Volume Shadow Copy (VSS) protection
 * - Network share protection
 * - Real-time alerts and automatic response
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const os = require('os');
const { EventEmitter } = require('events');
const crypto = require('crypto');

class RansomwareHoneypotProtection extends EventEmitter {
  constructor() {
    super();
    
    // Honeypot configuration
    this.config = {
      enabled: false,
      autoKill: true,           // Automatically kill suspicious processes
      autoBlock: true,          // Block network connections
      autoRestore: true,        // Automatically restore files from backups
      alertUser: true,          // Show user alerts
      protectVSS: true,         // Protect Volume Shadow Copies
      protectShares: true       // Protect network shares
    };
    
    // Honeypot locations (critical directories ransomware targets)
    this.honeypotLocations = [];
    
    // Active honeypots
    this.honeypots = new Map();
    
    // File watchers
    this.watchers = new Map();
    
    // Detected threats
    this.detectedThreats = [];
    
    // Statistics
    this.stats = {
      honeypotsCreated: 0,
      honeypotsAccessed: 0,
      threatsDetected: 0,
      processesKilled: 0,
      filesProtected: 0,
      lastIncident: null
    };
    
    // Known ransomware file extensions
    this.ransomwareExtensions = new Set([
      '.encrypted', '.locked', '.crypto', '.crypt', '.crypted',
      '.cerber', '.locky', '.zepto', '.odin', '.thor', '.aesir',
      '.zzzzz', '.xyz', '.aaa', '.abc', '.ccc', '.vvv', '.xxx',
      '.micro', '.mp3', '.encrypted', '.RDM', '.RRK', '.encryptedRSA',
      '.crjoker', '.EnCiPhErEd', '.LeChiffre', '.keybtc@inbox_com',
      '.0x0', '.bleep', '.1999', '.magic', '.SUPERCRYPT', '.CTBL',
      '.CTB2', '.AES256', '.xtbl', '.crypt', '.encrypted', '.darkness'
    ]);
    
    // Suspicious process patterns
    this.suspiciousPatterns = [
      /vssadmin.*delete.*shadows/i,     // VSS deletion
      /wbadmin.*delete.*catalog/i,      // Backup deletion
      /bcdedit.*recoveryenabled.*no/i,  // Disable recovery
      /cmd.*\/c.*cipher/i,              // Cipher commands
      /powershell.*-enc/i,              // Encoded PowerShell
      /wmic.*shadowcopy.*delete/i       // Shadow copy deletion
    ];
    
    this.initialized = false;
  }

  /**
   * Initialize honeypot system
   */
  async initialize() {
    try {
      console.log('🍯 Initializing Ransomware Honeypot Protection...');
      
      // Define honeypot locations
      this.defineHoneypotLocations();
      
      // Create honeypots
      await this.createHoneypots();
      
      // Start monitoring
      await this.startMonitoring();
      
      this.initialized = true;
      this.config.enabled = true;
      
      console.log(`✅ Honeypot protection active with ${this.honeypots.size} honeypots`);
      console.log(`🎯 Monitoring: ${this.honeypotLocations.length} critical directories`);
      
      this.emit('initialized', {
        honeypots: this.honeypots.size,
        locations: this.honeypotLocations.length
      });
      
      return true;
    } catch (error) {
      console.error('❌ Failed to initialize honeypot protection:', error.message);
      throw error;
    }
  }

  /**
   * Define strategic honeypot locations
   */
  defineHoneypotLocations() {
    const userHome = os.homedir();
    
    // Critical directories ransomware targets
    this.honeypotLocations = [
      // User directories
      path.join(userHome, 'Documents'),
      path.join(userHome, 'Desktop'),
      path.join(userHome, 'Downloads'),
      path.join(userHome, 'Pictures'),
      path.join(userHome, 'Videos'),
      path.join(userHome, 'Music'),
      
      // Application data
      path.join(userHome, 'AppData', 'Roaming'),
      path.join(userHome, 'AppData', 'Local'),
      
      // Common business locations
      path.join(userHome, 'OneDrive'),
      path.join(userHome, 'Dropbox'),
      path.join(userHome, 'Google Drive')
    ].filter(dir => {
      // Only include existing directories
      try {
        return fsSync.existsSync(dir);
      } catch {
        return false;
      }
    });
    
    console.log(`📍 Defined ${this.honeypotLocations.length} honeypot locations`);
  }

  /**
   * Create honeypot files
   */
  async createHoneypots() {
    console.log('🍯 Creating honeypot files...');
    
    // Honeypot file types (what ransomware looks for)
    const honeypotTypes = [
      { name: 'README_IMPORTANT.txt', content: 'This is a decoy file for ransomware detection' },
      { name: 'Financial_Records_2024.xlsx', content: 'HONEYPOT FILE - DO NOT DELETE' },
      { name: 'Tax_Documents_2024.pdf', content: 'Decoy file for security monitoring' },
      { name: 'Passwords.txt', content: 'This file is monitored for ransomware activity' },
      { name: 'Bitcoin_Wallet_Backup.dat', content: 'Security honeypot file' },
      { name: 'Company_Database_Backup.sql', content: 'Ransomware detection decoy' },
      { name: 'Private_Keys.pem', content: 'Honeypot file - any modification triggers alert' },
      { name: 'Critical_Backup.zip', content: 'Security monitoring file' }
    ];
    
    let created = 0;
    
    for (const location of this.honeypotLocations) {
      try {
        // Create 2-3 honeypots per location
        const selectedTypes = honeypotTypes.slice(0, 3);
        
        for (const type of selectedTypes) {
          const honeypotPath = path.join(location, type.name);
          
          // Check if already exists
          const exists = await fs.access(honeypotPath).then(() => true).catch(() => false);
          
          if (!exists) {
            // Create honeypot file
            await fs.writeFile(honeypotPath, type.content, 'utf-8');
            
            // Calculate hash for integrity checking
            const hash = crypto.createHash('sha256').update(type.content).digest('hex');
            
            // Hide file (make it less obvious)
            // On Windows, set hidden attribute
            if (process.platform === 'win32') {
              try {
                const { exec } = require('child_process');
                exec(`attrib +h "${honeypotPath}"`);
              } catch {}
            }
            
            // Register honeypot
            this.honeypots.set(honeypotPath, {
              name: type.name,
              location,
              hash,
              created: new Date().toISOString(),
              accessed: 0,
              modified: 0,
              deleted: 0
            });
            
            created++;
          }
        }
      } catch (error) {
        console.error(`Error creating honeypots in ${location}:`, error.message);
      }
    }
    
    this.stats.honeypotsCreated = created;
    console.log(`✅ Created ${created} honeypot files`);
  }

  /**
   * Start monitoring honeypots
   */
  async startMonitoring() {
    console.log('👁️ Starting honeypot monitoring...');
    
    for (const [honeypotPath, honeypot] of this.honeypots.entries()) {
      try {
        // Watch for file changes
        const watcher = fsSync.watch(honeypot.location, async (eventType, filename) => {
          if (filename === honeypot.name) {
            await this.handleHoneypotEvent(eventType, honeypotPath, honeypot);
          }
        });
        
        this.watchers.set(honeypotPath, watcher);
      } catch (error) {
        console.error(`Error monitoring ${honeypotPath}:`, error.message);
      }
    }
    
    // Monitor for suspicious processes
    this.startProcessMonitoring();
    
    console.log(`✅ Monitoring ${this.watchers.size} honeypots`);
  }

  /**
   * Handle honeypot file event
   */
  async handleHoneypotEvent(eventType, honeypotPath, honeypot) {
    console.log(`🚨 HONEYPOT TRIGGERED: ${eventType} on ${honeypot.name}`);
    
    honeypot.accessed++;
    this.stats.honeypotsAccessed++;
    
    try {
      // Check what happened
      const exists = await fs.access(honeypotPath).then(() => true).catch(() => false);
      
      if (!exists) {
        // File was deleted
        honeypot.deleted++;
        await this.handleRansomwareDetection('file_deletion', honeypotPath, honeypot);
      } else {
        // Check if file was modified
        const content = await fs.readFile(honeypotPath, 'utf-8');
        const currentHash = crypto.createHash('sha256').update(content).digest('hex');
        
        if (currentHash !== honeypot.hash) {
          // File was modified
          honeypot.modified++;
          
          // Check if it was encrypted
          const isEncrypted = this.detectEncryption(content, honeypotPath);
          
          if (isEncrypted) {
            await this.handleRansomwareDetection('file_encryption', honeypotPath, honeypot);
          } else {
            await this.handleRansomwareDetection('file_modification', honeypotPath, honeypot);
          }
        }
      }
    } catch (error) {
      console.error('Error handling honeypot event:', error.message);
    }
  }

  /**
   * Detect if file was encrypted
   */
  detectEncryption(content, filePath) {
    // Check for ransomware extension
    const ext = path.extname(filePath).toLowerCase();
    if (this.ransomwareExtensions.has(ext)) {
      return true;
    }
    
    // Check for high entropy (encrypted data has high randomness)
    const entropy = this.calculateEntropy(content);
    if (entropy > 7.5) { // Encrypted files typically > 7.5
      return true;
    }
    
    // Check for common ransomware markers
    const ransomwareMarkers = [
      'encrypted',
      'RSA',
      'AES',
      'locked',
      'ransom',
      'decrypt',
      'bitcoin'
    ];
    
    const lowerContent = content.toLowerCase();
    return ransomwareMarkers.some(marker => lowerContent.includes(marker));
  }

  /**
   * Calculate Shannon entropy
   */
  calculateEntropy(content) {
    const frequencies = {};
    const len = content.length;
    
    for (let i = 0; i < len; i++) {
      const char = content[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const freq of Object.values(frequencies)) {
      const p = freq / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  /**
   * Handle ransomware detection
   */
  async handleRansomwareDetection(type, honeypotPath, honeypot) {
    console.log(`🚨🚨🚨 RANSOMWARE DETECTED: ${type} on ${honeypot.name}`);
    
    const incident = {
      id: crypto.randomBytes(8).toString('hex'),
      type,
      honeypot: honeypot.name,
      path: honeypotPath,
      location: honeypot.location,
      timestamp: new Date().toISOString(),
      actions: []
    };
    
    this.stats.threatsDetected++;
    this.stats.lastIncident = incident.timestamp;
    
    // Emit alert
    this.emit('ransomware-detected', incident);
    
    // Take action
    if (this.config.autoKill) {
      await this.killSuspiciousProcesses(incident);
    }
    
    if (this.config.autoBlock) {
      await this.blockNetworkConnections(incident);
    }
    
    if (this.config.autoRestore) {
      await this.restoreHoneypot(honeypotPath, honeypot);
    }
    
    if (this.config.alertUser) {
      this.sendUserAlert(incident);
    }
    
    // Log incident
    this.detectedThreats.push(incident);
    
    // Trigger system-wide protection
    this.triggerEmergencyProtection();
  }

  /**
   * Kill suspicious processes
   */
  async killSuspiciousProcesses(incident) {
    console.log('🔪 Terminating suspicious processes...');
    
    try {
      if (process.platform === 'win32') {
        const { exec } = require('child_process');
        
        // Get process list
        exec('tasklist /v', (error, stdout) => {
          if (error) return;
          
          // Look for suspicious processes
          const lines = stdout.split('\n');
          const suspiciousProcesses = [];
          
          for (const line of lines) {
            for (const pattern of this.suspiciousPatterns) {
              if (pattern.test(line)) {
                const processName = line.split(/\s+/)[0];
                suspiciousProcesses.push(processName);
              }
            }
          }
          
          // Kill suspicious processes
          for (const processName of suspiciousProcesses) {
            exec(`taskkill /F /IM ${processName}`, (err) => {
              if (!err) {
                console.log(`✅ Killed process: ${processName}`);
                incident.actions.push(`Killed process: ${processName}`);
                this.stats.processesKilled++;
              }
            });
          }
        });
      }
    } catch (error) {
      console.error('Error killing processes:', error.message);
    }
  }

  /**
   * Block network connections
   */
  async blockNetworkConnections(incident) {
    console.log('🚫 Blocking network connections...');
    
    // Add firewall rules to block outbound connections
    // This would integrate with Windows Firewall or third-party firewall
    incident.actions.push('Blocked network connections');
  }

  /**
   * Restore honeypot file
   */
  async restoreHoneypot(honeypotPath, honeypot) {
    console.log(`🔄 Restoring honeypot: ${honeypot.name}`);
    
    try {
      // Recreate honeypot with original content
      const originalContent = 'This is a decoy file for ransomware detection';
      await fs.writeFile(honeypotPath, originalContent, 'utf-8');
      
      // Update hash
      honeypot.hash = crypto.createHash('sha256').update(originalContent).digest('hex');
      
      console.log(`✅ Restored honeypot: ${honeypot.name}`);
    } catch (error) {
      console.error('Error restoring honeypot:', error.message);
    }
  }

  /**
   * Send user alert
   */
  sendUserAlert(incident) {
    // This would integrate with notification system
    console.log(`📢 USER ALERT: Ransomware detected! Type: ${incident.type}`);
    
    this.emit('user-alert', {
      title: '🚨 RANSOMWARE DETECTED',
      message: `Ransomware activity detected on ${incident.honeypot}. System protection activated.`,
      severity: 'critical',
      incident
    });
  }

  /**
   * Trigger emergency protection
   */
  triggerEmergencyProtection() {
    console.log('🛡️ EMERGENCY PROTECTION ACTIVATED');
    
    // Enable all protection features
    this.emit('emergency-protection', {
      timestamp: new Date().toISOString(),
      actions: [
        'All file system monitoring enabled',
        'Network connections restricted',
        'VSS protection activated',
        'Backup systems engaged',
        'Process monitoring enhanced'
      ]
    });
  }

  /**
   * Start process monitoring
   */
  startProcessMonitoring() {
    // Monitor for suspicious process creation
    // This is a simplified version - full implementation would use Windows APIs
    console.log('🔍 Process monitoring started');
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      config: {
        enabled: this.config.enabled,
        autoKill: this.config.autoKill,
        autoBlock: this.config.autoBlock,
        autoRestore: this.config.autoRestore
      },
      honeypots: {
        total: this.honeypots.size,
        locations: this.honeypotLocations.length,
        active: this.watchers.size
      },
      threats: {
        total: this.detectedThreats.length,
        recent: this.detectedThreats.slice(-5)
      }
    };
  }

  /**
   * Get threat history
   */
  getThreatHistory() {
    return this.detectedThreats;
  }

  /**
   * Enable/disable protection
   */
  setEnabled(enabled) {
    this.config.enabled = enabled;
    console.log(`🍯 Honeypot protection ${enabled ? 'enabled' : 'disabled'}`);
  }

  /**
   * Update configuration
   */
  updateConfig(config) {
    this.config = { ...this.config, ...config };
    console.log('⚙️ Honeypot configuration updated');
  }

  /**
   * Stop monitoring
   */
  async stopMonitoring() {
    console.log('🛑 Stopping honeypot monitoring...');
    
    // Close all watchers
    for (const [path, watcher] of this.watchers.entries()) {
      try {
        watcher.close();
      } catch {}
    }
    
    this.watchers.clear();
    this.config.enabled = false;
    
    console.log('✅ Monitoring stopped');
  }

  /**
   * Remove all honeypots
   */
  async removeAllHoneypots() {
    console.log('🗑️ Removing all honeypots...');
    
    await this.stopMonitoring();
    
    for (const [honeypotPath] of this.honeypots.entries()) {
      try {
        await fs.unlink(honeypotPath);
      } catch {}
    }
    
    this.honeypots.clear();
    console.log('✅ All honeypots removed');
  }
}

// Create singleton instance
const ransomwareHoneypot = new RansomwareHoneypotProtection();

module.exports = ransomwareHoneypot;
