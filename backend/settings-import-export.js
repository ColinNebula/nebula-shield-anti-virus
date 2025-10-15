/**
 * Settings Import/Export Service
 * Handles exporting and importing application settings
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SettingsImportExportService {
  constructor() {
    this.settingsPath = path.join(process.cwd(), 'data', 'settings.json');
    this.backupDir = path.join(process.cwd(), 'data', 'settings-backups');
    this.maxBackups = 10;
    
    this.initialize();
  }

  /**
   * Initialize service
   */
  initialize() {
    // Ensure directories exist
    [path.dirname(this.settingsPath), this.backupDir].forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Export all settings
   */
  exportSettings(options = {}) {
    const settings = this.loadSettings();
    
    const exportData = {
      metadata: {
        exportedAt: Date.now(),
        exportedBy: options.userId || 'system',
        version: '1.0.0',
        applicationVersion: options.appVersion || '1.0.0',
        checksum: null
      },
      settings: {
        general: settings.general || {},
        scanner: settings.scanner || {},
        protection: settings.protection || {},
        notifications: settings.notifications || {},
        appearance: settings.appearance || {},
        advanced: settings.advanced || {},
        privacy: settings.privacy || {}
      },
      customRules: settings.customRules || [],
      whitelist: settings.whitelist || [],
      blacklist: settings.blacklist || [],
      scheduledScans: settings.scheduledScans || []
    };

    // Calculate checksum
    exportData.metadata.checksum = this.calculateChecksum(exportData.settings);

    // Optionally encrypt
    if (options.encrypt) {
      return this.encryptData(exportData, options.password);
    }

    return exportData;
  }

  /**
   * Export settings to file
   */
  exportToFile(filePath, options = {}) {
    const exportData = this.exportSettings(options);
    
    const format = options.format || 'json';
    let content;

    switch (format) {
      case 'json':
        content = JSON.stringify(exportData, null, 2);
        break;
      case 'compact':
        content = JSON.stringify(exportData);
        break;
      default:
        throw new Error(`Unsupported format: ${format}`);
    }

    fs.writeFileSync(filePath, content, 'utf8');
    
    return {
      filePath,
      size: content.length,
      checksum: exportData.metadata.checksum,
      exportedAt: exportData.metadata.exportedAt
    };
  }

  /**
   * Import settings
   */
  importSettings(importData, options = {}) {
    // Decrypt if needed
    if (options.encrypted) {
      importData = this.decryptData(importData, options.password);
    }

    // Validate structure
    if (!importData.metadata || !importData.settings) {
      throw new Error('Invalid settings data structure');
    }

    // Verify checksum
    const calculatedChecksum = this.calculateChecksum(importData.settings);
    if (calculatedChecksum !== importData.metadata.checksum) {
      if (!options.skipChecksumValidation) {
        throw new Error('Settings checksum mismatch - data may be corrupted');
      }
    }

    // Create backup before importing
    if (!options.skipBackup) {
      this.createBackup('pre-import');
    }

    // Merge or replace settings
    const currentSettings = this.loadSettings();
    let newSettings;

    if (options.merge) {
      newSettings = this.mergeSettings(currentSettings, importData.settings);
    } else {
      newSettings = importData.settings;
    }

    // Add additional data
    newSettings.customRules = importData.customRules || [];
    newSettings.whitelist = importData.whitelist || [];
    newSettings.blacklist = importData.blacklist || [];
    newSettings.scheduledScans = importData.scheduledScans || [];

    // Save settings
    this.saveSettings(newSettings);

    return {
      imported: true,
      timestamp: Date.now(),
      source: importData.metadata,
      mergeMode: options.merge || false
    };
  }

  /**
   * Import settings from file
   */
  importFromFile(filePath, options = {}) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Settings file not found: ${filePath}`);
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const importData = JSON.parse(content);

    return this.importSettings(importData, options);
  }

  /**
   * Create settings backup
   */
  createBackup(label = 'manual') {
    const settings = this.loadSettings();
    
    const backup = {
      metadata: {
        backupId: `backup_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        createdAt: Date.now(),
        label,
        version: '1.0.0'
      },
      settings
    };

    const filename = `settings-backup-${Date.now()}-${label}.json`;
    const backupPath = path.join(this.backupDir, filename);
    
    fs.writeFileSync(backupPath, JSON.stringify(backup, null, 2), 'utf8');

    // Clean old backups
    this.cleanOldBackups();

    return {
      backupId: backup.metadata.backupId,
      path: backupPath,
      size: fs.statSync(backupPath).size,
      createdAt: backup.metadata.createdAt
    };
  }

  /**
   * List available backups
   */
  listBackups() {
    if (!fs.existsSync(this.backupDir)) {
      return [];
    }

    const files = fs.readdirSync(this.backupDir)
      .filter(f => f.startsWith('settings-backup-') && f.endsWith('.json'))
      .map(f => {
        const filePath = path.join(this.backupDir, f);
        const stats = fs.statSync(filePath);
        
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const backup = JSON.parse(content);
          
          return {
            filename: f,
            path: filePath,
            backupId: backup.metadata.backupId,
            label: backup.metadata.label,
            createdAt: backup.metadata.createdAt,
            size: stats.size
          };
        } catch (error) {
          return null;
        }
      })
      .filter(b => b !== null)
      .sort((a, b) => b.createdAt - a.createdAt);

    return files;
  }

  /**
   * Restore from backup
   */
  restoreBackup(backupId, options = {}) {
    const backups = this.listBackups();
    const backup = backups.find(b => b.backupId === backupId);

    if (!backup) {
      throw new Error(`Backup not found: ${backupId}`);
    }

    const content = fs.readFileSync(backup.path, 'utf8');
    const backupData = JSON.parse(content);

    // Create pre-restore backup
    if (!options.skipBackup) {
      this.createBackup('pre-restore');
    }

    // Restore settings
    this.saveSettings(backupData.settings);

    return {
      restored: true,
      backupId,
      timestamp: Date.now(),
      source: backupData.metadata
    };
  }

  /**
   * Delete backup
   */
  deleteBackup(backupId) {
    const backups = this.listBackups();
    const backup = backups.find(b => b.backupId === backupId);

    if (!backup) {
      throw new Error(`Backup not found: ${backupId}`);
    }

    fs.unlinkSync(backup.path);

    return { deleted: true, backupId };
  }

  /**
   * Clean old backups
   */
  cleanOldBackups() {
    const backups = this.listBackups();
    
    if (backups.length > this.maxBackups) {
      const toDelete = backups.slice(this.maxBackups);
      
      toDelete.forEach(backup => {
        try {
          fs.unlinkSync(backup.path);
        } catch (error) {
          console.error(`Failed to delete backup: ${error.message}`);
        }
      });
    }
  }

  /**
   * Merge settings
   */
  mergeSettings(current, imported) {
    const merged = { ...current };

    Object.keys(imported).forEach(key => {
      if (typeof imported[key] === 'object' && !Array.isArray(imported[key])) {
        merged[key] = { ...current[key], ...imported[key] };
      } else {
        merged[key] = imported[key];
      }
    });

    return merged;
  }

  /**
   * Load settings
   */
  loadSettings() {
    try {
      if (fs.existsSync(this.settingsPath)) {
        const content = fs.readFileSync(this.settingsPath, 'utf8');
        return JSON.parse(content);
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }

    return this.getDefaultSettings();
  }

  /**
   * Save settings
   */
  saveSettings(settings) {
    fs.writeFileSync(this.settingsPath, JSON.stringify(settings, null, 2), 'utf8');
  }

  /**
   * Get default settings
   */
  getDefaultSettings() {
    return {
      general: {
        autoStart: false,
        minimizeToTray: true,
        checkUpdates: true,
        language: 'en'
      },
      scanner: {
        scanSpeed: 'balanced',
        deepScan: false,
        scanArchives: true,
        maxFileSize: 100 * 1024 * 1024
      },
      protection: {
        realTimeProtection: true,
        webProtection: true,
        emailProtection: false,
        ransomwareProtection: true
      },
      notifications: {
        enabled: true,
        sound: true,
        threatDetection: true,
        scanComplete: true
      },
      appearance: {
        theme: 'dark',
        compactMode: false,
        showAnimations: true
      },
      advanced: {
        cloudScanning: false,
        behavioralAnalysis: true,
        heuristicScanning: true
      },
      privacy: {
        sendAnonymousStats: false,
        crashReports: true
      }
    };
  }

  /**
   * Calculate checksum
   */
  calculateChecksum(data) {
    const content = JSON.stringify(data);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Encrypt data
   */
  encryptData(data, password) {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      encrypted: true,
      algorithm,
      iv: iv.toString('hex'),
      data: encrypted
    };
  }

  /**
   * Decrypt data
   */
  decryptData(encryptedData, password) {
    if (!encryptedData.encrypted) {
      throw new Error('Data is not encrypted');
    }

    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = Buffer.from(encryptedData.iv, 'hex');
    
    const decipher = crypto.createDecipheriv(encryptedData.algorithm, key, iv);
    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  }

  /**
   * Compare settings
   */
  compareSettings(settings1, settings2) {
    const differences = [];

    const compare = (obj1, obj2, path = '') => {
      Object.keys(obj1).forEach(key => {
        const fullPath = path ? `${path}.${key}` : key;
        
        if (typeof obj1[key] === 'object' && !Array.isArray(obj1[key])) {
          if (obj2[key]) {
            compare(obj1[key], obj2[key], fullPath);
          } else {
            differences.push({ path: fullPath, type: 'missing', value: obj1[key] });
          }
        } else if (obj1[key] !== obj2[key]) {
          differences.push({
            path: fullPath,
            type: 'changed',
            oldValue: obj2[key],
            newValue: obj1[key]
          });
        }
      });
    };

    compare(settings1, settings2);

    return {
      identical: differences.length === 0,
      differences,
      count: differences.length
    };
  }

  /**
   * Reset settings to defaults
   */
  resetToDefaults(options = {}) {
    if (!options.skipBackup) {
      this.createBackup('pre-reset');
    }

    const defaults = this.getDefaultSettings();
    this.saveSettings(defaults);

    return {
      reset: true,
      timestamp: Date.now()
    };
  }

  /**
   * Get settings statistics
   */
  getStatistics() {
    const settings = this.loadSettings();
    const backups = this.listBackups();

    return {
      settingsFile: {
        path: this.settingsPath,
        exists: fs.existsSync(this.settingsPath),
        size: fs.existsSync(this.settingsPath) ? fs.statSync(this.settingsPath).size : 0,
        checksum: this.calculateChecksum(settings)
      },
      backups: {
        count: backups.length,
        totalSize: backups.reduce((sum, b) => sum + b.size, 0),
        oldest: backups.length > 0 ? backups[backups.length - 1].createdAt : null,
        newest: backups.length > 0 ? backups[0].createdAt : null
      },
      categories: {
        total: Object.keys(settings).length,
        list: Object.keys(settings)
      }
    };
  }
}

// Singleton instance
const settingsImportExportService = new SettingsImportExportService();

module.exports = settingsImportExportService;
