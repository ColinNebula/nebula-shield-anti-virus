/**
 * Backup & Restore Service
 * Handles system backups, configuration exports, and data restoration
 */

const fs = require('fs').promises;
const path = require('path');
const archiver = require('archiver');
const extract = require('extract-zip');
const crypto = require('crypto');

class BackupService {
  constructor() {
    this.backupDir = path.join(__dirname, 'backups');
    this.maxBackups = 10; // Keep last 10 backups
    this.initialized = false;
  }

  /**
   * Initialize backup service
   */
  async initialize() {
    if (this.initialized) return;

    try {
      await fs.mkdir(this.backupDir, { recursive: true });
      this.initialized = true;
      console.log('✅ Backup service initialized');
    } catch (error) {
      console.error('❌ Failed to initialize backup service:', error);
      throw error;
    }
  }

  /**
   * Create full system backup
   */
  async createBackup(options = {}) {
    await this.initialize();

    const {
      includeLogs = true,
      includeQuarantine = true,
      includeSettings = true,
      includeActivities = true,
      description = 'Manual backup'
    } = options;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupId = crypto.randomBytes(8).toString('hex');
    const backupName = `backup_${timestamp}_${backupId}`;
    const backupPath = path.join(this.backupDir, `${backupName}.zip`);

    try {
      // Create backup metadata
      const metadata = {
        id: backupId,
        name: backupName,
        createdAt: new Date().toISOString(),
        description: description,
        version: '1.0.0',
        includes: {
          logs: includeLogs,
          quarantine: includeQuarantine,
          settings: includeSettings,
          activities: includeActivities
        }
      };

      // Create zip archive
      const output = await fs.open(backupPath, 'w');
      const archive = archiver('zip', {
        zlib: { level: 9 } // Maximum compression
      });

      // Pipe archive to file
      const writeStream = output.createWriteStream();
      archive.pipe(writeStream);

      // Add metadata
      archive.append(JSON.stringify(metadata, null, 2), { name: 'metadata.json' });

      // Add quarantine database
      if (includeQuarantine) {
        const quarantineDb = path.join(__dirname, 'data', 'quarantine.db');
        try {
          await fs.access(quarantineDb);
          archive.file(quarantineDb, { name: 'quarantine.db' });
        } catch (error) {
          console.warn('Quarantine database not found, skipping...');
        }
      }

      // Add activity logs
      if (includeActivities) {
        const activityDb = path.join(__dirname, 'data', 'activity.db');
        try {
          await fs.access(activityDb);
          archive.file(activityDb, { name: 'activity.db' });
        } catch (error) {
          console.warn('Activity database not found, skipping...');
        }
      }

      // Add log files
      if (includeLogs) {
        const logsDir = path.join(__dirname, 'logs');
        try {
          await fs.access(logsDir);
          archive.directory(logsDir, 'logs');
        } catch (error) {
          console.warn('Logs directory not found, skipping...');
        }
      }

      // Add settings/configuration
      if (includeSettings) {
        const settingsFile = path.join(__dirname, 'data', 'settings.json');
        try {
          await fs.access(settingsFile);
          archive.file(settingsFile, { name: 'settings.json' });
        } catch (error) {
          console.warn('Settings file not found, skipping...');
        }
      }

      // Finalize archive
      await archive.finalize();

      // Wait for write to complete
      await new Promise((resolve, reject) => {
        writeStream.on('close', resolve);
        writeStream.on('error', reject);
      });

      // Get backup size
      const stats = await fs.stat(backupPath);

      // Cleanup old backups
      await this.cleanupOldBackups();

      console.log(`✅ Backup created: ${backupName}`);

      return {
        success: true,
        backup: {
          id: backupId,
          name: backupName,
          path: backupPath,
          size: stats.size,
          createdAt: metadata.createdAt,
          description: description,
          includes: metadata.includes
        }
      };

    } catch (error) {
      console.error('❌ Backup failed:', error);
      
      // Cleanup failed backup
      try {
        await fs.unlink(backupPath);
      } catch {}

      throw error;
    }
  }

  /**
   * List all backups
   */
  async listBackups() {
    await this.initialize();

    try {
      const files = await fs.readdir(this.backupDir);
      const backups = [];

      for (const file of files) {
        if (!file.endsWith('.zip')) continue;

        const filePath = path.join(this.backupDir, file);
        const stats = await fs.stat(filePath);

        // Try to read metadata from zip
        let metadata = null;
        try {
          // For simplicity, we'll parse the filename
          // In production, you'd extract and read metadata.json
          const parts = file.replace('.zip', '').split('_');
          metadata = {
            id: parts[parts.length - 1],
            name: file.replace('.zip', ''),
            createdAt: new Date(stats.birthtime).toISOString(),
            size: stats.size
          };
        } catch (error) {
          console.warn(`Could not parse metadata for ${file}`);
        }

        if (metadata) {
          backups.push(metadata);
        }
      }

      // Sort by creation date (newest first)
      backups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      return backups;

    } catch (error) {
      console.error('Failed to list backups:', error);
      return [];
    }
  }

  /**
   * Restore from backup
   */
  async restoreBackup(backupId, options = {}) {
    await this.initialize();

    const {
      restoreLogs = true,
      restoreQuarantine = true,
      restoreSettings = true,
      restoreActivities = true
    } = options;

    try {
      // Find backup file
      const backups = await this.listBackups();
      const backup = backups.find(b => b.id === backupId);

      if (!backup) {
        throw new Error('Backup not found');
      }

      const backupPath = path.join(this.backupDir, `${backup.name}.zip`);
      const tempExtractDir = path.join(this.backupDir, `temp_${Date.now()}`);

      // Extract backup
      await extract(backupPath, { dir: tempExtractDir });

      // Read metadata
      const metadataPath = path.join(tempExtractDir, 'metadata.json');
      const metadataContent = await fs.readFile(metadataPath, 'utf8');
      const metadata = JSON.parse(metadataContent);

      console.log(`📦 Restoring backup: ${metadata.name}`);

      // Restore quarantine database
      if (restoreQuarantine && metadata.includes.quarantine) {
        const sourceDb = path.join(tempExtractDir, 'quarantine.db');
        const targetDb = path.join(__dirname, 'data', 'quarantine.db');
        try {
          await fs.copyFile(sourceDb, targetDb);
          console.log('✅ Quarantine database restored');
        } catch (error) {
          console.warn('Could not restore quarantine database:', error.message);
        }
      }

      // Restore activity database
      if (restoreActivities && metadata.includes.activities) {
        const sourceDb = path.join(tempExtractDir, 'activity.db');
        const targetDb = path.join(__dirname, 'data', 'activity.db');
        try {
          await fs.copyFile(sourceDb, targetDb);
          console.log('✅ Activity database restored');
        } catch (error) {
          console.warn('Could not restore activity database:', error.message);
        }
      }

      // Restore logs
      if (restoreLogs && metadata.includes.logs) {
        const sourceLogsDir = path.join(tempExtractDir, 'logs');
        const targetLogsDir = path.join(__dirname, 'logs');
        try {
          await fs.mkdir(targetLogsDir, { recursive: true });
          const logFiles = await fs.readdir(sourceLogsDir);
          for (const logFile of logFiles) {
            await fs.copyFile(
              path.join(sourceLogsDir, logFile),
              path.join(targetLogsDir, logFile)
            );
          }
          console.log('✅ Logs restored');
        } catch (error) {
          console.warn('Could not restore logs:', error.message);
        }
      }

      // Restore settings
      if (restoreSettings && metadata.includes.settings) {
        const sourceSettings = path.join(tempExtractDir, 'settings.json');
        const targetSettings = path.join(__dirname, 'data', 'settings.json');
        try {
          await fs.copyFile(sourceSettings, targetSettings);
          console.log('✅ Settings restored');
        } catch (error) {
          console.warn('Could not restore settings:', error.message);
        }
      }

      // Cleanup temp directory
      await fs.rm(tempExtractDir, { recursive: true, force: true });

      console.log('✅ Restore completed successfully');

      return {
        success: true,
        message: 'Backup restored successfully',
        restored: {
          quarantine: restoreQuarantine && metadata.includes.quarantine,
          activities: restoreActivities && metadata.includes.activities,
          logs: restoreLogs && metadata.includes.logs,
          settings: restoreSettings && metadata.includes.settings
        }
      };

    } catch (error) {
      console.error('❌ Restore failed:', error);
      throw error;
    }
  }

  /**
   * Delete backup
   */
  async deleteBackup(backupId) {
    await this.initialize();

    try {
      const backups = await this.listBackups();
      const backup = backups.find(b => b.id === backupId);

      if (!backup) {
        throw new Error('Backup not found');
      }

      const backupPath = path.join(this.backupDir, `${backup.name}.zip`);
      await fs.unlink(backupPath);

      console.log(`🗑️ Deleted backup: ${backup.name}`);

      return {
        success: true,
        message: 'Backup deleted successfully'
      };

    } catch (error) {
      console.error('Failed to delete backup:', error);
      throw error;
    }
  }

  /**
   * Cleanup old backups (keep only most recent)
   */
  async cleanupOldBackups() {
    try {
      const backups = await this.listBackups();

      if (backups.length > this.maxBackups) {
        const toDelete = backups.slice(this.maxBackups);
        
        for (const backup of toDelete) {
          await this.deleteBackup(backup.id);
        }

        console.log(`🧹 Cleaned up ${toDelete.length} old backup(s)`);
      }
    } catch (error) {
      console.error('Failed to cleanup old backups:', error);
    }
  }

  /**
   * Export configuration
   */
  async exportConfiguration() {
    const config = {
      exportedAt: new Date().toISOString(),
      version: '1.0.0',
      settings: {
        realTimeProtection: true,
        autoQuarantine: true,
        scanDepth: 'deep',
        updateFrequency: 'daily',
        notificationsEnabled: true
      },
      // Add other configuration as needed
    };

    return config;
  }

  /**
   * Import configuration
   */
  async importConfiguration(config) {
    try {
      // Validate configuration
      if (!config.version || !config.settings) {
        throw new Error('Invalid configuration format');
      }

      // Save to settings file
      const settingsPath = path.join(__dirname, 'data', 'settings.json');
      await fs.mkdir(path.dirname(settingsPath), { recursive: true });
      await fs.writeFile(settingsPath, JSON.stringify(config, null, 2));

      console.log('✅ Configuration imported successfully');

      return {
        success: true,
        message: 'Configuration imported successfully'
      };

    } catch (error) {
      console.error('Failed to import configuration:', error);
      throw error;
    }
  }

  /**
   * Get backup statistics
   */
  async getStatistics() {
    const backups = await this.listBackups();
    
    const totalSize = backups.reduce((sum, backup) => sum + backup.size, 0);

    return {
      totalBackups: backups.length,
      totalSize: totalSize,
      oldestBackup: backups.length > 0 ? backups[backups.length - 1].createdAt : null,
      newestBackup: backups.length > 0 ? backups[0].createdAt : null,
      maxBackups: this.maxBackups
    };
  }
}

// Singleton instance
module.exports = new BackupService();
