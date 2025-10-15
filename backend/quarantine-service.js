/**
 * Real Quarantine Service
 * Handles actual file quarantine with encryption, metadata storage, and restoration
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');

// Configuration
const QUARANTINE_DIR = path.join(__dirname, 'quarantine_vault');
const QUARANTINE_DB = path.join(__dirname, 'data', 'quarantine.db');
const ENCRYPTION_KEY = crypto.randomBytes(32); // In production, use env variable
const ENCRYPTION_IV_LENGTH = 16;

class QuarantineService {
  constructor() {
    this.db = null;
    this.initialized = false;
  }

  /**
   * Initialize quarantine service
   */
  async initialize() {
    if (this.initialized) return;

    try {
      // Create quarantine directory
      await fs.mkdir(QUARANTINE_DIR, { recursive: true });
      
      // Create data directory
      await fs.mkdir(path.dirname(QUARANTINE_DB), { recursive: true });

      // Initialize database
      await this.initializeDatabase();
      
      this.initialized = true;
      console.log('✅ Quarantine service initialized');
      console.log(`   Vault: ${QUARANTINE_DIR}`);
      console.log(`   Database: ${QUARANTINE_DB}`);
    } catch (error) {
      console.error('❌ Failed to initialize quarantine service:', error);
      throw error;
    }
  }

  /**
   * Initialize SQLite database
   */
  async initializeDatabase() {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(QUARANTINE_DB, (err) => {
        if (err) {
          reject(err);
          return;
        }

        // Create quarantine table
        this.db.run(`
          CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT NOT NULL,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            threat_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_hash TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            quarantined_date INTEGER NOT NULL,
            encrypted INTEGER DEFAULT 1,
            metadata TEXT
          )
        `, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    });
  }

  /**
   * Calculate file hash (SHA-256)
   */
  async calculateFileHash(filePath) {
    try {
      const fileBuffer = await fs.readFile(filePath);
      return crypto.createHash('sha256').update(fileBuffer).digest('hex');
    } catch (error) {
      console.error('Error calculating file hash:', error);
      throw error;
    }
  }

  /**
   * Encrypt file content
   */
  encryptFile(buffer) {
    const iv = crypto.randomBytes(ENCRYPTION_IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(buffer),
      cipher.final()
    ]);

    // Return IV + encrypted data
    return Buffer.concat([iv, encrypted]);
  }

  /**
   * Decrypt file content
   */
  decryptFile(encryptedBuffer) {
    const iv = encryptedBuffer.slice(0, ENCRYPTION_IV_LENGTH);
    const encrypted = encryptedBuffer.slice(ENCRYPTION_IV_LENGTH);
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    
    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);
  }

  /**
   * Quarantine a file
   */
  async quarantineFile(filePath, threatInfo) {
    try {
      await this.initialize();

      // Validate file exists
      try {
        await fs.access(filePath);
      } catch {
        throw new Error(`File not found: ${filePath}`);
      }

      // Get file info
      const stats = await fs.stat(filePath);
      const fileName = path.basename(filePath);
      const fileHash = await this.calculateFileHash(filePath);

      // Check if already quarantined
      const existing = await this.findByHash(fileHash);
      if (existing) {
        return {
          success: false,
          message: 'File already quarantined',
          quarantineId: existing.id
        };
      }

      // Read and encrypt file
      const fileContent = await fs.readFile(filePath);
      const encryptedContent = this.encryptFile(fileContent);

      // Generate unique quarantine filename
      const quarantineFileName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}.quar`;
      const quarantinePath = path.join(QUARANTINE_DIR, quarantineFileName);

      // Write encrypted file to quarantine
      await fs.writeFile(quarantinePath, encryptedContent);

      // Store metadata in database
      const quarantineId = await this.addToDatabase({
        fileName: fileName,
        originalPath: filePath,
        quarantinePath: quarantinePath,
        threatType: threatInfo.threatType || 'UNKNOWN',
        threatName: threatInfo.threatName || 'Generic Threat',
        fileSize: stats.size,
        fileHash: fileHash,
        riskLevel: threatInfo.riskLevel || 'medium',
        quarantinedDate: Date.now(),
        metadata: JSON.stringify({
          originalPermissions: stats.mode,
          detectedBy: threatInfo.detectedBy || 'Manual',
          scanDate: threatInfo.scanDate || new Date().toISOString(),
          additionalInfo: threatInfo.additionalInfo || {}
        })
      });

      // Delete original file
      try {
        await fs.unlink(filePath);
        console.log(`✅ Quarantined and deleted: ${filePath}`);
      } catch (error) {
        console.warn(`⚠️ Could not delete original file: ${error.message}`);
      }

      return {
        success: true,
        message: 'File successfully quarantined',
        quarantineId: quarantineId,
        quarantinePath: quarantinePath,
        encrypted: true
      };

    } catch (error) {
      console.error('❌ Quarantine error:', error);
      throw error;
    }
  }

  /**
   * Add file to database
   */
  async addToDatabase(data) {
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO quarantine (
          file_name, original_path, quarantine_path, threat_type, 
          threat_name, file_size, file_hash, risk_level, 
          quarantined_date, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      this.db.run(sql, [
        data.fileName,
        data.originalPath,
        data.quarantinePath,
        data.threatType,
        data.threatName,
        data.fileSize,
        data.fileHash,
        data.riskLevel,
        data.quarantinedDate,
        data.metadata
      ], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.lastID);
        }
      });
    });
  }

  /**
   * Get all quarantined files
   */
  async getAllQuarantined() {
    await this.initialize();

    return new Promise((resolve, reject) => {
      this.db.all('SELECT * FROM quarantine ORDER BY quarantined_date DESC', [], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          // Parse metadata JSON
          const files = rows.map(row => ({
            id: row.id,
            fileName: row.file_name,
            originalPath: row.original_path,
            quarantinePath: row.quarantine_path,
            threatType: row.threat_type,
            threatName: row.threat_name,
            fileSize: row.file_size,
            fileHash: row.file_hash,
            riskLevel: row.risk_level,
            quarantinedDate: new Date(row.quarantined_date),
            encrypted: row.encrypted === 1,
            metadata: row.metadata ? JSON.parse(row.metadata) : {}
          }));
          resolve(files);
        }
      });
    });
  }

  /**
   * Get quarantined file by ID
   */
  async getById(id) {
    await this.initialize();

    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM quarantine WHERE id = ?', [id], (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve(null);
        } else {
          resolve({
            id: row.id,
            fileName: row.file_name,
            originalPath: row.original_path,
            quarantinePath: row.quarantine_path,
            threatType: row.threat_type,
            threatName: row.threat_name,
            fileSize: row.file_size,
            fileHash: row.file_hash,
            riskLevel: row.risk_level,
            quarantinedDate: new Date(row.quarantined_date),
            encrypted: row.encrypted === 1,
            metadata: row.metadata ? JSON.parse(row.metadata) : {}
          });
        }
      });
    });
  }

  /**
   * Find quarantined file by hash
   */
  async findByHash(hash) {
    await this.initialize();

    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM quarantine WHERE file_hash = ?', [hash], (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          resolve(null);
        } else {
          resolve({
            id: row.id,
            fileName: row.file_name,
            originalPath: row.original_path,
            quarantinePath: row.quarantine_path,
            threatType: row.threat_type,
            threatName: row.threat_name,
            fileSize: row.file_size,
            fileHash: row.file_hash,
            riskLevel: row.risk_level,
            quarantinedDate: new Date(row.quarantined_date),
            encrypted: row.encrypted === 1,
            metadata: row.metadata ? JSON.parse(row.metadata) : {}
          });
        }
      });
    });
  }

  /**
   * Restore file from quarantine
   */
  async restoreFile(id, targetPath = null) {
    try {
      await this.initialize();

      // Get quarantine record
      const record = await this.getById(id);
      if (!record) {
        throw new Error('Quarantine record not found');
      }

      // Verify quarantined file exists
      try {
        await fs.access(record.quarantinePath);
      } catch {
        throw new Error('Quarantined file not found in vault');
      }

      // Determine restore path
      const restorePath = targetPath || record.originalPath;

      // Read and decrypt file
      const encryptedContent = await fs.readFile(record.quarantinePath);
      const decryptedContent = this.decryptFile(encryptedContent);

      // Ensure target directory exists
      await fs.mkdir(path.dirname(restorePath), { recursive: true });

      // Write restored file
      await fs.writeFile(restorePath, decryptedContent);

      // Restore original permissions if available
      if (record.metadata.originalPermissions) {
        try {
          await fs.chmod(restorePath, record.metadata.originalPermissions);
        } catch (error) {
          console.warn('Could not restore file permissions:', error.message);
        }
      }

      // Delete from quarantine vault
      await fs.unlink(record.quarantinePath);

      // Remove from database
      await this.deleteFromDatabase(id);

      console.log(`✅ Restored: ${restorePath}`);

      return {
        success: true,
        message: 'File successfully restored',
        restoredPath: restorePath
      };

    } catch (error) {
      console.error('❌ Restore error:', error);
      throw error;
    }
  }

  /**
   * Permanently delete quarantined file
   */
  async deleteQuarantined(id) {
    try {
      await this.initialize();

      // Get quarantine record
      const record = await this.getById(id);
      if (!record) {
        throw new Error('Quarantine record not found');
      }

      // Delete encrypted file from vault
      try {
        await fs.unlink(record.quarantinePath);
      } catch (error) {
        console.warn('Could not delete quarantine file:', error.message);
      }

      // Remove from database
      await this.deleteFromDatabase(id);

      console.log(`✅ Permanently deleted: ${record.fileName}`);

      return {
        success: true,
        message: 'File permanently deleted'
      };

    } catch (error) {
      console.error('❌ Delete error:', error);
      throw error;
    }
  }

  /**
   * Delete record from database
   */
  async deleteFromDatabase(id) {
    return new Promise((resolve, reject) => {
      this.db.run('DELETE FROM quarantine WHERE id = ?', [id], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes);
        }
      });
    });
  }

  /**
   * Get quarantine statistics
   */
  async getStatistics() {
    await this.initialize();

    return new Promise((resolve, reject) => {
      this.db.all(`
        SELECT 
          COUNT(*) as total_files,
          SUM(file_size) as total_size,
          threat_type,
          risk_level,
          COUNT(*) as count
        FROM quarantine
        GROUP BY threat_type, risk_level
      `, [], (err, rows) => {
        if (err) {
          reject(err);
        } else {
          this.db.get('SELECT COUNT(*) as total, SUM(file_size) as size FROM quarantine', [], (err, summary) => {
            if (err) {
              reject(err);
            } else {
              resolve({
                totalFiles: summary.total || 0,
                totalSize: summary.size || 0,
                byThreatType: this.groupBy(rows, 'threat_type'),
                byRiskLevel: this.groupBy(rows, 'risk_level')
              });
            }
          });
        }
      });
    });
  }

  /**
   * Helper to group statistics
   */
  groupBy(rows, field) {
    const grouped = {};
    rows.forEach(row => {
      const key = row[field];
      if (!grouped[key]) {
        grouped[key] = 0;
      }
      grouped[key] += row.count;
    });
    return grouped;
  }

  /**
   * Bulk delete quarantined files
   */
  async bulkDelete(ids) {
    const results = {
      success: [],
      failed: []
    };

    for (const id of ids) {
      try {
        await this.deleteQuarantined(id);
        results.success.push(id);
      } catch (error) {
        results.failed.push({ id, error: error.message });
      }
    }

    return results;
  }

  /**
   * Bulk restore quarantined files
   */
  async bulkRestore(ids) {
    const results = {
      success: [],
      failed: []
    };

    for (const id of ids) {
      try {
        const result = await this.restoreFile(id);
        results.success.push({ id, path: result.restoredPath });
      } catch (error) {
        results.failed.push({ id, error: error.message });
      }
    }

    return results;
  }

  /**
   * Export quarantine report
   */
  async exportReport() {
    const files = await this.getAllQuarantined();
    const stats = await this.getStatistics();

    return {
      generatedAt: new Date().toISOString(),
      statistics: stats,
      files: files.map(f => ({
        id: f.id,
        fileName: f.fileName,
        originalPath: f.originalPath,
        threatType: f.threatType,
        threatName: f.threatName,
        fileSize: f.fileSize,
        riskLevel: f.riskLevel,
        quarantinedDate: f.quarantinedDate,
        fileHash: f.fileHash
      }))
    };
  }

  /**
   * Clean up old quarantine files (older than specified days)
   */
  async cleanupOldFiles(daysOld = 30) {
    await this.initialize();

    const cutoffDate = Date.now() - (daysOld * 24 * 60 * 60 * 1000);

    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM quarantine WHERE quarantined_date < ?',
        [cutoffDate],
        async (err, rows) => {
          if (err) {
            reject(err);
            return;
          }

          let deleted = 0;
          for (const row of rows) {
            try {
              await this.deleteQuarantined(row.id);
              deleted++;
            } catch (error) {
              console.error(`Failed to delete old quarantine file ${row.id}:`, error);
            }
          }

          resolve({
            deleted: deleted,
            message: `Cleaned up ${deleted} old quarantine files`
          });
        }
      );
    });
  }

  /**
   * Close database connection
   */
  async close() {
    if (this.db) {
      return new Promise((resolve, reject) => {
        this.db.close((err) => {
          if (err) {
            reject(err);
          } else {
            console.log('✅ Quarantine database closed');
            resolve();
          }
        });
      });
    }
  }
}

// Export singleton instance
module.exports = new QuarantineService();
