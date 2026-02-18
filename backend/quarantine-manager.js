/**
 * Quarantine Manager
 * Securely isolates and manages potentially malicious files
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

class QuarantineManager {
    constructor() {
        // Quarantine directory in AppData
        const appDataPath = process.env.APPDATA || path.join(process.env.USERPROFILE, 'AppData', 'Roaming');
        this.quarantineDir = path.join(appDataPath, 'nebula-shield-anti-virus', 'quarantine');
        this.quarantineDbPath = path.join(appDataPath, 'nebula-shield-anti-virus', 'data', 'quarantine.json');
        
        // In-memory store (synced with JSON file)
        this.quarantineStore = [];
        
        this.initializeQuarantine();
    }

    /**
     * Initialize quarantine directory and database
     */
    async initializeQuarantine() {
        try {
            // Create quarantine directory
            if (!fsSync.existsSync(this.quarantineDir)) {
                await fs.mkdir(this.quarantineDir, { recursive: true });
                console.log('✅ Quarantine directory created:', this.quarantineDir);
            }

            // Create data directory for database
            const dataDir = path.dirname(this.quarantineDbPath);
            if (!fsSync.existsSync(dataDir)) {
                await fs.mkdir(dataDir, { recursive: true });
            }

            // Load existing quarantine database
            await this.loadQuarantineDb();
            
            console.log('✅ Quarantine manager initialized');
        } catch (error) {
            console.error('❌ Failed to initialize quarantine:', error);
        }
    }

    /**
     * Load quarantine database from JSON file
     */
    async loadQuarantineDb() {
        try {
            if (fsSync.existsSync(this.quarantineDbPath)) {
                const data = await fs.readFile(this.quarantineDbPath, 'utf8');
                this.quarantineStore = JSON.parse(data);
                console.log(`📂 Loaded ${this.quarantineStore.length} quarantined files`);
            } else {
                this.quarantineStore = [];
            }
        } catch (error) {
            console.error('Error loading quarantine database:', error);
            this.quarantineStore = [];
        }
    }

    /**
     * Save quarantine database to JSON file
     */
    async saveQuarantineDb() {
        try {
            await fs.writeFile(
                this.quarantineDbPath, 
                JSON.stringify(this.quarantineStore, null, 2),
                'utf8'
            );
        } catch (error) {
            console.error('Error saving quarantine database:', error);
        }
    }

    /**
     * Quarantine a file
     */
    async quarantineFile(filePath, threatName, threatType) {
        try {
            // Check if file exists
            const fileStats = await fs.stat(filePath);
            
            // Generate unique quarantine ID
            const quarantineId = crypto.randomBytes(16).toString('hex');
            const originalFileName = path.basename(filePath);
            const quarantineFileName = `${quarantineId}.qtn`;
            const quarantinePath = path.join(this.quarantineDir, quarantineFileName);

            // Read original file
            const fileContent = await fs.readFile(filePath);
            
            // Calculate file hash
            const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');

            // Encrypt file content (simple XOR encryption for isolation)
            const encryptionKey = crypto.randomBytes(32);
            const encryptedContent = this.encryptFile(fileContent, encryptionKey);

            // Write encrypted file to quarantine
            await fs.writeFile(quarantinePath, encryptedContent);

            // Store metadata
            const quarantineEntry = {
                id: quarantineId,
                originalPath: filePath,
                originalFileName: originalFileName,
                quarantinePath: quarantinePath,
                threatName: threatName,
                threatType: threatType,
                fileSize: fileStats.size,
                fileHash: fileHash,
                encryptionKey: encryptionKey.toString('hex'),
                quarantineDate: new Date().toISOString(),
                status: 'quarantined'
            };

            this.quarantineStore.push(quarantineEntry);
            await this.saveQuarantineDb();

            // Delete original file
            try {
                await fs.unlink(filePath);
                console.log(`✅ File quarantined: ${filePath} -> ${quarantinePath}`);
            } catch (error) {
                console.error('⚠️ Could not delete original file:', error);
                quarantineEntry.status = 'quarantined (original not deleted)';
            }

            return {
                success: true,
                quarantineId: quarantineId,
                message: 'File quarantined successfully'
            };

        } catch (error) {
            console.error('Error quarantining file:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Restore a quarantined file
     */
    async restoreFile(quarantineId) {
        try {
            const entry = this.quarantineStore.find(e => e.id === quarantineId);
            
            if (!entry) {
                return {
                    success: false,
                    error: 'Quarantined file not found'
                };
            }

            // Read encrypted file
            const encryptedContent = await fs.readFile(entry.quarantinePath);
            
            // Decrypt file
            const encryptionKey = Buffer.from(entry.encryptionKey, 'hex');
            const decryptedContent = this.decryptFile(encryptedContent, encryptionKey);

            // Create directory if it doesn't exist
            const originalDir = path.dirname(entry.originalPath);
            if (!fsSync.existsSync(originalDir)) {
                await fs.mkdir(originalDir, { recursive: true });
            }

            // Restore to original location
            await fs.writeFile(entry.originalPath, decryptedContent);

            // Remove from quarantine
            await fs.unlink(entry.quarantinePath);
            
            // Update database
            this.quarantineStore = this.quarantineStore.filter(e => e.id !== quarantineId);
            await this.saveQuarantineDb();

            console.log(`✅ File restored: ${entry.originalPath}`);

            return {
                success: true,
                restoredPath: entry.originalPath,
                message: 'File restored successfully'
            };

        } catch (error) {
            console.error('Error restoring file:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Permanently delete a quarantined file
     */
    async deleteQuarantinedFile(quarantineId) {
        try {
            const entry = this.quarantineStore.find(e => e.id === quarantineId);
            
            if (!entry) {
                return {
                    success: false,
                    error: 'Quarantined file not found'
                };
            }

            // Delete quarantined file
            await fs.unlink(entry.quarantinePath);
            
            // Remove from database
            this.quarantineStore = this.quarantineStore.filter(e => e.id !== quarantineId);
            await this.saveQuarantineDb();

            console.log(`🗑️ Quarantined file permanently deleted: ${entry.originalFileName}`);

            return {
                success: true,
                message: 'File permanently deleted'
            };

        } catch (error) {
            console.error('Error deleting quarantined file:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Get all quarantined files
     */
    getQuarantinedFiles() {
        return this.quarantineStore.map(entry => ({
            id: entry.id,
            fileName: entry.originalFileName,
            originalPath: entry.originalPath,
            threatName: entry.threatName,
            threatType: entry.threatType,
            fileSize: entry.fileSize,
            quarantineDate: entry.quarantineDate,
            status: entry.status
        }));
    }

    /**
     * Get quarantine statistics
     */
    getQuarantineStats() {
        return {
            totalQuarantined: this.quarantineStore.length,
            totalSize: this.quarantineStore.reduce((sum, e) => sum + e.fileSize, 0),
            byThreatType: this.quarantineStore.reduce((acc, e) => {
                acc[e.threatType] = (acc[e.threatType] || 0) + 1;
                return acc;
            }, {}),
            quarantineDir: this.quarantineDir
        };
    }

    /**
     * Simple XOR encryption for file isolation
     */
    encryptFile(buffer, key) {
        const encrypted = Buffer.alloc(buffer.length);
        for (let i = 0; i < buffer.length; i++) {
            encrypted[i] = buffer[i] ^ key[i % key.length];
        }
        return encrypted;
    }

    /**
     * Simple XOR decryption
     */
    decryptFile(buffer, key) {
        // XOR is symmetric
        return this.encryptFile(buffer, key);
    }
}

// Export singleton instance
module.exports = new QuarantineManager();
