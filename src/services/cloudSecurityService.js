/**
 * Cloud Security Service
 * Secure cloud storage, sync, and backup with end-to-end encryption
 */

import CryptoJS from 'crypto-js';
import notificationService from './notificationService';

class CloudSecurityService {
  constructor() {
    this.encryptionKey = null;
    this.cloudProvider = 'nebula-cloud'; // Default provider
    this.syncEnabled = false;
    this.autoBackup = true;
    this.encryptionEnabled = true;
    this.cloudFiles = new Map();
    this.syncQueue = [];
    this.uploadProgress = new Map();
    this.downloadProgress = new Map();
    this.listeners = new Set();
    this.stats = {
      totalUploaded: 0,
      totalDownloaded: 0,
      filesInCloud: 0,
      storageUsed: 0,
      storageLimit: 10 * 1024 * 1024 * 1024, // 10GB
      lastSync: null
    };
    this.loadSettings();
  }

  // ==================== ENCRYPTION ====================

  generateEncryptionKey(password) {
    // Derive key from password using PBKDF2
    const salt = CryptoJS.lib.WordArray.random(128/8);
    const key = CryptoJS.PBKDF2(password, salt, {
      keySize: 256/32,
      iterations: 10000
    });
    
    return {
      key: key.toString(),
      salt: salt.toString()
    };
  }

  setEncryptionKey(password) {
    const { key, salt } = this.generateEncryptionKey(password);
    this.encryptionKey = key;
    localStorage.setItem('cloud_encryption_salt', salt);
    this.saveSettings();
    
    notificationService.show({
      type: 'success',
      title: 'Encryption Key Set',
      message: 'Your cloud data will be encrypted with this key',
      duration: 3000
    });
  }

  encryptData(data) {
    if (!this.encryptionEnabled || !this.encryptionKey) {
      return data; // Return unencrypted if disabled
    }

    try {
      const encrypted = CryptoJS.AES.encrypt(
        typeof data === 'string' ? data : JSON.stringify(data),
        this.encryptionKey
      );
      
      return encrypted.toString();
    } catch (error) {
      console.error('[Cloud Security] Encryption failed:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  decryptData(encryptedData) {
    if (!this.encryptionEnabled || !this.encryptionKey) {
      return encryptedData;
    }

    try {
      const decrypted = CryptoJS.AES.decrypt(encryptedData, this.encryptionKey);
      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);
      
      try {
        return JSON.parse(decryptedString);
      } catch {
        return decryptedString;
      }
    } catch (error) {
      console.error('[Cloud Security] Decryption failed:', error);
      throw new Error('Failed to decrypt data - wrong password?');
    }
  }

  // ==================== FILE OPERATIONS ====================

  async uploadFile(file, options = {}) {
    const { encrypt = true, compress = false, metadata = {} } = options;

    try {
      // Read file
      const fileData = await this.readFile(file);
      
      // Compress if requested
      let processedData = fileData;
      if (compress) {
        processedData = await this.compressData(fileData);
      }

      // Encrypt
      const encryptedData = encrypt ? this.encryptData(processedData) : processedData;

      // Generate file ID
      const fileId = this.generateFileId(file.name);

      // Create cloud file entry
      const cloudFile = {
        id: fileId,
        name: file.name,
        size: file.size,
        encryptedSize: encryptedData.length,
        type: file.type,
        encrypted: encrypt,
        compressed: compress,
        uploadedAt: new Date().toISOString(),
        metadata,
        checksum: this.calculateChecksum(fileData)
      };

      // Simulate upload with progress
      await this.simulateUpload(fileId, encryptedData, cloudFile);

      // Store in cloud
      this.cloudFiles.set(fileId, cloudFile);
      
      // Update stats
      this.stats.filesInCloud++;
      this.stats.totalUploaded += cloudFile.encryptedSize;
      this.stats.storageUsed += cloudFile.encryptedSize;
      this.saveSettings();

      notificationService.show({
        type: 'success',
        title: 'Upload Complete',
        message: `${file.name} uploaded securely`,
        duration: 3000
      });

      return cloudFile;

    } catch (error) {
      console.error('[Cloud Security] Upload failed:', error);
      throw error;
    }
  }

  async downloadFile(fileId) {
    try {
      const cloudFile = this.cloudFiles.get(fileId);
      if (!cloudFile) {
        throw new Error('File not found in cloud');
      }

      // Simulate download with progress
      const encryptedData = await this.simulateDownload(fileId, cloudFile);

      // Decrypt
      const decryptedData = cloudFile.encrypted 
        ? this.decryptData(encryptedData) 
        : encryptedData;

      // Decompress if needed
      const fileData = cloudFile.compressed 
        ? await this.decompressData(decryptedData) 
        : decryptedData;

      // Verify checksum
      const checksum = this.calculateChecksum(fileData);
      if (checksum !== cloudFile.checksum) {
        throw new Error('File integrity check failed');
      }

      // Update stats
      this.stats.totalDownloaded += cloudFile.encryptedSize;
      this.saveSettings();

      notificationService.show({
        type: 'success',
        title: 'Download Complete',
        message: `${cloudFile.name} downloaded and verified`,
        duration: 3000
      });

      return {
        file: cloudFile,
        data: fileData
      };

    } catch (error) {
      console.error('[Cloud Security] Download failed:', error);
      throw error;
    }
  }

  async deleteFile(fileId) {
    const cloudFile = this.cloudFiles.get(fileId);
    if (!cloudFile) {
      throw new Error('File not found');
    }

    // Remove from cloud storage
    await this.simulateDelete(fileId);

    // Update stats
    this.stats.filesInCloud--;
    this.stats.storageUsed -= cloudFile.encryptedSize;
    
    // Remove from local cache
    this.cloudFiles.delete(fileId);
    this.saveSettings();

    notificationService.show({
      type: 'info',
      title: 'File Deleted',
      message: `${cloudFile.name} removed from cloud`,
      duration: 2000
    });
  }

  // ==================== SYNC OPERATIONS ====================

  async enableSync(password) {
    if (!password) {
      throw new Error('Password required for cloud sync');
    }

    this.setEncryptionKey(password);
    this.syncEnabled = true;
    this.saveSettings();

    // Start sync
    await this.performSync();

    notificationService.show({
      type: 'success',
      title: 'Cloud Sync Enabled',
      message: 'Your data will be automatically synced',
      duration: 3000
    });
  }

  async disableSync() {
    this.syncEnabled = false;
    this.saveSettings();

    notificationService.show({
      type: 'info',
      title: 'Cloud Sync Disabled',
      message: 'Automatic sync has been turned off',
      duration: 2000
    });
  }

  async performSync() {
    if (!this.syncEnabled) {
      return;
    }

    try {
      this.notifyListeners({ type: 'sync_started' });

      // Get local files
      const localFiles = this.getLocalFilesToSync();

      // Upload new/modified files
      for (const file of localFiles) {
        if (!this.isFileInCloud(file)) {
          await this.uploadFile(file, { encrypt: true });
        }
      }

      // Download cloud files not present locally
      const cloudFileIds = Array.from(this.cloudFiles.keys());
      for (const fileId of cloudFileIds) {
        if (!this.isFileLocal(fileId)) {
          await this.downloadFile(fileId);
        }
      }

      this.stats.lastSync = new Date().toISOString();
      this.saveSettings();

      this.notifyListeners({ type: 'sync_completed', filesSync: localFiles.length });

      notificationService.show({
        type: 'success',
        title: 'Sync Complete',
        message: `${localFiles.length} files synchronized`,
        duration: 2000
      });

    } catch (error) {
      console.error('[Cloud Security] Sync failed:', error);
      this.notifyListeners({ type: 'sync_failed', error: error.message });
      throw error;
    }
  }

  // ==================== BACKUP OPERATIONS ====================

  async createBackup(data, name = 'backup') {
    const backup = {
      name,
      timestamp: new Date().toISOString(),
      data,
      size: JSON.stringify(data).length
    };

    const backupFile = new Blob([JSON.stringify(backup)], { type: 'application/json' });
    const file = new File([backupFile], `${name}-${Date.now()}.bak`, { type: 'application/json' });

    return await this.uploadFile(file, { 
      encrypt: true, 
      compress: true,
      metadata: { type: 'backup', name }
    });
  }

  async restoreBackup(fileId) {
    const { data } = await this.downloadFile(fileId);
    const backup = typeof data === 'string' ? JSON.parse(data) : data;

    notificationService.show({
      type: 'success',
      title: 'Backup Restored',
      message: `${backup.name} restored successfully`,
      duration: 3000
    });

    return backup.data;
  }

  getBackups() {
    return Array.from(this.cloudFiles.values())
      .filter(file => file.metadata?.type === 'backup')
      .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  }

  // ==================== CLOUD THREAT DETECTION ====================

  async scanCloudFile(fileId) {
    const cloudFile = this.cloudFiles.get(fileId);
    if (!cloudFile) {
      throw new Error('File not found');
    }

    // Simulate cloud-based malware scan
    return new Promise((resolve) => {
      setTimeout(() => {
        const isMalicious = Math.random() < 0.02; // 2% chance for demo
        
        const result = {
          fileId,
          fileName: cloudFile.name,
          scanned: true,
          malicious: isMalicious,
          threats: isMalicious ? ['Trojan.Generic.Cloud', 'Suspicious.Archive'] : [],
          scannedAt: new Date().toISOString(),
          scanEngine: 'Nebula Cloud Scanner'
        };

        if (isMalicious) {
          notificationService.show({
            type: 'error',
            title: 'Threat Detected in Cloud',
            message: `${cloudFile.name} contains malware`,
            duration: 5000
          });
        }

        resolve(result);
      }, 1500);
    });
  }

  async scanAllCloudFiles() {
    const results = [];
    for (const fileId of this.cloudFiles.keys()) {
      const scanResult = await this.scanCloudFile(fileId);
      results.push(scanResult);
    }

    const threatsFound = results.filter(r => r.malicious).length;

    notificationService.show({
      type: threatsFound > 0 ? 'warning' : 'success',
      title: 'Cloud Scan Complete',
      message: threatsFound > 0 
        ? `${threatsFound} threats found in cloud storage`
        : 'All cloud files are safe',
      duration: 3000
    });

    return results;
  }

  // ==================== UTILITIES ====================

  readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  }

  async compressData(data) {
    // Simulate compression (in production, use pako or similar)
    return `COMPRESSED:${data}`;
  }

  async decompressData(data) {
    // Simulate decompression
    return data.replace('COMPRESSED:', '');
  }

  calculateChecksum(data) {
    return CryptoJS.SHA256(data.toString()).toString();
  }

  generateFileId(fileName) {
    return `${Date.now()}-${CryptoJS.SHA256(fileName).toString().substring(0, 16)}`;
  }

  simulateUpload(fileId, data, file) {
    return new Promise((resolve) => {
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 20;
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
          this.uploadProgress.delete(fileId);
          resolve();
        } else {
          this.uploadProgress.set(fileId, progress);
          this.notifyListeners({ type: 'upload_progress', fileId, progress, file });
        }
      }, 200);
    });
  }

  simulateDownload(fileId, file) {
    return new Promise((resolve) => {
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 25;
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
          this.downloadProgress.delete(fileId);
          // Simulate encrypted data
          resolve(`ENCRYPTED_DATA_FOR_${fileId}`);
        } else {
          this.downloadProgress.set(fileId, progress);
          this.notifyListeners({ type: 'download_progress', fileId, progress, file });
        }
      }, 150);
    });
  }

  simulateDelete(fileId) {
    return new Promise((resolve) => {
      setTimeout(resolve, 500);
    });
  }

  getLocalFilesToSync() {
    // In production, scan local directories
    return [];
  }

  isFileInCloud(file) {
    return Array.from(this.cloudFiles.values()).some(cf => cf.name === file.name);
  }

  isFileLocal(fileId) {
    // In production, check local filesystem
    return false;
  }

  getStorageInfo() {
    const used = this.stats.storageUsed;
    const limit = this.stats.storageLimit;
    const available = limit - used;
    const percentUsed = (used / limit) * 100;

    return {
      used,
      available,
      limit,
      percentUsed: percentUsed.toFixed(2),
      filesCount: this.stats.filesInCloud
    };
  }

  getCloudFiles() {
    return Array.from(this.cloudFiles.values()).sort((a, b) => 
      new Date(b.uploadedAt) - new Date(a.uploadedAt)
    );
  }

  // ==================== SETTINGS ====================

  loadSettings() {
    try {
      const saved = localStorage.getItem('cloud_security_settings');
      if (saved) {
        const settings = JSON.parse(saved);
        this.cloudProvider = settings.cloudProvider || 'nebula-cloud';
        this.syncEnabled = settings.syncEnabled || false;
        this.autoBackup = settings.autoBackup !== undefined ? settings.autoBackup : true;
        this.encryptionEnabled = settings.encryptionEnabled !== undefined ? settings.encryptionEnabled : true;
        this.encryptionKey = settings.encryptionKey || null;
      }

      const savedStats = localStorage.getItem('cloud_security_stats');
      if (savedStats) {
        this.stats = { ...this.stats, ...JSON.parse(savedStats) };
      }

      const savedFiles = localStorage.getItem('cloud_security_files');
      if (savedFiles) {
        const files = JSON.parse(savedFiles);
        this.cloudFiles = new Map(files);
      }
    } catch (error) {
      console.error('[Cloud Security] Failed to load settings:', error);
    }
  }

  saveSettings() {
    try {
      localStorage.setItem('cloud_security_settings', JSON.stringify({
        cloudProvider: this.cloudProvider,
        syncEnabled: this.syncEnabled,
        autoBackup: this.autoBackup,
        encryptionEnabled: this.encryptionEnabled,
        encryptionKey: this.encryptionKey
      }));

      localStorage.setItem('cloud_security_stats', JSON.stringify(this.stats));
      localStorage.setItem('cloud_security_files', JSON.stringify(Array.from(this.cloudFiles.entries())));
    } catch (error) {
      console.error('[Cloud Security] Failed to save settings:', error);
    }
  }

  // ==================== EVENT LISTENERS ====================

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  notifyListeners(event) {
    this.listeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error('[Cloud Security] Listener error:', error);
      }
    });
  }
}

// Export singleton instance
const cloudSecurityService = new CloudSecurityService();
export default cloudSecurityService;
