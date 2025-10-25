/**
 * Scan Cache Service
 * 
 * Provides offline-first caching for scan results, quarantine files, and scan history
 * using IndexedDB for persistent storage.
 * 
 * Benefits:
 * - Instant access to scan history
 * - Works offline
 * - Reduces backend load
 * - Persistent across sessions
 * - Automatic cleanup of old data
 */

import { openDB } from 'idb';

const DB_NAME = 'nebula-shield-cache';
const DB_VERSION = 2;

// Store names
const STORES = {
  SCAN_RESULTS: 'scanResults',
  QUARANTINE: 'quarantine',
  SCAN_HISTORY: 'scanHistory',
  SETTINGS: 'settings',
};

class ScanCache {
  constructor() {
    this.db = null;
    this.initPromise = null;
  }

  /**
   * Initialize IndexedDB database
   */
  async init() {
    // Return existing promise if already initializing
    if (this.initPromise) {
      return this.initPromise;
    }

    // Return existing connection if already initialized
    if (this.db) {
      return this.db;
    }

    this.initPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion, newVersion, transaction) {
        console.log(`Upgrading IndexedDB from v${oldVersion} to v${newVersion}`);

        // Create scan results store
        if (!db.objectStoreNames.contains(STORES.SCAN_RESULTS)) {
          const scanStore = db.createObjectStore(STORES.SCAN_RESULTS, { 
            keyPath: 'id', 
            autoIncrement: true 
          });
          scanStore.createIndex('path', 'path', { unique: false });
          scanStore.createIndex('timestamp', 'timestamp', { unique: false });
          scanStore.createIndex('type', 'type', { unique: false });
          console.log('✓ Created scan results store');
        }

        // Create quarantine store
        if (!db.objectStoreNames.contains(STORES.QUARANTINE)) {
          const quarantineStore = db.createObjectStore(STORES.QUARANTINE, { 
            keyPath: 'id'
          });
          quarantineStore.createIndex('threatType', 'threatType', { unique: false });
          quarantineStore.createIndex('riskLevel', 'riskLevel', { unique: false });
          quarantineStore.createIndex('quarantinedDate', 'quarantinedDate', { unique: false });
          console.log('✓ Created quarantine store');
        }

        // Create scan history store
        if (!db.objectStoreNames.contains(STORES.SCAN_HISTORY)) {
          const historyStore = db.createObjectStore(STORES.SCAN_HISTORY, { 
            keyPath: 'id', 
            autoIncrement: true 
          });
          historyStore.createIndex('timestamp', 'timestamp', { unique: false });
          console.log('✓ Created scan history store');
        }

        // Create settings store
        if (!db.objectStoreNames.contains(STORES.SETTINGS)) {
          db.createObjectStore(STORES.SETTINGS, { 
            keyPath: 'key'
          });
          console.log('✓ Created settings store');
        }
      }
    });

    this.db = await this.initPromise;
    console.log('✓ IndexedDB initialized successfully');
    
    return this.db;
  }

  /**
   * Ensure database is initialized
   */
  async ensureInit() {
    if (!this.db) {
      await this.init();
    }
    return this.db;
  }

  // ==================== SCAN RESULTS ====================

  /**
   * Cache a scan result
   */
  async cacheScanResult(scanData) {
    const db = await this.ensureInit();
    
    const data = {
      ...scanData,
      timestamp: Date.now(),
      cachedAt: new Date().toISOString()
    };

    try {
      const id = await db.add(STORES.SCAN_RESULTS, data);
      console.log(`✓ Cached scan result with ID: ${id}`);
      return id;
    } catch (error) {
      console.error('Failed to cache scan result:', error);
      throw error;
    }
  }

  /**
   * Get recent scan results
   */
  async getRecentScans(limit = 50) {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(STORES.SCAN_RESULTS, 'readonly');
      const store = tx.objectStore(STORES.SCAN_RESULTS);
      const index = store.index('timestamp');
      
      let results = await index.getAll();
      
      // Sort by timestamp descending (newest first)
      results.sort((a, b) => b.timestamp - a.timestamp);
      
      return results.slice(0, limit);
    } catch (error) {
      console.error('Failed to get recent scans:', error);
      return [];
    }
  }

  /**
   * Get scan result by path
   */
  async getScanByPath(path) {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(STORES.SCAN_RESULTS, 'readonly');
      const store = tx.objectStore(STORES.SCAN_RESULTS);
      const index = store.index('path');
      
      return await index.get(path);
    } catch (error) {
      console.error('Failed to get scan by path:', error);
      return null;
    }
  }

  /**
   * Get all scan results within date range
   */
  async getScansByDateRange(startDate, endDate) {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(STORES.SCAN_RESULTS, 'readonly');
      const store = tx.objectStore(STORES.SCAN_RESULTS);
      const index = store.index('timestamp');
      
      const range = IDBKeyRange.bound(
        startDate.getTime(),
        endDate.getTime()
      );
      
      return await index.getAll(range);
    } catch (error) {
      console.error('Failed to get scans by date range:', error);
      return [];
    }
  }

  /**
   * Clear old cached scans
   */
  async clearOldCache(daysOld = 30) {
    const db = await this.ensureInit();
    
    const cutoffTime = Date.now() - (daysOld * 24 * 60 * 60 * 1000);
    
    try {
      const tx = db.transaction(STORES.SCAN_RESULTS, 'readwrite');
      const store = tx.objectStore(STORES.SCAN_RESULTS);
      const index = store.index('timestamp');
      
      let cursor = await index.openCursor();
      let deletedCount = 0;
      
      while (cursor) {
        if (cursor.value.timestamp < cutoffTime) {
          await cursor.delete();
          deletedCount++;
        }
        cursor = await cursor.continue();
      }
      
      await tx.done;
      console.log(`✓ Cleared ${deletedCount} old scan results`);
      return deletedCount;
    } catch (error) {
      console.error('Failed to clear old cache:', error);
      throw error;
    }
  }

  // ==================== QUARANTINE ====================

  /**
   * Cache a quarantine file
   */
  async cacheQuarantineFile(fileData) {
    const db = await this.ensureInit();
    
    try {
      await db.put(STORES.QUARANTINE, fileData);
      console.log(`✓ Cached quarantine file: ${fileData.fileName}`);
      return fileData.id;
    } catch (error) {
      console.error('Failed to cache quarantine file:', error);
      throw error;
    }
  }

  /**
   * Get all quarantine files
   */
  async getQuarantineFiles() {
    const db = await this.ensureInit();
    
    try {
      const files = await db.getAll(STORES.QUARANTINE);
      return files;
    } catch (error) {
      console.error('Failed to get quarantine files:', error);
      return [];
    }
  }

  /**
   * Get quarantine files by threat type
   */
  async getQuarantineFilesByType(threatType) {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(STORES.QUARANTINE, 'readonly');
      const store = tx.objectStore(STORES.QUARANTINE);
      const index = store.index('threatType');
      
      return await index.getAll(threatType);
    } catch (error) {
      console.error('Failed to get quarantine files by type:', error);
      return [];
    }
  }

  /**
   * Get quarantine files by risk level
   */
  async getQuarantineFilesByRisk(riskLevel) {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(STORES.QUARANTINE, 'readonly');
      const store = tx.objectStore(STORES.QUARANTINE);
      const index = store.index('riskLevel');
      
      return await index.getAll(riskLevel);
    } catch (error) {
      console.error('Failed to get quarantine files by risk:', error);
      return [];
    }
  }

  /**
   * Delete quarantine file from cache
   */
  async deleteQuarantineFile(id) {
    const db = await this.ensureInit();
    
    try {
      await db.delete(STORES.QUARANTINE, id);
      console.log(`✓ Deleted quarantine file from cache: ${id}`);
    } catch (error) {
      console.error('Failed to delete quarantine file:', error);
      throw error;
    }
  }

  /**
   * Clear all quarantine cache
   */
  async clearQuarantineCache() {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(STORES.QUARANTINE, 'readwrite');
      await tx.objectStore(STORES.QUARANTINE).clear();
      await tx.done;
      console.log('✓ Cleared all quarantine cache');
    } catch (error) {
      console.error('Failed to clear quarantine cache:', error);
      throw error;
    }
  }

  // ==================== SETTINGS ====================

  /**
   * Save a setting
   */
  async saveSetting(key, value) {
    const db = await this.ensureInit();
    
    try {
      await db.put(STORES.SETTINGS, { key, value, updatedAt: Date.now() });
      console.log(`✓ Saved setting: ${key}`);
    } catch (error) {
      console.error('Failed to save setting:', error);
      throw error;
    }
  }

  /**
   * Get a setting
   */
  async getSetting(key, defaultValue = null) {
    const db = await this.ensureInit();
    
    try {
      const setting = await db.get(STORES.SETTINGS, key);
      return setting ? setting.value : defaultValue;
    } catch (error) {
      console.error('Failed to get setting:', error);
      return defaultValue;
    }
  }

  /**
   * Delete a setting
   */
  async deleteSetting(key) {
    const db = await this.ensureInit();
    
    try {
      await db.delete(STORES.SETTINGS, key);
      console.log(`✓ Deleted setting: ${key}`);
    } catch (error) {
      console.error('Failed to delete setting:', error);
      throw error;
    }
  }

  // ==================== UTILITIES ====================

  /**
   * Get database statistics
   */
  async getStats() {
    const db = await this.ensureInit();
    
    try {
      const stats = {
        scanResults: await db.count(STORES.SCAN_RESULTS),
        quarantineFiles: await db.count(STORES.QUARANTINE),
        scanHistory: await db.count(STORES.SCAN_HISTORY),
        settings: await db.count(STORES.SETTINGS),
      };
      
      return stats;
    } catch (error) {
      console.error('Failed to get stats:', error);
      return {
        scanResults: 0,
        quarantineFiles: 0,
        scanHistory: 0,
        settings: 0,
      };
    }
  }

  /**
   * Clear all data (reset)
   */
  async clearAllData() {
    const db = await this.ensureInit();
    
    try {
      const tx = db.transaction(
        [STORES.SCAN_RESULTS, STORES.QUARANTINE, STORES.SCAN_HISTORY, STORES.SETTINGS],
        'readwrite'
      );
      
      await Promise.all([
        tx.objectStore(STORES.SCAN_RESULTS).clear(),
        tx.objectStore(STORES.QUARANTINE).clear(),
        tx.objectStore(STORES.SCAN_HISTORY).clear(),
        tx.objectStore(STORES.SETTINGS).clear(),
      ]);
      
      await tx.done;
      console.log('✓ Cleared all cached data');
    } catch (error) {
      console.error('Failed to clear all data:', error);
      throw error;
    }
  }

  /**
   * Export all data as JSON
   */
  async exportData() {
    const db = await this.ensureInit();
    
    try {
      const data = {
        scanResults: await db.getAll(STORES.SCAN_RESULTS),
        quarantine: await db.getAll(STORES.QUARANTINE),
        scanHistory: await db.getAll(STORES.SCAN_HISTORY),
        settings: await db.getAll(STORES.SETTINGS),
        exportedAt: new Date().toISOString(),
      };
      
      return JSON.stringify(data, null, 2);
    } catch (error) {
      console.error('Failed to export data:', error);
      throw error;
    }
  }
}

// Export singleton instance
const scanCache = new ScanCache();
export default scanCache;
