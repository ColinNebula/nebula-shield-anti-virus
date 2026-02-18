/**
 * Nebula Shield - Automatic Signature Update Service
 * 
 * Features:
 * - Silent automatic signature updates
 * - Background downloading from threat intelligence feeds
 * - Incremental updates (only download changes)
 * - Fallback mechanisms for reliability
 * - Update verification and validation
 * - Configurable update intervals
 * - Offline mode support with cached signatures
 */

import axios from 'axios';
import { EventEmitter } from 'events';

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080' : '';

class SignatureUpdaterService extends EventEmitter {
  constructor() {
    super();
    
    // Update configuration
    this.config = {
      updateInterval: 3600000, // 1 hour (in milliseconds)
      updateUrls: [
        `${API_BASE_URL}/api/signatures/update`
      ],
      enableAutoUpdate: true,
      enableSilentUpdate: true,
      verifySignatures: true,
      maxRetries: 3,
      retryDelay: 5000, // 5 seconds
      timeout: 30000 // 30 seconds
    };

    // State management
    this.state = {
      lastUpdateTime: null,
      lastUpdateVersion: null,
      currentVersion: '2.0.0',
      signatureCount: 500,
      isUpdating: false,
      updateHistory: [],
      failedAttempts: 0,
      nextScheduledUpdate: null
    };

    // In-memory signature cache
    this.signatureCache = {
      virus: [],
      malware: [],
      suspicious: []
    };

    // Update scheduler
    this.updateTimer = null;
    
    // Statistics
    this.stats = {
      totalUpdates: 0,
      successfulUpdates: 0,
      failedUpdates: 0,
      signaturesAdded: 0,
      signaturesModified: 0,
      signaturesRemoved: 0,
      lastError: null
    };

    // Load last update state from localStorage
    this.loadState();
    
    // Initialize auto-update
    this.initializeAutoUpdate();
  }

  /**
   * Initialize automatic signature updates
   */
  initializeAutoUpdate() {
    console.log('[SignatureUpdater] Initializing auto-update service...');
    
    if (this.config.enableAutoUpdate) {
      // Check for updates immediately on startup (silent, don't log errors)
      setTimeout(() => {
        this.checkForUpdates(true).catch(err => {
          // Silently ignore errors on initial check
          console.debug('[SignatureUpdater] Initial update check failed (backend may not be ready):', err.message);
        });
      }, 5000); // Wait 5 seconds after app start

      // Schedule periodic updates
      this.scheduleNextUpdate();
    }

    // Listen for network status changes
    if (typeof window !== 'undefined') {
      window.addEventListener('online', () => {
        console.log('[SignatureUpdater] Network restored, checking for updates...');
        this.checkForUpdates(true).catch(() => {
          // Ignore network errors silently
        });
      });
    }
  }

  /**
   * Schedule the next automatic update
   */
  scheduleNextUpdate() {
    // Clear existing timer
    if (this.updateTimer) {
      clearTimeout(this.updateTimer);
    }

    // Schedule next update
    const nextUpdate = Date.now() + this.config.updateInterval;
    this.state.nextScheduledUpdate = new Date(nextUpdate);
    
    this.updateTimer = setTimeout(() => {
      this.checkForUpdates(this.config.enableSilentUpdate);
      this.scheduleNextUpdate(); // Reschedule
    }, this.config.updateInterval);

    console.log(`[SignatureUpdater] Next update scheduled for: ${this.state.nextScheduledUpdate.toLocaleString()}`);
  }

  /**
   * Check for available signature updates
   * @param {boolean} silent - If true, update silently without notifications
   */
  async checkForUpdates(silent = false) {
    if (this.state.isUpdating) {
      console.log('[SignatureUpdater] Update already in progress');
      return { success: false, reason: 'update_in_progress' };
    }

    this.state.isUpdating = true;
    
    if (!silent) {
      this.emit('updateStart');
    }

    try {
      console.log('[SignatureUpdater] Checking for signature updates...');
      
      // Try each update URL in order
      for (let i = 0; i < this.config.updateUrls.length; i++) {
        const url = this.config.updateUrls[i];
        
        try {
          const result = await this.downloadAndApplyUpdates(url, silent);
          
          if (result.success) {
            this.stats.successfulUpdates++;
            this.stats.failedAttempts = 0;
            this.state.lastUpdateTime = new Date();
            
            this.saveState();
            
            if (!silent) {
              this.emit('updateComplete', result);
            }
            
            console.log(`[SignatureUpdater] Update successful from ${url}`);
            this.state.isUpdating = false;
            return result;
          }
        } catch (error) {
          console.warn(`[SignatureUpdater] Failed to update from ${url}:`, error.message);
          
          // Try next URL
          if (i < this.config.updateUrls.length - 1) {
            console.log(`[SignatureUpdater] Trying next update source...`);
            await this.sleep(this.config.retryDelay);
          }
        }
      }

      // All update sources failed
      this.stats.failedUpdates++;
      this.state.failedAttempts++;
      this.stats.lastError = 'All update sources unavailable';
      
      if (!silent) {
        this.emit('updateFailed', { reason: 'all_sources_failed' });
      }
      
      console.error('[SignatureUpdater] All update sources failed');
      this.state.isUpdating = false;
      
      return { success: false, reason: 'all_sources_failed' };
      
    } catch (error) {
      this.stats.failedUpdates++;
      this.stats.lastError = error.message;
      
      if (!silent) {
        this.emit('updateFailed', { error: error.message });
      }
      
      console.error('[SignatureUpdater] Update check failed:', error);
      this.state.isUpdating = false;
      
      return { success: false, error: error.message };
    }
  }

  /**
   * Download and apply signature updates from a specific URL
   * @param {string} url - Update source URL
   * @param {boolean} silent - Silent mode
   */
  async downloadAndApplyUpdates(url, silent = false) {
    try {
      console.log(`[SignatureUpdater] Downloading updates from: ${url}`);
      
      // Download signature update
      const response = await axios.post(url, {
        currentVersion: this.state.currentVersion,
        lastUpdate: this.state.lastUpdateTime?.toISOString() || 'never'
      }, {
        timeout: this.config.timeout,
        headers: {
          'X-Current-Version': this.state.currentVersion,
          'X-Last-Update': this.state.lastUpdateTime?.toISOString() || 'never'
        },
        validateStatus: function (status) {
          return status >= 200 && status < 600; // Accept any status for better error messages
        }
      });

      // Check response status
      if (response.status === 503) {
        throw new Error('Backend server unavailable (503). Please ensure the backend is running on port 8080.');
      }

      if (response.status >= 400) {
        throw new Error(`HTTP error! status: ${response.status} - ${response.statusText || 'Unknown error'}`);
      }

      if (!response.data) {
        throw new Error('Empty response from update server');
      }

      const updateData = response.data;
      
      // Validate update data structure
      if (!this.validateUpdateData(updateData)) {
        throw new Error('Invalid update data format');
      }

      // Check if update is needed
      if (updateData.version === this.state.lastUpdateVersion) {
        console.log('[SignatureUpdater] Already up to date');
        return { 
          success: true, 
          upToDate: true, 
          version: updateData.version 
        };
      }

      // Verify signature integrity if enabled
      if (this.config.verifySignatures && updateData.signature) {
        const isValid = await this.verifyUpdateSignature(updateData);
        if (!isValid) {
          throw new Error('Signature verification failed');
        }
      }

      // Apply the update
      const result = await this.applySignatureUpdate(updateData, silent);
      
      if (result.success) {
        this.state.lastUpdateVersion = updateData.version;
        this.stats.totalUpdates++;
        
        // Add to update history
        this.state.updateHistory.unshift({
          timestamp: new Date(),
          version: updateData.version,
          signaturesAdded: result.added,
          signaturesModified: result.modified,
          signaturesRemoved: result.removed,
          source: url
        });

        // Keep only last 50 updates in history
        if (this.state.updateHistory.length > 50) {
          this.state.updateHistory = this.state.updateHistory.slice(0, 50);
        }
      }

      return result;
      
    } catch (error) {
      console.error(`[SignatureUpdater] Download failed from ${url}:`, error);
      throw error;
    }
  }

  /**
   * Validate update data structure
   * @param {object} data - Update data to validate
   */
  validateUpdateData(data) {
    if (!data) return false;
    
    // Check required fields
    if (!data.version || !data.timestamp) {
      console.error('[SignatureUpdater] Missing required fields (version, timestamp)');
      return false;
    }

    // Check signatures structure
    if (!data.signatures) {
      console.error('[SignatureUpdater] Missing signatures field');
      return false;
    }

    // Validate at least one signature category exists
    const hasSignatures = (
      (data.signatures.virus && Array.isArray(data.signatures.virus)) ||
      (data.signatures.malware && Array.isArray(data.signatures.malware)) ||
      (data.signatures.suspicious && Array.isArray(data.signatures.suspicious))
    );

    if (!hasSignatures) {
      console.error('[SignatureUpdater] No valid signature categories found');
      return false;
    }

    return true;
  }

  /**
   * Verify update signature (cryptographic verification)
   * @param {object} updateData - Update data with signature
   */
  async verifyUpdateSignature(updateData) {
    // TODO: Implement cryptographic signature verification
    // For now, basic checksum validation
    
    if (!updateData.signature || !updateData.checksum) {
      console.warn('[SignatureUpdater] No signature/checksum provided, skipping verification');
      return true; // Allow update without verification for now
    }

    try {
      // Calculate checksum of signature data
      const dataString = JSON.stringify(updateData.signatures);
      const calculatedChecksum = this.calculateChecksum(dataString);
      
      const isValid = calculatedChecksum === updateData.checksum;
      
      if (!isValid) {
        console.error('[SignatureUpdater] Checksum mismatch!');
      }
      
      return isValid;
      
    } catch (error) {
      console.error('[SignatureUpdater] Signature verification error:', error);
      return false;
    }
  }

  /**
   * Calculate simple checksum (SHA-256 would be better in production)
   * @param {string} data - Data to checksum
   */
  calculateChecksum(data) {
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
  }

  /**
   * Apply signature update to the system
   * @param {object} updateData - Update data containing new signatures
   * @param {boolean} silent - Silent mode
   */
  async applySignatureUpdate(updateData, silent = false) {
    console.log('[SignatureUpdater] Applying signature updates...');
    
    let added = 0;
    let modified = 0;
    let removed = 0;

    try {
      // Update each category
      if (updateData.signatures.virus) {
        const result = this.mergeSignatures('virus', updateData.signatures.virus);
        added += result.added;
        modified += result.modified;
      }

      if (updateData.signatures.malware) {
        const result = this.mergeSignatures('malware', updateData.signatures.malware);
        added += result.added;
        modified += result.modified;
      }

      if (updateData.signatures.suspicious) {
        const result = this.mergeSignatures('suspicious', updateData.signatures.suspicious);
        added += result.added;
        modified += result.modified;
      }

      // Update global statistics
      this.stats.signaturesAdded += added;
      this.stats.signaturesModified += modified;
      this.stats.signaturesRemoved += removed;
      
      // Calculate new total count
      this.state.signatureCount = 
        this.signatureCache.virus.length +
        this.signatureCache.malware.length +
        this.signatureCache.suspicious.length;

      console.log(`[SignatureUpdater] Update applied: +${added} added, ${modified} modified, ${removed} removed`);
      console.log(`[SignatureUpdater] Total signatures: ${this.state.signatureCount}`);

      if (!silent) {
        this.emit('signaturesUpdated', {
          added,
          modified,
          removed,
          total: this.state.signatureCount,
          version: updateData.version
        });
      }

      return {
        success: true,
        added,
        modified,
        removed,
        total: this.state.signatureCount,
        version: updateData.version
      };
      
    } catch (error) {
      console.error('[SignatureUpdater] Failed to apply updates:', error);
      throw error;
    }
  }

  /**
   * Merge new signatures with existing cache
   * @param {string} category - Signature category (virus/malware/suspicious)
   * @param {array} newSignatures - New signatures to merge
   */
  mergeSignatures(category, newSignatures) {
    let added = 0;
    let modified = 0;

    if (!this.signatureCache[category]) {
      this.signatureCache[category] = [];
    }

    const existingIds = new Set(
      this.signatureCache[category].map(sig => sig.id)
    );

    newSignatures.forEach(newSig => {
      if (existingIds.has(newSig.id)) {
        // Update existing signature
        const index = this.signatureCache[category].findIndex(
          sig => sig.id === newSig.id
        );
        
        if (index !== -1) {
          // Check if actually modified
          const isModified = JSON.stringify(this.signatureCache[category][index]) !== 
                            JSON.stringify(newSig);
          
          if (isModified) {
            this.signatureCache[category][index] = newSig;
            modified++;
          }
        }
      } else {
        // Add new signature
        this.signatureCache[category].push(newSig);
        added++;
      }
    });

    return { added, modified };
  }

  /**
   * Get current signatures (for use by scanner)
   * @param {string} category - Optional category filter
   */
  getSignatures(category = null) {
    if (category) {
      return this.signatureCache[category] || [];
    }
    
    return {
      virus: this.signatureCache.virus || [],
      malware: this.signatureCache.malware || [],
      suspicious: this.signatureCache.suspicious || []
    };
  }

  /**
   * Force update check (manual trigger)
   */
  async forceUpdate() {
    console.log('[SignatureUpdater] Force update requested');
    return await this.checkForUpdates(false); // Not silent, show notifications
  }

  /**
   * Configure update settings
   * @param {object} newConfig - Configuration options
   */
  configure(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Reschedule if interval changed
    if (newConfig.updateInterval) {
      this.scheduleNextUpdate();
    }
    
    console.log('[SignatureUpdater] Configuration updated:', this.config);
  }

  /**
   * Get current update status and statistics
   */
  getStatus() {
    return {
      config: this.config,
      state: {
        ...this.state,
        nextScheduledUpdate: this.state.nextScheduledUpdate?.toISOString()
      },
      stats: this.stats,
      isOnline: typeof navigator !== 'undefined' ? navigator.onLine : true
    };
  }

  /**
   * Get update history
   */
  getUpdateHistory() {
    return this.state.updateHistory;
  }

  /**
   * Save state to localStorage
   */
  saveState() {
    if (typeof localStorage === 'undefined') return;
    
    try {
      const stateToSave = {
        lastUpdateTime: this.state.lastUpdateTime?.toISOString(),
        lastUpdateVersion: this.state.lastUpdateVersion,
        signatureCount: this.state.signatureCount,
        updateHistory: this.state.updateHistory.slice(0, 10) // Save only last 10
      };
      
      localStorage.setItem('nebula_signature_update_state', JSON.stringify(stateToSave));
    } catch (error) {
      console.error('[SignatureUpdater] Failed to save state:', error);
    }
  }

  /**
   * Load state from localStorage
   */
  loadState() {
    if (typeof localStorage === 'undefined') return;
    
    try {
      const savedState = localStorage.getItem('nebula_signature_update_state');
      
      if (savedState) {
        const parsed = JSON.parse(savedState);
        
        this.state.lastUpdateTime = parsed.lastUpdateTime ? 
          new Date(parsed.lastUpdateTime) : null;
        this.state.lastUpdateVersion = parsed.lastUpdateVersion;
        this.state.signatureCount = parsed.signatureCount || 500;
        this.state.updateHistory = parsed.updateHistory || [];
        
        console.log('[SignatureUpdater] State loaded from storage');
      }
    } catch (error) {
      console.error('[SignatureUpdater] Failed to load state:', error);
    }
  }

  /**
   * Clear all cached signatures and state
   */
  clearCache() {
    this.signatureCache = {
      virus: [],
      malware: [],
      suspicious: []
    };
    
    this.state.signatureCount = 0;
    this.saveState();
    
    console.log('[SignatureUpdater] Cache cleared');
  }

  /**
   * Stop automatic updates
   */
  stopAutoUpdate() {
    if (this.updateTimer) {
      clearTimeout(this.updateTimer);
      this.updateTimer = null;
    }
    
    this.config.enableAutoUpdate = false;
    console.log('[SignatureUpdater] Automatic updates stopped');
  }

  /**
   * Resume automatic updates
   */
  resumeAutoUpdate() {
    this.config.enableAutoUpdate = true;
    this.scheduleNextUpdate();
    console.log('[SignatureUpdater] Automatic updates resumed');
  }

  /**
   * Helper: Sleep function
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Singleton instance
const signatureUpdater = new SignatureUpdaterService();

// Export singleton and class
export default signatureUpdater;
export { SignatureUpdaterService };
