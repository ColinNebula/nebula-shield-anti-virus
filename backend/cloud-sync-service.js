/**
 * Nebula Shield - Cloud Sync Service
 * Synchronize settings, quarantine, and reports across devices
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');

class CloudSyncService extends EventEmitter {
  constructor() {
    super();
    
    this.syncEnabled = true;
    this.syncInterval = 5 * 60 * 1000; // 5 minutes
    this.devices = new Map();
    this.syncQueue = [];
    this.conflictResolution = 'latest'; // 'latest', 'server', 'client'
    
    // Sync state
    this.lastSync = {
      settings: null,
      quarantine: null,
      reports: null,
      devices: null,
    };
    
    // Change tracking
    this.changes = {
      settings: new Map(),
      quarantine: new Map(),
      reports: new Map(),
    };
    
    this.startSyncTimer();
  }

  // Start automatic sync timer
  startSyncTimer() {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
    }
    
    this.syncTimer = setInterval(() => {
      if (this.syncEnabled) {
        this.performSync();
      }
    }, this.syncInterval);
  }

  // Register a device
  async registerDevice(deviceInfo) {
    const deviceId = this.generateDeviceId(deviceInfo);
    
    const device = {
      id: deviceId,
      name: deviceInfo.name || deviceInfo.hostname,
      platform: deviceInfo.platform,
      version: deviceInfo.version || '1.0.0',
      lastSeen: Date.now(),
      lastSync: null,
      syncEnabled: true,
      settings: {},
      quarantineCount: 0,
      ...deviceInfo,
    };
    
    this.devices.set(deviceId, device);
    this.emit('device-registered', device);
    
    return device;
  }

  // Generate unique device ID
  generateDeviceId(deviceInfo) {
    const data = `${deviceInfo.hostname}-${deviceInfo.platform}-${deviceInfo.macAddress || Date.now()}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  // Get all registered devices
  getDevices(userId = 'default') {
    return Array.from(this.devices.values());
  }

  // Get device by ID
  getDevice(deviceId) {
    return this.devices.get(deviceId);
  }

  // Update device status
  updateDeviceStatus(deviceId, status) {
    const device = this.devices.get(deviceId);
    if (device) {
      Object.assign(device, status);
      device.lastSeen = Date.now();
      this.devices.set(deviceId, device);
      this.emit('device-updated', device);
    }
  }

  // Sync settings across devices
  async syncSettings(deviceId, settings) {
    try {
      const device = this.devices.get(deviceId);
      if (!device) {
        throw new Error('Device not found');
      }

      // Track changes
      const timestamp = Date.now();
      this.changes.settings.set(deviceId, {
        data: settings,
        timestamp,
        deviceId,
      });

      // Merge with existing settings
      const mergedSettings = this.mergeSettings(device.settings, settings);
      device.settings = mergedSettings;
      device.lastSync = timestamp;
      
      this.devices.set(deviceId, device);
      this.lastSync.settings = timestamp;

      // Propagate to other devices
      await this.propagateSettings(deviceId, mergedSettings);

      this.emit('settings-synced', {
        deviceId,
        settings: mergedSettings,
        timestamp,
      });

      return {
        success: true,
        settings: mergedSettings,
        timestamp,
      };
    } catch (error) {
      console.error('Settings sync failed:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  // Merge settings with conflict resolution
  mergeSettings(existing, incoming) {
    const merged = { ...existing };

    Object.keys(incoming).forEach(key => {
      if (this.conflictResolution === 'latest') {
        // Use incoming (latest) value
        merged[key] = incoming[key];
      } else if (this.conflictResolution === 'server') {
        // Keep existing (server) value
        if (!(key in merged)) {
          merged[key] = incoming[key];
        }
      } else {
        // Client preference
        merged[key] = incoming[key];
      }
    });

    return merged;
  }

  // Propagate settings to other devices
  async propagateSettings(sourceDeviceId, settings) {
    const otherDevices = Array.from(this.devices.values())
      .filter(d => d.id !== sourceDeviceId && d.syncEnabled);

    for (const device of otherDevices) {
      device.settings = this.mergeSettings(device.settings, settings);
      this.devices.set(device.id, device);
    }
  }

  // Sync quarantine data
  async syncQuarantine(deviceId, quarantineData) {
    try {
      const device = this.devices.get(deviceId);
      if (!device) {
        throw new Error('Device not found');
      }

      const timestamp = Date.now();
      
      // Track quarantine changes
      this.changes.quarantine.set(deviceId, {
        data: quarantineData,
        timestamp,
        deviceId,
      });

      // Update device quarantine count
      device.quarantineCount = quarantineData.length;
      device.lastSync = timestamp;
      this.devices.set(deviceId, device);

      this.lastSync.quarantine = timestamp;

      this.emit('quarantine-synced', {
        deviceId,
        count: quarantineData.length,
        timestamp,
      });

      return {
        success: true,
        count: quarantineData.length,
        timestamp,
      };
    } catch (error) {
      console.error('Quarantine sync failed:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  // Sync reports
  async syncReports(deviceId, reports) {
    try {
      const device = this.devices.get(deviceId);
      if (!device) {
        throw new Error('Device not found');
      }

      const timestamp = Date.now();
      
      this.changes.reports.set(deviceId, {
        data: reports,
        timestamp,
        deviceId,
      });

      device.lastSync = timestamp;
      this.devices.set(deviceId, device);

      this.lastSync.reports = timestamp;

      this.emit('reports-synced', {
        deviceId,
        count: reports.length,
        timestamp,
      });

      return {
        success: true,
        count: reports.length,
        timestamp,
      };
    } catch (error) {
      console.error('Reports sync failed:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  // Perform full sync
  async performSync() {
    const startTime = Date.now();
    const results = {
      devices: 0,
      settings: 0,
      quarantine: 0,
      reports: 0,
      errors: [],
    };

    try {
      // Sync all devices
      for (const [deviceId, device] of this.devices) {
        if (!device.syncEnabled) continue;

        try {
          // Check if device needs sync
          const needsSync = !device.lastSync || 
                          (Date.now() - device.lastSync) > this.syncInterval;

          if (needsSync) {
            // Update device status
            device.lastSeen = Date.now();
            this.devices.set(deviceId, device);
            results.devices++;
          }
        } catch (error) {
          results.errors.push({
            deviceId,
            error: error.message,
          });
        }
      }

      // Process sync queue
      while (this.syncQueue.length > 0) {
        const task = this.syncQueue.shift();
        try {
          await this.processSyncTask(task);
        } catch (error) {
          results.errors.push({
            task: task.type,
            error: error.message,
          });
        }
      }

      const duration = Date.now() - startTime;

      this.emit('sync-completed', {
        duration,
        results,
        timestamp: Date.now(),
      });

      return {
        success: true,
        duration,
        results,
      };
    } catch (error) {
      console.error('Sync failed:', error);
      return {
        success: false,
        error: error.message,
      };
    }
  }

  // Process sync task
  async processSyncTask(task) {
    switch (task.type) {
      case 'settings':
        await this.syncSettings(task.deviceId, task.data);
        break;
      case 'quarantine':
        await this.syncQuarantine(task.deviceId, task.data);
        break;
      case 'reports':
        await this.syncReports(task.deviceId, task.data);
        break;
      default:
        throw new Error(`Unknown sync task type: ${task.type}`);
    }
  }

  // Queue sync task
  queueSync(type, deviceId, data) {
    this.syncQueue.push({
      type,
      deviceId,
      data,
      timestamp: Date.now(),
    });
  }

  // Get sync status
  getSyncStatus(deviceId = null) {
    if (deviceId) {
      const device = this.devices.get(deviceId);
      if (!device) {
        return { error: 'Device not found' };
      }

      return {
        deviceId,
        lastSync: device.lastSync,
        lastSeen: device.lastSeen,
        syncEnabled: device.syncEnabled,
        pendingTasks: this.syncQueue.filter(t => t.deviceId === deviceId).length,
      };
    }

    return {
      enabled: this.syncEnabled,
      lastSync: this.lastSync,
      devices: this.devices.size,
      pendingTasks: this.syncQueue.length,
      changes: {
        settings: this.changes.settings.size,
        quarantine: this.changes.quarantine.size,
        reports: this.changes.reports.size,
      },
    };
  }

  // Get pending changes for device
  getPendingChanges(deviceId) {
    const device = this.devices.get(deviceId);
    if (!device) {
      return { error: 'Device not found' };
    }

    const pending = {
      settings: null,
      quarantine: null,
      reports: null,
    };

    // Get latest changes for each category
    const settingsChange = this.changes.settings.get(deviceId);
    if (settingsChange && (!device.lastSync || settingsChange.timestamp > device.lastSync)) {
      pending.settings = settingsChange.data;
    }

    const quarantineChange = this.changes.quarantine.get(deviceId);
    if (quarantineChange && (!device.lastSync || quarantineChange.timestamp > device.lastSync)) {
      pending.quarantine = quarantineChange.data;
    }

    const reportsChange = this.changes.reports.get(deviceId);
    if (reportsChange && (!device.lastSync || reportsChange.timestamp > device.lastSync)) {
      pending.reports = reportsChange.data;
    }

    return pending;
  }

  // Resolve sync conflict
  resolveConflict(deviceId, type, resolution) {
    const device = this.devices.get(deviceId);
    if (!device) {
      return { error: 'Device not found' };
    }

    this.conflictResolution = resolution;
    
    return {
      success: true,
      resolution,
      deviceId,
      type,
    };
  }

  // Enable/disable sync
  setSyncEnabled(enabled, deviceId = null) {
    if (deviceId) {
      const device = this.devices.get(deviceId);
      if (device) {
        device.syncEnabled = enabled;
        this.devices.set(deviceId, device);
      }
    } else {
      this.syncEnabled = enabled;
    }
  }

  // Get sync statistics
  getStatistics() {
    const now = Date.now();
    const activeDevices = Array.from(this.devices.values())
      .filter(d => now - d.lastSeen < 10 * 60 * 1000); // Active in last 10 minutes

    return {
      totalDevices: this.devices.size,
      activeDevices: activeDevices.length,
      syncEnabled: this.syncEnabled,
      lastSync: this.lastSync,
      pendingTasks: this.syncQueue.length,
      totalChanges: {
        settings: this.changes.settings.size,
        quarantine: this.changes.quarantine.size,
        reports: this.changes.reports.size,
      },
      platforms: this.getPlatformDistribution(),
    };
  }

  // Get platform distribution
  getPlatformDistribution() {
    const distribution = {};
    
    for (const device of this.devices.values()) {
      distribution[device.platform] = (distribution[device.platform] || 0) + 1;
    }
    
    return distribution;
  }

  // Export sync data
  exportSyncData() {
    return {
      devices: Array.from(this.devices.values()),
      lastSync: this.lastSync,
      changes: {
        settings: Array.from(this.changes.settings.values()),
        quarantine: Array.from(this.changes.quarantine.values()),
        reports: Array.from(this.changes.reports.values()),
      },
      statistics: this.getStatistics(),
      exportedAt: Date.now(),
    };
  }

  // Import sync data
  importSyncData(data) {
    try {
      // Import devices
      if (data.devices) {
        data.devices.forEach(device => {
          this.devices.set(device.id, device);
        });
      }

      // Import changes
      if (data.changes) {
        if (data.changes.settings) {
          data.changes.settings.forEach(change => {
            this.changes.settings.set(change.deviceId, change);
          });
        }
        if (data.changes.quarantine) {
          data.changes.quarantine.forEach(change => {
            this.changes.quarantine.set(change.deviceId, change);
          });
        }
        if (data.changes.reports) {
          data.changes.reports.forEach(change => {
            this.changes.reports.set(change.deviceId, change);
          });
        }
      }

      return {
        success: true,
        devicesImported: data.devices?.length || 0,
        changesImported: (data.changes?.settings?.length || 0) + 
                        (data.changes?.quarantine?.length || 0) + 
                        (data.changes?.reports?.length || 0),
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
}

module.exports = new CloudSyncService();
