/**
 * USB Device Monitor Service
 * Monitors USB device connections and triggers automatic scans
 */

class USBMonitorService {
  constructor() {
    this.isSupported = 'usb' in navigator || this.isElectron();
    this.devices = new Map();
    this.listeners = new Set();
    this.autoScanEnabled = this.getAutoScanPreference();
    this.init();
  }

  isElectron() {
    return window.navigator.userAgent.toLowerCase().includes('electron');
  }

  init() {
    if (this.isElectron()) {
      this.initElectronMonitoring();
    } else if ('usb' in navigator) {
      this.initWebUSBMonitoring();
    } else {
      // Fallback: Use storage events (limited functionality)
      this.initStorageMonitoring();
    }
  }

  // Electron-specific USB monitoring
  initElectronMonitoring() {
    if (window.electron && window.electron.onUSBDeviceAdded) {
      window.electron.onUSBDeviceAdded((device) => {
        this.handleDeviceConnected(device);
      });

      window.electron.onUSBDeviceRemoved((device) => {
        this.handleDeviceDisconnected(device);
      });
    }
  }

  // WebUSB API monitoring (Chrome/Edge)
  initWebUSBMonitoring() {
    if ('usb' in navigator) {
      navigator.usb.addEventListener('connect', (event) => {
        const device = event.device;
        this.handleDeviceConnected({
          id: device.serialNumber || `usb-${Date.now()}`,
          name: device.productName || 'USB Device',
          vendorId: device.vendorId,
          productId: device.productId,
          type: 'usb'
        });
      });

      navigator.usb.addEventListener('disconnect', (event) => {
        const device = event.device;
        this.handleDeviceDisconnected({
          id: device.serialNumber || `usb-${Date.now()}`,
          name: device.productName || 'USB Device'
        });
      });
    }
  }

  // Fallback: Monitor storage changes (Windows/FileSystem API)
  initStorageMonitoring() {
    // Poll for new drives every 5 seconds
    this.storageInterval = setInterval(() => {
      this.checkStorageDevices();
    }, 5000);
  }

  async checkStorageDevices() {
    try {
      // Request directory access (user must grant permission)
      if ('showDirectoryPicker' in window) {
        // This requires user interaction
        // Can be triggered by a button click
        return;
      }

      // Alternative: Check for mounted drives via navigator.storage
      if (navigator.storage && navigator.storage.estimate) {
        const estimate = await navigator.storage.estimate();
        // Basic detection only
        console.log('Storage estimate:', estimate);
      }
    } catch (error) {
      console.warn('Storage monitoring error:', error);
    }
  }

  handleDeviceConnected(device) {
    console.log('USB device connected:', device);
    
    const deviceInfo = {
      id: device.id || `device-${Date.now()}`,
      name: device.name || 'Unknown Device',
      path: device.path || null,
      type: device.type || 'removable',
      connectedAt: new Date().toISOString(),
      scanned: false
    };

    this.devices.set(deviceInfo.id, deviceInfo);
    
    // Notify listeners
    this.notifyListeners('connected', deviceInfo);

    // Auto-scan if enabled
    if (this.autoScanEnabled) {
      this.triggerAutoScan(deviceInfo);
    }
  }

  handleDeviceDisconnected(device) {
    console.log('USB device disconnected:', device);
    
    const deviceInfo = this.devices.get(device.id);
    if (deviceInfo) {
      this.devices.delete(device.id);
      this.notifyListeners('disconnected', deviceInfo);
    }
  }

  async triggerAutoScan(device) {
    try {
      console.log('Auto-scanning device:', device.name);
      
      // Mark as scanning
      const deviceInfo = this.devices.get(device.id);
      if (deviceInfo) {
        deviceInfo.scanning = true;
        this.notifyListeners('scan-started', deviceInfo);
      }

      // Simulate scan (in production, this would call the real scanner API)
      await this.scanDevice(device);

      // Mark as scanned
      if (deviceInfo) {
        deviceInfo.scanning = false;
        deviceInfo.scanned = true;
        deviceInfo.scanResult = {
          filesScanned: Math.floor(Math.random() * 500) + 50,
          threatsFound: Math.random() > 0.9 ? Math.floor(Math.random() * 3) + 1 : 0,
          scanTime: Math.floor(Math.random() * 30) + 5
        };
        this.notifyListeners('scan-complete', deviceInfo);
      }

    } catch (error) {
      console.error('Auto-scan error:', error);
      const deviceInfo = this.devices.get(device.id);
      if (deviceInfo) {
        deviceInfo.scanning = false;
        deviceInfo.scanError = error.message;
        this.notifyListeners('scan-error', { device: deviceInfo, error });
      }
    }
  }

  async scanDevice(device) {
    // In production, this would:
    // 1. Get device mount point/path
    // 2. Call backend scanner API
    // 3. Return scan results
    
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          filesScanned: 100,
          threatsFound: 0,
          scanTime: 10
        });
      }, 2000);
    });
  }

  // Add event listener
  addListener(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback); // Return cleanup function
  }

  // Remove event listener
  removeListener(callback) {
    this.listeners.delete(callback);
  }

  // Notify all listeners
  notifyListeners(event, data) {
    this.listeners.forEach(callback => {
      try {
        callback(event, data);
      } catch (error) {
        console.error('Listener error:', error);
      }
    });
  }

  // Get connected devices
  getDevices() {
    return Array.from(this.devices.values());
  }

  // Enable/disable auto-scan
  setAutoScan(enabled) {
    this.autoScanEnabled = enabled;
    localStorage.setItem('usb-auto-scan', enabled);
  }

  getAutoScanPreference() {
    const stored = localStorage.getItem('usb-auto-scan');
    return stored !== 'false'; // Default to true
  }

  isAutoScanEnabled() {
    return this.autoScanEnabled;
  }

  // Request USB permissions (WebUSB)
  async requestPermissions() {
    if (!('usb' in navigator)) {
      return false;
    }

    try {
      await navigator.usb.requestDevice({ filters: [] });
      return true;
    } catch (error) {
      console.warn('USB permission denied:', error);
      return false;
    }
  }

  // Check if USB monitoring is supported
  isMonitoringSupported() {
    return this.isSupported;
  }

  // Cleanup
  destroy() {
    if (this.storageInterval) {
      clearInterval(this.storageInterval);
    }
    this.listeners.clear();
    this.devices.clear();
  }
}

// Export singleton instance
const usbMonitorService = new USBMonitorService();
export default usbMonitorService;
