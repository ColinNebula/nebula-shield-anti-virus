// Desktop Notification Service
class NotificationService {
  constructor() {
    this.isSupported = 'Notification' in window;
    this.permission = this.isSupported ? Notification.permission : 'default';
  }

  // Request notification permission
  async requestPermission() {
    if (!this.isSupported) {
      console.warn('Desktop notifications are not supported in this browser');
      return false;
    }

    // Check current permission status
    if (Notification.permission === 'granted') {
      this.permission = 'granted';
      return true;
    }

    if (Notification.permission === 'denied') {
      console.warn('Notification permission was previously denied');
      this.permission = 'denied';
      return false;
    }

    try {
      const permission = await Notification.requestPermission();
      this.permission = permission;
      return permission === 'granted';
    } catch (error) {
      console.error('Error requesting notification permission:', error);
      return false;
    }
  }

  // Check if notifications are enabled
  isEnabled() {
    return this.isSupported && Notification.permission === 'granted';
  }

  // Check if permission was denied
  isDenied() {
    return this.isSupported && Notification.permission === 'denied';
  }

  // Get current permission status
  getPermissionStatus() {
    if (!this.isSupported) return 'unsupported';
    return Notification.permission;
  }

  // Show a notification
  show(title, options = {}) {
    if (!this.isEnabled()) {
      console.warn('Notifications are not enabled');
      return null;
    }

    const defaultOptions = {
      icon: '/logo192.png',
      badge: '/favicon.png',
      vibrate: [200, 100, 200],
      requireInteraction: false,
      ...options
    };

    try {
      const notification = new Notification(title, defaultOptions);
      
      // Auto-close after 5 seconds unless requireInteraction is true
      if (!defaultOptions.requireInteraction) {
        setTimeout(() => notification.close(), 5000);
      }

      return notification;
    } catch (error) {
      console.error('Error showing notification:', error);
      return null;
    }
  }

  // Predefined notification types
  showThreatDetected(threatName, filePath) {
    return this.show('🚨 Threat Detected!', {
      body: `${threatName} found in ${filePath}`,
      tag: 'threat-detected',
      requireInteraction: true,
      icon: '/logo192.png',
      actions: [
        { action: 'quarantine', title: 'Quarantine' },
        { action: 'ignore', title: 'Ignore' }
      ]
    });
  }

  showScanComplete(filesScanned, threatsFound) {
    const body = threatsFound > 0 
      ? `Scanned ${filesScanned} files. Found ${threatsFound} threat(s)!`
      : `Scanned ${filesScanned} files. No threats detected.`;

    return this.show('✅ Scan Complete', {
      body,
      tag: 'scan-complete',
      icon: threatsFound > 0 ? '/logo192.png' : '/logo192.png'
    });
  }

  showProtectionEnabled() {
    return this.show('🛡️ Protection Enabled', {
      body: 'Real-time protection is now active',
      tag: 'protection-status'
    });
  }

  showProtectionDisabled() {
    return this.show('⚠️ Protection Disabled', {
      body: 'Real-time protection has been turned off',
      tag: 'protection-status',
      requireInteraction: true
    });
  }

  showQuarantineAction(fileName, action) {
    const actionText = action === 'restore' ? 'restored from' : 'moved to';
    return this.show(`📦 File ${action === 'restore' ? 'Restored' : 'Quarantined'}`, {
      body: `${fileName} ${actionText} quarantine`,
      tag: 'quarantine-action'
    });
  }

  showUpdateAvailable(version) {
    return this.show('🔄 Update Available', {
      body: `Version ${version} is ready to install`,
      tag: 'update-available',
      requireInteraction: true
    });
  }

  showScheduledScanStarted() {
    return this.show('⏰ Scheduled Scan Started', {
      body: 'Automatic scan is now running',
      tag: 'scheduled-scan'
    });
  }

  showCriticalThreat(threatName, severity) {
    return this.show('🔴 CRITICAL THREAT!', {
      body: `High-risk ${threatName} detected! Immediate action required.`,
      tag: 'critical-threat',
      requireInteraction: true,
      vibrate: [200, 100, 200, 100, 200]
    });
  }
}

// Export singleton instance
const notificationService = new NotificationService();
export default notificationService;
