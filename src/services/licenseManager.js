/**
 * Nebula Shield Anti-Virus - SaaS License Management System
 * Handles license validation, subscription tiers, and feature access control
 */

import CryptoJS from 'crypto-js';

class LicenseManager {
  constructor() {
    this.LICENSE_SECRET = 'NEBULA_SHIELD_LICENSE_2025';
    this.licenses = this.loadLicenses();
    this.licenseTypes = {
      FREE: {
        tier: 'free',
        name: 'Free Edition',
        duration: 'Lifetime',
        maxDevices: 1,
        features: {
          realTimeProtection: true,
          manualScan: true,
          basicReports: true,
          threatHistory: 30, // days
          scheduledScans: false,
          customPaths: false,
          advancedReports: false,
          prioritySupport: false,
          multiDevice: false,
          cloudBackup: false,
          aiDetection: false,
          zeroDay: false,
          ransomwareProtection: true, // basic
          webProtection: true, // basic
          emailProtection: false,
          networkProtection: false,
          parentalControls: false
        }
      },
      PERSONAL: {
        tier: 'personal',
        name: 'Personal License',
        price: 29.99,
        duration: '1 Year',
        maxDevices: 3,
        features: {
          realTimeProtection: true,
          manualScan: true,
          basicReports: true,
          advancedReports: true,
          threatHistory: 365, // days
          scheduledScans: true,
          customPaths: true,
          prioritySupport: false,
          multiDevice: true,
          cloudBackup: true,
          aiDetection: true,
          zeroDay: false,
          ransomwareProtection: true,
          webProtection: true,
          emailProtection: true,
          networkProtection: true,
          parentalControls: false
        }
      },
      PREMIUM: {
        tier: 'premium',
        name: 'Premium License',
        price: 49.99,
        duration: '1 Year',
        maxDevices: 5,
        features: {
          realTimeProtection: true,
          manualScan: true,
          basicReports: true,
          advancedReports: true,
          threatHistory: -1, // unlimited
          scheduledScans: true,
          customPaths: true,
          prioritySupport: true,
          multiDevice: true,
          cloudBackup: true,
          aiDetection: true,
          zeroDay: true,
          ransomwareProtection: true,
          webProtection: true,
          emailProtection: true,
          networkProtection: true,
          parentalControls: true
        }
      },
      BUSINESS: {
        tier: 'business',
        name: 'Business License',
        price: 99.99,
        duration: '1 Year',
        maxDevices: 25,
        features: {
          realTimeProtection: true,
          manualScan: true,
          basicReports: true,
          advancedReports: true,
          threatHistory: -1, // unlimited
          scheduledScans: true,
          customPaths: true,
          prioritySupport: true,
          multiDevice: true,
          cloudBackup: true,
          aiDetection: true,
          zeroDay: true,
          ransomwareProtection: true,
          webProtection: true,
          emailProtection: true,
          networkProtection: true,
          parentalControls: true,
          centralManagement: true,
          apiAccess: true,
          whiteLabeling: false,
          slaSupport: true
        }
      },
      ENTERPRISE: {
        tier: 'enterprise',
        name: 'Enterprise License',
        price: 499.99,
        duration: '1 Year',
        maxDevices: -1, // unlimited
        features: {
          realTimeProtection: true,
          manualScan: true,
          basicReports: true,
          advancedReports: true,
          threatHistory: -1,
          scheduledScans: true,
          customPaths: true,
          prioritySupport: true,
          multiDevice: true,
          cloudBackup: true,
          aiDetection: true,
          zeroDay: true,
          ransomwareProtection: true,
          webProtection: true,
          emailProtection: true,
          networkProtection: true,
          parentalControls: true,
          centralManagement: true,
          apiAccess: true,
          whiteLabeling: true,
          slaSupport: true,
          dedicatedSupport: true,
          customIntegration: true,
          onPremiseDeployment: true
        }
      }
    };
  }

  // Generate a unique license key
  generateLicenseKey(tier, email, expiryDate) {
    const data = {
      tier,
      email,
      issued: new Date().toISOString(),
      expires: expiryDate.toISOString(),
      uuid: this.generateUUID()
    };

    // Encrypt license data
    const encrypted = CryptoJS.AES.encrypt(
      JSON.stringify(data),
      this.LICENSE_SECRET
    ).toString();

    // Format as license key (XXXX-XXXX-XXXX-XXXX)
    const base64 = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(encrypted));
    const cleaned = base64.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    
    // Create formatted key
    const segments = [];
    for (let i = 0; i < 4; i++) {
      segments.push(cleaned.substr(i * 4, 4));
    }
    
    return segments.join('-');
  }

  // Validate and decode license key
  validateLicenseKey(licenseKey) {
    try {
      // Remove dashes and decode
      const cleaned = licenseKey.replace(/-/g, '');
      const base64 = CryptoJS.enc.Base64.parse(cleaned).toString(CryptoJS.enc.Utf8);
      
      // Decrypt
      const decrypted = CryptoJS.AES.decrypt(base64, this.LICENSE_SECRET);
      const data = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));

      // Check expiry
      const expiryDate = new Date(data.expires);
      const isExpired = expiryDate < new Date();

      return {
        valid: !isExpired,
        data,
        expired: isExpired,
        daysRemaining: this.getDaysRemaining(expiryDate)
      };
    } catch (error) {
      return {
        valid: false,
        error: 'Invalid license key'
      };
    }
  }

  // Activate a license
  activateLicense(licenseKey, deviceId, tosAccepted = false) {
    if (!tosAccepted) {
      return {
        success: false,
        error: 'You must accept the Terms of Service to activate this license'
      };
    }

    const validation = this.validateLicenseKey(licenseKey);
    
    if (!validation.valid) {
      return {
        success: false,
        error: validation.error || 'License key is expired'
      };
    }

    const licenseData = validation.data;
    const tier = this.licenseTypes[licenseData.tier.toUpperCase()];

    if (!tier) {
      return {
        success: false,
        error: 'Invalid license tier'
      };
    }

    // Check device limit
    const existingLicense = this.licenses.find(l => l.key === licenseKey);
    if (existingLicense) {
      if (tier.maxDevices !== -1 && existingLicense.devices.length >= tier.maxDevices) {
        return {
          success: false,
          error: `License limit reached (${tier.maxDevices} devices maximum)`
        };
      }

      // Add device to existing license
      if (!existingLicense.devices.includes(deviceId)) {
        existingLicense.devices.push(deviceId);
      }
    } else {
      // Create new license entry
      this.licenses.push({
        key: licenseKey,
        tier: licenseData.tier,
        email: licenseData.email,
        issued: licenseData.issued,
        expires: licenseData.expires,
        devices: [deviceId],
        tosAccepted: true,
        tosVersion: '1.0',
        tosAcceptedDate: new Date().toISOString()
      });
    }

    this.saveLicenses();

    return {
      success: true,
      license: {
        tier: licenseData.tier,
        expires: licenseData.expires,
        daysRemaining: validation.daysRemaining,
        features: tier.features
      }
    };
  }

  // Deactivate a license on a device
  deactivateLicense(licenseKey, deviceId) {
    const license = this.licenses.find(l => l.key === licenseKey);
    
    if (!license) {
      return { success: false, error: 'License not found' };
    }

    license.devices = license.devices.filter(d => d !== deviceId);
    this.saveLicenses();

    return { success: true };
  }

  // Check if user has accepted ToS
  hasAcceptedToS(email) {
    const license = this.licenses.find(l => l.email === email);
    return license?.tosAccepted || false;
  }

  // Record ToS acceptance
  acceptToS(email, version = '1.0') {
    const license = this.licenses.find(l => l.email === email);
    
    if (license) {
      license.tosAccepted = true;
      license.tosVersion = version;
      license.tosAcceptedDate = new Date().toISOString();
      this.saveLicenses();
      return true;
    }
    
    return false;
  }

  // Get current active license for device
  getActiveLicense(deviceId) {
    const license = this.licenses.find(l => l.devices.includes(deviceId));
    
    if (!license) {
      return {
        tier: 'free',
        features: this.licenseTypes.FREE.features,
        active: true
      };
    }

    const validation = this.validateLicenseKey(license.key);
    
    if (!validation.valid) {
      return {
        tier: 'free',
        features: this.licenseTypes.FREE.features,
        active: false,
        expired: true
      };
    }

    const tierInfo = this.licenseTypes[license.tier.toUpperCase()];

    return {
      tier: license.tier,
      features: tierInfo.features,
      active: true,
      expires: license.expires,
      daysRemaining: validation.daysRemaining,
      tosAccepted: license.tosAccepted
    };
  }

  // Check if feature is available
  hasFeature(deviceId, featureName) {
    const license = this.getActiveLicense(deviceId);
    return license.features[featureName] === true;
  }

  // Get license tiers info
  getLicenseTiers() {
    return this.licenseTypes;
  }

  // Get subscription status
  getSubscriptionStatus(deviceId) {
    const license = this.getActiveLicense(deviceId);
    
    return {
      tier: license.tier,
      tierName: this.licenseTypes[license.tier.toUpperCase()]?.name || 'Free Edition',
      active: license.active,
      expires: license.expires,
      daysRemaining: license.daysRemaining,
      features: license.features,
      expired: license.expired || false,
      tosAccepted: license.tosAccepted || false
    };
  }

  // Helper functions
  generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  getDaysRemaining(expiryDate) {
    const now = new Date();
    const expiry = new Date(expiryDate);
    const diffTime = expiry - now;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return Math.max(0, diffDays);
  }

  loadLicenses() {
    try {
      const stored = localStorage.getItem('nebula_licenses');
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      return [];
    }
  }

  saveLicenses() {
    localStorage.setItem('nebula_licenses', JSON.stringify(this.licenses));
  }

  // Get device fingerprint (simplified)
  getDeviceId() {
    let deviceId = localStorage.getItem('device_id');
    
    if (!deviceId) {
      deviceId = this.generateUUID();
      localStorage.setItem('device_id', deviceId);
    }
    
    return deviceId;
  }

  // Generate trial license (14 days)
  generateTrialLicense(email) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 14); // 14-day trial

    return this.generateLicenseKey('PERSONAL', email, expiryDate);
  }

  // Check license compliance
  checkCompliance(deviceId) {
    const license = this.getActiveLicense(deviceId);
    const issues = [];

    if (!license.tosAccepted) {
      issues.push({
        type: 'tos_not_accepted',
        severity: 'high',
        message: 'Terms of Service must be accepted to continue using this software'
      });
    }

    if (license.expired) {
      issues.push({
        type: 'license_expired',
        severity: 'critical',
        message: 'Your license has expired. Please renew to continue using premium features'
      });
    }

    if (license.daysRemaining !== undefined && license.daysRemaining < 7) {
      issues.push({
        type: 'license_expiring',
        severity: 'warning',
        message: `Your license expires in ${license.daysRemaining} days`
      });
    }

    return {
      compliant: issues.filter(i => i.severity === 'critical').length === 0,
      issues
    };
  }
}

// Export singleton instance
const licenseManager = new LicenseManager();
export default licenseManager;
