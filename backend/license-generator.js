/**
 * Server-Side License Key Generator
 * Handles secure license key generation, validation, and database storage
 */

const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class LicenseGenerator {
  constructor() {
    // In production, use environment variable
    this.SECRET_KEY = process.env.LICENSE_SECRET || 'NEBULA_SHIELD_LICENSE_SECRET_2025_CHANGE_IN_PRODUCTION';
    this.ALGORITHM = 'aes-256-cbc';
    
    // Initialize database
    this.db = new sqlite3.Database(path.join(__dirname, '../data/licenses.db'), (err) => {
      if (err) {
        console.error('License DB Error:', err);
      } else {
        console.log('📄 License database connected');
        this.initializeDatabase();
      }
    });
  }

  initializeDatabase() {
    this.db.serialize(() => {
      // Licenses table
      this.db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          license_key TEXT UNIQUE NOT NULL,
          tier TEXT NOT NULL,
          email TEXT NOT NULL,
          issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME NOT NULL,
          max_devices INTEGER NOT NULL,
          status TEXT DEFAULT 'active',
          order_id TEXT,
          payment_method TEXT,
          amount REAL,
          tos_version TEXT DEFAULT '1.0',
          created_by TEXT
        )
      `, (err) => {
        if (err) console.error('Error creating licenses table:', err);
        else console.log('✅ Licenses table ready');
      });

      // License activations table
      this.db.run(`
        CREATE TABLE IF NOT EXISTS license_activations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          license_key TEXT NOT NULL,
          device_id TEXT NOT NULL,
          device_name TEXT,
          activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          last_seen DATETIME,
          ip_address TEXT,
          os_info TEXT,
          tos_accepted BOOLEAN DEFAULT 0,
          tos_accepted_at DATETIME,
          status TEXT DEFAULT 'active',
          FOREIGN KEY (license_key) REFERENCES licenses(license_key),
          UNIQUE(license_key, device_id)
        )
      `, (err) => {
        if (err) console.error('Error creating activations table:', err);
        else console.log('✅ License activations table ready');
      });

      // License history table (for auditing)
      this.db.run(`
        CREATE TABLE IF NOT EXISTS license_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          license_key TEXT NOT NULL,
          action TEXT NOT NULL,
          details TEXT,
          ip_address TEXT,
          user_agent TEXT,
          timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (license_key) REFERENCES licenses(license_key)
        )
      `, (err) => {
        if (err) console.error('Error creating history table:', err);
        else console.log('✅ License history table ready');
      });
    });
  }

  /**
   * Generate a cryptographically secure license key
   * Format: XXXX-XXXX-XXXX-XXXX (16 characters + dashes)
   */
  generateLicenseKey(tier, email, durationDays, orderId = null, paymentMethod = null, amount = null) {
    return new Promise((resolve, reject) => {
      try {
        // Calculate expiration
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + durationDays);

        // Create unique identifier
        const uuid = crypto.randomUUID();
        
        // Tier-based prefix for easy identification
        const prefixes = {
          free: 'FREE',
          trial: 'TRIL',
          personal: 'PERS',
          premium: 'PREM',
          business: 'BUSI',
          enterprise: 'ENTR'
        };

        const prefix = prefixes[tier.toLowerCase()] || 'UNKN';

        // Generate cryptographic data
        const licenseData = {
          tier,
          email,
          issued: new Date().toISOString(),
          expires: expiresAt.toISOString(),
          uuid
        };

        // Encrypt license data
        const iv = crypto.randomBytes(16);
        const key = crypto.scryptSync(this.SECRET_KEY, 'salt', 32);
        const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
        
        let encrypted = cipher.update(JSON.stringify(licenseData), 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Combine IV and encrypted data
        const combined = iv.toString('hex') + encrypted;

        // Generate checksum
        const checksum = crypto.createHash('sha256')
          .update(combined + this.SECRET_KEY)
          .digest('hex')
          .substring(0, 4)
          .toUpperCase();

        // Create formatted license key
        const random = crypto.randomBytes(2).toString('hex').toUpperCase();
        const licenseKey = `${prefix}-${random}${checksum.substring(0, 2)}-${checksum.substring(2, 4)}${combined.substring(0, 2).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

        // Get max devices for tier
        const maxDevices = this.getMaxDevices(tier);

        // Store in database
        this.db.run(
          `INSERT INTO licenses (license_key, tier, email, expires_at, max_devices, order_id, payment_method, amount)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [licenseKey, tier, email, expiresAt.toISOString(), maxDevices, orderId, paymentMethod, amount],
          function(err) {
            if (err) {
              reject(err);
            } else {
              // Log generation
              this.logAction(licenseKey, 'generated', `License generated for ${email}`);
              
              resolve({
                success: true,
                licenseKey,
                tier,
                email,
                expiresAt: expiresAt.toISOString(),
                maxDevices,
                daysRemaining: durationDays,
                orderId
              });
            }
          }.bind(this)
        );
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Validate a license key
   */
  validateLicenseKey(licenseKey) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM licenses WHERE license_key = ?',
        [licenseKey],
        (err, row) => {
          if (err) {
            return reject(err);
          }

          if (!row) {
            return resolve({
              valid: false,
              error: 'Invalid license key'
            });
          }

          const now = new Date();
          const expiresAt = new Date(row.expires_at);
          const isExpired = expiresAt < now;
          const isActive = row.status === 'active';

          const daysRemaining = Math.max(0, Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24)));

          resolve({
            valid: !isExpired && isActive,
            expired: isExpired,
            status: row.status,
            tier: row.tier,
            email: row.email,
            expiresAt: row.expires_at,
            daysRemaining,
            maxDevices: row.max_devices
          });
        }
      );
    });
  }

  /**
   * Activate license on a device
   */
  activateLicense(licenseKey, deviceId, deviceInfo = {}) {
    return new Promise(async (resolve, reject) => {
      try {
        // Validate license first
        const validation = await this.validateLicenseKey(licenseKey);
        
        if (!validation.valid) {
          return resolve({
            success: false,
            error: validation.expired ? 'License has expired' : validation.error || 'Invalid license'
          });
        }

        // Check device limit
        this.db.get(
          'SELECT COUNT(*) as count FROM license_activations WHERE license_key = ? AND status = "active"',
          [licenseKey],
          (err, row) => {
            if (err) {
              return reject(err);
            }

            if (row.count >= validation.maxDevices) {
              return resolve({
                success: false,
                error: `Device limit reached (${validation.maxDevices} devices maximum). Deactivate a device to continue.`
              });
            }

            // Check if already activated on this device
            this.db.get(
              'SELECT * FROM license_activations WHERE license_key = ? AND device_id = ?',
              [licenseKey, deviceId],
              (err, existing) => {
                if (err) {
                  return reject(err);
                }

                if (existing) {
                  // Update existing activation
                  this.db.run(
                    `UPDATE license_activations 
                     SET last_seen = CURRENT_TIMESTAMP, status = 'active', 
                         ip_address = ?, os_info = ?
                     WHERE license_key = ? AND device_id = ?`,
                    [deviceInfo.ipAddress, deviceInfo.osInfo, licenseKey, deviceId],
                    (err) => {
                      if (err) {
                        return reject(err);
                      }

                      this.logAction(licenseKey, 'reactivated', `Reactivated on device ${deviceId}`);
                      
                      resolve({
                        success: true,
                        message: 'License reactivated',
                        license: validation
                      });
                    }
                  );
                } else {
                  // New activation
                  this.db.run(
                    `INSERT INTO license_activations 
                     (license_key, device_id, device_name, ip_address, os_info, tos_accepted, tos_accepted_at)
                     VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                    [licenseKey, deviceId, deviceInfo.deviceName, deviceInfo.ipAddress, deviceInfo.osInfo, 1],
                    (err) => {
                      if (err) {
                        return reject(err);
                      }

                      this.logAction(licenseKey, 'activated', `Activated on device ${deviceId}`);
                      
                      resolve({
                        success: true,
                        message: 'License activated successfully',
                        license: validation
                      });
                    }
                  );
                }
              }
            );
          }
        );
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Deactivate license from a device
   */
  deactivateLicense(licenseKey, deviceId) {
    return new Promise((resolve, reject) => {
      this.db.run(
        'UPDATE license_activations SET status = "inactive" WHERE license_key = ? AND device_id = ?',
        [licenseKey, deviceId],
        function(err) {
          if (err) {
            return reject(err);
          }

          if (this.changes === 0) {
            return resolve({
              success: false,
              error: 'Device not found or already inactive'
            });
          }

          this.logAction(licenseKey, 'deactivated', `Deactivated from device ${deviceId}`);
          
          resolve({
            success: true,
            message: 'License deactivated from device'
          });
        }.bind(this)
      );
    });
  }

  /**
   * Get license status for a device
   */
  getLicenseStatus(deviceId) {
    return new Promise((resolve, reject) => {
      this.db.get(
        `SELECT l.*, a.activated_at, a.last_seen, a.tos_accepted
         FROM licenses l
         INNER JOIN license_activations a ON l.license_key = a.license_key
         WHERE a.device_id = ? AND a.status = 'active' AND l.status = 'active'`,
        [deviceId],
        async (err, row) => {
          if (err) {
            return reject(err);
          }

          if (!row) {
            // Return free tier
            return resolve({
              tier: 'free',
              active: true,
              features: this.getFeatures('free')
            });
          }

          const validation = await this.validateLicenseKey(row.license_key);

          resolve({
            tier: row.tier,
            active: validation.valid,
            expired: validation.expired,
            expiresAt: row.expires_at,
            daysRemaining: validation.daysRemaining,
            activatedAt: row.activated_at,
            lastSeen: row.last_seen,
            tosAccepted: row.tos_accepted === 1,
            features: this.getFeatures(row.tier)
          });
        }
      );
    });
  }

  /**
   * Get all activations for a license key
   */
  getActivations(licenseKey) {
    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM license_activations WHERE license_key = ? ORDER BY activated_at DESC',
        [licenseKey],
        (err, rows) => {
          if (err) {
            return reject(err);
          }
          resolve(rows);
        }
      );
    });
  }

  /**
   * Revoke/Cancel a license
   */
  revokeLicense(licenseKey, reason) {
    return new Promise((resolve, reject) => {
      this.db.run(
        'UPDATE licenses SET status = "revoked" WHERE license_key = ?',
        [licenseKey],
        function(err) {
          if (err) {
            return reject(err);
          }

          // Deactivate all devices
          this.db.run(
            'UPDATE license_activations SET status = "inactive" WHERE license_key = ?',
            [licenseKey]
          );

          this.logAction(licenseKey, 'revoked', reason);
          
          resolve({
            success: true,
            message: 'License revoked'
          });
        }.bind(this)
      );
    });
  }

  /**
   * Extend license expiration
   */
  extendLicense(licenseKey, additionalDays) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT expires_at FROM licenses WHERE license_key = ?',
        [licenseKey],
        (err, row) => {
          if (err) {
            return reject(err);
          }

          if (!row) {
            return resolve({ success: false, error: 'License not found' });
          }

          const newExpiry = new Date(row.expires_at);
          newExpiry.setDate(newExpiry.getDate() + additionalDays);

          this.db.run(
            'UPDATE licenses SET expires_at = ? WHERE license_key = ?',
            [newExpiry.toISOString(), licenseKey],
            function(err) {
              if (err) {
                return reject(err);
              }

              this.logAction(licenseKey, 'extended', `Extended by ${additionalDays} days`);
              
              resolve({
                success: true,
                message: `License extended by ${additionalDays} days`,
                newExpiry: newExpiry.toISOString()
              });
            }.bind(this)
          );
        }
      );
    });
  }

  /**
   * Log license action for auditing
   */
  logAction(licenseKey, action, details, ipAddress = null, userAgent = null) {
    this.db.run(
      'INSERT INTO license_history (license_key, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
      [licenseKey, action, details, ipAddress, userAgent]
    );
  }

  /**
   * Get license history
   */
  getHistory(licenseKey) {
    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM license_history WHERE license_key = ? ORDER BY timestamp DESC LIMIT 100',
        [licenseKey],
        (err, rows) => {
          if (err) {
            return reject(err);
          }
          resolve(rows);
        }
      );
    });
  }

  /**
   * Helper: Get max devices for tier
   */
  getMaxDevices(tier) {
    const limits = {
      free: 1,
      trial: 3,
      personal: 3,
      premium: 5,
      business: 25,
      enterprise: -1 // unlimited
    };
    return limits[tier.toLowerCase()] || 1;
  }

  /**
   * Helper: Get features for tier
   */
  getFeatures(tier) {
    const features = {
      free: { realTimeProtection: true, manualScan: true, basicReports: true, scheduledScans: false },
      trial: { realTimeProtection: true, manualScan: true, basicReports: true, advancedReports: true, scheduledScans: true },
      personal: { realTimeProtection: true, manualScan: true, basicReports: true, advancedReports: true, scheduledScans: true, aiDetection: true },
      premium: { realTimeProtection: true, manualScan: true, basicReports: true, advancedReports: true, scheduledScans: true, aiDetection: true, zeroDay: true, prioritySupport: true },
      business: { realTimeProtection: true, manualScan: true, basicReports: true, advancedReports: true, scheduledScans: true, aiDetection: true, zeroDay: true, prioritySupport: true, centralManagement: true, apiAccess: true },
      enterprise: { realTimeProtection: true, manualScan: true, basicReports: true, advancedReports: true, scheduledScans: true, aiDetection: true, zeroDay: true, prioritySupport: true, centralManagement: true, apiAccess: true, whiteLabeling: true, dedicatedSupport: true }
    };
    return features[tier.toLowerCase()] || features.free;
  }
}

module.exports = new LicenseGenerator();
