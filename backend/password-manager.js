const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const EventEmitter = require('events');

class PasswordManager extends EventEmitter {
  constructor() {
    super();
    this.vaultPath = path.join(__dirname, 'data', 'password-vault.json');
    this.configPath = path.join(__dirname, 'data', 'vault-config.json');
    this.breachedPasswordsCache = new Map();
    this.vault = {
      passwords: [],
      lastModified: null,
      encrypted: true
    };
    this.masterKeyHash = null;
    this.isUnlocked = false;
    this.encryptionKey = null;
    this.autoLockTimeout = null;
    this.autoLockDelay = 5 * 60 * 1000; // 5 minutes
    
    // Password strength criteria
    this.strengthCriteria = {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecial: true,
      commonPatterns: [
        /password/i,
        /123456/,
        /qwerty/i,
        /admin/i,
        /letmein/i,
        /welcome/i,
        /monkey/i,
        /dragon/i,
        /master/i,
        /sunshine/i
      ]
    };
  }

  async initialize() {
    try {
      // Create data directory if it doesn't exist
      const dataDir = path.join(__dirname, 'data');
      await fs.mkdir(dataDir, { recursive: true });

      // Load vault if exists
      await this.loadVault();
      
      // Load configuration
      await this.loadConfig();
      
      console.log('🔐 Password Manager initialized');
      this.emit('initialized');
      
      return { success: true };
    } catch (error) {
      console.error('Failed to initialize Password Manager:', error);
      throw error;
    }
  }

  async loadVault() {
    try {
      const data = await fs.readFile(this.vaultPath, 'utf8');
      this.vault = JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        // Vault doesn't exist, create new one
        await this.saveVault();
      }
    }
  }

  async saveVault() {
    try {
      await fs.writeFile(this.vaultPath, JSON.stringify(this.vault, null, 2));
      this.vault.lastModified = new Date().toISOString();
    } catch (error) {
      console.error('Failed to save vault:', error);
      throw error;
    }
  }

  async loadConfig() {
    try {
      const data = await fs.readFile(this.configPath, 'utf8');
      const config = JSON.parse(data);
      this.masterKeyHash = config.masterKeyHash;
      this.autoLockDelay = config.autoLockDelay || this.autoLockDelay;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('Failed to load config:', error);
      }
    }
  }

  async saveConfig() {
    try {
      const config = {
        masterKeyHash: this.masterKeyHash,
        autoLockDelay: this.autoLockDelay,
        createdAt: new Date().toISOString()
      };
      await fs.writeFile(this.configPath, JSON.stringify(config, null, 2));
    } catch (error) {
      console.error('Failed to save config:', error);
      throw error;
    }
  }

  // Master password management
  hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  deriveEncryptionKey(masterPassword, salt) {
    return crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, 'sha256');
  }

  async setMasterPassword(password) {
    if (!password || password.length < 8) {
      throw new Error('Master password must be at least 8 characters');
    }

    const strength = this.checkPasswordStrength(password);
    if (strength.score < 3) {
      throw new Error('Master password is too weak. Use a stronger password.');
    }

    this.masterKeyHash = this.hashPassword(password);
    await this.saveConfig();

    this.emit('master-password-set');
    return { success: true };
  }

  async unlockVault(masterPassword) {
    const hash = this.hashPassword(masterPassword);
    
    if (!this.masterKeyHash) {
      throw new Error('No master password set. Please set one first.');
    }

    if (hash !== this.masterKeyHash) {
      this.emit('unlock-failed');
      throw new Error('Invalid master password');
    }

    // Derive encryption key from master password
    const salt = 'nebula-shield-salt'; // In production, use random salt per user
    this.encryptionKey = this.deriveEncryptionKey(masterPassword, salt);
    this.isUnlocked = true;

    // Start auto-lock timer
    this.resetAutoLock();

    this.emit('vault-unlocked');
    return { success: true, message: 'Vault unlocked successfully' };
  }

  lockVault() {
    this.isUnlocked = false;
    this.encryptionKey = null;
    
    if (this.autoLockTimeout) {
      clearTimeout(this.autoLockTimeout);
      this.autoLockTimeout = null;
    }

    this.emit('vault-locked');
    return { success: true, message: 'Vault locked' };
  }

  resetAutoLock() {
    if (this.autoLockTimeout) {
      clearTimeout(this.autoLockTimeout);
    }

    this.autoLockTimeout = setTimeout(() => {
      this.lockVault();
      this.emit('auto-locked');
    }, this.autoLockDelay);
  }

  ensureUnlocked() {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock it first.');
    }
    this.resetAutoLock();
  }

  // Encryption/Decryption
  encrypt(text) {
    if (!this.encryptionKey) {
      throw new Error('No encryption key available');
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {
      iv: iv.toString('hex'),
      data: encrypted
    };
  }

  decrypt(encryptedData) {
    if (!this.encryptionKey) {
      throw new Error('No encryption key available');
    }

    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
    
    let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  // Password CRUD operations
  async addPassword(entry) {
    this.ensureUnlocked();

    const { website, username, password, notes, category } = entry;

    if (!website || !password) {
      throw new Error('Website and password are required');
    }

    // Check password strength
    const strength = this.checkPasswordStrength(password);
    
    // Check if password has been breached
    const breached = await this.checkPasswordBreach(password);

    // Encrypt sensitive data
    const encryptedPassword = this.encrypt(password);
    const encryptedNotes = notes ? this.encrypt(notes) : null;

    const passwordEntry = {
      id: crypto.randomUUID(),
      website,
      username: username || '',
      password: encryptedPassword,
      notes: encryptedNotes,
      category: category || 'General',
      strength: strength.score,
      breached: breached.isBreached,
      breachCount: breached.count,
      createdAt: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      lastUsed: null,
      usageCount: 0,
      autoFillEnabled: true
    };

    this.vault.passwords.push(passwordEntry);
    await this.saveVault();

    this.emit('password-added', { id: passwordEntry.id, website });

    return {
      success: true,
      id: passwordEntry.id,
      strength: strength,
      breached: breached
    };
  }

  async updatePassword(id, updates) {
    this.ensureUnlocked();

    const index = this.vault.passwords.findIndex(p => p.id === id);
    if (index === -1) {
      throw new Error('Password entry not found');
    }

    const entry = this.vault.passwords[index];

    // Update fields
    if (updates.website) entry.website = updates.website;
    if (updates.username) entry.username = updates.username;
    if (updates.category) entry.category = updates.category;
    if (updates.autoFillEnabled !== undefined) entry.autoFillEnabled = updates.autoFillEnabled;

    // Update password if provided
    if (updates.password) {
      const strength = this.checkPasswordStrength(updates.password);
      const breached = await this.checkPasswordBreach(updates.password);

      entry.password = this.encrypt(updates.password);
      entry.strength = strength.score;
      entry.breached = breached.isBreached;
      entry.breachCount = breached.count;
    }

    // Update notes if provided
    if (updates.notes !== undefined) {
      entry.notes = updates.notes ? this.encrypt(updates.notes) : null;
    }

    entry.lastModified = new Date().toISOString();

    await this.saveVault();
    this.emit('password-updated', { id, website: entry.website });

    return { success: true, id };
  }

  async deletePassword(id) {
    this.ensureUnlocked();

    const index = this.vault.passwords.findIndex(p => p.id === id);
    if (index === -1) {
      throw new Error('Password entry not found');
    }

    const entry = this.vault.passwords[index];
    this.vault.passwords.splice(index, 1);

    await this.saveVault();
    this.emit('password-deleted', { id, website: entry.website });

    return { success: true };
  }

  async getPassword(id) {
    this.ensureUnlocked();

    const entry = this.vault.passwords.find(p => p.id === id);
    if (!entry) {
      throw new Error('Password entry not found');
    }

    // Decrypt password and notes
    const decryptedPassword = this.decrypt(entry.password);
    const decryptedNotes = entry.notes ? this.decrypt(entry.notes) : null;

    // Update usage stats
    entry.lastUsed = new Date().toISOString();
    entry.usageCount++;
    await this.saveVault();

    return {
      ...entry,
      password: decryptedPassword,
      notes: decryptedNotes
    };
  }

  async getAllPasswords() {
    this.ensureUnlocked();

    // Return entries without decrypted passwords
    return this.vault.passwords.map(entry => ({
      id: entry.id,
      website: entry.website,
      username: entry.username,
      category: entry.category,
      strength: entry.strength,
      breached: entry.breached,
      breachCount: entry.breachCount,
      createdAt: entry.createdAt,
      lastModified: entry.lastModified,
      lastUsed: entry.lastUsed,
      usageCount: entry.usageCount,
      autoFillEnabled: entry.autoFillEnabled
    }));
  }

  async searchPasswords(query) {
    this.ensureUnlocked();

    const lowerQuery = query.toLowerCase();
    const results = this.vault.passwords.filter(entry => 
      entry.website.toLowerCase().includes(lowerQuery) ||
      entry.username.toLowerCase().includes(lowerQuery) ||
      entry.category.toLowerCase().includes(lowerQuery)
    );

    return results.map(entry => ({
      id: entry.id,
      website: entry.website,
      username: entry.username,
      category: entry.category,
      strength: entry.strength,
      breached: entry.breached
    }));
  }

  // Auto-fill functionality
  async getAutoFillSuggestions(url) {
    this.ensureUnlocked();

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      // Find matching passwords
      const matches = this.vault.passwords.filter(entry => {
        if (!entry.autoFillEnabled) return false;
        
        const entryDomain = this.extractDomain(entry.website);
        return entryDomain === domain || entry.website.includes(domain);
      });

      return matches.map(entry => ({
        id: entry.id,
        website: entry.website,
        username: entry.username,
        lastUsed: entry.lastUsed,
        usageCount: entry.usageCount
      })).sort((a, b) => b.usageCount - a.usageCount);
    } catch (error) {
      return [];
    }
  }

  extractDomain(url) {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      return urlObj.hostname.replace(/^www\./, '');
    } catch {
      return url;
    }
  }

  // Password strength checker
  checkPasswordStrength(password) {
    let score = 0;
    const feedback = [];

    // Length check
    if (password.length >= this.strengthCriteria.minLength) {
      score += 1;
    } else {
      feedback.push(`Use at least ${this.strengthCriteria.minLength} characters`);
    }

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Add uppercase letters');

    if (/[0-9]/.test(password)) score += 1;
    else feedback.push('Add numbers');

    if (/[^a-zA-Z0-9]/.test(password)) score += 1;
    else feedback.push('Add special characters (!@#$%^&*)');

    // Check for common patterns
    const hasCommonPattern = this.strengthCriteria.commonPatterns.some(pattern => 
      pattern.test(password)
    );
    if (hasCommonPattern) {
      score = Math.max(0, score - 2);
      feedback.push('Avoid common words and patterns');
    }

    // Check for repeated characters
    if (/(.)\1{2,}/.test(password)) {
      score = Math.max(0, score - 1);
      feedback.push('Avoid repeated characters');
    }

    // Check for sequential characters
    if (/abc|bcd|cde|123|234|345/i.test(password)) {
      score = Math.max(0, score - 1);
      feedback.push('Avoid sequential patterns');
    }

    // Bonus for length
    if (password.length >= 16) score += 1;
    if (password.length >= 20) score += 1;

    // Calculate final score (0-5)
    score = Math.min(5, score);

    let strength, color;
    if (score <= 1) {
      strength = 'Very Weak';
      color = '#ef4444';
    } else if (score === 2) {
      strength = 'Weak';
      color = '#f59e0b';
    } else if (score === 3) {
      strength = 'Fair';
      color = '#eab308';
    } else if (score === 4) {
      strength = 'Strong';
      color = '#10b981';
    } else {
      strength = 'Very Strong';
      color = '#059669';
    }

    return {
      score,
      strength,
      color,
      feedback: feedback.length > 0 ? feedback : ['Password strength is good'],
      percentage: (score / 5) * 100
    };
  }

  // Generate strong password
  generatePassword(options = {}) {
    const {
      length = 16,
      includeUppercase = true,
      includeLowercase = true,
      includeNumbers = true,
      includeSymbols = true,
      excludeSimilar = true,
      excludeAmbiguous = true
    } = options;

    let charset = '';
    let lowercase = 'abcdefghijklmnopqrstuvwxyz';
    let uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let numbers = '0123456789';
    let symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    // Exclude similar characters
    if (excludeSimilar) {
      lowercase = lowercase.replace(/[il1o0]/g, '');
      uppercase = uppercase.replace(/[ILO]/g, '');
      numbers = numbers.replace(/[10]/g, '');
    }

    // Exclude ambiguous characters
    if (excludeAmbiguous) {
      symbols = symbols.replace(/[{}[\]()\/\\'"`,~;:<>]/g, '');
    }

    if (includeLowercase) charset += lowercase;
    if (includeUppercase) charset += uppercase;
    if (includeNumbers) charset += numbers;
    if (includeSymbols) charset += symbols;

    if (charset.length === 0) {
      throw new Error('At least one character type must be selected');
    }

    let password = '';
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }

    // Ensure password meets all criteria
    const ensureCriteria = (pwd) => {
      let result = pwd;
      if (includeUppercase && !/[A-Z]/.test(result)) {
        result = result.substring(0, result.length - 1) + uppercase[Math.floor(Math.random() * uppercase.length)];
      }
      if (includeLowercase && !/[a-z]/.test(result)) {
        result = result.substring(0, result.length - 1) + lowercase[Math.floor(Math.random() * lowercase.length)];
      }
      if (includeNumbers && !/[0-9]/.test(result)) {
        result = result.substring(0, result.length - 1) + numbers[Math.floor(Math.random() * numbers.length)];
      }
      if (includeSymbols && !/[^a-zA-Z0-9]/.test(result)) {
        result = result.substring(0, result.length - 1) + symbols[Math.floor(Math.random() * symbols.length)];
      }
      return result;
    };

    password = ensureCriteria(password);

    const strength = this.checkPasswordStrength(password);

    return {
      password,
      strength,
      options
    };
  }

  // Breach monitoring using Have I Been Pwned API
  async checkPasswordBreach(password) {
    try {
      // Use k-Anonymity model - only send first 5 chars of SHA-1 hash
      const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5);

      // Check cache first
      if (this.breachedPasswordsCache.has(sha1Hash)) {
        return this.breachedPasswordsCache.get(sha1Hash);
      }

      // Query Have I Been Pwned API
      const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
        timeout: 5000,
        headers: {
          'User-Agent': 'Nebula-Shield-Password-Manager'
        }
      });

      const hashes = response.data.split('\n');
      const match = hashes.find(line => line.startsWith(suffix));

      let result = {
        isBreached: false,
        count: 0,
        message: 'Password has not been found in any data breaches'
      };

      if (match) {
        const count = parseInt(match.split(':')[1]);
        result = {
          isBreached: true,
          count,
          message: `⚠️ This password has been exposed ${count.toLocaleString()} times in data breaches!`,
          severity: count > 1000 ? 'critical' : count > 100 ? 'high' : 'medium'
        };
      }

      // Cache result
      this.breachedPasswordsCache.set(sha1Hash, result);

      return result;
    } catch (error) {
      console.error('Breach check failed:', error.message);
      return {
        isBreached: false,
        count: 0,
        message: 'Unable to check breach status',
        error: true
      };
    }
  }

  async scanAllPasswordsForBreaches() {
    this.ensureUnlocked();

    const results = {
      total: this.vault.passwords.length,
      breached: 0,
      safe: 0,
      weak: 0,
      details: []
    };

    for (const entry of this.vault.passwords) {
      try {
        const decryptedPassword = this.decrypt(entry.password);
        const breachCheck = await this.checkPasswordBreach(decryptedPassword);
        const strengthCheck = this.checkPasswordStrength(decryptedPassword);

        // Update entry
        entry.breached = breachCheck.isBreached;
        entry.breachCount = breachCheck.count;
        entry.strength = strengthCheck.score;

        if (breachCheck.isBreached) {
          results.breached++;
          results.details.push({
            id: entry.id,
            website: entry.website,
            status: 'breached',
            count: breachCheck.count,
            severity: breachCheck.severity
          });
        } else {
          results.safe++;
        }

        if (strengthCheck.score < 3) {
          results.weak++;
        }

        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.error(`Failed to check password for ${entry.website}:`, error.message);
      }
    }

    await this.saveVault();
    this.emit('breach-scan-completed', results);

    return results;
  }

  // Statistics
  getStatistics() {
    return {
      totalPasswords: this.vault.passwords.length,
      isUnlocked: this.isUnlocked,
      hasMasterPassword: !!this.masterKeyHash,
      categories: this.getCategoryCounts(),
      strengthDistribution: this.getStrengthDistribution(),
      breachedCount: this.vault.passwords.filter(p => p.breached).length,
      weakCount: this.vault.passwords.filter(p => p.strength < 3).length,
      lastModified: this.vault.lastModified,
      autoLockDelay: this.autoLockDelay / 1000 / 60 // minutes
    };
  }

  getCategoryCounts() {
    const counts = {};
    this.vault.passwords.forEach(entry => {
      counts[entry.category] = (counts[entry.category] || 0) + 1;
    });
    return counts;
  }

  getStrengthDistribution() {
    const distribution = {
      veryWeak: 0,
      weak: 0,
      fair: 0,
      strong: 0,
      veryStrong: 0
    };

    this.vault.passwords.forEach(entry => {
      if (entry.strength <= 1) distribution.veryWeak++;
      else if (entry.strength === 2) distribution.weak++;
      else if (entry.strength === 3) distribution.fair++;
      else if (entry.strength === 4) distribution.strong++;
      else distribution.veryStrong++;
    });

    return distribution;
  }

  // Export/Import
  async exportVault(includePasswords = false) {
    this.ensureUnlocked();

    const exportData = {
      exportedAt: new Date().toISOString(),
      version: '1.0',
      entries: this.vault.passwords.map(entry => {
        const exported = {
          website: entry.website,
          username: entry.username,
          category: entry.category,
          notes: entry.notes ? this.decrypt(entry.notes) : null,
          createdAt: entry.createdAt
        };

        if (includePasswords) {
          exported.password = this.decrypt(entry.password);
        }

        return exported;
      })
    };

    return exportData;
  }

  async importVault(data) {
    this.ensureUnlocked();

    if (!data.entries || !Array.isArray(data.entries)) {
      throw new Error('Invalid import data format');
    }

    let imported = 0;
    let skipped = 0;

    for (const entry of data.entries) {
      try {
        await this.addPassword(entry);
        imported++;
      } catch (error) {
        console.error(`Failed to import entry for ${entry.website}:`, error.message);
        skipped++;
      }
    }

    return {
      success: true,
      imported,
      skipped,
      total: data.entries.length
    };
  }
}

// Singleton instance
const passwordManager = new PasswordManager();

module.exports = passwordManager;
