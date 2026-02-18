/**
 * Password Manager Service
 * Secure password vault with breach monitoring and encryption
 * Features: AES-256 encryption, breach detection, password health analysis
 */

import CryptoJS from 'crypto-js';
import notificationService from './notificationService';

class PasswordManager {
  constructor() {
    this.vault = new Map();
    this.masterPasswordHash = null;
    this.isUnlocked = false;
    this.encryptionKey = null;
    this.listeners = new Set();
    this.breachDatabase = new Set(); // Known breached passwords
    this.statistics = {
      totalPasswords: 0,
      weakPasswords: 0,
      reusedPasswords: 0,
      breachedPasswords: 0,
      lastBreachCheck: null
    };
    this.autoLockTimeout = null;
    this.autoLockDuration = 300000; // 5 minutes
    this.loadVaultData();
    this.loadBreachDatabase();
  }

  // ==================== MASTER PASSWORD ====================
  
  async setMasterPassword(password) {
    if (!this.validateMasterPassword(password)) {
      throw new Error('Master password does not meet security requirements');
    }

    // Hash master password using PBKDF2
    this.masterPasswordHash = CryptoJS.PBKDF2(password, 'nebula-shield-salt', {
      keySize: 256 / 32,
      iterations: 10000
    }).toString();

    // Derive encryption key from master password
    this.encryptionKey = CryptoJS.PBKDF2(password, 'nebula-shield-encryption-salt', {
      keySize: 256 / 32,
      iterations: 10000
    }).toString();

    // Save hash (not the password itself)
    localStorage.setItem('password-manager-master-hash', this.masterPasswordHash);
    
    this.isUnlocked = true;
    this.startAutoLockTimer();
    this.notifyListeners('vault-unlocked', {});

    return { success: true };
  }

  async verifyMasterPassword(password) {
    const hash = CryptoJS.PBKDF2(password, 'nebula-shield-salt', {
      keySize: 256 / 32,
      iterations: 10000
    }).toString();

    return hash === this.masterPasswordHash;
  }

  validateMasterPassword(password) {
    // Master password requirements
    const requirements = {
      minLength: 12,
      hasUppercase: /[A-Z]/.test(password),
      hasLowercase: /[a-z]/.test(password),
      hasNumber: /\d/.test(password),
      hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    };

    return (
      password.length >= requirements.minLength &&
      requirements.hasUppercase &&
      requirements.hasLowercase &&
      requirements.hasNumber &&
      requirements.hasSpecial
    );
  }

  async unlock(masterPassword) {
    if (!this.masterPasswordHash) {
      throw new Error('No master password set. Please set one first.');
    }

    if (await this.verifyMasterPassword(masterPassword)) {
      // Derive encryption key
      this.encryptionKey = CryptoJS.PBKDF2(masterPassword, 'nebula-shield-encryption-salt', {
        keySize: 256 / 32,
        iterations: 10000
      }).toString();

      this.isUnlocked = true;
      this.startAutoLockTimer();
      this.notifyListeners('vault-unlocked', {});

      notificationService.show({
        type: 'success',
        title: 'Password Vault Unlocked',
        message: 'Your passwords are now accessible',
        duration: 3000
      });

      return { success: true };
    } else {
      throw new Error('Incorrect master password');
    }
  }

  lock() {
    this.isUnlocked = false;
    this.encryptionKey = null;
    this.stopAutoLockTimer();
    this.notifyListeners('vault-locked', {});

    notificationService.show({
      type: 'info',
      title: 'Password Vault Locked',
      message: 'Your passwords are now secured',
      duration: 3000
    });
  }

  // ==================== AUTO-LOCK ====================
  
  startAutoLockTimer() {
    this.stopAutoLockTimer();
    
    this.autoLockTimeout = setTimeout(() => {
      this.lock();
      notificationService.show({
        type: 'info',
        title: 'Vault Auto-Locked',
        message: 'Password vault locked due to inactivity',
        duration: 5000
      });
    }, this.autoLockDuration);
  }

  stopAutoLockTimer() {
    if (this.autoLockTimeout) {
      clearTimeout(this.autoLockTimeout);
      this.autoLockTimeout = null;
    }
  }

  resetAutoLockTimer() {
    if (this.isUnlocked) {
      this.startAutoLockTimer();
    }
  }

  setAutoLockDuration(minutes) {
    this.autoLockDuration = minutes * 60000;
    if (this.isUnlocked) {
      this.startAutoLockTimer();
    }
  }

  // ==================== PASSWORD OPERATIONS ====================
  
  async addPassword(entry) {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const id = `pwd-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    const passwordEntry = {
      id,
      name: entry.name || 'Untitled',
      username: entry.username || '',
      password: entry.password,
      website: entry.website || '',
      notes: entry.notes || '',
      category: entry.category || 'General',
      favorite: entry.favorite || false,
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      lastUsed: null,
      tags: entry.tags || []
    };

    // Analyze password strength
    const analysis = this.analyzePassword(passwordEntry.password);
    passwordEntry.strength = analysis.strength;
    passwordEntry.score = analysis.score;

    // Check for breaches
    const breached = await this.checkPasswordBreach(passwordEntry.password);
    passwordEntry.breached = breached;

    // Encrypt password
    const encrypted = this.encryptData(passwordEntry.password);
    passwordEntry.encryptedPassword = encrypted;
    delete passwordEntry.password; // Remove plain text

    // Save to vault
    this.vault.set(id, passwordEntry);
    this.updateStatistics();
    this.saveVaultData();

    this.resetAutoLockTimer();
    this.notifyListeners('password-added', passwordEntry);

    if (breached) {
      notificationService.show({
        type: 'warning',
        title: 'Compromised Password Detected',
        message: `The password for ${passwordEntry.name} has been found in data breaches`,
        duration: 8000
      });
    }

    return { success: true, id };
  }

  async getPassword(id) {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const entry = this.vault.get(id);
    if (!entry) {
      throw new Error('Password not found');
    }

    // Decrypt password
    const decryptedPassword = this.decryptData(entry.encryptedPassword);
    
    // Update last used
    entry.lastUsed = new Date().toISOString();
    this.saveVaultData();

    this.resetAutoLockTimer();

    return {
      ...entry,
      password: decryptedPassword
    };
  }

  async updatePassword(id, updates) {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const entry = this.vault.get(id);
    if (!entry) {
      throw new Error('Password not found');
    }

    // Update fields
    if (updates.name !== undefined) entry.name = updates.name;
    if (updates.username !== undefined) entry.username = updates.username;
    if (updates.website !== undefined) entry.website = updates.website;
    if (updates.notes !== undefined) entry.notes = updates.notes;
    if (updates.category !== undefined) entry.category = updates.category;
    if (updates.favorite !== undefined) entry.favorite = updates.favorite;
    if (updates.tags !== undefined) entry.tags = updates.tags;

    // Update password if changed
    if (updates.password !== undefined) {
      const analysis = this.analyzePassword(updates.password);
      entry.strength = analysis.strength;
      entry.score = analysis.score;
      
      const breached = await this.checkPasswordBreach(updates.password);
      entry.breached = breached;

      const encrypted = this.encryptData(updates.password);
      entry.encryptedPassword = encrypted;

      if (breached) {
        notificationService.show({
          type: 'warning',
          title: 'Compromised Password',
          message: `This password has been found in data breaches`,
          duration: 8000
        });
      }
    }

    entry.modifiedAt = new Date().toISOString();
    
    this.updateStatistics();
    this.saveVaultData();
    this.resetAutoLockTimer();
    this.notifyListeners('password-updated', entry);

    return { success: true };
  }

  async deletePassword(id) {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const entry = this.vault.get(id);
    if (!entry) {
      throw new Error('Password not found');
    }

    this.vault.delete(id);
    this.updateStatistics();
    this.saveVaultData();
    this.resetAutoLockTimer();
    this.notifyListeners('password-deleted', { id });

    return { success: true };
  }

  getAllPasswords() {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    this.resetAutoLockTimer();

    // Return passwords without decrypted values
    return Array.from(this.vault.values()).map(entry => ({
      ...entry,
      password: '••••••••' // Masked
    }));
  }

  searchPasswords(query) {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const lowerQuery = query.toLowerCase();
    const results = [];

    for (const entry of this.vault.values()) {
      if (
        entry.name.toLowerCase().includes(lowerQuery) ||
        entry.username.toLowerCase().includes(lowerQuery) ||
        entry.website.toLowerCase().includes(lowerQuery) ||
        entry.category.toLowerCase().includes(lowerQuery) ||
        entry.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
      ) {
        results.push({
          ...entry,
          password: '••••••••'
        });
      }
    }

    this.resetAutoLockTimer();
    return results;
  }

  // ==================== PASSWORD ANALYSIS ====================
  
  analyzePassword(password) {
    const analysis = {
      length: password.length,
      hasUppercase: /[A-Z]/.test(password),
      hasLowercase: /[a-z]/.test(password),
      hasNumber: /\d/.test(password),
      hasSpecial: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
      score: 0,
      strength: 'weak',
      feedback: []
    };

    // Calculate score
    if (analysis.length >= 8) analysis.score += 20;
    if (analysis.length >= 12) analysis.score += 20;
    if (analysis.length >= 16) analysis.score += 20;
    if (analysis.hasUppercase) analysis.score += 10;
    if (analysis.hasLowercase) analysis.score += 10;
    if (analysis.hasNumber) analysis.score += 10;
    if (analysis.hasSpecial) analysis.score += 10;

    // Check for common patterns (reduce score)
    if (/(.)\1{2,}/.test(password)) {
      analysis.score -= 10;
      analysis.feedback.push('Contains repeated characters');
    }
    if (/^[a-zA-Z]+$/.test(password)) {
      analysis.score -= 10;
      analysis.feedback.push('Only contains letters');
    }
    if (/^[0-9]+$/.test(password)) {
      analysis.score -= 20;
      analysis.feedback.push('Only contains numbers');
    }
    if (/^(password|123456|qwerty)/i.test(password)) {
      analysis.score -= 30;
      analysis.feedback.push('Contains common password pattern');
    }

    // Determine strength
    if (analysis.score >= 80) {
      analysis.strength = 'very_strong';
    } else if (analysis.score >= 60) {
      analysis.strength = 'strong';
    } else if (analysis.score >= 40) {
      analysis.strength = 'medium';
    } else if (analysis.score >= 20) {
      analysis.strength = 'weak';
    } else {
      analysis.strength = 'very_weak';
    }

    // Add recommendations
    if (analysis.length < 12) {
      analysis.feedback.push('Use at least 12 characters');
    }
    if (!analysis.hasSpecial) {
      analysis.feedback.push('Add special characters');
    }
    if (!analysis.hasNumber) {
      analysis.feedback.push('Add numbers');
    }

    return analysis;
  }

  // ==================== PASSWORD GENERATION ====================
  
  generatePassword(options = {}) {
    const defaults = {
      length: 16,
      uppercase: true,
      lowercase: true,
      numbers: true,
      special: true,
      excludeSimilar: true, // Exclude i, l, 1, L, o, 0, O
      excludeAmbiguous: true // Exclude { } [ ] ( ) / \ ' " ` ~ , ; : . < >
    };

    const settings = { ...defaults, ...options };

    let chars = '';
    if (settings.lowercase) chars += 'abcdefghjkmnpqrstuvwxyz';
    if (settings.uppercase) chars += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    if (settings.numbers) chars += '23456789';
    if (settings.special) chars += '!@#$%^&*-_=+';

    if (settings.excludeSimilar) {
      chars = chars.replace(/[il1Lo0O]/g, '');
    }
    if (settings.excludeAmbiguous) {
      chars = chars.replace(/[{}[\]()/\\'"'`~,;:.<>]/g, '');
    }

    let password = '';
    const array = new Uint32Array(settings.length);
    window.crypto.getRandomValues(array);

    for (let i = 0; i < settings.length; i++) {
      password += chars[array[i] % chars.length];
    }

    // Ensure at least one of each required type
    if (settings.uppercase && !/[A-Z]/.test(password)) {
      password = password.substring(0, password.length - 1) + 'A';
    }
    if (settings.lowercase && !/[a-z]/.test(password)) {
      password = password.substring(0, password.length - 1) + 'a';
    }
    if (settings.numbers && !/\d/.test(password)) {
      password = password.substring(0, password.length - 1) + '2';
    }
    if (settings.special && !/[!@#$%^&*]/.test(password)) {
      password = password.substring(0, password.length - 1) + '!';
    }

    return password;
  }

  // ==================== BREACH MONITORING ====================
  
  loadBreachDatabase() {
    // Load known breached passwords (simplified for demo)
    this.breachDatabase = new Set([
      'password123',
      '12345678',
      'qwerty',
      'abc123',
      'password',
      'admin123',
      'letmein',
      'welcome'
    ]);
  }

  async checkPasswordBreach(password) {
    // Simple check against local database
    // In production, this would use Have I Been Pwned API
    
    // Check exact match
    if (this.breachDatabase.has(password.toLowerCase())) {
      return true;
    }

    // Check hash against HIBP (simulated)
    // const sha1Hash = CryptoJS.SHA1(password).toString();
    // const prefix = sha1Hash.substring(0, 5);
    // const suffix = sha1Hash.substring(5);
    // In production: Check HIBP k-Anonymity API

    return false;
  }

  async scanAllPasswordsForBreaches() {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const breached = [];
    
    for (const entry of this.vault.values()) {
      const decryptedPassword = this.decryptData(entry.encryptedPassword);
      const isBreached = await this.checkPasswordBreach(decryptedPassword);
      
      if (isBreached) {
        entry.breached = true;
        breached.push(entry);
      }
    }

    this.statistics.breachedPasswords = breached.length;
    this.statistics.lastBreachCheck = new Date().toISOString();
    this.saveVaultData();

    this.notifyListeners('breach-scan-complete', { count: breached.length, breached });

    if (breached.length > 0) {
      notificationService.show({
        type: 'error',
        title: '⚠️ Compromised Passwords Found',
        message: `${breached.length} password(s) found in data breaches`,
        duration: 0,
        actions: [
          {
            label: 'View Details',
            onClick: () => this.notifyListeners('show-breached-passwords', breached)
          }
        ]
      });
    }

    return { breachedCount: breached.length, breached };
  }

  // ==================== PASSWORD HEALTH ====================
  
  getPasswordHealth() {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const health = {
      totalPasswords: this.vault.size,
      weak: 0,
      reused: 0,
      breached: 0,
      old: 0, // > 90 days
      score: 100
    };

    const passwordValues = new Map(); // Track password reuse

    for (const entry of this.vault.values()) {
      // Check weakness
      if (entry.strength === 'weak' || entry.strength === 'very_weak') {
        health.weak++;
      }

      // Check breach
      if (entry.breached) {
        health.breached++;
      }

      // Check age
      const age = Date.now() - new Date(entry.createdAt).getTime();
      if (age > 90 * 24 * 60 * 60 * 1000) { // 90 days
        health.old++;
      }

      // Check reuse (simplified - would need to decrypt all)
      const pwd = entry.encryptedPassword;
      if (passwordValues.has(pwd)) {
        health.reused++;
      } else {
        passwordValues.set(pwd, 1);
      }
    }

    // Calculate health score
    health.score = 100;
    health.score -= (health.weak / health.totalPasswords) * 30;
    health.score -= (health.reused / health.totalPasswords) * 30;
    health.score -= (health.breached / health.totalPasswords) * 40;
    health.score = Math.max(0, Math.round(health.score));

    return health;
  }

  // ==================== ENCRYPTION/DECRYPTION ====================
  
  encryptData(plaintext) {
    if (!this.encryptionKey) {
      throw new Error('No encryption key available');
    }

    return CryptoJS.AES.encrypt(plaintext, this.encryptionKey).toString();
  }

  decryptData(ciphertext) {
    if (!this.encryptionKey) {
      throw new Error('No encryption key available');
    }

    const bytes = CryptoJS.AES.decrypt(ciphertext, this.encryptionKey);
    return bytes.toString(CryptoJS.enc.Utf8);
  }

  // ==================== DATA MANAGEMENT ====================
  
  updateStatistics() {
    let weak = 0;
    let breached = 0;
    const passwords = new Set();

    for (const entry of this.vault.values()) {
      if (entry.strength === 'weak' || entry.strength === 'very_weak') {
        weak++;
      }
      if (entry.breached) {
        breached++;
      }
      passwords.add(entry.encryptedPassword);
    }

    const reused = this.vault.size - passwords.size;

    this.statistics = {
      totalPasswords: this.vault.size,
      weakPasswords: weak,
      reusedPasswords: reused,
      breachedPasswords: breached,
      lastBreachCheck: this.statistics.lastBreachCheck
    };
  }

  getStatistics() {
    return { ...this.statistics };
  }

  saveVaultData() {
    try {
      const data = {
        vault: Array.from(this.vault.entries()),
        statistics: this.statistics
      };
      localStorage.setItem('password-manager-vault', JSON.stringify(data));
    } catch (error) {
      console.error('Failed to save vault data:', error);
    }
  }

  loadVaultData() {
    try {
      const stored = localStorage.getItem('password-manager-vault');
      if (stored) {
        const data = JSON.parse(stored);
        this.vault = new Map(data.vault);
        this.statistics = data.statistics || this.statistics;
      }

      const masterHash = localStorage.getItem('password-manager-master-hash');
      if (masterHash) {
        this.masterPasswordHash = masterHash;
      }
    } catch (error) {
      console.error('Failed to load vault data:', error);
    }
  }

  async exportVault(format = 'json') {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    const entries = [];
    for (const entry of this.vault.values()) {
      const decryptedPassword = this.decryptData(entry.encryptedPassword);
      entries.push({
        name: entry.name,
        username: entry.username,
        password: decryptedPassword,
        website: entry.website,
        notes: entry.notes,
        category: entry.category
      });
    }

    if (format === 'json') {
      return JSON.stringify(entries, null, 2);
    } else if (format === 'csv') {
      let csv = 'Name,Username,Password,Website,Category,Notes\n';
      entries.forEach(e => {
        csv += `"${e.name}","${e.username}","${e.password}","${e.website}","${e.category}","${e.notes}"\n`;
      });
      return csv;
    }

    return entries;
  }

  async importVault(data, format = 'json') {
    if (!this.isUnlocked) {
      throw new Error('Vault is locked. Please unlock first.');
    }

    let entries = [];
    
    if (format === 'json') {
      entries = JSON.parse(data);
    } else if (format === 'csv') {
      // Parse CSV (simplified)
      const lines = data.split('\n').slice(1); // Skip header
      entries = lines.map(line => {
        const parts = line.match(/(".*?"|[^,]+)(?=\s*,|\s*$)/g);
        return {
          name: parts[0]?.replace(/"/g, ''),
          username: parts[1]?.replace(/"/g, ''),
          password: parts[2]?.replace(/"/g, ''),
          website: parts[3]?.replace(/"/g, ''),
          category: parts[4]?.replace(/"/g, ''),
          notes: parts[5]?.replace(/"/g, '')
        };
      });
    }

    let imported = 0;
    for (const entry of entries) {
      if (entry.password) {
        await this.addPassword(entry);
        imported++;
      }
    }

    return { success: true, imported };
  }

  // ==================== EVENT LISTENERS ====================
  
  addListener(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  removeListener(callback) {
    this.listeners.delete(callback);
  }

  notifyListeners(event, data) {
    this.listeners.forEach(callback => {
      try {
        callback(event, data);
      } catch (error) {
        console.error('Listener error:', error);
      }
    });
  }

  // ==================== CLEANUP ====================
  
  destroy() {
    this.lock();
    this.listeners.clear();
  }
}

// Export singleton instance
const passwordManager = new PasswordManager();
export default passwordManager;
