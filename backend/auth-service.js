/**
 * Authentication Service with 2FA Support
 * Handles user authentication, session management, and two-factor authentication
 */

const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

class AuthService {
  constructor() {
    this.users = new Map(); // In production, use database
    this.sessions = new Map();
    this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
    this.maxSessions = 5; // Max concurrent sessions per user
    
    // Note: Demo accounts removed for production security
    // Use database-based authentication in auth-server.js instead
  }

  /**
   * Initialize demo user for testing - REMOVED FOR PRODUCTION
   * Demo accounts have been removed for security.
   * Use the database-based authentication in auth-server.js instead.
   * Create admin accounts through secure registration process.
   */
  // Former demo account initialization removed for production security

  /**
   * Hash password using SHA-256
   */
  hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  /**
   * Generate secure session token
   */
  generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Authenticate user with credentials
   */
  async authenticate(email, password) {
    const user = this.users.get(email);
    
    if (!user) {
      return {
        success: false,
        error: 'Invalid credentials'
      };
    }

    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockedUntil - Date.now()) / 60000);
      return {
        success: false,
        error: `Account locked. Try again in ${minutesLeft} minutes`,
        locked: true
      };
    }

    // Verify password
    const hashedPassword = this.hashPassword(password);
    console.log('🔐 Login attempt:', { email, providedHash: hashedPassword.substring(0, 20) + '...', storedHash: user.password.substring(0, 20) + '...', match: hashedPassword === user.password });
    if (hashedPassword !== user.password) {
      user.failedAttempts++;
      
      // Lock account after 5 failed attempts
      if (user.failedAttempts >= 5) {
        user.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 minutes
        return {
          success: false,
          error: 'Too many failed attempts. Account locked for 15 minutes',
          locked: true
        };
      }

      return {
        success: false,
        error: 'Invalid credentials',
        attemptsLeft: 5 - user.failedAttempts
      };
    }

    // Reset failed attempts
    user.failedAttempts = 0;
    user.lockedUntil = null;

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      return {
        success: true,
        requiresTwoFactor: true,
        userId: user.id,
        email: user.email
      };
    }

    // Create session
    return this.createSession(user);
  }

  /**
   * Verify 2FA token
   */
  async verifyTwoFactor(email, token) {
    const user = this.users.get(email);
    
    if (!user || !user.twoFactorEnabled) {
      return {
        success: false,
        error: '2FA not enabled for this account'
      };
    }

    // Verify TOTP token
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow 2 time steps before/after
    });

    if (!verified) {
      return {
        success: false,
        error: 'Invalid 2FA code'
      };
    }

    // Create session
    return this.createSession(user);
  }

  /**
   * Create user session
   */
  createSession(user) {
    const sessionToken = this.generateSessionToken();
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    const session = {
      id: sessionId,
      token: sessionToken,
      userId: user.id,
      email: user.email,
      username: user.username,
      fullName: user.fullName || user.username,
      role: user.role || 'user',
      tier: user.tier || 'free',
      verified: user.verified !== undefined ? user.verified : true,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.sessionTimeout,
      ipAddress: null, // Set by API
      userAgent: null, // Set by API
      lastActivity: Date.now()
    };

    // Clean up old sessions if exceeding max
    this.cleanupUserSessions(user.id);

    this.sessions.set(sessionToken, session);
    user.lastLogin = new Date();

    return {
      success: true,
      sessionToken: sessionToken,
      sessionId: sessionId,
      expiresAt: session.expiresAt,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        fullName: user.fullName || user.username,
        role: user.role || 'user',
        tier: user.tier || 'free',
        twoFactorEnabled: user.twoFactorEnabled,
        verified: user.verified !== undefined ? user.verified : true
      }
    };
  }

  /**
   * Validate session token
   */
  validateSession(token) {
    const session = this.sessions.get(token);
    
    if (!session) {
      return {
        valid: false,
        error: 'Invalid session'
      };
    }

    // Check if session expired
    if (session.expiresAt < Date.now()) {
      this.sessions.delete(token);
      return {
        valid: false,
        error: 'Session expired'
      };
    }

    // Update last activity and extend session
    session.lastActivity = Date.now();
    session.expiresAt = Date.now() + this.sessionTimeout;

    return {
      valid: true,
      session: session
    };
  }

  /**
   * Logout and destroy session
   */
  logout(token) {
    const session = this.sessions.get(token);
    
    if (session) {
      this.sessions.delete(token);
      return {
        success: true,
        message: 'Logged out successfully'
      };
    }

    return {
      success: false,
      error: 'Session not found'
    };
  }

  /**
   * Verify token and return session data
   * Used for token-based authentication verification
   */
  verifyToken(token) {
    const session = this.sessions.get(token);
    
    if (!session) {
      return null;
    }

    // Check if session expired
    if (session.expiresAt < Date.now()) {
      this.sessions.delete(token);
      return null;
    }

    // Update last activity and extend session
    session.lastActivity = Date.now();
    session.expiresAt = Date.now() + this.sessionTimeout;

    return session;
  }

  /**
   * Enable 2FA for user
   */
  async enableTwoFactor(email) {
    const user = this.users.get(email);
    
    if (!user) {
      return {
        success: false,
        error: 'User not found'
      };
    }

    if (user.twoFactorEnabled) {
      return {
        success: false,
        error: '2FA already enabled'
      };
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Nebula Shield (${email})`,
      issuer: 'Nebula Shield Anti-Virus'
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Store secret temporarily (will be confirmed later)
    user.twoFactorSecretTemp = secret.base32;

    return {
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntry: secret.otpauth_url
    };
  }

  /**
   * Confirm and activate 2FA
   */
  async confirmTwoFactor(email, token) {
    const user = this.users.get(email);
    
    if (!user || !user.twoFactorSecretTemp) {
      return {
        success: false,
        error: 'No pending 2FA setup'
      };
    }

    // Verify token with temporary secret
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecretTemp,
      encoding: 'base32',
      token: token,
      window: 2
    });

    if (!verified) {
      return {
        success: false,
        error: 'Invalid verification code'
      };
    }

    // Activate 2FA
    user.twoFactorEnabled = true;
    user.twoFactorSecret = user.twoFactorSecretTemp;
    delete user.twoFactorSecretTemp;

    // Generate backup codes
    const backupCodes = this.generateBackupCodes();
    user.backupCodes = backupCodes.map(code => this.hashPassword(code));

    return {
      success: true,
      message: '2FA enabled successfully',
      backupCodes: backupCodes
    };
  }

  /**
   * Disable 2FA
   */
  async disableTwoFactor(email, password) {
    const user = this.users.get(email);
    
    if (!user) {
      return {
        success: false,
        error: 'User not found'
      };
    }

    // Verify password
    const hashedPassword = this.hashPassword(password);
    if (hashedPassword !== user.password) {
      return {
        success: false,
        error: 'Invalid password'
      };
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    user.backupCodes = null;

    return {
      success: true,
      message: '2FA disabled successfully'
    };
  }

  /**
   * Generate backup codes for 2FA
   */
  generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(code);
    }
    return codes;
  }

  /**
   * Get all active sessions for a user
   */
  getUserSessions(userId) {
    const userSessions = [];
    
    for (const [token, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        userSessions.push({
          id: session.id,
          createdAt: new Date(session.createdAt),
          expiresAt: new Date(session.expiresAt),
          lastActivity: new Date(session.lastActivity),
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          current: false // Will be set by API
        });
      }
    }

    return userSessions.sort((a, b) => b.lastActivity - a.lastActivity);
  }

  /**
   * Revoke specific session
   */
  revokeSession(userId, sessionId) {
    for (const [token, session] of this.sessions.entries()) {
      if (session.userId === userId && session.id === sessionId) {
        this.sessions.delete(token);
        return {
          success: true,
          message: 'Session revoked'
        };
      }
    }

    return {
      success: false,
      error: 'Session not found'
    };
  }

  /**
   * Revoke all sessions except current
   */
  revokeAllSessions(userId, exceptToken) {
    let revoked = 0;
    
    for (const [token, session] of this.sessions.entries()) {
      if (session.userId === userId && token !== exceptToken) {
        this.sessions.delete(token);
        revoked++;
      }
    }

    return {
      success: true,
      message: `Revoked ${revoked} session(s)`,
      count: revoked
    };
  }

  /**
   * Clean up expired sessions
   */
  cleanupExpiredSessions() {
    const now = Date.now();
    let cleaned = 0;

    for (const [token, session] of this.sessions.entries()) {
      if (session.expiresAt < now) {
        this.sessions.delete(token);
        cleaned++;
      }
    }

    return cleaned;
  }

  /**
   * Clean up old sessions for user (keep only most recent)
   */
  cleanupUserSessions(userId) {
    const userSessions = [];
    
    for (const [token, session] of this.sessions.entries()) {
      if (session.userId === userId) {
        userSessions.push({ token, session });
      }
    }

    // Sort by creation time
    userSessions.sort((a, b) => b.session.createdAt - a.session.createdAt);

    // Remove excess sessions
    if (userSessions.length >= this.maxSessions) {
      const toRemove = userSessions.slice(this.maxSessions - 1);
      toRemove.forEach(({ token }) => this.sessions.delete(token));
    }
  }

  /**
   * Change password
   */
  async changePassword(email, currentPassword, newPassword) {
    const user = this.users.get(email);
    
    if (!user) {
      return {
        success: false,
        error: 'User not found'
      };
    }

    // Verify current password
    const hashedPassword = this.hashPassword(currentPassword);
    if (hashedPassword !== user.password) {
      return {
        success: false,
        error: 'Current password is incorrect'
      };
    }

    // Update password
    user.password = this.hashPassword(newPassword);

    // Revoke all sessions (force re-login)
    this.revokeAllSessions(user.id);

    return {
      success: true,
      message: 'Password changed successfully. Please login again.'
    };
  }

  /**
   * Get user info
   */
  getUserInfo(email) {
    const user = this.users.get(email);
    
    if (!user) {
      return null;
    }

    return {
      id: user.id,
      email: user.email,
      username: user.username,
      twoFactorEnabled: user.twoFactorEnabled,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin
    };
  }

  /**
   * Reset all users' 2FA (Admin only)
   */
  resetAll2FA() {
    let count = 0;
    for (const [email, user] of this.users.entries()) {
      if (user.twoFactorEnabled) {
        user.twoFactorEnabled = false;
        user.twoFactorSecret = null;
        user.twoFactorSecretTemp = null;
        count++;
      }
    }
    console.log(`🔓 Reset 2FA for ${count} user(s)`);
    return {
      success: true,
      message: `Reset 2FA for ${count} user(s)`,
      count: count
    };
  }

  /**
   * Reset specific user's 2FA (Admin only)
   */
  reset2FAForUser(email) {
    const user = this.users.get(email);
    
    if (!user) {
      return {
        success: false,
        error: 'User not found'
      };
    }

    if (user.twoFactorEnabled) {
      user.twoFactorEnabled = false;
      user.twoFactorSecret = null;
      user.twoFactorSecretTemp = null;
      console.log(`🔓 Reset 2FA for user: ${email}`);
      return {
        success: true,
        message: `2FA reset for ${email}`
      };
    } else {
      return {
        success: true,
        message: `User ${email} did not have 2FA enabled`
      };
    }
  }
}

// Singleton instance
const authService = new AuthService();

// Cleanup expired sessions every 5 minutes
setInterval(() => {
  const cleaned = authService.cleanupExpiredSessions();
  if (cleaned > 0) {
    console.log(`🧹 Cleaned up ${cleaned} expired session(s)`);
  }
}, 5 * 60 * 1000);

module.exports = authService;
