/**
 * Enhanced JWT Security Manager
 * Implements token rotation, refresh tokens, and blacklisting
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class JWTSecurityManager {
    constructor() {
        this.accessTokenSecret = process.env.JWT_SECRET || this.generateSecureSecret();
        this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET || this.generateSecureSecret();
        this.accessTokenExpiry = process.env.JWT_ACCESS_EXPIRY || '15m';
        this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRY || '7d';
        
        this.dbPath = path.join(__dirname, '..', 'data', 'tokens.db');
        this.db = null;
        
        this.initializeDatabase();
    }

    /**
     * Generate secure random secret
     */
    generateSecureSecret(length = 64) {
        return crypto.randomBytes(length).toString('hex');
    }

    /**
     * Initialize token database
     */
    async initializeDatabase() {
        const fs = require('fs').promises;
        const dir = path.dirname(this.dbPath);
        
        try {
            await fs.mkdir(dir, { recursive: true });
        } catch (error) {
            console.error('Failed to create tokens directory:', error);
        }

        this.db = new sqlite3.Database(this.dbPath, (err) => {
            if (err) {
                console.error('Failed to open tokens database:', err);
                return;
            }
            console.log('✅ JWT tokens database connected');
        });

        // Token blacklist table
        const createBlacklistSQL = `
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_jti TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                token_type TEXT NOT NULL,
                revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                reason TEXT,
                revoked_by TEXT
            )
        `;

        // Refresh tokens table
        const createRefreshTokensSQL = `
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_jti TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                device_info TEXT,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                last_used DATETIME,
                is_active INTEGER DEFAULT 1
            )
        `;

        // Active sessions table
        const createSessionsSQL = `
            CREATE TABLE IF NOT EXISTS active_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                access_token_jti TEXT NOT NULL,
                refresh_token_jti TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL
            )
        `;

        this.db.run(createBlacklistSQL);
        this.db.run(createRefreshTokensSQL);
        this.db.run(createSessionsSQL);

        // Create indexes
        const indexes = [
            'CREATE INDEX IF NOT EXISTS idx_blacklist_jti ON token_blacklist(token_jti)',
            'CREATE INDEX IF NOT EXISTS idx_blacklist_user ON token_blacklist(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON token_blacklist(expires_at)',
            'CREATE INDEX IF NOT EXISTS idx_refresh_jti ON refresh_tokens(token_jti)',
            'CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_sessions_access ON active_sessions(access_token_jti)'
        ];

        indexes.forEach(indexSQL => this.db.run(indexSQL));

        // Clean up expired tokens periodically (every hour)
        setInterval(() => this.cleanupExpiredTokens(), 60 * 60 * 1000);
    }

    /**
     * Generate access and refresh token pair
     */
    async generateTokenPair(payload, deviceInfo = {}) {
        const accessTokenJTI = crypto.randomBytes(16).toString('hex');
        const refreshTokenJTI = crypto.randomBytes(16).toString('hex');
        const sessionId = crypto.randomBytes(32).toString('hex');

        // Create access token
        const accessToken = jwt.sign(
            {
                ...payload,
                jti: accessTokenJTI,
                type: 'access',
                sessionId
            },
            this.accessTokenSecret,
            {
                expiresIn: this.accessTokenExpiry,
                issuer: 'nebula-shield',
                audience: 'nebula-shield-app'
            }
        );

        // Create refresh token
        const refreshToken = jwt.sign(
            {
                userId: payload.userId,
                email: payload.email,
                jti: refreshTokenJTI,
                type: 'refresh',
                sessionId
            },
            this.refreshTokenSecret,
            {
                expiresIn: this.refreshTokenExpiry,
                issuer: 'nebula-shield',
                audience: 'nebula-shield-app'
            }
        );

        // Store refresh token in database
        const refreshTokenHash = crypto
            .createHash('sha256')
            .update(refreshToken)
            .digest('hex');

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

        await this.storeRefreshToken({
            tokenJTI: refreshTokenJTI,
            userId: payload.userId,
            tokenHash: refreshTokenHash,
            deviceInfo: JSON.stringify(deviceInfo),
            ipAddress: deviceInfo.ipAddress,
            expiresAt: expiresAt.toISOString()
        });

        // Create session record
        await this.createSession({
            sessionId,
            userId: payload.userId,
            accessTokenJTI,
            refreshTokenJTI,
            ipAddress: deviceInfo.ipAddress,
            userAgent: deviceInfo.userAgent,
            expiresAt: expiresAt.toISOString()
        });

        return {
            accessToken,
            refreshToken,
            sessionId,
            expiresIn: this.parseExpiry(this.accessTokenExpiry),
            refreshExpiresIn: this.parseExpiry(this.refreshTokenExpiry)
        };
    }

    /**
     * Verify access token
     */
    async verifyAccessToken(token) {
        try {
            const decoded = jwt.verify(token, this.accessTokenSecret, {
                issuer: 'nebula-shield',
                audience: 'nebula-shield-app'
            });

            // Check if token is blacklisted
            const isBlacklisted = await this.isTokenBlacklisted(decoded.jti);
            if (isBlacklisted) {
                throw new Error('Token has been revoked');
            }

            // Update session activity
            await this.updateSessionActivity(decoded.jti);

            return {
                valid: true,
                payload: decoded
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    /**
     * Verify refresh token
     */
    async verifyRefreshToken(token) {
        try {
            const decoded = jwt.verify(token, this.refreshTokenSecret, {
                issuer: 'nebula-shield',
                audience: 'nebula-shield-app'
            });

            // Check if token is blacklisted
            const isBlacklisted = await this.isTokenBlacklisted(decoded.jti);
            if (isBlacklisted) {
                throw new Error('Token has been revoked');
            }

            // Verify token exists in database and is active
            const tokenRecord = await this.getRefreshTokenRecord(decoded.jti);
            if (!tokenRecord || !tokenRecord.is_active) {
                throw new Error('Invalid refresh token');
            }

            // Verify token hash
            const tokenHash = crypto
                .createHash('sha256')
                .update(token)
                .digest('hex');

            if (tokenHash !== tokenRecord.token_hash) {
                throw new Error('Token hash mismatch');
            }

            // Update last used timestamp
            await this.updateRefreshTokenUsage(decoded.jti);

            return {
                valid: true,
                payload: decoded
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshAccessToken(refreshToken, deviceInfo = {}) {
        const verification = await this.verifyRefreshToken(refreshToken);
        
        if (!verification.valid) {
            throw new Error(verification.error);
        }

        const payload = verification.payload;

        // Generate new access token with same session
        const newAccessTokenJTI = crypto.randomBytes(16).toString('hex');

        const newAccessToken = jwt.sign(
            {
                userId: payload.userId,
                email: payload.email,
                tier: payload.tier,
                jti: newAccessTokenJTI,
                type: 'access',
                sessionId: payload.sessionId
            },
            this.accessTokenSecret,
            {
                expiresIn: this.accessTokenExpiry,
                issuer: 'nebula-shield',
                audience: 'nebula-shield-app'
            }
        );

        // Update session with new access token
        await this.updateSessionAccessToken(payload.sessionId, newAccessTokenJTI);

        return {
            accessToken: newAccessToken,
            expiresIn: this.parseExpiry(this.accessTokenExpiry)
        };
    }

    /**
     * Revoke token (add to blacklist)
     */
    async revokeToken(tokenJTI, reason = 'User logout', revokedBy = 'system') {
        return new Promise((resolve, reject) => {
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 30); // Keep in blacklist for 30 days

            const sql = `
                INSERT OR IGNORE INTO token_blacklist (token_jti, user_id, token_type, expires_at, reason, revoked_by)
                VALUES (?, ?, ?, ?, ?, ?)
            `;

            this.db.run(
                sql,
                [tokenJTI, 0, 'unknown', expiresAt.toISOString(), reason, revokedBy],
                (err) => {
                    if (err) {
                        console.error('Failed to revoke token:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Revoke all tokens for a user
     */
    async revokeAllUserTokens(userId, reason = 'Security policy') {
        // Get all active sessions
        const sessions = await this.getUserSessions(userId);

        // Revoke all tokens
        const promises = sessions.map(session => {
            return Promise.all([
                this.revokeToken(session.access_token_jti, reason),
                this.revokeToken(session.refresh_token_jti, reason)
            ]);
        });

        await Promise.all(promises);

        // Deactivate all refresh tokens
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE refresh_tokens SET is_active = 0 WHERE user_id = ?',
                [userId],
                (err) => {
                    if (err) {
                        console.error('Failed to deactivate refresh tokens:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Check if token is blacklisted
     */
    async isTokenBlacklisted(tokenJTI) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM token_blacklist WHERE token_jti = ? AND expires_at > ?',
                [tokenJTI, new Date().toISOString()],
                (err, row) => {
                    if (err) {
                        console.error('Failed to check token blacklist:', err);
                        return resolve(false);
                    }
                    resolve(!!row);
                }
            );
        });
    }

    /**
     * Store refresh token
     */
    storeRefreshToken(tokenData) {
        return new Promise((resolve, reject) => {
            const sql = `
                INSERT INTO refresh_tokens (token_jti, user_id, token_hash, device_info, ip_address, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            `;

            this.db.run(
                sql,
                [
                    tokenData.tokenJTI,
                    tokenData.userId,
                    tokenData.tokenHash,
                    tokenData.deviceInfo,
                    tokenData.ipAddress,
                    tokenData.expiresAt
                ],
                (err) => {
                    if (err) {
                        console.error('Failed to store refresh token:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Get refresh token record
     */
    getRefreshTokenRecord(tokenJTI) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM refresh_tokens WHERE token_jti = ?',
                [tokenJTI],
                (err, row) => {
                    if (err) {
                        console.error('Failed to get refresh token:', err);
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    /**
     * Update refresh token usage
     */
    updateRefreshTokenUsage(tokenJTI) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE refresh_tokens SET last_used = ? WHERE token_jti = ?',
                [new Date().toISOString(), tokenJTI],
                (err) => {
                    if (err) console.error('Failed to update token usage:', err);
                    resolve();
                }
            );
        });
    }

    /**
     * Create session record
     */
    createSession(sessionData) {
        return new Promise((resolve, reject) => {
            const sql = `
                INSERT INTO active_sessions (session_id, user_id, access_token_jti, refresh_token_jti, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `;

            this.db.run(
                sql,
                [
                    sessionData.sessionId,
                    sessionData.userId,
                    sessionData.accessTokenJTI,
                    sessionData.refreshTokenJTI,
                    sessionData.ipAddress,
                    sessionData.userAgent,
                    sessionData.expiresAt
                ],
                (err) => {
                    if (err) {
                        console.error('Failed to create session:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Update session activity
     */
    updateSessionActivity(accessTokenJTI) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE active_sessions SET last_activity = ? WHERE access_token_jti = ?',
                [new Date().toISOString(), accessTokenJTI],
                (err) => {
                    if (err) console.error('Failed to update session activity:', err);
                    resolve();
                }
            );
        });
    }

    /**
     * Update session access token
     */
    updateSessionAccessToken(sessionId, newAccessTokenJTI) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE active_sessions SET access_token_jti = ?, last_activity = ? WHERE session_id = ?',
                [newAccessTokenJTI, new Date().toISOString(), sessionId],
                (err) => {
                    if (err) {
                        console.error('Failed to update session access token:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Get user sessions
     */
    getUserSessions(userId) {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT * FROM active_sessions WHERE user_id = ? AND expires_at > ?',
                [userId, new Date().toISOString()],
                (err, rows) => {
                    if (err) {
                        console.error('Failed to get user sessions:', err);
                        reject(err);
                    } else {
                        resolve(rows || []);
                    }
                }
            );
        });
    }

    /**
     * Clean up expired tokens
     */
    async cleanupExpiredTokens() {
        const now = new Date().toISOString();

        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                this.db.run('DELETE FROM token_blacklist WHERE expires_at < ?', [now]);
                this.db.run('DELETE FROM refresh_tokens WHERE expires_at < ?', [now]);
                this.db.run('DELETE FROM active_sessions WHERE expires_at < ?', [now]);
                
                console.log('🧹 Cleaned up expired tokens');
                resolve();
            });
        });
    }

    /**
     * Parse expiry string to seconds
     */
    parseExpiry(expiryString) {
        const units = {
            's': 1,
            'm': 60,
            'h': 3600,
            'd': 86400
        };

        const match = expiryString.match(/^(\d+)([smhd])$/);
        if (!match) return 900; // Default 15 minutes

        const value = parseInt(match[1]);
        const unit = match[2];

        return value * units[unit];
    }

    /**
     * Create Express middleware
     */
    createMiddleware() {
        return async (req, res, next) => {
            const authHeader = req.headers.authorization;

            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    success: false,
                    message: 'Access token required'
                });
            }

            const token = authHeader.substring(7);

            const verification = await this.verifyAccessToken(token);

            if (!verification.valid) {
                return res.status(403).json({
                    success: false,
                    message: verification.error
                });
            }

            req.user = verification.payload;
            req.token = token;

            next();
        };
    }

    /**
     * Close database connection
     */
    close() {
        if (this.db) {
            this.db.close();
        }
    }
}

module.exports = new JWTSecurityManager();
