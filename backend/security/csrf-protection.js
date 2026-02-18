/**
 * CSRF Protection Module
 * Implements Cross-Site Request Forgery protection with token-based validation
 */

const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class CSRFProtection {
    constructor() {
        this.dbPath = path.join(__dirname, '..', 'data', 'csrf_tokens.db');
        this.db = null;
        this.tokenExpiry = 3600000; // 1 hour in milliseconds
        this.tokenLength = 32;
        
        this.initializeDatabase();
        
        // Clean up expired tokens every 10 minutes
        setInterval(() => this.cleanupExpiredTokens(), 10 * 60 * 1000);
    }

    /**
     * Initialize CSRF tokens database
     */
    async initializeDatabase() {
        const fs = require('fs').promises;
        const dir = path.dirname(this.dbPath);
        
        try {
            await fs.mkdir(dir, { recursive: true });
        } catch (error) {
            console.error('Failed to create CSRF tokens directory:', error);
        }

        this.db = new sqlite3.Database(this.dbPath, (err) => {
            if (err) {
                console.error('Failed to open CSRF database:', err);
                return;
            }
            console.log('✅ CSRF protection database connected');
        });

        const createTableSQL = `
            CREATE TABLE IF NOT EXISTS csrf_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                session_id TEXT NOT NULL,
                user_id INTEGER,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used INTEGER DEFAULT 0,
                used_at DATETIME
            )
        `;

        this.db.run(createTableSQL, (err) => {
            if (err) {
                console.error('Failed to create CSRF tokens table:', err);
            } else {
                console.log('✅ CSRF tokens table ready');
            }
        });

        // Create indexes
        const indexes = [
            'CREATE INDEX IF NOT EXISTS idx_csrf_token ON csrf_tokens(token)',
            'CREATE INDEX IF NOT EXISTS idx_csrf_session ON csrf_tokens(session_id)',
            'CREATE INDEX IF NOT EXISTS idx_csrf_expires ON csrf_tokens(expires_at)'
        ];

        indexes.forEach(indexSQL => this.db.run(indexSQL));
    }

    /**
     * Generate CSRF token
     */
    async generateToken(sessionId, userId = null, ipAddress = null) {
        return new Promise((resolve, reject) => {
            // Generate random token
            const token = crypto.randomBytes(this.tokenLength).toString('hex');
            
            // Calculate expiry
            const expiresAt = new Date(Date.now() + this.tokenExpiry);

            const sql = `
                INSERT INTO csrf_tokens (token, session_id, user_id, ip_address, expires_at)
                VALUES (?, ?, ?, ?, ?)
            `;

            this.db.run(
                sql,
                [token, sessionId, userId, ipAddress, expiresAt.toISOString()],
                (err) => {
                    if (err) {
                        console.error('Failed to generate CSRF token:', err);
                        reject(err);
                    } else {
                        resolve(token);
                    }
                }
            );
        });
    }

    /**
     * Validate CSRF token
     */
    async validateToken(token, sessionId, ipAddress = null) {
        return new Promise((resolve, reject) => {
            if (!token || !sessionId) {
                return resolve({
                    valid: false,
                    reason: 'Missing token or session ID'
                });
            }

            const sql = `
                SELECT * FROM csrf_tokens 
                WHERE token = ? 
                AND session_id = ? 
                AND expires_at > ? 
                AND used = 0
            `;

            this.db.get(
                sql,
                [token, sessionId, new Date().toISOString()],
                (err, row) => {
                    if (err) {
                        console.error('Failed to validate CSRF token:', err);
                        return reject(err);
                    }

                    if (!row) {
                        return resolve({
                            valid: false,
                            reason: 'Invalid, expired, or already used token'
                        });
                    }

                    // Optional: Check IP address if provided
                    if (ipAddress && row.ip_address && row.ip_address !== ipAddress) {
                        return resolve({
                            valid: false,
                            reason: 'IP address mismatch'
                        });
                    }

                    // Mark token as used
                    this.markTokenUsed(token).catch(console.error);

                    resolve({
                        valid: true,
                        tokenData: row
                    });
                }
            );
        });
    }

    /**
     * Mark token as used (optional single-use tokens)
     */
    markTokenUsed(token) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE csrf_tokens SET used = 1, used_at = ? WHERE token = ?',
                [new Date().toISOString(), token],
                (err) => {
                    if (err) {
                        console.error('Failed to mark token as used:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Revoke all tokens for a session
     */
    async revokeSessionTokens(sessionId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM csrf_tokens WHERE session_id = ?',
                [sessionId],
                (err) => {
                    if (err) {
                        console.error('Failed to revoke session tokens:', err);
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
    async revokeUserTokens(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM csrf_tokens WHERE user_id = ?',
                [userId],
                (err) => {
                    if (err) {
                        console.error('Failed to revoke user tokens:', err);
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Clean up expired tokens
     */
    async cleanupExpiredTokens() {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM csrf_tokens WHERE expires_at < ?',
                [new Date().toISOString()],
                (err) => {
                    if (err) {
                        console.error('Failed to cleanup expired CSRF tokens:', err);
                        reject(err);
                    } else {
                        console.log('🧹 Cleaned up expired CSRF tokens');
                        resolve();
                    }
                }
            );
        });
    }

    /**
     * Get session ID from request
     */
    getSessionId(req) {
        // Try to get session ID from:
        // 1. Session middleware
        if (req.session && req.session.id) {
            return req.session.id;
        }

        // 2. JWT token
        if (req.user && req.user.sessionId) {
            return req.user.sessionId;
        }

        // 3. Cookie
        if (req.cookies && req.cookies.sessionId) {
            return req.cookies.sessionId;
        }

        // 4. Generate temporary session ID from IP + User-Agent
        const crypto = require('crypto');
        const identifier = `${req.ip}-${req.get('user-agent')}`;
        return crypto.createHash('sha256').update(identifier).digest('hex');
    }

    /**
     * Create Express middleware for token generation
     */
    createGenerateMiddleware() {
        return async (req, res, next) => {
            try {
                const sessionId = this.getSessionId(req);
                const userId = req.user ? req.user.userId : null;
                const ipAddress = req.ip || req.connection.remoteAddress;

                // Generate CSRF token
                const csrfToken = await this.generateToken(sessionId, userId, ipAddress);

                // Attach token to request object
                req.csrfToken = csrfToken;

                // Optionally set as cookie
                res.cookie('XSRF-TOKEN', csrfToken, {
                    httpOnly: false, // Must be false so client-side JS can read it
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: this.tokenExpiry
                });

                next();
            } catch (error) {
                console.error('CSRF token generation error:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to generate CSRF token'
                });
            }
        };
    }

    /**
     * Create Express middleware for token validation
     */
    createValidateMiddleware(options = {}) {
        const {
            ignoreMethods = ['GET', 'HEAD', 'OPTIONS'],
            tokenHeader = 'x-csrf-token',
            tokenBody = 'csrfToken',
            tokenQuery = '_csrf',
            validateIP = false
        } = options;

        return async (req, res, next) => {
            // Skip validation for safe methods
            if (ignoreMethods.includes(req.method)) {
                return next();
            }

            try {
                const sessionId = this.getSessionId(req);
                const ipAddress = validateIP ? (req.ip || req.connection.remoteAddress) : null;

                // Get token from various sources
                const token = 
                    req.headers[tokenHeader] ||
                    req.body[tokenBody] ||
                    req.query[tokenQuery] ||
                    req.cookies['XSRF-TOKEN'];

                if (!token) {
                    console.warn('[CSRF] Missing token:', {
                        method: req.method,
                        path: req.path,
                        ip: req.ip
                    });

                    return res.status(403).json({
                        success: false,
                        message: 'CSRF token missing',
                        code: 'CSRF_MISSING'
                    });
                }

                // Validate token
                const validation = await this.validateToken(token, sessionId, ipAddress);

                if (!validation.valid) {
                    console.warn('[CSRF] Invalid token:', {
                        method: req.method,
                        path: req.path,
                        ip: req.ip,
                        reason: validation.reason
                    });

                    return res.status(403).json({
                        success: false,
                        message: 'Invalid CSRF token',
                        reason: validation.reason,
                        code: 'CSRF_INVALID'
                    });
                }

                // Token is valid, proceed
                next();
            } catch (error) {
                console.error('CSRF validation error:', error);
                res.status(500).json({
                    success: false,
                    message: 'CSRF validation failed'
                });
            }
        };
    }

    /**
     * Create combined middleware (generate on GET, validate on POST/PUT/DELETE)
     */
    createMiddleware(options = {}) {
        const generateMiddleware = this.createGenerateMiddleware();
        const validateMiddleware = this.createValidateMiddleware(options);

        return (req, res, next) => {
            const safeMethods = options.ignoreMethods || ['GET', 'HEAD', 'OPTIONS'];

            if (safeMethods.includes(req.method)) {
                // Generate token for safe methods
                return generateMiddleware(req, res, next);
            } else {
                // Validate token for unsafe methods
                return validateMiddleware(req, res, next);
            }
        };
    }

    /**
     * Get CSRF token for frontend
     */
    createTokenEndpoint() {
        return async (req, res) => {
            try {
                const sessionId = this.getSessionId(req);
                const userId = req.user ? req.user.userId : null;
                const ipAddress = req.ip || req.connection.remoteAddress;

                const token = await this.generateToken(sessionId, userId, ipAddress);

                res.json({
                    success: true,
                    csrfToken: token,
                    expiresIn: this.tokenExpiry
                });
            } catch (error) {
                console.error('Failed to generate CSRF token endpoint:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to generate CSRF token'
                });
            }
        };
    }

    /**
     * Close database connection
     */
    close() {
        if (this.db) {
            this.db.close((err) => {
                if (err) {
                    console.error('Error closing CSRF database:', err);
                } else {
                    console.log('CSRF database closed');
                }
            });
        }
    }
}

module.exports = new CSRFProtection();
