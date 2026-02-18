/**
 * Security Audit Logger
 * Tracks security-related events and suspicious activities
 */

const fs = require('fs').promises;
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

class SecurityAuditLogger {
    constructor() {
        this.dbPath = process.env.AUDIT_DB_PATH || path.join(__dirname, '..', 'data', 'security_audit.db');
        this.logDir = path.join(__dirname, '..', 'logs', 'security');
        this.db = null;
        
        this.eventTypes = {
            AUTH_SUCCESS: 'auth_success',
            AUTH_FAILURE: 'auth_failure',
            AUTH_LOCKED: 'auth_locked',
            TOKEN_CREATED: 'token_created',
            TOKEN_EXPIRED: 'token_expired',
            TOKEN_REVOKED: 'token_revoked',
            PASSWORD_CHANGED: 'password_changed',
            PASSWORD_RESET: 'password_reset',
            PRIVILEGE_ESCALATION: 'privilege_escalation',
            SUSPICIOUS_ACTIVITY: 'suspicious_activity',
            SQL_INJECTION_ATTEMPT: 'sql_injection_attempt',
            XSS_ATTEMPT: 'xss_attempt',
            COMMAND_INJECTION_ATTEMPT: 'command_injection_attempt',
            PATH_TRAVERSAL_ATTEMPT: 'path_traversal_attempt',
            RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
            UNAUTHORIZED_ACCESS: 'unauthorized_access',
            FILE_UPLOAD_REJECTED: 'file_upload_rejected',
            ACCOUNT_CREATED: 'account_created',
            ACCOUNT_DELETED: 'account_deleted',
            TWO_FACTOR_ENABLED: '2fa_enabled',
            TWO_FACTOR_DISABLED: '2fa_disabled',
            PAYMENT_INITIATED: 'payment_initiated',
            PAYMENT_COMPLETED: 'payment_completed',
            PAYMENT_FAILED: 'payment_failed',
            DATA_EXPORT: 'data_export',
            SETTINGS_CHANGED: 'settings_changed'
        };

        this.severityLevels = {
            INFO: 'info',
            WARNING: 'warning',
            ERROR: 'error',
            CRITICAL: 'critical'
        };

        this.initializeDatabase();
        this.initializeLogDirectory();
    }

    /**
     * Initialize SQLite database for audit logs
     */
    async initializeDatabase() {
        try {
            // Ensure data directory exists
            const dir = path.dirname(this.dbPath);
            await fs.mkdir(dir, { recursive: true });

            this.db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    console.error('Failed to open audit database:', err);
                    return;
                }
                console.log('✅ Security audit database connected');
            });

            // Create audit_logs table
            const createTableSQL = `
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id INTEGER,
                    username TEXT,
                    email TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    endpoint TEXT,
                    method TEXT,
                    status_code INTEGER,
                    message TEXT,
                    details TEXT,
                    threat_type TEXT,
                    action_taken TEXT,
                    session_id TEXT,
                    request_id TEXT
                )
            `;

            this.db.run(createTableSQL, (err) => {
                if (err) {
                    console.error('Failed to create audit_logs table:', err);
                } else {
                    console.log('✅ Audit logs table ready');
                }
            });

            // Create indexes for better performance
            const indexes = [
                'CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type)',
                'CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_logs(severity)',
                'CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id)',
                'CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_logs(ip_address)',
                'CREATE INDEX IF NOT EXISTS idx_audit_threat ON audit_logs(threat_type)'
            ];

            indexes.forEach(indexSQL => {
                this.db.run(indexSQL, (err) => {
                    if (err) console.error('Index creation error:', err);
                });
            });

            // Create suspicious_ips table for tracking
            const createSuspiciousIPsSQL = `
                CREATE TABLE IF NOT EXISTS suspicious_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    incident_count INTEGER DEFAULT 1,
                    threat_level TEXT DEFAULT 'low',
                    is_blocked INTEGER DEFAULT 0,
                    blocked_until DATETIME,
                    reason TEXT,
                    country TEXT,
                    asn TEXT
                )
            `;

            this.db.run(createSuspiciousIPsSQL);

        } catch (error) {
            console.error('Database initialization error:', error);
        }
    }

    /**
     * Initialize log directory for file-based logs
     */
    async initializeLogDirectory() {
        try {
            await fs.mkdir(this.logDir, { recursive: true });
        } catch (error) {
            console.error('Failed to create log directory:', error);
        }
    }

    /**
     * Log security event
     */
    async log(eventData) {
        const {
            eventType,
            severity = this.severityLevels.INFO,
            userId = null,
            username = null,
            email = null,
            ipAddress = null,
            userAgent = null,
            endpoint = null,
            method = null,
            statusCode = null,
            message = '',
            details = {},
            threatType = null,
            actionTaken = null,
            sessionId = null,
            requestId = null
        } = eventData;

        const logEntry = {
            timestamp: new Date().toISOString(),
            event_type: eventType,
            severity,
            user_id: userId,
            username,
            email,
            ip_address: ipAddress,
            user_agent: userAgent,
            endpoint,
            method,
            status_code: statusCode,
            message,
            details: JSON.stringify(details),
            threat_type: threatType,
            action_taken: actionTaken,
            session_id: sessionId,
            request_id: requestId
        };

        // Log to database
        await this.logToDatabase(logEntry);

        // Log to file for critical events
        if (severity === this.severityLevels.CRITICAL || severity === this.severityLevels.ERROR) {
            await this.logToFile(logEntry);
        }

        // Track suspicious IPs
        if (threatType && ipAddress) {
            await this.trackSuspiciousIP(ipAddress, threatType, severity);
        }

        // Console output for visibility
        this.logToConsole(logEntry);
    }

    /**
     * Log to SQLite database
     */
    logToDatabase(logEntry) {
        return new Promise((resolve, reject) => {
            if (!this.db) {
                console.error('Database not initialized');
                return reject(new Error('Database not initialized'));
            }

            const sql = `
                INSERT INTO audit_logs (
                    timestamp, event_type, severity, user_id, username, email,
                    ip_address, user_agent, endpoint, method, status_code,
                    message, details, threat_type, action_taken, session_id, request_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;

            const values = [
                logEntry.timestamp,
                logEntry.event_type,
                logEntry.severity,
                logEntry.user_id,
                logEntry.username,
                logEntry.email,
                logEntry.ip_address,
                logEntry.user_agent,
                logEntry.endpoint,
                logEntry.method,
                logEntry.status_code,
                logEntry.message,
                logEntry.details,
                logEntry.threat_type,
                logEntry.action_taken,
                logEntry.session_id,
                logEntry.request_id
            ];

            this.db.run(sql, values, (err) => {
                if (err) {
                    console.error('Failed to log to database:', err);
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    /**
     * Log to file (for critical events)
     */
    async logToFile(logEntry) {
        try {
            const date = new Date().toISOString().split('T')[0];
            const fileName = `security_audit_${date}.log`;
            const filePath = path.join(this.logDir, fileName);

            const logLine = `[${logEntry.timestamp}] [${logEntry.severity.toUpperCase()}] ${logEntry.event_type} - ${logEntry.message}\n` +
                           `  IP: ${logEntry.ip_address || 'N/A'} | User: ${logEntry.username || 'N/A'} | Endpoint: ${logEntry.endpoint || 'N/A'}\n` +
                           `  Details: ${logEntry.details}\n\n`;

            await fs.appendFile(filePath, logLine, 'utf8');
        } catch (error) {
            console.error('Failed to write to log file:', error);
        }
    }

    /**
     * Log to console with color coding
     */
    logToConsole(logEntry) {
        const colors = {
            info: '\x1b[36m',      // Cyan
            warning: '\x1b[33m',   // Yellow
            error: '\x1b[31m',     // Red
            critical: '\x1b[35m'   // Magenta
        };
        const reset = '\x1b[0m';

        const color = colors[logEntry.severity] || colors.info;
        const prefix = logEntry.threat_type ? '🚨' : '🔒';

        console.log(
            `${prefix} ${color}[${logEntry.severity.toUpperCase()}]${reset} ${logEntry.event_type} - ${logEntry.message}`,
            logEntry.ip_address ? `(IP: ${logEntry.ip_address})` : ''
        );
    }

    /**
     * Track suspicious IP addresses
     */
    async trackSuspiciousIP(ipAddress, threatType, severity) {
        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('Database not initialized'));

            // Check if IP exists
            this.db.get(
                'SELECT * FROM suspicious_ips WHERE ip_address = ?',
                [ipAddress],
                (err, row) => {
                    if (err) {
                        console.error('Failed to check suspicious IP:', err);
                        return reject(err);
                    }

                    if (row) {
                        // Update existing record
                        const newCount = row.incident_count + 1;
                        const threatLevel = this.calculateThreatLevel(newCount, severity);
                        const shouldBlock = newCount >= 5 || severity === this.severityLevels.CRITICAL;

                        this.db.run(
                            `UPDATE suspicious_ips 
                             SET last_seen = ?, incident_count = ?, threat_level = ?, 
                                 is_blocked = ?, blocked_until = ?, reason = ?
                             WHERE ip_address = ?`,
                            [
                                new Date().toISOString(),
                                newCount,
                                threatLevel,
                                shouldBlock ? 1 : 0,
                                shouldBlock ? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() : null,
                                `${threatType} (${newCount} incidents)`,
                                ipAddress
                            ],
                            (err) => {
                                if (err) console.error('Failed to update suspicious IP:', err);
                                resolve();
                            }
                        );
                    } else {
                        // Insert new record
                        this.db.run(
                            `INSERT INTO suspicious_ips (ip_address, threat_level, reason)
                             VALUES (?, ?, ?)`,
                            [ipAddress, 'low', threatType],
                            (err) => {
                                if (err) console.error('Failed to insert suspicious IP:', err);
                                resolve();
                            }
                        );
                    }
                }
            );
        });
    }

    /**
     * Calculate threat level based on incidents
     */
    calculateThreatLevel(incidentCount, severity) {
        if (incidentCount >= 10 || severity === this.severityLevels.CRITICAL) {
            return 'critical';
        } else if (incidentCount >= 5 || severity === this.severityLevels.ERROR) {
            return 'high';
        } else if (incidentCount >= 3 || severity === this.severityLevels.WARNING) {
            return 'medium';
        }
        return 'low';
    }

    /**
     * Check if IP is blocked
     */
    async isIPBlocked(ipAddress) {
        return new Promise((resolve, reject) => {
            if (!this.db) return resolve(false);

            this.db.get(
                `SELECT * FROM suspicious_ips 
                 WHERE ip_address = ? AND is_blocked = 1 
                 AND (blocked_until IS NULL OR blocked_until > ?)`,
                [ipAddress, new Date().toISOString()],
                (err, row) => {
                    if (err) {
                        console.error('Failed to check IP block status:', err);
                        return resolve(false);
                    }
                    resolve(!!row);
                }
            );
        });
    }

    /**
     * Get audit logs with filters
     */
    async getAuditLogs(filters = {}) {
        const {
            startDate = null,
            endDate = null,
            eventType = null,
            severity = null,
            userId = null,
            ipAddress = null,
            limit = 100,
            offset = 0
        } = filters;

        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('Database not initialized'));

            let sql = 'SELECT * FROM audit_logs WHERE 1=1';
            const params = [];

            if (startDate) {
                sql += ' AND timestamp >= ?';
                params.push(startDate);
            }

            if (endDate) {
                sql += ' AND timestamp <= ?';
                params.push(endDate);
            }

            if (eventType) {
                sql += ' AND event_type = ?';
                params.push(eventType);
            }

            if (severity) {
                sql += ' AND severity = ?';
                params.push(severity);
            }

            if (userId) {
                sql += ' AND user_id = ?';
                params.push(userId);
            }

            if (ipAddress) {
                sql += ' AND ip_address = ?';
                params.push(ipAddress);
            }

            sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
            params.push(limit, offset);

            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    console.error('Failed to retrieve audit logs:', err);
                    return reject(err);
                }
                resolve(rows);
            });
        });
    }

    /**
     * Get suspicious IPs
     */
    async getSuspiciousIPs(filters = {}) {
        const { threatLevel = null, isBlocked = null, limit = 100 } = filters;

        return new Promise((resolve, reject) => {
            if (!this.db) return reject(new Error('Database not initialized'));

            let sql = 'SELECT * FROM suspicious_ips WHERE 1=1';
            const params = [];

            if (threatLevel) {
                sql += ' AND threat_level = ?';
                params.push(threatLevel);
            }

            if (isBlocked !== null) {
                sql += ' AND is_blocked = ?';
                params.push(isBlocked ? 1 : 0);
            }

            sql += ' ORDER BY incident_count DESC, last_seen DESC LIMIT ?';
            params.push(limit);

            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    console.error('Failed to retrieve suspicious IPs:', err);
                    return reject(err);
                }
                resolve(rows);
            });
        });
    }

    /**
     * Create Express middleware for automatic audit logging
     */
    createMiddleware() {
        return async (req, res, next) => {
            const startTime = Date.now();

            // Capture response
            const originalSend = res.send;
            res.send = function(data) {
                res.send = originalSend;
                
                // Log the request/response
                const duration = Date.now() - startTime;
                
                // Determine if this should be logged based on status code
                if (res.statusCode >= 400 || req.path.includes('/auth/')) {
                    const eventType = res.statusCode >= 400 
                        ? 'unauthorized_access' 
                        : req.method === 'POST' ? 'auth_success' : 'api_access';

                    const severity = res.statusCode >= 500 
                        ? 'error' 
                        : res.statusCode >= 400 
                        ? 'warning' 
                        : 'info';

                    this.log({
                        eventType,
                        severity,
                        userId: req.user?.userId || null,
                        username: req.user?.email || null,
                        ipAddress: req.ip || req.connection.remoteAddress,
                        userAgent: req.get('user-agent'),
                        endpoint: req.path,
                        method: req.method,
                        statusCode: res.statusCode,
                        message: `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`,
                        details: {
                            duration,
                            query: req.query,
                            bodyKeys: req.body ? Object.keys(req.body) : []
                        }
                    }).catch(err => console.error('Audit log error:', err));
                }

                return originalSend.call(this, data);
            }.bind(this);

            next();
        };
    }

    /**
     * Close database connection
     */
    close() {
        if (this.db) {
            this.db.close((err) => {
                if (err) {
                    console.error('Error closing audit database:', err);
                } else {
                    console.log('Audit database closed');
                }
            });
        }
    }
}

module.exports = new SecurityAuditLogger();
