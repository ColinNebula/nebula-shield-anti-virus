/**
 * Advanced Input Sanitization and Validation Module
 * Provides comprehensive protection against injection attacks
 */

const validator = require('validator');
const path = require('path');

class InputSanitizer {
    constructor() {
        this.sqlInjectionPatterns = [
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/gi,
            /(--|\*\/|\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)/gi,
            /(\bxp_cmdshell\b|\bsp_executesql\b)/gi,
            /(;.*?(DROP|DELETE|TRUNCATE|ALTER))/gi
        ];

        this.xssPatterns = [
            /<script[^>]*>[\s\S]*?<\/script>/gi,
            /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
            /javascript:/gi,
            /on\w+\s*=\s*["'][^"']*["']/gi,
            /<embed[^>]*>/gi,
            /<object[^>]*>/gi,
            /vbscript:/gi,
            /data:text\/html/gi
        ];

        this.commandInjectionPatterns = [
            /[;&|`$(){}[\]<>]/g,
            /\$\{.*?\}/g,
            /(eval|exec|system|passthru|shell_exec)\s*\(/gi,
            /\|\s*(cat|ls|pwd|whoami|netstat|ifconfig|rm|mv|cp)/gi
        ];

        this.pathTraversalPatterns = [
            /\.\.(\/|\\)/g,
            /%2e%2e[\/\\]/gi,
            /\.\.%2f/gi,
            /%00/g,
            /\0/g
        ];
    }

    /**
     * Sanitize string input - removes dangerous characters and patterns
     */
    sanitizeString(input, options = {}) {
        if (typeof input !== 'string') {
            return input;
        }

        let sanitized = input;

        // Trim whitespace
        if (options.trim !== false) {
            sanitized = sanitized.trim();
        }

        // Remove null bytes
        sanitized = sanitized.replace(/\0/g, '');

        // Escape HTML entities if requested
        if (options.escapeHtml) {
            sanitized = validator.escape(sanitized);
        }

        // Remove XSS patterns
        if (options.preventXSS !== false) {
            this.xssPatterns.forEach(pattern => {
                sanitized = sanitized.replace(pattern, '');
            });
        }

        // Remove SQL injection patterns
        if (options.preventSQL !== false) {
            this.sqlInjectionPatterns.forEach(pattern => {
                sanitized = sanitized.replace(pattern, '');
            });
        }

        // Remove command injection patterns
        if (options.preventCommand !== false) {
            this.commandInjectionPatterns.forEach(pattern => {
                sanitized = sanitized.replace(pattern, '');
            });
        }

        // Maximum length
        if (options.maxLength) {
            sanitized = sanitized.substring(0, options.maxLength);
        }

        return sanitized;
    }

    /**
     * Sanitize file path - prevents directory traversal
     */
    sanitizeFilePath(filePath, allowedBasePaths = []) {
        if (typeof filePath !== 'string') {
            throw new Error('File path must be a string');
        }

        // Check for path traversal patterns
        if (this.pathTraversalPatterns.some(pattern => pattern.test(filePath))) {
            throw new Error('Path traversal attempt detected');
        }

        // Normalize path
        const normalized = path.normalize(filePath);

        // Resolve to absolute path
        const resolved = path.resolve(normalized);

        // If allowed base paths specified, ensure path is within them
        if (allowedBasePaths.length > 0) {
            const isAllowed = allowedBasePaths.some(basePath => {
                const resolvedBase = path.resolve(basePath);
                return resolved.startsWith(resolvedBase);
            });

            if (!isAllowed) {
                throw new Error('File path outside allowed directories');
            }
        }

        // Check for dangerous characters in filename
        const fileName = path.basename(normalized);
        if (/[<>"|?*]/.test(fileName)) {
            throw new Error('Invalid characters in filename');
        }

        // Check path length (Windows MAX_PATH = 260)
        if (resolved.length > 260) {
            throw new Error('Path too long (max 260 characters)');
        }

        return resolved;
    }

    /**
     * Validate and sanitize email
     */
    sanitizeEmail(email) {
        if (!email || typeof email !== 'string') {
            throw new Error('Invalid email format');
        }

        const sanitized = email.trim().toLowerCase();

        if (!validator.isEmail(sanitized)) {
            throw new Error('Invalid email format');
        }

        return validator.normalizeEmail(sanitized, {
            gmail_remove_dots: false,
            gmail_remove_subaddress: false,
            outlookdotcom_remove_subaddress: false,
            yahoo_remove_subaddress: false,
            icloud_remove_subaddress: false
        });
    }

    /**
     * Validate URL
     */
    sanitizeURL(url, options = {}) {
        if (!url || typeof url !== 'string') {
            throw new Error('Invalid URL');
        }

        const sanitized = url.trim();

        // Validate URL format
        if (!validator.isURL(sanitized, {
            protocols: options.protocols || ['http', 'https'],
            require_protocol: options.requireProtocol !== false,
            require_valid_protocol: true,
            allow_underscores: false,
            allow_trailing_dot: false,
            allow_protocol_relative_urls: false
        })) {
            throw new Error('Invalid URL format');
        }

        // Check for dangerous protocols
        const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
        if (dangerousProtocols.some(proto => sanitized.toLowerCase().startsWith(proto))) {
            throw new Error('Dangerous URL protocol');
        }

        return sanitized;
    }

    /**
     * Sanitize JSON input
     */
    sanitizeJSON(jsonString, maxDepth = 10) {
        if (typeof jsonString !== 'string') {
            throw new Error('JSON input must be a string');
        }

        try {
            const parsed = JSON.parse(jsonString);
            const sanitized = this._sanitizeObject(parsed, 0, maxDepth);
            return JSON.stringify(sanitized);
        } catch (error) {
            throw new Error('Invalid JSON format');
        }
    }

    /**
     * Recursively sanitize object properties
     */
    _sanitizeObject(obj, depth, maxDepth) {
        if (depth > maxDepth) {
            throw new Error('JSON depth limit exceeded');
        }

        if (typeof obj === 'string') {
            return this.sanitizeString(obj, { trim: false, preventXSS: true });
        }

        if (Array.isArray(obj)) {
            return obj.map(item => this._sanitizeObject(item, depth + 1, maxDepth));
        }

        if (obj && typeof obj === 'object') {
            const sanitized = {};
            for (const [key, value] of Object.entries(obj)) {
                // Sanitize keys too
                const sanitizedKey = this.sanitizeString(key, { maxLength: 100 });
                sanitized[sanitizedKey] = this._sanitizeObject(value, depth + 1, maxDepth);
            }
            return sanitized;
        }

        return obj;
    }

    /**
     * Detect SQL injection attempt
     */
    detectSQLInjection(input) {
        if (typeof input !== 'string') return false;
        return this.sqlInjectionPatterns.some(pattern => pattern.test(input));
    }

    /**
     * Detect XSS attempt
     */
    detectXSS(input) {
        if (typeof input !== 'string') return false;
        return this.xssPatterns.some(pattern => pattern.test(input));
    }

    /**
     * Detect command injection attempt
     */
    detectCommandInjection(input) {
        if (typeof input !== 'string') return false;
        return this.commandInjectionPatterns.some(pattern => pattern.test(input));
    }

    /**
     * Detect path traversal attempt
     */
    detectPathTraversal(input) {
        if (typeof input !== 'string') return false;
        return this.pathTraversalPatterns.some(pattern => pattern.test(input));
    }

    /**
     * Comprehensive threat detection
     */
    detectThreats(input) {
        const threats = [];

        if (this.detectSQLInjection(input)) {
            threats.push({ type: 'SQL Injection', severity: 'critical' });
        }

        if (this.detectXSS(input)) {
            threats.push({ type: 'XSS', severity: 'high' });
        }

        if (this.detectCommandInjection(input)) {
            threats.push({ type: 'Command Injection', severity: 'critical' });
        }

        if (this.detectPathTraversal(input)) {
            threats.push({ type: 'Path Traversal', severity: 'high' });
        }

        return {
            safe: threats.length === 0,
            threats,
            input
        };
    }

    /**
     * Validate password strength
     */
    validatePassword(password) {
        if (!password || typeof password !== 'string') {
            return { valid: false, message: 'Password is required' };
        }

        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

        if (password.length < minLength) {
            return { valid: false, message: `Password must be at least ${minLength} characters` };
        }

        if (!hasUpperCase) {
            return { valid: false, message: 'Password must contain uppercase letters' };
        }

        if (!hasLowerCase) {
            return { valid: false, message: 'Password must contain lowercase letters' };
        }

        if (!hasNumbers) {
            return { valid: false, message: 'Password must contain numbers' };
        }

        if (!hasSpecialChar) {
            return { valid: false, message: 'Password must contain special characters' };
        }

        // Check for common patterns
        const commonPatterns = [
            /^password/i,
            /^12345/,
            /^qwerty/i,
            /^admin/i,
            /(.)\1{3,}/  // repeated characters
        ];

        if (commonPatterns.some(pattern => pattern.test(password))) {
            return { valid: false, message: 'Password is too common or simple' };
        }

        return { valid: true, message: 'Password is strong' };
    }

    /**
     * Create Express middleware for automatic sanitization
     */
    createMiddleware(options = {}) {
        return (req, res, next) => {
            try {
                // Sanitize query parameters
                if (req.query) {
                    for (const [key, value] of Object.entries(req.query)) {
                        if (typeof value === 'string') {
                            req.query[key] = this.sanitizeString(value, options);
                        }
                    }
                }

                // Sanitize body
                if (req.body && typeof req.body === 'object') {
                    req.body = this._sanitizeObject(req.body, 0, options.maxDepth || 10);
                }

                // Sanitize params
                if (req.params) {
                    for (const [key, value] of Object.entries(req.params)) {
                        if (typeof value === 'string') {
                            req.params[key] = this.sanitizeString(value, options);
                        }
                    }
                }

                // Detect threats in all inputs
                const allInputs = [
                    ...Object.values(req.query || {}),
                    ...Object.values(req.params || {}),
                    ...(req.body ? Object.values(req.body) : [])
                ].filter(val => typeof val === 'string');

                for (const input of allInputs) {
                    const detection = this.detectThreats(input);
                    if (!detection.safe) {
                        console.error('[SECURITY] Threat detected:', {
                            ip: req.ip,
                            path: req.path,
                            threats: detection.threats,
                            timestamp: new Date().toISOString()
                        });

                        return res.status(400).json({
                            success: false,
                            message: 'Malicious input detected',
                            threats: detection.threats.map(t => t.type)
                        });
                    }
                }

                next();
            } catch (error) {
                console.error('[SECURITY] Sanitization error:', error.message);
                res.status(400).json({
                    success: false,
                    message: 'Invalid input format'
                });
            }
        };
    }
}

module.exports = new InputSanitizer();
