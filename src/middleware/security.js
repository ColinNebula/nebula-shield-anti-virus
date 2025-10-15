// Security Middleware - Code Protection & Integrity Verification
// Protects against malicious manipulation and unauthorized access

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SecurityMiddleware {
  constructor() {
    this.fileHashes = new Map();
    this.initializeFileHashes();
  }

  // Initialize file integrity hashes
  initializeFileHashes() {
    const criticalFiles = [
      'mock-backend-secure.js',
      'src/services/antivirusScanner.js',
      'src/services/mlAnomalyDetection.js',
      'src/services/emailVerification.js',
      'src/contexts/AuthContext.js'
    ];

    criticalFiles.forEach(file => {
      const filePath = path.join(__dirname, '..', file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        this.fileHashes.set(file, hash);
      }
    });
  }

  // Verify file integrity
  verifyFileIntegrity(filename) {
    const filePath = path.join(__dirname, '..', filename);
    if (!fs.existsSync(filePath)) {
      console.warn(`[SECURITY] File not found: ${filename}`);
      return false;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const currentHash = crypto.createHash('sha256').update(content).digest('hex');
    const originalHash = this.fileHashes.get(filename);

    if (originalHash && currentHash !== originalHash) {
      console.error(`[SECURITY ALERT] File modified: ${filename}`);
      console.error(`Expected: ${originalHash}`);
      console.error(`Found: ${currentHash}`);
      return false;
    }

    return true;
  }

  // Input sanitization - prevent injection attacks
  sanitizeInput(input) {
    if (typeof input !== 'string') return input;

    // Remove dangerous characters
    let sanitized = input
      .replace(/[<>\"\']/g, '') // XSS prevention
      .replace(/(\.\.(\/|\\))+/g, '') // Path traversal prevention
      .replace(/[;&|`$()]/g, ''); // Command injection prevention

    return sanitized.trim();
  }

  // Validate file paths - prevent directory traversal
  validateFilePath(filePath) {
    const normalized = path.normalize(filePath);
    const resolved = path.resolve(normalized);
    
    // Ensure path doesn't escape allowed directories
    const allowedDirs = [
      path.resolve(__dirname, '..', 'uploads'),
      path.resolve(__dirname, '..', 'quarantine'),
      path.resolve(__dirname, '..', 'temp')
    ];

    const isAllowed = allowedDirs.some(dir => resolved.startsWith(dir));
    
    if (!isAllowed) {
      console.error(`[SECURITY] Unauthorized file path access attempt: ${filePath}`);
      return false;
    }

    return true;
  }

  // Rate limiting - prevent brute force and DoS
  createRateLimiter(maxRequests = 100, windowMs = 900000) {
    const requests = new Map();

    return (req, res, next) => {
      const ip = req.ip || req.connection.remoteAddress;
      const now = Date.now();
      
      if (!requests.has(ip)) {
        requests.set(ip, []);
      }

      const userRequests = requests.get(ip);
      const recentRequests = userRequests.filter(time => now - time < windowMs);

      if (recentRequests.length >= maxRequests) {
        console.warn(`[SECURITY] Rate limit exceeded for IP: ${ip}`);
        return res.status(429).json({
          error: 'Too many requests',
          message: 'Rate limit exceeded. Please try again later.',
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }

      recentRequests.push(now);
      requests.set(ip, recentRequests);
      next();
    };
  }

  // Request validation middleware
  validateRequest(req, res, next) {
    // Validate content type for POST/PUT requests
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      const contentType = req.get('Content-Type');
      if (!contentType || (!contentType.includes('application/json') && !contentType.includes('multipart/form-data'))) {
        return res.status(400).json({
          error: 'Invalid Content-Type',
          message: 'Content-Type must be application/json or multipart/form-data'
        });
      }
    }

    // Check for suspicious headers
    const suspiciousHeaders = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url'];
    for (const header of suspiciousHeaders) {
      if (req.get(header)) {
        console.warn(`[SECURITY] Suspicious header detected: ${header} from ${req.ip}`);
      }
    }

    next();
  }

  // Detect malicious patterns in requests
  detectMaliciousPatterns(data) {
    if (typeof data !== 'string') return false;

    const maliciousPatterns = [
      /<script[^>]*>.*?<\/script>/gi, // Script tags
      /javascript:/gi, // JavaScript protocol
      /on\w+\s*=\s*["'][^"']*["']/gi, // Event handlers
      /(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+/gi, // SQL keywords
      /(\.\.(\/|\\))+/g, // Path traversal
      /[;&|`$(){}[\]]/g, // Command injection characters
      /%00/g, // Null byte
      /<!--.*?-->/g // HTML comments
    ];

    return maliciousPatterns.some(pattern => pattern.test(data));
  }

  // Sanitize SQL queries (parameterized queries are preferred)
  sanitizeSQL(query) {
    // Remove dangerous SQL keywords and patterns
    const dangerous = [
      'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE',
      'EXEC', 'EXECUTE', 'SCRIPT', '--', '/*', '*/',
      'xp_', 'sp_', 'INFORMATION_SCHEMA'
    ];

    let sanitized = query;
    dangerous.forEach(keyword => {
      const regex = new RegExp(keyword, 'gi');
      sanitized = sanitized.replace(regex, '');
    });

    return sanitized;
  }

  // Validate email format
  validateEmail(email) {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
  }

  // Generate secure random token
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  // Hash password (use bcrypt for production)
  hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return { salt, hash };
  }

  // Verify password
  verifyPassword(password, salt, hash) {
    const verifyHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === verifyHash;
  }

  // Log security events
  logSecurityEvent(event, details = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      details,
      severity: this.calculateSeverity(event)
    };

    console.log('[SECURITY LOG]', JSON.stringify(logEntry, null, 2));

    // In production, send to security monitoring service
    // e.g., Datadog, Sentry, CloudWatch
  }

  // Calculate event severity
  calculateSeverity(event) {
    const criticalEvents = ['file_modified', 'unauthorized_access', 'injection_attempt'];
    const highEvents = ['rate_limit_exceeded', 'invalid_token', 'suspicious_pattern'];
    const mediumEvents = ['invalid_input', 'validation_failed'];

    if (criticalEvents.includes(event)) return 'CRITICAL';
    if (highEvents.includes(event)) return 'HIGH';
    if (mediumEvents.includes(event)) return 'MEDIUM';
    return 'LOW';
  }

  // Check for known malicious IPs (integrate with threat intelligence)
  async checkIPReputation(ip) {
    // In production, integrate with services like:
    // - AbuseIPDB
    // - IPQualityScore
    // - VirusTotal IP report

    const knownBadIPs = [
      // Add known malicious IPs here
    ];

    if (knownBadIPs.includes(ip)) {
      this.logSecurityEvent('malicious_ip_detected', { ip });
      return false;
    }

    return true;
  }

  // Secure session management
  generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  // Validate session
  validateSession(sessionId, storedSession) {
    if (!sessionId || !storedSession) return false;

    // Check expiration
    if (Date.now() > storedSession.expiresAt) {
      return false;
    }

    // Verify session integrity
    return sessionId === storedSession.id;
  }

  // Content Security Policy headers
  getCSPHeaders() {
    return {
      'Content-Security-Policy': [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Adjust for production
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' data:",
        "connect-src 'self' http://localhost:* https://www.virustotal.com",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join('; ')
    };
  }

  // Complete security middleware stack
  getSecurityMiddleware() {
    return [
      this.validateRequest.bind(this),
      this.createRateLimiter(100, 900000), // 100 requests per 15 minutes
      (req, res, next) => {
        // Add security headers
        res.set(this.getCSPHeaders());
        res.set('X-Content-Type-Options', 'nosniff');
        res.set('X-Frame-Options', 'DENY');
        res.set('X-XSS-Protection', '1; mode=block');
        res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        next();
      }
    ];
  }
}

// Export singleton instance
const securityMiddleware = new SecurityMiddleware();

module.exports = securityMiddleware;
