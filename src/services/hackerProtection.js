/**
 * Hacker Attack Protection Service
 * Comprehensive protection against DDoS, brute force, injection attacks, and more
 */

// Attack detection thresholds
const THRESHOLDS = {
  ddos: {
    requestsPerSecond: 100,
    requestsPerMinute: 500,
    simultaneousConnections: 50
  },
  bruteForce: {
    maxFailedAttempts: 5,
    timeWindowMinutes: 15,
    blockDurationMinutes: 30
  },
  rateLimit: {
    apiCallsPerMinute: 60,
    apiCallsPerHour: 1000
  }
};

// Known attack patterns
const ATTACK_PATTERNS = {
  sqlInjection: [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /union.*select/i,
    /select.*from/i,
    /insert.*into/i,
    /delete.*from/i,
    /drop.*table/i,
    /exec(\s|\+)+(s|x)p\w+/i
  ],
  xss: [
    /<script[^>]*>.*?<\/script>/i,
    /<iframe[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<img[^>]+src[^>]*>/i,
    /eval\(/i,
    /expression\(/i,
    /vbscript:/i
  ],
  commandInjection: [
    /[;&|`$()]/,
    /\.\.\//,
    /\/etc\/passwd/i,
    /\/bin\/(sh|bash)/i,
    /nc\s+-/i,
    /wget\s+/i,
    /curl\s+/i
  ],
  pathTraversal: [
    /\.\.[\/\\]/,
    /%2e%2e[\/\\]/i,
    /\.\.[%252f%255c]/i
  ]
};

// Honeypot services (fake vulnerable endpoints to trap attackers)
const HONEYPOTS = [
  {
    id: 1,
    name: 'Fake Admin Login',
    endpoint: '/admin/login',
    type: 'web',
    description: 'Decoy admin panel to catch unauthorized access attempts',
    status: 'active',
    hits: 0,
    lastHit: null
  },
  {
    id: 2,
    name: 'Fake Database Port',
    port: 3306,
    type: 'service',
    description: 'Fake MySQL service to detect port scanning',
    status: 'active',
    hits: 0,
    lastHit: null
  },
  {
    id: 3,
    name: 'Fake SSH Service',
    port: 22,
    type: 'service',
    description: 'Honeypot SSH service to catch brute force attempts',
    status: 'active',
    hits: 0,
    lastHit: null
  },
  {
    id: 4,
    name: 'Fake API Key Endpoint',
    endpoint: '/api/keys',
    type: 'web',
    description: 'Trap for credential harvesting attempts',
    status: 'active',
    hits: 0,
    lastHit: null
  }
];

// Real-time attack tracking
let attackLog = [];
let blockedIPs = new Map(); // IP -> { reason, blockedAt, expiresAt }
let rateLimits = new Map(); // IP -> { requests: [], apiCalls: [] }
let failedLogins = new Map(); // IP -> { attempts: [], blockedUntil }

// Geo-blocking configuration
const BLOCKED_COUNTRIES = ['KP', 'IR', 'SY']; // North Korea, Iran, Syria (example)
const GEO_DATABASE = {
  '103.224.182.0': 'KP',
  '175.45.176.0': 'KP',
  '91.198.115.0': 'IR',
  '5.160.0.0': 'SY'
};

/**
 * DDoS Protection - Detect and mitigate distributed denial of service attacks
 */
export function detectDDoS(ip, timestamp = Date.now()) {
  if (!rateLimits.has(ip)) {
    rateLimits.set(ip, { requests: [], apiCalls: [] });
  }

  const tracker = rateLimits.get(ip);
  tracker.requests.push(timestamp);

  // Clean old requests (older than 1 minute)
  const oneMinuteAgo = timestamp - 60000;
  tracker.requests = tracker.requests.filter(t => t > oneMinuteAgo);

  // Check thresholds
  const requestsPerMinute = tracker.requests.length;
  const requestsPerSecond = tracker.requests.filter(t => t > timestamp - 1000).length;

  if (requestsPerSecond > THRESHOLDS.ddos.requestsPerSecond) {
    blockIP(ip, 'DDoS Attack - Excessive requests per second', 3600000); // 1 hour
    logAttack({
      type: 'DDoS',
      severity: 'Critical',
      ip,
      details: `${requestsPerSecond} requests/second detected`,
      action: 'IP Blocked',
      timestamp
    });
    return { blocked: true, reason: 'DDoS detected', requestsPerSecond };
  }

  if (requestsPerMinute > THRESHOLDS.ddos.requestsPerMinute) {
    blockIP(ip, 'DDoS Attack - Excessive requests per minute', 1800000); // 30 minutes
    logAttack({
      type: 'DDoS',
      severity: 'High',
      ip,
      details: `${requestsPerMinute} requests/minute detected`,
      action: 'IP Blocked',
      timestamp
    });
    return { blocked: true, reason: 'DDoS detected', requestsPerMinute };
  }

  return { blocked: false, requestsPerSecond, requestsPerMinute };
}

/**
 * Brute Force Protection - Detect and block password guessing attempts
 */
export function detectBruteForce(ip, username, success = false, timestamp = Date.now()) {
  if (!failedLogins.has(ip)) {
    failedLogins.set(ip, { attempts: [], blockedUntil: null });
  }

  const tracker = failedLogins.get(ip);

  // Check if already blocked
  if (tracker.blockedUntil && timestamp < tracker.blockedUntil) {
    const remainingTime = Math.ceil((tracker.blockedUntil - timestamp) / 60000);
    return { 
      blocked: true, 
      reason: 'Brute force protection active',
      remainingMinutes: remainingTime 
    };
  }

  // Reset block if expired
  if (tracker.blockedUntil && timestamp >= tracker.blockedUntil) {
    tracker.blockedUntil = null;
    tracker.attempts = [];
  }

  // If login succeeded, clear attempts
  if (success) {
    tracker.attempts = [];
    return { blocked: false };
  }

  // Record failed attempt
  tracker.attempts.push({ username, timestamp });

  // Clean old attempts (older than time window)
  const timeWindow = THRESHOLDS.bruteForce.timeWindowMinutes * 60000;
  tracker.attempts = tracker.attempts.filter(a => a.timestamp > timestamp - timeWindow);

  // Check threshold
  if (tracker.attempts.length >= THRESHOLDS.bruteForce.maxFailedAttempts) {
    const blockDuration = THRESHOLDS.bruteForce.blockDurationMinutes * 60000;
    tracker.blockedUntil = timestamp + blockDuration;
    
    blockIP(ip, `Brute Force Attack - ${tracker.attempts.length} failed login attempts`, blockDuration);
    
    logAttack({
      type: 'Brute Force',
      severity: 'High',
      ip,
      details: `${tracker.attempts.length} failed login attempts for user: ${username}`,
      action: 'IP Blocked',
      timestamp
    });

    return { 
      blocked: true, 
      reason: 'Too many failed login attempts',
      attempts: tracker.attempts.length,
      blockedMinutes: THRESHOLDS.bruteForce.blockDurationMinutes
    };
  }

  return { 
    blocked: false, 
    attempts: tracker.attempts.length,
    remaining: THRESHOLDS.bruteForce.maxFailedAttempts - tracker.attempts.length
  };
}

/**
 * SQL Injection Detection
 */
export function detectSQLInjection(input) {
  for (const pattern of ATTACK_PATTERNS.sqlInjection) {
    if (pattern.test(input)) {
      return {
        detected: true,
        type: 'SQL Injection',
        pattern: pattern.toString(),
        input: input.substring(0, 100) + (input.length > 100 ? '...' : '')
      };
    }
  }
  return { detected: false };
}

/**
 * XSS (Cross-Site Scripting) Detection
 */
export function detectXSS(input) {
  for (const pattern of ATTACK_PATTERNS.xss) {
    if (pattern.test(input)) {
      return {
        detected: true,
        type: 'XSS Attack',
        pattern: pattern.toString(),
        input: input.substring(0, 100) + (input.length > 100 ? '...' : '')
      };
    }
  }
  return { detected: false };
}

/**
 * Command Injection Detection
 */
export function detectCommandInjection(input) {
  for (const pattern of ATTACK_PATTERNS.commandInjection) {
    if (pattern.test(input)) {
      return {
        detected: true,
        type: 'Command Injection',
        pattern: pattern.toString(),
        input: input.substring(0, 100) + (input.length > 100 ? '...' : '')
      };
    }
  }
  return { detected: false };
}

/**
 * Path Traversal Detection
 */
export function detectPathTraversal(input) {
  for (const pattern of ATTACK_PATTERNS.pathTraversal) {
    if (pattern.test(input)) {
      return {
        detected: true,
        type: 'Path Traversal',
        pattern: pattern.toString(),
        input: input.substring(0, 100) + (input.length > 100 ? '...' : '')
      };
    }
  }
  return { detected: false };
}

/**
 * Comprehensive Input Validation
 */
export function validateInput(input, ip = null, context = 'unknown') {
  const checks = [
    detectSQLInjection(input),
    detectXSS(input),
    detectCommandInjection(input),
    detectPathTraversal(input)
  ];

  const threats = checks.filter(check => check.detected);

  if (threats.length > 0) {
    logAttack({
      type: 'Injection Attack',
      severity: 'Critical',
      ip,
      details: `${threats.map(t => t.type).join(', ')} detected in ${context}`,
      action: ip ? 'IP Blocked' : 'Request Rejected',
      timestamp: Date.now()
    });

    if (ip) {
      blockIP(ip, `Injection attack detected: ${threats[0].type}`, 7200000); // 2 hours
    }

    return {
      valid: false,
      threats,
      action: 'blocked'
    };
  }

  return { valid: true };
}

/**
 * Rate Limiting
 */
export function checkRateLimit(ip, endpoint = 'api', timestamp = Date.now()) {
  if (!rateLimits.has(ip)) {
    rateLimits.set(ip, { requests: [], apiCalls: [] });
  }

  const tracker = rateLimits.get(ip);
  tracker.apiCalls.push({ endpoint, timestamp });

  // Clean old API calls
  const oneHourAgo = timestamp - 3600000;
  const oneMinuteAgo = timestamp - 60000;
  tracker.apiCalls = tracker.apiCalls.filter(c => c.timestamp > oneHourAgo);

  const callsPerMinute = tracker.apiCalls.filter(c => c.timestamp > oneMinuteAgo).length;
  const callsPerHour = tracker.apiCalls.length;

  if (callsPerMinute > THRESHOLDS.rateLimit.apiCallsPerMinute) {
    logAttack({
      type: 'Rate Limit Exceeded',
      severity: 'Medium',
      ip,
      details: `${callsPerMinute} API calls per minute to ${endpoint}`,
      action: 'Request Throttled',
      timestamp
    });
    return { 
      allowed: false, 
      reason: 'Rate limit exceeded',
      retryAfter: 60,
      callsPerMinute 
    };
  }

  if (callsPerHour > THRESHOLDS.rateLimit.apiCallsPerHour) {
    blockIP(ip, 'Rate limit exceeded - API abuse', 3600000); // 1 hour
    return { 
      allowed: false, 
      reason: 'Hourly rate limit exceeded',
      retryAfter: 3600,
      callsPerHour 
    };
  }

  return { 
    allowed: true, 
    callsPerMinute, 
    callsPerHour,
    remaining: THRESHOLDS.rateLimit.apiCallsPerMinute - callsPerMinute
  };
}

/**
 * Geo-blocking
 */
export function checkGeoBlock(ip) {
  // Find country code for IP
  const countryCode = getCountryCode(ip);
  
  if (BLOCKED_COUNTRIES.includes(countryCode)) {
    blockIP(ip, `Geo-blocked country: ${countryCode}`, 86400000); // 24 hours
    logAttack({
      type: 'Geo-block',
      severity: 'Medium',
      ip,
      details: `Connection from blocked country: ${countryCode}`,
      action: 'IP Blocked',
      timestamp: Date.now()
    });
    return { blocked: true, country: countryCode };
  }

  return { blocked: false, country: countryCode };
}

function getCountryCode(ip) {
  // Simple IP prefix matching (in production, use MaxMind GeoIP database)
  for (const [prefix, country] of Object.entries(GEO_DATABASE)) {
    if (ip.startsWith(prefix.split('.').slice(0, 2).join('.'))) {
      return country;
    }
  }
  return 'US'; // Default
}

/**
 * Honeypot Management
 */
export function triggerHoneypot(honeypotId, ip, details = {}) {
  const honeypot = HONEYPOTS.find(h => h.id === honeypotId);
  if (!honeypot) return;

  honeypot.hits++;
  honeypot.lastHit = Date.now();

  // Immediate block for honeypot access
  blockIP(ip, `Honeypot triggered: ${honeypot.name}`, 604800000); // 7 days

  logAttack({
    type: 'Honeypot Triggered',
    severity: 'Critical',
    ip,
    details: `${honeypot.name} accessed - Likely attacker`,
    action: 'IP Blocked (7 days)',
    timestamp: Date.now(),
    honeypot: honeypot.name
  });
}

export function getHoneypots() {
  return HONEYPOTS.map(h => ({
    ...h,
    lastHit: h.lastHit ? new Date(h.lastHit).toLocaleString() : 'Never'
  }));
}

/**
 * IP Blocking
 */
export function blockIP(ip, reason, duration = 3600000) {
  const expiresAt = Date.now() + duration;
  blockedIPs.set(ip, {
    reason,
    blockedAt: Date.now(),
    expiresAt,
    duration: Math.ceil(duration / 60000) // minutes
  });
}

export function unblockIP(ip) {
  blockedIPs.delete(ip);
  // Also clear failed login attempts
  failedLogins.delete(ip);
  rateLimits.delete(ip);
}

export function isIPBlocked(ip) {
  if (!blockedIPs.has(ip)) return { blocked: false };

  const block = blockedIPs.get(ip);
  const now = Date.now();

  // Auto-expire if time has passed
  if (now >= block.expiresAt) {
    blockedIPs.delete(ip);
    return { blocked: false };
  }

  return {
    blocked: true,
    reason: block.reason,
    remainingMinutes: Math.ceil((block.expiresAt - now) / 60000)
  };
}

export function getBlockedIPs() {
  const now = Date.now();
  const blocked = [];

  for (const [ip, block] of blockedIPs.entries()) {
    if (now < block.expiresAt) {
      blocked.push({
        ip,
        reason: block.reason,
        blockedAt: new Date(block.blockedAt).toLocaleString(),
        expiresAt: new Date(block.expiresAt).toLocaleString(),
        remainingMinutes: Math.ceil((block.expiresAt - now) / 60000)
      });
    } else {
      // Clean expired blocks
      blockedIPs.delete(ip);
    }
  }

  return blocked;
}

/**
 * Attack Logging
 */
function logAttack(attack) {
  attackLog.push({
    id: attackLog.length + 1,
    ...attack,
    timestamp: new Date(attack.timestamp).toLocaleString()
  });

  // Keep only last 500 attacks
  if (attackLog.length > 500) {
    attackLog = attackLog.slice(-500);
  }
}

export function getAttackLog(limit = 100) {
  return attackLog.slice(-limit).reverse();
}

export function getAttackStats(hours = 24) {
  const cutoff = Date.now() - (hours * 3600000);
  const recentAttacks = attackLog.filter(a => new Date(a.timestamp).getTime() > cutoff);

  const stats = {
    total: recentAttacks.length,
    byType: {},
    bySeverity: { Critical: 0, High: 0, Medium: 0, Low: 0 },
    topAttackers: {},
    blocked: blockedIPs.size,
    honeypotHits: HONEYPOTS.reduce((sum, h) => sum + h.hits, 0)
  };

  recentAttacks.forEach(attack => {
    // Count by type
    stats.byType[attack.type] = (stats.byType[attack.type] || 0) + 1;
    
    // Count by severity
    stats.bySeverity[attack.severity]++;
    
    // Track top attackers
    if (attack.ip) {
      stats.topAttackers[attack.ip] = (stats.topAttackers[attack.ip] || 0) + 1;
    }
  });

  // Convert topAttackers to sorted array
  stats.topAttackers = Object.entries(stats.topAttackers)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return stats;
}

/**
 * Security Dashboard Data
 */
export function getSecurityDashboard() {
  const stats = getAttackStats(24);
  
  return {
    realTimeStatus: {
      activeThreats: attackLog.filter(a => 
        new Date(a.timestamp).getTime() > Date.now() - 300000 // Last 5 minutes
      ).length,
      blockedIPs: blockedIPs.size,
      honeypotHits: HONEYPOTS.reduce((sum, h) => sum + h.hits, 0),
      rateLimitedIPs: Array.from(rateLimits.keys()).length
    },
    attackStats: stats,
    recentAttacks: getAttackLog(20),
    blockedIPs: getBlockedIPs(),
    honeypots: getHoneypots(),
    protectionStatus: {
      ddos: 'Active',
      bruteForce: 'Active',
      injection: 'Active',
      rateLimit: 'Active',
      geoBlock: 'Active',
      honeypots: 'Active'
    }
  };
}

/**
 * Generate sample attack data for demonstration
 */
export function generateSampleAttacks() {
  const sampleIPs = [
    '45.142.212.61',
    '185.220.101.1',
    '91.198.115.23',
    '103.224.182.45',
    '192.168.1.100'
  ];

  const attackTypes = [
    { type: 'DDoS', severity: 'Critical' },
    { type: 'Brute Force', severity: 'High' },
    { type: 'SQL Injection', severity: 'Critical' },
    { type: 'XSS Attack', severity: 'High' },
    { type: 'Port Scanning', severity: 'Medium' },
    { type: 'Honeypot Triggered', severity: 'Critical' }
  ];

  // Generate 25 sample attacks over the last 24 hours
  const now = Date.now();
  for (let i = 0; i < 25; i++) {
    const attack = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    const ip = sampleIPs[Math.floor(Math.random() * sampleIPs.length)];
    const timestamp = now - Math.random() * 86400000; // Random time in last 24 hours

    logAttack({
      type: attack.type,
      severity: attack.severity,
      ip,
      details: `Sample ${attack.type} attack detected`,
      action: Math.random() > 0.3 ? 'IP Blocked' : 'Request Rejected',
      timestamp
    });
  }

  // Block a few IPs
  blockIP('45.142.212.61', 'Multiple DDoS attempts', 3600000);
  blockIP('185.220.101.1', 'Brute force attack on admin panel', 7200000);
  blockIP('103.224.182.45', 'SQL injection attempts', 86400000);

  // Trigger some honeypots
  HONEYPOTS[0].hits = 5;
  HONEYPOTS[0].lastHit = now - 3600000;
  HONEYPOTS[2].hits = 3;
  HONEYPOTS[2].lastHit = now - 7200000;
}

// Generate sample data on module load
generateSampleAttacks();
