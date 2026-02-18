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

// AI/ML Behavioral Analysis
let userBehaviorProfiles = new Map(); // userId -> behavioral profile
let anomalyScores = new Map(); // userId/IP -> risk score (0-100)
let mlModels = {
  loginPatterns: new Map(),
  accessPatterns: new Map(),
  timingPatterns: new Map()
};

// Advanced Threat Intelligence
let threatIntelDB = new Map(); // IP -> threat data
let ipReputationCache = new Map(); // IP -> { score, lastChecked, sources }
let knownBotnets = new Set();
let malwareC2Servers = new Set();
let threatFeeds = [];

// Geo-blocking configuration
const BLOCKED_COUNTRIES = ['KP', 'IR', 'SY']; // North Korea, Iran, Syria (example)
const GEO_DATABASE = {
  '103.224.182.0': 'KP',
  '175.45.176.0': 'KP',
  '91.198.115.0': 'IR',
  '5.160.0.0': 'SY'
};

// Threat Intelligence Database
const KNOWN_THREAT_IPS = new Map([
  ['45.142.212.0', { type: 'botnet', name: 'Mirai', severity: 'critical', firstSeen: '2024-01-15' }],
  ['185.220.101.0', { type: 'tor-exit', name: 'TOR Exit Node', severity: 'high', firstSeen: '2024-02-20' }],
  ['91.198.115.0', { type: 'malware-c2', name: 'Zeus C2', severity: 'critical', firstSeen: '2024-03-10' }],
  ['103.224.182.0', { type: 'botnet', name: 'Emotet', severity: 'critical', firstSeen: '2024-04-05' }],
  ['194.165.16.0', { type: 'scanner', name: 'Shodan Scanner', severity: 'medium', firstSeen: '2024-05-12' }]
]);

const BOTNET_SIGNATURES = [
  { name: 'Mirai', userAgents: ['Hello, world'], ports: [23, 2323] },
  { name: 'Emotet', userAgents: ['Mozilla/4.0'], patterns: [/doc\d+\.zip/] },
  { name: 'Zeus', patterns: [/\/gate\.php/, /\/config\.bin/] },
  { name: 'QakBot', userAgents: ['WinHTTP'], patterns: [/\/t\d+/] }
];

const C2_SERVER_INDICATORS = [
  /\/c2\/beacon/i,
  /\/admin\/bot/i,
  /\/panel\/gate/i,
  /base64_decode.*eval/i
];

/**
 * AI/ML Behavioral Analysis - Detect anomalous user behavior
 */
export function analyzeUserBehavior(userId, action, metadata = {}) {
  if (!userBehaviorProfiles.has(userId)) {
    userBehaviorProfiles.set(userId, {
      loginTimes: [],
      loginLocations: [],
      devices: new Set(),
      typicalActions: new Map(),
      sessionDurations: [],
      createdAt: Date.now(),
      totalActions: 0
    });
  }

  const profile = userBehaviorProfiles.get(userId);
  profile.totalActions++;

  // Learn normal behavior patterns
  if (action === 'login') {
    const hour = new Date().getHours();
    profile.loginTimes.push(hour);
    if (metadata.location) profile.loginLocations.push(metadata.location);
    if (metadata.device) profile.devices.add(metadata.device);
  }

  // Track action frequency
  const actionCount = profile.typicalActions.get(action) || 0;
  profile.typicalActions.set(action, actionCount + 1);

  // Calculate anomaly score
  const anomalyScore = calculateAnomalyScore(userId, action, metadata, profile);
  anomalyScores.set(userId, anomalyScore);

  if (anomalyScore > 75) {
    logAttack({
      type: 'Behavioral Anomaly',
      severity: anomalyScore > 90 ? 'Critical' : 'High',
      ip: metadata.ip,
      details: `Suspicious behavior detected for user ${userId} (score: ${anomalyScore})`,
      action: 'Account Flagged',
      timestamp: Date.now(),
      anomalyScore
    });
  }

  return { anomalyScore, profile, suspicious: anomalyScore > 75 };
}

function calculateAnomalyScore(userId, action, metadata, profile) {
  let score = 0;

  // Check login time anomaly
  if (action === 'login' && profile.loginTimes.length > 5) {
    const currentHour = new Date().getHours();
    const avgHour = profile.loginTimes.reduce((a, b) => a + b, 0) / profile.loginTimes.length;
    const hourDiff = Math.abs(currentHour - avgHour);
    if (hourDiff > 6) score += 25; // Login at unusual time
  }

  // Check location anomaly
  if (metadata.location && profile.loginLocations.length > 3) {
    if (!profile.loginLocations.includes(metadata.location)) {
      score += 30; // Login from new location
    }
  }

  // Check device anomaly
  if (metadata.device && profile.devices.size > 0) {
    if (!profile.devices.has(metadata.device)) {
      score += 20; // Login from new device
    }
  }

  // Check rapid successive actions (possible automation)
  if (profile.totalActions > 10) {
    const recentActions = Array.from(profile.typicalActions.values()).slice(-5);
    const avgInterval = recentActions.reduce((a, b) => a + b, 0) / recentActions.length;
    if (avgInterval > 100) score += 15; // Unusually high activity
  }

  // Impossible travel detection
  if (metadata.location && profile.loginLocations.length > 0) {
    const lastLocation = profile.loginLocations[profile.loginLocations.length - 1];
    const timeSinceLastLogin = Date.now() - (metadata.lastLoginTime || 0);
    if (lastLocation !== metadata.location && timeSinceLastLogin < 3600000) {
      score += 35; // Login from different location too quickly (impossible travel)
    }
  }

  return Math.min(100, score);
}

export function predictAttack(ip, patterns = []) {
  const predictions = [];
  let riskScore = 0;

  // Analyze request patterns using ML-like heuristics
  const patternAnalysis = {
    requestFrequency: patterns.filter(p => p.timestamp > Date.now() - 60000).length,
    uniqueEndpoints: new Set(patterns.map(p => p.endpoint)).size,
    errorRate: patterns.filter(p => p.statusCode >= 400).length / Math.max(patterns.length, 1),
    methodVariety: new Set(patterns.map(p => p.method)).size
  };

  // Predict DDoS
  if (patternAnalysis.requestFrequency > 50) {
    predictions.push({ type: 'DDoS', probability: 85, reason: 'High request frequency' });
    riskScore += 40;
  }

  // Predict scanning/reconnaissance
  if (patternAnalysis.uniqueEndpoints > 20 && patternAnalysis.errorRate > 0.5) {
    predictions.push({ type: 'Scanning', probability: 75, reason: 'High endpoint diversity with errors' });
    riskScore += 25;
  }

  // Predict brute force
  if (patterns.filter(p => p.endpoint?.includes('login')).length > 10) {
    predictions.push({ type: 'Brute Force', probability: 80, reason: 'Repeated login attempts' });
    riskScore += 35;
  }

  return {
    predictions,
    riskScore: Math.min(100, riskScore),
    shouldBlock: riskScore > 70,
    analysis: patternAnalysis
  };
}

/**
 * Advanced Threat Intelligence - Check IP against threat databases
 */
export function checkThreatIntelligence(ip) {
  const threats = [];
  let reputationScore = 100; // Start with perfect score

  // Check known threat IPs
  for (const [threatIP, data] of KNOWN_THREAT_IPS) {
    if (ip.startsWith(threatIP.split('.').slice(0, 3).join('.'))) {
      threats.push({
        source: 'Internal Database',
        type: data.type,
        name: data.name,
        severity: data.severity,
        firstSeen: data.firstSeen
      });
      reputationScore -= data.severity === 'critical' ? 80 : 50;
    }
  }

  // Check botnet signatures
  if (knownBotnets.has(ip)) {
    threats.push({
      source: 'Botnet Detection',
      type: 'botnet',
      severity: 'critical'
    });
    reputationScore -= 90;
  }

  // Check C2 servers
  if (malwareC2Servers.has(ip)) {
    threats.push({
      source: 'C2 Server Database',
      type: 'malware-c2',
      severity: 'critical'
    });
    reputationScore -= 95;
  }

  // Simulate AbuseIPDB check
  const abuseScore = simulateAbuseIPDB(ip);
  if (abuseScore > 50) {
    threats.push({
      source: 'AbuseIPDB',
      type: 'abuse',
      confidence: abuseScore,
      severity: abuseScore > 80 ? 'high' : 'medium'
    });
    reputationScore -= abuseScore / 2;
  }

  reputationScore = Math.max(0, reputationScore);

  // Cache results
  ipReputationCache.set(ip, {
    score: reputationScore,
    threats,
    lastChecked: Date.now(),
    sources: ['Internal', 'AbuseIPDB', 'Botnet DB', 'C2 DB']
  });

  if (threats.length > 0) {
    logAttack({
      type: 'Threat Intelligence Match',
      severity: threats.some(t => t.severity === 'critical') ? 'Critical' : 'High',
      ip,
      details: `IP matched ${threats.length} threat source(s): ${threats.map(t => t.type).join(', ')}`,
      action: 'IP Blocked',
      timestamp: Date.now(),
      reputationScore
    });

    blockIP(ip, `Threat intelligence: ${threats[0].type}`, 86400000); // 24 hours
  }

  return {
    isThreat: threats.length > 0,
    reputationScore,
    threats,
    shouldBlock: reputationScore < 30
  };
}

function simulateAbuseIPDB(ip) {
  // Simulate AbuseIPDB abuse confidence score (0-100)
  const ipNum = ip.split('.').reduce((acc, oct) => acc * 256 + parseInt(oct), 0);
  const score = (ipNum % 100);
  
  // Known malicious IPs get high scores
  if (ip.startsWith('45.') || ip.startsWith('185.') || ip.startsWith('91.')) {
    return 85 + (ipNum % 15);
  }
  
  return score;
}

export function detectBotnet(ip, userAgent = '', requestPath = '') {
  for (const botnet of BOTNET_SIGNATURES) {
    // Check user agent
    if (botnet.userAgents && botnet.userAgents.some(ua => userAgent.includes(ua))) {
      knownBotnets.add(ip);
      logAttack({
        type: 'Botnet Detected',
        severity: 'Critical',
        ip,
        details: `${botnet.name} botnet signature detected via user agent`,
        action: 'IP Blocked',
        timestamp: Date.now(),
        botnetName: botnet.name
      });
      blockIP(ip, `Botnet detected: ${botnet.name}`, 604800000); // 7 days
      return { detected: true, botnet: botnet.name, method: 'user-agent' };
    }

    // Check request patterns
    if (botnet.patterns && botnet.patterns.some(pattern => pattern.test(requestPath))) {
      knownBotnets.add(ip);
      logAttack({
        type: 'Botnet Detected',
        severity: 'Critical',
        ip,
        details: `${botnet.name} botnet signature detected via request pattern`,
        action: 'IP Blocked',
        timestamp: Date.now(),
        botnetName: botnet.name
      });
      blockIP(ip, `Botnet detected: ${botnet.name}`, 604800000); // 7 days
      return { detected: true, botnet: botnet.name, method: 'request-pattern' };
    }
  }

  return { detected: false };
}

export function detectC2Communication(requestPath, requestBody = '') {
  for (const indicator of C2_SERVER_INDICATORS) {
    if (indicator.test(requestPath) || indicator.test(requestBody)) {
      return {
        detected: true,
        indicator: indicator.toString(),
        type: 'C2 Communication'
      };
    }
  }
  return { detected: false };
}

export function getIPReputation(ip) {
  // Check cache first
  if (ipReputationCache.has(ip)) {
    const cached = ipReputationCache.get(ip);
    const age = Date.now() - cached.lastChecked;
    if (age < 3600000) { // Cache for 1 hour
      return cached;
    }
  }

  // Fresh check
  return checkThreatIntelligence(ip);
}

export function getMachineLearningInsights() {
  return {
    totalProfiles: userBehaviorProfiles.size,
    highRiskUsers: Array.from(anomalyScores.entries())
      .filter(([_, score]) => score > 75)
      .map(([userId, score]) => ({ userId, riskScore: score })),
    threatIntelligenceStats: {
      knownThreats: KNOWN_THREAT_IPS.size,
      detectedBotnets: knownBotnets.size,
      c2Servers: malwareC2Servers.size,
      cachedReputations: ipReputationCache.size
    },
    behaviorPatterns: {
      avgLoginTime: calculateAverageLoginTime(),
      commonDevices: getCommonDevices(),
      suspiciousActivities: getSuspiciousActivities()
    }
  };
}

function calculateAverageLoginTime() {
  let totalHours = 0;
  let count = 0;
  for (const profile of userBehaviorProfiles.values()) {
    totalHours += profile.loginTimes.reduce((a, b) => a + b, 0);
    count += profile.loginTimes.length;
  }
  return count > 0 ? Math.round(totalHours / count) : 0;
}

function getCommonDevices() {
  const deviceCount = new Map();
  for (const profile of userBehaviorProfiles.values()) {
    for (const device of profile.devices) {
      deviceCount.set(device, (deviceCount.get(device) || 0) + 1);
    }
  }
  return Array.from(deviceCount.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([device, count]) => ({ device, count }));
}

function getSuspiciousActivities() {
  return attackLog
    .filter(a => a.type === 'Behavioral Anomaly' || a.type === 'Threat Intelligence Match')
    .slice(-10);
}

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
  const mlInsights = getMachineLearningInsights();
  
  return {
    realTimeStatus: {
      activeThreats: attackLog.filter(a => 
        new Date(a.timestamp).getTime() > Date.now() - 300000 // Last 5 minutes
      ).length,
      blockedIPs: blockedIPs.size,
      honeypotHits: HONEYPOTS.reduce((sum, h) => sum + h.hits, 0),
      rateLimitedIPs: Array.from(rateLimits.keys()).length,
      highRiskUsers: mlInsights.highRiskUsers.length,
      detectedBotnets: mlInsights.threatIntelligenceStats.detectedBotnets,
      threatIntelMatches: Array.from(ipReputationCache.values()).filter(r => r.score < 50).length
    },
    attackStats: stats,
    recentAttacks: getAttackLog(20),
    blockedIPs: getBlockedIPs(),
    honeypots: getHoneypots(),
    mlInsights,
    threatIntelligence: {
      knownThreats: KNOWN_THREAT_IPS.size,
      botnets: Array.from(knownBotnets),
      c2Servers: Array.from(malwareC2Servers),
      reputationCache: Array.from(ipReputationCache.entries())
        .filter(([_, data]) => data.score < 70)
        .map(([ip, data]) => ({ ip, ...data }))
        .slice(0, 10)
    },
    protectionStatus: {
      ddos: 'Active',
      bruteForce: 'Active',
      injection: 'Active',
      rateLimit: 'Active',
      geoBlock: 'Active',
      honeypots: 'Active',
      aiML: 'Active',
      threatIntel: 'Active',
      botnetDetection: 'Active'
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

  // Generate sample user behavior profiles
  const sampleUsers = ['user_001', 'user_002', 'user_003', 'admin_001'];
  sampleUsers.forEach(userId => {
    // Normal user
    analyzeUserBehavior(userId, 'login', {
      ip: '192.168.1.100',
      location: 'New York',
      device: 'Chrome/Windows',
      lastLoginTime: now - 86400000
    });
    
    // Create some activity
    for (let i = 0; i < 5; i++) {
      analyzeUserBehavior(userId, 'page_view', { ip: '192.168.1.100' });
    }
  });

  // Create anomalous user
  analyzeUserBehavior('user_suspicious', 'login', {
    ip: '45.142.212.61',
    location: 'Unknown',
    device: 'Unknown/Linux',
    lastLoginTime: now - 3600000 // Logged in from New York 1 hour ago, now from Russia
  });

  // Populate known botnets
  knownBotnets.add('45.142.212.61');
  knownBotnets.add('103.224.182.45');

  // Populate C2 servers
  malwareC2Servers.add('91.198.115.23');
  malwareC2Servers.add('185.220.101.1');

  // Generate IP reputation data
  sampleIPs.forEach(ip => {
    checkThreatIntelligence(ip);
  });

  // Add some AI-detected attacks
  logAttack({
    type: 'Behavioral Anomaly',
    severity: 'High',
    ip: '45.142.212.61',
    details: 'Impossible travel detected: Login from Russia 1hr after US login',
    action: 'Account Flagged',
    timestamp: now - 1800000,
    anomalyScore: 85
  });

  logAttack({
    type: 'Botnet Detected',
    severity: 'Critical',
    ip: '103.224.182.45',
    details: 'Emotet botnet signature detected via user agent',
    action: 'IP Blocked',
    timestamp: now - 5400000,
    botnetName: 'Emotet'
  });

  logAttack({
    type: 'Threat Intelligence Match',
    severity: 'Critical',
    ip: '91.198.115.23',
    details: 'IP matched 2 threat source(s): malware-c2, abuse',
    action: 'IP Blocked',
    timestamp: now - 3600000,
    reputationScore: 5
  });
}

// Generate sample data on module load
generateSampleAttacks();
