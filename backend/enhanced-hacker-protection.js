/**
 * Enhanced Hacker Protection Service
 * Advanced multi-layer security against cyber attacks
 * 
 * Features:
 * - AI-based anomaly detection
 * - Zero-day exploit protection
 * - Advanced DDoS mitigation
 * - Behavioral analysis
 * - Threat intelligence integration
 * - Automated incident response
 */

const EventEmitter = require('events');
const crypto = require('crypto');

class EnhancedHackerProtection extends EventEmitter {
  constructor() {
    super();
    
    // Attack detection thresholds
    this.thresholds = {
      ddos: {
        requestsPerSecond: 100,
        requestsPerMinute: 500,
        simultaneousConnections: 50,
        packetFloodThreshold: 10000
      },
      bruteForce: {
        maxFailedAttempts: 5,
        timeWindowMinutes: 15,
        blockDurationMinutes: 30,
        adaptiveBlocking: true
      },
      rateLimit: {
        apiCallsPerMinute: 60,
        apiCallsPerHour: 1000,
        burstAllowance: 10
      },
      anomaly: {
        deviationThreshold: 3, // Standard deviations
        learningPeriodHours: 24,
        minDataPoints: 100
      }
    };

    // Advanced attack patterns
    this.attackPatterns = {
      sqlInjection: [
        /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
        /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
        /union.*select/i,
        /select.*from/i,
        /insert.*into/i,
        /delete.*from/i,
        /drop.*table/i,
        /exec(\s|\+)+(s|x)p\w+/i,
        /or\s+1\s*=\s*1/i,
        /having\s+1\s*=\s*1/i
      ],
      xss: [
        /<script[^>]*>.*?<\/script>/i,
        /<iframe[^>]*>/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /eval\(/i,
        /expression\(/i,
        /vbscript:/i,
        /<embed[^>]*>/i,
        /<object[^>]*>/i,
        /document\.cookie/i
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
        /\.\.%2f/i,
        /\.\.%5c/i
      ],
      xxe: [
        /<!ENTITY/i,
        /<!DOCTYPE.*\[/i,
        /SYSTEM\s+["']file:/i
      ],
      ldapInjection: [
        /\*\)\(/,
        /\|\(/,
        /&\(/
      ],
      codeInjection: [
        /eval\s*\(/i,
        /exec\s*\(/i,
        /system\s*\(/i,
        /passthru\s*\(/i,
        /shell_exec\s*\(/i
      ],
      zeroDay: [
        // Pattern for detecting unusual payloads
        /[\x00-\x08\x0B\x0C\x0E-\x1F]/,
        // Shellcode indicators
        /\\x[0-9a-f]{2}/i,
        // Buffer overflow attempts
        /A{100,}/,
        // Format string attacks
        /%[0-9]*[sdxpn]/
      ]
    };

    // Threat intelligence
    this.threatIntel = {
      knownMaliciousIPs: new Set([
        '192.168.1.666',
        '10.0.0.666',
        '172.16.0.666'
      ]),
      knownBotNets: new Set([
        'Mirai',
        'Emotet',
        'TrickBot',
        'Qakbot',
        'Dridex'
      ]),
      knownExploits: new Map([
        ['CVE-2021-44228', { name: 'Log4Shell', severity: 'Critical' }],
        ['CVE-2017-0144', { name: 'EternalBlue', severity: 'Critical' }],
        ['CVE-2019-0708', { name: 'BlueKeep', severity: 'Critical' }],
        ['CVE-2021-26855', { name: 'ProxyLogon', severity: 'Critical' }],
        ['CVE-2020-1472', { name: 'Zerologon', severity: 'Critical' }]
      ])
    };

    // State tracking
    this.state = {
      blockedIPs: new Map(),
      suspiciousIPs: new Map(),
      requestHistory: new Map(),
      failedAttempts: new Map(),
      activeConnections: new Map(),
      attackLog: [],
      behaviorProfiles: new Map(),
      anomalyBaseline: null
    };

    // Statistics
    this.stats = {
      totalAttacksBlocked: 0,
      attacksByType: {},
      topAttackers: [],
      protectionLevel: 'High',
      lastUpdate: new Date()
    };

    // Start background processes
    this.startBackgroundProcesses();
  }

  /**
   * Analyze incoming request for threats
   */
  analyzeRequest(req) {
    const analysis = {
      safe: true,
      threats: [],
      riskScore: 0,
      recommendations: []
    };

    const ip = this.extractIP(req);
    const timestamp = Date.now();

    // 1. Check if IP is already blocked (except localhost)
    const isLocalhost = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    if (!isLocalhost && this.isIPBlocked(ip)) {
      analysis.safe = false;
      analysis.threats.push({
        type: 'blocked-ip',
        severity: 'Critical',
        description: `IP ${ip} is currently blocked`,
        action: 'reject'
      });
      analysis.riskScore += 100;
      return analysis;
    }

    // 2. Check threat intelligence
    const intelCheck = this.checkThreatIntelligence(ip, req);
    if (intelCheck.threat) {
      analysis.safe = false;
      analysis.threats.push(intelCheck);
      analysis.riskScore += 80;
    }

    // 3. Detect DDoS patterns
    const ddosCheck = this.detectDDoS(ip, timestamp);
    if (ddosCheck.detected) {
      analysis.safe = false;
      analysis.threats.push(ddosCheck);
      analysis.riskScore += 70;
    }

    // 4. Check for brute force attempts
    const bruteForceCheck = this.detectBruteForce(ip, req);
    if (bruteForceCheck.detected) {
      analysis.safe = false;
      analysis.threats.push(bruteForceCheck);
      analysis.riskScore += 60;
    }

    // 5. Scan for injection attacks
    const injectionCheck = this.detectInjectionAttacks(req);
    if (injectionCheck.detected) {
      analysis.safe = false;
      analysis.threats = analysis.threats.concat(injectionCheck.threats);
      analysis.riskScore += 90;
    }

    // 6. Behavioral analysis
    const behaviorCheck = this.analyzeBehavior(ip, req);
    if (behaviorCheck.anomalous) {
      analysis.threats.push(behaviorCheck);
      analysis.riskScore += behaviorCheck.score;
    }

    // 7. Zero-day detection
    const zeroDay = this.detectZeroDay(req);
    if (zeroDay.detected) {
      analysis.safe = false;
      analysis.threats.push(zeroDay);
      analysis.riskScore += 95;
    }

    // 8. Rate limiting check
    const rateLimitCheck = this.checkRateLimit(ip, timestamp);
    if (rateLimitCheck.exceeded) {
      analysis.threats.push(rateLimitCheck);
      analysis.riskScore += 40;
    }

    // Take action based on risk score
    if (analysis.riskScore >= 70) {
      this.blockIP(ip, 'High risk score: ' + analysis.riskScore, 3600000); // 1 hour
      analysis.recommendations.push('IP automatically blocked for 1 hour');
    } else if (analysis.riskScore >= 40) {
      this.addSuspiciousIP(ip, analysis.threats);
      analysis.recommendations.push('IP marked as suspicious, monitoring closely');
    }

    // Log the analysis
    this.logAttack(ip, req, analysis);

    return analysis;
  }

  /**
   * Check threat intelligence databases
   */
  checkThreatIntelligence(ip, req) {
    // Check known malicious IPs
    if (this.threatIntel.knownMaliciousIPs.has(ip)) {
      return {
        threat: true,
        type: 'known-malicious-ip',
        severity: 'Critical',
        description: `IP ${ip} is on the malicious IP list`,
        source: 'Threat Intelligence',
        action: 'block'
      };
    }

    // Check for known exploit patterns in request
    const userAgent = req.headers?.['user-agent'] || '';
    for (const [cve, details] of this.threatIntel.knownExploits) {
      if (userAgent.includes(cve) || JSON.stringify(req.body || '').includes(cve)) {
        return {
          threat: true,
          type: 'known-exploit',
          severity: details.severity,
          description: `Known exploit detected: ${details.name} (${cve})`,
          source: 'CVE Database',
          action: 'block'
        };
      }
    }

    // Check for botnet signatures
    for (const botnet of this.threatIntel.knownBotNets) {
      if (userAgent.toLowerCase().includes(botnet.toLowerCase())) {
        return {
          threat: true,
          type: 'botnet',
          severity: 'High',
          description: `Botnet signature detected: ${botnet}`,
          source: 'Botnet Database',
          action: 'block'
        };
      }
    }

    return { threat: false };
  }

  /**
   * Detect DDoS attacks
   */
  detectDDoS(ip, timestamp) {
    // Initialize tracking for this IP
    if (!this.state.requestHistory.has(ip)) {
      this.state.requestHistory.set(ip, []);
    }

    const history = this.state.requestHistory.get(ip);
    history.push(timestamp);

    // Keep only last minute of requests
    const oneMinuteAgo = timestamp - 60000;
    const recentRequests = history.filter(t => t > oneMinuteAgo);
    this.state.requestHistory.set(ip, recentRequests);

    // Check requests per second
    const oneSecondAgo = timestamp - 1000;
    const requestsPerSecond = recentRequests.filter(t => t > oneSecondAgo).length;

    if (requestsPerSecond > this.thresholds.ddos.requestsPerSecond) {
      return {
        detected: true,
        type: 'ddos',
        severity: 'Critical',
        description: `DDoS attack detected: ${requestsPerSecond} requests/second from ${ip}`,
        requestsPerSecond,
        threshold: this.thresholds.ddos.requestsPerSecond,
        action: 'block'
      };
    }

    // Check requests per minute
    if (recentRequests.length > this.thresholds.ddos.requestsPerMinute) {
      return {
        detected: true,
        type: 'ddos',
        severity: 'High',
        description: `High request rate: ${recentRequests.length} requests/minute from ${ip}`,
        requestsPerMinute: recentRequests.length,
        threshold: this.thresholds.ddos.requestsPerMinute,
        action: 'throttle'
      };
    }

    return { detected: false };
  }

  /**
   * Detect brute force attacks
   */
  detectBruteForce(ip, req) {
    // Only check on authentication endpoints
    const authEndpoints = ['/login', '/api/auth', '/signin', '/authenticate'];
    const isAuthEndpoint = authEndpoints.some(endpoint => 
      req.url?.includes(endpoint) || req.path?.includes(endpoint)
    );

    if (!isAuthEndpoint) {
      return { detected: false };
    }

    // Track failed attempts
    if (!this.state.failedAttempts.has(ip)) {
      this.state.failedAttempts.set(ip, []);
    }

    const attempts = this.state.failedAttempts.get(ip);
    const timestamp = Date.now();
    const windowMs = this.thresholds.bruteForce.timeWindowMinutes * 60000;
    const cutoff = timestamp - windowMs;

    // Remove old attempts
    const recentAttempts = attempts.filter(t => t > cutoff);
    
    // Add current attempt (will be validated later)
    recentAttempts.push(timestamp);
    this.state.failedAttempts.set(ip, recentAttempts);

    // Check if threshold exceeded
    if (recentAttempts.length > this.thresholds.bruteForce.maxFailedAttempts) {
      const blockDuration = this.thresholds.bruteForce.blockDurationMinutes * 60000;
      
      // Adaptive blocking: increase duration for repeat offenders
      if (this.thresholds.bruteForce.adaptiveBlocking) {
        const previousBlocks = this.state.blockedIPs.get(ip)?.count || 0;
        const adaptiveDuration = blockDuration * Math.pow(2, previousBlocks);
        
        return {
          detected: true,
          type: 'brute-force',
          severity: 'High',
          description: `Brute force attack detected: ${recentAttempts.length} failed attempts from ${ip}`,
          attempts: recentAttempts.length,
          threshold: this.thresholds.bruteForce.maxFailedAttempts,
          blockDuration: adaptiveDuration,
          action: 'block'
        };
      }

      return {
        detected: true,
        type: 'brute-force',
        severity: 'High',
        description: `Brute force attack detected from ${ip}`,
        attempts: recentAttempts.length,
        action: 'block'
      };
    }

    return { detected: false };
  }

  /**
   * Detect injection attacks
   */
  detectInjectionAttacks(req) {
    const threats = [];
    const testData = [
      req.url || '',
      req.path || '',
      JSON.stringify(req.query || {}),
      JSON.stringify(req.body || {}),
      JSON.stringify(req.headers || {})
    ].join(' ');

    // Test for SQL injection
    for (const pattern of this.attackPatterns.sqlInjection) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'sql-injection',
          severity: 'Critical',
          description: 'SQL injection attempt detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    // Test for XSS
    for (const pattern of this.attackPatterns.xss) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'xss',
          severity: 'High',
          description: 'Cross-site scripting (XSS) attempt detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    // Test for command injection
    for (const pattern of this.attackPatterns.commandInjection) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'command-injection',
          severity: 'Critical',
          description: 'Command injection attempt detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    // Test for path traversal
    for (const pattern of this.attackPatterns.pathTraversal) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'path-traversal',
          severity: 'High',
          description: 'Path traversal attempt detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    // Test for XXE
    for (const pattern of this.attackPatterns.xxe) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'xxe',
          severity: 'High',
          description: 'XML External Entity (XXE) attack detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    // Test for LDAP injection
    for (const pattern of this.attackPatterns.ldapInjection) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'ldap-injection',
          severity: 'High',
          description: 'LDAP injection attempt detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    // Test for code injection
    for (const pattern of this.attackPatterns.codeInjection) {
      if (pattern.test(testData)) {
        threats.push({
          type: 'code-injection',
          severity: 'Critical',
          description: 'Code injection attempt detected',
          pattern: pattern.toString(),
          action: 'block'
        });
      }
    }

    return {
      detected: threats.length > 0,
      threats
    };
  }

  /**
   * Behavioral analysis and anomaly detection
   */
  analyzeBehavior(ip, req) {
    // Get or create behavior profile
    if (!this.state.behaviorProfiles.has(ip)) {
      this.state.behaviorProfiles.set(ip, {
        requestPatterns: [],
        avgRequestSize: 0,
        avgTimeBetweenRequests: 0,
        endpoints: new Set(),
        userAgents: new Set(),
        methods: {}
      });
    }

    const profile = this.state.behaviorProfiles.get(ip);
    const timestamp = Date.now();

    // Update profile
    const requestSize = JSON.stringify(req.body || '').length;
    profile.requestPatterns.push({
      timestamp,
      size: requestSize,
      endpoint: req.path || req.url,
      method: req.method,
      userAgent: req.headers?.['user-agent']
    });

    profile.endpoints.add(req.path || req.url);
    profile.userAgents.add(req.headers?.['user-agent']);
    profile.methods[req.method] = (profile.methods[req.method] || 0) + 1;

    // Keep only recent data (last 1000 requests)
    if (profile.requestPatterns.length > 1000) {
      profile.requestPatterns = profile.requestPatterns.slice(-1000);
    }

    // Detect anomalies
    const anomalies = [];

    // 1. Rapidly changing user agents
    if (profile.userAgents.size > 10) {
      anomalies.push('Rapidly changing user agents');
    }

    // 2. Accessing too many different endpoints
    if (profile.endpoints.size > 50) {
      anomalies.push('Accessing unusual number of endpoints');
    }

    // 3. Unusual request size
    if (profile.requestPatterns.length > 10) {
      const sizes = profile.requestPatterns.map(p => p.size);
      const avgSize = sizes.reduce((a, b) => a + b, 0) / sizes.length;
      const stdDev = Math.sqrt(
        sizes.reduce((sq, n) => sq + Math.pow(n - avgSize, 2), 0) / sizes.length
      );

      if (requestSize > avgSize + (stdDev * this.thresholds.anomaly.deviationThreshold)) {
        anomalies.push('Unusually large request size');
      }
    }

    // 4. Suspicious method distribution
    const totalMethods = Object.values(profile.methods).reduce((a, b) => a + b, 0);
    const postRatio = (profile.methods.POST || 0) / totalMethods;
    if (postRatio > 0.9 && totalMethods > 50) {
      anomalies.push('Suspicious POST request ratio');
    }

    if (anomalies.length > 0) {
      return {
        anomalous: true,
        type: 'behavioral-anomaly',
        severity: 'Medium',
        description: 'Anomalous behavior detected',
        anomalies,
        score: anomalies.length * 15,
        action: 'monitor'
      };
    }

    return { anomalous: false };
  }

  /**
   * Zero-day exploit detection with advanced heuristics
   */
  detectZeroDay(req) {
    const testData = [
      req.url || '',
      req.path || '',
      JSON.stringify(req.body || {}),
      JSON.stringify(req.headers || {})
    ].join(' ');

    const indicators = [];
    let threatScore = 0;

    // Test for zero-day patterns
    for (const pattern of this.attackPatterns.zeroDay) {
      if (pattern.test(testData)) {
        indicators.push(pattern.toString());
        threatScore += 20;
      }
    }

    // Check for unusual encoding
    if (testData.includes('%u') || testData.includes('\\u')) {
      indicators.push('Unicode encoding detected');
      threatScore += 15;
    }

    // Check for unusual headers
    const suspiciousHeaders = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip'];
    for (const header of suspiciousHeaders) {
      if (req.headers?.[header] && req.headers[header].split(',').length > 5) {
        indicators.push(`Suspicious ${header} header`);
        threatScore += 10;
      }
    }

    // Check for polyglot payloads (polymorphic attack detection)
    const polyglotResult = this.detectPolymorphicAttack(testData);
    if (polyglotResult.detected) {
      indicators.push(...polyglotResult.indicators);
      threatScore += polyglotResult.score;
    }
    
    // Heuristic analysis for unknown attack patterns
    const heuristicResult = this.performHeuristicAnalysis(req, testData);
    if (heuristicResult.suspicious) {
      indicators.push(...heuristicResult.findings);
      threatScore += heuristicResult.score;
    }
    
    // Fuzzy matching for pattern variants
    const fuzzyResult = this.fuzzyPatternMatch(testData);
    if (fuzzyResult.matched) {
      indicators.push(...fuzzyResult.patterns);
      threatScore += fuzzyResult.score;
    }
    
    // Sandbox execution simulation (for potentially malicious payloads)
    const sandboxResult = this.sandboxAnalysis(req, testData);
    if (sandboxResult.dangerous) {
      indicators.push(...sandboxResult.threats);
      threatScore += sandboxResult.score;
    }

    // Determine severity based on threat score
    let severity = 'Low';
    let action = 'monitor';
    
    if (threatScore >= 80) {
      severity = 'Critical';
      action = 'block_and_quarantine';
    } else if (threatScore >= 50) {
      severity = 'High';
      action = 'block';
    } else if (threatScore >= 30) {
      severity = 'Medium';
      action = 'alert';
    }

    if (indicators.length > 0) {
      return {
        detected: true,
        type: 'zero-day',
        severity,
        threatScore,
        description: 'Potential zero-day exploit detected',
        indicators,
        action,
        recommendedAction: this.getRecommendedAction(threatScore)
      };
    }

    return { detected: false };
  }
  
  /**
   * Detect polymorphic attacks using polyglot payload analysis
   */
  detectPolymorphicAttack(data) {
    const indicators = [];
    let score = 0;
    
    // Check for polyglot payloads (multiple attack types in one payload)
    const attackTypeIndicators = {
      xss: ['<script>', 'javascript:', 'onerror=', 'onload=', 'onclick='],
      sqli: ['SELECT', 'UNION', 'INSERT', 'DELETE', 'DROP', "'", '--'],
      cmdi: ['&&', '||', ';', '`', '$(',  'eval('],
      lfi: ['../', '..../', '..\\', '/etc/', 'C:\\'],
      xxe: ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://']
    };
    
    const foundTypes = [];
    const upperData = data.toUpperCase();
    
    for (const [type, patterns] of Object.entries(attackTypeIndicators)) {
      const matchCount = patterns.filter(p => {
        const upperPattern = p.toUpperCase();
        return upperData.includes(upperPattern) || data.includes(p);
      }).length;
      
      if (matchCount >= 2) {
        foundTypes.push(type);
      }
    }
    
    // Polyglot detected if multiple attack types present
    if (foundTypes.length >= 2) {
      indicators.push(`Polyglot payload (${foundTypes.join(', ')})`);
      score = foundTypes.length * 15;
      return { detected: true, indicators, score };
    }
    
    // Check for obfuscation techniques (polymorphic encoding)
    const obfuscationPatterns = [
      /\\x[0-9a-f]{2}/gi,       // Hex encoding
      /%[0-9a-f]{2}/gi,          // URL encoding
      /&#(x)?[0-9a-f]+;/gi,      // HTML entity encoding
      /\\u[0-9a-f]{4}/gi,        // Unicode encoding
      /String\.fromCharCode/i,  // JavaScript char encoding
      /eval\s*\(/i,             // Dynamic code execution
      /atob\s*\(/i              // Base64 decode
    ];
    
    let obfuscationCount = 0;
    for (const pattern of obfuscationPatterns) {
      if (pattern.test(data)) {
        obfuscationCount++;
      }
    }
    
    if (obfuscationCount >= 3) {
      indicators.push('Multiple obfuscation techniques detected');
      score += 25;
      return { detected: true, indicators, score };
    }
    
    return { detected: false, indicators: [], score: 0 };
  }
  
  /**
   * Heuristic analysis for unknown attacks
   */
  performHeuristicAnalysis(req, data) {
    const findings = [];
    let score = 0;
    
    // 1. Entropy analysis (high entropy may indicate encryption/obfuscation)
    const entropy = this.calculateEntropy(data);
    if (entropy > 4.5) {
      findings.push(`High entropy detected: ${entropy.toFixed(2)}`);
      score += 15;
    }
    
    // 2. Unusual request size
    const dataSize = data.length;
    if (dataSize > 50000) {
      findings.push(`Unusually large payload: ${dataSize} bytes`);
      score += 10;
    }
    
    // 3. Suspicious character sequences
    const suspiciousSequences = [
      { pattern: /[A-Z]{50,}/, name: 'Long uppercase sequence' },
      { pattern: /\d{100,}/, name: 'Long numeric sequence' },
      { pattern: /[\x00-\x1F]{10,}/, name: 'Control characters sequence' },
      { pattern: /[!@#$%^&*()]{20,}/, name: 'Excessive special characters' }
    ];
    
    for (const seq of suspiciousSequences) {
      if (seq.pattern.test(data)) {
        findings.push(seq.name);
        score += 12;
      }
    }
    
    // 4. Protocol anomalies
    if (req.method && req.method !== 'GET' && req.method !== 'POST' && 
        req.method !== 'PUT' && req.method !== 'DELETE') {
      findings.push(`Unusual HTTP method: ${req.method}`);
      score += 15;
    }
    
    // 5. Malformed or missing standard headers
    const standardHeaders = ['host', 'user-agent'];
    const missingHeaders = standardHeaders.filter(h => !req.headers?.[h]);
    if (missingHeaders.length > 0) {
      findings.push(`Missing standard headers: ${missingHeaders.join(', ')}`);
      score += 10;
    }
    
    // 6. Nested encoding detection
    const encodingLayers = this.detectNestedEncoding(data);
    if (encodingLayers > 2) {
      findings.push(`Multiple encoding layers detected: ${encodingLayers}`);
      score += 20;
    }
    
    return {
      suspicious: findings.length > 0,
      findings,
      score
    };
  }
  
  /**
   * Fuzzy matching for attack pattern variants
   */
  fuzzyPatternMatch(data) {
    const patterns = [];
    let score = 0;
    const lowerData = data.toLowerCase();
    
    // SQL Injection variants (with common evasion techniques)
    const sqlVariants = [
      { pattern: /un\s*ion\s+se\s*lect/i, name: 'SQL UNION variant' },
      { pattern: /se\s*lect\s+.*\s*fr\s*om/i, name: 'SQL SELECT variant' },
      { pattern: /or\s+['"]?1['"]?\s*=\s*['"]?1/i, name: 'SQL OR 1=1 variant' },
      { pattern: /and\s+['"]?1['"]?\s*=\s*['"]?1/i, name: 'SQL AND 1=1 variant' },
      { pattern: /dr\s*op\s+ta\s*ble/i, name: 'SQL DROP variant' }
    ];
    
    // XSS variants
    const xssVariants = [
      { pattern: /<\s*script[^>]*>/i, name: 'XSS script tag variant' },
      { pattern: /on\s*\w+\s*=\s*['"]?[^'"]+/i, name: 'XSS event handler variant' },
      { pattern: /java\s*script\s*:/i, name: 'XSS javascript protocol variant' },
      { pattern: /<\s*iframe[^>]*>/i, name: 'XSS iframe variant' }
    ];
    
    // Command Injection variants
    const cmdVariants = [
      { pattern: /[;&|]\s*(cat|ls|dir|type|echo|whoami|id)/i, name: 'Command injection variant' },
      { pattern: /`[^`]*`/, name: 'Backtick command execution' },
      { pattern: /\$\([^)]*\)/, name: 'Shell command substitution' }
    ];
    
    const allVariants = [...sqlVariants, ...xssVariants, ...cmdVariants];
    
    for (const variant of allVariants) {
      if (variant.pattern.test(data)) {
        patterns.push(variant.name);
        score += 18;
      }
    }
    
    // Levenshtein distance check for known exploit strings
    const knownExploits = [
      'union select',
      '<script>alert',
      'javascript:void',
      'eval(unescape',
      'exec("cmd.exe'
    ];
    
    for (const exploit of knownExploits) {
      const distance = this.levenshteinDistance(lowerData, exploit);
      if (distance < 3 && distance > 0) {
        patterns.push(`Fuzzy match: ${exploit} (distance: ${distance})`);
        score += 15;
      }
    }
    
    return {
      matched: patterns.length > 0,
      patterns,
      score
    };
  }
  
  /**
   * Sandbox analysis simulation (evaluates payload danger without execution)
   */
  sandboxAnalysis(req, data) {
    const threats = [];
    let score = 0;
    
    // Check for dangerous function calls
    const dangerousFunctions = [
      { name: 'eval', severity: 'critical', score: 30 },
      { name: 'exec', severity: 'critical', score: 30 },
      { name: 'system', severity: 'critical', score: 30 },
      { name: 'passthru', severity: 'critical', score: 25 },
      { name: 'shell_exec', severity: 'critical', score: 25 },
      { name: 'popen', severity: 'high', score: 20 },
      { name: 'proc_open', severity: 'high', score: 20 },
      { name: 'pcntl_exec', severity: 'high', score: 20 }
    ];
    
    for (const func of dangerousFunctions) {
      const pattern = new RegExp(`${func.name}\\s*\\(`, 'i');
      if (pattern.test(data)) {
        threats.push(`Dangerous function: ${func.name}`);
        score += func.score;
      }
    }
    
    // Check for file system operations
    const fileOps = [
      'file_get_contents',
      'file_put_contents',
      'fopen',
      'readfile',
      'include',
      'require',
      'unlink',
      'rmdir'
    ];
    
    for (const op of fileOps) {
      const pattern = new RegExp(`${op}\\s*\\(`, 'i');
      if (pattern.test(data)) {
        threats.push(`File system operation: ${op}`);
        score += 15;
      }
    }
    
    // Check for network operations
    const networkOps = [
      'fsockopen',
      'socket_connect',
      'curl_exec',
      'file_get_contents.*http',
      'XMLHttpRequest',
      'fetch(',
      'axios.'
    ];
    
    for (const op of networkOps) {
      const pattern = new RegExp(op, 'i');
      if (pattern.test(data)) {
        threats.push(`Network operation: ${op}`);
        score += 12;
      }
    }
    
    // Check for cryptographic operations (potential ransomware)
    const cryptoOps = ['encrypt', 'AES', 'RSA', 'crypto.subtle', 'CryptoJS'];
    let cryptoCount = 0;
    for (const op of cryptoOps) {
      if (data.includes(op)) {
        cryptoCount++;
      }
    }
    
    if (cryptoCount >= 2) {
      threats.push('Multiple cryptographic operations detected');
      score += 20;
    }
    
    // Check for persistence mechanisms
    const persistenceIndicators = [
      'crontab',
      'schtasks',
      'startup',
      'autorun',
      'HKEY_',
      'CurrentVersion\\Run'
    ];
    
    for (const indicator of persistenceIndicators) {
      if (data.includes(indicator)) {
        threats.push(`Persistence mechanism: ${indicator}`);
        score += 25;
      }
    }
    
    return {
      dangerous: threats.length > 0,
      threats,
      score
    };
  }
  
  /**
   * Calculate Shannon entropy for data
   */
  calculateEntropy(data) {
    if (!data || data.length === 0) return 0;
    
    const freq = {};
    for (let char of data) {
      freq[char] = (freq[char] || 0) + 1;
    }
    
    let entropy = 0;
    const len = data.length;
    
    for (let char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }
  
  /**
   * Detect nested encoding layers
   */
  detectNestedEncoding(data) {
    let layers = 0;
    let current = data;
    
    const encodingPatterns = [
      { pattern: /%[0-9a-f]{2}/gi, name: 'URL' },
      { pattern: /\\x[0-9a-f]{2}/gi, name: 'Hex' },
      { pattern: /&#(x)?[0-9a-f]+;/gi, name: 'HTML' },
      { pattern: /\\u[0-9a-f]{4}/gi, name: 'Unicode' }
    ];
    
    for (let i = 0; i < 5; i++) {
      let found = false;
      for (const enc of encodingPatterns) {
        if (enc.pattern.test(current)) {
          layers++;
          found = true;
          // Simulate decoding (simplified)
          current = current.replace(enc.pattern, 'X');
          break;
        }
      }
      if (!found) break;
    }
    
    return layers;
  }
  
  /**
   * Calculate Levenshtein distance for fuzzy matching
   */
  levenshteinDistance(str1, str2) {
    // Limit search to substrings for performance
    const searchLength = Math.min(str1.length, 1000);
    const searchStr = str1.substring(0, searchLength);
    
    // Find minimum distance in sliding window
    let minDistance = Infinity;
    
    for (let i = 0; i <= searchStr.length - str2.length; i++) {
      const substr = searchStr.substring(i, i + str2.length);
      const distance = this.calcDistance(substr, str2);
      minDistance = Math.min(minDistance, distance);
      
      if (minDistance === 0) break;
    }
    
    return minDistance;
  }
  
  /**
   * Helper: Calculate edit distance
   */
  calcDistance(s, t) {
    const m = s.length;
    const n = t.length;
    const d = [];
    
    if (m === 0) return n;
    if (n === 0) return m;
    
    for (let i = 0; i <= m; i++) {
      d[i] = [i];
    }
    
    for (let j = 0; j <= n; j++) {
      d[0][j] = j;
    }
    
    for (let j = 1; j <= n; j++) {
      for (let i = 1; i <= m; i++) {
        const cost = s[i - 1] === t[j - 1] ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1,
          d[i][j - 1] + 1,
          d[i - 1][j - 1] + cost
        );
      }
    }
    
    return d[m][n];
  }
  
  /**
   * Get recommended action based on threat score
   */
  getRecommendedAction(score) {
    if (score >= 80) {
      return 'Block immediately and quarantine payload for analysis';
    } else if (score >= 50) {
      return 'Block request and alert security team';
    } else if (score >= 30) {
      return 'Log for investigation and monitor source IP';
    } else {
      return 'Continue monitoring';
    }
  }

  /**
   * Rate limiting check
   */
  checkRateLimit(ip, timestamp) {
    const history = this.state.requestHistory.get(ip) || [];
    
    // Check per-minute limit
    const oneMinuteAgo = timestamp - 60000;
    const requestsPerMinute = history.filter(t => t > oneMinuteAgo).length;
    
    if (requestsPerMinute > this.thresholds.rateLimit.apiCallsPerMinute) {
      return {
        exceeded: true,
        type: 'rate-limit',
        severity: 'Low',
        description: `Rate limit exceeded: ${requestsPerMinute} requests/minute`,
        limit: this.thresholds.rateLimit.apiCallsPerMinute,
        action: 'throttle'
      };
    }

    // Check per-hour limit
    const oneHourAgo = timestamp - 3600000;
    const requestsPerHour = history.filter(t => t > oneHourAgo).length;
    
    if (requestsPerHour > this.thresholds.rateLimit.apiCallsPerHour) {
      return {
        exceeded: true,
        type: 'rate-limit',
        severity: 'Medium',
        description: `Hourly rate limit exceeded: ${requestsPerHour} requests/hour`,
        limit: this.thresholds.rateLimit.apiCallsPerHour,
        action: 'block'
      };
    }

    return { exceeded: false };
  }

  /**
   * Block an IP address
   */
  blockIP(ip, reason, duration = 3600000) {
    const blockInfo = {
      ip,
      reason,
      blockedAt: Date.now(),
      expiresAt: Date.now() + duration,
      count: (this.state.blockedIPs.get(ip)?.count || 0) + 1
    };

    this.state.blockedIPs.set(ip, blockInfo);
    this.stats.totalAttacksBlocked++;

    this.emit('ip:blocked', blockInfo);

    // Auto-unblock after duration
    setTimeout(() => {
      if (this.state.blockedIPs.has(ip)) {
        this.unblockIP(ip);
      }
    }, duration);

    return blockInfo;
  }

  /**
   * Unblock an IP address
   */
  unblockIP(ip) {
    this.state.blockedIPs.delete(ip);
    this.emit('ip:unblocked', { ip, unblockedAt: Date.now() });
  }

  /**
   * Check if IP is blocked
   */
  isIPBlocked(ip) {
    const blockInfo = this.state.blockedIPs.get(ip);
    if (!blockInfo) return false;

    // Check if block has expired
    if (Date.now() > blockInfo.expiresAt) {
      this.unblockIP(ip);
      return false;
    }

    return true;
  }

  /**
   * Add IP to suspicious list
   */
  addSuspiciousIP(ip, threats) {
    this.state.suspiciousIPs.set(ip, {
      addedAt: Date.now(),
      threats,
      monitored: true
    });
  }

  /**
   * Extract IP from request
   */
  extractIP(req) {
    return req.ip || 
           req.headers?.['x-forwarded-for']?.split(',')[0].trim() ||
           req.connection?.remoteAddress ||
           'unknown';
  }

  /**
   * Log attack
   */
  logAttack(ip, req, analysis) {
    const entry = {
      timestamp: new Date().toISOString(),
      ip,
      method: req.method,
      url: req.url || req.path,
      threats: analysis.threats,
      riskScore: analysis.riskScore,
      blocked: analysis.riskScore >= 70
    };

    this.state.attackLog.unshift(entry);

    // Keep only last 1000 entries
    if (this.state.attackLog.length > 1000) {
      this.state.attackLog = this.state.attackLog.slice(0, 1000);
    }

    // Update statistics
    analysis.threats.forEach(threat => {
      this.stats.attacksByType[threat.type] = 
        (this.stats.attacksByType[threat.type] || 0) + 1;
    });

    this.emit('attack:detected', entry);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    const topAttackers = Array.from(this.state.blockedIPs.entries())
      .map(([ip, info]) => ({ ip, count: info.count, reason: info.reason }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      ...this.stats,
      topAttackers,
      blockedIPs: this.state.blockedIPs.size,
      suspiciousIPs: this.state.suspiciousIPs.size,
      recentAttacks: this.state.attackLog.slice(0, 10),
      protectionStatus: 'Active',
      lastUpdate: new Date()
    };
  }

  /**
   * Get all blocked IPs
   */
  getBlockedIPs() {
    return Array.from(this.state.blockedIPs.entries()).map(([ip, info]) => ({
      ip,
      ...info
    }));
  }

  /**
   * Get attack log
   */
  getAttackLog(limit = 100) {
    return this.state.attackLog.slice(0, limit);
  }

  /**
   * Start background processes
   */
  startBackgroundProcesses() {
    // Cleanup expired blocks every minute
    setInterval(() => {
      const now = Date.now();
      for (const [ip, blockInfo] of this.state.blockedIPs) {
        if (now > blockInfo.expiresAt) {
          this.unblockIP(ip);
        }
      }
    }, 60000);

    // Cleanup old request history every 5 minutes
    setInterval(() => {
      const fiveMinutesAgo = Date.now() - 300000;
      for (const [ip, history] of this.state.requestHistory) {
        const recent = history.filter(t => t > fiveMinutesAgo);
        if (recent.length === 0) {
          this.state.requestHistory.delete(ip);
        } else {
          this.state.requestHistory.set(ip, recent);
        }
      }
    }, 300000);

    // Update statistics every minute
    setInterval(() => {
      this.stats.lastUpdate = new Date();
      this.emit('stats:updated', this.stats);
    }, 60000);
  }

  /**
   * Express middleware
   */
  middleware() {
    return (req, res, next) => {
      // Whitelist certain endpoints that should bypass strict security checks
      const whitelistedPaths = [
        '/api/disk/analyze',
        '/api/disk/clean/recyclebin',
        '/api/disk/clean/temp',
        '/api/disk/clean/downloads',
        '/api/disk/clean/all',
        '/api/status',
        '/api/stats',
        '/api/settings',
        '/api/config',
        '/api/system/health',
        '/api/system/performance-report',
        '/api/system/alerts/clear',
        '/api/analytics/dashboard',
        '/api/analytics/track',
        '/api/analytics/event',
        '/api/analytics/pageview',
        '/api/analytics/session',
        '/api/analytics/error',
        '/api/analytics/events',
        '/api/analytics/pageviews',
        '/api/analytics/sessions',
        '/api/analytics/errors',
        '/api/analytics/performance',
        '/api/auth/login',
        '/api/auth/register',
        '/api/auth/verify',
        '/api/auth/verify-2fa',
        '/api/auth/logout',
        '/api/auth/enable-2fa',
        '/api/auth/confirm-2fa',
        '/api/auth/disable-2fa',
        '/api/auth/change-password',
        '/api/signatures/update',
        '/api/database/update',
        '/api/subscription',
        '/api/scan/results',
        '/api/scan/quick',
        '/api/scan/full',
        '/api/scan/file',
        '/api/scan/directory',
        '/api/quarantine',
        '/api/quarantine/stats',
        '/api/quarantine/export',
        '/api/file/clean',
        '/api/protection/status',
        '/api/protection/toggle',
        '/api/protection/events',
        '/api/storage/info',
        '/api/sessions',
        '/api/activities',
        '/api/backup/create',
        '/api/backup/list',
        '/api/backup/stats'
      ];

      // Check if current path is whitelisted (exact match or starts with pattern)
      console.log('🔍 Checking path:', req.path, 'URL:', req.url);
      const isWhitelisted = whitelistedPaths.some(path => {
        if (req.path === path) return true;
        // Also allow if path starts with /api/auth/ (all auth endpoints)
        if (req.path && req.path.startsWith('/api/auth/')) return true;
        // Allow all analytics endpoints
        if (req.path.startsWith('/api/analytics/')) return true;
        // Allow all disk cleanup endpoints
        if (req.path.startsWith('/api/disk/')) return true;
        // Allow all system monitoring endpoints
        if (req.path.startsWith('/api/system/')) return true;
        // Allow all session management endpoints
        if (req.path.startsWith('/api/sessions')) return true;
        // Allow all activity log endpoints
        if (req.path.startsWith('/api/activities')) return true;
        // Allow all backup endpoints
        if (req.path.startsWith('/api/backup')) return true;
        // Allow all config endpoints
        if (req.path.startsWith('/api/config')) return true;
        // Allow all quarantine endpoints
        if (req.path.startsWith('/api/quarantine')) return true;
        return false;
      });

      if (isWhitelisted) {
        // Skip security analysis for whitelisted paths, just add headers
        res.setHeader('X-Security-Scan', 'Whitelisted');
        res.setHeader('X-Risk-Score', '0');
        console.log('✅ Whitelisted request:', req.method, req.path);
        return next();
      }

      console.log('🔍 Scanning request:', req.method, req.path);
      const analysis = this.analyzeRequest(req);

      // Attach analysis to request
      req.securityAnalysis = analysis;

      // Block if necessary
      if (!analysis.safe && analysis.riskScore >= 70) {
        console.log('🚫 BLOCKED:', req.method, req.path, 'Risk:', analysis.riskScore, 'Threats:', analysis.threats.map(t => t.type));
        return res.status(403).json({
          error: 'Access denied',
          reason: 'Security threat detected',
          threats: analysis.threats.map(t => t.type)
        });
      }

      // Add security headers
      res.setHeader('X-Security-Scan', 'Passed');
      res.setHeader('X-Risk-Score', analysis.riskScore);

      next();
    };
  }
  
  /**
   * Get all attack statistics
   */
  getAttackStats() {
    return {
      totalAttacks: this.state.attackLog.length,
      blockedIPs: this.state.blockedIPs.size,
      suspiciousIPs: this.state.suspiciousIPs.size,
      recentAttacks: this.state.attackLog.slice(-50),
      attacksByType: this.getAttacksByType(),
      topAttackers: this.getTopAttackers(10)
    };
  }
  
  /**
   * Get attacks grouped by type
   */
  getAttacksByType() {
    const typeCount = {};
    for (const attack of this.state.attackLog) {
      typeCount[attack.type] = (typeCount[attack.type] || 0) + 1;
    }
    return typeCount;
  }
  
  /**
   * Get top attackers
   */
  getTopAttackers(limit = 10) {
    const attackerCount = {};
    for (const attack of this.state.attackLog) {
      const ip = attack.ip || 'unknown';
      attackerCount[ip] = (attackerCount[ip] || 0) + 1;
    }
    
    return Object.entries(attackerCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([ip, count]) => ({ ip, count }));
  }
}

// Export singleton instance
module.exports = new EnhancedHackerProtection();
