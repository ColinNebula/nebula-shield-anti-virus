/**
 * Authentication Hardening Service
 * Provides advanced authentication security with device fingerprinting,
 * behavioral biometrics, and anomaly detection
 */

import EventEmitter from 'events';
import crypto from 'crypto';
import os from 'os';

class AuthenticationHardeningService extends EventEmitter {
  constructor() {
    super();
    this.deviceFingerprints = new Map();
    this.userBehaviorProfiles = new Map();
    this.activeSessions = new Map();
    this.suspiciousLocations = new Set();
    this.loginAttempts = new Map();
    this.maxLoginAttempts = 5;
    this.lockoutDuration = 15 * 60 * 1000; // 15 minutes
    this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
    this.behavioralThreshold = 0.7; // 70% similarity threshold
    
    this.initializeService();
  }

  /**
   * Initialize authentication hardening service
   */
  initializeService() {
    // Start session monitor
    setInterval(() => this.monitorActiveSessions(), 60000);
    
    // Clean up old login attempts
    setInterval(() => this.cleanupLoginAttempts(), 300000);
    
    this.emit('service-initialized');
  }

  /**
   * Generate comprehensive device fingerprint
   */
  async generateDeviceFingerprint(context) {
    const fingerprint = {
      id: crypto.randomBytes(16).toString('hex'),
      timestamp: new Date().toISOString(),
      hardware: {
        cpu: this.getCPUInfo(),
        memory: os.totalmem(),
        platform: os.platform(),
        arch: os.arch(),
        hostname: os.hostname(),
        macAddresses: this.getMACAddresses()
      },
      software: {
        osVersion: os.release(),
        nodeVersion: process.version,
        userAgent: context.userAgent || 'Unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: context.language || 'en-US',
        screenResolution: context.screenResolution || 'Unknown'
      },
      browser: {
        canvas: context.canvasFingerprint,
        webgl: context.webglFingerprint,
        fonts: context.installedFonts || [],
        plugins: context.plugins || [],
        cookiesEnabled: context.cookiesEnabled !== false,
        doNotTrack: context.doNotTrack || false
      },
      network: {
        ipAddress: context.ipAddress,
        proxy: context.proxyDetected || false,
        vpn: context.vpnDetected || false,
        tor: context.torDetected || false
      },
      hash: null
    };

    // Generate unique hash of all fingerprint data
    fingerprint.hash = this.hashFingerprint(fingerprint);
    
    this.deviceFingerprints.set(fingerprint.hash, fingerprint);
    this.emit('fingerprint-generated', fingerprint);
    
    return fingerprint;
  }

  /**
   * Verify device fingerprint
   */
  verifyDeviceFingerprint(fingerprintHash, context) {
    const storedFingerprint = this.deviceFingerprints.get(fingerprintHash);
    
    if (!storedFingerprint) {
      return {
        verified: false,
        reason: 'UNKNOWN_DEVICE',
        confidence: 0
      };
    }

    const currentFingerprint = {
      hardware: {
        cpu: this.getCPUInfo(),
        memory: os.totalmem(),
        platform: os.platform(),
        arch: os.arch(),
        hostname: os.hostname()
      },
      software: {
        osVersion: os.release(),
        userAgent: context.userAgent || 'Unknown',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      network: {
        ipAddress: context.ipAddress
      }
    };

    const similarity = this.calculateFingerprintSimilarity(
      storedFingerprint,
      currentFingerprint
    );

    const verified = similarity >= 0.85; // 85% match required

    return {
      verified,
      confidence: similarity,
      reason: verified ? 'DEVICE_VERIFIED' : 'DEVICE_MISMATCH',
      changes: this.detectFingerprintChanges(storedFingerprint, currentFingerprint)
    };
  }

  /**
   * Analyze behavioral biometrics
   */
  async analyzeBehavioralBiometrics(userId, behavior) {
    const profile = this.userBehaviorProfiles.get(userId) || this.createBehaviorProfile(userId);
    
    const analysis = {
      userId,
      timestamp: new Date().toISOString(),
      metrics: {
        typingPattern: this.analyzeTypingPattern(behavior.typing, profile.typing),
        mouseMovement: this.analyzeMouseMovement(behavior.mouse, profile.mouse),
        navigationPattern: this.analyzeNavigationPattern(behavior.navigation, profile.navigation),
        timeOfDay: this.analyzeTimePattern(behavior.timestamp, profile.activeTimes),
        sessionDuration: this.analyzeSessionDuration(behavior.sessionStart, profile.avgSessionDuration)
      },
      overallScore: 0,
      anomalies: [],
      trustLevel: 'HIGH'
    };

    // Calculate overall behavioral score
    const scores = Object.values(analysis.metrics);
    analysis.overallScore = scores.reduce((sum, metric) => sum + metric.score, 0) / scores.length;

    // Detect anomalies
    if (analysis.metrics.typingPattern.score < this.behavioralThreshold) {
      analysis.anomalies.push('UNUSUAL_TYPING_PATTERN');
    }
    if (analysis.metrics.mouseMovement.score < this.behavioralThreshold) {
      analysis.anomalies.push('UNUSUAL_MOUSE_BEHAVIOR');
    }
    if (analysis.metrics.navigationPattern.score < this.behavioralThreshold) {
      analysis.anomalies.push('UNUSUAL_NAVIGATION');
    }

    // Determine trust level
    if (analysis.overallScore < 0.5) {
      analysis.trustLevel = 'LOW';
    } else if (analysis.overallScore < 0.7) {
      analysis.trustLevel = 'MEDIUM';
    }

    // Update behavior profile
    this.updateBehaviorProfile(userId, behavior);

    this.emit('behavior-analyzed', analysis);
    return analysis;
  }

  /**
   * Detect anomalous login locations
   */
  async detectAnomalousLocation(userId, location) {
    const profile = this.userBehaviorProfiles.get(userId);
    
    if (!profile || !profile.locations || profile.locations.length === 0) {
      // First login or no location history
      this.addLocationToProfile(userId, location);
      return {
        anomalous: false,
        reason: 'FIRST_LOGIN',
        riskScore: 0
      };
    }

    const analysis = {
      anomalous: false,
      reason: null,
      riskScore: 0,
      details: {
        distance: 0,
        timeTravel: false,
        newCountry: false,
        vpnDetected: false,
        torDetected: false
      }
    };

    // Get last known location
    const lastLocation = profile.locations[profile.locations.length - 1];
    
    // Calculate distance
    analysis.details.distance = this.calculateDistance(
      lastLocation.coordinates,
      location.coordinates
    );

    // Check for impossible travel
    const timeDiff = new Date(location.timestamp) - new Date(lastLocation.timestamp);
    const maxPossibleDistance = (timeDiff / 3600000) * 900; // 900 km/h (airplane speed)
    
    if (analysis.details.distance > maxPossibleDistance) {
      analysis.anomalous = true;
      analysis.reason = 'IMPOSSIBLE_TRAVEL';
      analysis.details.timeTravel = true;
      analysis.riskScore += 0.4;
    }

    // Check for new country
    if (lastLocation.country !== location.country) {
      const countryHistory = profile.locations.map(l => l.country);
      if (!countryHistory.includes(location.country)) {
        analysis.anomalous = true;
        analysis.reason = analysis.reason || 'NEW_COUNTRY';
        analysis.details.newCountry = true;
        analysis.riskScore += 0.3;
      }
    }

    // Check for VPN/Tor
    if (location.vpnDetected || location.torDetected) {
      analysis.anomalous = true;
      analysis.reason = analysis.reason || 'ANONYMIZATION_DETECTED';
      analysis.details.vpnDetected = location.vpnDetected;
      analysis.details.torDetected = location.torDetected;
      analysis.riskScore += 0.2;
    }

    // Check for suspicious regions
    if (this.suspiciousLocations.has(location.country)) {
      analysis.riskScore += 0.1;
    }

    // Add location to profile if not too anomalous
    if (analysis.riskScore < 0.5) {
      this.addLocationToProfile(userId, location);
    }

    this.emit('location-analyzed', { userId, analysis });
    return analysis;
  }

  /**
   * Prevent session hijacking
   */
  async preventSessionHijacking(sessionId, context) {
    const session = this.activeSessions.get(sessionId);
    
    if (!session) {
      return {
        hijacked: false,
        reason: 'SESSION_NOT_FOUND',
        action: 'DENY'
      };
    }

    const checks = {
      ipMismatch: session.ipAddress !== context.ipAddress,
      userAgentMismatch: session.userAgent !== context.userAgent,
      fingerprintMismatch: session.fingerprint !== context.fingerprint,
      locationJump: false,
      timeAnomaly: false
    };

    // Check for location jump
    if (context.location && session.lastLocation) {
      const distance = this.calculateDistance(
        session.lastLocation.coordinates,
        context.location.coordinates
      );
      const timeDiff = Date.now() - session.lastActivity;
      const maxDistance = (timeDiff / 3600000) * 900;
      
      checks.locationJump = distance > maxDistance;
    }

    // Check for time anomaly
    const timeSinceLastActivity = Date.now() - session.lastActivity;
    if (timeSinceLastActivity > this.sessionTimeout) {
      checks.timeAnomaly = true;
    }

    // Calculate hijacking probability
    const suspiciousChecks = Object.values(checks).filter(v => v === true).length;
    const hijackingProbability = suspiciousChecks / Object.keys(checks).length;

    const result = {
      hijacked: hijackingProbability >= 0.4, // 40% threshold
      probability: hijackingProbability,
      reason: null,
      action: 'ALLOW',
      checks
    };

    if (result.hijacked) {
      result.reason = 'SUSPICIOUS_SESSION_ACTIVITY';
      result.action = 'TERMINATE';
      
      // Terminate session
      this.terminateSession(sessionId, 'HIJACKING_SUSPECTED');
      
      this.emit('session-hijack-detected', { sessionId, context });
    } else {
      // Update session activity
      session.lastActivity = Date.now();
      session.lastLocation = context.location;
      this.activeSessions.set(sessionId, session);
    }

    return result;
  }

  /**
   * Create new authenticated session
   */
  async createSession(userId, context) {
    // Check login attempts
    const attempts = this.loginAttempts.get(userId) || [];
    const recentAttempts = attempts.filter(
      a => Date.now() - a.timestamp < this.lockoutDuration
    );

    if (recentAttempts.length >= this.maxLoginAttempts) {
      const lockoutEnd = recentAttempts[0].timestamp + this.lockoutDuration;
      return {
        success: false,
        reason: 'ACCOUNT_LOCKED',
        lockoutEnd: new Date(lockoutEnd).toISOString()
      };
    }

    // Generate device fingerprint
    const fingerprint = await this.generateDeviceFingerprint(context);

    // Analyze location
    const locationAnalysis = await this.detectAnomalousLocation(userId, context.location);

    // Create session
    const sessionId = crypto.randomBytes(32).toString('hex');
    const session = {
      id: sessionId,
      userId,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      fingerprint: fingerprint.hash,
      location: context.location,
      lastLocation: context.location,
      mfaVerified: false,
      riskScore: locationAnalysis.riskScore
    };

    this.activeSessions.set(sessionId, session);

    // Clear login attempts on success
    this.loginAttempts.delete(userId);

    this.emit('session-created', session);

    return {
      success: true,
      sessionId,
      requireMFA: locationAnalysis.anomalous || session.riskScore > 0.3,
      riskScore: session.riskScore
    };
  }

  /**
   * Terminate session
   */
  terminateSession(sessionId, reason = 'USER_LOGOUT') {
    const session = this.activeSessions.get(sessionId);
    
    if (session) {
      this.activeSessions.delete(sessionId);
      this.emit('session-terminated', { sessionId, reason });
      return true;
    }
    
    return false;
  }

  /**
   * Record failed login attempt
   */
  recordFailedLogin(userId, context) {
    const attempts = this.loginAttempts.get(userId) || [];
    attempts.push({
      timestamp: Date.now(),
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      reason: context.reason
    });
    
    this.loginAttempts.set(userId, attempts);
    
    const recentAttempts = attempts.filter(
      a => Date.now() - a.timestamp < this.lockoutDuration
    );

    if (recentAttempts.length >= this.maxLoginAttempts) {
      this.emit('account-locked', { userId, attempts: recentAttempts.length });
    }
  }

  // Helper methods
  getCPUInfo() {
    const cpus = os.cpus();
    return {
      model: cpus[0].model,
      cores: cpus.length,
      speed: cpus[0].speed
    };
  }

  getMACAddresses() {
    const interfaces = os.networkInterfaces();
    const addresses = [];
    
    for (const name in interfaces) {
      for (const iface of interfaces[name]) {
        if (iface.mac && iface.mac !== '00:00:00:00:00:00') {
          addresses.push(iface.mac);
        }
      }
    }
    
    return addresses;
  }

  hashFingerprint(fingerprint) {
    const data = JSON.stringify({
      hardware: fingerprint.hardware,
      software: fingerprint.software,
      browser: fingerprint.browser
    });
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  calculateFingerprintSimilarity(fp1, fp2) {
    let matches = 0;
    let total = 0;

    // Compare hardware
    if (fp1.hardware.platform === fp2.hardware.platform) matches++;
    total++;
    if (fp1.hardware.arch === fp2.hardware.arch) matches++;
    total++;
    if (fp1.hardware.cpu.model === fp2.hardware.cpu.model) matches++;
    total++;

    // Compare software
    if (fp1.software.osVersion === fp2.software.osVersion) matches++;
    total++;
    if (fp1.software.timezone === fp2.software.timezone) matches++;
    total++;

    // Compare network
    if (fp1.network.ipAddress === fp2.network.ipAddress) matches++;
    total++;

    return matches / total;
  }

  detectFingerprintChanges(stored, current) {
    const changes = [];

    if (stored.network.ipAddress !== current.network.ipAddress) {
      changes.push('IP_ADDRESS_CHANGED');
    }
    if (stored.software.userAgent !== current.software.userAgent) {
      changes.push('USER_AGENT_CHANGED');
    }
    if (stored.software.timezone !== current.software.timezone) {
      changes.push('TIMEZONE_CHANGED');
    }

    return changes;
  }

  createBehaviorProfile(userId) {
    const profile = {
      userId,
      createdAt: new Date().toISOString(),
      typing: { avgSpeed: 0, rhythm: [], samples: 0 },
      mouse: { avgSpeed: 0, patterns: [], samples: 0 },
      navigation: { sequences: [], commonPaths: [] },
      activeTimes: [],
      avgSessionDuration: 0,
      locations: []
    };

    this.userBehaviorProfiles.set(userId, profile);
    return profile;
  }

  analyzeTypingPattern(current, baseline) {
    if (!baseline || baseline.samples === 0) {
      return { score: 1.0, confidence: 'LOW' };
    }

    const speedDiff = Math.abs(current.avgSpeed - baseline.avgSpeed) / baseline.avgSpeed;
    const score = Math.max(0, 1 - speedDiff);

    return {
      score,
      confidence: baseline.samples > 10 ? 'HIGH' : 'MEDIUM',
      deviation: speedDiff
    };
  }

  analyzeMouseMovement(current, baseline) {
    if (!baseline || baseline.samples === 0) {
      return { score: 1.0, confidence: 'LOW' };
    }

    const speedDiff = Math.abs(current.avgSpeed - baseline.avgSpeed) / baseline.avgSpeed;
    const score = Math.max(0, 1 - speedDiff);

    return {
      score,
      confidence: baseline.samples > 10 ? 'HIGH' : 'MEDIUM',
      deviation: speedDiff
    };
  }

  analyzeNavigationPattern(current, baseline) {
    if (!baseline || baseline.sequences.length === 0) {
      return { score: 1.0, confidence: 'LOW' };
    }

    // Simple pattern matching
    const score = baseline.commonPaths.includes(current.path) ? 0.9 : 0.5;

    return {
      score,
      confidence: baseline.sequences.length > 20 ? 'HIGH' : 'MEDIUM'
    };
  }

  analyzeTimePattern(currentTime, baselineTimes) {
    if (!baselineTimes || baselineTimes.length === 0) {
      return { score: 1.0, confidence: 'LOW' };
    }

    const currentHour = new Date(currentTime).getHours();
    const commonHours = baselineTimes.map(t => new Date(t).getHours());
    const score = commonHours.includes(currentHour) ? 0.9 : 0.6;

    return {
      score,
      confidence: baselineTimes.length > 10 ? 'HIGH' : 'MEDIUM'
    };
  }

  analyzeSessionDuration(sessionStart, avgDuration) {
    const currentDuration = Date.now() - sessionStart;
    if (avgDuration === 0) {
      return { score: 1.0, confidence: 'LOW' };
    }

    const durationDiff = Math.abs(currentDuration - avgDuration) / avgDuration;
    const score = Math.max(0, 1 - durationDiff / 2);

    return {
      score,
      confidence: 'MEDIUM',
      deviation: durationDiff
    };
  }

  updateBehaviorProfile(userId, behavior) {
    const profile = this.userBehaviorProfiles.get(userId);
    if (!profile) return;

    // Update typing profile
    if (behavior.typing) {
      profile.typing.samples++;
      profile.typing.avgSpeed = 
        (profile.typing.avgSpeed * (profile.typing.samples - 1) + behavior.typing.avgSpeed) / 
        profile.typing.samples;
    }

    // Update mouse profile
    if (behavior.mouse) {
      profile.mouse.samples++;
      profile.mouse.avgSpeed = 
        (profile.mouse.avgSpeed * (profile.mouse.samples - 1) + behavior.mouse.avgSpeed) / 
        profile.mouse.samples;
    }

    // Update navigation
    if (behavior.navigation) {
      profile.navigation.sequences.push(behavior.navigation);
      if (profile.navigation.sequences.length > 100) {
        profile.navigation.sequences.shift();
      }
    }

    // Update active times
    profile.activeTimes.push(behavior.timestamp);
    if (profile.activeTimes.length > 50) {
      profile.activeTimes.shift();
    }

    this.userBehaviorProfiles.set(userId, profile);
  }

  addLocationToProfile(userId, location) {
    const profile = this.userBehaviorProfiles.get(userId) || this.createBehaviorProfile(userId);
    
    profile.locations.push({
      ...location,
      timestamp: new Date().toISOString()
    });

    // Keep last 20 locations
    if (profile.locations.length > 20) {
      profile.locations.shift();
    }

    this.userBehaviorProfiles.set(userId, profile);
  }

  calculateDistance(coord1, coord2) {
    // Haversine formula for distance calculation
    const R = 6371; // Earth radius in km
    const dLat = this.toRad(coord2.lat - coord1.lat);
    const dLon = this.toRad(coord2.lon - coord1.lon);
    
    const a = 
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRad(coord1.lat)) * Math.cos(this.toRad(coord2.lat)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  toRad(degrees) {
    return degrees * (Math.PI / 180);
  }

  monitorActiveSessions() {
    const now = Date.now();
    
    for (const [sessionId, session] of this.activeSessions) {
      if (now - session.lastActivity > this.sessionTimeout) {
        this.terminateSession(sessionId, 'SESSION_TIMEOUT');
      }
    }
  }

  cleanupLoginAttempts() {
    const now = Date.now();
    
    for (const [userId, attempts] of this.loginAttempts) {
      const recentAttempts = attempts.filter(
        a => now - a.timestamp < this.lockoutDuration
      );
      
      if (recentAttempts.length === 0) {
        this.loginAttempts.delete(userId);
      } else {
        this.loginAttempts.set(userId, recentAttempts);
      }
    }
  }

  getStatistics() {
    return {
      activeSessions: this.activeSessions.size,
      deviceFingerprints: this.deviceFingerprints.size,
      behaviorProfiles: this.userBehaviorProfiles.size,
      lockedAccounts: Array.from(this.loginAttempts.values())
        .filter(attempts => {
          const recent = attempts.filter(a => Date.now() - a.timestamp < this.lockoutDuration);
          return recent.length >= this.maxLoginAttempts;
        }).length
    };
  }
}

export default new AuthenticationHardeningService();
