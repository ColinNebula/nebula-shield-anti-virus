/**
 * Advanced Monitoring System
 * Real-time attack heatmap, prediction, threat scoring, and alerting
 */

const EventEmitter = require('events');

class AdvancedMonitoringSystem extends EventEmitter {
  constructor() {
    super();
    
    // Geographic attack tracking
    this.attackHeatmap = new Map();
    this.geoDatabase = this.initializeGeoDatabase();
    
    // Attack prediction
    this.attackTimeline = [];
    this.predictionModel = {
      timeWindows: [300000, 900000, 1800000], // 5min, 15min, 30min
      patterns: new Map(),
      confidence: 0
    };
    
    // Threat severity scoring
    this.threatScores = new Map();
    this.severityThresholds = {
      low: 30,
      medium: 50,
      high: 70,
      critical: 90
    };
    
    // Alert system
    this.alerts = {
      email: [],
      sms: [],
      webhook: []
    };
    this.alertQueue = [];
    this.alertConfig = {
      emailEnabled: true,
      smsEnabled: true,
      emailThreshold: 'high',
      smsThreshold: 'critical',
      cooldownPeriod: 300000, // 5 minutes between alerts for same threat
      maxAlertsPerHour: 10
    };
    
    // Alert history
    this.alertHistory = [];
    this.lastAlertTime = new Map();
  }
  
  /**
   * Initialize geographic database
   */
  initializeGeoDatabase() {
    return {
      // Country codes to coordinates and risk levels
      'US': { lat: 37.0902, lon: -95.7129, name: 'United States', risk: 'low' },
      'CN': { lat: 35.8617, lon: 104.1954, name: 'China', risk: 'high' },
      'RU': { lat: 61.5240, lon: 105.3188, name: 'Russia', risk: 'high' },
      'KP': { lat: 40.3399, lon: 127.5101, name: 'North Korea', risk: 'critical' },
      'IR': { lat: 32.4279, lon: 53.6880, name: 'Iran', risk: 'high' },
      'BR': { lat: -14.2350, lon: -51.9253, name: 'Brazil', risk: 'medium' },
      'IN': { lat: 20.5937, lon: 78.9629, name: 'India', risk: 'medium' },
      'UK': { lat: 55.3781, lon: -3.4360, name: 'United Kingdom', risk: 'low' },
      'DE': { lat: 51.1657, lon: 10.4515, name: 'Germany', risk: 'low' },
      'FR': { lat: 46.2276, lon: 2.2137, name: 'France', risk: 'low' },
      'JP': { lat: 36.2048, lon: 138.2529, name: 'Japan', risk: 'low' },
      'KR': { lat: 35.9078, lon: 127.7669, name: 'South Korea', risk: 'low' },
      'VN': { lat: 14.0583, lon: 108.2772, name: 'Vietnam', risk: 'medium' },
      'UA': { lat: 48.3794, lon: 31.1656, name: 'Ukraine', risk: 'medium' },
      'RO': { lat: 45.9432, lon: 24.9668, name: 'Romania', risk: 'medium' }
    };
  }
  
  /**
   * Record attack on heatmap
   */
  recordAttackOnHeatmap(attack) {
    const country = this.getCountryFromIP(attack.ip || attack.sourceIP);
    
    if (!this.attackHeatmap.has(country)) {
      this.attackHeatmap.set(country, {
        country,
        coordinates: this.geoDatabase[country] || { lat: 0, lon: 0, name: 'Unknown' },
        attackCount: 0,
        attackTypes: {},
        severity: 'low',
        lastAttack: null,
        firstAttack: Date.now()
      });
    }
    
    const heatmapEntry = this.attackHeatmap.get(country);
    heatmapEntry.attackCount++;
    heatmapEntry.attackTypes[attack.type] = (heatmapEntry.attackTypes[attack.type] || 0) + 1;
    heatmapEntry.lastAttack = Date.now();
    heatmapEntry.severity = this.calculateRegionalSeverity(heatmapEntry);
    
    return heatmapEntry;
  }
  
  /**
   * Get country from IP (simplified)
   */
  getCountryFromIP(ip) {
    if (!ip) return 'XX';
    
    // Simplified IP to country mapping
    const ipPrefixes = {
      '45.142.': 'RU',
      '91.219.': 'RU',
      '185.220.': 'RU',
      '103.253.': 'CN',
      '198.98.': 'CN',
      '142.250.': 'US',
      '172.217.': 'US',
      '151.101.': 'US',
      '8.8.': 'US',
      '1.1.': 'US'
    };
    
    for (const [prefix, country] of Object.entries(ipPrefixes)) {
      if (ip.startsWith(prefix)) {
        return country;
      }
    }
    
    return 'XX'; // Unknown
  }
  
  /**
   * Calculate regional severity
   */
  calculateRegionalSeverity(heatmapEntry) {
    const attackRate = heatmapEntry.attackCount / ((Date.now() - heatmapEntry.firstAttack) / 3600000);
    
    if (attackRate > 100) return 'critical';
    if (attackRate > 50) return 'high';
    if (attackRate > 10) return 'medium';
    return 'low';
  }
  
  /**
   * Get real-time attack heatmap
   */
  getAttackHeatmap(timeRange = 3600000) {
    const now = Date.now();
    const cutoff = now - timeRange;
    
    const heatmap = [];
    for (const [country, data] of this.attackHeatmap) {
      if (data.lastAttack && data.lastAttack > cutoff) {
        heatmap.push({
          country: data.country,
          countryName: this.geoDatabase[country]?.name || 'Unknown',
          coordinates: data.coordinates,
          attackCount: data.attackCount,
          attackTypes: data.attackTypes,
          severity: data.severity,
          intensity: Math.min(100, data.attackCount * 2),
          riskLevel: this.geoDatabase[country]?.risk || 'unknown'
        });
      }
    }
    
    return heatmap.sort((a, b) => b.attackCount - a.attackCount);
  }
  
  /**
   * Predict upcoming attacks using timeline analysis
   */
  predictAttacks() {
    const now = Date.now();
    const predictions = [];
    
    // Analyze each time window
    for (const window of this.predictionModel.timeWindows) {
      const windowStart = now - window;
      const recentAttacks = this.attackTimeline.filter(a => a.timestamp > windowStart);
      
      if (recentAttacks.length < 3) continue;
      
      // Calculate attack rate
      const attackRate = recentAttacks.length / (window / 60000); // per minute
      
      // Detect patterns
      const patterns = this.detectAttackPatterns(recentAttacks);
      
      // Calculate prediction
      const prediction = {
        timeWindow: window / 60000, // Convert to minutes
        currentRate: attackRate.toFixed(2),
        predictedRate: (attackRate * 1.2).toFixed(2), // Simple prediction: 20% increase
        confidence: this.calculatePredictionConfidence(patterns),
        likelihood: this.calculateAttackLikelihood(attackRate),
        topThreats: patterns.topTypes,
        recommendedAction: this.getRecommendedDefense(attackRate)
      };
      
      predictions.push(prediction);
    }
    
    return predictions;
  }
  
  /**
   * Detect attack patterns
   */
  detectAttackPatterns(attacks) {
    const typeCount = {};
    const sourceCount = {};
    
    for (const attack of attacks) {
      typeCount[attack.type] = (typeCount[attack.type] || 0) + 1;
      sourceCount[attack.sourceIP] = (sourceCount[attack.sourceIP] || 0) + 1;
    }
    
    const topTypes = Object.entries(typeCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([type, count]) => ({ type, count }));
    
    const topSources = Object.entries(sourceCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));
    
    return { topTypes, topSources };
  }
  
  /**
   * Calculate prediction confidence
   */
  calculatePredictionConfidence(patterns) {
    const dataPoints = this.attackTimeline.length;
    
    if (dataPoints < 10) return 0.3;
    if (dataPoints < 50) return 0.5;
    if (dataPoints < 100) return 0.7;
    return 0.85;
  }
  
  /**
   * Calculate attack likelihood
   */
  calculateAttackLikelihood(attackRate) {
    if (attackRate > 10) return 'very high';
    if (attackRate > 5) return 'high';
    if (attackRate > 2) return 'moderate';
    if (attackRate > 0.5) return 'low';
    return 'very low';
  }
  
  /**
   * Get recommended defense based on attack rate
   */
  getRecommendedDefense(attackRate) {
    if (attackRate > 10) {
      return 'Activate maximum DDoS protection, enable CAPTCHA for all requests';
    } else if (attackRate > 5) {
      return 'Increase DDoS protection to high, monitor closely';
    } else if (attackRate > 2) {
      return 'Enable enhanced monitoring, prepare for potential escalation';
    }
    return 'Continue normal monitoring';
  }
  
  /**
   * Calculate comprehensive threat severity score
   */
  calculateThreatSeverity(threat) {
    let score = 0;
    
    // Base score from threat type
    const typeScores = {
      'ddos': 60,
      'zero-day': 80,
      'exploit': 70,
      'brute-force': 50,
      'sql-injection': 75,
      'xss': 60,
      'bot': 40,
      'slowloris': 65
    };
    
    score += typeScores[threat.type] || 30;
    
    // Adjust for attack frequency
    if (threat.frequency) {
      if (threat.frequency > 100) score += 20;
      else if (threat.frequency > 50) score += 15;
      else if (threat.frequency > 10) score += 10;
    }
    
    // Adjust for source reputation
    if (threat.sourceReputation) {
      if (threat.sourceReputation < 25) score += 15;
      else if (threat.sourceReputation < 50) score += 10;
    }
    
    // Adjust for geographic risk
    const country = this.getCountryFromIP(threat.sourceIP || threat.ip);
    const geoRisk = this.geoDatabase[country]?.risk || 'unknown';
    if (geoRisk === 'critical') score += 15;
    else if (geoRisk === 'high') score += 10;
    else if (geoRisk === 'medium') score += 5;
    
    // Adjust for payload analysis
    if (threat.payloadScore) {
      score += threat.payloadScore * 0.2;
    }
    
    // Clamp to 0-100
    score = Math.max(0, Math.min(100, score));
    
    return {
      score,
      severity: this.getSeverityLevel(score),
      category: this.getThreatCategory(score),
      requiresAlert: score >= this.severityThresholds[this.alertConfig.emailThreshold]
    };
  }
  
  /**
   * Get severity level from score
   */
  getSeverityLevel(score) {
    if (score >= this.severityThresholds.critical) return 'critical';
    if (score >= this.severityThresholds.high) return 'high';
    if (score >= this.severityThresholds.medium) return 'medium';
    return 'low';
  }
  
  /**
   * Get threat category
   */
  getThreatCategory(score) {
    if (score >= 90) return 'immediate-action-required';
    if (score >= 70) return 'high-priority';
    if (score >= 50) return 'monitor-closely';
    if (score >= 30) return 'routine-monitoring';
    return 'informational';
  }
  
  /**
   * Send alert (Email/SMS)
   */
  sendAlert(threat, channel = 'email') {
    const threatSeverity = this.calculateThreatSeverity(threat);
    
    // Check if alert should be sent
    if (!this.shouldSendAlert(threat, threatSeverity, channel)) {
      return { sent: false, reason: 'Alert threshold not met or cooldown active' };
    }
    
    // Create alert message
    const alert = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now(),
      channel,
      threat: {
        type: threat.type,
        sourceIP: threat.sourceIP || threat.ip,
        severity: threatSeverity.severity,
        score: threatSeverity.score,
        category: threatSeverity.category
      },
      message: this.formatAlertMessage(threat, threatSeverity),
      sent: false
    };
    
    // Queue alert for sending
    this.alertQueue.push(alert);
    
    // Update last alert time
    const alertKey = `${threat.sourceIP || threat.ip}_${threat.type}`;
    this.lastAlertTime.set(alertKey, Date.now());
    
    // Simulate sending (in production, integrate with actual email/SMS service)
    this.processAlert(alert);
    
    // Record in history
    this.alertHistory.push(alert);
    if (this.alertHistory.length > 1000) {
      this.alertHistory.shift();
    }
    
    return alert;
  }
  
  /**
   * Check if alert should be sent
   */
  shouldSendAlert(threat, threatSeverity, channel) {
    // Check if channel is enabled
    if (channel === 'email' && !this.alertConfig.emailEnabled) return false;
    if (channel === 'sms' && !this.alertConfig.smsEnabled) return false;
    
    // Check severity threshold
    const threshold = channel === 'sms' ? 
      this.alertConfig.smsThreshold : 
      this.alertConfig.emailThreshold;
    
    if (threatSeverity.severity !== threshold && 
        this.severityThresholds[threatSeverity.severity] < this.severityThresholds[threshold]) {
      return false;
    }
    
    // Check cooldown period
    const alertKey = `${threat.sourceIP || threat.ip}_${threat.type}`;
    const lastAlert = this.lastAlertTime.get(alertKey);
    if (lastAlert && (Date.now() - lastAlert) < this.alertConfig.cooldownPeriod) {
      return false;
    }
    
    // Check rate limit
    const oneHourAgo = Date.now() - 3600000;
    const recentAlerts = this.alertHistory.filter(a => a.timestamp > oneHourAgo);
    if (recentAlerts.length >= this.alertConfig.maxAlertsPerHour) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Format alert message
   */
  formatAlertMessage(threat, threatSeverity) {
    const emoji = {
      'critical': '🚨',
      'high': '⚠️',
      'medium': '⚡',
      'low': 'ℹ️'
    };
    
    return {
      subject: `${emoji[threatSeverity.severity]} Security Alert: ${threat.type.toUpperCase()} - ${threatSeverity.severity.toUpperCase()}`,
      body: `
SECURITY ALERT - ${threatSeverity.severity.toUpperCase()} PRIORITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Threat Type:     ${threat.type}
Severity Score:  ${threatSeverity.score}/100
Source IP:       ${threat.sourceIP || threat.ip}
Country:         ${this.geoDatabase[this.getCountryFromIP(threat.sourceIP || threat.ip)]?.name || 'Unknown'}
Category:        ${threatSeverity.category}
Timestamp:       ${new Date().toISOString()}

Action Required:
${this.getActionRequired(threatSeverity)}

Recommendation:
${threat.recommendation || 'Review and take appropriate action'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Nebula Shield Anti-Virus - Security Operations
      `,
      sms: `${emoji[threatSeverity.severity]} ALERT: ${threat.type} from ${threat.sourceIP || threat.ip} - Severity: ${threatSeverity.severity.toUpperCase()} (${threatSeverity.score}/100)`
    };
  }
  
  /**
   * Get action required based on severity
   */
  getActionRequired(threatSeverity) {
    if (threatSeverity.severity === 'critical') {
      return '- Immediate investigation required\n- IP has been automatically blocked\n- Review attack logs immediately\n- Contact security team';
    } else if (threatSeverity.severity === 'high') {
      return '- Investigation recommended\n- Monitor for escalation\n- Review recent activity';
    } else if (threatSeverity.severity === 'medium') {
      return '- Monitor situation\n- No immediate action required\n- Review during next security audit';
    }
    return '- Informational only\n- No action required';
  }
  
  /**
   * Process alert (simulate sending)
   */
  processAlert(alert) {
    // In production, integrate with:
    // - Email service (SendGrid, AWS SES, etc.)
    // - SMS service (Twilio, etc.)
    // - Webhook/Slack notifications
    
    console.log(`[ALERT-${alert.channel.toUpperCase()}] ${alert.message.subject}`);
    alert.sent = true;
    alert.sentAt = Date.now();
    
    // Emit event
    this.emit('alert-sent', alert);
  }
  
  /**
   * Get monitoring statistics
   */
  getMonitoringStats() {
    return {
      heatmap: this.getAttackHeatmap(),
      predictions: this.predictAttacks(),
      alertsSent: this.alertHistory.length,
      recentAlerts: this.alertHistory.slice(-10),
      activeThreats: this.attackTimeline.length,
      topCountries: this.getTopAttackCountries(5)
    };
  }
  
  /**
   * Get top attack countries
   */
  getTopAttackCountries(limit = 5) {
    const countries = Array.from(this.attackHeatmap.values())
      .sort((a, b) => b.attackCount - a.attackCount)
      .slice(0, limit)
      .map(entry => ({
        country: entry.country,
        name: this.geoDatabase[entry.country]?.name || 'Unknown',
        attackCount: entry.attackCount,
        severity: entry.severity
      }));
    
    return countries;
  }
  
  /**
   * Record attack for timeline and monitoring
   */
  recordAttack(attack) {
    // Add to timeline
    this.attackTimeline.push({
      timestamp: Date.now(),
      type: attack.type,
      sourceIP: attack.ip || attack.sourceIP,
      severity: attack.severity
    });
    
    // Keep timeline to reasonable size
    if (this.attackTimeline.length > 10000) {
      this.attackTimeline = this.attackTimeline.slice(-5000);
    }
    
    // Update heatmap
    this.recordAttackOnHeatmap(attack);
    
    // Calculate threat severity and send alerts if needed
    const threatSeverity = this.calculateThreatSeverity(attack);
    
    if (threatSeverity.requiresAlert) {
      this.sendAlert(attack, 'email');
      
      if (threatSeverity.severity === 'critical') {
        this.sendAlert(attack, 'sms');
      }
    }
  }
}

// Export singleton instance
module.exports = new AdvancedMonitoringSystem();
