/**
 * AI-Powered Threat Detection Engine
 * Machine learning-based network threat analysis
 */

class AIThreatDetector {
  constructor() {
    this.anomalyThreshold = 0.7;
    this.learningRate = 0.01;
    this.trafficPatterns = new Map();
    this.threatScores = new Map();
    this.behavioralProfiles = new Map();
    
    // Pre-trained threat indicators
    this.threatIndicators = {
      // Port scanning patterns
      portScanning: {
        consecutivePorts: 10,
        timeWindow: 5000, // ms
        threatScore: 0.85
      },
      
      // DDoS patterns
      ddos: {
        requestThreshold: 100,
        timeWindow: 1000, // ms
        threatScore: 0.95
      },
      
      // Data exfiltration
      exfiltration: {
        dataThreshold: 100 * 1024 * 1024, // 100MB
        timeWindow: 60000, // 1 minute
        threatScore: 0.90
      },
      
      // Brute force
      bruteForce: {
        failedAttempts: 5,
        timeWindow: 300000, // 5 minutes
        threatScore: 0.80
      },
      
      // Unusual traffic patterns
      anomalous: {
        deviationThreshold: 3, // standard deviations
        threatScore: 0.75
      }
    };
    
    // Initialize baseline traffic patterns
    this.baselineTraffic = {
      avgPacketsPerSecond: 50,
      avgBytesPerSecond: 1024 * 100,
      commonPorts: new Set([80, 443, 22, 3389, 53]),
      commonProtocols: new Set(['tcp', 'udp', 'icmp'])
    };
  }

  /**
   * Analyze connection for threats using AI/ML techniques
   */
  analyzeConnection(connection) {
    const {
      sourceIP,
      destIP,
      sourcePort,
      destPort,
      protocol,
      bytes,
      packets,
      timestamp
    } = connection;

    let totalThreatScore = 0;
    const detectedThreats = [];
    const indicators = [];

    // 1. Check for port scanning
    const portScanScore = this.detectPortScanning(sourceIP, destPort, timestamp);
    if (portScanScore > 0) {
      totalThreatScore += portScanScore;
      detectedThreats.push('port_scanning');
      indicators.push(`Port scanning detected: ${portScanScore.toFixed(2)} confidence`);
    }

    // 2. Check for DDoS patterns
    const ddosScore = this.detectDDoS(sourceIP, timestamp, packets);
    if (ddosScore > 0) {
      totalThreatScore += ddosScore;
      detectedThreats.push('ddos');
      indicators.push(`DDoS pattern: ${ddosScore.toFixed(2)} confidence`);
    }

    // 3. Check for data exfiltration
    const exfilScore = this.detectExfiltration(sourceIP, destIP, bytes, timestamp);
    if (exfilScore > 0) {
      totalThreatScore += exfilScore;
      detectedThreats.push('exfiltration');
      indicators.push(`Data exfiltration: ${exfilScore.toFixed(2)} confidence`);
    }

    // 4. Check for brute force attacks
    const bruteForceScore = this.detectBruteForce(sourceIP, destPort, timestamp);
    if (bruteForceScore > 0) {
      totalThreatScore += bruteForceScore;
      detectedThreats.push('brute_force');
      indicators.push(`Brute force: ${bruteForceScore.toFixed(2)} confidence`);
    }

    // 5. Behavioral analysis
    const behaviorScore = this.analyzeBehavior(sourceIP, connection);
    if (behaviorScore > 0) {
      totalThreatScore += behaviorScore;
      detectedThreats.push('anomalous_behavior');
      indicators.push(`Anomalous behavior: ${behaviorScore.toFixed(2)} confidence`);
    }

    // 6. Protocol anomaly detection
    const protocolScore = this.detectProtocolAnomalies(protocol, destPort, bytes);
    if (protocolScore > 0) {
      totalThreatScore += protocolScore;
      detectedThreats.push('protocol_anomaly');
      indicators.push(`Protocol anomaly: ${protocolScore.toFixed(2)} confidence`);
    }

    // Normalize threat score (0-1)
    const normalizedScore = Math.min(totalThreatScore / detectedThreats.length || 0, 1);

    // Update learning model
    this.updateModel(sourceIP, connection, normalizedScore);

    return {
      isThreat: normalizedScore >= this.anomalyThreshold,
      threatScore: normalizedScore,
      confidence: normalizedScore * 100,
      threats: detectedThreats,
      indicators,
      severity: this.calculateSeverity(normalizedScore),
      recommendation: this.getRecommendation(detectedThreats, normalizedScore)
    };
  }

  /**
   * Detect port scanning activity
   */
  detectPortScanning(sourceIP, destPort, timestamp) {
    const key = `portscan_${sourceIP}`;
    const scans = this.trafficPatterns.get(key) || [];
    
    // Add current scan
    scans.push({ port: destPort, time: timestamp });
    
    // Filter recent scans within time window
    const recentScans = scans.filter(
      scan => timestamp - scan.time < this.threatIndicators.portScanning.timeWindow
    );
    
    // Update patterns
    this.trafficPatterns.set(key, recentScans);
    
    // Check for consecutive ports
    const uniquePorts = new Set(recentScans.map(s => s.port));
    
    if (uniquePorts.size >= this.threatIndicators.portScanning.consecutivePorts) {
      // Check if ports are sequential
      const sortedPorts = Array.from(uniquePorts).sort((a, b) => a - b);
      let sequential = 0;
      
      for (let i = 1; i < sortedPorts.length; i++) {
        if (sortedPorts[i] - sortedPorts[i-1] <= 5) {
          sequential++;
        }
      }
      
      if (sequential >= this.threatIndicators.portScanning.consecutivePorts * 0.7) {
        return this.threatIndicators.portScanning.threatScore;
      }
    }
    
    return 0;
  }

  /**
   * Detect DDoS attack patterns
   */
  detectDDoS(sourceIP, timestamp, packets) {
    const key = `ddos_${sourceIP}`;
    const requests = this.trafficPatterns.get(key) || [];
    
    // Add current request
    requests.push({ time: timestamp, packets });
    
    // Filter recent requests
    const recentRequests = requests.filter(
      req => timestamp - req.time < this.threatIndicators.ddos.timeWindow
    );
    
    this.trafficPatterns.set(key, recentRequests);
    
    // Check request rate
    if (recentRequests.length >= this.threatIndicators.ddos.requestThreshold) {
      const totalPackets = recentRequests.reduce((sum, req) => sum + (req.packets || 1), 0);
      const avgPackets = totalPackets / recentRequests.length;
      
      // Higher score for more packets
      const intensityFactor = Math.min(avgPackets / 100, 2);
      return this.threatIndicators.ddos.threatScore * intensityFactor;
    }
    
    return 0;
  }

  /**
   * Detect data exfiltration
   */
  detectExfiltration(sourceIP, destIP, bytes, timestamp) {
    const key = `exfil_${sourceIP}_${destIP}`;
    const transfers = this.trafficPatterns.get(key) || [];
    
    transfers.push({ time: timestamp, bytes: bytes || 0 });
    
    // Filter recent transfers
    const recentTransfers = transfers.filter(
      t => timestamp - t.time < this.threatIndicators.exfiltration.timeWindow
    );
    
    this.trafficPatterns.set(key, recentTransfers);
    
    // Calculate total data transferred
    const totalBytes = recentTransfers.reduce((sum, t) => sum + t.bytes, 0);
    
    if (totalBytes >= this.threatIndicators.exfiltration.dataThreshold) {
      // Higher score for larger transfers
      const sizeFactor = Math.min(totalBytes / (500 * 1024 * 1024), 1.5);
      return this.threatIndicators.exfiltration.threatScore * sizeFactor;
    }
    
    return 0;
  }

  /**
   * Detect brute force attacks
   */
  detectBruteForce(sourceIP, destPort, timestamp) {
    // Common authentication ports
    const authPorts = [22, 23, 3389, 5900, 21, 143, 110, 25];
    
    if (!authPorts.includes(destPort)) {
      return 0;
    }
    
    const key = `bruteforce_${sourceIP}_${destPort}`;
    const attempts = this.trafficPatterns.get(key) || [];
    
    attempts.push({ time: timestamp });
    
    // Filter recent attempts
    const recentAttempts = attempts.filter(
      a => timestamp - a.time < this.threatIndicators.bruteForce.timeWindow
    );
    
    this.trafficPatterns.set(key, recentAttempts);
    
    if (recentAttempts.length >= this.threatIndicators.bruteForce.failedAttempts) {
      // Higher score for more attempts
      const attemptFactor = Math.min(recentAttempts.length / 20, 1.5);
      return this.threatIndicators.bruteForce.threatScore * attemptFactor;
    }
    
    return 0;
  }

  /**
   * Analyze behavioral patterns
   */
  analyzeBehavior(sourceIP, connection) {
    const profile = this.behavioralProfiles.get(sourceIP) || {
      connectionCount: 0,
      commonPorts: new Map(),
      commonProtocols: new Map(),
      avgBytes: 0,
      avgPackets: 0,
      firstSeen: Date.now()
    };
    
    // Update profile
    profile.connectionCount++;
    profile.commonPorts.set(
      connection.destPort,
      (profile.commonPorts.get(connection.destPort) || 0) + 1
    );
    profile.commonProtocols.set(
      connection.protocol,
      (profile.commonProtocols.get(connection.protocol) || 0) + 1
    );
    
    // Calculate moving average
    profile.avgBytes = (profile.avgBytes * 0.9) + ((connection.bytes || 0) * 0.1);
    profile.avgPackets = (profile.avgPackets * 0.9) + ((connection.packets || 0) * 0.1);
    
    this.behavioralProfiles.set(sourceIP, profile);
    
    // Detect anomalies
    let anomalyScore = 0;
    
    // Unusual port usage
    const portUsageRatio = profile.commonPorts.size / profile.connectionCount;
    if (portUsageRatio > 0.8) { // Many different ports
      anomalyScore += 0.3;
    }
    
    // Unusual protocol usage
    if (profile.commonProtocols.size > 3) {
      anomalyScore += 0.2;
    }
    
    // Unusual data transfer
    const bytesDeviation = Math.abs((connection.bytes || 0) - profile.avgBytes) / 
                          (profile.avgBytes || 1);
    if (bytesDeviation > this.threatIndicators.anomalous.deviationThreshold) {
      anomalyScore += 0.3;
    }
    
    // New source IP (suspicious if immediately high activity)
    const timeSinceFirstSeen = Date.now() - profile.firstSeen;
    if (timeSinceFirstSeen < 60000 && profile.connectionCount > 50) { // < 1 minute, > 50 connections
      anomalyScore += 0.4;
    }
    
    return anomalyScore;
  }

  /**
   * Detect protocol anomalies
   */
  detectProtocolAnomalies(protocol, port, bytes) {
    let anomalyScore = 0;
    
    // Check for protocol-port mismatches
    const expectedProtocolPort = {
      'tcp': [80, 443, 22, 21, 23, 25, 110, 143, 3389],
      'udp': [53, 67, 68, 69, 123, 161, 162, 514],
      'icmp': []
    };
    
    if (expectedProtocolPort[protocol]) {
      const isCommonPort = this.baselineTraffic.commonPorts.has(port);
      const isExpectedPort = expectedProtocolPort[protocol].includes(port);
      
      if (!isCommonPort && !isExpectedPort) {
        anomalyScore += 0.3;
      }
    }
    
    // Check for unusual packet sizes
    const typicalSizes = {
      'tcp': { min: 40, max: 1500 },
      'udp': { min: 28, max: 1472 },
      'icmp': { min: 28, max: 1500 }
    };
    
    if (typicalSizes[protocol]) {
      if (bytes < typicalSizes[protocol].min || bytes > typicalSizes[protocol].max) {
        anomalyScore += 0.2;
      }
    }
    
    return anomalyScore;
  }

  /**
   * Update ML model with new data
   */
  updateModel(sourceIP, connection, threatScore) {
    // Update threat scores
    const currentScore = this.threatScores.get(sourceIP) || 0;
    const newScore = currentScore * (1 - this.learningRate) + threatScore * this.learningRate;
    this.threatScores.set(sourceIP, newScore);
    
    // Adaptive threshold adjustment
    if (threatScore > 0.9) {
      // High confidence threat - slightly lower threshold
      this.anomalyThreshold = Math.max(0.6, this.anomalyThreshold * 0.98);
    } else if (threatScore < 0.3 && currentScore > 0.5) {
      // False positive correction - slightly raise threshold
      this.anomalyThreshold = Math.min(0.8, this.anomalyThreshold * 1.02);
    }
  }

  /**
   * Calculate severity level
   */
  calculateSeverity(threatScore) {
    if (threatScore >= 0.9) return 'critical';
    if (threatScore >= 0.75) return 'high';
    if (threatScore >= 0.5) return 'medium';
    if (threatScore >= 0.3) return 'low';
    return 'info';
  }

  /**
   * Get recommendation based on threats
   */
  getRecommendation(threats, score) {
    const recommendations = [];
    
    if (threats.includes('port_scanning')) {
      recommendations.push('Block source IP - Port scanning detected');
    }
    
    if (threats.includes('ddos')) {
      recommendations.push('Implement rate limiting - DDoS pattern detected');
    }
    
    if (threats.includes('exfiltration')) {
      recommendations.push('Block outbound traffic - Data exfiltration detected');
    }
    
    if (threats.includes('brute_force')) {
      recommendations.push('Block authentication attempts - Brute force detected');
    }
    
    if (threats.includes('anomalous_behavior')) {
      recommendations.push('Monitor closely - Anomalous behavior detected');
    }
    
    if (threats.includes('protocol_anomaly')) {
      recommendations.push('Inspect traffic - Protocol anomaly detected');
    }
    
    if (score >= 0.8 && recommendations.length === 0) {
      recommendations.push('Block immediately - High threat score');
    }
    
    return recommendations.length > 0 ? recommendations : ['Monitor - Low threat level'];
  }

  /**
   * Get IP reputation from ML model
   */
  getIPReputation(sourceIP) {
    const threatScore = this.threatScores.get(sourceIP) || 0;
    const profile = this.behavioralProfiles.get(sourceIP);
    
    return {
      ip: sourceIP,
      threatScore,
      reputation: threatScore < 0.3 ? 'good' : threatScore < 0.7 ? 'suspicious' : 'malicious',
      confidence: Math.min(profile ? profile.connectionCount / 100 : 0.1, 1) * 100,
      firstSeen: profile ? new Date(profile.firstSeen).toISOString() : null,
      totalConnections: profile ? profile.connectionCount : 0
    };
  }

  /**
   * Reset learning model
   */
  resetModel() {
    this.trafficPatterns.clear();
    this.threatScores.clear();
    this.behavioralProfiles.clear();
    this.anomalyThreshold = 0.7;
    
    return {
      success: true,
      message: 'AI model reset to defaults'
    };
  }

  /**
   * Get model statistics
   */
  getModelStats() {
    return {
      anomalyThreshold: this.anomalyThreshold,
      learningRate: this.learningRate,
      trackedIPs: this.threatScores.size,
      behavioralProfiles: this.behavioralProfiles.size,
      trafficPatterns: this.trafficPatterns.size,
      avgThreatScore: Array.from(this.threatScores.values()).reduce((a, b) => a + b, 0) / 
                      (this.threatScores.size || 1)
    };
  }
}

module.exports = new AIThreatDetector();
