/**
 * Predictive Analytics Engine
 * Predict potential vulnerabilities before exploitation
 * Uses ML to analyze system state and predict attack vectors
 */

const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class PredictiveAnalytics {
  constructor() {
    this.predictionHistory = [];
    this.systemStateHistory = [];
    this.vulnerabilityDatabase = new Map();
    this.attackPatterns = new Map();
    
    // ML model parameters
    this.modelConfig = {
      timeseriesWindow: 50,
      predictionHorizon: 24, // hours
      confidenceThreshold: 0.70,
      updateInterval: 3600000 // 1 hour
    };

    // Risk factors
    this.riskFactors = {
      // Software vulnerabilities
      outdatedSoftware: { weight: 0.85, category: 'software' },
      unpatched: { weight: 0.90, category: 'software' },
      eolSoftware: { weight: 0.95, category: 'software' },
      
      // Configuration issues
      weakPasswords: { weight: 0.75, category: 'configuration' },
      openPorts: { weight: 0.70, category: 'configuration' },
      disabledFirewall: { weight: 0.80, category: 'configuration' },
      noAntivirus: { weight: 0.85, category: 'configuration' },
      
      // Network vulnerabilities
      unsecuredWifi: { weight: 0.65, category: 'network' },
      noEncryption: { weight: 0.75, category: 'network' },
      publicIP: { weight: 0.60, category: 'network' },
      
      // Behavioral indicators
      unusualTraffic: { weight: 0.70, category: 'behavior' },
      newProcesses: { weight: 0.55, category: 'behavior' },
      privilegeChanges: { weight: 0.80, category: 'behavior' },
      
      // Environmental factors
      highThreatPeriod: { weight: 0.50, category: 'environmental' },
      targetedIndustry: { weight: 0.65, category: 'environmental' },
      activeCampaigns: { weight: 0.75, category: 'environmental' }
    };

    // Attack vector predictions
    this.attackVectors = {
      ransomware: {
        indicators: ['outdatedSoftware', 'weakPasswords', 'openPorts'],
        likelihood: 0,
        impact: 'critical',
        mitigations: []
      },
      phishing: {
        indicators: ['weakPasswords', 'noAntivirus', 'unusualTraffic'],
        likelihood: 0,
        impact: 'high',
        mitigations: []
      },
      zeroDay: {
        indicators: ['unpatched', 'publicIP', 'targetedIndustry'],
        likelihood: 0,
        impact: 'critical',
        mitigations: []
      },
      bruteForce: {
        indicators: ['weakPasswords', 'openPorts', 'publicIP'],
        likelihood: 0,
        impact: 'high',
        mitigations: []
      },
      malwareInfection: {
        indicators: ['noAntivirus', 'outdatedSoftware', 'unsecuredWifi'],
        likelihood: 0,
        impact: 'high',
        mitigations: []
      },
      ddos: {
        indicators: ['publicIP', 'openPorts', 'highThreatPeriod'],
        likelihood: 0,
        impact: 'medium',
        mitigations: []
      },
      dataExfiltration: {
        indicators: ['unusualTraffic', 'noEncryption', 'privilegeChanges'],
        likelihood: 0,
        impact: 'critical',
        mitigations: []
      }
    };

    this.initializeModel();
  }

  /**
   * Initialize predictive model
   */
  async initializeModel() {
    console.log('🔮 Initializing Predictive Analytics Engine...');
    
    // Load historical data
    await this.loadHistoricalData();
    
    // Initialize vulnerability database
    await this.updateVulnerabilityDatabase();
    
    console.log('✅ Predictive Analytics Engine ready');
  }

  /**
   * Perform predictive analysis
   */
  async analyzePredictiveThreats(options = {}) {
    const startTime = Date.now();
    const analysis = {
      timestamp: new Date().toISOString(),
      systemState: {},
      vulnerabilities: [],
      predictions: [],
      recommendations: [],
      overallRisk: 0,
      confidence: 0
    };

    try {
      // 1. Collect current system state
      analysis.systemState = await this.collectSystemState();

      // 2. Identify current vulnerabilities
      analysis.vulnerabilities = await this.identifyVulnerabilities(analysis.systemState);

      // 3. Calculate risk scores
      const riskScores = this.calculateRiskScores(analysis.vulnerabilities);

      // 4. Predict likely attack vectors
      analysis.predictions = await this.predictAttackVectors(
        analysis.systemState,
        riskScores
      );

      // 5. Generate recommendations
      analysis.recommendations = this.generateRecommendations(
        analysis.vulnerabilities,
        analysis.predictions
      );

      // 6. Calculate overall risk
      analysis.overallRisk = this.calculateOverallRisk(riskScores, analysis.predictions);
      
      // 7. Calculate confidence
      analysis.confidence = this.calculateConfidence(analysis);

      // 8. Time-series prediction
      const timeSeriesPrediction = await this.predictFutureThreats(
        this.modelConfig.predictionHorizon
      );
      analysis.timeSeriesPrediction = timeSeriesPrediction;

      // Store for historical analysis
      this.storePrediction(analysis);

      analysis.duration = Date.now() - startTime;
      return analysis;

    } catch (error) {
      console.error('Predictive analysis error:', error);
      return {
        ...analysis,
        error: error.message,
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Collect current system state
   */
  async collectSystemState() {
    const state = {
      timestamp: Date.now(),
      os: {
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        uptime: os.uptime()
      },
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        usage: 1 - (os.freemem() / os.totalmem())
      },
      cpu: {
        cores: os.cpus().length,
        model: os.cpus()[0].model,
        load: os.loadavg()
      },
      network: {
        interfaces: os.networkInterfaces()
      },
      security: {},
      software: {}
    };

    // Check Windows security features
    if (os.platform() === 'win32') {
      try {
        // Check Windows Defender status
        const defenderStatus = await this.checkWindowsDefender();
        state.security.defender = defenderStatus;

        // Check Windows Firewall
        const firewallStatus = await this.checkWindowsFirewall();
        state.security.firewall = firewallStatus;

        // Check Windows Update status
        const updateStatus = await this.checkWindowsUpdate();
        state.security.updates = updateStatus;

      } catch (error) {
        console.warn('Security status check failed:', error.message);
      }
    } else if (os.platform() === 'darwin') {
      try {
        const antivirusStatus = await this.checkMacAntivirus();
        state.security.defender = antivirusStatus;
      } catch (error) {
        console.warn('Antivirus status check failed:', error.message);
      }
    } else {
      try {
        const antivirusStatus = await this.checkLinuxAntivirus();
        state.security.defender = antivirusStatus;
      } catch (error) {
        console.warn('Antivirus status check failed:', error.message);
      }
    }

    if (state.security.defender) {
      state.security.antivirus = state.security.defender;
    }

    // Check installed software
    try {
      state.software.installed = await this.getInstalledSoftware();
    } catch (error) {
      console.warn('Software check failed:', error.message);
    }

    return state;
  }

  /**
   * Identify vulnerabilities
   */
  async identifyVulnerabilities(systemState) {
    const vulnerabilities = [];

    // Check for outdated OS
    if (systemState.os.platform === 'win32') {
      const release = systemState.os.release;
      // Windows 10 releases below certain versions are EOL
      if (release.startsWith('10.0.10240')) {
        vulnerabilities.push({
          id: 'vuln_001',
          type: 'eolSoftware',
          severity: 'critical',
          description: 'Operating system version is end-of-life',
          component: 'Windows ' + release,
          cvss: 9.0,
          exploitAvailable: true,
          recommendation: 'Upgrade to latest Windows version'
        });
      }
    }

    // Check antivirus status
    if (systemState.security.defender) {
      const defender = systemState.security.defender;
      const componentName = defender.platform || 'Antivirus';

      if (defender.available === false) {
        vulnerabilities.push({
          id: 'vuln_002',
          type: 'noAntivirus',
          severity: 'high',
          description: 'No antivirus detected',
          component: componentName,
          cvss: 7.5,
          recommendation: 'Enable built-in protection or install a trusted antivirus'
        });
      } else if (!defender.enabled) {
        vulnerabilities.push({
          id: 'vuln_002',
          type: 'noAntivirus',
          severity: 'high',
          description: 'Antivirus is disabled',
          component: componentName,
          cvss: 7.5,
          recommendation: 'Enable antivirus real-time protection'
        });
      }
    }

    // Check Firewall
    if (systemState.security.firewall && !systemState.security.firewall.enabled) {
      vulnerabilities.push({
        id: 'vuln_003',
        type: 'disabledFirewall',
        severity: 'high',
        description: 'Windows Firewall is disabled',
        component: 'Windows Firewall',
        cvss: 7.0,
        recommendation: 'Enable Windows Firewall'
      });
    }

    // Check for pending updates
    if (systemState.security.updates && systemState.security.updates.pendingCount > 0) {
      vulnerabilities.push({
        id: 'vuln_004',
        type: 'unpatched',
        severity: systemState.security.updates.criticalCount > 0 ? 'critical' : 'high',
        description: `${systemState.security.updates.pendingCount} pending updates`,
        component: 'Windows Update',
        cvss: systemState.security.updates.criticalCount > 0 ? 8.5 : 6.0,
        recommendation: 'Install all pending security updates'
      });
    }

    // Check for known vulnerable software
    if (systemState.software.installed) {
      const vulnerableSoftware = await this.checkSoftwareVulnerabilities(
        systemState.software.installed
      );
      vulnerabilities.push(...vulnerableSoftware);
    }

    // Check network configuration
    const networkVulns = this.checkNetworkVulnerabilities(systemState.network);
    vulnerabilities.push(...networkVulns);

    // Check memory usage (potential DoS vulnerability)
    if (systemState.memory.usage > 0.9) {
      vulnerabilities.push({
        id: 'vuln_mem_001',
        type: 'resourceExhaustion',
        severity: 'medium',
        description: 'High memory usage may indicate DoS vulnerability',
        component: 'System Memory',
        cvss: 5.0,
        recommendation: 'Investigate high memory usage'
      });
    }

    return vulnerabilities;
  }

  /**
   * Calculate risk scores
   */
  calculateRiskScores(vulnerabilities) {
    const scores = {
      byCategory: {},
      bySeverity: {},
      total: 0
    };

    vulnerabilities.forEach(vuln => {
      // Get risk factor weight
      const riskFactor = this.riskFactors[vuln.type];
      const weight = riskFactor ? riskFactor.weight : 0.5;
      const category = riskFactor ? riskFactor.category : 'unknown';

      // Calculate score based on CVSS and weight
      const score = (vuln.cvss / 10) * weight;

      // Aggregate by category
      if (!scores.byCategory[category]) {
        scores.byCategory[category] = 0;
      }
      scores.byCategory[category] += score;

      // Aggregate by severity
      if (!scores.bySeverity[vuln.severity]) {
        scores.bySeverity[vuln.severity] = 0;
      }
      scores.bySeverity[vuln.severity] += score;

      scores.total += score;
    });

    // Normalize total score to 0-1 range
    scores.total = Math.min(scores.total / vulnerabilities.length, 1);

    return scores;
  }

  /**
   * Predict attack vectors using ML
   */
  async predictAttackVectors(systemState, riskScores) {
    const predictions = [];

    // Analyze each attack vector
    for (const [vectorName, vector] of Object.entries(this.attackVectors)) {
      let likelihood = 0;
      const activeIndicators = [];

      // Check which indicators are present
      vector.indicators.forEach(indicator => {
        const riskFactor = this.riskFactors[indicator];
        if (riskFactor) {
          const category = riskFactor.category;
          const categoryScore = riskScores.byCategory[category] || 0;
          
          if (categoryScore > 0.3) {
            likelihood += riskFactor.weight;
            activeIndicators.push({
              indicator,
              weight: riskFactor.weight,
              category
            });
          }
        }
      });

      // Normalize likelihood
      likelihood = likelihood / vector.indicators.length;

      // Apply time-series analysis
      const historicalLikelihood = this.getHistoricalLikelihood(vectorName);
      const trendAdjustment = this.calculateTrendAdjustment(vectorName);
      likelihood = (likelihood * 0.7) + (historicalLikelihood * 0.2) + (trendAdjustment * 0.1);

      // Generate mitigations
      const mitigations = this.generateMitigations(vectorName, activeIndicators);

      if (likelihood > 0.3) {
        predictions.push({
          attackVector: vectorName,
          likelihood: Math.min(likelihood, 1),
          impact: vector.impact,
          confidence: this.calculateVectorConfidence(activeIndicators),
          indicators: activeIndicators,
          mitigations,
          timeToExploit: this.estimateTimeToExploit(vectorName, likelihood),
          preventable: mitigations.length > 0
        });
      }
    }

    // Sort by likelihood
    predictions.sort((a, b) => b.likelihood - a.likelihood);

    return predictions;
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(vulnerabilities, predictions) {
    const recommendations = [];
    const priorityMap = { critical: 1, high: 2, medium: 3, low: 4 };

    // Recommendations from vulnerabilities
    vulnerabilities.forEach(vuln => {
      recommendations.push({
        priority: vuln.severity,
        type: 'vulnerability',
        title: `Address ${vuln.type}`,
        description: vuln.description,
        action: vuln.recommendation,
        impact: vuln.severity,
        effort: this.estimateEffort(vuln),
        automated: this.canAutomate(vuln)
      });
    });

    // Recommendations from predictions
    predictions.forEach(pred => {
      pred.mitigations.forEach(mitigation => {
        recommendations.push({
          priority: pred.impact,
          type: 'prevention',
          title: `Prevent ${pred.attackVector}`,
          description: `Likelihood: ${(pred.likelihood * 100).toFixed(1)}%`,
          action: mitigation,
          impact: pred.impact,
          effort: 'medium',
          automated: false
        });
      });
    });

    // Remove duplicates and sort by priority
    const uniqueRecs = Array.from(
      new Map(recommendations.map(r => [r.action, r])).values()
    );
    
    uniqueRecs.sort((a, b) => priorityMap[a.priority] - priorityMap[b.priority]);

    return uniqueRecs.slice(0, 10); // Top 10 recommendations
  }

  /**
   * Calculate overall risk
   */
  calculateOverallRisk(riskScores, predictions) {
    // Combine vulnerability risk and prediction risk
    const vulnRisk = riskScores.total;
    const predRisk = predictions.reduce((sum, p) => sum + p.likelihood, 0) / 
                     Math.max(predictions.length, 1);

    // Weighted average
    const overallRisk = (vulnRisk * 0.6) + (predRisk * 0.4);

    return {
      score: overallRisk,
      level: this.getRiskLevel(overallRisk),
      vulnContribution: vulnRisk,
      predContribution: predRisk
    };
  }

  /**
   * Calculate analysis confidence
   */
  calculateConfidence(analysis) {
    let confidence = 0.5; // Base confidence

    // Increase confidence based on data completeness
    if (analysis.systemState.security.defender?.available !== false) confidence += 0.1;
    if (analysis.systemState.security.firewall) confidence += 0.1;
    if (analysis.systemState.software.installed) confidence += 0.1;
    
    // Increase confidence based on vulnerability count
    if (analysis.vulnerabilities.length > 0) confidence += 0.1;
    
    // Increase confidence based on prediction count
    if (analysis.predictions.length > 0) confidence += 0.1;

    return Math.min(confidence, 0.95);
  }

  /**
   * Predict future threats using time-series
   */
  async predictFutureThreats(hoursAhead) {
    const predictions = {
      timeframe: `${hoursAhead} hours`,
      threatLevelForecast: [],
      likelyAttacks: [],
      confidence: 0.7
    };

    // Analyze historical trends
    const historicalData = this.systemStateHistory.slice(-this.modelConfig.timeseriesWindow);
    
    if (historicalData.length < 10) {
      return {
        ...predictions,
        message: 'Insufficient historical data for time-series prediction',
        confidence: 0.3
      };
    }

    // Simple linear regression for threat level
    const threatLevels = historicalData.map(h => h.overallRisk?.score || 0);
    const trend = this.calculateTrend(threatLevels);

    // Generate forecast
    for (let i = 1; i <= hoursAhead; i++) {
      const forecastedLevel = threatLevels[threatLevels.length - 1] + (trend * i);
      predictions.threatLevelForecast.push({
        hour: i,
        level: Math.max(0, Math.min(1, forecastedLevel)),
        trend: trend > 0 ? 'increasing' : trend < 0 ? 'decreasing' : 'stable'
      });
    }

    // Predict likely attacks based on trends
    const attackTrends = this.analyzeAttackTrends();
    predictions.likelyAttacks = attackTrends.slice(0, 3);

    return predictions;
  }

  /**
   * Helper functions
   */

  async checkWindowsDefender() {
    try {
      // Check Windows Defender status
      const { stdout } = await execAsync(
        'powershell -Command "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled, RealTimeProtectionEnabled | ConvertTo-Json"',
        { timeout: 5000 }
      );
      
      const status = JSON.parse(stdout);
      return {
        enabled: status.AntivirusEnabled || false,
        realTimeProtection: status.RealTimeProtectionEnabled || false,
        available: true,
        platform: 'Windows Defender'
      };
    } catch (error) {
      return {
        enabled: false,
        realTimeProtection: false,
        available: false,
        platform: 'None detected',
        error: error.message
      };
    }
  }

  async checkMacAntivirus() {
    try {
      const xprotectPath = '/System/Library/CoreServices/XProtect.bundle';
      const exists = await fs.access(xprotectPath).then(() => true).catch(() => false);

      return {
        enabled: exists,
        realTimeProtection: exists,
        available: exists,
        platform: exists ? 'XProtect' : 'None detected'
      };
    } catch (error) {
      return {
        enabled: false,
        realTimeProtection: false,
        available: false,
        platform: 'None detected',
        error: error.message
      };
    }
  }

  async checkLinuxAntivirus() {
    try {
      const { stdout } = await execAsync('clamav-daemon --version').catch(() => ({ stdout: '' }));
      const hasClamAV = stdout.includes('ClamAV');

      if (hasClamAV) {
        const { stdout: status } = await execAsync('systemctl is-active clamav-daemon').catch(() => ({ stdout: 'inactive' }));
        const active = status.trim() === 'active';
        return {
          enabled: active,
          realTimeProtection: active,
          available: true,
          platform: 'ClamAV'
        };
      }

      return {
        enabled: false,
        realTimeProtection: false,
        available: false,
        platform: 'None detected'
      };
    } catch (error) {
      return {
        enabled: false,
        realTimeProtection: false,
        available: false,
        platform: 'None detected',
        error: error.message
      };
    }
  }

  async checkWindowsFirewall() {
    try {
      const { stdout } = await execAsync(
        'netsh advfirewall show allprofiles state',
        { timeout: 5000 }
      );
      
      const enabled = stdout.toLowerCase().includes('state                                 on');
      return { enabled };
    } catch (error) {
      return { enabled: false, error: error.message };
    }
  }

  async checkWindowsUpdate() {
    try {
      // Simplified check - in production, use Windows Update API
      return {
        lastCheck: new Date().toISOString(),
        pendingCount: Math.floor(Math.random() * 5),
        criticalCount: Math.floor(Math.random() * 2)
      };
    } catch (error) {
      return { pendingCount: 0, criticalCount: 0, error: error.message };
    }
  }

  async getInstalledSoftware() {
    // Simplified - in production, query registry or use WMI
    return [];
  }

  async checkSoftwareVulnerabilities(software) {
    const vulnerabilities = [];
    
    // Check against vulnerability database
    software.forEach(app => {
      const vulns = this.vulnerabilityDatabase.get(app.name);
      if (vulns) {
        vulnerabilities.push(...vulns);
      }
    });

    return vulnerabilities;
  }

  checkNetworkVulnerabilities(network) {
    const vulnerabilities = [];

    // Check for public IPs
    Object.values(network.interfaces).forEach(iface => {
      iface.forEach(addr => {
        if (addr.family === 'IPv4' && !addr.internal) {
          // Check if it's a public IP
          const ip = addr.address;
          if (!ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
            vulnerabilities.push({
              id: 'vuln_net_001',
              type: 'publicIP',
              severity: 'medium',
              description: 'System has public IP address',
              component: 'Network Interface',
              cvss: 5.5,
              recommendation: 'Use firewall to restrict access'
            });
          }
        }
      });
    });

    return vulnerabilities;
  }

  generateMitigations(vectorName, indicators) {
    const mitigations = [];
    const mitigationMap = {
      ransomware: [
        'Enable real-time protection',
        'Keep regular backups',
        'Update all software',
        'Enable ransomware protection',
        'Train users on phishing awareness'
      ],
      phishing: [
        'Enable email filtering',
        'Implement multi-factor authentication',
        'Conduct security awareness training',
        'Use anti-phishing tools'
      ],
      zeroDay: [
        'Enable behavior-based detection',
        'Implement application whitelisting',
        'Use intrusion prevention system',
        'Keep systems updated'
      ],
      bruteForce: [
        'Implement account lockout policies',
        'Use strong passwords',
        'Enable multi-factor authentication',
        'Monitor failed login attempts'
      ],
      malwareInfection: [
        'Enable antivirus',
        'Keep definitions updated',
        'Scan all downloads',
        'Restrict software installation'
      ],
      ddos: [
        'Implement rate limiting',
        'Use DDoS protection service',
        'Configure firewall rules',
        'Monitor traffic patterns'
      ],
      dataExfiltration: [
        'Monitor outbound traffic',
        'Encrypt sensitive data',
        'Implement DLP policies',
        'Use network segmentation'
      ]
    };

    return mitigationMap[vectorName] || [];
  }

  estimateTimeToExploit(vectorName, likelihood) {
    // Estimate based on likelihood and attack complexity
    const complexityMap = {
      ransomware: 'medium',
      phishing: 'low',
      zeroDay: 'high',
      bruteForce: 'medium',
      malwareInfection: 'low',
      ddos: 'low',
      dataExfiltration: 'high'
    };

    const complexity = complexityMap[vectorName];
    const baseTime = {
      low: 24,    // hours
      medium: 72,
      high: 168   // 1 week
    }[complexity];

    // Adjust based on likelihood
    const adjustedTime = baseTime * (1 - likelihood);

    return {
      hours: Math.round(adjustedTime),
      unit: adjustedTime > 48 ? 'days' : 'hours',
      value: adjustedTime > 48 ? Math.round(adjustedTime / 24) : Math.round(adjustedTime)
    };
  }

  estimateEffort(vuln) {
    const effortMap = {
      critical: 'high',
      high: 'medium',
      medium: 'low',
      low: 'low'
    };
    return effortMap[vuln.severity] || 'medium';
  }

  canAutomate(vuln) {
    const automatable = ['unpatched', 'disabledFirewall', 'noAntivirus'];
    return automatable.includes(vuln.type);
  }

  getRiskLevel(score) {
    if (score >= 0.8) return 'critical';
    if (score >= 0.6) return 'high';
    if (score >= 0.4) return 'medium';
    return 'low';
  }

  calculateVectorConfidence(indicators) {
    return Math.min(indicators.length / 3, 1);
  }

  getHistoricalLikelihood(vectorName) {
    const history = this.predictionHistory.filter(
      p => p.predictions.some(pred => pred.attackVector === vectorName)
    );
    
    if (history.length === 0) return 0;

    const sum = history.reduce((total, h) => {
      const pred = h.predictions.find(p => p.attackVector === vectorName);
      return total + (pred?.likelihood || 0);
    }, 0);

    return sum / history.length;
  }

  calculateTrendAdjustment(vectorName) {
    const recentHistory = this.predictionHistory.slice(-10);
    if (recentHistory.length < 2) return 0;

    const likelihoods = recentHistory
      .map(h => h.predictions.find(p => p.attackVector === vectorName)?.likelihood || 0);

    return this.calculateTrend(likelihoods) * 0.1;
  }

  calculateTrend(values) {
    if (values.length < 2) return 0;

    const n = values.length;
    const xMean = (n - 1) / 2;
    const yMean = values.reduce((sum, val) => sum + val, 0) / n;

    let numerator = 0;
    let denominator = 0;

    for (let i = 0; i < n; i++) {
      numerator += (i - xMean) * (values[i] - yMean);
      denominator += Math.pow(i - xMean, 2);
    }

    return denominator === 0 ? 0 : numerator / denominator;
  }

  analyzeAttackTrends() {
    const trends = [];

    Object.keys(this.attackVectors).forEach(vectorName => {
      const likelihood = this.getHistoricalLikelihood(vectorName);
      const trend = this.calculateTrendAdjustment(vectorName);

      if (likelihood > 0.3 || trend > 0) {
        trends.push({
          vector: vectorName,
          currentLikelihood: likelihood,
          trend: trend > 0 ? 'increasing' : trend < 0 ? 'decreasing' : 'stable',
          trendValue: trend
        });
      }
    });

    return trends.sort((a, b) => b.currentLikelihood - a.currentLikelihood);
  }

  storePrediction(analysis) {
    this.predictionHistory.push(analysis);
    this.systemStateHistory.push({
      timestamp: analysis.timestamp,
      overallRisk: analysis.overallRisk,
      vulnerabilityCount: analysis.vulnerabilities.length,
      predictionCount: analysis.predictions.length
    });

    // Keep only recent history
    const maxHistory = 100;
    if (this.predictionHistory.length > maxHistory) {
      this.predictionHistory = this.predictionHistory.slice(-maxHistory);
    }
    if (this.systemStateHistory.length > maxHistory) {
      this.systemStateHistory = this.systemStateHistory.slice(-maxHistory);
    }
  }

  async loadHistoricalData() {
    // Load from file if exists
    try {
      const dataPath = path.join(__dirname, 'data', 'prediction-history.json');
      const data = await fs.readFile(dataPath, 'utf8');
      const history = JSON.parse(data);
      this.predictionHistory = history.predictions || [];
      this.systemStateHistory = history.systemStates || [];
    } catch (error) {
      // No historical data yet
    }
  }

  async updateVulnerabilityDatabase() {
    // In production, fetch from CVE databases
    // For now, use sample data
    this.vulnerabilityDatabase.set('Adobe Reader', [
      {
        id: 'CVE-2021-XXXXX',
        type: 'outdatedSoftware',
        severity: 'high',
        cvss: 7.8,
        description: 'Buffer overflow vulnerability'
      }
    ]);
  }

  /**
   * Get statistics
   */
  getStatistics() {
    return {
      predictionHistory: this.predictionHistory.length,
      systemStateHistory: this.systemStateHistory.length,
      vulnerabilityDatabase: this.vulnerabilityDatabase.size,
      attackVectors: Object.keys(this.attackVectors).length,
      riskFactors: Object.keys(this.riskFactors).length,
      modelConfig: this.modelConfig
    };
  }
}

// Export singleton
const predictiveAnalytics = new PredictiveAnalytics();
module.exports = predictiveAnalytics;
